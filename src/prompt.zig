const std = @import("std");
const keygen = @import("keygen.zig");
const builtin = @import("builtin");

const max_password_length = 1024;

/// Raw mode needs a Windows console or termios
const supports_raw_mode = builtin.os.tag != .wasi;

const TerminalState = if (builtin.os.tag == .windows)
    struct {
        handle: std.os.windows.HANDLE,
        original_mode: std.os.windows.DWORD,
    }
else
    std.posix.termios;

/// Console mode functions that the standard library no longer declares
extern "kernel32" fn GetConsoleMode(hConsoleHandle: std.os.windows.HANDLE, lpMode: *std.os.windows.DWORD) callconv(.winapi) std.os.windows.BOOL;
extern "kernel32" fn SetConsoleMode(hConsoleHandle: std.os.windows.HANDLE, dwMode: std.os.windows.DWORD) callconv(.winapi) std.os.windows.BOOL;

/// Ask for a password, twice when confirm is set. The caller frees the result.
pub fn promptPassword(
    allocator: std.mem.Allocator,
    prompt_text: []const u8,
    confirm: bool,
    io: std.Io,
) ![]u8 {
    const stdout = std.Io.File.stdout();

    // Read from /dev/tty when possible.
    // A killed process could echo buffered stdin in clear text.
    const stdin_file = if (builtin.os.tag == .windows)
        std.Io.File.stdin()
    else blk: {
        const tty = std.Io.Dir.openFileAbsolute(io, "/dev/tty", .{ .mode = .read_write }) catch {
            break :blk std.Io.File.stdin();
        };
        break :blk tty;
    };

    const should_close = builtin.os.tag != .windows and stdin_file.handle != std.Io.File.stdin().handle;
    defer if (should_close) stdin_file.close(io);

    const is_terminal = stdin_file.isTty(io) catch false;

    // Raw mode leaves the editing keys to readLine
    const raw_input = supports_raw_mode and is_terminal;

    var original: TerminalState = undefined;
    if (raw_input) try setRawMode(stdin_file, &original);
    defer if (is_terminal) {
        stdout.writeStreamingAll(io, "\n") catch {};
        if (raw_input) restoreMode(stdin_file, original) catch {};
    };

    try stdout.writeStreamingAll(io, prompt_text);
    try stdout.writeStreamingAll(io, ": ");

    var buffer: [max_password_length]u8 = undefined;
    defer std.crypto.secureZero(u8, &buffer);
    const password1 = buffer[0..try readLine(stdin_file, &buffer, raw_input, io)];

    if (confirm) {
        try stdout.writeStreamingAll(io, "Confirm password: ");

        var buffer2: [max_password_length]u8 = undefined;
        defer std.crypto.secureZero(u8, &buffer2);
        const password2 = buffer2[0..try readLine(stdin_file, &buffer2, raw_input, io)];

        if (!std.mem.eql(u8, password1, password2)) {
            return error.PasswordMismatch;
        }
    }

    return try allocator.dupe(u8, password1);
}

/// Read one line into buffer and return its length.
/// In raw mode, backspace erases, Ctrl-C aborts and Ctrl-D ends the input.
fn readLine(file: std.Io.File, buffer: []u8, raw: bool, io: std.Io) !usize {
    var pos: usize = 0;
    var read_any = false;
    var byte_buf: [1]u8 = undefined;

    while (pos < buffer.len) {
        const bytes_read = try file.readStreaming(io, &.{&byte_buf});
        if (bytes_read == 0) {
            if (!read_any) return error.EndOfStream;
            break;
        }
        read_any = true;

        const byte = byte_buf[0];
        if (byte == '\n' or byte == '\r') {
            break;
        }

        if (raw) {
            switch (byte) {
                0x03 => return error.Interrupted,
                0x04 => {
                    if (pos == 0) return error.EndOfStream;
                    break;
                },
                0x08, 0x7f => {
                    // Step back over one whole UTF-8 sequence
                    while (pos > 0) {
                        pos -= 1;
                        if ((buffer[pos] & 0xC0) != 0x80) break;
                    }
                    continue;
                },
                else => {},
            }
        }

        buffer[pos] = byte;
        pos += 1;
    }

    return pos;
}

/// Raw mode keeps a killed process from echoing buffered input.
fn setRawMode(file: std.Io.File, state: *TerminalState) !void {
    if (builtin.os.tag == .windows) {
        const handle = file.handle;
        state.handle = handle;

        if (GetConsoleMode(handle, &state.original_mode) == .FALSE) {
            return error.GetConsoleModeFailure;
        }

        // Processed input would let Ctrl-C end the process before the console is restored
        const ENABLE_PROCESSED_INPUT: std.os.windows.DWORD = 0x0001;
        const ENABLE_LINE_INPUT: std.os.windows.DWORD = 0x0002;
        const ENABLE_ECHO_INPUT: std.os.windows.DWORD = 0x0004;
        const new_mode = state.original_mode & ~(ENABLE_PROCESSED_INPUT | ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT);

        if (SetConsoleMode(handle, new_mode) == .FALSE) {
            return error.SetConsoleModeFailure;
        }
    } else {
        state.* = try std.posix.tcgetattr(file.handle);
        var new_termios = state.*;

        new_termios.lflag.ECHO = false;
        new_termios.lflag.ECHOE = false;
        new_termios.lflag.ECHOK = false;
        new_termios.lflag.ECHONL = false;
        new_termios.lflag.ECHOCTL = false;
        new_termios.lflag.ECHOPRT = false;
        new_termios.lflag.ECHOKE = false;

        new_termios.lflag.ICANON = false;
        new_termios.lflag.ISIG = false;
        new_termios.lflag.IEXTEN = false;

        new_termios.iflag.IXON = false;
        new_termios.iflag.ICRNL = false;
        new_termios.iflag.INLCR = false;
        new_termios.iflag.IGNCR = false;

        new_termios.cc[@backingInt(std.posix.V.MIN)] = 1;
        new_termios.cc[@backingInt(std.posix.V.TIME)] = 0;

        try std.posix.tcsetattr(file.handle, .FLUSH, new_termios);
    }
}

fn restoreMode(file: std.Io.File, state: TerminalState) !void {
    if (builtin.os.tag == .windows) {
        if (SetConsoleMode(state.handle, state.original_mode) == .FALSE) {
            return error.SetConsoleModeFailure;
        }
    } else {
        try std.posix.tcsetattr(file.handle, .FLUSH, state);
    }
}

pub fn isKeyPasswordProtected(path: []const u8, io: std.Io) !bool {
    const file = try std.Io.Dir.openFile(.cwd(), io, path, .{});
    defer file.close(io);

    const stat = try file.stat(io);
    return stat.size == keygen.protected_key_file_size;
}
