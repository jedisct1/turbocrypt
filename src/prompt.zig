//! Password prompts that keep typed passwords out of the terminal output.

const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;
const Io = std.Io;

const keygen = @import("keygen.zig");

const max_password_length = 1024;

/// Raw input is available through Windows consoles or POSIX termios.
const supports_raw_mode = builtin.os.tag != .wasi;

const TerminalState = if (builtin.os.tag == .windows)
    struct {
        handle: std.os.windows.HANDLE,
        original_mode: std.os.windows.DWORD,
    }
else
    std.posix.termios;

/// Declares the Windows console calls needed to restore password input safely.
extern "kernel32" fn GetConsoleMode(
    hConsoleHandle: std.os.windows.HANDLE,
    lpMode: *std.os.windows.DWORD,
) callconv(.winapi) std.os.windows.BOOL;
extern "kernel32" fn SetConsoleMode(
    hConsoleHandle: std.os.windows.HANDLE,
    dwMode: std.os.windows.DWORD,
) callconv(.winapi) std.os.windows.BOOL;

/// Prompts for a password and confirms it when requested.
/// The caller owns the returned memory.
pub fn password(
    gpa: Allocator,
    io: Io,
    prompt_text: []const u8,
    confirm: bool,
) ![]u8 {
    const stdout = Io.File.stdout();

    // Prefer the controlling terminal so an interrupted process cannot echo buffered input in clear text.
    const input = if (builtin.os.tag == .windows)
        Io.File.stdin()
    else
        Io.Dir.openFileAbsolute(io, "/dev/tty", .{ .mode = .read_write }) catch Io.File.stdin();

    const should_close = builtin.os.tag != .windows and input.handle != Io.File.stdin().handle;
    defer if (should_close) input.close(io);

    const is_terminal = input.isTty(io) catch false;

    // Let `readLine` handle editing so terminal behavior stays predictable.
    const raw_input = supports_raw_mode and is_terminal;

    var original: TerminalState = undefined;
    if (raw_input) try setRawMode(input, &original);
    defer if (is_terminal) {
        stdout.writeStreamingAll(io, "\n") catch {};
        if (raw_input) restoreMode(input, original) catch {};
    };

    try stdout.writeStreamingAll(io, prompt_text);
    try stdout.writeStreamingAll(io, ": ");

    var buffer: [max_password_length]u8 = undefined;
    defer std.crypto.secureZero(u8, &buffer);
    const first = buffer[0..try readLine(input, io, &buffer, raw_input)];

    if (confirm) {
        try stdout.writeStreamingAll(io, "Confirm password: ");

        var confirm_buffer: [max_password_length]u8 = undefined;
        defer std.crypto.secureZero(u8, &confirm_buffer);
        const second = confirm_buffer[0..try readLine(input, io, &confirm_buffer, raw_input)];
        if (!std.mem.eql(u8, first, second)) return error.PasswordMismatch;
    }

    return gpa.dupe(u8, first);
}

/// Reads one password line into `buffer` and returns its length.
/// In raw mode, backspace erases, Ctrl-C aborts, and Ctrl-D ends input.
fn readLine(file: Io.File, io: Io, buffer: []u8, raw: bool) !usize {
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
        if (byte == '\n' or byte == '\r') break;

        if (raw) {
            switch (byte) {
                0x03 => return error.Interrupted,
                0x04 => {
                    if (pos == 0) return error.EndOfStream;
                    break;
                },
                0x08, 0x7f => {
                    // Erase one character rather than leaving part of a UTF-8 sequence behind.
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

/// Disables terminal echo so interrupted password input is not exposed.
fn setRawMode(file: Io.File, state: *TerminalState) !void {
    if (builtin.os.tag == .windows) {
        const handle = file.handle;
        state.handle = handle;

        if (GetConsoleMode(handle, &state.original_mode) == .FALSE) {
            return error.GetConsoleModeFailure;
        }

        // Handle Ctrl-C ourselves so the console mode is restored first.
        const ENABLE_PROCESSED_INPUT: std.os.windows.DWORD = 0x0001;
        const ENABLE_LINE_INPUT: std.os.windows.DWORD = 0x0002;
        const ENABLE_ECHO_INPUT: std.os.windows.DWORD = 0x0004;
        const new_mode = state.original_mode &
            ~(ENABLE_PROCESSED_INPUT | ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT);

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

fn restoreMode(file: Io.File, state: TerminalState) !void {
    if (builtin.os.tag == .windows) {
        if (SetConsoleMode(state.handle, state.original_mode) == .FALSE) {
            return error.SetConsoleModeFailure;
        }
    } else {
        try std.posix.tcsetattr(file.handle, .FLUSH, state);
    }
}

/// Checks the file layout without reading or prompting for its password.
pub fn isKeyPasswordProtected(io: Io, path: []const u8) !bool {
    const file = try Io.Dir.openFile(.cwd(), io, path, .{});
    defer file.close(io);

    const stat = try file.stat(io);
    return keygen.isProtectedFileSize(stat.size);
}
