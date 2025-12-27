const std = @import("std");
const keygen = @import("keygen.zig");
const builtin = @import("builtin");

/// Maximum password length
const MAX_PASSWORD_LENGTH = 1024;

/// Platform-specific terminal state
const TerminalState = if (builtin.os.tag == .windows)
    struct {
        handle: std.os.windows.HANDLE,
        original_mode: std.os.windows.DWORD,
    }
else
    std.posix.termios;

/// Prompt the user for a password (with confirmation for new passwords)
/// Allocates memory for the password - caller must free
pub fn promptPassword(
    allocator: std.mem.Allocator,
    prompt_text: []const u8,
    confirm: bool,
    io: std.Io,
) ![]u8 {
    const stdout = std.Io.File.stdout();

    // On Unix, try to open /dev/tty directly to avoid stdin buffering issues
    // If the process is killed, buffered stdin could be echoed in cleartext
    // Fall back to stdin if /dev/tty can't be opened (e.g., non-interactive scenarios)
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

    const has_termios = builtin.os.tag != .wasi and builtin.os.tag != .windows;
    const is_terminal = stdin_file.isTty(io) catch false;

    var original: TerminalState = undefined;
    if (has_termios and is_terminal) {
        original = try std.posix.tcgetattr(stdin_file.handle);
        var raw = original;

        raw.lflag.ICANON = false;
        raw.lflag.ECHO = false;
        raw.lflag.ECHONL = false;
        raw.lflag.ISIG = false;
        raw.lflag.IEXTEN = false;

        raw.iflag.BRKINT = false;
        raw.iflag.ICRNL = false;
        raw.iflag.INPCK = false;
        raw.iflag.ISTRIP = false;
        raw.iflag.IXON = false;

        raw.cc[@intFromEnum(std.posix.V.MIN)] = 1;
        raw.cc[@intFromEnum(std.posix.V.TIME)] = 0;

        try std.posix.tcsetattr(stdin_file.handle, .FLUSH, raw);
        try stdout.writeStreamingAll(io, prompt_text);
        try stdout.writeStreamingAll(io, ": ");
    } else if (builtin.os.tag == .windows and is_terminal) {
        try setRawMode(stdin_file, &original, io);
        try stdout.writeStreamingAll(io, prompt_text);
        try stdout.writeStreamingAll(io, ": ");
    } else {
        try stdout.writeStreamingAll(io, prompt_text);
        try stdout.writeStreamingAll(io, ": ");
    }
    defer if (is_terminal) {
        stdout.writeStreamingAll(io, "\n") catch {};
        if (has_termios) {
            std.posix.tcsetattr(stdin_file.handle, .FLUSH, original) catch {};
        } else if (builtin.os.tag == .windows) {
            restoreMode(stdin_file, original) catch {};
        }
    };

    var buffer: [MAX_PASSWORD_LENGTH]u8 = undefined;

    var pos: usize = 0;
    var read_any = false;
    var byte_buf: [1]u8 = undefined;

    while (pos < buffer.len) {
        const bytes_read = try stdin_file.readStreaming(io, &.{&byte_buf});
        if (bytes_read == 0) {
            if (!read_any) return error.EndOfStream;
            break;
        }
        read_any = true;

        const byte = byte_buf[0];
        if (byte == '\n' or byte == '\r') {
            break;
        }

        buffer[pos] = byte;
        pos += 1;
    }

    const password1 = buffer[0..pos];

    if (confirm) {
        try stdout.writeStreamingAll(io, "Confirm password: ");

        var buffer2: [MAX_PASSWORD_LENGTH]u8 = undefined;

        var pos2: usize = 0;
        var read_any2 = false;
        var byte_buf2: [1]u8 = undefined;

        while (pos2 < buffer2.len) {
            const bytes_read = try stdin_file.readStreaming(io, &.{&byte_buf2});
            if (bytes_read == 0) {
                if (!read_any2) return error.EndOfStream;
                break;
            }
            read_any2 = true;

            const byte = byte_buf2[0];
            if (byte == '\n' or byte == '\r') {
                break;
            }

            buffer2[pos2] = byte;
            pos2 += 1;
        }

        const password2 = buffer2[0..pos2];

        if (!std.mem.eql(u8, password1, password2)) {
            return error.PasswordMismatch;
        }
    }

    return try allocator.dupe(u8, password1);
}

/// Set raw mode for password input (disables echo, buffering, and line processing)
/// This prevents buffered input from being echoed if the process is killed
fn setRawMode(file: std.Io.File, state: *TerminalState, io: std.Io) !void {
    _ = io;
    if (builtin.os.tag == .windows) {
        const handle = file.handle;
        state.handle = handle;

        if (std.os.windows.kernel32.GetConsoleMode(handle, &state.original_mode) == 0) {
            return error.GetConsoleModeFailure;
        }

        const ENABLE_ECHO_INPUT: std.os.windows.DWORD = 0x0004;
        const ENABLE_LINE_INPUT: std.os.windows.DWORD = 0x0002;
        const new_mode = state.original_mode & ~(ENABLE_ECHO_INPUT | ENABLE_LINE_INPUT);

        if (std.os.windows.kernel32.SetConsoleMode(handle, new_mode) == 0) {
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

        new_termios.cc[@intFromEnum(std.posix.V.MIN)] = 1;
        new_termios.cc[@intFromEnum(std.posix.V.TIME)] = 0;

        try std.posix.tcsetattr(file.handle, .FLUSH, new_termios);
    }
}

/// Restore terminal to original mode
fn restoreMode(file: std.Io.File, state: TerminalState) !void {
    if (builtin.os.tag == .windows) {
        if (std.os.windows.kernel32.SetConsoleMode(state.handle, state.original_mode) == 0) {
            return error.SetConsoleModeFailure;
        }
    } else {
        try std.posix.tcsetattr(file.handle, .FLUSH, state);
    }
}

/// Check if a key file is password-protected
pub fn isKeyPasswordProtected(path: []const u8, io: std.Io) !bool {
    const file = try std.Io.Dir.openFile(.cwd(), io, path, .{});
    defer file.close(io);

    const stat = try file.stat(io);
    return stat.size == keygen.protected_key_file_size;
}
