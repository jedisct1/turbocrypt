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
) ![]u8 {
    const stdout = std.fs.File.stdout();

    // On Unix, try to open /dev/tty directly to avoid stdin buffering issues
    // If the process is killed, buffered stdin could be echoed in cleartext
    // Fall back to stdin if /dev/tty can't be opened (e.g., non-interactive scenarios)
    const stdin_file = if (builtin.os.tag == .windows)
        std.fs.File.stdin()
    else blk: {
        const tty = std.fs.openFileAbsolute("/dev/tty", .{ .mode = .read_write }) catch {
            break :blk std.fs.File.stdin();
        };
        break :blk tty;
    };

    const should_close = builtin.os.tag != .windows and stdin_file.handle != std.fs.File.stdin().handle;
    defer if (should_close) stdin_file.close();

    // Check if stdin is a terminal
    const is_terminal = stdin_file.isTty();

    if (is_terminal) {
        // Set raw mode for password input (disables echo and buffering)
        var terminal_state: TerminalState = undefined;
        try setRawMode(stdin_file, &terminal_state);
        defer restoreMode(stdin_file, terminal_state) catch {};
    }

    // First prompt
    try stdout.writeAll(prompt_text);
    try stdout.writeAll(": ");

    var buffer: [MAX_PASSWORD_LENGTH]u8 = undefined;

    var pos: usize = 0;
    var read_any = false;
    var byte_buf: [1]u8 = undefined;

    // Read until newline, tolerate CRLF without embedding '\r'
    while (pos < buffer.len) {
        const bytes_read = try stdin_file.read(&byte_buf);
        if (bytes_read == 0) {
            if (!read_any) return error.EndOfStream;
            break;
        }
        read_any = true;

        const byte = byte_buf[0];
        if (byte == '\n') {
            break;
        }
        if (byte == '\r') {
            continue;
        }

        buffer[pos] = byte;
        pos += 1;
    }

    const password1 = buffer[0..pos];

    if (is_terminal) {
        // Print newline since echo was disabled
        try stdout.writeAll("\n");
    }

    if (confirm) {
        // Confirmation prompt
        try stdout.writeAll("Confirm password: ");

        var buffer2: [MAX_PASSWORD_LENGTH]u8 = undefined;

        var pos2: usize = 0;
        var read_any2 = false;
        var byte_buf2: [1]u8 = undefined;

        while (pos2 < buffer2.len) {
            const bytes_read = try stdin_file.read(&byte_buf2);
            if (bytes_read == 0) {
                if (!read_any2) return error.EndOfStream;
                break;
            }
            read_any2 = true;

            const byte = byte_buf2[0];
            if (byte == '\n') {
                break;
            }
            if (byte == '\r') {
                continue;
            }

            buffer2[pos2] = byte;
            pos2 += 1;
        }

        const password2 = buffer2[0..pos2];

        if (is_terminal) {
            try stdout.writeAll("\n");
        }

        if (!std.mem.eql(u8, password1, password2)) {
            return error.PasswordMismatch;
        }
    }

    // Allocate and return password
    return try allocator.dupe(u8, password1);
}

/// Set raw mode for password input (disables echo, buffering, and line processing)
/// This prevents buffered input from being echoed if the process is killed
fn setRawMode(file: std.fs.File, state: *TerminalState) !void {
    if (builtin.os.tag == .windows) {
        const handle = file.handle;
        state.handle = handle;

        // Get current console mode
        if (std.os.windows.kernel32.GetConsoleMode(handle, &state.original_mode) == 0) {
            return error.GetConsoleModeFailure;
        }

        // Disable ENABLE_ECHO_INPUT (0x0004) and ENABLE_LINE_INPUT (0x0002)
        const ENABLE_ECHO_INPUT: std.os.windows.DWORD = 0x0004;
        const ENABLE_LINE_INPUT: std.os.windows.DWORD = 0x0002;
        const new_mode = state.original_mode & ~(ENABLE_ECHO_INPUT | ENABLE_LINE_INPUT);

        if (std.os.windows.kernel32.SetConsoleMode(handle, new_mode) == 0) {
            return error.SetConsoleModeFailure;
        }
    } else {
        // Save original terminal settings
        state.* = try std.posix.tcgetattr(file.handle);

        // Set raw mode: disable echo, canonical mode, and signal generation
        var new_termios = state.*;

        // Disable echo, canonical mode (line buffering), and signal chars
        new_termios.lflag.ECHO = false; // No echo
        new_termios.lflag.ICANON = false; // No line buffering
        new_termios.lflag.ISIG = false; // No signal generation (Ctrl-C, etc.)
        new_termios.lflag.IEXTEN = false; // No extended processing

        // Disable input processing
        new_termios.iflag.IXON = false; // No XON/XOFF flow control
        new_termios.iflag.ICRNL = false; // No CR to NL translation
        new_termios.iflag.INLCR = false; // No NL to CR translation
        new_termios.iflag.IGNCR = false; // Don't ignore CR

        // Read settings: return immediately with 1+ chars, no timeout
        new_termios.cc[@intFromEnum(std.posix.V.MIN)] = 1;
        new_termios.cc[@intFromEnum(std.posix.V.TIME)] = 0;

        try std.posix.tcsetattr(file.handle, .FLUSH, new_termios);
    }
}

/// Restore terminal to original mode
fn restoreMode(file: std.fs.File, state: TerminalState) !void {
    if (builtin.os.tag == .windows) {
        if (std.os.windows.kernel32.SetConsoleMode(state.handle, state.original_mode) == 0) {
            return error.SetConsoleModeFailure;
        }
    } else {
        try std.posix.tcsetattr(file.handle, .FLUSH, state);
    }
}

/// Check if a key file is password-protected
pub fn isKeyPasswordProtected(path: []const u8) !bool {
    const file = try std.fs.cwd().openFile(path, .{});
    defer file.close();

    const stat = try file.stat();
    return stat.size == keygen.protected_key_file_size;
}
