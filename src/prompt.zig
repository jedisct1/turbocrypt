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
    const stdin = std.fs.File.stdin();
    const stdout = std.fs.File.stdout();

    // Check if stdin is a terminal
    const is_terminal = stdin.isTty();

    if (is_terminal) {
        // Disable echo for password input
        var terminal_state: TerminalState = undefined;
        try disableEcho(stdin, &terminal_state);
        defer enableEcho(stdin, terminal_state) catch {};
    }

    // First prompt
    try stdout.writeAll(prompt_text);
    try stdout.writeAll(": ");

    var buffer: [MAX_PASSWORD_LENGTH]u8 = undefined;
    var password1: []const u8 = undefined;

    // Read until newline
    var pos: usize = 0;
    while (pos < buffer.len) {
        const bytes_read = try stdin.read(buffer[pos .. pos + 1]);
        if (bytes_read == 0) {
            if (pos == 0) return error.EndOfStream;
            break;
        }
        if (buffer[pos] == '\n') {
            password1 = buffer[0..pos];
            break;
        }
        pos += 1;
    } else {
        password1 = buffer[0..pos];
    }

    if (is_terminal) {
        // Print newline since echo was disabled
        try stdout.writeAll("\n");
    }

    if (confirm) {
        // Confirmation prompt
        try stdout.writeAll("Confirm password: ");

        var buffer2: [MAX_PASSWORD_LENGTH]u8 = undefined;
        var password2: []const u8 = undefined;

        // Read until newline
        var pos2: usize = 0;
        while (pos2 < buffer2.len) {
            const bytes_read = try stdin.read(buffer2[pos2 .. pos2 + 1]);
            if (bytes_read == 0) {
                if (pos2 == 0) return error.EndOfStream;
                break;
            }
            if (buffer2[pos2] == '\n') {
                password2 = buffer2[0..pos2];
                break;
            }
            pos2 += 1;
        } else {
            password2 = buffer2[0..pos2];
        }

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

/// Disable terminal echo for password input
fn disableEcho(file: std.fs.File, state: *TerminalState) !void {
    if (builtin.os.tag == .windows) {
        const handle = file.handle;
        state.handle = handle;

        // Get current console mode
        if (std.os.windows.kernel32.GetConsoleMode(handle, &state.original_mode) == 0) {
            return error.GetConsoleModeFailure;
        }

        // Disable ENABLE_ECHO_INPUT (0x0004)
        const ENABLE_ECHO_INPUT: std.os.windows.DWORD = 0x0004;
        const new_mode = state.original_mode & ~ENABLE_ECHO_INPUT;

        if (std.os.windows.kernel32.SetConsoleMode(handle, new_mode) == 0) {
            return error.SetConsoleModeFailure;
        }
    } else {
        state.* = try std.posix.tcgetattr(file.handle);

        var new_termios = state.*;
        new_termios.lflag.ECHO = false;

        try std.posix.tcsetattr(file.handle, .FLUSH, new_termios);
    }
}

/// Restore terminal echo
fn enableEcho(file: std.fs.File, state: TerminalState) !void {
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
