const std = @import("std");
const keygen = @import("keygen.zig");

/// Maximum password length
const MAX_PASSWORD_LENGTH = 1024;

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
        var original_termios: std.posix.termios = undefined;
        try disableEcho(stdin, &original_termios);
        defer enableEcho(stdin, original_termios) catch {};
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
fn disableEcho(file: std.fs.File, original: *std.posix.termios) !void {
    original.* = try std.posix.tcgetattr(file.handle);

    var new_termios = original.*;
    new_termios.lflag.ECHO = false;

    try std.posix.tcsetattr(file.handle, .FLUSH, new_termios);
}

/// Restore terminal echo
fn enableEcho(file: std.fs.File, original: std.posix.termios) !void {
    try std.posix.tcsetattr(file.handle, .FLUSH, original);
}

/// Check if a key file is password-protected
pub fn isKeyPasswordProtected(path: []const u8) !bool {
    const file = try std.fs.cwd().openFile(path, .{});
    defer file.close();

    const stat = try file.stat();
    return stat.size == keygen.protected_key_file_size;
}
