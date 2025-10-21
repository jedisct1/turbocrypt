const std = @import("std");
const builtin = @import("builtin");
const password = @import("password.zig");

/// Key size for AEGIS-128X2 (16 bytes = 128 bits)
pub const key_length = 16;

/// Plain key file size (just the key bytes)
pub const plain_key_file_size = key_length;

/// Password-protected key file size (flag + XOR'd key + checksum)
pub const protected_key_file_size = 1 + key_length + 4;

/// Key file format flags
pub const KeyFormat = enum(u8) {
    /// Plain key (16 bytes)
    plain = 0x00,
    /// Password-protected key (21 bytes: flag + 16 XOR'd bytes + 4 checksum bytes)
    password_protected = 0x01,
};

/// Generate a cryptographically secure 128-bit key
pub fn generate() [key_length]u8 {
    var key: [key_length]u8 = undefined;
    std.crypto.random.bytes(&key);
    return key;
}

/// Write a key to a file with secure permissions (chmod 600)
/// If password is provided, the key will be XOR'd with Argon2id(password)
/// Returns error if file operations fail
pub fn writeKeyFile(
    path: []const u8,
    key: [key_length]u8,
    password_opt: ?[]const u8,
) !void {
    // Create/open file
    const file = try std.fs.cwd().createFile(path, .{
        .read = true,
        .truncate = true,
    });
    defer file.close();

    if (password_opt) |pwd| {
        // Password-protected format: flag byte + XOR'd key
        const protected = try password.protectKey(key, pwd);
        const flag = [1]u8{@intFromEnum(KeyFormat.password_protected)};
        try file.writeAll(&flag);
        try file.writeAll(&protected);
    } else {
        // Plain format: just the key bytes
        try file.writeAll(&key);
    }

    // Set restrictive permissions (owner read/write only)
    // chmod 600 (rw-------)
    // Note: Windows doesn't support Unix-style permissions
    if (builtin.os.tag != .windows) {
        try file.chmod(0o600);
    }
}

/// Read a key from a file
/// If password is provided and key is password-protected, it will be decrypted
/// Returns error if file doesn't exist, is wrong size, or can't be read
/// Warns if file permissions are too permissive
pub fn readKeyFile(path: []const u8, password_opt: ?[]const u8) ![key_length]u8 {
    // Open file
    const file = try std.fs.cwd().openFile(path, .{});
    defer file.close();

    // Check file permissions (Unix-like systems only)
    const stat = try file.stat();

    if (builtin.os.tag != .windows) {
        const mode = stat.mode;

        // Warn if permissions are too permissive (not 0600 or stricter)
        // On Unix-like systems, check if group or other have any permissions
        // Mode 0600 = owner read/write only
        const group_perms = (mode >> 3) & 0o7; // Group permissions
        const other_perms = mode & 0o7; // Other permissions

        if (group_perms != 0 or other_perms != 0) {
            std.debug.print("WARNING: Key file '{s}' has overly permissive permissions ({o}).\n", .{ path, mode & 0o777 });
            std.debug.print("         Recommended: chmod 600 {s}\n", .{path});
            std.debug.print("         Anyone with access to this file can decrypt your data!\n", .{});
        }
    }

    // Determine file format by size
    const file_size = stat.size;

    if (file_size == plain_key_file_size) {
        // Plain key format
        var key: [key_length]u8 = undefined;
        const bytes_read = try file.readAll(&key);
        if (bytes_read != key_length) {
            return error.InvalidKeyFile;
        }
        return key;
    } else if (file_size == protected_key_file_size) {
        // Password-protected format
        var format_buf: [1]u8 = undefined;
        const bytes_read_flag = try file.read(&format_buf);
        if (bytes_read_flag != 1) {
            return error.InvalidKeyFile;
        }
        if (format_buf[0] != @intFromEnum(KeyFormat.password_protected)) {
            return error.InvalidKeyFile;
        }

        var protected_data: [20]u8 = undefined;
        const bytes_read = try file.readAll(&protected_data);
        if (bytes_read != 20) {
            return error.InvalidKeyFile;
        }

        // Require password for protected keys
        const pwd = password_opt orelse return error.PasswordRequired;

        // Decrypt the key (verifies checksum internally)
        return try password.unprotectKey(protected_data, pwd);
    } else {
        return error.InvalidKeyFile;
    }
}

test "key generation" {
    // Generate two keys and ensure they're different
    const key1 = generate();
    const key2 = generate();

    try std.testing.expect(!std.mem.eql(u8, &key1, &key2));
}

test "key file write and read (plain)" {
    const testing = std.testing;

    // Generate a key
    const original_key = generate();

    // Write to temp file
    const test_path = "tmp/test_key_plain.bin";

    // Ensure tmp directory exists
    std.fs.cwd().makeDir("tmp") catch |err| {
        if (err != error.PathAlreadyExists) return err;
    };

    try writeKeyFile(test_path, original_key, null);
    defer std.fs.cwd().deleteFile(test_path) catch {};

    // Read back
    const read_key = try readKeyFile(test_path, null);

    // Verify they match
    try testing.expectEqualSlices(u8, &original_key, &read_key);
}

test "key file write and read (password-protected)" {
    const testing = std.testing;

    // Generate a key
    const original_key = generate();
    const test_password = "test_password_123";

    // Write to temp file with password
    const test_path = "tmp/test_key_protected.bin";

    // Ensure tmp directory exists
    std.fs.cwd().makeDir("tmp") catch |err| {
        if (err != error.PathAlreadyExists) return err;
    };

    try writeKeyFile(test_path, original_key, test_password);
    defer std.fs.cwd().deleteFile(test_path) catch {};

    // Verify file size is correct for password-protected keys
    const file = try std.fs.cwd().openFile(test_path, .{});
    defer file.close();
    const stat = try file.stat();
    try testing.expectEqual(@as(u64, protected_key_file_size), stat.size);

    // Read back with password
    const read_key = try readKeyFile(test_path, test_password);

    // Verify they match
    try testing.expectEqualSlices(u8, &original_key, &read_key);
}

test "password-protected key requires password" {
    const testing = std.testing;

    const original_key = generate();
    const test_password = "test_password_123";
    const test_path = "tmp/test_key_no_pwd.bin";

    // Ensure tmp directory exists
    std.fs.cwd().makeDir("tmp") catch |err| {
        if (err != error.PathAlreadyExists) return err;
    };

    try writeKeyFile(test_path, original_key, test_password);
    defer std.fs.cwd().deleteFile(test_path) catch {};

    // Attempt to read without password should fail
    const result = readKeyFile(test_path, null);
    try testing.expectError(error.PasswordRequired, result);
}

test "wrong password fails" {
    const testing = std.testing;

    const original_key = generate();
    const correct_password = "correct_password";
    const wrong_password = "wrong_password";
    const test_path = "tmp/test_key_wrong_pwd.bin";

    // Ensure tmp directory exists
    std.fs.cwd().makeDir("tmp") catch |err| {
        if (err != error.PathAlreadyExists) return err;
    };

    try writeKeyFile(test_path, original_key, correct_password);
    defer std.fs.cwd().deleteFile(test_path) catch {};

    // Read with wrong password should fail with InvalidPassword error
    const result = readKeyFile(test_path, wrong_password);
    try testing.expectError(error.InvalidPassword, result);
}
