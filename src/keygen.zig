const std = @import("std");
const builtin = @import("builtin");
const password = @import("password.zig");

fn readAll(file: std.fs.File, io: std.Io, buffer: []u8) !usize {
    var file_reader = file.reader(io, &.{});
    return file_reader.interface.readSliceShort(buffer) catch |err| switch (err) {
        error.ReadFailed => return file_reader.err.?,
    };
}

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
pub fn readKeyFile(path: []const u8, password_opt: ?[]const u8, io: std.Io) ![key_length]u8 {
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
        const bytes_read = try readAll(file, io, &key);
        if (bytes_read != key_length) {
            return error.InvalidKeyFile;
        }
        return key;
    } else if (file_size == protected_key_file_size) {
        // Password-protected format
        // Read the entire file (1 byte flag + 20 bytes protected data)
        var full_data: [21]u8 = undefined;
        const bytes_read = try readAll(file, io, &full_data);
        if (bytes_read != 21) {
            return error.InvalidKeyFile;
        }

        if (full_data[0] != @intFromEnum(KeyFormat.password_protected)) {
            return error.InvalidKeyFile;
        }

        // Extract protected data (skip first byte which is the format flag)
        var protected_data: [20]u8 = undefined;
        @memcpy(&protected_data, full_data[1..21]);

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
    const io = testing.io;

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
    const read_key = try readKeyFile(test_path, null, io);

    // Verify they match
    try testing.expectEqualSlices(u8, &original_key, &read_key);
}

test "key file write and read (password-protected)" {
    const testing = std.testing;
    const io = testing.io;

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
    const read_key = try readKeyFile(test_path, test_password, io);

    // Verify they match
    try testing.expectEqualSlices(u8, &original_key, &read_key);
}

test "password-protected key requires password" {
    const testing = std.testing;
    const io = testing.io;

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
    const result = readKeyFile(test_path, null, io);
    try testing.expectError(error.PasswordRequired, result);
}

test "wrong password fails" {
    const testing = std.testing;
    const io = testing.io;

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
    const result = readKeyFile(test_path, wrong_password, io);
    try testing.expectError(error.InvalidPassword, result);
}

test "change password on protected key" {
    const testing = std.testing;
    const io = testing.io;

    const original_key = generate();
    const old_password = "old_password_123";
    const new_password = "new_password_456";
    const test_path = "tmp/test_key_change_pwd.bin";

    // Ensure tmp directory exists
    std.fs.cwd().makeDir("tmp") catch |err| {
        if (err != error.PathAlreadyExists) return err;
    };

    // Write with old password
    try writeKeyFile(test_path, original_key, old_password);
    defer std.fs.cwd().deleteFile(test_path) catch {};

    // Read with old password and re-write with new password
    const read_key = try readKeyFile(test_path, old_password, io);
    try writeKeyFile(test_path, read_key, new_password);

    // Verify old password no longer works
    const result_old = readKeyFile(test_path, old_password, io);
    try testing.expectError(error.InvalidPassword, result_old);

    // Verify new password works
    const read_key_new = try readKeyFile(test_path, new_password, io);
    try testing.expectEqualSlices(u8, &original_key, &read_key_new);
}

test "add password protection to plain key" {
    const testing = std.testing;
    const io = testing.io;

    const original_key = generate();
    const test_password = "new_password_789";
    const test_path = "tmp/test_key_add_pwd.bin";

    // Ensure tmp directory exists
    std.fs.cwd().makeDir("tmp") catch |err| {
        if (err != error.PathAlreadyExists) return err;
    };

    // Write as plain key
    try writeKeyFile(test_path, original_key, null);
    defer std.fs.cwd().deleteFile(test_path) catch {};

    // Verify file size is for plain key
    const file1 = try std.fs.cwd().openFile(test_path, .{});
    defer file1.close();
    const stat1 = try file1.stat();
    try testing.expectEqual(@as(u64, plain_key_file_size), stat1.size);

    // Read and re-write with password
    const read_key = try readKeyFile(test_path, null, io);
    try writeKeyFile(test_path, read_key, test_password);

    // Verify file size is now for protected key
    const file2 = try std.fs.cwd().openFile(test_path, .{});
    defer file2.close();
    const stat2 = try file2.stat();
    try testing.expectEqual(@as(u64, protected_key_file_size), stat2.size);

    // Verify key can be read with password
    const read_key_protected = try readKeyFile(test_path, test_password, io);
    try testing.expectEqualSlices(u8, &original_key, &read_key_protected);
}

test "remove password protection from protected key" {
    const testing = std.testing;
    const io = testing.io;

    const original_key = generate();
    const test_password = "temporary_password";
    const test_path = "tmp/test_key_remove_pwd.bin";

    // Ensure tmp directory exists
    std.fs.cwd().makeDir("tmp") catch |err| {
        if (err != error.PathAlreadyExists) return err;
    };

    // Write with password
    try writeKeyFile(test_path, original_key, test_password);
    defer std.fs.cwd().deleteFile(test_path) catch {};

    // Verify file size is for protected key
    const file1 = try std.fs.cwd().openFile(test_path, .{});
    defer file1.close();
    const stat1 = try file1.stat();
    try testing.expectEqual(@as(u64, protected_key_file_size), stat1.size);

    // Read with password and re-write without password
    const read_key = try readKeyFile(test_path, test_password, io);
    try writeKeyFile(test_path, read_key, null);

    // Verify file size is now for plain key
    const file2 = try std.fs.cwd().openFile(test_path, .{});
    defer file2.close();
    const stat2 = try file2.stat();
    try testing.expectEqual(@as(u64, plain_key_file_size), stat2.size);

    // Verify key can be read without password
    const read_key_plain = try readKeyFile(test_path, null, io);
    try testing.expectEqualSlices(u8, &original_key, &read_key_plain);
}
