const std = @import("std");
const builtin = @import("builtin");
const password = @import("password.zig");
const processor = @import("processor.zig");
const utils = @import("utils.zig");

fn readAll(file: std.Io.File, io: std.Io, buffer: []u8) !usize {
    var file_reader = file.reader(io, &.{});
    return file_reader.interface.readSliceShort(buffer) catch |err| switch (err) {
        error.ReadFailed => return file_reader.err.?,
    };
}

/// AEGIS-128X2 keys are 16 bytes.
pub const key_length = 16;

pub const plain_key_file_size = key_length;

/// Format flag, masked key, checksum.
pub const protected_key_file_size = 1 + key_length + 4;

pub const KeyFormat = enum(u8) {
    plain = 0x00,
    password_protected = 0x01,
};

pub fn generate(io: std.Io) [key_length]u8 {
    var key: [key_length]u8 = undefined;
    io.random(&key);
    return key;
}

/// Write the key file, protected with the password when there is one.
pub fn writeKeyFile(
    path: []const u8,
    key: [key_length]u8,
    password_opt: ?[]const u8,
    allocator: std.mem.Allocator,
    io: std.Io,
) !void {
    var protected_file: [protected_key_file_size]u8 = undefined;
    const data: []const u8 = if (password_opt) |pwd| blk: {
        protected_file[0] = @backingInt(KeyFormat.password_protected);
        protected_file[1..].* = try password.protectKey(key, pwd);
        break :blk &protected_file;
    } else &key;

    try processor.writeFileAtomic(path, data, utils.private_file_permissions, null, allocator, io);
}

/// Read a key file. A protected key needs its password.
/// Warns when other users can read the file.
pub fn readKeyFile(path: []const u8, password_opt: ?[]const u8, io: std.Io) ![key_length]u8 {
    const file = try std.Io.Dir.openFile(.cwd(), io, path, .{});
    defer file.close(io);

    const stat = try file.stat(io);

    if (builtin.os.tag != .windows) {
        const mode = stat.permissions.toMode();

        const group_perms = (mode >> 3) & 0o7;
        const other_perms = mode & 0o7;

        if (group_perms != 0 or other_perms != 0) {
            std.debug.print("WARNING: Key file '{s}' has overly permissive permissions ({o}).\n", .{ path, mode & 0o777 });
            std.debug.print("         Recommended: chmod 600 {s}\n", .{path});
            std.debug.print("         Anyone with access to this file can decrypt your data!\n", .{});
        }
    }

    // The file size tells the format.
    const file_size = stat.size;

    if (file_size == plain_key_file_size) {
        var key: [key_length]u8 = undefined;
        const bytes_read = try readAll(file, io, &key);
        if (bytes_read != key_length) {
            return error.InvalidKeyFile;
        }
        return key;
    } else if (file_size == protected_key_file_size) {
        var full_data: [21]u8 = undefined;
        const bytes_read = try readAll(file, io, &full_data);
        if (bytes_read != 21) {
            return error.InvalidKeyFile;
        }

        if (full_data[0] != @backingInt(KeyFormat.password_protected)) {
            return error.InvalidKeyFile;
        }

        var protected_data: [20]u8 = undefined;
        @memcpy(&protected_data, full_data[1..21]);

        const pwd = password_opt orelse return error.PasswordRequired;

        return try password.unprotectKey(protected_data, pwd);
    } else {
        return error.InvalidKeyFile;
    }
}

test "key generation" {
    const testing = std.testing;
    const io = testing.io;

    const key1 = generate(io);
    const key2 = generate(io);

    try testing.expect(!std.mem.eql(u8, &key1, &key2));
}

test "key file write and read (plain)" {
    const testing = std.testing;
    const io = testing.io;

    const original_key = generate(io);
    const test_path = "tmp/test_key_plain.bin";

    std.Io.Dir.createDir(.cwd(), io, "tmp", .default_dir) catch |err| {
        if (err != error.PathAlreadyExists) return err;
    };

    try writeKeyFile(test_path, original_key, null, std.testing.allocator, io);
    defer std.Io.Dir.deleteFile(.cwd(), io, test_path) catch {};

    const read_key = try readKeyFile(test_path, null, io);
    try testing.expectEqualSlices(u8, &original_key, &read_key);
}

test "writing a key replaces a symbolic link without changing its target" {
    const testing = std.testing;
    const allocator = testing.allocator;
    const io = testing.io;
    const root = "tmp/key_atomic_symlink";
    const target_path = root ++ "/target";
    const key_path = root ++ "/key";
    const sentinel = "do not replace";
    const key: [key_length]u8 = @splat(0x5a);

    std.Io.Dir.deleteTree(.cwd(), io, root) catch {};
    try std.Io.Dir.createDirPath(.cwd(), io, root);
    defer std.Io.Dir.deleteTree(.cwd(), io, root) catch {};
    try std.Io.Dir.writeFile(.cwd(), io, .{ .sub_path = target_path, .data = sentinel });
    std.Io.Dir.symLink(.cwd(), io, "target", key_path, .{}) catch |err| {
        if (err == error.Unexpected or err == error.AccessDenied) return error.SkipZigTest;
        return err;
    };

    try writeKeyFile(key_path, key, null, std.testing.allocator, io);

    const target = try std.Io.Dir.readFileAlloc(.cwd(), io, target_path, allocator, .limited(sentinel.len + 1));
    defer allocator.free(target);
    try testing.expectEqualStrings(sentinel, target);
    const stat = try std.Io.Dir.statFile(.cwd(), io, key_path, .{ .follow_symlinks = false });
    try testing.expectEqual(std.Io.File.Kind.file, stat.kind);
    try testing.expectEqualSlices(u8, &key, &try readKeyFile(key_path, null, io));
}

test "key file write and read (password-protected)" {
    const testing = std.testing;
    const io = testing.io;

    const original_key = generate(io);
    const test_password = "test_password_123";
    const test_path = "tmp/test_key_protected.bin";

    std.Io.Dir.createDir(.cwd(), io, "tmp", .default_dir) catch |err| {
        if (err != error.PathAlreadyExists) return err;
    };

    try writeKeyFile(test_path, original_key, test_password, std.testing.allocator, io);
    defer std.Io.Dir.deleteFile(.cwd(), io, test_path) catch {};

    const file = try std.Io.Dir.openFile(.cwd(), io, test_path, .{});
    defer file.close(io);
    const stat = try file.stat(io);
    try testing.expectEqual(@as(u64, protected_key_file_size), stat.size);

    const read_key = try readKeyFile(test_path, test_password, io);
    try testing.expectEqualSlices(u8, &original_key, &read_key);
}

test "password-protected key requires password" {
    const testing = std.testing;
    const io = testing.io;

    const original_key = generate(io);
    const test_password = "test_password_123";
    const test_path = "tmp/test_key_no_pwd.bin";

    std.Io.Dir.createDir(.cwd(), io, "tmp", .default_dir) catch |err| {
        if (err != error.PathAlreadyExists) return err;
    };

    try writeKeyFile(test_path, original_key, test_password, std.testing.allocator, io);
    defer std.Io.Dir.deleteFile(.cwd(), io, test_path) catch {};

    const result = readKeyFile(test_path, null, io);
    try testing.expectError(error.PasswordRequired, result);
}

test "wrong password fails" {
    const testing = std.testing;
    const io = testing.io;

    const original_key = generate(io);
    const correct_password = "correct_password";
    const wrong_password = "wrong_password";
    const test_path = "tmp/test_key_wrong_pwd.bin";

    std.Io.Dir.createDir(.cwd(), io, "tmp", .default_dir) catch |err| {
        if (err != error.PathAlreadyExists) return err;
    };

    try writeKeyFile(test_path, original_key, correct_password, std.testing.allocator, io);
    defer std.Io.Dir.deleteFile(.cwd(), io, test_path) catch {};

    const result = readKeyFile(test_path, wrong_password, io);
    try testing.expectError(error.InvalidPassword, result);
}

test "change password on protected key" {
    const testing = std.testing;
    const io = testing.io;

    const original_key = generate(io);
    const old_password = "old_password_123";
    const new_password = "new_password_456";
    const test_path = "tmp/test_key_change_pwd.bin";

    std.Io.Dir.createDir(.cwd(), io, "tmp", .default_dir) catch |err| {
        if (err != error.PathAlreadyExists) return err;
    };

    try writeKeyFile(test_path, original_key, old_password, std.testing.allocator, io);
    defer std.Io.Dir.deleteFile(.cwd(), io, test_path) catch {};

    const read_key = try readKeyFile(test_path, old_password, io);
    try writeKeyFile(test_path, read_key, new_password, std.testing.allocator, io);

    const result_old = readKeyFile(test_path, old_password, io);
    try testing.expectError(error.InvalidPassword, result_old);

    const read_key_new = try readKeyFile(test_path, new_password, io);
    try testing.expectEqualSlices(u8, &original_key, &read_key_new);
}

test "add password protection to plain key" {
    const testing = std.testing;
    const io = testing.io;

    const original_key = generate(io);
    const test_password = "new_password_789";
    const test_path = "tmp/test_key_add_pwd.bin";

    std.Io.Dir.createDir(.cwd(), io, "tmp", .default_dir) catch |err| {
        if (err != error.PathAlreadyExists) return err;
    };

    try writeKeyFile(test_path, original_key, null, std.testing.allocator, io);
    defer std.Io.Dir.deleteFile(.cwd(), io, test_path) catch {};

    const file1 = try std.Io.Dir.openFile(.cwd(), io, test_path, .{});
    defer file1.close(io);
    const stat1 = try file1.stat(io);
    try testing.expectEqual(@as(u64, plain_key_file_size), stat1.size);

    const read_key = try readKeyFile(test_path, null, io);
    try writeKeyFile(test_path, read_key, test_password, std.testing.allocator, io);

    const file2 = try std.Io.Dir.openFile(.cwd(), io, test_path, .{});
    defer file2.close(io);
    const stat2 = try file2.stat(io);
    try testing.expectEqual(@as(u64, protected_key_file_size), stat2.size);

    const read_key_protected = try readKeyFile(test_path, test_password, io);
    try testing.expectEqualSlices(u8, &original_key, &read_key_protected);
}

test "remove password protection from protected key" {
    const testing = std.testing;
    const io = testing.io;

    const original_key = generate(io);
    const test_password = "temporary_password";
    const test_path = "tmp/test_key_remove_pwd.bin";

    std.Io.Dir.createDir(.cwd(), io, "tmp", .default_dir) catch |err| {
        if (err != error.PathAlreadyExists) return err;
    };

    try writeKeyFile(test_path, original_key, test_password, std.testing.allocator, io);
    defer std.Io.Dir.deleteFile(.cwd(), io, test_path) catch {};

    const file1 = try std.Io.Dir.openFile(.cwd(), io, test_path, .{});
    defer file1.close(io);
    const stat1 = try file1.stat(io);
    try testing.expectEqual(@as(u64, protected_key_file_size), stat1.size);

    const read_key = try readKeyFile(test_path, test_password, io);
    try writeKeyFile(test_path, read_key, null, std.testing.allocator, io);

    const file2 = try std.Io.Dir.openFile(.cwd(), io, test_path, .{});
    defer file2.close(io);
    const stat2 = try file2.stat(io);
    try testing.expectEqual(@as(u64, plain_key_file_size), stat2.size);

    const read_key_plain = try readKeyFile(test_path, null, io);
    try testing.expectEqualSlices(u8, &original_key, &read_key_plain);
}
