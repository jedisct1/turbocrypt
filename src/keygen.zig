//! Creates keys and reads or writes key files.
//!
//! Plain files store the raw key.
//! Protected files include a format byte and password-protected key data.

const std = @import("std");
const builtin = @import("builtin");
const testing = std.testing;
const Allocator = std.mem.Allocator;
const Io = std.Io;

const password = @import("password.zig");
const processor = @import("processor.zig");
const fs = @import("fs.zig");

/// AEGIS-128X2 requires 16-byte keys.
pub const key_length = 16;

pub const plain_key_file_size = key_length;

/// Includes the format flag and password-protected key data.
pub const protected_key_file_size = 1 + password.protected_key_size;
pub const legacy_protected_key_file_size = 1 + password.legacy_protected_key_size;

/// Accepts both current and legacy protected key-file sizes.
pub fn isProtectedFileSize(size: u64) bool {
    return size == protected_key_file_size or size == legacy_protected_key_file_size;
}

pub const KeyFormat = enum(u8) {
    plain = 0x00,
    password_protected = 0x01,
};

pub fn generate(io: Io) [key_length]u8 {
    var key: [key_length]u8 = undefined;
    io.random(&key);
    return key;
}

/// Writes a key file, protecting its contents when a password is provided.
pub fn writeKeyFile(
    gpa: Allocator,
    io: Io,
    path: []const u8,
    key: [key_length]u8,
    maybe_password: ?[]const u8,
) !void {
    var protected_file: [protected_key_file_size]u8 = undefined;
    const data: []const u8 = if (maybe_password) |pass| blk: {
        protected_file[0] = @backingInt(KeyFormat.password_protected);
        protected_file[1..].* = try password.protectKey(io, key, pass);
        break :blk &protected_file;
    } else &key;

    try processor.writeFileAtomic(gpa, io, path, data, fs.private_file_permissions, null);
}

/// Reads a key file, requiring `maybe_password` for protected keys.
/// Warns when another account could read the key.
pub fn readKeyFile(io: Io, path: []const u8, maybe_password: ?[]const u8) ![key_length]u8 {
    const file = try Io.Dir.openFile(.cwd(), io, path, .{});
    defer file.close(io);

    const stat = try file.stat(io);

    if (builtin.os.tag != .windows) {
        const mode = stat.permissions.toMode();

        const group_bits = (mode >> 3) & 0o7;
        const other_bits = mode & 0o7;

        if (group_bits != 0 or other_bits != 0) {
            std.debug.print(
                "WARNING: Key file '{s}' has overly permissive permissions ({o}).\n",
                .{ path, mode & 0o777 },
            );
            std.debug.print("         Recommended: chmod 600 {s}\n", .{path});
            std.debug.print("         Anyone with access to this file can decrypt your data!\n", .{});
        }
    }

    // The size identifies the supported key-file layout, including legacy files.
    const file_size = stat.size;

    if (file_size == plain_key_file_size) {
        var key: [key_length]u8 = undefined;
        const bytes_read = try readAll(file, io, &key);
        if (bytes_read != key_length) return error.InvalidKeyFile;
        return key;
    } else if (isProtectedFileSize(file_size)) {
        const serialized_size: usize = @intCast(file_size);
        var full_data: [protected_key_file_size]u8 = undefined;
        const bytes_read = try readAll(file, io, full_data[0..serialized_size]);
        if (bytes_read != serialized_size) return error.InvalidKeyFile;
        if (full_data[0] != @backingInt(KeyFormat.password_protected)) return error.InvalidKeyFile;

        const pass = maybe_password orelse return error.PasswordRequired;
        return password.unprotectKey(full_data[1..serialized_size], pass);
    } else {
        return error.InvalidKeyFile;
    }
}

fn readAll(file: Io.File, io: Io, buffer: []u8) !usize {
    var file_reader = file.reader(io, &.{});
    return file_reader.interface.readSliceShort(buffer) catch |err| switch (err) {
        error.ReadFailed => return file_reader.err.?,
    };
}

fn fileSize(io: Io, path: []const u8) !u64 {
    const stat = try Io.Dir.statFile(.cwd(), io, path, .{});
    return stat.size;
}

test "generated keys differ" {
    const first = generate(testing.io);
    const second = generate(testing.io);
    try testing.expect(!std.mem.eql(u8, &first, &second));
}

test "a plain key file round-trips and can gain a password" {
    const gpa = testing.allocator;
    const io = testing.io;
    const root = "tmp/keygen_add_password";
    Io.Dir.deleteTree(.cwd(), io, root) catch {};
    try Io.Dir.createDirPath(.cwd(), io, root);
    defer Io.Dir.deleteTree(.cwd(), io, root) catch {};
    const path = root ++ "/key";
    const key = generate(io);

    try writeKeyFile(gpa, io, path, key, null);
    try testing.expectEqual(plain_key_file_size, try fileSize(io, path));
    const plain = try readKeyFile(io, path, null);
    try testing.expectEqualSlices(u8, &key, &plain);

    try writeKeyFile(gpa, io, path, plain, "new_password_789");
    try testing.expectEqual(protected_key_file_size, try fileSize(io, path));
    try testing.expectEqualSlices(u8, &key, &try readKeyFile(io, path, "new_password_789"));
}

test "a protected key file round-trips and requires its password" {
    const gpa = testing.allocator;
    const io = testing.io;
    const root = "tmp/keygen_protected";
    Io.Dir.deleteTree(.cwd(), io, root) catch {};
    try Io.Dir.createDirPath(.cwd(), io, root);
    defer Io.Dir.deleteTree(.cwd(), io, root) catch {};
    const path = root ++ "/key";
    const key = generate(io);

    try writeKeyFile(gpa, io, path, key, "test_password_123");
    try testing.expectEqual(protected_key_file_size, try fileSize(io, path));
    try testing.expectEqualSlices(u8, &key, &try readKeyFile(io, path, "test_password_123"));
    try testing.expectError(error.PasswordRequired, readKeyFile(io, path, null));
}

test "a wrong password is rejected" {
    const gpa = testing.allocator;
    const io = testing.io;
    const root = "tmp/keygen_wrong_password";
    Io.Dir.deleteTree(.cwd(), io, root) catch {};
    try Io.Dir.createDirPath(.cwd(), io, root);
    defer Io.Dir.deleteTree(.cwd(), io, root) catch {};
    const path = root ++ "/key";

    try writeKeyFile(gpa, io, path, generate(io), "correct_password");
    try testing.expectError(error.InvalidPassword, readKeyFile(io, path, "wrong_password"));
}

test "changing the password keeps the key and retires the old password" {
    const gpa = testing.allocator;
    const io = testing.io;
    const root = "tmp/keygen_change_password";
    Io.Dir.deleteTree(.cwd(), io, root) catch {};
    try Io.Dir.createDirPath(.cwd(), io, root);
    defer Io.Dir.deleteTree(.cwd(), io, root) catch {};
    const path = root ++ "/key";
    const key = generate(io);

    try writeKeyFile(gpa, io, path, key, "old_password_123");
    const read_key = try readKeyFile(io, path, "old_password_123");
    try writeKeyFile(gpa, io, path, read_key, "new_password_456");

    try testing.expectError(error.InvalidPassword, readKeyFile(io, path, "old_password_123"));
    try testing.expectEqualSlices(u8, &key, &try readKeyFile(io, path, "new_password_456"));
}

test "removing the password writes a plain key file" {
    const gpa = testing.allocator;
    const io = testing.io;
    const root = "tmp/keygen_remove_password";
    Io.Dir.deleteTree(.cwd(), io, root) catch {};
    try Io.Dir.createDirPath(.cwd(), io, root);
    defer Io.Dir.deleteTree(.cwd(), io, root) catch {};
    const path = root ++ "/key";
    const key = generate(io);

    try writeKeyFile(gpa, io, path, key, "temporary_password");
    try testing.expectEqual(protected_key_file_size, try fileSize(io, path));
    const read_key = try readKeyFile(io, path, "temporary_password");
    try writeKeyFile(gpa, io, path, read_key, null);

    try testing.expectEqual(plain_key_file_size, try fileSize(io, path));
    try testing.expectEqualSlices(u8, &key, &try readKeyFile(io, path, null));
}

test "changing a legacy key password upgrades its format" {
    const gpa = testing.allocator;
    const io = testing.io;
    const root = "tmp/keygen_legacy";
    Io.Dir.deleteTree(.cwd(), io, root) catch {};
    try Io.Dir.createDirPath(.cwd(), io, root);
    defer Io.Dir.deleteTree(.cwd(), io, root) catch {};
    const path = root ++ "/key";
    const legacy = password.legacy_test_vector;
    const flag = @backingInt(KeyFormat.password_protected);
    const serialized: [legacy_protected_key_file_size]u8 = [_]u8{flag} ++ legacy.protected;
    try processor.writeFileAtomic(gpa, io, path, &serialized, fs.private_file_permissions, null);

    const key = try readKeyFile(io, path, legacy.passphrase);
    try writeKeyFile(gpa, io, path, key, "new password");

    try testing.expectEqual(protected_key_file_size, try fileSize(io, path));
    try testing.expectEqualSlices(u8, &legacy.key, &try readKeyFile(io, path, "new password"));
}

test "writing a key replaces a symbolic link without changing its target" {
    const gpa = testing.allocator;
    const io = testing.io;
    const root = "tmp/key_atomic_symlink";
    const target_path = root ++ "/target";
    const key_path = root ++ "/key";
    const sentinel = "do not replace";
    const key: [key_length]u8 = @splat(0x5a);

    Io.Dir.deleteTree(.cwd(), io, root) catch {};
    try Io.Dir.createDirPath(.cwd(), io, root);
    defer Io.Dir.deleteTree(.cwd(), io, root) catch {};
    try Io.Dir.writeFile(.cwd(), io, .{ .sub_path = target_path, .data = sentinel });
    Io.Dir.symLink(.cwd(), io, "target", key_path, .{}) catch |err| {
        if (err == error.Unexpected or err == error.AccessDenied) return error.SkipZigTest;
        return err;
    };

    try writeKeyFile(gpa, io, key_path, key, null);

    const limit: Io.Limit = .limited(sentinel.len + 1);
    const target = try Io.Dir.readFileAlloc(.cwd(), io, target_path, gpa, limit);
    defer gpa.free(target);
    try testing.expectEqualStrings(sentinel, target);
    const stat = try Io.Dir.statFile(.cwd(), io, key_path, .{ .follow_symlinks = false });
    try testing.expectEqual(Io.File.Kind.file, stat.kind);
    try testing.expectEqualSlices(u8, &key, &try readKeyFile(io, key_path, null));
}
