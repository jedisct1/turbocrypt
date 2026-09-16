//! Map filenames without persistent metadata; hide backing entries that cannot be represented safely.

const std = @import("std");
const container = @import("../container.zig");
const filename_crypto = @import("../filename_crypto.zig");
const processor = @import("../processor.zig");

pub const Error = error{
    NameTooLong,
    OutOfMemory,
};

pub const suffix = ".enc";

/// Plaintext length guaranteed to fit after name encryption.
pub const max_encrypted_plain_length = 197;

pub const Kind = enum { file, directory };

pub const Mapper = struct {
    /// Strip the suffix from files in the view; directories keep their names.
    enc_suffix: bool = false,
    filename_key: ?[16]u8 = null,

    /// The caller frees the encoded component.
    pub fn toBacking(self: Mapper, allocator: std.mem.Allocator, name: []const u8, kind: Kind) Error![]u8 {
        const with_suffix = self.enc_suffix and kind == .file;
        const key = self.filename_key orelse {
            if (with_suffix) return std.mem.concat(allocator, u8, &.{ name, suffix });
            return allocator.dupe(u8, name);
        };
        if (!with_suffix) return encrypt(allocator, name, key);
        const joined = try std.mem.concat(allocator, u8, &.{ name, suffix });
        defer allocator.free(joined);
        return encrypt(allocator, joined, key);
    }

    pub fn kindsDiffer(self: Mapper) bool {
        return self.enc_suffix;
    }

    /// Return an owned plaintext name, or null for a hidden entry.
    ///
    /// Hide temporary files, the container descriptor, noncanonical encodings, and files missing a required suffix.
    pub fn toPlain(self: Mapper, allocator: std.mem.Allocator, backing: []const u8, kind: Kind) Error!?[]u8 {
        if (isReserved(backing)) return null;
        const decoded = if (self.filename_key) |key|
            filename_crypto.decryptFilenameForFilesystem(allocator, backing, key) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => return null,
            }
        else
            try allocator.dupe(u8, backing);
        if (!self.enc_suffix or kind == .directory) return decoded;
        defer allocator.free(decoded);
        if (decoded.len <= suffix.len or !std.mem.endsWith(u8, decoded, suffix)) return null;
        return try allocator.dupe(u8, decoded[0 .. decoded.len - suffix.len]);
    }

    /// Protect write-back debris and the container descriptor at every depth.
    /// Reserve descriptor aliases too, since case-insensitive filesystems treat them as the same file.
    pub fn isReserved(backing: []const u8) bool {
        return processor.isTemporaryName(backing) or std.ascii.eqlIgnoreCase(backing, container.descriptor_name);
    }

    /// Report a conservative plaintext name limit to filesystem clients.
    pub fn nameMax(self: Mapper) u64 {
        const base: u64 = if (self.filename_key != null) max_encrypted_plain_length else 255;
        return if (self.enc_suffix) base - suffix.len else base;
    }

    fn encrypt(allocator: std.mem.Allocator, name: []const u8, key: [16]u8) Error![]u8 {
        return filename_crypto.encryptFilename(allocator, name, key) catch |err| switch (err) {
            error.EncryptedFilenameTooLong => error.NameTooLong,
            error.OutOfMemory => error.OutOfMemory,
            else => error.NameTooLong,
        };
    }
};

test "plain names pass through and temporary names stay hidden" {
    const testing = std.testing;
    const allocator = testing.allocator;
    const mapper: Mapper = .{};

    const backing = try mapper.toBacking(allocator, "notes.txt", .file);
    defer allocator.free(backing);
    try testing.expectEqualStrings("notes.txt", backing);

    const plain = (try mapper.toPlain(allocator, "notes.txt", .file)).?;
    defer allocator.free(plain);
    try testing.expectEqualStrings("notes.txt", plain);

    try testing.expect(!mapper.kindsDiffer());
    try testing.expectEqual(null, try mapper.toPlain(allocator, ".tc-0123456789abcdef.tmp", .file));
    try testing.expect(Mapper.isReserved(".tc-0123456789abcdef.tmp"));
    try testing.expect(!Mapper.isReserved("notes.txt"));
    try testing.expectEqual(255, mapper.nameMax());
}

test "the container descriptor stays hidden under every filename setting" {
    const testing = std.testing;
    const allocator = testing.allocator;
    const key: [16]u8 = @splat(5);
    const raw = container.descriptor_name;
    try testing.expect(Mapper.isReserved(raw));
    try testing.expect(Mapper.isReserved(".TURBOCRYPT-RAF"));
    try testing.expect(Mapper.isReserved(".Turbocrypt-Raf"));
    try testing.expect(!Mapper.isReserved(".turbocrypt-raf2"));

    for ([_]Mapper{ .{}, .{ .enc_suffix = true }, .{ .filename_key = key }, .{ .filename_key = key, .enc_suffix = true } }) |mapper| {
        for ([_]Kind{ .file, .directory }) |kind| {
            try testing.expectEqual(null, try mapper.toPlain(allocator, raw, kind));
        }
    }
    try testing.expectEqual(null, try (Mapper{}).toPlain(allocator, ".TURBOCRYPT-RAF", .file));

    // A plaintext name may map elsewhere; only a collision with the raw descriptor is reserved.
    for ([_]struct { mapper: Mapper, kind: Kind, reserved: bool }{
        .{ .mapper = .{}, .kind = .file, .reserved = true },
        .{ .mapper = .{ .enc_suffix = true }, .kind = .file, .reserved = false },
        .{ .mapper = .{ .enc_suffix = true }, .kind = .directory, .reserved = true },
        .{ .mapper = .{ .filename_key = key }, .kind = .file, .reserved = false },
    }) |case| {
        const backing = try case.mapper.toBacking(allocator, raw, case.kind);
        defer allocator.free(backing);
        try testing.expectEqual(case.reserved, Mapper.isReserved(backing));
    }
}

test "suffix mode adds the suffix to files only and hides files without it" {
    const testing = std.testing;
    const allocator = testing.allocator;
    const mapper: Mapper = .{ .enc_suffix = true };

    const file = try mapper.toBacking(allocator, "notes.txt", .file);
    defer allocator.free(file);
    try testing.expectEqualStrings("notes.txt.enc", file);
    const dir = try mapper.toBacking(allocator, "docs", .directory);
    defer allocator.free(dir);
    try testing.expectEqualStrings("docs", dir);
    try testing.expect(mapper.kindsDiffer());

    const plain = (try mapper.toPlain(allocator, "notes.txt.enc", .file)).?;
    defer allocator.free(plain);
    try testing.expectEqualStrings("notes.txt", plain);
    try testing.expectEqual(null, try mapper.toPlain(allocator, "notes.txt", .file));
    try testing.expectEqual(null, try mapper.toPlain(allocator, ".enc", .file));
    const plain_dir = (try mapper.toPlain(allocator, "docs", .directory)).?;
    defer allocator.free(plain_dir);
    try testing.expectEqualStrings("docs", plain_dir);
    try testing.expectEqual(251, mapper.nameMax());
}

test "encrypted names round-trip in both kinds and hide what does not decode" {
    const testing = std.testing;
    const allocator = testing.allocator;
    const key: [16]u8 = @splat(5);
    const mapper: Mapper = .{ .filename_key = key, .enc_suffix = true };

    const file = try mapper.toBacking(allocator, "notes.txt", .file);
    defer allocator.free(file);
    const dir = try mapper.toBacking(allocator, "notes.txt", .directory);
    defer allocator.free(dir);
    try testing.expect(!std.mem.eql(u8, file, dir));

    const plain_file = (try mapper.toPlain(allocator, file, .file)).?;
    defer allocator.free(plain_file);
    try testing.expectEqualStrings("notes.txt", plain_file);
    const plain_dir = (try mapper.toPlain(allocator, dir, .directory)).?;
    defer allocator.free(plain_dir);
    try testing.expectEqualStrings("notes.txt", plain_dir);

    try testing.expectEqual(null, try mapper.toPlain(allocator, dir, .file));
    try testing.expectEqual(null, try mapper.toPlain(allocator, "not-a-ciphertext", .file));
    try testing.expectEqual(null, try mapper.toPlain(allocator, "", .directory));

    // Reservation applies to the backing spelling, not the plaintext name.
    const odd = try mapper.toBacking(allocator, ".tc-0123456789abcdef.tmp", .directory);
    defer allocator.free(odd);
    try testing.expect(!Mapper.isReserved(odd));
    try testing.expectEqual(193, mapper.nameMax());

    const plain_mapper: Mapper = .{ .filename_key = key };
    const too_long: [255]u8 = @splat('b');
    try testing.expectError(error.NameTooLong, plain_mapper.toBacking(allocator, &too_long, .file));
    try testing.expectEqual(197, plain_mapper.nameMax());
}
