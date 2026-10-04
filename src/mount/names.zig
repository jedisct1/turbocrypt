//! Translate filenames without storing extra metadata.
//! Keep backing entries out of view when they cannot be represented safely.

const std = @import("std");
const mem = std.mem;
const testing = std.testing;
const Allocator = std.mem.Allocator;

const container = @import("../container.zig");
const filename_crypto = @import("../filename_crypto.zig");
const processor = @import("../processor.zig");

pub const Error = error{
    NameTooLong,
    OutOfMemory,
};

pub const suffix = ".enc";

/// Maximum plaintext length that always fits after encryption.
pub const max_encrypted_plain_length = 197;

pub const Kind = enum { file, directory };

pub const Mapper = struct {
    /// Remove the file suffix in the view; directory names do not use it.
    enc_suffix: bool = false,
    filename_key: ?[16]u8 = null,

    /// The caller frees the returned name.
    pub fn toBacking(self: Mapper, gpa: Allocator, name: []const u8, kind: Kind) Error![]u8 {
        const with_suffix = self.enc_suffix and kind == .file;
        const key = self.filename_key orelse {
            if (with_suffix) return mem.concat(gpa, u8, &.{ name, suffix });
            return gpa.dupe(u8, name);
        };
        if (!with_suffix) return encrypt(gpa, name, key);
        const joined = try mem.concat(gpa, u8, &.{ name, suffix });
        defer gpa.free(joined);
        return encrypt(gpa, joined, key);
    }

    /// True when files and directories with one visible name need distinct backing names.
    pub fn kindsDiffer(self: Mapper) bool {
        return self.enc_suffix;
    }

    /// Return an owned visible name, or null when the backing entry must stay hidden.
    ///
    /// Hide temporary files, the container descriptor, invalid encodings,
    /// and files missing a required suffix.
    pub fn toPlain(self: Mapper, gpa: Allocator, backing: []const u8, kind: Kind) Error!?[]u8 {
        if (isReserved(backing)) return null;
        const decoded = if (self.filename_key) |key|
            filename_crypto.decryptForFilesystem(gpa, backing, key) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => return null,
            }
        else
            try gpa.dupe(u8, backing);
        if (!self.enc_suffix or kind == .directory) return decoded;
        defer gpa.free(decoded);
        if (decoded.len <= suffix.len or !mem.endsWith(u8, decoded, suffix)) return null;
        return try gpa.dupe(u8, decoded[0 .. decoded.len - suffix.len]);
    }

    /// Reserve temporary names and the descriptor throughout the backing tree.
    /// Reserve case variants of the descriptor too,
    /// because case-insensitive filesystems treat them as one file.
    pub fn isReserved(backing: []const u8) bool {
        return processor.isTmpName(backing) or
            std.ascii.eqlIgnoreCase(backing, container.descriptor_name);
    }

    /// Give clients a safe upper bound for visible filename lengths.
    pub fn nameMax(self: Mapper) u64 {
        const base: u64 = if (self.filename_key != null) max_encrypted_plain_length else 255;
        return if (self.enc_suffix) base - suffix.len else base;
    }

    fn encrypt(gpa: Allocator, name: []const u8, key: [16]u8) Error![]u8 {
        return filename_crypto.encrypt(gpa, name, key) catch |err| switch (err) {
            error.EncryptedFilenameTooLong => error.NameTooLong,
            error.OutOfMemory => error.OutOfMemory,
            else => error.NameTooLong,
        };
    }
};

test "plain names pass through and temporary names stay hidden" {
    const gpa = testing.allocator;
    const mapper: Mapper = .{};

    const backing = try mapper.toBacking(gpa, "notes.txt", .file);
    defer gpa.free(backing);
    try testing.expectEqualStrings("notes.txt", backing);

    const plain = (try mapper.toPlain(gpa, "notes.txt", .file)).?;
    defer gpa.free(plain);
    try testing.expectEqualStrings("notes.txt", plain);

    try testing.expect(!mapper.kindsDiffer());
    try testing.expectEqual(null, try mapper.toPlain(gpa, ".tc-0123456789abcdef.tmp", .file));
    try testing.expect(Mapper.isReserved(".tc-0123456789abcdef.tmp"));
    try testing.expect(!Mapper.isReserved("notes.txt"));
    try testing.expectEqual(255, mapper.nameMax());
}

test "the container descriptor stays hidden under every filename setting" {
    const gpa = testing.allocator;
    const key: [16]u8 = @splat(5);
    const raw = container.descriptor_name;
    try testing.expect(Mapper.isReserved(raw));
    try testing.expect(Mapper.isReserved(".TURBOCRYPT-RAF"));
    try testing.expect(Mapper.isReserved(".Turbocrypt-Raf"));
    try testing.expect(!Mapper.isReserved(".turbocrypt-raf2"));

    for ([_]Mapper{
        .{},
        .{ .enc_suffix = true },
        .{ .filename_key = key },
        .{ .filename_key = key, .enc_suffix = true },
    }) |mapper| {
        for ([_]Kind{ .file, .directory }) |kind| {
            try testing.expectEqual(null, try mapper.toPlain(gpa, raw, kind));
        }
    }
    try testing.expectEqual(null, try (Mapper{}).toPlain(gpa, ".TURBOCRYPT-RAF", .file));

    // Only the raw backing descriptor name is reserved; another plaintext spelling may encode safely.
    for ([_]struct { mapper: Mapper, kind: Kind, reserved: bool }{
        .{ .mapper = .{}, .kind = .file, .reserved = true },
        .{ .mapper = .{ .enc_suffix = true }, .kind = .file, .reserved = false },
        .{ .mapper = .{ .enc_suffix = true }, .kind = .directory, .reserved = true },
        .{ .mapper = .{ .filename_key = key }, .kind = .file, .reserved = false },
    }) |case| {
        const backing = try case.mapper.toBacking(gpa, raw, case.kind);
        defer gpa.free(backing);
        try testing.expectEqual(case.reserved, Mapper.isReserved(backing));
    }
}

test "suffix mode adds the suffix to files only and hides files without it" {
    const gpa = testing.allocator;
    const mapper: Mapper = .{ .enc_suffix = true };

    const file = try mapper.toBacking(gpa, "notes.txt", .file);
    defer gpa.free(file);
    try testing.expectEqualStrings("notes.txt.enc", file);
    const dir = try mapper.toBacking(gpa, "docs", .directory);
    defer gpa.free(dir);
    try testing.expectEqualStrings("docs", dir);
    try testing.expect(mapper.kindsDiffer());

    const plain = (try mapper.toPlain(gpa, "notes.txt.enc", .file)).?;
    defer gpa.free(plain);
    try testing.expectEqualStrings("notes.txt", plain);
    try testing.expectEqual(null, try mapper.toPlain(gpa, "notes.txt", .file));
    try testing.expectEqual(null, try mapper.toPlain(gpa, ".enc", .file));
    const plain_dir = (try mapper.toPlain(gpa, "docs", .directory)).?;
    defer gpa.free(plain_dir);
    try testing.expectEqualStrings("docs", plain_dir);
    try testing.expectEqual(251, mapper.nameMax());
}

test "encrypted names round-trip in both kinds and hide what does not decode" {
    const gpa = testing.allocator;
    const key: [16]u8 = @splat(5);
    const mapper: Mapper = .{ .filename_key = key, .enc_suffix = true };

    const file = try mapper.toBacking(gpa, "notes.txt", .file);
    defer gpa.free(file);
    const dir = try mapper.toBacking(gpa, "notes.txt", .directory);
    defer gpa.free(dir);
    try testing.expect(!mem.eql(u8, file, dir));

    const plain_file = (try mapper.toPlain(gpa, file, .file)).?;
    defer gpa.free(plain_file);
    try testing.expectEqualStrings("notes.txt", plain_file);
    const plain_dir = (try mapper.toPlain(gpa, dir, .directory)).?;
    defer gpa.free(plain_dir);
    try testing.expectEqualStrings("notes.txt", plain_dir);

    try testing.expectEqual(null, try mapper.toPlain(gpa, dir, .file));
    try testing.expectEqual(null, try mapper.toPlain(gpa, "not-a-ciphertext", .file));
    try testing.expectEqual(null, try mapper.toPlain(gpa, "", .directory));

    // Reservations apply to the backing name, not the visible name.
    const odd = try mapper.toBacking(gpa, ".tc-0123456789abcdef.tmp", .directory);
    defer gpa.free(odd);
    try testing.expect(!Mapper.isReserved(odd));
    try testing.expectEqual(193, mapper.nameMax());

    const plain_mapper: Mapper = .{ .filename_key = key };
    const too_long: [255]u8 = @splat('b');
    try testing.expectError(error.NameTooLong, plain_mapper.toBacking(gpa, &too_long, .file));
    try testing.expectEqual(197, plain_mapper.nameMax());
}
