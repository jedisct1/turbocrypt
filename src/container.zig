//! Detects RAF containers and authenticates their settings, key, and context.
//!
//! This stays independent of FUSE so every build can keep ordinary commands out of containers.

const std = @import("std");
const mem = std.mem;
const testing = std.testing;
const Allocator = std.mem.Allocator;
const Io = std.Io;

const aegis_raf = @import("aegis_raf");
const crypto = @import("crypto.zig");
const fs = @import("fs.zig");

pub const Error = error{
    DescriptorMissing,
    InvalidDescriptor,
    UnsupportedDescriptor,
    AuthenticationFailed,
};

/// Use a raw reserved name so container detection never requires a decryption key.
pub const descriptor_name = ".turbocrypt-raf";

/// Reserve one chunk for every nonempty file so RAF storage has a stable minimum size.
pub const data_chunk_size: u32 = 16384;

/// Distinguish stray files from descriptors that need a newer TurboCrypt version.
const magic = "turbocrypt-raf-container";
const descriptor_version: u32 = 1;
const prefix_length = magic.len + 4;

/// Randomness prevents matching descriptors from linking containers that share a key.
/// Authenticate settings for integrity; filenames and file sizes already reveal them.
const random_length = 16;
const settings_length = 4 + 1;
const random_offset = prefix_length;
const settings_offset = random_offset + random_length;
const mac_offset = settings_offset + settings_length;

/// Authenticate every descriptor field that comes before the MAC.
pub const descriptor_size = mac_offset + crypto.mac_length;

const flag_encrypted_filenames: u8 = 1;
const flag_enc_suffix: u8 = 2;

/// Keep RAF encryption and descriptor authentication separate while retaining the user context.
const raf_key_purpose = "turbocrypt-raf-mount-v1";
const descriptor_key_purpose = "turbocrypt-raf-descriptor-mac-v1";

/// Filename settings chosen at initialization and enforced by each mount.
pub const Settings = struct {
    encrypted_filenames: bool = false,
    enc_suffix: bool = false,
};

/// Derive the context-bound RAF key without changing the version 1 key schedule.
pub fn deriveRafKey(keys: crypto.DerivedKeys) [16]u8 {
    return deriveKey(keys, raf_key_purpose);
}

/// Derive a separate key so descriptor authentication cannot overlap with RAF encryption.
pub fn deriveDescriptorKey(keys: crypto.DerivedKeys) [16]u8 {
    return deriveKey(keys, descriptor_key_purpose);
}

fn deriveKey(keys: crypto.DerivedKeys, purpose: []const u8) [16]u8 {
    // These fixed labels stay within the helper's 120-byte input limit.
    return aegis_raf.deriveMasterKey(16, &keys.encryption_key, purpose) catch unreachable;
}

fn buildSettings(settings: Settings) [settings_length]u8 {
    var plain: [settings_length]u8 = undefined;
    mem.writeInt(u32, plain[0..4], data_chunk_size, .little);
    var flags: u8 = 0;
    if (settings.encrypted_filenames) flags |= flag_encrypted_filenames;
    if (settings.enc_suffix) flags |= flag_enc_suffix;
    plain[4] = flags;
    return plain;
}

fn parseSettings(plain: [settings_length]u8) Error!Settings {
    if (mem.readInt(u32, plain[0..4], .little) != data_chunk_size) {
        return error.UnsupportedDescriptor;
    }
    const flags = plain[4];
    if (flags & ~(flag_encrypted_filenames | flag_enc_suffix) != 0) {
        return error.UnsupportedDescriptor;
    }
    return .{
        .encrypted_filenames = flags & flag_encrypted_filenames != 0,
        .enc_suffix = flags & flag_enc_suffix != 0,
    };
}

/// Include random data in the MAC only; it does not serve as a nonce.
fn encodeDescriptor(
    plain: [settings_length]u8,
    random_field: [random_length]u8,
    key: [16]u8,
) [descriptor_size]u8 {
    var out: [descriptor_size]u8 = undefined;
    out[0..magic.len].* = magic.*;
    mem.writeInt(u32, out[magic.len..prefix_length], descriptor_version, .little);
    out[random_offset..settings_offset].* = random_field;
    out[settings_offset..mac_offset].* = plain;
    out[mac_offset..].* = crypto.keyedMac(out[0..mac_offset], key);
    return out;
}

/// Identify future descriptor versions before checking their size so callers can report them clearly.
/// Do not trust settings until the descriptor authenticates.
fn decodeDescriptor(bytes: []const u8, key: [16]u8) Error!Settings {
    if (bytes.len < prefix_length or !mem.eql(u8, bytes[0..magic.len], magic)) {
        return error.InvalidDescriptor;
    }
    if (mem.readInt(u32, bytes[magic.len..prefix_length], .little) != descriptor_version) {
        return error.UnsupportedDescriptor;
    }
    if (bytes.len != descriptor_size) return error.InvalidDescriptor;
    const expected = crypto.keyedMac(bytes[0..mac_offset], key);
    const actual = bytes[mac_offset..descriptor_size].*;
    if (!std.crypto.timing_safe.eql([crypto.mac_length]u8, expected, actual)) {
        return error.AuthenticationFailed;
    }
    return parseSettings(bytes[settings_offset..mac_offset].*);
}

/// Write a new descriptor to an open, empty file.
/// The caller is responsible for publishing and syncing it.
pub fn writeDescriptor(file: Io.File, io: Io, descriptor_key: [16]u8, settings: Settings) !void {
    var random_field: [random_length]u8 = undefined;
    io.random(&random_field);
    const bytes = encodeDescriptor(buildSettings(settings), random_field, descriptor_key);
    try file.writePositionalAll(io, &bytes, 0);
}

/// Read and authenticate settings while preserving I/O errors for useful diagnostics.
///
/// Check the entry before opening it to avoid blocking on FIFOs or devices.
/// Read one extra byte so oversized descriptors cannot be accepted.
pub fn readDescriptor(dir: Io.Dir, io: Io, descriptor_key: [16]u8) !Settings {
    const stat = dir.statFile(io, descriptor_name, .{
        .follow_symlinks = false,
    }) catch |err| switch (err) {
        error.FileNotFound => return error.DescriptorMissing,
        else => return err,
    };
    if (stat.kind != .file) return error.InvalidDescriptor;

    const file = try dir.openFile(io, descriptor_name, .{
        .follow_symlinks = false,
        .allow_directory = false,
    });
    defer file.close(io);
    var buffer: [descriptor_size + 1]u8 = undefined;
    const n = try file.readPositionalAll(io, &buffer, 0);
    return decodeDescriptor(buffer[0..n], descriptor_key);
}

/// Find the reserved name regardless of entry type without needing a key.
pub fn hasDescriptorAt(dir: Io.Dir, io: Io, sub_path: []const u8) bool {
    var buffer: [Io.Dir.max_path_bytes]u8 = undefined;
    const joined = Io.Dir.path.fmtJoin(&.{ sub_path, descriptor_name });
    const marker = mem.print(&buffer, "{f}", .{joined}) catch return false;
    _ = dir.statFile(io, marker, .{ .follow_symlinks = false }) catch return false;
    return true;
}

pub const Enclosure = struct {
    /// Owns the canonical path that `root` slices.
    path: []u8,
    /// Identifies the container root at this path or one of its ancestors.
    root: []const u8,

    pub fn isRoot(self: Enclosure) bool {
        return self.root.len == self.path.len;
    }

    pub fn deinit(self: Enclosure, gpa: Allocator) void {
        gpa.free(self.path);
    }
};

/// Find the enclosing container, including for a destination that does not exist yet.
/// Caller owns returned memory.
pub fn enclosingRoot(gpa: Allocator, io: Io, path: []const u8) !?Enclosure {
    const canonical = try fs.canonicalizePotentialPath(gpa, io, path);
    var current: []const u8 = canonical;
    while (true) {
        if (hasDescriptorAt(.cwd(), io, current)) return .{ .path = canonical, .root = current };
        current = Io.Dir.path.dirname(current) orelse {
            gpa.free(canonical);
            return null;
        };
    }
}

pub fn explainRefusal(operand: []const u8, root: []const u8) void {
    if (mem.eql(u8, operand, root)) {
        std.debug.print(
            "Error: {s} is a TurboCrypt container, made with \"turbocrypt init\"\n",
            .{operand},
        );
    } else {
        std.debug.print("Error: {s} is inside the TurboCrypt container {s}\n", .{ operand, root });
    }
    std.debug.print("       The ordinary commands do not read or write containers.\n", .{});
    std.debug.print("       Mount it and copy the files through the mounted view:\n", .{});
    std.debug.print("         turbocrypt mount {s} <mountpoint>\n", .{root});
}

test "settings round-trip for every flag combination" {
    for ([_]Settings{
        .{},
        .{ .encrypted_filenames = true },
        .{ .enc_suffix = true },
        .{ .encrypted_filenames = true, .enc_suffix = true },
    }) |settings| {
        try testing.expectEqual(settings, try parseSettings(buildSettings(settings)));
    }
}

test "the two key derivations are pinned, distinct, and depend on the context" {
    const keys = crypto.deriveKeys(@splat(0x42), null);
    const raf_key = deriveRafKey(keys);
    const descriptor_key = deriveDescriptorKey(keys);

    for ([_]struct { key: [16]u8, pinned: []const u8 }{
        .{ .key = raf_key, .pinned = "89da9eb1f532aee295557394b3087dd7" },
        .{ .key = descriptor_key, .pinned = "443ce932e8cd3085d6e3e03da31ca8e1" },
    }) |case| {
        var pinned: [16]u8 = undefined;
        _ = try std.fmt.hexToBytes(&pinned, case.pinned);
        try testing.expectEqualSlices(u8, &pinned, &case.key);
        try testing.expect(!mem.eql(u8, &case.key, &keys.encryption_key));
    }

    const other = crypto.deriveKeys(@splat(0x42), "project");
    try testing.expect(!mem.eql(u8, &raf_key, &deriveRafKey(other)));
    try testing.expect(!mem.eql(u8, &descriptor_key, &deriveDescriptorKey(other)));
}

test "a descriptor has a fixed 65-byte layout, and every field is covered" {
    const key = deriveDescriptorKey(crypto.deriveKeys(@splat(0x42), null));
    var random_field: [random_length]u8 = undefined;
    for (&random_field, 0..) |*byte, i| byte.* = @intCast(i);
    const settings: Settings = .{ .encrypted_filenames = true, .enc_suffix = true };
    const bytes = encodeDescriptor(buildSettings(settings), random_field, key);

    // Pin this authenticated descriptor so format changes cannot slip in unnoticed.
    const pinned_hex = "747572626f63727970742d7261662d636f6e7461696e6572" ++
        "01000000" ++
        "000102030405060708090a0b0c0d0e0f" ++
        "0040000003" ++
        "7713e4d2ccbd97218de57f1203343f09";
    var pinned: [descriptor_size]u8 = undefined;
    _ = try std.fmt.hexToBytes(&pinned, pinned_hex);
    try testing.expectEqual(65, descriptor_size);
    try testing.expectEqualSlices(u8, &pinned, &bytes);
    try testing.expectEqual(settings, try decodeDescriptor(&bytes, key));

    var damaged = bytes;
    damaged[0] ^= 1;
    try testing.expectError(error.InvalidDescriptor, decodeDescriptor(&damaged, key));
    damaged = bytes;
    mem.writeInt(u32, damaged[magic.len..prefix_length], 2, .little);
    try testing.expectError(error.UnsupportedDescriptor, decodeDescriptor(&damaged, key));
    for ([_]usize{
        random_offset,
        settings_offset,
        settings_offset + 4,
        mac_offset,
        descriptor_size - 1,
    }) |offset| {
        damaged = bytes;
        damaged[offset] ^= 1;
        try testing.expectError(error.AuthenticationFailed, decodeDescriptor(&damaged, key));
    }
    const wrong_key = deriveDescriptorKey(crypto.deriveKeys(@splat(0x43), null));
    try testing.expectError(error.AuthenticationFailed, decodeDescriptor(&bytes, wrong_key));
    const raf_key = deriveRafKey(crypto.deriveKeys(@splat(0x42), null));
    try testing.expectError(error.AuthenticationFailed, decodeDescriptor(&bytes, raf_key));

    // Preserve the unsupported-version result even when a future layout changes size.
    const truncated = bytes[0 .. descriptor_size - 1];
    try testing.expectError(error.InvalidDescriptor, decodeDescriptor(truncated, key));
    const too_short = bytes[0 .. prefix_length - 1];
    try testing.expectError(error.InvalidDescriptor, decodeDescriptor(too_short, key));
    var longer: [descriptor_size + 7]u8 = @splat(0);
    @memcpy(longer[0..descriptor_size], &bytes);
    try testing.expectError(error.InvalidDescriptor, decodeDescriptor(&longer, key));
    mem.writeInt(u32, longer[magic.len..prefix_length], 2, .little);
    try testing.expectError(error.UnsupportedDescriptor, decodeDescriptor(&longer, key));

    // Authentication must not make unsupported settings acceptable.
    for ([_]usize{ 0, 4 }) |offset| {
        var plain = buildSettings(.{});
        plain[offset] ^= 4;
        const future = encodeDescriptor(plain, random_field, key);
        try testing.expectError(error.UnsupportedDescriptor, decodeDescriptor(&future, key));
    }
}

test "a descriptor round-trips through a directory and rejects other keys, contexts and damage" {
    const io = testing.io;
    const root = "tmp/container_descriptor";
    Io.Dir.deleteTree(.cwd(), io, root) catch {};
    try Io.Dir.createDirPath(.cwd(), io, root);
    defer Io.Dir.deleteTree(.cwd(), io, root) catch {};
    var dir = try Io.Dir.openDir(.cwd(), io, root, .{ .iterate = true });
    defer dir.close(io);

    const key = deriveDescriptorKey(crypto.deriveKeys(@splat(3), null));
    try testing.expectError(error.DescriptorMissing, readDescriptor(dir, io, key));
    try testing.expect(!hasDescriptorAt(dir, io, "."));

    {
        const file = try dir.createFile(io, descriptor_name, .{ .read = true, .exclusive = true });
        defer file.close(io);
        try writeDescriptor(file, io, key, .{ .enc_suffix = true });
        try testing.expectEqual(descriptor_size, try file.length(io));
    }
    try testing.expect(hasDescriptorAt(dir, io, "."));
    try testing.expectEqual(Settings{ .enc_suffix = true }, try readDescriptor(dir, io, key));

    const wrong_key = deriveDescriptorKey(crypto.deriveKeys(@splat(4), null));
    try testing.expectError(error.AuthenticationFailed, readDescriptor(dir, io, wrong_key));
    const other_context = deriveDescriptorKey(crypto.deriveKeys(@splat(3), "other"));
    try testing.expectError(error.AuthenticationFailed, readDescriptor(dir, io, other_context));

    {
        const file = try dir.openFile(io, descriptor_name, .{ .mode = .read_write });
        defer file.close(io);
        var byte: [1]u8 = undefined;
        _ = try file.readPositionalAll(io, &byte, mac_offset);
        byte[0] ^= 1;
        try file.writePositionalAll(io, &byte, mac_offset);
        try testing.expectError(error.AuthenticationFailed, readDescriptor(dir, io, key));
        byte[0] ^= 1;
        try file.writePositionalAll(io, &byte, mac_offset);
        try testing.expectEqual(Settings{ .enc_suffix = true }, try readDescriptor(dir, io, key));
        try file.writePositionalAll(io, "x", descriptor_size);
        try testing.expectError(error.InvalidDescriptor, readDescriptor(dir, io, key));
        try file.setLength(io, descriptor_size - 1);
        try testing.expectError(error.InvalidDescriptor, readDescriptor(dir, io, key));
    }

    try dir.deleteFile(io, descriptor_name);
    try dir.createDir(io, descriptor_name, .default_dir);
    try testing.expect(hasDescriptorAt(dir, io, "."));
    try testing.expectError(error.InvalidDescriptor, readDescriptor(dir, io, key));
    try dir.deleteDir(io, descriptor_name);

    dir.symLink(io, "elsewhere", descriptor_name, .{}) catch return;
    try testing.expect(hasDescriptorAt(dir, io, "."));
    try testing.expectError(error.InvalidDescriptor, readDescriptor(dir, io, key));
}

test "the enclosing root is found at the path, at an ancestor, or not at all" {
    const gpa = testing.allocator;
    const io = testing.io;
    const root = "tmp/container_enclosing";
    Io.Dir.deleteTree(.cwd(), io, root) catch {};
    try Io.Dir.createDirPath(.cwd(), io, root ++ "/box/deep/er");
    try Io.Dir.createDirPath(.cwd(), io, root ++ "/plain/sub");
    defer Io.Dir.deleteTree(.cwd(), io, root) catch {};
    try Io.Dir.writeFile(.cwd(), io, .{
        .sub_path = root ++ "/box/" ++ descriptor_name,
        .data = "any content marks it",
    });

    const expected = try Io.Dir.realPathFileAlloc(.cwd(), io, root ++ "/box", gpa);
    defer gpa.free(expected);

    const at_root = (try enclosingRoot(gpa, io, root ++ "/box")).?;
    defer at_root.deinit(gpa);
    try testing.expectEqualStrings(expected, at_root.root);
    try testing.expectEqualStrings(expected, at_root.path);
    try testing.expect(at_root.isRoot());
    for ([_][]const u8{ root ++ "/box/deep/er", root ++ "/box/missing/yet" }) |path| {
        const inside = (try enclosingRoot(gpa, io, path)).?;
        defer inside.deinit(gpa);
        try testing.expectEqualStrings(expected, inside.root);
        try testing.expect(!inside.isRoot());
        try testing.expect(mem.startsWith(u8, inside.path, expected));
    }
    try testing.expectEqual(null, try enclosingRoot(gpa, io, root ++ "/plain/sub"));
    try testing.expectEqual(null, try enclosingRoot(gpa, io, root ++ "/plain/new"));

    var parent = try Io.Dir.openDir(.cwd(), io, root, .{});
    defer parent.close(io);
    try testing.expect(hasDescriptorAt(parent, io, "box"));
    try testing.expect(!hasDescriptorAt(parent, io, "plain"));
    try testing.expect(!hasDescriptorAt(parent, io, "missing"));
    try testing.expect(hasDescriptorAt(.cwd(), io, root ++ "/box"));
    try testing.expect(hasDescriptorAt(.cwd(), io, expected));
}
