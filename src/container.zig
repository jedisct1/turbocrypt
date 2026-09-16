//! Detect RAF containers and authenticate their settings, key, and context.
//!
//! Detection stays independent of FUSE so ordinary commands can refuse containers in every build.

const std = @import("std");
const aegis_raf = @import("aegis_raf");
const crypto = @import("crypto.zig");
const utils = @import("utils.zig");

pub const Error = error{
    DescriptorMissing,
    InvalidDescriptor,
    UnsupportedDescriptor,
    AuthenticationFailed,
};

/// Stored under this raw name, never through the name mapper, so detection needs no key.
pub const descriptor_name = ".turbocrypt-raf";

/// Each nonempty file occupies at least one chunk.
pub const data_chunk_size: u32 = 16384;

/// Distinguish stray files from descriptors that require a newer build.
const magic = "turbocrypt-raf-container";
const descriptor_version: u32 = 1;
const prefix_length = magic.len + 4;

/// Randomness prevents matching descriptors from linking containers that share a key.
/// Settings need authentication only: filenames and file sizes already reveal them.
const random_length = 16;
const settings_length = 4 + 1;
const random_offset = prefix_length;
const settings_offset = random_offset + random_length;
const mac_offset = settings_offset + settings_length;

/// The MAC covers every preceding byte.
pub const descriptor_size = mac_offset + crypto.mac_length;

const flag_encrypted_filenames: u8 = 1;
const flag_enc_suffix: u8 = 2;

/// Separate the two key uses; `crypto.deriveKeys` already binds the user context.
const raf_key_purpose = "turbocrypt-raf-mount-v1";
const descriptor_key_purpose = "turbocrypt-raf-descriptor-mac-v1";

/// The filename settings fixed at initialization. A mount takes them from the descriptor.
pub const Settings = struct {
    encrypted_filenames: bool = false,
    enc_suffix: bool = false,
};

/// Derive a context-bound RAF key without changing the v1 key schedule.
pub fn deriveRafKey(keys: crypto.DerivedKeys) [16]u8 {
    return deriveKey(keys, raf_key_purpose);
}

/// Keep descriptor MACs separate from RAF encryption while authenticating the same key and context.
pub fn deriveDescriptorKey(keys: crypto.DerivedKeys) [16]u8 {
    return deriveKey(keys, descriptor_key_purpose);
}

fn deriveKey(keys: crypto.DerivedKeys, purpose: []const u8) [16]u8 {
    // Fixed purposes satisfy the helper's 120-byte limit.
    return aegis_raf.deriveMasterKey(16, &keys.encryption_key, purpose) catch unreachable;
}

fn buildSettings(settings: Settings) [settings_length]u8 {
    var plain: [settings_length]u8 = undefined;
    std.mem.writeInt(u32, plain[0..4], data_chunk_size, .little);
    var flags: u8 = 0;
    if (settings.encrypted_filenames) flags |= flag_encrypted_filenames;
    if (settings.enc_suffix) flags |= flag_enc_suffix;
    plain[4] = flags;
    return plain;
}

fn parseSettings(plain: [settings_length]u8) Error!Settings {
    if (std.mem.readInt(u32, plain[0..4], .little) != data_chunk_size) return error.UnsupportedDescriptor;
    const flags = plain[4];
    if (flags & ~(flag_encrypted_filenames | flag_enc_suffix) != 0) return error.UnsupportedDescriptor;
    return .{
        .encrypted_filenames = flags & flag_encrypted_filenames != 0,
        .enc_suffix = flags & flag_enc_suffix != 0,
    };
}

/// The random field is MAC input, not a nonce.
fn encodeDescriptor(plain: [settings_length]u8, random_field: [random_length]u8, key: [16]u8) [descriptor_size]u8 {
    var out: [descriptor_size]u8 = undefined;
    out[0..magic.len].* = magic.*;
    std.mem.writeInt(u32, out[magic.len..prefix_length], descriptor_version, .little);
    out[random_offset..settings_offset].* = random_field;
    out[settings_offset..mac_offset].* = plain;
    out[mac_offset..].* = crypto.keyedMac(out[0..mac_offset], key);
    return out;
}

/// Recognize future versions before checking their size, so they report as unsupported.
/// Trust settings only after authentication.
fn decodeDescriptor(bytes: []const u8, key: [16]u8) Error!Settings {
    if (bytes.len < prefix_length or !std.mem.eql(u8, bytes[0..magic.len], magic)) return error.InvalidDescriptor;
    if (std.mem.readInt(u32, bytes[magic.len..prefix_length], .little) != descriptor_version) return error.UnsupportedDescriptor;
    if (bytes.len != descriptor_size) return error.InvalidDescriptor;
    const expected = crypto.keyedMac(bytes[0..mac_offset], key);
    if (!std.crypto.timing_safe.eql([crypto.mac_length]u8, expected, bytes[mac_offset..descriptor_size].*)) return error.AuthenticationFailed;
    return parseSettings(bytes[settings_offset..mac_offset].*);
}

/// Write a fresh descriptor into an open, empty file. The caller publishes and syncs it.
pub fn writeDescriptorFile(file: std.Io.File, descriptor_key: [16]u8, settings: Settings, io: std.Io) !void {
    var random_field: [random_length]u8 = undefined;
    io.random(&random_field);
    const bytes = encodeDescriptor(buildSettings(settings), random_field, descriptor_key);
    try file.writePositionalAll(io, &bytes, 0);
}

/// Authenticate settings, preserving I/O errors for the caller's diagnostic.
///
/// Stat before opening to reject FIFOs and devices without blocking.
/// Read an extra byte to reject oversized files.
pub fn readDescriptor(dir: std.Io.Dir, descriptor_key: [16]u8, io: std.Io) !Settings {
    const st = dir.statFile(io, descriptor_name, .{ .follow_symlinks = false }) catch |err| switch (err) {
        error.FileNotFound => return error.DescriptorMissing,
        else => return err,
    };
    if (st.kind != .file) return error.InvalidDescriptor;

    const file = try dir.openFile(io, descriptor_name, .{ .follow_symlinks = false, .allow_directory = false });
    defer file.close(io);
    var buffer: [descriptor_size + 1]u8 = undefined;
    const n = try file.readPositionalAll(io, &buffer, 0);
    return decodeDescriptor(buffer[0..n], descriptor_key);
}

/// Detect the reserved name regardless of entry type, without needing a key.
pub fn hasDescriptorAt(dir: std.Io.Dir, io: std.Io, sub_path: []const u8) bool {
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const marker = std.fmt.bufPrint(&buffer, "{f}", .{std.fs.path.fmtJoin(&.{ sub_path, descriptor_name })}) catch return false;
    _ = dir.statFile(io, marker, .{ .follow_symlinks = false }) catch return false;
    return true;
}

pub const Enclosure = struct {
    /// Owned canonical path; `root` borrows a slice of it.
    path: []u8,
    /// The container root: the path itself, or one of its ancestors.
    root: []const u8,

    pub fn isRoot(self: Enclosure) bool {
        return self.root.len == self.path.len;
    }

    pub fn deinit(self: Enclosure, allocator: std.mem.Allocator) void {
        allocator.free(self.path);
    }
};

/// Find the enclosing container, including for a destination that doesn't exist yet.
/// The caller owns the result.
pub fn enclosingRoot(path: []const u8, allocator: std.mem.Allocator, io: std.Io) !?Enclosure {
    const canonical = try utils.canonicalizePotentialPath(path, allocator, io);
    var current: []const u8 = canonical;
    while (true) {
        if (hasDescriptorAt(.cwd(), io, current)) return .{ .path = canonical, .root = current };
        current = std.fs.path.dirname(current) orelse {
            allocator.free(canonical);
            return null;
        };
    }
}

pub fn explainRefusal(operand: []const u8, root: []const u8) void {
    if (std.mem.eql(u8, operand, root)) {
        std.debug.print("Error: {s} is a TurboCrypt container, made with \"turbocrypt init\"\n", .{operand});
    } else {
        std.debug.print("Error: {s} is inside the TurboCrypt container {s}\n", .{ operand, root });
    }
    std.debug.print("       The ordinary commands do not read or write containers.\n", .{});
    std.debug.print("       Mount it and copy the files through the mounted view:\n", .{});
    std.debug.print("         turbocrypt mount {s} <mountpoint>\n", .{root});
}

const testing = std.testing;

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
        try testing.expect(!std.mem.eql(u8, &case.key, &keys.encryption_key));
    }

    const other = crypto.deriveKeys(@splat(0x42), "project");
    try testing.expect(!std.mem.eql(u8, &raf_key, &deriveRafKey(other)));
    try testing.expect(!std.mem.eql(u8, &descriptor_key, &deriveDescriptorKey(other)));
}

test "a descriptor has a fixed 65-byte layout, and every field is covered" {
    const key = deriveDescriptorKey(crypto.deriveKeys(@splat(0x42), null));
    var random_field: [random_length]u8 = undefined;
    for (&random_field, 0..) |*byte, i| byte.* = @intCast(i);
    const settings: Settings = .{ .encrypted_filenames = true, .enc_suffix = true };
    const bytes = encodeDescriptor(buildSettings(settings), random_field, key);

    // Fixed AEGIS-128X2-MAC vector to detect accidental format changes.
    var pinned: [descriptor_size]u8 = undefined;
    _ = try std.fmt.hexToBytes(&pinned, "747572626f63727970742d7261662d636f6e7461696e6572" ++ "01000000" ++
        "000102030405060708090a0b0c0d0e0f" ++ "0040000003" ++ "7713e4d2ccbd97218de57f1203343f09");
    try testing.expectEqual(65, descriptor_size);
    try testing.expectEqualSlices(u8, &pinned, &bytes);
    try testing.expectEqual(settings, try decodeDescriptor(&bytes, key));

    var damaged = bytes;
    damaged[0] ^= 1;
    try testing.expectError(error.InvalidDescriptor, decodeDescriptor(&damaged, key));
    damaged = bytes;
    std.mem.writeInt(u32, damaged[magic.len..prefix_length], 2, .little);
    try testing.expectError(error.UnsupportedDescriptor, decodeDescriptor(&damaged, key));
    for ([_]usize{ random_offset, settings_offset, settings_offset + 4, mac_offset, descriptor_size - 1 }) |offset| {
        damaged = bytes;
        damaged[offset] ^= 1;
        try testing.expectError(error.AuthenticationFailed, decodeDescriptor(&damaged, key));
    }
    const wrong_key = deriveDescriptorKey(crypto.deriveKeys(@splat(0x43), null));
    try testing.expectError(error.AuthenticationFailed, decodeDescriptor(&bytes, wrong_key));
    const raf_key = deriveRafKey(crypto.deriveKeys(@splat(0x42), null));
    try testing.expectError(error.AuthenticationFailed, decodeDescriptor(&bytes, raf_key));

    // Future layouts must report as unsupported even when their size differs.
    try testing.expectError(error.InvalidDescriptor, decodeDescriptor(bytes[0 .. descriptor_size - 1], key));
    try testing.expectError(error.InvalidDescriptor, decodeDescriptor(bytes[0 .. prefix_length - 1], key));
    var longer: [descriptor_size + 7]u8 = @splat(0);
    @memcpy(longer[0..descriptor_size], &bytes);
    try testing.expectError(error.InvalidDescriptor, decodeDescriptor(&longer, key));
    std.mem.writeInt(u32, longer[magic.len..prefix_length], 2, .little);
    try testing.expectError(error.UnsupportedDescriptor, decodeDescriptor(&longer, key));

    // Valid MACs must not admit unsupported settings.
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
    std.Io.Dir.deleteTree(.cwd(), io, root) catch {};
    try std.Io.Dir.createDirPath(.cwd(), io, root);
    defer std.Io.Dir.deleteTree(.cwd(), io, root) catch {};
    var dir = try std.Io.Dir.openDir(.cwd(), io, root, .{ .iterate = true });
    defer dir.close(io);

    const key = deriveDescriptorKey(crypto.deriveKeys(@splat(3), null));
    try testing.expectError(error.DescriptorMissing, readDescriptor(dir, key, io));
    try testing.expect(!hasDescriptorAt(dir, io, "."));

    {
        const file = try dir.createFile(io, descriptor_name, .{ .read = true, .exclusive = true });
        defer file.close(io);
        try writeDescriptorFile(file, key, .{ .enc_suffix = true }, io);
        try testing.expectEqual(descriptor_size, try file.length(io));
    }
    try testing.expect(hasDescriptorAt(dir, io, "."));
    try testing.expectEqual(Settings{ .enc_suffix = true }, try readDescriptor(dir, key, io));

    const wrong_key = deriveDescriptorKey(crypto.deriveKeys(@splat(4), null));
    try testing.expectError(error.AuthenticationFailed, readDescriptor(dir, wrong_key, io));
    const other_context = deriveDescriptorKey(crypto.deriveKeys(@splat(3), "other"));
    try testing.expectError(error.AuthenticationFailed, readDescriptor(dir, other_context, io));

    {
        const file = try dir.openFile(io, descriptor_name, .{ .mode = .read_write });
        defer file.close(io);
        var byte: [1]u8 = undefined;
        _ = try file.readPositionalAll(io, &byte, mac_offset);
        byte[0] ^= 1;
        try file.writePositionalAll(io, &byte, mac_offset);
        try testing.expectError(error.AuthenticationFailed, readDescriptor(dir, key, io));
        byte[0] ^= 1;
        try file.writePositionalAll(io, &byte, mac_offset);
        try testing.expectEqual(Settings{ .enc_suffix = true }, try readDescriptor(dir, key, io));
        try file.writePositionalAll(io, "x", descriptor_size);
        try testing.expectError(error.InvalidDescriptor, readDescriptor(dir, key, io));
        try file.setLength(io, descriptor_size - 1);
        try testing.expectError(error.InvalidDescriptor, readDescriptor(dir, key, io));
    }

    try dir.deleteFile(io, descriptor_name);
    try dir.createDir(io, descriptor_name, .default_dir);
    try testing.expect(hasDescriptorAt(dir, io, "."));
    try testing.expectError(error.InvalidDescriptor, readDescriptor(dir, key, io));
    try dir.deleteDir(io, descriptor_name);

    dir.symLink(io, "elsewhere", descriptor_name, .{}) catch return;
    try testing.expect(hasDescriptorAt(dir, io, "."));
    try testing.expectError(error.InvalidDescriptor, readDescriptor(dir, key, io));
}

test "the enclosing root is found at the path, at an ancestor, or not at all" {
    const allocator = testing.allocator;
    const io = testing.io;
    const root = "tmp/container_enclosing";
    std.Io.Dir.deleteTree(.cwd(), io, root) catch {};
    try std.Io.Dir.createDirPath(.cwd(), io, root ++ "/box/deep/er");
    try std.Io.Dir.createDirPath(.cwd(), io, root ++ "/plain/sub");
    defer std.Io.Dir.deleteTree(.cwd(), io, root) catch {};
    try std.Io.Dir.writeFile(.cwd(), io, .{ .sub_path = root ++ "/box/" ++ descriptor_name, .data = "any content marks it" });

    const expected = try std.Io.Dir.realPathFileAlloc(.cwd(), io, root ++ "/box", allocator);
    defer allocator.free(expected);

    const at_root = (try enclosingRoot(root ++ "/box", allocator, io)).?;
    defer at_root.deinit(allocator);
    try testing.expectEqualStrings(expected, at_root.root);
    try testing.expectEqualStrings(expected, at_root.path);
    try testing.expect(at_root.isRoot());
    for ([_][]const u8{ root ++ "/box/deep/er", root ++ "/box/missing/yet" }) |path| {
        const inside = (try enclosingRoot(path, allocator, io)).?;
        defer inside.deinit(allocator);
        try testing.expectEqualStrings(expected, inside.root);
        try testing.expect(!inside.isRoot());
        try testing.expect(std.mem.startsWith(u8, inside.path, expected));
    }
    try testing.expectEqual(null, try enclosingRoot(root ++ "/plain/sub", allocator, io));
    try testing.expectEqual(null, try enclosingRoot(root ++ "/plain/new", allocator, io));

    var parent = try std.Io.Dir.openDir(.cwd(), io, root, .{});
    defer parent.close(io);
    try testing.expect(hasDescriptorAt(parent, io, "box"));
    try testing.expect(!hasDescriptorAt(parent, io, "plain"));
    try testing.expect(!hasDescriptorAt(parent, io, "missing"));
    try testing.expect(hasDescriptorAt(.cwd(), io, root ++ "/box"));
    try testing.expect(hasDescriptorAt(.cwd(), io, expected));
}
