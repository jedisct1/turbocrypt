const std = @import("std");
const crypto = @import("crypto.zig");

const argon2 = std.crypto.pwhash.argon2;
const key_length = crypto.key_length;
const derived_key_length = 20;
const checksum_length = derived_key_length - key_length;
const legacy_salt = "turbocrypt";

const salt_length = 16;
pub const legacy_protected_key_size = derived_key_length;
pub const protected_key_size = salt_length + key_length + checksum_length;

/// Derive 20 bytes from a password with Argon2id.
/// The first 16 bytes mask the key and the last 4 bytes are a checksum.
pub fn deriveKey(password: []const u8, salt: []const u8) ![derived_key_length]u8 {
    var key: [derived_key_length]u8 = undefined;

    var threaded_io = std.Io.Threaded.init(std.heap.page_allocator, .{ .environ = .empty });
    defer threaded_io.deinit();

    try argon2.kdf(
        std.heap.page_allocator,
        &key,
        password,
        salt,
        argon2.Params.interactive_2id,
        .argon2id,
        threaded_io.io(),
    );

    return key;
}

/// Mask a key with a password.
/// The result is the salt, 16 masked bytes, and the 4 byte checksum.
pub fn protectKey(key: [key_length]u8, password: []const u8, io: std.Io) ![protected_key_size]u8 {
    var salt: [salt_length]u8 = undefined;
    io.random(&salt);

    const derived = try deriveKey(password, &salt);

    var protected: [protected_key_size]u8 = undefined;
    @memcpy(protected[0..salt_length], &salt);

    for (key, 0..) |byte, i| {
        protected[salt_length + i] = byte ^ derived[i];
    }

    @memcpy(protected[salt_length + key_length ..], derived[key_length..]);

    return protected;
}

/// Recover a key masked with protectKey.
/// A wrong password fails the checksum and returns error.InvalidPassword.
pub fn unprotectKey(protected_data: []const u8, password: []const u8) ![key_length]u8 {
    const salt, const payload = if (protected_data.len == protected_key_size)
        .{ protected_data[0..salt_length], protected_data[salt_length..] }
    else if (protected_data.len == legacy_protected_key_size)
        .{ legacy_salt, protected_data }
    else
        return error.InvalidKeyFile;

    const derived = try deriveKey(password, salt);

    const stored_checksum = payload[key_length..][0..checksum_length];
    const expected_checksum = derived[key_length..];

    if (!std.crypto.timing_safe.eql([checksum_length]u8, stored_checksum.*, expected_checksum.*)) {
        return error.InvalidPassword;
    }

    var key: [key_length]u8 = undefined;
    for (payload[0..key_length], 0..) |byte, i| {
        key[i] = byte ^ derived[i];
    }

    return key;
}

/// A key protected by a release that used the fixed salt, for compatibility tests.
pub const legacy_test_vector = struct {
    pub const passphrase = "legacy password";
    pub const protected = [legacy_protected_key_size]u8{
        0x44, 0x22, 0x75, 0x00, 0x44, 0x72, 0xdb, 0xee, 0x8f, 0x2d,
        0x59, 0x09, 0x46, 0x24, 0x00, 0x9d, 0x10, 0xc8, 0xcc, 0x53,
    };
    pub const key: [key_length]u8 = std.simd.iota(u8, key_length);
};

test "protecting the same key twice uses different salts" {
    const key: [key_length]u8 = @splat(0x5a);
    const first = try protectKey(key, "same password", std.testing.io);
    const second = try protectKey(key, "same password", std.testing.io);

    try std.testing.expect(!std.mem.eql(u8, first[0..salt_length], second[0..salt_length]));
}

test "legacy protected keys remain readable" {
    const v = legacy_test_vector;
    try std.testing.expectEqualSlices(u8, &v.key, &try unprotectKey(&v.protected, v.passphrase));
}
