//! Protects encryption keys with passwords using Argon2id.

const std = @import("std");
const testing = std.testing;
const Io = std.Io;
const argon2 = std.crypto.pwhash.argon2;

const crypto = @import("crypto.zig");

const key_length = crypto.key_length;
const derived_key_length = 20;
const checksum_length = derived_key_length - key_length;
const salt_length = 16;
const legacy_salt = "turbocrypt";

pub const legacy_protected_key_size = derived_key_length;
pub const protected_key_size = salt_length + key_length + checksum_length;

/// Derive enough password material to mask a key and verify the password.
pub fn deriveKey(password: []const u8, salt: []const u8) ![derived_key_length]u8 {
    var key: [derived_key_length]u8 = undefined;

    var threaded: Io.Threaded = .init(std.heap.page_allocator, .{ .environ = .empty });
    defer threaded.deinit();

    try argon2.kdf(
        std.heap.page_allocator,
        &key,
        password,
        salt,
        .interactive_2id,
        .argon2id,
        threaded.io(),
    );
    return key;
}

/// Protect a key with a password and a fresh salt to prevent matching password checks.
pub fn protectKey(io: Io, key: [key_length]u8, password: []const u8) ![protected_key_size]u8 {
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

/// Recover a key protected by `protectKey`.
/// Reject a wrong password before returning key material.
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

/// Legacy fixed-salt data retained to ensure older protected keys stay readable.
pub const legacy_test_vector = struct {
    pub const passphrase = "legacy password";
    pub const protected = [legacy_protected_key_size]u8{
        0x44, 0x22, 0x75, 0x00, 0x44, 0x72, 0xdb, 0xee, 0x8f, 0x2d,
        0x59, 0x09, 0x46, 0x24, 0x00, 0x9d, 0x10, 0xc8, 0xcc, 0x53,
    };
    pub const key: [key_length]u8 = std.simd.iota(u8, key_length);
};

test "protecting the same key twice uses different salts" {
    const io = testing.io;
    const key: [key_length]u8 = @splat(0x5a);
    const first = try protectKey(io, key, "same password");
    const second = try protectKey(io, key, "same password");
    try testing.expect(!std.mem.eql(u8, first[0..salt_length], second[0..salt_length]));
}

test "legacy protected keys remain readable" {
    const legacy = legacy_test_vector;
    const key = try unprotectKey(&legacy.protected, legacy.passphrase);
    try testing.expectEqualSlices(u8, &legacy.key, &key);
}
