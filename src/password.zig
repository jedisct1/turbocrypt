const std = @import("std");

pub const salt = "turbocrypt";

const argon2 = std.crypto.pwhash.argon2;

/// Derive 20 bytes from a password with Argon2id.
/// The first 16 bytes mask the key and the last 4 bytes are a checksum.
pub fn deriveKey(password: []const u8) ![20]u8 {
    var key: [20]u8 = undefined;

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
/// The result is the 16 masked bytes followed by the 4 byte checksum.
pub fn protectKey(key: [16]u8, password: []const u8) ![20]u8 {
    const derived = try deriveKey(password);

    var protected: [20]u8 = undefined;

    for (key, 0..) |byte, i| {
        protected[i] = byte ^ derived[i];
    }

    @memcpy(protected[16..20], derived[16..20]);

    return protected;
}

/// Recover a key masked with protectKey.
/// A wrong password fails the checksum and returns error.InvalidPassword.
pub fn unprotectKey(protected_data: [20]u8, password: []const u8) ![16]u8 {
    const derived = try deriveKey(password);

    const stored_checksum = protected_data[16..20];
    const expected_checksum = derived[16..20];

    if (!std.crypto.timing_safe.eql([4]u8, stored_checksum[0..4].*, expected_checksum[0..4].*)) {
        return error.InvalidPassword;
    }

    var key: [16]u8 = undefined;
    for (protected_data[0..16], 0..) |byte, i| {
        key[i] = byte ^ derived[i];
    }

    return key;
}
