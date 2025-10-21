const std = @import("std");

/// Fixed salt for Argon2id key derivation
pub const SALT = "turbocrypt";

const Argon2 = std.crypto.pwhash.argon2;

/// Derive 20 bytes from a password using Argon2id
/// First 16 bytes are used for XOR, last 4 bytes are used as checksum
/// Uses the standard interactive_2id parameters: t=2, m=64MB, p=1
pub fn deriveKey(password: []const u8) ![20]u8 {
    var key: [20]u8 = undefined;

    try Argon2.kdf(
        std.heap.page_allocator,
        &key,
        password,
        SALT,
        Argon2.Params.interactive_2id,
        .argon2id,
    );

    return key;
}

/// Protect a key with a password
/// Returns 20 bytes: [16 bytes XOR'd key][4 bytes checksum]
pub fn protectKey(key: [16]u8, password: []const u8) ![20]u8 {
    const derived = try deriveKey(password);

    var protected: [20]u8 = undefined;

    // XOR the key with first 16 bytes
    for (key, 0..) |byte, i| {
        protected[i] = byte ^ derived[i];
    }

    // Copy checksum (last 4 bytes)
    @memcpy(protected[16..20], derived[16..20]);

    return protected;
}

/// Unprotect a password-protected key
/// Returns error.InvalidPassword if checksum doesn't match
pub fn unprotectKey(protected_data: [20]u8, password: []const u8) ![16]u8 {
    const derived = try deriveKey(password);

    // Verify checksum (last 4 bytes)
    const stored_checksum = protected_data[16..20];
    const expected_checksum = derived[16..20];

    if (!std.crypto.timing_safe.eql([4]u8, stored_checksum[0..4].*, expected_checksum[0..4].*)) {
        return error.InvalidPassword;
    }

    // XOR to recover the key
    var key: [16]u8 = undefined;
    for (protected_data[0..16], 0..) |byte, i| {
        key[i] = byte ^ derived[i];
    }

    return key;
}
