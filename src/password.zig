const std = @import("std");

/// Fixed salt for Argon2id key derivation
pub const SALT = "turbocrypt";

const Argon2 = std.crypto.pwhash.argon2;

/// Derive a 16-byte key from a password using Argon2id
/// Uses the standard interactive_2id parameters: t=2, m=64MB, p=1
pub fn deriveKey(password: []const u8) ![16]u8 {
    var key: [16]u8 = undefined;

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

/// XOR a key with password-derived material
pub fn xorKey(key: *[16]u8, password: []const u8) !void {
    const derived = try deriveKey(password);
    for (key, 0..) |*byte, i| {
        byte.* ^= derived[i];
    }
}

/// Protect a key with a password (XOR with Argon2id output)
pub fn protectKey(key: [16]u8, password: []const u8) ![16]u8 {
    var protected = key;
    try xorKey(&protected, password);
    return protected;
}

/// Unprotect a password-protected key (XOR with Argon2id output)
pub fn unprotectKey(protected_key: [16]u8, password: []const u8) ![16]u8 {
    return protectKey(protected_key, password);
}
