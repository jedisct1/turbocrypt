//! Encrypts files with AEGIS-128X2 and derives keys with TurboSHAKE128.

const std = @import("std");
const assert = std.debug.assert;
const mem = std.mem;
const testing = std.testing;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const Aegis128X2 = std.crypto.aead.aegis.Aegis128X2;
const Aegis128X2Mac_128 = std.crypto.auth.aegis.Aegis128X2Mac_128;
const TurboShake128 = std.crypto.hash.sha3.TurboShake128(null);

pub const key_length = 16;
pub const nonce_length = 16;
pub const tag_length = 16;
pub const mac_length = 16;
pub const fingerprint_length = mac_length;
pub const cipher_id_length = mac_length;
pub const header_size = nonce_length + mac_length;
pub const overhead_size = header_size + tag_length;

/// Bind header authentication to version 1 of the file format.
const domain_separator = "TC01";

pub const DerivedKeys = struct {
    header_mac_key: [16]u8,
    encryption_key: [16]u8,
    filename_key: [16]u8,
    fingerprint_key: [16]u8,
    cipher_id_key: [16]u8,
    key_id_key: [16]u8,
};

/// Derive independent keys from one master key.
///
/// The original three keys remain at the start of the output so existing files keep working.
/// A nonempty context isolates keys for uses such as separate directories.
/// Encryption and decryption must use the same context.
pub fn deriveKeys(master_key: [key_length]u8, context: ?[]const u8) DerivedKeys {
    var shake = TurboShake128.init(.{});

    shake.update(&master_key);
    shake.update("turbocrypt");

    if (context) |ctx| {
        if (ctx.len > 0) {
            shake.update("-");
            shake.update(ctx);
        }
    }

    var output: [96]u8 = undefined;
    shake.squeeze(&output);

    return .{
        .header_mac_key = output[0..16].*,
        .encryption_key = output[16..32].*,
        .filename_key = output[32..48].*,
        .fingerprint_key = output[48..64].*,
        .cipher_id_key = output[64..80].*,
        .key_id_key = output[80..96].*,
    };
}

/// Return a public identifier for a key.
/// It can appear in commits without exposing the key it identifies.
pub fn keyId(key_id_key: [key_length]u8) [mac_length]u8 {
    return keyedMac("key id", key_id_key);
}

/// Return a keyed fingerprint of plaintext for local change tracking.
///
/// Keying prevents a leaked state file from confirming guesses about file contents.
pub fn fingerprint(plaintext: []const u8, fingerprint_key: [key_length]u8) [fingerprint_length]u8 {
    return keyedMac(plaintext, fingerprint_key);
}

/// Identify an entire ciphertext with a MAC under a dedicated derived key.
///
/// This catches body changes that leave the nonce and authentication tag intact.
/// A key holder can already create valid ciphertext, so a MAC provides the needed guarantee.
pub fn ciphertextId(encrypted: []const u8, cipher_id_key: [key_length]u8) [cipher_id_length]u8 {
    return keyedMac(encrypted, cipher_id_key);
}

/// Authenticate arbitrary data with one derived key.
pub fn keyedMac(data: []const u8, key: [key_length]u8) [mac_length]u8 {
    var mac: [mac_length]u8 = undefined;
    Aegis128X2Mac_128.create(&mac, data, &key);
    return mac;
}

/// Authenticate the nonce with a format marker so headers cannot cross file-format versions.
fn computeHeaderMac(nonce: [nonce_length]u8, header_mac_key: [key_length]u8) [mac_length]u8 {
    var msg: [domain_separator.len + nonce_length]u8 = undefined;
    @memcpy(msg[0..domain_separator.len], domain_separator);
    @memcpy(msg[domain_separator.len..], &nonce);

    return keyedMac(&msg, header_mac_key);
}

const ParsedEncrypted = struct {
    nonce: *const [nonce_length]u8,
    stored_mac: *const [mac_length]u8,
    ciphertext: []const u8,
    tag: *const [tag_length]u8,
};

fn parseEncrypted(encrypted: []const u8) !ParsedEncrypted {
    if (encrypted.len < overhead_size) {
        return error.InvalidFileSize;
    }

    const nonce = encrypted[0..nonce_length];
    const stored_mac = encrypted[nonce_length..header_size];

    const ciphertext_len = encrypted.len - overhead_size;
    const ciphertext = encrypted[header_size..][0..ciphertext_len];
    const tag = encrypted[header_size + ciphertext_len ..][0..tag_length];

    return .{
        .nonce = nonce,
        .stored_mac = stored_mac,
        .ciphertext = ciphertext,
        .tag = tag,
    };
}

/// Return a self-contained ciphertext with its nonce, header authentication, and tag.
pub fn encrypt(
    gpa: Allocator,
    io: Io,
    plaintext: []const u8,
    derived_keys: DerivedKeys,
) ![]u8 {
    return encryptBound(gpa, io, plaintext, "", derived_keys);
}

/// Encrypt a file for one fixed relative path.
///
/// Authenticate the path so moving or swapping entries is detected during decryption.
pub fn encryptBound(
    gpa: Allocator,
    io: Io,
    plaintext: []const u8,
    path: []const u8,
    derived_keys: DerivedKeys,
) ![]u8 {
    var nonce: [nonce_length]u8 = undefined;
    io.random(&nonce);

    const header_mac = computeHeaderMac(nonce, derived_keys.header_mac_key);

    const overhead = header_size + tag_length;
    const output_size = std.math.add(usize, overhead, plaintext.len) catch {
        return error.OutputTooLarge;
    };
    const output = try gpa.alloc(u8, output_size);
    errdefer gpa.free(output);

    const ciphertext = output[header_size..][0..plaintext.len];

    var tag: [tag_length]u8 = undefined;
    Aegis128X2.encrypt(
        ciphertext,
        &tag,
        plaintext,
        path,
        nonce,
        derived_keys.encryption_key,
    );

    @memcpy(output[0..nonce_length], &nonce);
    @memcpy(output[nonce_length..header_size], &header_mac);
    @memcpy(output[header_size + plaintext.len ..][0..tag_length], &tag);

    return output;
}

/// Encrypt into caller-provided storage.
/// The output must include room for the plaintext and encryption overhead.
pub fn encryptZeroCopy(
    io: Io,
    output: []u8,
    plaintext: []const u8,
    derived_keys: DerivedKeys,
) void {
    assert(output.len == plaintext.len + overhead_size);

    var nonce: [nonce_length]u8 = undefined;
    io.random(&nonce);

    const header_mac = computeHeaderMac(nonce, derived_keys.header_mac_key);

    const ciphertext = output[header_size..][0..plaintext.len];

    var tag: [tag_length]u8 = undefined;
    Aegis128X2.encrypt(
        ciphertext,
        &tag,
        plaintext,
        &.{},
        nonce,
        derived_keys.encryption_key,
    );

    @memcpy(output[0..nonce_length], &nonce);
    @memcpy(output[nonce_length..header_size], &header_mac);
    @memcpy(output[header_size + plaintext.len ..][0..tag_length], &tag);
}

/// Distinguish a wrong key from ciphertext damage before returning plaintext.
pub fn decrypt(
    gpa: Allocator,
    encrypted: []const u8,
    derived_keys: DerivedKeys,
) ![]u8 {
    return decryptBound(gpa, encrypted, "", derived_keys);
}

/// Decrypt a file only when it was encrypted for the same path.
pub fn decryptBound(
    gpa: Allocator,
    encrypted: []const u8,
    path: []const u8,
    derived_keys: DerivedKeys,
) ![]u8 {
    const parsed = try parseEncrypted(encrypted);

    const expected_mac = computeHeaderMac(parsed.nonce.*, derived_keys.header_mac_key);
    if (!std.crypto.timing_safe.eql([mac_length]u8, expected_mac, parsed.stored_mac.*)) {
        return error.InvalidHeaderMac;
    }

    const plaintext = try gpa.alloc(u8, parsed.ciphertext.len);
    errdefer gpa.free(plaintext);

    try Aegis128X2.decrypt(
        plaintext,
        parsed.ciphertext,
        parsed.tag.*,
        path,
        parsed.nonce.*,
        derived_keys.encryption_key,
    );

    return plaintext;
}

/// Decrypt into caller-provided storage.
/// The output must match the ciphertext length without encryption overhead.
pub fn decryptZeroCopy(
    output: []u8,
    encrypted: []const u8,
    derived_keys: DerivedKeys,
) !void {
    const parsed = try parseEncrypted(encrypted);

    assert(output.len == parsed.ciphertext.len);

    const expected_mac = computeHeaderMac(parsed.nonce.*, derived_keys.header_mac_key);
    if (!std.crypto.timing_safe.eql([mac_length]u8, expected_mac, parsed.stored_mac.*)) {
        return error.InvalidHeaderMac;
    }

    try Aegis128X2.decrypt(
        output,
        parsed.ciphertext,
        parsed.tag.*,
        &.{},
        parsed.nonce.*,
        derived_keys.encryption_key,
    );
}

/// Check whether the key matches without reading the ciphertext body.
/// This intentionally does not detect body damage.
pub fn verifyHeaderOnly(
    encrypted: []const u8,
    derived_keys: DerivedKeys,
) !void {
    const parsed = try parseEncrypted(encrypted);

    const expected_mac = computeHeaderMac(parsed.nonce.*, derived_keys.header_mac_key);
    if (!std.crypto.timing_safe.eql([mac_length]u8, expected_mac, parsed.stored_mac.*)) {
        return error.InvalidHeaderMac;
    }
}

/// Verify the key, header, and ciphertext without retaining plaintext.
pub fn verify(
    gpa: Allocator,
    encrypted: []const u8,
    derived_keys: DerivedKeys,
) !void {
    const parsed = try parseEncrypted(encrypted);

    const expected_mac = computeHeaderMac(parsed.nonce.*, derived_keys.header_mac_key);
    if (!std.crypto.timing_safe.eql([mac_length]u8, expected_mac, parsed.stored_mac.*)) {
        return error.InvalidHeaderMac;
    }

    // Verification must decrypt, so discard the plaintext after checking its tag.
    const plaintext = try gpa.alloc(u8, parsed.ciphertext.len);
    defer gpa.free(plaintext);

    try Aegis128X2.decrypt(
        plaintext,
        parsed.ciphertext,
        parsed.tag.*,
        &.{},
        parsed.nonce.*,
        derived_keys.encryption_key,
    );
}

test "encrypt and decrypt round trip" {
    const gpa = testing.allocator;
    const io = testing.io;

    const key: [key_length]u8 = @splat(1);
    const derived = deriveKeys(key, null);
    const plaintext = "Hello, World! This is a test message.";

    const encrypted = try encrypt(gpa, io, plaintext, derived);
    defer gpa.free(encrypted);

    try testing.expectEqual(plaintext.len + overhead_size, encrypted.len);

    const decrypted = try decrypt(gpa, encrypted, derived);
    defer gpa.free(decrypted);

    try testing.expectEqualStrings(plaintext, decrypted);
}

test "decrypt and verify fail with a wrong key" {
    const gpa = testing.allocator;
    const io = testing.io;

    const key1: [key_length]u8 = @splat(1);
    const key2: [key_length]u8 = @splat(2);
    const derived1 = deriveKeys(key1, null);
    const derived2 = deriveKeys(key2, null);
    const plaintext = "Secret message";

    const encrypted = try encrypt(gpa, io, plaintext, derived1);
    defer gpa.free(encrypted);

    try testing.expectError(error.InvalidHeaderMac, decrypt(gpa, encrypted, derived2));
    try testing.expectError(error.InvalidHeaderMac, verify(gpa, encrypted, derived2));
}

test "decrypt and verify fail on a corrupted ciphertext" {
    const gpa = testing.allocator;
    const io = testing.io;

    const key: [key_length]u8 = @splat(1);
    const derived = deriveKeys(key, null);
    const plaintext = "Test message";

    const encrypted = try encrypt(gpa, io, plaintext, derived);
    defer gpa.free(encrypted);

    encrypted[header_size] ^= 0xFF;

    try testing.expectError(error.AuthenticationFailed, decrypt(gpa, encrypted, derived));
    try testing.expectError(error.AuthenticationFailed, verify(gpa, encrypted, derived));
}

test "decrypt rejects input shorter than the overhead" {
    const gpa = testing.allocator;

    const key: [key_length]u8 = @splat(1);
    const derived = deriveKeys(key, null);
    const too_small: [32]u8 = @splat(0);

    try testing.expectError(error.InvalidFileSize, decrypt(gpa, &too_small, derived));
}

test "empty plaintext round trip" {
    const gpa = testing.allocator;
    const io = testing.io;

    const key: [key_length]u8 = @splat(1);
    const derived = deriveKeys(key, null);
    const plaintext = "";

    const encrypted = try encrypt(gpa, io, plaintext, derived);
    defer gpa.free(encrypted);

    try testing.expectEqual(overhead_size, encrypted.len);

    const decrypted = try decrypt(gpa, encrypted, derived);
    defer gpa.free(decrypted);

    try testing.expectEqual(0, decrypted.len);
}

test "one megabyte round trip" {
    const gpa = testing.allocator;
    const io = testing.io;

    const key: [key_length]u8 = @splat(42);
    const derived = deriveKeys(key, null);

    const data_size = 1024 * 1024;
    const plaintext = try gpa.alloc(u8, data_size);
    defer gpa.free(plaintext);

    for (plaintext, 0..) |*byte, i| {
        byte.* = @intCast(i % 256);
    }

    const encrypted = try encrypt(gpa, io, plaintext, derived);
    defer gpa.free(encrypted);

    const decrypted = try decrypt(gpa, encrypted, derived);
    defer gpa.free(decrypted);

    try testing.expectEqualSlices(u8, plaintext, decrypted);
}

test "verify accepts valid ciphertext" {
    const gpa = testing.allocator;
    const io = testing.io;

    const key: [key_length]u8 = @splat(1);
    const derived = deriveKeys(key, null);
    const plaintext = "Test message for verification";

    const encrypted = try encrypt(gpa, io, plaintext, derived);
    defer gpa.free(encrypted);

    try verify(gpa, encrypted, derived);
}

test "derived keys keep their first 48 bytes" {
    const key: [key_length]u8 = @splat(7);
    const derived = deriveKeys(key, "ctx");

    var shake = TurboShake128.init(.{});
    shake.update(&key);
    shake.update("turbocrypt");
    shake.update("-");
    shake.update("ctx");
    var expected: [48]u8 = undefined;
    shake.squeeze(&expected);

    try testing.expectEqualSlices(u8, expected[0..16], &derived.header_mac_key);
    try testing.expectEqualSlices(u8, expected[16..32], &derived.encryption_key);
    try testing.expectEqualSlices(u8, expected[32..48], &derived.filename_key);
}

test "key id is stable and key dependent" {
    const a = deriveKeys(@splat(1), null);
    const b = deriveKeys(@splat(2), null);

    try testing.expectEqualSlices(u8, &keyId(a.key_id_key), &keyId(a.key_id_key));
    try testing.expect(!mem.eql(u8, &keyId(a.key_id_key), &keyId(b.key_id_key)));
    try testing.expect(!mem.eql(u8, &a.key_id_key, &a.cipher_id_key));
}

test "fingerprint is stable and key dependent" {
    const a = deriveKeys(@splat(1), null);
    const b = deriveKeys(@splat(2), null);

    const fp1 = fingerprint("private notes", a.fingerprint_key);
    const fp2 = fingerprint("private notes", a.fingerprint_key);
    const fp3 = fingerprint("private notes!", a.fingerprint_key);
    const fp4 = fingerprint("private notes", b.fingerprint_key);

    try testing.expectEqualSlices(u8, &fp1, &fp2);
    try testing.expect(!mem.eql(u8, &fp1, &fp3));
    try testing.expect(!mem.eql(u8, &fp1, &fp4));
}

test "ciphertext id sees a flipped body byte" {
    const gpa = testing.allocator;
    const io = testing.io;

    const derived = deriveKeys(@splat(3), null);
    const encrypted = try encrypt(gpa, io, "some content that is long enough", derived);
    defer gpa.free(encrypted);

    const before = ciphertextId(encrypted, derived.cipher_id_key);
    encrypted[header_size + 4] ^= 0x01;
    const after = ciphertextId(encrypted, derived.cipher_id_key);

    try testing.expect(!mem.eql(u8, &before, &after));
    try verifyHeaderOnly(encrypted, derived);
    try testing.expectError(error.AuthenticationFailed, decrypt(gpa, encrypted, derived));
}

test "bound ciphertext only decrypts at its path" {
    const gpa = testing.allocator;
    const io = testing.io;

    const derived = deriveKeys(@splat(4), null);
    const encrypted = try encryptBound(gpa, io, "deploy notes", "docs/internal.md", derived);
    defer gpa.free(encrypted);

    const plain = try decryptBound(gpa, encrypted, "docs/internal.md", derived);
    defer gpa.free(plain);
    try testing.expectEqualStrings("deploy notes", plain);

    try verifyHeaderOnly(encrypted, derived);
    try testing.expectError(
        error.AuthenticationFailed,
        decryptBound(gpa, encrypted, "docs/other.md", derived),
    );
    try testing.expectError(error.AuthenticationFailed, decrypt(gpa, encrypted, derived));
}
