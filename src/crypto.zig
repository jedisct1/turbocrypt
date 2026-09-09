const std = @import("std");
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

/// Names version 1 of the file format.
const domain_separator = "TC01";

pub const DerivedKeys = struct {
    header_mac_key: [16]u8,
    encryption_key: [16]u8,
    filename_key: [16]u8,
    fingerprint_key: [16]u8,
    cipher_id_key: [16]u8,
    key_id_key: [16]u8,
};

/// Six keys from one master key, with TurboSHAKE128.
/// Input: master_key || "turbocrypt", then "-" || context when a context is given.
/// Output: 96 bytes, split into six keys in field order.
///
/// The last three keys came later than the first three.
/// TurboSHAKE is an XOF, so squeezing more bytes leaves the first 48 unchanged and every older file still decrypts.
///
/// A context gives independent keys from the same master key, for example one per directory.
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

    return DerivedKeys{
        .header_mac_key = output[0..16].*,
        .encryption_key = output[16..32].*,
        .filename_key = output[32..48].*,
        .fingerprint_key = output[48..64].*,
        .cipher_id_key = output[64..80].*,
        .key_id_key = output[80..96].*,
    };
}

/// Public name of a key. It appears in commits, so it is a MAC under a key of its own and reveals nothing.
pub fn keyId(key_id_key: [key_length]u8) [mac_length]u8 {
    return keyedMac("key id", key_id_key);
}

/// Keyed fingerprint of a plaintext.
///
/// The git integration stores it locally to tell whether a plain file changed since the last sync.
/// A keyed value keeps a leaked state file from confirming guesses about file contents.
pub fn fingerprint(plaintext: []const u8, fingerprint_key: [key_length]u8) [fingerprint_length]u8 {
    return keyedMac(plaintext, fingerprint_key);
}

/// Identity of a complete ciphertext, a MAC under its own derived key.
///
/// The nonce and the tag alone do not identify the bytes: a flipped body byte keeps both and only fails at decryption.
/// A MAC over everything does.
/// Only a key holder could craft a second preimage, and a key holder can already write any valid ciphertext, so a MAC is enough.
pub fn ciphertextId(encrypted: []const u8, cipher_id_key: [key_length]u8) [cipher_id_length]u8 {
    return keyedMac(encrypted, cipher_id_key);
}

/// MAC of any data under one of the derived keys.
pub fn keyedMac(data: []const u8, key: [key_length]u8) [mac_length]u8 {
    var mac: [mac_length]u8 = undefined;
    Aegis128X2Mac_128.create(&mac, data, &key);
    return mac;
}

/// MAC = Aegis128X2Mac_128(header_mac_key, "TC01" || nonce).
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

    return ParsedEncrypted{
        .nonce = nonce,
        .stored_mac = stored_mac,
        .ciphertext = ciphertext,
        .tag = tag,
    };
}

/// Output layout: nonce (16) || header_mac (16) || ciphertext || tag (16).
pub fn encrypt(
    plaintext: []const u8,
    derived_keys: DerivedKeys,
    allocator: std.mem.Allocator,
    io: std.Io,
) ![]u8 {
    return encryptBound(plaintext, "", derived_keys, allocator, io);
}

/// Encrypt a file that belongs to a fixed relative path.
///
/// The path is authenticated as associated data, so the ciphertext only decrypts at that path.
/// Moving or swapping entries is detected.
pub fn encryptBound(
    plaintext: []const u8,
    path: []const u8,
    derived_keys: DerivedKeys,
    allocator: std.mem.Allocator,
    io: std.Io,
) ![]u8 {
    var nonce: [nonce_length]u8 = undefined;
    io.random(&nonce);

    const header_mac = computeHeaderMac(nonce, derived_keys.header_mac_key);

    const overhead = header_size + tag_length;
    const output_size = std.math.add(usize, overhead, plaintext.len) catch {
        return error.OutputTooLarge;
    };
    const output = try allocator.alloc(u8, output_size);
    errdefer allocator.free(output);

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

/// Like encrypt, but into a caller buffer of exactly plaintext.len + overhead_size bytes.
pub fn encryptZeroCopy(
    output: []u8,
    plaintext: []const u8,
    derived_keys: DerivedKeys,
    io: std.Io,
) void {
    std.debug.assert(output.len == plaintext.len + overhead_size);

    var nonce: [nonce_length]u8 = undefined;
    io.random(&nonce);

    const header_mac = computeHeaderMac(nonce, derived_keys.header_mac_key);

    const ciphertext = output[header_size..][0..plaintext.len];

    var tag: [tag_length]u8 = undefined;
    Aegis128X2.encrypt(
        ciphertext,
        &tag,
        plaintext,
        &[_]u8{},
        nonce,
        derived_keys.encryption_key,
    );

    @memcpy(output[0..nonce_length], &nonce);
    @memcpy(output[nonce_length..header_size], &header_mac);
    @memcpy(output[header_size + plaintext.len ..][0..tag_length], &tag);
}

/// A wrong key fails with InvalidHeaderMAC, a damaged body with AuthenticationFailed.
pub fn decrypt(
    encrypted: []const u8,
    derived_keys: DerivedKeys,
    allocator: std.mem.Allocator,
) ![]u8 {
    return decryptBound(encrypted, "", derived_keys, allocator);
}

/// Decrypt a file that was encrypted with encryptBound for the same path.
pub fn decryptBound(
    encrypted: []const u8,
    path: []const u8,
    derived_keys: DerivedKeys,
    allocator: std.mem.Allocator,
) ![]u8 {
    const parsed = try parseEncrypted(encrypted);

    const expected_mac = computeHeaderMac(parsed.nonce.*, derived_keys.header_mac_key);
    if (!std.crypto.timing_safe.eql([mac_length]u8, expected_mac, parsed.stored_mac.*)) {
        return error.InvalidHeaderMAC;
    }

    const plaintext = try allocator.alloc(u8, parsed.ciphertext.len);
    errdefer allocator.free(plaintext);

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

/// Like decrypt, but into a caller buffer of exactly encrypted.len - overhead_size bytes.
pub fn decryptZeroCopy(
    output: []u8,
    encrypted: []const u8,
    derived_keys: DerivedKeys,
) !void {
    const parsed = try parseEncrypted(encrypted);

    std.debug.assert(output.len == parsed.ciphertext.len);

    const expected_mac = computeHeaderMac(parsed.nonce.*, derived_keys.header_mac_key);
    if (!std.crypto.timing_safe.eql([mac_length]u8, expected_mac, parsed.stored_mac.*)) {
        return error.InvalidHeaderMAC;
    }

    try Aegis128X2.decrypt(
        output,
        parsed.ciphertext,
        parsed.tag.*,
        &[_]u8{},
        parsed.nonce.*,
        derived_keys.encryption_key,
    );
}

/// Checks the key through the header MAC only. A damaged body still passes.
pub fn verifyHeaderOnly(
    encrypted: []const u8,
    derived_keys: DerivedKeys,
) !void {
    const parsed = try parseEncrypted(encrypted);

    const expected_mac = computeHeaderMac(parsed.nonce.*, derived_keys.header_mac_key);
    if (!std.crypto.timing_safe.eql([mac_length]u8, expected_mac, parsed.stored_mac.*)) {
        return error.InvalidHeaderMAC;
    }
}

/// Checks the header MAC and the tag without keeping the plaintext.
pub fn verify(
    encrypted: []const u8,
    derived_keys: DerivedKeys,
    allocator: std.mem.Allocator,
) !void {
    const parsed = try parseEncrypted(encrypted);

    const expected_mac = computeHeaderMac(parsed.nonce.*, derived_keys.header_mac_key);
    if (!std.crypto.timing_safe.eql([mac_length]u8, expected_mac, parsed.stored_mac.*)) {
        return error.InvalidHeaderMAC;
    }

    // The AEGIS API cannot check the tag without decryption, so the plaintext goes to a scratch buffer.
    const plaintext = try allocator.alloc(u8, parsed.ciphertext.len);
    defer allocator.free(plaintext);

    try Aegis128X2.decrypt(
        plaintext,
        parsed.ciphertext,
        parsed.tag.*,
        &[_]u8{},
        parsed.nonce.*,
        derived_keys.encryption_key,
    );
}

test "encrypt/decrypt round-trip" {
    const testing = std.testing;
    const allocator = testing.allocator;
    const io = testing.io;

    const key: [key_length]u8 = @splat(1);
    const derived = deriveKeys(key, null);
    const plaintext = "Hello, World! This is a test message.";

    const encrypted = try encrypt(plaintext, derived, allocator, io);
    defer allocator.free(encrypted);

    try testing.expectEqual(plaintext.len + overhead_size, encrypted.len);

    const decrypted = try decrypt(encrypted, derived, allocator);
    defer allocator.free(decrypted);

    try testing.expectEqualStrings(plaintext, decrypted);
}

test "decrypt with wrong key fails" {
    const testing = std.testing;
    const allocator = testing.allocator;
    const io = testing.io;

    const key1: [key_length]u8 = @splat(1);
    const key2: [key_length]u8 = @splat(2);
    const derived1 = deriveKeys(key1, null);
    const derived2 = deriveKeys(key2, null);
    const plaintext = "Secret message";

    const encrypted = try encrypt(plaintext, derived1, allocator, io);
    defer allocator.free(encrypted);

    const result = decrypt(encrypted, derived2, allocator);
    try testing.expectError(error.InvalidHeaderMAC, result);
}

test "decrypt corrupted ciphertext fails" {
    const testing = std.testing;
    const allocator = testing.allocator;
    const io = testing.io;

    const key: [key_length]u8 = @splat(1);
    const derived = deriveKeys(key, null);
    const plaintext = "Test message";

    const encrypted = try encrypt(plaintext, derived, allocator, io);
    defer allocator.free(encrypted);

    encrypted[header_size] ^= 0xFF;

    const result = decrypt(encrypted, derived, allocator);
    try testing.expectError(error.AuthenticationFailed, result);
}

test "decrypt invalid file size" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const key: [key_length]u8 = @splat(1);
    const derived = deriveKeys(key, null);
    const too_small: [32]u8 = @splat(0);

    const result = decrypt(&too_small, derived, allocator);
    try testing.expectError(error.InvalidFileSize, result);
}

test "empty plaintext encryption" {
    const testing = std.testing;
    const allocator = testing.allocator;
    const io = testing.io;

    const key: [key_length]u8 = @splat(1);
    const derived = deriveKeys(key, null);
    const plaintext = "";

    const encrypted = try encrypt(plaintext, derived, allocator, io);
    defer allocator.free(encrypted);

    try testing.expectEqual(overhead_size, encrypted.len);

    const decrypted = try decrypt(encrypted, derived, allocator);
    defer allocator.free(decrypted);

    try testing.expectEqual(@as(usize, 0), decrypted.len);
}

test "large data encryption" {
    const testing = std.testing;
    const allocator = testing.allocator;
    const io = testing.io;

    const key: [key_length]u8 = @splat(42);
    const derived = deriveKeys(key, null);

    const data_size = 1024 * 1024;
    const plaintext = try allocator.alloc(u8, data_size);
    defer allocator.free(plaintext);

    for (plaintext, 0..) |*byte, i| {
        byte.* = @intCast(i % 256);
    }

    const encrypted = try encrypt(plaintext, derived, allocator, io);
    defer allocator.free(encrypted);

    const decrypted = try decrypt(encrypted, derived, allocator);
    defer allocator.free(decrypted);

    try testing.expectEqualSlices(u8, plaintext, decrypted);
}

test "verify valid encrypted data" {
    const testing = std.testing;
    const allocator = testing.allocator;
    const io = testing.io;

    const key: [key_length]u8 = @splat(1);
    const derived = deriveKeys(key, null);
    const plaintext = "Test message for verification";

    const encrypted = try encrypt(plaintext, derived, allocator, io);
    defer allocator.free(encrypted);

    try verify(encrypted, derived, allocator);
}

test "verify with wrong key fails" {
    const testing = std.testing;
    const allocator = testing.allocator;
    const io = testing.io;

    const key1: [key_length]u8 = @splat(1);
    const key2: [key_length]u8 = @splat(2);
    const derived1 = deriveKeys(key1, null);
    const derived2 = deriveKeys(key2, null);
    const plaintext = "Secret message";

    const encrypted = try encrypt(plaintext, derived1, allocator, io);
    defer allocator.free(encrypted);

    const result = verify(encrypted, derived2, allocator);
    try testing.expectError(error.InvalidHeaderMAC, result);
}

test "verify corrupted ciphertext fails" {
    const testing = std.testing;
    const allocator = testing.allocator;
    const io = testing.io;

    const key: [key_length]u8 = @splat(1);
    const derived = deriveKeys(key, null);
    const plaintext = "Test message";

    const encrypted = try encrypt(plaintext, derived, allocator, io);
    defer allocator.free(encrypted);

    encrypted[header_size] ^= 0xFF;

    const result = verify(encrypted, derived, allocator);
    try testing.expectError(error.AuthenticationFailed, result);
}

test "derived keys keep their first 48 bytes" {
    const testing = std.testing;

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
    const testing = std.testing;

    const a = deriveKeys(@splat(1), null);
    const b = deriveKeys(@splat(2), null);

    try testing.expectEqualSlices(u8, &keyId(a.key_id_key), &keyId(a.key_id_key));
    try testing.expect(!std.mem.eql(u8, &keyId(a.key_id_key), &keyId(b.key_id_key)));
    try testing.expect(!std.mem.eql(u8, &a.key_id_key, &a.cipher_id_key));
}

test "fingerprint is stable and key dependent" {
    const testing = std.testing;

    const a = deriveKeys(@splat(1), null);
    const b = deriveKeys(@splat(2), null);

    const fp1 = fingerprint("private notes", a.fingerprint_key);
    const fp2 = fingerprint("private notes", a.fingerprint_key);
    const fp3 = fingerprint("private notes!", a.fingerprint_key);
    const fp4 = fingerprint("private notes", b.fingerprint_key);

    try testing.expectEqualSlices(u8, &fp1, &fp2);
    try testing.expect(!std.mem.eql(u8, &fp1, &fp3));
    try testing.expect(!std.mem.eql(u8, &fp1, &fp4));
}

test "ciphertext id sees a flipped body byte" {
    const testing = std.testing;
    const allocator = testing.allocator;
    const io = testing.io;

    const derived = deriveKeys(@splat(3), null);
    const encrypted = try encrypt("some content that is long enough", derived, allocator, io);
    defer allocator.free(encrypted);

    const before = ciphertextId(encrypted, derived.cipher_id_key);
    encrypted[header_size + 4] ^= 0x01;
    const after = ciphertextId(encrypted, derived.cipher_id_key);

    try testing.expect(!std.mem.eql(u8, &before, &after));
    try verifyHeaderOnly(encrypted, derived);
    try testing.expectError(error.AuthenticationFailed, decrypt(encrypted, derived, allocator));
}

test "bound ciphertext only decrypts at its path" {
    const testing = std.testing;
    const allocator = testing.allocator;
    const io = testing.io;

    const derived = deriveKeys(@splat(4), null);
    const encrypted = try encryptBound("deploy notes", "docs/internal.md", derived, allocator, io);
    defer allocator.free(encrypted);

    const plain = try decryptBound(encrypted, "docs/internal.md", derived, allocator);
    defer allocator.free(plain);
    try testing.expectEqualStrings("deploy notes", plain);

    try verifyHeaderOnly(encrypted, derived);
    try testing.expectError(error.AuthenticationFailed, decryptBound(encrypted, "docs/other.md", derived, allocator));
    try testing.expectError(error.AuthenticationFailed, decrypt(encrypted, derived, allocator));
}
