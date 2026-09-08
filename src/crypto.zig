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
pub const header_size = nonce_length + mac_length; // 32 bytes
pub const overhead_size = header_size + tag_length; // 48 bytes

/// Domain separator for version 1 of TurboCrypt format
const domain_separator = "TC01";

/// Derived keys from master key using TurboSHAKE128
pub const DerivedKeys = struct {
    header_mac_key: [16]u8,
    encryption_key: [16]u8,
    filename_key: [16]u8,
    fingerprint_key: [16]u8,
    cipher_id_key: [16]u8,
};

/// Derive five separate keys from the master key using TurboSHAKE128
/// Input: master_key || "turbocrypt" || ("-" || context if provided)
/// Output: 80 bytes split into five 16-byte keys
///
/// The last two keys came later than the first three.
/// TurboSHAKE is an XOF, so squeezing more bytes leaves the first 48 unchanged and every file encrypted before that addition still decrypts.
///
/// The optional context parameter allows deriving different keys from the same master key.
/// This enables encrypting different directories with cryptographically independent keys
/// while using a single master key. The same context must be used for both encryption and decryption.
pub fn deriveKeys(master_key: [key_length]u8, context: ?[]const u8) DerivedKeys {
    var shake = TurboShake128.init(.{});

    // Feed input: master_key || "turbocrypt" || ("-" || context if provided)
    shake.update(&master_key);
    shake.update("turbocrypt");

    // Add context if provided and non-empty
    if (context) |ctx| {
        if (ctx.len > 0) {
            shake.update("-");
            shake.update(ctx);
        }
    }

    var output: [80]u8 = undefined;
    shake.squeeze(&output);

    return DerivedKeys{
        .header_mac_key = output[0..16].*,
        .encryption_key = output[16..32].*,
        .filename_key = output[32..48].*,
        .fingerprint_key = output[48..64].*,
        .cipher_id_key = output[64..80].*,
    };
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

/// Generate a header MAC for the given nonce and header_mac_key
/// MAC = Aegis128X2Mac_128(header_mac_key, "TC01" || nonce)
fn computeHeaderMac(nonce: [nonce_length]u8, header_mac_key: [key_length]u8) [mac_length]u8 {
    // Construct message: "TC01" || nonce (4 + 16 = 20 bytes)
    var msg: [domain_separator.len + nonce_length]u8 = undefined;
    @memcpy(msg[0..domain_separator.len], domain_separator);
    @memcpy(msg[domain_separator.len..], &nonce);

    return keyedMac(&msg, header_mac_key);
}

/// Parsed encrypted data structure
const ParsedEncrypted = struct {
    nonce: *const [nonce_length]u8,
    stored_mac: *const [mac_length]u8,
    ciphertext: []const u8,
    tag: *const [tag_length]u8,
};

/// Parse and validate encrypted data structure
/// Returns parsed components or error if invalid
fn parseEncrypted(encrypted: []const u8) !ParsedEncrypted {
    // Validate minimum file size
    if (encrypted.len < overhead_size) {
        return error.InvalidFileSize;
    }

    // Parse header
    const nonce = encrypted[0..nonce_length];
    const stored_mac = encrypted[nonce_length..header_size];

    // Parse body
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

/// Encrypt plaintext and return encrypted data with TurboCrypt file format
/// Format: nonce (16) || header_mac (16) || ciphertext (len) || tag (16)
/// Total size: plaintext.len + 48
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
    // Generate random nonce
    var nonce: [nonce_length]u8 = undefined;
    io.random(&nonce);

    // Compute header MAC using derived header_mac_key
    const header_mac = computeHeaderMac(nonce, derived_keys.header_mac_key);

    // Allocate output buffer: nonce || header_mac || ciphertext || tag
    // Check for integer overflow when calculating output size
    const overhead = header_size + tag_length; // This is safe: 32 + 16 = 48
    const output_size = std.math.add(usize, overhead, plaintext.len) catch {
        return error.OutputTooLarge;
    };
    const output = try allocator.alloc(u8, output_size);
    errdefer allocator.free(output);

    // Get view of ciphertext portion in output buffer
    const ciphertext = output[header_size..][0..plaintext.len];

    // Encrypt directly to output buffer using derived encryption_key
    var tag: [tag_length]u8 = undefined;
    Aegis128X2.encrypt(
        ciphertext,
        &tag,
        plaintext,
        path,
        nonce,
        derived_keys.encryption_key,
    );

    // Write header and tag to output
    @memcpy(output[0..nonce_length], &nonce);
    @memcpy(output[nonce_length..header_size], &header_mac);
    @memcpy(output[header_size + plaintext.len ..][0..tag_length], &tag);

    return output;
}

/// Zero-copy encryption: writes directly to pre-allocated output buffer
/// Output buffer must be exactly plaintext.len + overhead_size bytes
/// Format: nonce (16) || header_mac (16) || ciphertext (len) || tag (16)
pub fn encryptZeroCopy(
    output: []u8,
    plaintext: []const u8,
    derived_keys: DerivedKeys,
    io: std.Io,
) void {
    // Verify output buffer size
    std.debug.assert(output.len == plaintext.len + overhead_size);

    // Generate random nonce
    var nonce: [nonce_length]u8 = undefined;
    io.random(&nonce);

    // Compute header MAC using derived header_mac_key
    const header_mac = computeHeaderMac(nonce, derived_keys.header_mac_key);

    // Get view of ciphertext portion in output buffer
    const ciphertext = output[header_size..][0..plaintext.len];

    // Encrypt directly to output buffer using derived encryption_key
    var tag: [tag_length]u8 = undefined;
    Aegis128X2.encrypt(
        ciphertext,
        &tag,
        plaintext,
        &[_]u8{}, // empty associated data
        nonce,
        derived_keys.encryption_key,
    );

    // Write header and tag to output
    @memcpy(output[0..nonce_length], &nonce);
    @memcpy(output[nonce_length..header_size], &header_mac);
    @memcpy(output[header_size + plaintext.len ..][0..tag_length], &tag);
}

/// Decrypt encrypted data in TurboCrypt file format
/// Returns plaintext if successful, error otherwise
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
    // Parse encrypted data
    const parsed = try parseEncrypted(encrypted);

    // Verify header MAC using derived header_mac_key
    const expected_mac = computeHeaderMac(parsed.nonce.*, derived_keys.header_mac_key);
    if (!std.crypto.timing_safe.eql([mac_length]u8, expected_mac, parsed.stored_mac.*)) {
        return error.InvalidHeaderMAC;
    }

    // Allocate plaintext buffer
    const plaintext = try allocator.alloc(u8, parsed.ciphertext.len);
    errdefer allocator.free(plaintext);

    // Decrypt using derived encryption_key
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

/// Zero-copy decryption: writes directly to pre-allocated output buffer
/// Output buffer must be exactly encrypted.len - overhead_size bytes
pub fn decryptZeroCopy(
    output: []u8,
    encrypted: []const u8,
    derived_keys: DerivedKeys,
) !void {
    // Parse encrypted data
    const parsed = try parseEncrypted(encrypted);

    // Verify output buffer size
    std.debug.assert(output.len == parsed.ciphertext.len);

    // Verify header MAC using derived header_mac_key
    const expected_mac = computeHeaderMac(parsed.nonce.*, derived_keys.header_mac_key);
    if (!std.crypto.timing_safe.eql([mac_length]u8, expected_mac, parsed.stored_mac.*)) {
        return error.InvalidHeaderMAC;
    }

    // Decrypt directly to output buffer using derived encryption_key
    try Aegis128X2.decrypt(
        output,
        parsed.ciphertext,
        parsed.tag.*,
        &[_]u8{}, // empty associated data
        parsed.nonce.*,
        derived_keys.encryption_key,
    );
}

/// Verify only the header MAC without decrypting (quick mode)
/// This is faster than full verification but only checks if the key is correct
/// Does not verify data integrity (authentication tag)
pub fn verifyHeaderOnly(
    encrypted: []const u8,
    derived_keys: DerivedKeys,
) !void {
    // Parse encrypted data
    const parsed = try parseEncrypted(encrypted);

    // Verify header MAC using derived header_mac_key
    const expected_mac = computeHeaderMac(parsed.nonce.*, derived_keys.header_mac_key);
    if (!std.crypto.timing_safe.eql([mac_length]u8, expected_mac, parsed.stored_mac.*)) {
        return error.InvalidHeaderMAC;
    }

    // If we reach here, the header MAC is valid (correct key)
}

/// Verify encrypted data without decrypting (checks header MAC and authentication tag)
/// This is useful for integrity checking without exposing plaintext
/// Returns Ok if verification succeeds, error otherwise
pub fn verify(
    encrypted: []const u8,
    derived_keys: DerivedKeys,
    allocator: std.mem.Allocator,
) !void {
    // Parse encrypted data
    const parsed = try parseEncrypted(encrypted);

    // Verify header MAC using derived header_mac_key
    const expected_mac = computeHeaderMac(parsed.nonce.*, derived_keys.header_mac_key);
    if (!std.crypto.timing_safe.eql([mac_length]u8, expected_mac, parsed.stored_mac.*)) {
        return error.InvalidHeaderMAC;
    }

    // Allocate temporary plaintext buffer for verification
    // AEGIS-128X2 requires decryption to verify the tag (no separate verify API)
    const plaintext = try allocator.alloc(u8, parsed.ciphertext.len);
    defer allocator.free(plaintext);

    // Decrypt to verify tag using derived encryption_key (plaintext is discarded)
    try Aegis128X2.decrypt(
        plaintext,
        parsed.ciphertext,
        parsed.tag.*,
        &[_]u8{}, // empty associated data
        parsed.nonce.*,
        derived_keys.encryption_key,
    );

    // If we reach here, both header MAC and authentication tag are valid
}

test "encrypt/decrypt round-trip" {
    const testing = std.testing;
    const allocator = testing.allocator;
    const io = testing.io;

    const key: [key_length]u8 = @splat(1);
    const derived = deriveKeys(key, null);
    const plaintext = "Hello, World! This is a test message.";

    // Encrypt
    const encrypted = try encrypt(plaintext, derived, allocator, io);
    defer allocator.free(encrypted);

    // Verify size
    try testing.expectEqual(plaintext.len + overhead_size, encrypted.len);

    // Decrypt
    const decrypted = try decrypt(encrypted, derived, allocator);
    defer allocator.free(decrypted);

    // Verify content
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

    // Encrypt with key1
    const encrypted = try encrypt(plaintext, derived1, allocator, io);
    defer allocator.free(encrypted);

    // Try to decrypt with key2 - should fail with InvalidHeaderMAC
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

    // Encrypt
    const encrypted = try encrypt(plaintext, derived, allocator, io);
    defer allocator.free(encrypted);

    // Corrupt ciphertext (modify a byte in the ciphertext portion)
    encrypted[header_size] ^= 0xFF;

    // Try to decrypt - should fail with AuthenticationFailed
    const result = decrypt(encrypted, derived, allocator);
    try testing.expectError(error.AuthenticationFailed, result);
}

test "decrypt invalid file size" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const key: [key_length]u8 = @splat(1);
    const derived = deriveKeys(key, null);
    const too_small: [32]u8 = @splat(0); // Less than overhead_size (48)

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

    // Encrypt empty plaintext
    const encrypted = try encrypt(plaintext, derived, allocator, io);
    defer allocator.free(encrypted);

    // Should have only overhead
    try testing.expectEqual(overhead_size, encrypted.len);

    // Decrypt
    const decrypted = try decrypt(encrypted, derived, allocator);
    defer allocator.free(decrypted);

    // Should be empty
    try testing.expectEqual(@as(usize, 0), decrypted.len);
}

test "large data encryption" {
    const testing = std.testing;
    const allocator = testing.allocator;
    const io = testing.io;

    const key: [key_length]u8 = @splat(42);
    const derived = deriveKeys(key, null);

    // Create 1MB of test data
    const data_size = 1024 * 1024;
    const plaintext = try allocator.alloc(u8, data_size);
    defer allocator.free(plaintext);

    // Fill with pattern
    for (plaintext, 0..) |*byte, i| {
        byte.* = @intCast(i % 256);
    }

    // Encrypt
    const encrypted = try encrypt(plaintext, derived, allocator, io);
    defer allocator.free(encrypted);

    // Decrypt
    const decrypted = try decrypt(encrypted, derived, allocator);
    defer allocator.free(decrypted);

    // Verify
    try testing.expectEqualSlices(u8, plaintext, decrypted);
}

test "verify valid encrypted data" {
    const testing = std.testing;
    const allocator = testing.allocator;
    const io = testing.io;

    const key: [key_length]u8 = @splat(1);
    const derived = deriveKeys(key, null);
    const plaintext = "Test message for verification";

    // Encrypt
    const encrypted = try encrypt(plaintext, derived, allocator, io);
    defer allocator.free(encrypted);

    // Verify should succeed
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

    // Encrypt with key1
    const encrypted = try encrypt(plaintext, derived1, allocator, io);
    defer allocator.free(encrypted);

    // Verify with key2 should fail with InvalidHeaderMAC
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

    // Encrypt
    const encrypted = try encrypt(plaintext, derived, allocator, io);
    defer allocator.free(encrypted);

    // Corrupt ciphertext
    encrypted[header_size] ^= 0xFF;

    // Verify should fail with AuthenticationFailed
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
