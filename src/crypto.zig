const std = @import("std");
const Aegis128X2 = std.crypto.aead.aegis.Aegis128X2;
const Aegis128LMac_128 = std.crypto.auth.aegis.Aegis128LMac_128;

pub const key_length = 16;
pub const nonce_length = 16;
pub const tag_length = 16;
pub const mac_length = 16;
pub const header_size = nonce_length + mac_length; // 32 bytes
pub const overhead_size = header_size + tag_length; // 48 bytes

/// Domain separator for version 1 of TurboCrypt format
const domain_separator = "TC01";

/// Derived keys from master key using TurboSHAKE128
pub const DerivedKeys = struct {
    header_mac_key: [16]u8,
    encryption_key: [16]u8,
    filename_key: [16]u8,
};

/// Derive three separate keys from the master key using TurboSHAKE128
/// Input: master_key || "turbocrypt" || ("-" || context if provided)
/// Output: 48 bytes split into three 16-byte keys
///
/// The optional context parameter allows deriving different keys from the same master key.
/// This enables encrypting different directories with cryptographically independent keys
/// while using a single master key. The same context must be used for both encryption and decryption.
pub fn deriveKeys(master_key: [key_length]u8, context: ?[]const u8) DerivedKeys {
    // Import TurboShake128 from std.crypto.hash.sha3
    const sha3 = @import("std").crypto.hash.sha3;
    const TurboShake = sha3.TurboShake128(null);
    var shake = TurboShake.init(.{});

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

    // Extract 48 bytes
    var output: [48]u8 = undefined;
    shake.squeeze(&output);

    // Split into three 16-byte keys
    return DerivedKeys{
        .header_mac_key = output[0..16].*,
        .encryption_key = output[16..32].*,
        .filename_key = output[32..48].*,
    };
}

/// Generate a header MAC for the given nonce and header_mac_key
/// MAC = Aegis128LMac_128(header_mac_key, "TC01" || nonce)
fn computeHeaderMac(nonce: [nonce_length]u8, header_mac_key: [key_length]u8) [mac_length]u8 {
    // Construct message: "TC01" || nonce (4 + 16 = 20 bytes)
    var msg: [domain_separator.len + nonce_length]u8 = undefined;
    @memcpy(msg[0..domain_separator.len], domain_separator);
    @memcpy(msg[domain_separator.len..], &nonce);

    // Compute MAC
    var mac: [mac_length]u8 = undefined;
    Aegis128LMac_128.create(&mac, &msg, &header_mac_key);

    return mac;
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
) ![]u8 {
    // Generate random nonce
    var nonce: [nonce_length]u8 = undefined;
    std.crypto.random.bytes(&nonce);

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
        &[_]u8{}, // empty associated data
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
) void {
    // Verify output buffer size
    std.debug.assert(output.len == plaintext.len + overhead_size);

    // Generate random nonce
    var nonce: [nonce_length]u8 = undefined;
    std.crypto.random.bytes(&nonce);

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
        &[_]u8{}, // empty associated data
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

    const key: [key_length]u8 = @splat(1);
    const derived = deriveKeys(key, null);
    const plaintext = "Hello, World! This is a test message.";

    // Encrypt
    const encrypted = try encrypt(plaintext, derived, allocator);
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

    const key1: [key_length]u8 = @splat(1);
    const key2: [key_length]u8 = @splat(2);
    const derived1 = deriveKeys(key1, null);
    const derived2 = deriveKeys(key2, null);
    const plaintext = "Secret message";

    // Encrypt with key1
    const encrypted = try encrypt(plaintext, derived1, allocator);
    defer allocator.free(encrypted);

    // Try to decrypt with key2 - should fail with InvalidHeaderMAC
    const result = decrypt(encrypted, derived2, allocator);
    try testing.expectError(error.InvalidHeaderMAC, result);
}

test "decrypt corrupted ciphertext fails" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const key: [key_length]u8 = @splat(1);
    const derived = deriveKeys(key, null);
    const plaintext = "Test message";

    // Encrypt
    const encrypted = try encrypt(plaintext, derived, allocator);
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

    const key: [key_length]u8 = @splat(1);
    const derived = deriveKeys(key, null);
    const plaintext = "";

    // Encrypt empty plaintext
    const encrypted = try encrypt(plaintext, derived, allocator);
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
    const encrypted = try encrypt(plaintext, derived, allocator);
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

    const key: [key_length]u8 = @splat(1);
    const derived = deriveKeys(key, null);
    const plaintext = "Test message for verification";

    // Encrypt
    const encrypted = try encrypt(plaintext, derived, allocator);
    defer allocator.free(encrypted);

    // Verify should succeed
    try verify(encrypted, derived, allocator);
}

test "verify with wrong key fails" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const key1: [key_length]u8 = @splat(1);
    const key2: [key_length]u8 = @splat(2);
    const derived1 = deriveKeys(key1, null);
    const derived2 = deriveKeys(key2, null);
    const plaintext = "Secret message";

    // Encrypt with key1
    const encrypted = try encrypt(plaintext, derived1, allocator);
    defer allocator.free(encrypted);

    // Verify with key2 should fail with InvalidHeaderMAC
    const result = verify(encrypted, derived2, allocator);
    try testing.expectError(error.InvalidHeaderMAC, result);
}

test "verify corrupted ciphertext fails" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const key: [key_length]u8 = @splat(1);
    const derived = deriveKeys(key, null);
    const plaintext = "Test message";

    // Encrypt
    const encrypted = try encrypt(plaintext, derived, allocator);
    defer allocator.free(encrypted);

    // Corrupt ciphertext
    encrypted[header_size] ^= 0xFF;

    // Verify should fail with AuthenticationFailed
    const result = verify(encrypted, derived, allocator);
    try testing.expectError(error.AuthenticationFailed, result);
}
