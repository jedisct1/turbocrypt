const std = @import("std");
const hctr2 = @import("hctr2");
const base91 = @import("base91");

/// Minimum filename length before encryption (padded with null bytes)
/// HCTR2 requires minimum 16 bytes (one AES block).
/// This prevents path length explosion for deeply nested directories.
const min_padded_length = 16;

/// Maximum filename length to use stack buffers (typical filesystem limit is 255)
const max_stack_filename_length = 256;

/// Maximum base91 encoded size for stack buffer (conservative upper bound)
const max_stack_encoded_length = 384;

/// Encrypt a single filename component using HCTR2 and base91 encoding
///
/// The filename is padded to a minimum of 16 bytes (HCTR2 minimum block size) with null bytes (0x00),
/// encrypted with HCTR2 using an empty tweak, then encoded with base91
/// using the filesystem-safe alphabet.
///
/// Special filenames "." and ".." are not encrypted.
///
/// Uses stack buffers for typical filenames (<=256 bytes), falls back to heap for longer names.
///
/// Note: The key parameter should be the derived filename_key from DerivedKeys.
///
/// Returns: Owned slice that caller must free
pub fn encryptFilename(
    allocator: std.mem.Allocator,
    plaintext_name: []const u8,
    filename_key: [16]u8,
) ![]u8 {
    // Don't encrypt special directory entries
    if (std.mem.eql(u8, plaintext_name, ".") or std.mem.eql(u8, plaintext_name, "..")) {
        return allocator.dupe(u8, plaintext_name);
    }

    // Pad to minimum 64 bytes with null bytes
    const padded_len = @max(plaintext_name.len, min_padded_length);

    // Use stack buffers for typical filenames
    if (padded_len <= max_stack_filename_length) {
        var padded_buf: [max_stack_filename_length]u8 = undefined;
        const padded = padded_buf[0..padded_len];

        // Copy plaintext and fill rest with null bytes
        @memcpy(padded[0..plaintext_name.len], plaintext_name);
        if (padded_len > plaintext_name.len) {
            @memset(padded[plaintext_name.len..], 0);
        }

        // Encrypt with HCTR2 using empty tweak
        var cipher = hctr2.Hctr2_128.init(filename_key);
        var ciphertext_buf: [max_stack_filename_length]u8 = undefined;
        const ciphertext = ciphertext_buf[0..padded_len];

        try cipher.encrypt(ciphertext, padded, &[_]u8{});

        // Encode with base91 filesystem alphabet
        var encode_buf: [max_stack_encoded_length]u8 = undefined;
        const encoded = try base91.filesystem.encode(&encode_buf, ciphertext);

        // Return owned copy
        return allocator.dupe(u8, encoded);
    } else {
        // Fall back to heap allocation for long filenames
        var padded = try allocator.alloc(u8, padded_len);
        defer allocator.free(padded);

        // Copy plaintext and fill rest with null bytes
        @memcpy(padded[0..plaintext_name.len], plaintext_name);
        if (padded_len > plaintext_name.len) {
            @memset(padded[plaintext_name.len..], 0);
        }

        // Encrypt with HCTR2 using empty tweak
        var cipher = hctr2.Hctr2_128.init(filename_key);
        var ciphertext = try allocator.alloc(u8, padded_len);
        defer allocator.free(ciphertext);

        try cipher.encrypt(ciphertext, padded, &[_]u8{});

        // Encode with base91 filesystem alphabet
        const upper_bound = base91.filesystem.calcSizeUpperBound(ciphertext.len);
        const encode_buf = try allocator.alloc(u8, upper_bound);
        errdefer allocator.free(encode_buf);

        const encoded = try base91.filesystem.encode(encode_buf, ciphertext);

        // Resize to actual encoded length
        return allocator.realloc(encode_buf, encoded.len);
    }
}

/// Decrypt a filename encrypted with encryptFilename
///
/// Decodes from base91, decrypts with HCTR2, and removes null byte padding.
/// If the filename cannot be decoded (i.e., never encrypted), returns it unchanged.
///
/// Uses stack buffers for typical filenames (<=384 bytes encoded), falls back to heap for longer names.
///
/// Note: The key parameter should be the derived filename_key from DerivedKeys.
///
/// Returns: Owned slice that caller must free
pub fn decryptFilename(
    allocator: std.mem.Allocator,
    encrypted_name: []const u8,
    filename_key: [16]u8,
) ![]u8 {
    // Don't decrypt special directory entries
    if (std.mem.eql(u8, encrypted_name, ".") or std.mem.eql(u8, encrypted_name, "..")) {
        return allocator.dupe(u8, encrypted_name);
    }

    // Use stack buffers for typical filenames
    if (encrypted_name.len <= max_stack_encoded_length) {
        // Try to decode from base91 using stack buffer
        var decode_buf: [max_stack_filename_length]u8 = undefined;

        const ciphertext = base91.filesystem.decode(&decode_buf, encrypted_name) catch {
            // Not a valid base91 string - return as-is (was never encrypted)
            return allocator.dupe(u8, encrypted_name);
        };

        // Decrypt with HCTR2
        var cipher = hctr2.Hctr2_128.init(filename_key);
        var padded_buf: [max_stack_filename_length]u8 = undefined;
        const padded = padded_buf[0..ciphertext.len];

        cipher.decrypt(padded, ciphertext, &[_]u8{}) catch {
            // Decryption failed (e.g., InputTooShort) - return as-is (was never encrypted)
            return allocator.dupe(u8, encrypted_name);
        };

        // Remove null byte padding (find first null byte)
        const actual_len = std.mem.indexOfScalar(u8, padded, 0) orelse padded.len;

        // Return owned copy
        return allocator.dupe(u8, padded[0..actual_len]);
    } else {
        // Fall back to heap allocation for long filenames
        const decode_upper_bound = base91.filesystem.calcDecodedSizeUpperBound(encrypted_name.len);
        const decode_buf = try allocator.alloc(u8, decode_upper_bound);
        defer allocator.free(decode_buf);

        const ciphertext = base91.filesystem.decode(decode_buf, encrypted_name) catch {
            // Not a valid base91 string - return as-is (was never encrypted)
            return allocator.dupe(u8, encrypted_name);
        };

        // Decrypt with HCTR2
        var cipher = hctr2.Hctr2_128.init(filename_key);
        var padded = try allocator.alloc(u8, ciphertext.len);
        defer allocator.free(padded);

        cipher.decrypt(padded, ciphertext, &[_]u8{}) catch {
            // Decryption failed (e.g., InputTooShort) - return as-is (was never encrypted)
            return allocator.dupe(u8, encrypted_name);
        };

        // Remove null byte padding (find first null byte)
        const actual_len = std.mem.indexOfScalar(u8, padded, 0) orelse padded.len;

        // Return unpadded plaintext
        return allocator.dupe(u8, padded[0..actual_len]);
    }
}

/// Encrypt a full path by encrypting each component separately
///
/// Path components are split by '/', each encrypted independently,
/// then rejoined with '/' to preserve directory structure.
///
/// Note: The key parameter should be the derived filename_key from DerivedKeys.
///
/// Returns: Owned slice that caller must free
pub fn encryptPath(
    allocator: std.mem.Allocator,
    path: []const u8,
    filename_key: [16]u8,
) ![]u8 {
    // Split path by separator
    var components = std.ArrayList([]const u8){};
    defer {
        for (components.items) |component| {
            allocator.free(component);
        }
        components.deinit(allocator);
    }

    var it = std.mem.splitScalar(u8, path, '/');
    while (it.next()) |component| {
        if (component.len == 0) continue; // Skip empty components (e.g., leading slash)

        const encrypted = try encryptFilename(allocator, component, filename_key);
        try components.append(allocator, encrypted);
    }

    // Join encrypted components with '/'
    return std.mem.join(allocator, "/", components.items);
}

/// Decrypt a path encrypted with encryptPath
///
/// Note: The key parameter should be the derived filename_key from DerivedKeys.
///
/// Returns: Owned slice that caller must free
pub fn decryptPath(
    allocator: std.mem.Allocator,
    encrypted_path: []const u8,
    filename_key: [16]u8,
) ![]u8 {
    // Split path by separator
    var components = std.ArrayList([]const u8){};
    defer {
        for (components.items) |component| {
            allocator.free(component);
        }
        components.deinit(allocator);
    }

    var it = std.mem.splitScalar(u8, encrypted_path, '/');
    while (it.next()) |component| {
        if (component.len == 0) continue; // Skip empty components

        const decrypted = try decryptFilename(allocator, component, filename_key);
        try components.append(allocator, decrypted);
    }

    // Join decrypted components with '/'
    return std.mem.join(allocator, "/", components.items);
}

// Tests
test "encrypt and decrypt filename" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const key = [_]u8{0x42} ** 16;
    const plaintext = "myfile.txt";

    const encrypted = try encryptFilename(allocator, plaintext, key);
    defer allocator.free(encrypted);

    const decrypted = try decryptFilename(allocator, encrypted, key);
    defer allocator.free(decrypted);

    try testing.expectEqualStrings(plaintext, decrypted);
}

test "special directory entries not encrypted" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const key = [_]u8{0x42} ** 16;

    const dot_encrypted = try encryptFilename(allocator, ".", key);
    defer allocator.free(dot_encrypted);
    try testing.expectEqualStrings(".", dot_encrypted);

    const dotdot_encrypted = try encryptFilename(allocator, "..", key);
    defer allocator.free(dotdot_encrypted);
    try testing.expectEqualStrings("..", dotdot_encrypted);
}

test "encrypt and decrypt path" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const key = [_]u8{0x42} ** 16;
    const plaintext_path = "dir/subdir/file.txt";

    const encrypted_path = try encryptPath(allocator, plaintext_path, key);
    defer allocator.free(encrypted_path);

    const decrypted_path = try decryptPath(allocator, encrypted_path, key);
    defer allocator.free(decrypted_path);

    try testing.expectEqualStrings(plaintext_path, decrypted_path);
}

test "long filename encryption" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const key = [_]u8{0x42} ** 16;
    const long_name = "this_is_a_very_long_filename_that_exceeds_the_minimum_padding_length_of_64_bytes_for_testing.txt";

    const encrypted = try encryptFilename(allocator, long_name, key);
    defer allocator.free(encrypted);

    const decrypted = try decryptFilename(allocator, encrypted, key);
    defer allocator.free(decrypted);

    try testing.expectEqualStrings(long_name, decrypted);
}

test "filename encryption length analysis" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const key = [_]u8{0x42} ** 16;

    // Test with the 85-character filename from varnish
    const varnish_name = "tracing_attributes-9e84d350f1142111.tracing_attributes.cb6dd642f55c194a-cgu.15.rcgu.o";
    const encrypted = try encryptFilename(allocator, varnish_name, key);
    defer allocator.free(encrypted);

    std.debug.print("\nFilename encryption length analysis:\n", .{});
    std.debug.print("  Original: '{s}' ({d} bytes)\n", .{ varnish_name, varnish_name.len });
    std.debug.print("  Encrypted: '{s}' ({d} bytes)\n", .{ encrypted, encrypted.len });
    std.debug.print("  Filesystem limit: 255 bytes\n", .{});
    if (encrypted.len > 255) {
        std.debug.print("  ❌ ERROR: Exceeds limit by {d} bytes\n", .{encrypted.len - 255});
    } else {
        std.debug.print("  ✓ OK: Fits within limit ({d} bytes remaining)\n", .{255 - encrypted.len});
    }

    // Test various lengths to find the breaking point
    std.debug.print("\nTesting various filename lengths:\n", .{});
    const test_lengths = [_]usize{ 50, 100, 150, 200, 205, 210, 215, 220 };
    for (test_lengths) |len| {
        const test_name = try allocator.alloc(u8, len);
        defer allocator.free(test_name);
        @memset(test_name, 'a');

        const enc = try encryptFilename(allocator, test_name, key);
        defer allocator.free(enc);

        const status = if (enc.len > 255) "❌ TOO LONG" else "✓ OK";
        std.debug.print("  {s} | {d:3} bytes -> {d:3} bytes\n", .{ status, len, enc.len });
    }
}
