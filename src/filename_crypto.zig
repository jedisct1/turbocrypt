const std = @import("std");
const hctr2 = @import("hctr2");
const base84 = @import("base84");

/// Minimum filename length before encryption (padded with null bytes)
/// HCTR2 requires minimum 16 bytes (one AES block).
/// This prevents path length explosion for deeply nested directories.
/// It also keeps every encrypted name longer than any reserved Windows device name, such as CON.
const min_padded_length = 16;

/// Maximum filename length to use stack buffers (typical filesystem limit is 255)
const max_stack_filename_length = 256;

/// Longest encoded name that fits the stack buffers
const max_stack_encoded_length = base84.standard.calcSizeUpperBound(max_stack_filename_length);

/// Decoded size that a name of that length can reach
const max_stack_decoded_length = base84.standard.calcDecodedSizeUpperBound(max_stack_encoded_length);

/// Filesystem filename length limit (ext4, APFS, NTFS all support 255 bytes)
const filesystem_filename_limit = 255;

/// Error for when encrypted filename exceeds filesystem limits
pub const FilenameError = error{
    EncryptedFilenameTooLong,
};

/// Errors of the strict decryption used for names that come from a git store
pub const StrictError = error{
    InvalidEncryptedFilename,
    UnsafeDecryptedFilename,
};

/// Encrypt a single filename component using HCTR2 and base84 encoding
///
/// The filename is padded to a minimum of 16 bytes (HCTR2 minimum block size) with null bytes (0x00),
/// encrypted with HCTR2 using an empty tweak, then encoded with base84,
/// whose alphabet is valid in file names on Linux, macOS and Windows.
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

    // Pad to minimum 16 bytes with null bytes
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

        var encode_buf: [max_stack_encoded_length]u8 = undefined;
        const encoded = try base84.standard.encode(&encode_buf, ciphertext);

        // Validate that encrypted filename fits within filesystem limit
        if (encoded.len > filesystem_filename_limit) {
            return FilenameError.EncryptedFilenameTooLong;
        }

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
        const ciphertext = try allocator.alloc(u8, padded_len);
        defer allocator.free(ciphertext);

        try cipher.encrypt(ciphertext, padded, &[_]u8{});

        const upper_bound = base84.standard.calcSizeUpperBound(ciphertext.len);
        const encode_buf = try allocator.alloc(u8, upper_bound);
        errdefer allocator.free(encode_buf);

        const encoded = try base84.standard.encode(encode_buf, ciphertext);

        // Validate that encrypted filename fits within filesystem limit
        if (encoded.len > filesystem_filename_limit) {
            return FilenameError.EncryptedFilenameTooLong;
        }

        // Resize to actual encoded length
        return allocator.realloc(encode_buf, encoded.len);
    }
}

/// Decrypt a filename encrypted with encryptFilename
///
/// Decodes from base84, decrypts with HCTR2, and removes null byte padding.
/// If the filename cannot be decoded (i.e., never encrypted), returns it unchanged.
///
/// Uses stack buffers for typical filenames, falls back to heap for longer names.
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
        var decode_buf: [max_stack_decoded_length]u8 = undefined;

        const ciphertext = base84.standard.decode(&decode_buf, encrypted_name) catch {
            // A name that does not decode was never encrypted
            return allocator.dupe(u8, encrypted_name);
        };

        // Decrypt with HCTR2
        var cipher = hctr2.Hctr2_128.init(filename_key);
        var padded_buf: [max_stack_decoded_length]u8 = undefined;
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
        const decode_upper_bound = base84.standard.calcDecodedSizeUpperBound(encrypted_name.len);
        const decode_buf = try allocator.alloc(u8, decode_upper_bound);
        defer allocator.free(decode_buf);

        const ciphertext = base84.standard.decode(decode_buf, encrypted_name) catch {
            // A name that does not decode was never encrypted
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

/// Decrypt a name that comes from an untrusted place, such as a git store.
///
/// decryptFilename returns its input when decoding fails, which hides a wrong key or a planted name.
/// This variant fails instead.
/// The result must be usable as one path component, and only the canonical encoding of that component is accepted.
///
/// Returns: Owned slice that caller must free
pub fn decryptFilenameStrict(
    allocator: std.mem.Allocator,
    encrypted_name: []const u8,
    filename_key: [16]u8,
) ![]u8 {
    if (encrypted_name.len == 0 or encrypted_name.len > filesystem_filename_limit) {
        return StrictError.InvalidEncryptedFilename;
    }

    const decode_buf = try allocator.alloc(u8, base84.standard.calcDecodedSizeUpperBound(encrypted_name.len));
    defer allocator.free(decode_buf);
    const ciphertext = base84.standard.decode(decode_buf, encrypted_name) catch {
        return StrictError.InvalidEncryptedFilename;
    };

    const padded = try allocator.alloc(u8, ciphertext.len);
    defer allocator.free(padded);
    var cipher = hctr2.Hctr2_128.init(filename_key);
    cipher.decrypt(padded, ciphertext, &[_]u8{}) catch {
        return StrictError.InvalidEncryptedFilename;
    };

    const name = padded[0 .. std.mem.indexOfScalar(u8, padded, 0) orelse padded.len];
    if (!isSafeComponent(name)) {
        return StrictError.UnsafeDecryptedFilename;
    }

    const canonical = try encryptFilename(allocator, name, filename_key);
    defer allocator.free(canonical);
    if (!std.mem.eql(u8, canonical, encrypted_name)) {
        return StrictError.InvalidEncryptedFilename;
    }

    return allocator.dupe(u8, name);
}

/// A decrypted name is safe when it cannot leave its directory and cannot confuse a terminal or a shell script that prints it.
pub fn isSafeComponent(name: []const u8) bool {
    if (name.len == 0) return false;
    if (std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, "..")) return false;
    for (name) |c| {
        if (c == '/' or c == '\\' or c < 0x20 or c == 0x7f) return false;
    }
    return true;
}

/// Decrypt a relative path from a git store, one component at a time.
///
/// Git reports paths with '/' on every platform.
/// Empty components are rejected, so an absolute path or a doubled separator is an error rather than being silently dropped.
///
/// Returns: Owned slice that caller must free
pub fn decryptPathStrict(
    allocator: std.mem.Allocator,
    encrypted_path: []const u8,
    filename_key: [16]u8,
) ![]u8 {
    var components: std.ArrayList([]const u8) = .empty;
    defer {
        for (components.items) |component| {
            allocator.free(component);
        }
        components.deinit(allocator);
    }

    var it = std.mem.splitScalar(u8, encrypted_path, std.fs.path.sep_posix);
    while (it.next()) |component| {
        if (component.len == 0) return StrictError.InvalidEncryptedFilename;

        const decrypted = try decryptFilenameStrict(allocator, component, filename_key);
        errdefer allocator.free(decrypted);
        try components.append(allocator, decrypted);
    }
    if (components.items.len == 0) return StrictError.InvalidEncryptedFilename;

    return std.mem.join(allocator, std.fs.path.sep_str_posix, components.items);
}

/// Encrypt a full path by encrypting each component separately
///
/// `sep` separates the components: the native separator for filesystem paths, '/' for paths that git reports.
///
/// Note: The key parameter should be the derived filename_key from DerivedKeys.
///
/// Returns: Owned slice that caller must free
pub fn encryptPath(
    allocator: std.mem.Allocator,
    path: []const u8,
    filename_key: [16]u8,
    sep: u8,
) ![]u8 {
    // Split path by separator
    var components: std.ArrayList([]const u8) = .empty;
    defer {
        for (components.items) |component| {
            allocator.free(component);
        }
        components.deinit(allocator);
    }

    var it = std.mem.splitScalar(u8, path, sep);
    while (it.next()) |component| {
        if (component.len == 0) continue; // Skip empty components (e.g., leading slash)

        const encrypted = try encryptFilename(allocator, component, filename_key);
        try components.append(allocator, encrypted);
    }

    return std.mem.join(allocator, &.{sep}, components.items);
}

/// Decrypt a path encrypted with encryptPath
///
/// `sep` is the separator that was given to encryptPath.
///
/// Note: The key parameter should be the derived filename_key from DerivedKeys.
///
/// Returns: Owned slice that caller must free
pub fn decryptPath(
    allocator: std.mem.Allocator,
    encrypted_path: []const u8,
    filename_key: [16]u8,
    sep: u8,
) ![]u8 {
    // Split path by separator
    var components: std.ArrayList([]const u8) = .empty;
    defer {
        for (components.items) |component| {
            allocator.free(component);
        }
        components.deinit(allocator);
    }

    var it = std.mem.splitScalar(u8, encrypted_path, sep);
    while (it.next()) |component| {
        if (component.len == 0) continue; // Skip empty components

        const decrypted = try decryptFilename(allocator, component, filename_key);
        try components.append(allocator, decrypted);
    }

    return std.mem.join(allocator, &.{sep}, components.items);
}

// Tests
test "encrypt and decrypt filename" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const key: [16]u8 = @splat(0x42);
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

    const key: [16]u8 = @splat(0x42);

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

    const key: [16]u8 = @splat(0x42);
    const plaintext_path = "dir/subdir/file.txt";

    const encrypted_path = try encryptPath(allocator, plaintext_path, key, '/');
    defer allocator.free(encrypted_path);

    const decrypted_path = try decryptPath(allocator, encrypted_path, key, '/');
    defer allocator.free(decrypted_path);

    try testing.expectEqualStrings(plaintext_path, decrypted_path);
}

test "long filename encryption" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const key: [16]u8 = @splat(0x42);
    const long_name = "this_is_a_very_long_filename_that_exceeds_the_minimum_padding_length_of_16_bytes_for_testing.txt";

    const encrypted = try encryptFilename(allocator, long_name, key);
    defer allocator.free(encrypted);

    const decrypted = try decryptFilename(allocator, encrypted, key);
    defer allocator.free(decrypted);

    try testing.expectEqualStrings(long_name, decrypted);
}

test "filename encryption length validation" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const key: [16]u8 = @splat(0x42);

    // Test that typical filenames encrypt successfully and fit within limit
    const long_name = "tracing_attributes-9e84d350f1142111.tracing_attributes.cb6dd642f55c194a-cgu.15.rcgu.o";
    const encrypted = try encryptFilename(allocator, long_name, key);
    defer allocator.free(encrypted);
    try testing.expect(encrypted.len <= filesystem_filename_limit);

    // Names of up to 197 bytes fit whatever the ciphertext looks like
    const safe_lengths = [_]usize{ 50, 100, 150, 197 };
    for (safe_lengths) |len| {
        const test_name = try allocator.alloc(u8, len);
        defer allocator.free(test_name);
        @memset(test_name, 'a');

        const enc = try encryptFilename(allocator, test_name, key);
        defer allocator.free(enc);

        try testing.expect(enc.len <= filesystem_filename_limit);
    }

    // Names of 205 bytes or more never fit
    // The last length takes the heap path
    const unsafe_lengths = [_]usize{ 205, 215, 220, max_stack_filename_length + 1 };
    for (unsafe_lengths) |len| {
        const test_name = try allocator.alloc(u8, len);
        defer allocator.free(test_name);
        @memset(test_name, 'a');

        const result = encryptFilename(allocator, test_name, key);
        try testing.expectError(FilenameError.EncryptedFilenameTooLong, result);
    }
}

test "encrypted names are valid file names on Windows" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const key: [16]u8 = @splat(0x42);
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();

    var name_buf: [64]u8 = undefined;
    for (0..1000) |_| {
        const name = name_buf[0 .. 1 + random.uintLessThan(usize, name_buf.len)];
        random.bytes(name);

        const encrypted = try encryptFilename(allocator, name, key);
        defer allocator.free(encrypted);

        // Reserved device names like CON are short, and a period never shows up
        try testing.expect(encrypted.len >= 20);
        try testing.expect(std.mem.findAny(u8, encrypted, " .<>:\"/\\|?*") == null);
        for (encrypted) |c| try testing.expect(c > 0x20 and c < 0x7f);
    }
}

test "strict decrypt round trips and rejects garbage" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const key: [16]u8 = @splat(0x42);
    const other_key: [16]u8 = @splat(0x43);

    const long_name: [197]u8 = @splat('a');
    const names = [_][]const u8{ "AGENT.md", "r\u{e9}sum\u{e9}.txt", &long_name };
    for (names) |name| {
        const encrypted = try encryptFilename(allocator, name, key);
        defer allocator.free(encrypted);

        const decrypted = try decryptFilenameStrict(allocator, encrypted, key);
        defer allocator.free(decrypted);
        try testing.expectEqualStrings(name, decrypted);
    }

    try testing.expectError(StrictError.InvalidEncryptedFilename, decryptFilenameStrict(allocator, "not base84 \x01", key));
    try testing.expectError(StrictError.InvalidEncryptedFilename, decryptFilenameStrict(allocator, "", key));
    try testing.expectError(StrictError.InvalidEncryptedFilename, decryptFilenameStrict(allocator, "abc", key));

    const encrypted = try encryptFilename(allocator, "AGENT.md", key);
    defer allocator.free(encrypted);
    const wrong = decryptFilenameStrict(allocator, encrypted, other_key);
    if (wrong) |name| allocator.free(name) else |err| {
        try testing.expect(err == StrictError.InvalidEncryptedFilename or err == StrictError.UnsafeDecryptedFilename);
    }
}

test "strict decrypt rejects names that leave the directory" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const key: [16]u8 = @splat(0x42);

    const planted = [_][]const u8{ "a/b", "tab\there" };
    for (planted) |name| {
        const encrypted = try encryptFilename(allocator, name, key);
        defer allocator.free(encrypted);
        try testing.expectError(StrictError.UnsafeDecryptedFilename, decryptFilenameStrict(allocator, encrypted, key));
    }

    var padded: [16]u8 = @splat(0);
    @memcpy(padded[0..2], "..");
    var cipher = hctr2.Hctr2_128.init(key);
    var ciphertext: [16]u8 = undefined;
    try cipher.encrypt(&ciphertext, &padded, &[_]u8{});
    var encode_buf: [64]u8 = undefined;
    const encoded = try base84.standard.encode(&encode_buf, &ciphertext);
    try testing.expectError(StrictError.UnsafeDecryptedFilename, decryptFilenameStrict(allocator, encoded, key));
}

test "strict path decrypt" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const key: [16]u8 = @splat(0x42);
    const encrypted_path = try encryptPath(allocator, "docs/internal.md", key, '/');
    defer allocator.free(encrypted_path);

    const decrypted = try decryptPathStrict(allocator, encrypted_path, key);
    defer allocator.free(decrypted);
    try testing.expectEqualStrings("docs/internal.md", decrypted);

    const with_leading_sep = try std.fmt.allocPrint(allocator, "/{s}", .{encrypted_path});
    defer allocator.free(with_leading_sep);
    try testing.expectError(StrictError.InvalidEncryptedFilename, decryptPathStrict(allocator, with_leading_sep, key));
    try testing.expectError(StrictError.InvalidEncryptedFilename, decryptPathStrict(allocator, "", key));
}
