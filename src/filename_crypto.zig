const std = @import("std");
const hctr2 = @import("hctr2");
const base84 = @import("base84");

/// HCTR2 needs at least one AES block.
/// The padding also keeps every encrypted name longer than a reserved Windows device name, such as CON.
const min_padded_length = 16;

const max_stack_filename_length = 256;

const max_stack_encoded_length = base84.standard.calcSizeUpperBound(max_stack_filename_length);

const max_decoded_length = base84.standard.calcDecodedSizeUpperBound(filesystem_filename_limit);

/// ext4, APFS and NTFS all stop at 255 bytes.
const filesystem_filename_limit = 255;

pub const FilenameError = error{
    EncryptedFilenameTooLong,
};

/// Errors of the strict decryption used for names that come from a git store
pub const StrictError = error{
    InvalidEncryptedFilename,
    UnsafeDecryptedFilename,
};

/// Names are padded with zero bytes to 16 bytes at least, encrypted with HCTR2 and an empty tweak, then base84 encoded.
/// The base84 alphabet is valid in file names on Linux, macOS and Windows.
///
/// "." and ".." stay as they are. The caller frees the result.
pub fn encryptFilename(
    allocator: std.mem.Allocator,
    plaintext_name: []const u8,
    filename_key: [16]u8,
) ![]u8 {
    if (std.mem.eql(u8, plaintext_name, ".") or std.mem.eql(u8, plaintext_name, "..")) {
        return allocator.dupe(u8, plaintext_name);
    }

    const padded_len = @max(plaintext_name.len, min_padded_length);

    if (padded_len <= max_stack_filename_length) {
        var padded_buf: [max_stack_filename_length]u8 = undefined;
        const padded = padded_buf[0..padded_len];

        @memcpy(padded[0..plaintext_name.len], plaintext_name);
        if (padded_len > plaintext_name.len) {
            @memset(padded[plaintext_name.len..], 0);
        }

        var cipher = hctr2.Hctr2_128.init(filename_key);
        var ciphertext_buf: [max_stack_filename_length]u8 = undefined;
        const ciphertext = ciphertext_buf[0..padded_len];

        try cipher.encrypt(ciphertext, padded, &[_]u8{});

        var encode_buf: [max_stack_encoded_length]u8 = undefined;
        const encoded = try base84.standard.encode(&encode_buf, ciphertext);

        if (encoded.len > filesystem_filename_limit) {
            return FilenameError.EncryptedFilenameTooLong;
        }

        return allocator.dupe(u8, encoded);
    } else {
        var padded = try allocator.alloc(u8, padded_len);
        defer allocator.free(padded);

        @memcpy(padded[0..plaintext_name.len], plaintext_name);
        if (padded_len > plaintext_name.len) {
            @memset(padded[plaintext_name.len..], 0);
        }

        var cipher = hctr2.Hctr2_128.init(filename_key);
        const ciphertext = try allocator.alloc(u8, padded_len);
        defer allocator.free(ciphertext);

        try cipher.encrypt(ciphertext, padded, &[_]u8{});

        const upper_bound = base84.standard.calcSizeUpperBound(ciphertext.len);
        const encode_buf = try allocator.alloc(u8, upper_bound);
        errdefer allocator.free(encode_buf);

        const encoded = try base84.standard.encode(encode_buf, ciphertext);

        if (encoded.len > filesystem_filename_limit) {
            return FilenameError.EncryptedFilenameTooLong;
        }

        return allocator.realloc(encode_buf, encoded.len);
    }
}

/// Decrypt a name that comes from an untrusted place, such as a git store.
///
/// Only the canonical encoding of a usable path component is accepted.
/// Anything else is an error rather than being passed through.
/// The caller frees the result.
pub fn decryptFilenameStrict(
    allocator: std.mem.Allocator,
    encrypted_name: []const u8,
    filename_key: [16]u8,
) ![]u8 {
    return decryptFilenameCanonical(allocator, encrypted_name, filename_key, .strict);
}

/// What a decrypted name may contain.
/// `strict` is for names that are printed and joined with '/'. `filesystem` is for native paths with the given separator.
const DecryptionSafety = union(enum) {
    strict,
    filesystem: u8,
};

fn decryptFilenameCanonical(
    allocator: std.mem.Allocator,
    encrypted_name: []const u8,
    filename_key: [16]u8,
    safety: DecryptionSafety,
) ![]u8 {
    if (encrypted_name.len == 0 or encrypted_name.len > filesystem_filename_limit) {
        return StrictError.InvalidEncryptedFilename;
    }

    var decode_buf: [max_decoded_length]u8 = undefined;
    const ciphertext = base84.standard.decode(&decode_buf, encrypted_name) catch {
        return StrictError.InvalidEncryptedFilename;
    };

    var padded_buf: [max_decoded_length]u8 = undefined;
    const padded = padded_buf[0..ciphertext.len];
    var cipher = hctr2.Hctr2_128.init(filename_key);
    cipher.decrypt(padded, ciphertext, &[_]u8{}) catch {
        return StrictError.InvalidEncryptedFilename;
    };

    // The base84 decoder is strict, so the name is canonical when the padding is what encryptFilename adds.
    const name = padded[0 .. std.mem.indexOfScalar(u8, padded, 0) orelse padded.len];
    if (padded.len != @max(name.len, min_padded_length) or !std.mem.allEqual(u8, padded[name.len..], 0)) {
        return StrictError.InvalidEncryptedFilename;
    }
    const safe = switch (safety) {
        .strict => isSafeComponent(name),
        .filesystem => |sep| isSafeFilesystemComponent(name, sep),
    };
    if (!safe) return StrictError.UnsafeDecryptedFilename;

    return allocator.dupe(u8, name);
}

/// A decrypted name that can stand as one component of a native path.
fn isSafeFilesystemComponent(name: []const u8, sep: u8) bool {
    if (name.len == 0) return false;
    if (std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, "..")) return false;
    for (name) |c| {
        if (c == 0 or c == sep) return false;
        if (sep == std.fs.path.sep_windows and c == std.fs.path.sep_posix) return false;
    }
    return true;
}

/// A decrypted name is safe when it cannot leave its directory and cannot confuse a terminal or a shell script that prints it.
pub fn isSafeComponent(name: []const u8) bool {
    if (!isSafeFilesystemComponent(name, std.fs.path.sep_windows)) return false;
    for (name) |c| {
        if (c < 0x20 or c == 0x7f) return false;
    }
    return true;
}

/// Decrypt a relative path from a git store, one component at a time.
/// Git reports paths with '/' on every platform. The caller frees the result.
pub fn decryptPathStrict(
    allocator: std.mem.Allocator,
    encrypted_path: []const u8,
    filename_key: [16]u8,
) ![]u8 {
    return decryptPathWith(allocator, encrypted_path, filename_key, .strict);
}

/// Decrypt a filesystem path without allowing decrypted components to change its structure.
/// A name that does not decode is kept as it is, so a directory can mix encrypted and plain names.
/// A plain name that happens to decode cannot be told from an encrypted one.
/// The caller frees the result.
pub fn decryptPathForFilesystem(
    allocator: std.mem.Allocator,
    encrypted_path: []const u8,
    filename_key: [16]u8,
    sep: u8,
) ![]u8 {
    return decryptPathWith(allocator, encrypted_path, filename_key, .{ .filesystem = sep });
}

/// Empty components are rejected, so an absolute path or a doubled separator is an error rather than being silently dropped.
fn decryptPathWith(
    allocator: std.mem.Allocator,
    encrypted_path: []const u8,
    filename_key: [16]u8,
    safety: DecryptionSafety,
) ![]u8 {
    const sep: u8 = switch (safety) {
        .strict => std.fs.path.sep_posix,
        .filesystem => |s| s,
    };
    var components: std.ArrayList([]const u8) = .empty;
    defer {
        for (components.items) |component| {
            allocator.free(component);
        }
        components.deinit(allocator);
    }

    var it = std.mem.splitScalar(u8, encrypted_path, sep);
    while (it.next()) |component| {
        if (component.len == 0) return StrictError.InvalidEncryptedFilename;

        const decrypted = decryptFilenameCanonical(allocator, component, filename_key, safety) catch |err| switch (err) {
            StrictError.InvalidEncryptedFilename => if (safety == .filesystem) try allocator.dupe(u8, component) else return err,
            else => return err,
        };
        errdefer allocator.free(decrypted);
        try components.append(allocator, decrypted);
    }
    if (components.items.len == 0) return StrictError.InvalidEncryptedFilename;

    return std.mem.join(allocator, &.{sep}, components.items);
}

/// Encrypt a path one component at a time.
/// `sep` separates the components: the native separator for filesystem paths, '/' for paths that git reports.
/// The caller frees the result.
pub fn encryptPath(
    allocator: std.mem.Allocator,
    path: []const u8,
    filename_key: [16]u8,
    sep: u8,
) ![]u8 {
    var components: std.ArrayList([]const u8) = .empty;
    defer {
        for (components.items) |component| {
            allocator.free(component);
        }
        components.deinit(allocator);
    }

    var it = std.mem.splitScalar(u8, path, sep);
    while (it.next()) |component| {
        // A leading separator gives an empty component.
        if (component.len == 0) continue;

        const encrypted = try encryptFilename(allocator, component, filename_key);
        try components.append(allocator, encrypted);
    }

    return std.mem.join(allocator, &.{sep}, components.items);
}

test "encrypt and decrypt filename" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const key: [16]u8 = @splat(0x42);
    const plaintext = "myfile.txt";

    const encrypted = try encryptFilename(allocator, plaintext, key);
    defer allocator.free(encrypted);

    const decrypted = try decryptFilenameStrict(allocator, encrypted, key);
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

    const decrypted_path = try decryptPathForFilesystem(allocator, encrypted_path, key, '/');
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

    const decrypted = try decryptFilenameStrict(allocator, encrypted, key);
    defer allocator.free(decrypted);

    try testing.expectEqualStrings(long_name, decrypted);
}

test "filename encryption length validation" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const key: [16]u8 = @splat(0x42);

    const long_name = "tracing_attributes-9e84d350f1142111.tracing_attributes.cb6dd642f55c194a-cgu.15.rcgu.o";
    const encrypted = try encryptFilename(allocator, long_name, key);
    defer allocator.free(encrypted);
    try testing.expect(encrypted.len <= filesystem_filename_limit);

    // Names of up to 197 bytes fit whatever the ciphertext looks like.
    const safe_lengths = [_]usize{ 50, 100, 150, 197 };
    for (safe_lengths) |len| {
        const test_name = try allocator.alloc(u8, len);
        defer allocator.free(test_name);
        @memset(test_name, 'a');

        const enc = try encryptFilename(allocator, test_name, key);
        defer allocator.free(enc);

        try testing.expect(enc.len <= filesystem_filename_limit);
    }

    // Names of 205 bytes or more never fit. The last length takes the heap path.
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
        const name = name_buf[0 .. 3 + random.uintLessThan(usize, name_buf.len - 2)];
        random.bytes(name);

        const encrypted = try encryptFilename(allocator, name, key);
        defer allocator.free(encrypted);

        // Reserved device names like CON are short, and a period never shows up.
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

test "filesystem path decrypt preserves names without allowing new separators" {
    const testing = std.testing;
    const allocator = testing.allocator;
    const key: [16]u8 = @splat(0x42);

    const unusual_name = "line\nbreak\\name";
    const encrypted = try encryptFilename(allocator, unusual_name, key);
    defer allocator.free(encrypted);
    const decrypted = try decryptPathForFilesystem(allocator, encrypted, key, '/');
    defer allocator.free(decrypted);
    try testing.expectEqualStrings(unusual_name, decrypted);

    const plain = try decryptPathForFilesystem(allocator, "not encrypted.txt", key, '/');
    defer allocator.free(plain);
    try testing.expectEqualStrings("not encrypted.txt", plain);

    const planted = try encryptFilename(allocator, "../outside", key);
    defer allocator.free(planted);
    try testing.expectError(StrictError.UnsafeDecryptedFilename, decryptPathForFilesystem(allocator, planted, key, '/'));
}
