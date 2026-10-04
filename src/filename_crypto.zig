//! Encrypts file and directory names into portable path components.

const std = @import("std");
const builtin = @import("builtin");
const mem = std.mem;
const testing = std.testing;
const Allocator = std.mem.Allocator;
const Io = std.Io;

const hctr2 = @import("hctr2");
const base84 = @import("base84");
const unicode = @import("unicode.zig");

/// HCTR2 requires at least one AES block.
/// This minimum also keeps encrypted names clear of Windows device names such as CON.
const min_padded_length = 16;

/// Keep encrypted components within the 255-byte limit shared by ext4, APFS, and NTFS.
const max_name_bytes = 255;
const max_decoded_length = base84.standard.calcDecodedSizeUpperBound(max_name_bytes);

const max_stack_filename_length = 256;
const max_stack_encoded_length = base84.standard.calcSizeUpperBound(max_stack_filename_length);

pub const Error = error{
    EncryptedFilenameTooLong,
};

/// Returned when an encrypted name is noncanonical or decrypts to an unsafe name.
pub const StrictError = error{
    InvalidEncryptedFilename,
    UnsafeDecryptedFilename,
};

/// Encrypt one path component into a file name that works on Linux, macOS, and Windows.
///
/// `.` and `..` remain unchanged so they retain their path meaning.
/// Caller owns returned memory.
pub fn encrypt(
    gpa: Allocator,
    plaintext_name: []const u8,
    filename_key: [16]u8,
) ![]u8 {
    if (mem.eql(u8, plaintext_name, ".") or mem.eql(u8, plaintext_name, "..")) {
        return gpa.dupe(u8, plaintext_name);
    }

    // Normalize macOS spellings so one file cannot acquire two encrypted names.
    const composed = try unicode.precompose(gpa, plaintext_name);
    defer if (composed) |c| gpa.free(c);
    const name = composed orelse plaintext_name;

    const padded_len = @max(name.len, min_padded_length);

    if (padded_len <= max_stack_filename_length) {
        var padded_buf: [max_stack_filename_length]u8 = undefined;
        const padded = padded_buf[0..padded_len];

        @memcpy(padded[0..name.len], name);
        @memset(padded[name.len..], 0);

        var cipher = hctr2.Hctr2_128.init(filename_key);
        var ciphertext_buf: [max_stack_filename_length]u8 = undefined;
        const ciphertext = ciphertext_buf[0..padded_len];

        try cipher.encrypt(ciphertext, padded, &.{});

        var encode_buf: [max_stack_encoded_length]u8 = undefined;
        const encoded = try base84.standard.encode(&encode_buf, ciphertext);

        if (encoded.len > max_name_bytes) {
            return Error.EncryptedFilenameTooLong;
        }

        return gpa.dupe(u8, encoded);
    } else {
        const padded = try gpa.alloc(u8, padded_len);
        defer gpa.free(padded);

        @memcpy(padded[0..name.len], name);
        @memset(padded[name.len..], 0);

        var cipher = hctr2.Hctr2_128.init(filename_key);
        const ciphertext = try gpa.alloc(u8, padded_len);
        defer gpa.free(ciphertext);

        try cipher.encrypt(ciphertext, padded, &.{});

        const upper_bound = base84.standard.calcSizeUpperBound(ciphertext.len);
        const encode_buf = try gpa.alloc(u8, upper_bound);
        errdefer gpa.free(encode_buf);

        const encoded = try base84.standard.encode(encode_buf, ciphertext);

        if (encoded.len > max_name_bytes) {
            return Error.EncryptedFilenameTooLong;
        }

        return gpa.realloc(encode_buf, encoded.len);
    }
}

/// Decrypt a name from untrusted storage, such as a Git store.
///
/// Reject noncanonical encodings and unsafe components instead of passing them through.
/// Caller owns returned memory.
pub fn decryptStrict(
    gpa: Allocator,
    encrypted_name: []const u8,
    filename_key: [16]u8,
) ![]u8 {
    return decryptCanonical(gpa, encrypted_name, filename_key, .strict);
}

/// Decrypt a name for use as a native path component.
///
/// Reject values that could escape the intended directory.
/// Caller owns returned memory.
pub fn decryptForFilesystem(
    gpa: Allocator,
    encrypted_name: []const u8,
    filename_key: [16]u8,
) ![]u8 {
    return decryptCanonical(gpa, encrypted_name, filename_key, .{ .filesystem = Io.Dir.path.sep });
}

/// Selects the path context used to validate a decrypted name.
/// `strict` protects portable paths and printed names.
/// `filesystem` protects native paths with the given separator.
const DecryptionSafety = union(enum) {
    strict,
    filesystem: u8,
};

fn decryptCanonical(
    gpa: Allocator,
    encrypted_name: []const u8,
    filename_key: [16]u8,
    safety: DecryptionSafety,
) ![]u8 {
    if (encrypted_name.len == 0 or encrypted_name.len > max_name_bytes) {
        return StrictError.InvalidEncryptedFilename;
    }

    var decode_buf: [max_decoded_length]u8 = undefined;
    const ciphertext = base84.standard.decode(&decode_buf, encrypted_name) catch {
        return StrictError.InvalidEncryptedFilename;
    };

    var padded_buf: [max_decoded_length]u8 = undefined;
    const padded = padded_buf[0..ciphertext.len];
    var cipher = hctr2.Hctr2_128.init(filename_key);
    cipher.decrypt(padded, ciphertext, &.{}) catch {
        return StrictError.InvalidEncryptedFilename;
    };

    // Require the padding written by `encrypt` so each ciphertext has one accepted spelling.
    const name = padded[0 .. mem.findScalar(u8, padded, 0) orelse padded.len];
    if (padded.len != @max(name.len, min_padded_length) or
        !mem.allEqual(u8, padded[name.len..], 0))
    {
        return StrictError.InvalidEncryptedFilename;
    }
    const safe = switch (safety) {
        .strict => isSafeComponent(name),
        .filesystem => |sep| isSafeFilesystemComponent(name, sep),
    };
    if (!safe) return StrictError.UnsafeDecryptedFilename;

    return gpa.dupe(u8, name);
}

/// Reports whether `name` can remain a single native path component.
fn isSafeFilesystemComponent(name: []const u8, sep: u8) bool {
    if (name.len == 0) return false;
    if (mem.eql(u8, name, ".") or mem.eql(u8, name, "..")) return false;
    for (name) |c| {
        if (c == 0 or c == sep) return false;
        if (sep == Io.Dir.path.sep_windows and c == Io.Dir.path.sep_posix) return false;
    }
    return true;
}

/// Reports whether a name stays in its directory and is safe to print in portable paths.
pub fn isSafeComponent(name: []const u8) bool {
    if (!isSafeFilesystemComponent(name, Io.Dir.path.sep_windows)) return false;
    for (name) |c| {
        if (c < 0x20 or c == 0x7f) return false;
    }
    return true;
}

/// Decrypt a relative path from a Git store without changing its component boundaries.
/// Git reports paths with `/` on every platform.
/// Caller owns returned memory.
pub fn decryptPathStrict(
    gpa: Allocator,
    encrypted_path: []const u8,
    filename_key: [16]u8,
) ![]u8 {
    return decryptPathWith(gpa, encrypted_path, filename_key, .strict);
}

/// Decrypt a native path without allowing decrypted components to change its structure.
/// Preserve undecodable names so encrypted and plain entries can coexist.
/// A plain name that decodes cannot be distinguished from an encrypted name.
/// Caller owns returned memory.
pub fn decryptPathForFilesystem(
    gpa: Allocator,
    encrypted_path: []const u8,
    filename_key: [16]u8,
    sep: u8,
) ![]u8 {
    return decryptPathWith(gpa, encrypted_path, filename_key, .{ .filesystem = sep });
}

/// Reject empty components so absolute paths and repeated separators are never silently changed.
fn decryptPathWith(
    gpa: Allocator,
    encrypted_path: []const u8,
    filename_key: [16]u8,
    safety: DecryptionSafety,
) ![]u8 {
    const sep: u8 = switch (safety) {
        .strict => Io.Dir.path.sep_posix,
        .filesystem => |s| s,
    };
    var components: std.ArrayList([]const u8) = .empty;
    defer {
        for (components.items) |component| {
            gpa.free(component);
        }
        components.deinit(gpa);
    }

    var it = mem.splitScalar(u8, encrypted_path, sep);
    while (it.next()) |component| {
        if (component.len == 0) return StrictError.InvalidEncryptedFilename;

        const decrypted = decryptCanonical(gpa, component, filename_key, safety) catch |err| switch (err) {
            StrictError.InvalidEncryptedFilename => if (safety == .filesystem)
                try gpa.dupe(u8, component)
            else
                return err,
            else => return err,
        };
        errdefer gpa.free(decrypted);
        try components.append(gpa, decrypted);
    }
    if (components.items.len == 0) return StrictError.InvalidEncryptedFilename;

    return mem.join(gpa, &.{sep}, components.items);
}

/// Encrypt each nonempty path component while preserving its boundaries.
/// `sep` is native for filesystem paths and `/` for paths reported by Git.
/// Caller owns returned memory.
pub fn encryptPath(
    gpa: Allocator,
    path: []const u8,
    filename_key: [16]u8,
    sep: u8,
) ![]u8 {
    var components: std.ArrayList([]const u8) = .empty;
    defer {
        for (components.items) |component| {
            gpa.free(component);
        }
        components.deinit(gpa);
    }

    var it = mem.splitScalar(u8, path, sep);
    while (it.next()) |component| {
        // Ignore empty components because this helper encrypts path components, not roots.
        if (component.len == 0) continue;

        const encrypted = try encrypt(gpa, component, filename_key);
        try components.append(gpa, encrypted);
    }

    return mem.join(gpa, &.{sep}, components.items);
}

test "dot and dot-dot are not encrypted" {
    const gpa = testing.allocator;

    const key: [16]u8 = @splat(0x42);

    const dot_encrypted = try encrypt(gpa, ".", key);
    defer gpa.free(dot_encrypted);
    try testing.expectEqualStrings(".", dot_encrypted);

    const dotdot_encrypted = try encrypt(gpa, "..", key);
    defer gpa.free(dotdot_encrypted);
    try testing.expectEqualStrings("..", dotdot_encrypted);
}

test "path round trip through filesystem decryption" {
    const gpa = testing.allocator;

    const key: [16]u8 = @splat(0x42);
    const plaintext_path = "dir/subdir/file.txt";

    const encrypted_path = try encryptPath(gpa, plaintext_path, key, '/');
    defer gpa.free(encrypted_path);

    const decrypted_path = try decryptPathForFilesystem(gpa, encrypted_path, key, '/');
    defer gpa.free(decrypted_path);

    try testing.expectEqualStrings(plaintext_path, decrypted_path);
}

test "encrypted names fit in 255 bytes or are rejected" {
    const gpa = testing.allocator;

    const key: [16]u8 = @splat(0x42);

    const long_name = "tracing_attributes-9e84d350f1142111.tracing_attributes.cb6dd642f55c194a-cgu.15.rcgu.o";
    const encrypted = try encrypt(gpa, long_name, key);
    defer gpa.free(encrypted);
    try testing.expect(encrypted.len <= max_name_bytes);

    // These source lengths leave enough room for every base84 encoding.
    const safe_lengths = [_]usize{ 50, 100, 150, 197 };
    for (safe_lengths) |len| {
        const test_name = try gpa.alloc(u8, len);
        defer gpa.free(test_name);
        @memset(test_name, 'a');

        const enc = try encrypt(gpa, test_name, key);
        defer gpa.free(enc);

        try testing.expect(enc.len <= max_name_bytes);
    }

    // These lengths cannot fit after encoding; the last also exercises heap storage.
    const unsafe_lengths = [_]usize{ 205, 215, 220, max_stack_filename_length + 1 };
    for (unsafe_lengths) |len| {
        const test_name = try gpa.alloc(u8, len);
        defer gpa.free(test_name);
        @memset(test_name, 'a');

        const result = encrypt(gpa, test_name, key);
        try testing.expectError(Error.EncryptedFilenameTooLong, result);
    }
}

test "encrypted names are valid file names on Windows" {
    const gpa = testing.allocator;

    const key: [16]u8 = @splat(0x42);
    var prng = std.Random.DefaultPrng.init(testing.random_seed);
    const random = prng.random();

    var name_buf: [64]u8 = undefined;
    for (0..1000) |_| {
        const name = name_buf[0 .. 3 + random.uintLessThan(usize, name_buf.len - 2)];
        random.bytes(name);

        const encrypted = try encrypt(gpa, name, key);
        defer gpa.free(encrypted);

        // Padding avoids short device names, and base84 never emits a period.
        try testing.expect(encrypted.len >= 20);
        try testing.expect(mem.findAny(u8, encrypted, " .<>:\"/\\|?*") == null);
        for (encrypted) |c| try testing.expect(c > 0x20 and c < 0x7f);
    }
}

test "strict decrypt round trips and rejects garbage" {
    const gpa = testing.allocator;

    const key: [16]u8 = @splat(0x42);
    const other_key: [16]u8 = @splat(0x43);

    const long_name: [197]u8 = @splat('a');
    const names = [_][]const u8{
        "myfile.txt",
        "this_is_a_very_long_filename_that_exceeds_the_minimum_padding_length_of_16_bytes_for_testing.txt",
        "AGENT.md",
        "r\u{e9}sum\u{e9}.txt",
        &long_name,
    };
    for (names) |name| {
        const encrypted = try encrypt(gpa, name, key);
        defer gpa.free(encrypted);

        const decrypted = try decryptStrict(gpa, encrypted, key);
        defer gpa.free(decrypted);
        try testing.expectEqualStrings(name, decrypted);
    }

    const invalid = StrictError.InvalidEncryptedFilename;
    try testing.expectError(invalid, decryptStrict(gpa, "not base84 \x01", key));
    try testing.expectError(invalid, decryptStrict(gpa, "", key));
    try testing.expectError(invalid, decryptStrict(gpa, "abc", key));

    const encrypted = try encrypt(gpa, "AGENT.md", key);
    defer gpa.free(encrypted);
    const wrong = decryptStrict(gpa, encrypted, other_key);
    if (wrong) |name| gpa.free(name) else |err| {
        try testing.expect(err == StrictError.InvalidEncryptedFilename or
            err == StrictError.UnsafeDecryptedFilename);
    }
}

test "strict decrypt rejects names that leave the directory" {
    const gpa = testing.allocator;

    const key: [16]u8 = @splat(0x42);

    const planted = [_][]const u8{ "a/b", "tab\there" };
    for (planted) |name| {
        const encrypted = try encrypt(gpa, name, key);
        defer gpa.free(encrypted);
        try testing.expectError(
            StrictError.UnsafeDecryptedFilename,
            decryptStrict(gpa, encrypted, key),
        );
    }

    var padded: [16]u8 = @splat(0);
    @memcpy(padded[0..2], "..");
    var cipher = hctr2.Hctr2_128.init(key);
    var ciphertext: [16]u8 = undefined;
    try cipher.encrypt(&ciphertext, &padded, &.{});
    var encode_buf: [64]u8 = undefined;
    const encoded = try base84.standard.encode(&encode_buf, &ciphertext);
    try testing.expectError(StrictError.UnsafeDecryptedFilename, decryptStrict(gpa, encoded, key));
}

test "strict path decryption round trips and rejects empty components" {
    const gpa = testing.allocator;

    const key: [16]u8 = @splat(0x42);
    const encrypted_path = try encryptPath(gpa, "docs/internal.md", key, '/');
    defer gpa.free(encrypted_path);

    const decrypted = try decryptPathStrict(gpa, encrypted_path, key);
    defer gpa.free(decrypted);
    try testing.expectEqualStrings("docs/internal.md", decrypted);

    const with_leading_sep = try gpa.print("/{s}", .{encrypted_path});
    defer gpa.free(with_leading_sep);
    const invalid = StrictError.InvalidEncryptedFilename;
    try testing.expectError(invalid, decryptPathStrict(gpa, with_leading_sep, key));
    try testing.expectError(invalid, decryptPathStrict(gpa, "", key));
}

test "filesystem path decrypt preserves names without allowing new separators" {
    const gpa = testing.allocator;
    const key: [16]u8 = @splat(0x42);

    const unusual_name = "line\nbreak\\name";
    const encrypted = try encrypt(gpa, unusual_name, key);
    defer gpa.free(encrypted);
    const decrypted = try decryptPathForFilesystem(gpa, encrypted, key, '/');
    defer gpa.free(decrypted);
    try testing.expectEqualStrings(unusual_name, decrypted);

    const plain = try decryptPathForFilesystem(gpa, "not encrypted.txt", key, '/');
    defer gpa.free(plain);
    try testing.expectEqualStrings("not encrypted.txt", plain);

    const planted = try encrypt(gpa, "../outside", key);
    defer gpa.free(planted);
    try testing.expectError(
        StrictError.UnsafeDecryptedFilename,
        decryptPathForFilesystem(gpa, planted, key, '/'),
    );
}

test "both spellings of an accented name encrypt to one composed name on macOS" {
    const gpa = testing.allocator;
    if (builtin.os.tag != .macos) return error.SkipZigTest;
    const key: [16]u8 = @splat(0x42);

    const from_decomposed = try encrypt(gpa, "re\u{301}sume\u{301}.md", key);
    defer gpa.free(from_decomposed);
    const from_composed = try encrypt(gpa, "r\u{e9}sum\u{e9}.md", key);
    defer gpa.free(from_composed);
    try testing.expectEqualStrings(from_composed, from_decomposed);

    const decrypted = try decryptStrict(gpa, from_decomposed, key);
    defer gpa.free(decrypted);
    try testing.expectEqualStrings("r\u{e9}sum\u{e9}.md", decrypted);
}
