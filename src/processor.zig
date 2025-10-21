const std = @import("std");
const crypto = @import("crypto.zig");
const builtin = @import("builtin");

// Threshold for using mmap vs buffered I/O (1MB)
const MMAP_THRESHOLD: u64 = 1024 * 1024;

/// Read file using buffered I/O
fn readBuffered(file: std.fs.File, file_size: u64, allocator: std.mem.Allocator) ![]u8 {
    const buffer = try allocator.alloc(u8, file_size);
    errdefer allocator.free(buffer);

    const bytes_read = try file.readAll(buffer);
    if (bytes_read != file_size) {
        return error.IncompleteRead;
    }

    return buffer;
}

/// Process a single file for encryption using zero-copy mmap for large files
pub fn encryptFile(
    input_path: []const u8,
    output_path: []const u8,
    key: [crypto.key_length]u8,
    allocator: std.mem.Allocator,
) !void {
    // Check if in-place operation
    const in_place = std.mem.eql(u8, input_path, output_path);

    // For in-place, use temporary file
    const actual_output_path = if (in_place) blk: {
        break :blk try std.fmt.allocPrint(allocator, "{s}.tmp", .{output_path});
    } else output_path;
    defer if (in_place) allocator.free(actual_output_path);

    // Open input file
    const input_file = try std.fs.cwd().openFile(input_path, .{});
    defer input_file.close();

    const input_stat = try input_file.stat();
    const file_size = input_stat.size;

    // Use zero-copy mmap for large files on non-Windows platforms
    if (file_size >= MMAP_THRESHOLD and builtin.os.tag != .windows) {
        try encryptFileZeroCopy(input_file, file_size, actual_output_path, key, input_stat.mode);
    } else {
        // Use buffered I/O for small files
        try encryptFileBuffered(input_file, file_size, actual_output_path, key, allocator, input_stat.mode);
    }

    // For in-place operation, atomically rename temp file to original
    if (in_place) {
        try std.fs.cwd().rename(actual_output_path, output_path);
    }
}

/// Zero-copy encryption using dual mmap
fn encryptFileZeroCopy(
    input_file: std.fs.File,
    input_size: u64,
    output_path: []const u8,
    key: [crypto.key_length]u8,
    mode: std.fs.File.Mode,
) !void {
    // mmap input file (read-only)
    const input_mapped = std.posix.mmap(
        null,
        input_size,
        std.posix.PROT.READ,
        .{ .TYPE = .PRIVATE },
        input_file.handle,
        0,
    ) catch {
        // Fall back to buffered I/O if mmap fails
        var gpa = std.heap.GeneralPurposeAllocator(.{}){};
        defer _ = gpa.deinit();
        const allocator = gpa.allocator();
        return encryptFileBuffered(input_file, input_size, output_path, key, allocator, mode);
    };
    defer std.posix.munmap(input_mapped);

    // Advise kernel about sequential access pattern
    std.posix.madvise(input_mapped.ptr, input_size, std.posix.MADV.SEQUENTIAL) catch {};

    // Create output file with correct size and read/write permissions for mmap
    const output_file = try std.fs.cwd().createFile(output_path, .{ .read = true });
    defer output_file.close();

    // Check for integer overflow when calculating output size
    const output_size = std.math.add(u64, input_size, crypto.overhead_size) catch {
        return error.FileTooLarge;
    };
    try output_file.setEndPos(output_size);

    // mmap output file (write)
    const output_mapped = try std.posix.mmap(
        null,
        output_size,
        std.posix.PROT.WRITE,
        .{ .TYPE = .SHARED }, // SHARED to write back to file
        output_file.handle,
        0,
    );
    defer {
        // Ensure data is written before unmapping
        std.posix.msync(output_mapped, std.posix.MSF.SYNC) catch {};
        std.posix.munmap(output_mapped);
    }

    // Advise kernel about sequential access pattern
    std.posix.madvise(output_mapped.ptr, output_size, std.posix.MADV.SEQUENTIAL) catch {};

    // Zero-copy encrypt: input_mapped → output_mapped
    crypto.encryptZeroCopy(output_mapped, input_mapped, key);

    // Preserve original file permissions
    try output_file.chmod(mode);
}

/// Buffered encryption for small files
fn encryptFileBuffered(
    input_file: std.fs.File,
    file_size: u64,
    output_path: []const u8,
    key: [crypto.key_length]u8,
    allocator: std.mem.Allocator,
    mode: std.fs.File.Mode,
) !void {
    // Read input file
    const plaintext = try readBuffered(input_file, file_size, allocator);
    defer allocator.free(plaintext);

    // Encrypt
    const encrypted = try crypto.encrypt(plaintext, key, allocator);
    defer allocator.free(encrypted);

    // Write output file
    const output_file = try std.fs.cwd().createFile(output_path, .{});
    defer output_file.close();

    try output_file.writeAll(encrypted);

    // Preserve original file permissions
    try output_file.chmod(mode);
}

/// Process a single file for decryption using zero-copy mmap for large files
pub fn decryptFile(
    input_path: []const u8,
    output_path: []const u8,
    key: [crypto.key_length]u8,
    allocator: std.mem.Allocator,
) !void {
    // Check if in-place operation
    const in_place = std.mem.eql(u8, input_path, output_path);

    // For in-place, use temporary file
    const actual_output_path = if (in_place) blk: {
        break :blk try std.fmt.allocPrint(allocator, "{s}.tmp", .{output_path});
    } else output_path;
    defer if (in_place) allocator.free(actual_output_path);

    // Open input file
    const input_file = try std.fs.cwd().openFile(input_path, .{});
    defer input_file.close();

    const input_stat = try input_file.stat();
    const file_size = input_stat.size;

    // Use zero-copy mmap for large files on non-Windows platforms
    if (file_size >= MMAP_THRESHOLD and builtin.os.tag != .windows) {
        try decryptFileZeroCopy(input_file, file_size, actual_output_path, key, input_stat.mode);
    } else {
        // Use buffered I/O for small files
        try decryptFileBuffered(input_file, file_size, actual_output_path, key, allocator, input_stat.mode);
    }

    // For in-place operation, atomically rename temp file to original
    if (in_place) {
        try std.fs.cwd().rename(actual_output_path, output_path);
    }
}

/// Zero-copy decryption using dual mmap
fn decryptFileZeroCopy(
    input_file: std.fs.File,
    input_size: u64,
    output_path: []const u8,
    key: [crypto.key_length]u8,
    mode: std.fs.File.Mode,
) !void {
    // mmap input file (read-only)
    const input_mapped = std.posix.mmap(
        null,
        input_size,
        std.posix.PROT.READ,
        .{ .TYPE = .PRIVATE },
        input_file.handle,
        0,
    ) catch {
        // Fall back to buffered I/O if mmap fails
        var gpa = std.heap.GeneralPurposeAllocator(.{}){};
        defer _ = gpa.deinit();
        const allocator = gpa.allocator();
        return decryptFileBuffered(input_file, input_size, output_path, key, allocator, mode);
    };
    defer std.posix.munmap(input_mapped);

    // Advise kernel about sequential access pattern
    std.posix.madvise(input_mapped.ptr, input_size, std.posix.MADV.SEQUENTIAL) catch {};

    // Create output file with correct size and read/write permissions for mmap
    const output_file = try std.fs.cwd().createFile(output_path, .{ .read = true });
    defer output_file.close();

    // Check for integer underflow when calculating output size
    if (input_size < crypto.overhead_size) {
        return error.InvalidFileSize;
    }
    const output_size = input_size - crypto.overhead_size;
    try output_file.setEndPos(output_size);

    // mmap output file (write)
    const output_mapped = try std.posix.mmap(
        null,
        output_size,
        std.posix.PROT.WRITE,
        .{ .TYPE = .SHARED }, // SHARED to write back to file
        output_file.handle,
        0,
    );
    defer {
        // Ensure data is written before unmapping
        std.posix.msync(output_mapped, std.posix.MSF.SYNC) catch {};
        std.posix.munmap(output_mapped);
    }

    // Advise kernel about sequential access pattern
    std.posix.madvise(output_mapped.ptr, output_size, std.posix.MADV.SEQUENTIAL) catch {};

    // Zero-copy decrypt: input_mapped → output_mapped
    try crypto.decryptZeroCopy(output_mapped, input_mapped, key);

    // Preserve original file permissions
    try output_file.chmod(mode);
}

/// Buffered decryption for small files
fn decryptFileBuffered(
    input_file: std.fs.File,
    file_size: u64,
    output_path: []const u8,
    key: [crypto.key_length]u8,
    allocator: std.mem.Allocator,
    mode: std.fs.File.Mode,
) !void {
    // Read input file
    const encrypted = try readBuffered(input_file, file_size, allocator);
    defer allocator.free(encrypted);

    // Decrypt
    const plaintext = try crypto.decrypt(encrypted, key, allocator);
    defer allocator.free(plaintext);

    // Write output file
    const output_file = try std.fs.cwd().createFile(output_path, .{});
    defer output_file.close();

    try output_file.writeAll(plaintext);

    // Preserve original file permissions
    try output_file.chmod(mode);
}

/// Verify a single encrypted file without decrypting it
/// Checks header MAC and AEGIS authentication tag
pub fn verifyFile(
    input_path: []const u8,
    key: [crypto.key_length]u8,
    allocator: std.mem.Allocator,
) !void {
    // Open input file
    const input_file = try std.fs.cwd().openFile(input_path, .{});
    defer input_file.close();

    const input_stat = try input_file.stat();
    const file_size = input_stat.size;

    // Use mmap for large files on non-Windows platforms, otherwise buffered I/O
    if (file_size >= MMAP_THRESHOLD and builtin.os.tag != .windows) {
        try verifyFileZeroCopy(input_file, file_size, key, allocator);
    } else {
        try verifyFileBuffered(input_file, file_size, key, allocator);
    }
}

/// Verify using mmap for large files
fn verifyFileZeroCopy(
    input_file: std.fs.File,
    input_size: u64,
    key: [crypto.key_length]u8,
    allocator: std.mem.Allocator,
) !void {
    // mmap input file (read-only)
    const input_mapped = std.posix.mmap(
        null,
        input_size,
        std.posix.PROT.READ,
        .{ .TYPE = .PRIVATE },
        input_file.handle,
        0,
    ) catch {
        // Fall back to buffered I/O if mmap fails
        return verifyFileBuffered(input_file, input_size, key, allocator);
    };
    defer std.posix.munmap(input_mapped);

    // Advise kernel about sequential access pattern
    std.posix.madvise(input_mapped.ptr, input_size, std.posix.MADV.SEQUENTIAL) catch {};

    // Verify the encrypted data
    try crypto.verify(input_mapped, key, allocator);
}

/// Verify using buffered I/O for small files
fn verifyFileBuffered(
    input_file: std.fs.File,
    file_size: u64,
    key: [crypto.key_length]u8,
    allocator: std.mem.Allocator,
) !void {
    // Read encrypted file
    const encrypted = try readBuffered(input_file, file_size, allocator);
    defer allocator.free(encrypted);

    // Verify
    try crypto.verify(encrypted, key, allocator);
}

test "encrypt and decrypt file" {
    const testing = std.testing;
    const allocator = testing.allocator;

    // Ensure tmp directory exists
    std.fs.cwd().makeDir("tmp") catch |err| {
        if (err != error.PathAlreadyExists) return err;
    };

    // Create test file
    const test_data = "Hello, World! This is test data for file encryption.";
    const input_path = "tmp/test_input.txt";
    const encrypted_path = "tmp/test_encrypted.bin";
    const decrypted_path = "tmp/test_decrypted.txt";

    // Write test file
    {
        const file = try std.fs.cwd().createFile(input_path, .{});
        defer file.close();
        try file.writeAll(test_data);
    }
    defer std.fs.cwd().deleteFile(input_path) catch {};

    // Generate key
    const key: [crypto.key_length]u8 = [_]u8{42} ** crypto.key_length;

    // Encrypt file
    try encryptFile(input_path, encrypted_path, key, allocator);
    defer std.fs.cwd().deleteFile(encrypted_path) catch {};

    // Verify encrypted file exists and is larger than plaintext
    {
        const file = try std.fs.cwd().openFile(encrypted_path, .{});
        defer file.close();
        const size = (try file.stat()).size;
        try testing.expect(size == test_data.len + crypto.overhead_size);
    }

    // Decrypt file
    try decryptFile(encrypted_path, decrypted_path, key, allocator);
    defer std.fs.cwd().deleteFile(decrypted_path) catch {};

    // Verify decrypted content matches original
    {
        const file = try std.fs.cwd().openFile(decrypted_path, .{});
        defer file.close();
        const size = (try file.stat()).size;
        const content = try allocator.alloc(u8, size);
        defer allocator.free(content);
        _ = try file.readAll(content);
        try testing.expectEqualStrings(test_data, content);
    }
}

test "decrypt with wrong key fails" {
    const testing = std.testing;
    const allocator = testing.allocator;

    // Ensure tmp directory exists
    std.fs.cwd().makeDir("tmp") catch |err| {
        if (err != error.PathAlreadyExists) return err;
    };

    const test_data = "Secret data";
    const input_path = "tmp/test_wrong_key_input.txt";
    const encrypted_path = "tmp/test_wrong_key_encrypted.bin";
    const decrypted_path = "tmp/test_wrong_key_decrypted.txt";

    // Write test file
    {
        const file = try std.fs.cwd().createFile(input_path, .{});
        defer file.close();
        try file.writeAll(test_data);
    }
    defer std.fs.cwd().deleteFile(input_path) catch {};

    const key1: [crypto.key_length]u8 = [_]u8{1} ** crypto.key_length;
    const key2: [crypto.key_length]u8 = [_]u8{2} ** crypto.key_length;

    // Encrypt with key1
    try encryptFile(input_path, encrypted_path, key1, allocator);
    defer std.fs.cwd().deleteFile(encrypted_path) catch {};

    // Try to decrypt with key2 - should fail
    const result = decryptFile(encrypted_path, decrypted_path, key2, allocator);
    try testing.expectError(error.InvalidHeaderMAC, result);

    // Verify decrypted file was not created
    const file_result = std.fs.cwd().openFile(decrypted_path, .{});
    try testing.expectError(error.FileNotFound, file_result);
}
