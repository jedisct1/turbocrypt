const std = @import("std");
const crypto = @import("crypto.zig");
const builtin = @import("builtin");
const io_hints = @import("io_hints.zig");

// Threshold for using mmap vs buffered I/O (1MB)
const MMAP_THRESHOLD: u64 = 1024 * 1024;

fn readAll(file: std.fs.File, io: std.Io, buffer: []u8) !usize {
    var file_reader = file.reader(io, &.{});
    return file_reader.interface.readSliceShort(buffer) catch |err| switch (err) {
        error.ReadFailed => return file_reader.err.?,
    };
}

/// Read file using buffered I/O with I/O hints
fn readBuffered(file: std.fs.File, file_size: u64, allocator: std.mem.Allocator, io: std.Io) ![]u8 {
    // Advise kernel about sequential file access for better read-ahead
    io_hints.adviseFile(file, 0, @intCast(file_size), .sequential);

    const buffer = try allocator.alloc(u8, file_size);
    errdefer allocator.free(buffer);

    const bytes_read = try readAll(file, io, buffer);
    if (bytes_read != file_size) {
        return error.IncompleteRead;
    }

    return buffer;
}

/// Process a single file for encryption using zero-copy mmap for large files
pub fn encryptFile(
    input_path: []const u8,
    output_path: []const u8,
    derived_keys: crypto.DerivedKeys,
    allocator: std.mem.Allocator,
    io: std.Io,
) !void {
    // Check if in-place operation
    const in_place = std.mem.eql(u8, input_path, output_path);

    // Check if this is an in-place operation with .enc suffix addition (e.g., --in-place --enc-suffix)
    // For encryption: file.txt -> file.txt.enc (output = input + ".enc")
    // We should delete the original after successful encryption
    const in_place_with_suffix = !in_place and
        output_path.len == input_path.len + 4 and
        std.mem.startsWith(u8, output_path, input_path) and
        std.mem.endsWith(u8, output_path, ".enc");

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
        try encryptFileZeroCopy(input_file, file_size, actual_output_path, derived_keys, allocator, input_stat.mode, io);
    } else {
        // Use buffered I/O for small files
        try encryptFileBuffered(input_file, file_size, actual_output_path, derived_keys, allocator, input_stat.mode, io);
    }

    // For in-place operation, atomically rename temp file to original
    if (in_place) {
        try std.fs.cwd().rename(actual_output_path, output_path);
    }

    // For in-place with suffix (e.g., file.txt -> file.txt.enc), delete the original after success
    if (in_place_with_suffix) {
        try std.fs.cwd().deleteFile(input_path);
    }
}

/// Zero-copy encryption using dual mmap
fn encryptFileZeroCopy(
    input_file: std.fs.File,
    input_size: u64,
    output_path: []const u8,
    derived_keys: crypto.DerivedKeys,
    allocator: std.mem.Allocator,
    mode: std.fs.File.Mode,
    io: std.Io,
) !void {
    // Advise kernel about sequential file access (before mmap for better prefetch)
    io_hints.adviseFile(input_file, 0, @intCast(input_size), .sequential);

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
        return encryptFileBuffered(input_file, input_size, output_path, derived_keys, allocator, mode, io);
    };
    defer {
        // Drop pages from cache after processing to free memory
        io_hints.adviseMemory(input_mapped.ptr, input_size, .dontneed);
        std.posix.munmap(input_mapped);
    }

    // Advise kernel about memory access pattern
    io_hints.adviseMemory(input_mapped.ptr, input_size, .sequential);
    // Proactively start prefetching data into memory
    io_hints.adviseMemory(input_mapped.ptr, input_size, .willneed);

    // Create output file with correct size and read/write permissions for mmap
    // If it fails due to existing read-only file, delete and retry
    const output_file = blk: {
        break :blk std.fs.cwd().createFile(output_path, .{ .read = true }) catch |err| {
            if (err == error.AccessDenied) {
                // Try deleting the existing file (might be read-only) and retry
                std.fs.cwd().deleteFile(output_path) catch {};
                break :blk try std.fs.cwd().createFile(output_path, .{ .read = true });
            }
            return err;
        };
    };
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
        // Flush asynchronously (non-blocking) - kernel will write in background
        io_hints.flushAsync(output_mapped);
        std.posix.munmap(output_mapped);
        // Optional: sync file data for durability (can be skipped for performance)
        // io_hints.syncFileData(output_file);
    }

    // Advise kernel about sequential write pattern
    io_hints.adviseMemory(output_mapped.ptr, output_size, .sequential);

    // Zero-copy encrypt: input_mapped → output_mapped
    crypto.encryptZeroCopy(output_mapped, input_mapped, derived_keys);

    // Preserve original file permissions (Unix-like systems only)
    if (builtin.os.tag != .windows) {
        try output_file.chmod(mode);
    }
}

/// Buffered encryption for small files
fn encryptFileBuffered(
    input_file: std.fs.File,
    file_size: u64,
    output_path: []const u8,
    derived_keys: crypto.DerivedKeys,
    allocator: std.mem.Allocator,
    mode: std.fs.File.Mode,
    io: std.Io,
) !void {
    // Read input file
    const plaintext = try readBuffered(input_file, file_size, allocator, io);
    defer allocator.free(plaintext);

    // Encrypt
    const encrypted = try crypto.encrypt(plaintext, derived_keys, allocator);
    defer allocator.free(encrypted);

    // Write output file
    // If it fails due to existing read-only file, delete and retry
    const output_file = blk: {
        break :blk std.fs.cwd().createFile(output_path, .{}) catch |err| {
            if (err == error.AccessDenied) {
                // Try deleting the existing file (might be read-only) and retry
                std.fs.cwd().deleteFile(output_path) catch {};
                break :blk try std.fs.cwd().createFile(output_path, .{});
            }
            return err;
        };
    };
    defer output_file.close();

    try output_file.writeAll(encrypted);

    // Preserve original file permissions (Unix-like systems only)
    if (builtin.os.tag != .windows) {
        try output_file.chmod(mode);
    }
}

/// Process a single file for decryption using zero-copy mmap for large files
pub fn decryptFile(
    input_path: []const u8,
    output_path: []const u8,
    derived_keys: crypto.DerivedKeys,
    allocator: std.mem.Allocator,
    io: std.Io,
) !void {
    // Check if in-place operation
    const in_place = std.mem.eql(u8, input_path, output_path);

    // Check if this is an in-place operation with .enc suffix removal (e.g., --in-place --enc-suffix)
    // For decryption: file.txt.enc -> file.txt (input = output + ".enc")
    // We should delete the encrypted file after successful decryption
    const in_place_with_suffix = !in_place and
        input_path.len == output_path.len + 4 and
        std.mem.startsWith(u8, input_path, output_path) and
        std.mem.endsWith(u8, input_path, ".enc");

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
        try decryptFileZeroCopy(input_file, file_size, actual_output_path, derived_keys, allocator, input_stat.mode, io);
    } else {
        // Use buffered I/O for small files
        try decryptFileBuffered(input_file, file_size, actual_output_path, derived_keys, allocator, input_stat.mode, io);
    }

    // For in-place operation, atomically rename temp file to original
    if (in_place) {
        try std.fs.cwd().rename(actual_output_path, output_path);
    }

    // For in-place with suffix removal (e.g., file.enc -> file), delete the original after success
    if (in_place_with_suffix) {
        try std.fs.cwd().deleteFile(input_path);
    }
}

/// Zero-copy decryption using dual mmap
fn decryptFileZeroCopy(
    input_file: std.fs.File,
    input_size: u64,
    output_path: []const u8,
    derived_keys: crypto.DerivedKeys,
    allocator: std.mem.Allocator,
    mode: std.fs.File.Mode,
    io: std.Io,
) !void {
    // Advise kernel about sequential file access (before mmap for better prefetch)
    io_hints.adviseFile(input_file, 0, @intCast(input_size), .sequential);

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
        return decryptFileBuffered(input_file, input_size, output_path, derived_keys, allocator, mode, io);
    };
    defer {
        // Drop pages from cache after processing to free memory
        io_hints.adviseMemory(input_mapped.ptr, input_size, .dontneed);
        std.posix.munmap(input_mapped);
    }

    // Advise kernel about memory access pattern
    io_hints.adviseMemory(input_mapped.ptr, input_size, .sequential);
    // Proactively start prefetching data into memory
    io_hints.adviseMemory(input_mapped.ptr, input_size, .willneed);

    // Create output file with correct size and read/write permissions for mmap
    // If it fails due to existing read-only file, delete and retry
    const output_file = blk: {
        break :blk std.fs.cwd().createFile(output_path, .{ .read = true }) catch |err| {
            if (err == error.AccessDenied) {
                // Try deleting the existing file (might be read-only) and retry
                std.fs.cwd().deleteFile(output_path) catch {};
                break :blk try std.fs.cwd().createFile(output_path, .{ .read = true });
            }
            return err;
        };
    };
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
        // Flush asynchronously (non-blocking) - kernel will write in background
        io_hints.flushAsync(output_mapped);
        std.posix.munmap(output_mapped);
        // Optional: sync file data for durability (can be skipped for performance)
        // io_hints.syncFileData(output_file);
    }

    // Advise kernel about sequential write pattern
    io_hints.adviseMemory(output_mapped.ptr, output_size, .sequential);

    // Zero-copy decrypt: input_mapped → output_mapped
    try crypto.decryptZeroCopy(output_mapped, input_mapped, derived_keys);

    // Preserve original file permissions (Unix-like systems only)
    if (builtin.os.tag != .windows) {
        try output_file.chmod(mode);
    }
}

/// Buffered decryption for small files
fn decryptFileBuffered(
    input_file: std.fs.File,
    file_size: u64,
    output_path: []const u8,
    derived_keys: crypto.DerivedKeys,
    allocator: std.mem.Allocator,
    mode: std.fs.File.Mode,
    io: std.Io,
) !void {
    // Read input file
    const encrypted = try readBuffered(input_file, file_size, allocator, io);
    defer allocator.free(encrypted);

    // Decrypt
    const plaintext = try crypto.decrypt(encrypted, derived_keys, allocator);
    defer allocator.free(plaintext);

    // Write output file
    // If it fails due to existing read-only file, delete and retry
    const output_file = blk: {
        break :blk std.fs.cwd().createFile(output_path, .{}) catch |err| {
            if (err == error.AccessDenied) {
                // Try deleting the existing file (might be read-only) and retry
                std.fs.cwd().deleteFile(output_path) catch {};
                break :blk try std.fs.cwd().createFile(output_path, .{});
            }
            return err;
        };
    };
    defer output_file.close();

    try output_file.writeAll(plaintext);

    // Preserve original file permissions (Unix-like systems only)
    if (builtin.os.tag != .windows) {
        try output_file.chmod(mode);
    }
}

/// Verify a single encrypted file without decrypting it
/// Checks header MAC and AEGIS authentication tag
/// If quick is true, only verifies header MAC (faster but doesn't check data integrity)
pub fn verifyFile(
    input_path: []const u8,
    derived_keys: crypto.DerivedKeys,
    allocator: std.mem.Allocator,
    quick: bool,
    io: std.Io,
) !void {
    // Open input file
    const input_file = try std.fs.cwd().openFile(input_path, .{});
    defer input_file.close();

    const input_stat = try input_file.stat();
    const file_size = input_stat.size;

    // Use mmap for large files on non-Windows platforms, otherwise buffered I/O
    if (file_size >= MMAP_THRESHOLD and builtin.os.tag != .windows) {
        try verifyFileZeroCopy(input_file, file_size, derived_keys, allocator, quick, io);
    } else {
        try verifyFileBuffered(input_file, file_size, derived_keys, allocator, quick, io);
    }
}

/// Verify using mmap for large files
fn verifyFileZeroCopy(
    input_file: std.fs.File,
    input_size: u64,
    derived_keys: crypto.DerivedKeys,
    allocator: std.mem.Allocator,
    quick: bool,
    io: std.Io,
) !void {
    // Advise kernel about sequential file access (before mmap for better prefetch)
    io_hints.adviseFile(input_file, 0, @intCast(input_size), .sequential);

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
        return verifyFileBuffered(input_file, input_size, derived_keys, allocator, quick, io);
    };
    defer {
        // Drop pages from cache after processing to free memory
        io_hints.adviseMemory(input_mapped.ptr, input_size, .dontneed);
        std.posix.munmap(input_mapped);
    }

    // Advise kernel about memory access pattern
    io_hints.adviseMemory(input_mapped.ptr, input_size, .sequential);
    // Proactively start prefetching data into memory
    io_hints.adviseMemory(input_mapped.ptr, input_size, .willneed);

    // Verify the encrypted data
    if (quick) {
        try crypto.verifyHeaderOnly(input_mapped, derived_keys);
    } else {
        try crypto.verify(input_mapped, derived_keys, allocator);
    }
}

/// Verify using buffered I/O for small files
fn verifyFileBuffered(
    input_file: std.fs.File,
    file_size: u64,
    derived_keys: crypto.DerivedKeys,
    allocator: std.mem.Allocator,
    quick: bool,
    io: std.Io,
) !void {
    // Read encrypted file
    const encrypted = try readBuffered(input_file, file_size, allocator, io);
    defer allocator.free(encrypted);

    // Verify
    if (quick) {
        try crypto.verifyHeaderOnly(encrypted, derived_keys);
    } else {
        try crypto.verify(encrypted, derived_keys, allocator);
    }
}

test "encrypt and decrypt file" {
    const testing = std.testing;
    const allocator = testing.allocator;
    const io = testing.io;

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

    // Generate key and derive keys
    const key: [crypto.key_length]u8 = @splat(42);
    const derived = crypto.deriveKeys(key, null);

    // Encrypt file
    try encryptFile(input_path, encrypted_path, derived, allocator, io);
    defer std.fs.cwd().deleteFile(encrypted_path) catch {};

    // Verify encrypted file exists and is larger than plaintext
    {
        const file = try std.fs.cwd().openFile(encrypted_path, .{});
        defer file.close();
        const size = (try file.stat()).size;
        try testing.expect(size == test_data.len + crypto.overhead_size);
    }

    // Decrypt file
    try decryptFile(encrypted_path, decrypted_path, derived, allocator, io);
    defer std.fs.cwd().deleteFile(decrypted_path) catch {};

    // Verify decrypted content matches original
    {
        const file = try std.fs.cwd().openFile(decrypted_path, .{});
        defer file.close();
        const size = (try file.stat()).size;
        const content = try allocator.alloc(u8, size);
        defer allocator.free(content);
        _ = try readAll(file, io, content);
        try testing.expectEqualStrings(test_data, content);
    }
}

test "decrypt with wrong key fails" {
    const testing = std.testing;
    const allocator = testing.allocator;
    const io = testing.io;

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

    const key1: [crypto.key_length]u8 = @splat(1);
    const key2: [crypto.key_length]u8 = @splat(2);
    const derived1 = crypto.deriveKeys(key1, null);
    const derived2 = crypto.deriveKeys(key2, null);

    // Encrypt with key1
    try encryptFile(input_path, encrypted_path, derived1, allocator, io);
    defer std.fs.cwd().deleteFile(encrypted_path) catch {};

    // Try to decrypt with key2 - should fail
    const result = decryptFile(encrypted_path, decrypted_path, derived2, allocator, io);
    try testing.expectError(error.InvalidHeaderMAC, result);

    // Verify decrypted file was not created
    const file_result = std.fs.cwd().openFile(decrypted_path, .{});
    try testing.expectError(error.FileNotFound, file_result);
}

test "in-place encrypt/decrypt works with absolute path" {
    const testing = std.testing;
    const allocator = testing.allocator;
    const io = testing.io;

    std.fs.cwd().makeDir("tmp") catch |err| {
        if (err != error.PathAlreadyExists) return err;
    };

    const relative_path = "tmp/in_place_absolute.txt";
    const plaintext = "absolute path data";

    // Write initial plaintext file
    {
        const file = try std.fs.cwd().createFile(relative_path, .{});
        defer file.close();
        try file.writeAll(plaintext);
    }
    defer std.fs.cwd().deleteFile(relative_path) catch {};

    // Resolve absolute path for in-place operations
    const abs_path = try std.fs.cwd().realpathAlloc(allocator, relative_path);
    defer allocator.free(abs_path);

    const key: [crypto.key_length]u8 = @splat(9);
    const derived = crypto.deriveKeys(key, null);

    // Encrypt in place using absolute path
    try encryptFile(abs_path, abs_path, derived, allocator, io);

    // Verify encrypted file size increased by overhead
    {
        const file = try std.fs.cwd().openFile(relative_path, .{});
        defer file.close();
        const stat = try file.stat();
        try testing.expectEqual(@as(u64, plaintext.len + crypto.overhead_size), stat.size);
    }

    // Decrypt in place back to plaintext
    try decryptFile(abs_path, abs_path, derived, allocator, io);

    // Confirm content restored
    {
        const file = try std.fs.cwd().openFile(relative_path, .{});
        defer file.close();
        const buf = try allocator.alloc(u8, plaintext.len);
        defer allocator.free(buf);
        const read = try readAll(file, io, buf);
        try testing.expectEqual(@as(usize, plaintext.len), read);
        try testing.expectEqualStrings(plaintext, buf);
    }
}
