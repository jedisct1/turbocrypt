const std = @import("std");
const crypto = @import("crypto.zig");
const builtin = @import("builtin");
const io_hints = @import("io_hints.zig");

// Threshold for using mmap vs buffered I/O (1MB)
const MMAP_THRESHOLD: u64 = 1024 * 1024;

fn readAll(file: std.Io.File, io: std.Io, buffer: []u8) !usize {
    var file_reader = file.reader(io, &.{});
    return file_reader.interface.readSliceShort(buffer) catch |err| switch (err) {
        error.ReadFailed => return file_reader.err.?,
    };
}

const max_tmp_attempts = 16;

const AtomicOutput = struct {
    file: std.Io.File,
    tmp_path: []u8,
    dest_path: []const u8,
    allocator: std.mem.Allocator,

    fn create(
        dest_path: []const u8,
        options: std.Io.Dir.CreateFileOptions,
        allocator: std.mem.Allocator,
        io: std.Io,
    ) !AtomicOutput {
        var opts = options;
        opts.exclusive = true;

        var attempt: u32 = 0;
        while (attempt < max_tmp_attempts) : (attempt += 1) {
            var rand: u64 = undefined;
            io.random(std.mem.asBytes(&rand));
            const tmp_path = try std.fmt.allocPrint(allocator, "{s}.{x}.tmp", .{ dest_path, rand });
            errdefer allocator.free(tmp_path);

            const file = std.Io.Dir.createFile(.cwd(), io, tmp_path, opts) catch |err| switch (err) {
                error.PathAlreadyExists => {
                    allocator.free(tmp_path);
                    continue;
                },
                else => return err,
            };

            return .{
                .file = file,
                .tmp_path = tmp_path,
                .dest_path = dest_path,
                .allocator = allocator,
            };
        }
        return error.TempFileCollision;
    }

    fn setPermissions(self: *AtomicOutput, io: std.Io, permissions: std.Io.File.Permissions) !void {
        if (builtin.os.tag == .windows) return;
        try self.file.setPermissions(io, permissions);
    }

    fn finalize(self: *AtomicOutput, io: std.Io) !void {
        try std.Io.Dir.rename(.cwd(), self.tmp_path, .cwd(), self.dest_path, io);
        self.allocator.free(self.tmp_path);
        self.tmp_path = &.{};
    }

    fn deinit(self: *AtomicOutput, io: std.Io) void {
        self.file.close(io);
        if (self.tmp_path.len != 0) {
            std.Io.Dir.deleteFile(.cwd(), io, self.tmp_path) catch {};
            self.allocator.free(self.tmp_path);
        }
    }
};

/// Read file using buffered I/O with I/O hints
fn readBuffered(file: std.Io.File, file_size: u64, allocator: std.mem.Allocator, io: std.Io) ![]u8 {
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
    const in_place_with_suffix = !std.mem.eql(u8, input_path, output_path) and
        output_path.len == input_path.len + 4 and
        std.mem.startsWith(u8, output_path, input_path) and
        std.mem.endsWith(u8, output_path, ".enc");

    const input_file = try std.Io.Dir.openFile(.cwd(), io, input_path, .{});
    defer input_file.close(io);

    const input_stat = try input_file.stat(io);
    const file_size = input_stat.size;

    if (file_size >= MMAP_THRESHOLD and builtin.os.tag != .windows) {
        try encryptFileZeroCopy(input_file, file_size, output_path, derived_keys, allocator, input_stat.permissions, io);
    } else {
        try encryptFileBuffered(input_file, file_size, output_path, derived_keys, allocator, input_stat.permissions, io);
    }

    if (in_place_with_suffix) {
        try std.Io.Dir.deleteFile(.cwd(), io, input_path);
    }
}

/// Zero-copy encryption using dual mmap
fn encryptFileZeroCopy(
    input_file: std.Io.File,
    input_size: u64,
    output_path: []const u8,
    derived_keys: crypto.DerivedKeys,
    allocator: std.mem.Allocator,
    permissions: std.Io.File.Permissions,
    io: std.Io,
) !void {
    // Advise kernel about sequential file access (before mmap for better prefetch)
    io_hints.adviseFile(input_file, 0, @intCast(input_size), .sequential);

    // Memory-map input file (read-only)
    var input_mm = std.Io.File.MemoryMap.create(io, input_file, .{
        .len = input_size,
        .protection = .{ .read = true, .write = false },
        .populate = true,
    }) catch {
        // Fall back to buffered I/O if mmap fails
        return encryptFileBuffered(input_file, input_size, output_path, derived_keys, allocator, permissions, io);
    };
    defer input_mm.destroy(io);

    // Advise kernel about memory access pattern
    io_hints.adviseMemory(input_mm.memory.ptr, input_size, .sequential);
    io_hints.adviseMemory(input_mm.memory.ptr, input_size, .willneed);

    const output_size = std.math.add(u64, input_size, crypto.overhead_size) catch {
        return error.FileTooLarge;
    };

    var atomic = try AtomicOutput.create(output_path, .{ .read = true }, allocator, io);
    defer atomic.deinit(io);

    try atomic.file.setLength(io, output_size);

    {
        var output_mm = try std.Io.File.MemoryMap.create(io, atomic.file, .{
            .len = output_size,
            .protection = .{ .read = true, .write = true },
            .undefined_contents = true,
            .populate = false,
        });
        defer output_mm.destroy(io);

        io_hints.adviseMemory(output_mm.memory.ptr, output_size, .sequential);

        crypto.encryptZeroCopy(output_mm.memory, input_mm.memory, derived_keys, io);

        io_hints.adviseMemory(input_mm.memory.ptr, input_size, .dontneed);

        try output_mm.write(io);
    }

    try atomic.setPermissions(io, permissions);
    try atomic.finalize(io);
}

/// Buffered encryption for small files
fn encryptFileBuffered(
    input_file: std.Io.File,
    file_size: u64,
    output_path: []const u8,
    derived_keys: crypto.DerivedKeys,
    allocator: std.mem.Allocator,
    permissions: std.Io.File.Permissions,
    io: std.Io,
) !void {
    // Read input file
    const plaintext = try readBuffered(input_file, file_size, allocator, io);
    defer allocator.free(plaintext);

    // Encrypt
    const encrypted = try crypto.encrypt(plaintext, derived_keys, allocator, io);
    defer allocator.free(encrypted);

    var atomic = try AtomicOutput.create(output_path, .{}, allocator, io);
    defer atomic.deinit(io);

    try atomic.file.writeStreamingAll(io, encrypted);

    try atomic.setPermissions(io, permissions);
    try atomic.finalize(io);
}

/// Process a single file for decryption using zero-copy mmap for large files
pub fn decryptFile(
    input_path: []const u8,
    output_path: []const u8,
    derived_keys: crypto.DerivedKeys,
    allocator: std.mem.Allocator,
    io: std.Io,
) !void {
    const in_place_with_suffix = !std.mem.eql(u8, input_path, output_path) and
        input_path.len == output_path.len + 4 and
        std.mem.startsWith(u8, input_path, output_path) and
        std.mem.endsWith(u8, input_path, ".enc");

    const input_file = try std.Io.Dir.openFile(.cwd(), io, input_path, .{});
    defer input_file.close(io);

    const input_stat = try input_file.stat(io);
    const file_size = input_stat.size;

    if (file_size >= MMAP_THRESHOLD and builtin.os.tag != .windows) {
        try decryptFileZeroCopy(input_file, file_size, output_path, derived_keys, allocator, input_stat.permissions, io);
    } else {
        try decryptFileBuffered(input_file, file_size, output_path, derived_keys, allocator, input_stat.permissions, io);
    }

    if (in_place_with_suffix) {
        try std.Io.Dir.deleteFile(.cwd(), io, input_path);
    }
}

/// Zero-copy decryption using dual mmap
fn decryptFileZeroCopy(
    input_file: std.Io.File,
    input_size: u64,
    output_path: []const u8,
    derived_keys: crypto.DerivedKeys,
    allocator: std.mem.Allocator,
    permissions: std.Io.File.Permissions,
    io: std.Io,
) !void {
    // Advise kernel about sequential file access (before mmap for better prefetch)
    io_hints.adviseFile(input_file, 0, @intCast(input_size), .sequential);

    // Memory-map input file (read-only)
    var input_mm = std.Io.File.MemoryMap.create(io, input_file, .{
        .len = input_size,
        .protection = .{ .read = true, .write = false },
        .populate = true,
    }) catch {
        // Fall back to buffered I/O if mmap fails
        return decryptFileBuffered(input_file, input_size, output_path, derived_keys, allocator, permissions, io);
    };
    defer input_mm.destroy(io);

    // Advise kernel about memory access pattern
    io_hints.adviseMemory(input_mm.memory.ptr, input_size, .sequential);
    io_hints.adviseMemory(input_mm.memory.ptr, input_size, .willneed);

    if (input_size < crypto.overhead_size) {
        return error.InvalidFileSize;
    }
    const output_size = input_size - crypto.overhead_size;

    var atomic = try AtomicOutput.create(output_path, .{ .read = true }, allocator, io);
    defer atomic.deinit(io);

    try atomic.file.setLength(io, output_size);

    {
        var output_mm = try std.Io.File.MemoryMap.create(io, atomic.file, .{
            .len = output_size,
            .protection = .{ .read = true, .write = true },
            .undefined_contents = true,
            .populate = false,
        });
        defer output_mm.destroy(io);

        io_hints.adviseMemory(output_mm.memory.ptr, output_size, .sequential);

        try crypto.decryptZeroCopy(output_mm.memory, input_mm.memory, derived_keys);

        io_hints.adviseMemory(input_mm.memory.ptr, input_size, .dontneed);

        try output_mm.write(io);
    }

    try atomic.setPermissions(io, permissions);
    try atomic.finalize(io);
}

/// Buffered decryption for small files
fn decryptFileBuffered(
    input_file: std.Io.File,
    file_size: u64,
    output_path: []const u8,
    derived_keys: crypto.DerivedKeys,
    allocator: std.mem.Allocator,
    permissions: std.Io.File.Permissions,
    io: std.Io,
) !void {
    // Read input file
    const encrypted = try readBuffered(input_file, file_size, allocator, io);
    defer allocator.free(encrypted);

    // Decrypt
    const plaintext = try crypto.decrypt(encrypted, derived_keys, allocator);
    defer allocator.free(plaintext);

    var atomic = try AtomicOutput.create(output_path, .{}, allocator, io);
    defer atomic.deinit(io);

    try atomic.file.writeStreamingAll(io, plaintext);

    try atomic.setPermissions(io, permissions);
    try atomic.finalize(io);
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
    const input_file = try std.Io.Dir.openFile(.cwd(), io, input_path, .{});
    defer input_file.close(io);

    const input_stat = try input_file.stat(io);
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
    input_file: std.Io.File,
    input_size: u64,
    derived_keys: crypto.DerivedKeys,
    allocator: std.mem.Allocator,
    quick: bool,
    io: std.Io,
) !void {
    // Advise kernel about sequential file access (before mmap for better prefetch)
    io_hints.adviseFile(input_file, 0, @intCast(input_size), .sequential);

    // Memory-map input file (read-only)
    var input_mm = std.Io.File.MemoryMap.create(io, input_file, .{
        .len = input_size,
        .protection = .{ .read = true, .write = false },
        .populate = true,
    }) catch {
        // Fall back to buffered I/O if mmap fails
        return verifyFileBuffered(input_file, input_size, derived_keys, allocator, quick, io);
    };
    defer {
        // Drop pages from cache after processing
        io_hints.adviseMemory(input_mm.memory.ptr, input_size, .dontneed);
        input_mm.destroy(io);
    }

    // Advise kernel about memory access pattern
    io_hints.adviseMemory(input_mm.memory.ptr, input_size, .sequential);
    io_hints.adviseMemory(input_mm.memory.ptr, input_size, .willneed);

    // Verify the encrypted data
    if (quick) {
        try crypto.verifyHeaderOnly(input_mm.memory, derived_keys);
    } else {
        try crypto.verify(input_mm.memory, derived_keys, allocator);
    }
}

/// Verify using buffered I/O for small files
fn verifyFileBuffered(
    input_file: std.Io.File,
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
    std.Io.Dir.createDir(.cwd(), io, "tmp", .default_dir) catch |err| {
        if (err != error.PathAlreadyExists) return err;
    };

    // Create test file
    const test_data = "Hello, World! This is test data for file encryption.";
    const input_path = "tmp/test_input.txt";
    const encrypted_path = "tmp/test_encrypted.bin";
    const decrypted_path = "tmp/test_decrypted.txt";

    // Write test file
    {
        const file = try std.Io.Dir.createFile(.cwd(), io, input_path, .{});
        defer file.close(io);
        try file.writeStreamingAll(io, test_data);
    }
    defer std.Io.Dir.deleteFile(.cwd(), io, input_path) catch {};

    // Generate key and derive keys
    const key: [crypto.key_length]u8 = @splat(42);
    const derived = crypto.deriveKeys(key, null);

    // Encrypt file
    try encryptFile(input_path, encrypted_path, derived, allocator, io);
    defer std.Io.Dir.deleteFile(.cwd(), io, encrypted_path) catch {};

    // Verify encrypted file exists and is larger than plaintext
    {
        const file = try std.Io.Dir.openFile(.cwd(), io, encrypted_path, .{});
        defer file.close(io);
        const size = (try file.stat(io)).size;
        try testing.expect(size == test_data.len + crypto.overhead_size);
    }

    // Decrypt file
    try decryptFile(encrypted_path, decrypted_path, derived, allocator, io);
    defer std.Io.Dir.deleteFile(.cwd(), io, decrypted_path) catch {};

    // Verify decrypted content matches original
    {
        const file = try std.Io.Dir.openFile(.cwd(), io, decrypted_path, .{});
        defer file.close(io);
        const size = (try file.stat(io)).size;
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
    std.Io.Dir.createDir(.cwd(), io, "tmp", .default_dir) catch |err| {
        if (err != error.PathAlreadyExists) return err;
    };

    const test_data = "Secret data";
    const input_path = "tmp/test_wrong_key_input.txt";
    const encrypted_path = "tmp/test_wrong_key_encrypted.bin";
    const decrypted_path = "tmp/test_wrong_key_decrypted.txt";

    // Write test file
    {
        const file = try std.Io.Dir.createFile(.cwd(), io, input_path, .{});
        defer file.close(io);
        try file.writeStreamingAll(io, test_data);
    }
    defer std.Io.Dir.deleteFile(.cwd(), io, input_path) catch {};

    const key1: [crypto.key_length]u8 = @splat(1);
    const key2: [crypto.key_length]u8 = @splat(2);
    const derived1 = crypto.deriveKeys(key1, null);
    const derived2 = crypto.deriveKeys(key2, null);

    // Encrypt with key1
    try encryptFile(input_path, encrypted_path, derived1, allocator, io);
    defer std.Io.Dir.deleteFile(.cwd(), io, encrypted_path) catch {};

    // Try to decrypt with key2 - should fail
    const result = decryptFile(encrypted_path, decrypted_path, derived2, allocator, io);
    try testing.expectError(error.InvalidHeaderMAC, result);

    // Verify decrypted file was not created
    const file_result = std.Io.Dir.openFile(.cwd(), io, decrypted_path, .{});
    try testing.expectError(error.FileNotFound, file_result);
}

test "in-place encrypt/decrypt works with absolute path" {
    const testing = std.testing;
    const allocator = testing.allocator;
    const io = testing.io;

    std.Io.Dir.createDir(.cwd(), io, "tmp", .default_dir) catch |err| {
        if (err != error.PathAlreadyExists) return err;
    };

    const relative_path = "tmp/in_place_absolute.txt";
    const plaintext = "absolute path data";

    // Write initial plaintext file
    {
        const file = try std.Io.Dir.createFile(.cwd(), io, relative_path, .{});
        defer file.close(io);
        try file.writeStreamingAll(io, plaintext);
    }
    defer std.Io.Dir.deleteFile(.cwd(), io, relative_path) catch {};

    // Resolve absolute path for in-place operations
    const abs_path = try std.Io.Dir.realPathFileAlloc(.cwd(), io, relative_path, allocator);
    defer allocator.free(abs_path);

    const key: [crypto.key_length]u8 = @splat(9);
    const derived = crypto.deriveKeys(key, null);

    // Encrypt in place using absolute path
    try encryptFile(abs_path, abs_path, derived, allocator, io);

    // Verify encrypted file size increased by overhead
    {
        const file = try std.Io.Dir.openFile(.cwd(), io, relative_path, .{});
        defer file.close(io);
        const stat = try file.stat(io);
        try testing.expectEqual(@as(u64, plaintext.len + crypto.overhead_size), stat.size);
    }

    // Decrypt in place back to plaintext
    try decryptFile(abs_path, abs_path, derived, allocator, io);

    // Confirm content restored
    {
        const file = try std.Io.Dir.openFile(.cwd(), io, relative_path, .{});
        defer file.close(io);
        const buf = try allocator.alloc(u8, plaintext.len);
        defer allocator.free(buf);
        const read = try readAll(file, io, buf);
        try testing.expectEqual(@as(usize, plaintext.len), read);
        try testing.expectEqualStrings(plaintext, buf);
    }
}

test "symlink at output path does not hijack writes" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;

    const testing = std.testing;
    const allocator = testing.allocator;
    const io = testing.io;

    std.Io.Dir.createDir(.cwd(), io, "tmp", .default_dir) catch |err| {
        if (err != error.PathAlreadyExists) return err;
    };

    const input_path = "tmp/symhijack_input.txt";
    const sentinel_path = "tmp/symhijack_sentinel.txt";
    const output_path = "tmp/symhijack_output.bin";
    const sentinel_content = "DO NOT OVERWRITE ME";
    const plaintext = "secret payload that must land in output_path only";

    std.Io.Dir.deleteFile(.cwd(), io, output_path) catch {};
    std.Io.Dir.deleteFile(.cwd(), io, sentinel_path) catch {};
    std.Io.Dir.deleteFile(.cwd(), io, input_path) catch {};

    {
        const f = try std.Io.Dir.createFile(.cwd(), io, input_path, .{});
        defer f.close(io);
        try f.writeStreamingAll(io, plaintext);
    }
    defer std.Io.Dir.deleteFile(.cwd(), io, input_path) catch {};

    {
        const f = try std.Io.Dir.createFile(.cwd(), io, sentinel_path, .{});
        defer f.close(io);
        try f.writeStreamingAll(io, sentinel_content);
    }
    defer std.Io.Dir.deleteFile(.cwd(), io, sentinel_path) catch {};

    try std.Io.Dir.symLink(.cwd(), io, "symhijack_sentinel.txt", output_path, .{});
    defer std.Io.Dir.deleteFile(.cwd(), io, output_path) catch {};

    const key: [crypto.key_length]u8 = @splat(7);
    const derived = crypto.deriveKeys(key, null);

    try encryptFile(input_path, output_path, derived, allocator, io);

    {
        const f = try std.Io.Dir.openFile(.cwd(), io, sentinel_path, .{});
        defer f.close(io);
        const buf = try allocator.alloc(u8, sentinel_content.len);
        defer allocator.free(buf);
        const read = try readAll(f, io, buf);
        try testing.expectEqual(@as(usize, sentinel_content.len), read);
        try testing.expectEqualStrings(sentinel_content, buf);
    }

    {
        const f = try std.Io.Dir.openFile(.cwd(), io, output_path, .{});
        defer f.close(io);
        const stat = try f.stat(io);
        try testing.expectEqual(@as(u64, plaintext.len + crypto.overhead_size), stat.size);
    }
}
