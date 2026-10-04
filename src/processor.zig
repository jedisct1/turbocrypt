//! File processing and the safe write path shared by the rest of the program.

const std = @import("std");
const builtin = @import("builtin");
const mem = std.mem;
const testing = std.testing;
const Allocator = std.mem.Allocator;
const Io = std.Io;

const crypto = @import("crypto.zig");
const io_hints = @import("io_hints.zig");

const mmap_threshold: u64 = 1024 * 1024;

fn readAll(file: Io.File, io: Io, buffer: []u8) !usize {
    var file_reader = file.reader(io, &.{});
    return file_reader.interface.readSliceShort(buffer) catch |err| switch (err) {
        error.ReadFailed => return file_reader.err.?,
    };
}

const max_tmp_attempts = 16;

const tmp_prefix = ".tc-";
const tmp_suffix = ".tmp";
pub const tmp_name_length = tmp_prefix.len + 16 + tmp_suffix.len;

/// Keep staging names short enough to fit beside the longest valid destination name.
pub fn tmpName(random: u64) [tmp_name_length]u8 {
    var name: [tmp_name_length]u8 = undefined;
    const format = tmp_prefix ++ "{x:0>16}" ++ tmp_suffix;
    _ = mem.print(&name, format, .{random}) catch unreachable;
    return name;
}

/// Hide staging files from mounts, including ones left behind by an interrupted write.
pub fn isTmpName(name: []const u8) bool {
    if (name.len != tmp_name_length) return false;
    if (!mem.startsWith(u8, name, tmp_prefix) or !mem.endsWith(u8, name, tmp_suffix)) return false;
    for (name[tmp_prefix.len .. name.len - tmp_suffix.len]) |c| {
        if (!std.ascii.isHex(c) or std.ascii.isUpper(c)) return false;
    }
    return true;
}

pub const TmpFile = struct {
    file: Io.File,
    name: [tmp_name_length]u8,
};

/// Reserve a new staging file without replacing someone else's entry.
/// The caller must publish it or clean it up.
pub fn createTmpIn(dir: Io.Dir, io: Io, options: Io.Dir.CreateFileOptions) !TmpFile {
    var opts = options;
    opts.exclusive = true;
    for (0..max_tmp_attempts) |_| {
        var random: u64 = undefined;
        io.random(mem.asBytes(&random));
        const name = tmpName(random);
        const file = dir.createFile(io, &name, opts) catch |err| switch (err) {
            error.PathAlreadyExists => continue,
            else => return err,
        };
        return .{ .file = file, .name = name };
    }
    return error.TmpFileCollision;
}

/// Replace the destination only after its new contents are complete.
///
/// A separate staging directory keeps temporary plain files out of a Git worktree.
pub const AtomicOutput = struct {
    file: Io.File,
    /// This stays open until cleanup so the staging path cannot be redirected.
    tmp_dir: Io.Dir,
    tmp_path: []u8,
    dest_path: []const u8,
    gpa: Allocator,

    pub fn init(
        gpa: Allocator,
        io: Io,
        dest_path: []const u8,
        options: Io.Dir.CreateFileOptions,
        tmp_dir: ?[]const u8,
    ) !AtomicOutput {
        const dir = tmp_dir orelse (Io.Dir.path.dirname(dest_path) orelse ".");
        return initWith(.cwd(), gpa, io, dir, dest_path, options);
    }

    /// Use a directory handle when the caller has already established a safe destination.
    pub fn initIn(
        dir: Io.Dir,
        gpa: Allocator,
        io: Io,
        options: Io.Dir.CreateFileOptions,
    ) !AtomicOutput {
        return initWith(dir, gpa, io, null, &.{}, options);
    }

    fn initWith(
        tmp_dir: Io.Dir,
        gpa: Allocator,
        io: Io,
        prefix_dir: ?[]const u8,
        dest_path: []const u8,
        options: Io.Dir.CreateFileOptions,
    ) !AtomicOutput {
        var staging = tmp_dir;
        if (prefix_dir) |dir| staging = try tmp_dir.openDir(io, dir, .{});
        defer if (prefix_dir != null) staging.close(io);
        const tmp = try createTmpIn(staging, io, options);
        errdefer {
            tmp.file.close(io);
            staging.deleteFile(io, &tmp.name) catch {};
        }
        const tmp_path = if (prefix_dir) |dir|
            try gpa.print("{s}/{s}", .{ dir, tmp.name })
        else
            try gpa.dupe(u8, &tmp.name);
        return .{
            .file = tmp.file,
            .tmp_dir = tmp_dir,
            .tmp_path = tmp_path,
            .dest_path = dest_path,
            .gpa = gpa,
        };
    }

    pub fn setPermissions(self: *AtomicOutput, io: Io, permissions: Io.File.Permissions) !void {
        if (builtin.os.tag == .windows) return;
        try self.file.setPermissions(io, permissions);
    }

    pub fn finalize(self: *AtomicOutput, io: Io) !void {
        try self.finalizeInto(io, .cwd(), self.dest_path);
    }

    /// Publish through an already-checked directory.
    ///
    /// The open handle keeps a later symlink change from sending the file elsewhere.
    pub fn finalizeInto(
        self: *AtomicOutput,
        io: Io,
        dest_dir: Io.Dir,
        dest_name: []const u8,
    ) !void {
        try Io.Dir.rename(self.tmp_dir, self.tmp_path, dest_dir, dest_name, io);
        self.keep();
    }

    /// Mark the staging file as published so cleanup leaves it alone.
    pub fn keep(self: *AtomicOutput) void {
        self.gpa.free(self.tmp_path);
        self.tmp_path = &.{};
    }

    pub fn deinit(self: *AtomicOutput, io: Io) void {
        self.file.close(io);
        if (self.tmp_path.len != 0) {
            self.tmp_dir.deleteFile(io, self.tmp_path) catch {};
            self.gpa.free(self.tmp_path);
        }
    }
};

/// Publish a complete file without ever exposing a partial replacement.
pub fn writeFileAtomic(
    gpa: Allocator,
    io: Io,
    dest_path: []const u8,
    data: []const u8,
    permissions: ?Io.File.Permissions,
    tmp_dir: ?[]const u8,
) !void {
    const dir = tmp_dir orelse (Io.Dir.path.dirname(dest_path) orelse ".");
    try writeFileAtomicIn(.cwd(), gpa, io, dest_path, data, permissions, dir);
}

/// Publish within an open directory instead of trusting a destination path.
/// Staging through that handle keeps a changed path from redirecting the write.
pub fn writeFileAtomicIn(
    dest_dir: Io.Dir,
    gpa: Allocator,
    io: Io,
    dest_name: []const u8,
    data: []const u8,
    permissions: ?Io.File.Permissions,
    tmp_dir: ?[]const u8,
) !void {
    var options: Io.Dir.CreateFileOptions = .{};
    if (permissions) |p| options.permissions = p;
    var atomic = if (tmp_dir) |dir|
        try AtomicOutput.init(gpa, io, dest_name, options, dir)
    else
        try AtomicOutput.initIn(dest_dir, gpa, io, options);
    defer atomic.deinit(io);

    try atomic.file.writeStreamingAll(io, data);
    // Finish the data before publishing so a crash cannot replace a good file with a partial one.
    try atomic.file.sync(io);
    if (permissions) |p| {
        try atomic.setPermissions(io, p);
    }
    try atomic.finalizeInto(io, dest_dir, dest_name);
}

fn readBuffered(file: Io.File, gpa: Allocator, io: Io, file_size: u64) ![]u8 {
    io_hints.adviseFile(file, 0, @intCast(file_size), .sequential);

    const buffer = try gpa.alloc(u8, file_size);
    errdefer gpa.free(buffer);

    const bytes_read = try readAll(file, io, buffer);
    if (bytes_read != file_size) {
        return error.IncompleteRead;
    }

    return buffer;
}

pub fn encryptFile(
    gpa: Allocator,
    io: Io,
    source_path: []const u8,
    dest_path: []const u8,
    derived_keys: crypto.DerivedKeys,
) !void {
    const input_file = try Io.Dir.openFile(.cwd(), io, source_path, .{});
    defer input_file.close(io);

    const input_stat = try input_file.stat(io);
    const file_size = input_stat.size;

    if (file_size >= mmap_threshold and builtin.os.tag != .windows) {
        try encryptFileZeroCopy(
            input_file,
            gpa,
            io,
            file_size,
            dest_path,
            derived_keys,
            input_stat.permissions,
        );
    } else {
        try encryptFileBuffered(
            input_file,
            gpa,
            io,
            file_size,
            dest_path,
            derived_keys,
            input_stat.permissions,
        );
    }
}

fn encryptFileZeroCopy(
    input_file: Io.File,
    gpa: Allocator,
    io: Io,
    file_size: u64,
    dest_path: []const u8,
    derived_keys: crypto.DerivedKeys,
    permissions: Io.File.Permissions,
) !void {
    io_hints.adviseFile(input_file, 0, @intCast(file_size), .sequential);

    var input_map = Io.File.MemoryMap.create(io, input_file, .{
        .len = file_size,
        .protection = .{ .read = true, .write = false },
        .populate = true,
    }) catch {
        return encryptFileBuffered(
            input_file,
            gpa,
            io,
            file_size,
            dest_path,
            derived_keys,
            permissions,
        );
    };
    defer input_map.destroy(io);

    io_hints.adviseMemory(input_map.memory.ptr, file_size, .sequential);
    io_hints.adviseMemory(input_map.memory.ptr, file_size, .will_need);

    const output_size = std.math.add(u64, file_size, crypto.overhead_size) catch {
        return error.FileTooLarge;
    };

    var atomic = try AtomicOutput.init(gpa, io, dest_path, .{ .read = true }, null);
    defer atomic.deinit(io);

    try atomic.file.setLength(io, output_size);

    {
        var output_map = try Io.File.MemoryMap.create(io, atomic.file, .{
            .len = output_size,
            .protection = .{ .read = true, .write = true },
            .undefined_contents = true,
            .populate = false,
        });
        defer output_map.destroy(io);

        io_hints.adviseMemory(output_map.memory.ptr, output_size, .sequential);

        crypto.encryptZeroCopy(io, output_map.memory, input_map.memory, derived_keys);

        io_hints.adviseMemory(input_map.memory.ptr, file_size, .dont_need);

        try output_map.write(io);
    }

    try atomic.setPermissions(io, permissions);
    try atomic.finalize(io);
}

fn encryptFileBuffered(
    input_file: Io.File,
    gpa: Allocator,
    io: Io,
    file_size: u64,
    dest_path: []const u8,
    derived_keys: crypto.DerivedKeys,
    permissions: Io.File.Permissions,
) !void {
    const plaintext = try readBuffered(input_file, gpa, io, file_size);
    defer gpa.free(plaintext);

    const encrypted = try crypto.encrypt(gpa, io, plaintext, derived_keys);
    defer gpa.free(encrypted);

    var atomic = try AtomicOutput.init(gpa, io, dest_path, .{}, null);
    defer atomic.deinit(io);

    try atomic.file.writeStreamingAll(io, encrypted);

    try atomic.setPermissions(io, permissions);
    try atomic.finalize(io);
}

pub fn decryptFile(
    gpa: Allocator,
    io: Io,
    source_path: []const u8,
    dest_path: []const u8,
    derived_keys: crypto.DerivedKeys,
) !void {
    const input_file = try Io.Dir.openFile(.cwd(), io, source_path, .{});
    defer input_file.close(io);

    const input_stat = try input_file.stat(io);
    const file_size = input_stat.size;

    if (file_size >= mmap_threshold and builtin.os.tag != .windows) {
        try decryptFileZeroCopy(
            input_file,
            gpa,
            io,
            file_size,
            dest_path,
            derived_keys,
            input_stat.permissions,
        );
    } else {
        try decryptFileBuffered(
            input_file,
            gpa,
            io,
            file_size,
            dest_path,
            derived_keys,
            input_stat.permissions,
        );
    }
}

fn decryptFileZeroCopy(
    input_file: Io.File,
    gpa: Allocator,
    io: Io,
    file_size: u64,
    dest_path: []const u8,
    derived_keys: crypto.DerivedKeys,
    permissions: Io.File.Permissions,
) !void {
    io_hints.adviseFile(input_file, 0, @intCast(file_size), .sequential);

    var input_map = Io.File.MemoryMap.create(io, input_file, .{
        .len = file_size,
        .protection = .{ .read = true, .write = false },
        .populate = true,
    }) catch {
        return decryptFileBuffered(
            input_file,
            gpa,
            io,
            file_size,
            dest_path,
            derived_keys,
            permissions,
        );
    };
    defer input_map.destroy(io);

    io_hints.adviseMemory(input_map.memory.ptr, file_size, .sequential);
    io_hints.adviseMemory(input_map.memory.ptr, file_size, .will_need);

    if (file_size < crypto.overhead_size) {
        return error.InvalidFileSize;
    }
    const output_size = file_size - crypto.overhead_size;

    var atomic = try AtomicOutput.init(
        gpa,
        io,
        dest_path,
        .{ .read = true, .permissions = permissions },
        null,
    );
    defer atomic.deinit(io);

    try atomic.file.setLength(io, output_size);

    {
        var output_map = try Io.File.MemoryMap.create(io, atomic.file, .{
            .len = output_size,
            .protection = .{ .read = true, .write = true },
            .undefined_contents = true,
            .populate = false,
        });
        defer output_map.destroy(io);

        io_hints.adviseMemory(output_map.memory.ptr, output_size, .sequential);

        try crypto.decryptZeroCopy(output_map.memory, input_map.memory, derived_keys);

        io_hints.adviseMemory(input_map.memory.ptr, file_size, .dont_need);

        try output_map.write(io);
    }

    try atomic.setPermissions(io, permissions);
    try atomic.finalize(io);
}

fn decryptFileBuffered(
    input_file: Io.File,
    gpa: Allocator,
    io: Io,
    file_size: u64,
    dest_path: []const u8,
    derived_keys: crypto.DerivedKeys,
    permissions: Io.File.Permissions,
) !void {
    const encrypted = try readBuffered(input_file, gpa, io, file_size);
    defer gpa.free(encrypted);

    const plaintext = try crypto.decrypt(gpa, encrypted, derived_keys);
    defer gpa.free(plaintext);

    var atomic = try AtomicOutput.init(gpa, io, dest_path, .{ .permissions = permissions }, null);
    defer atomic.deinit(io);

    try atomic.file.writeStreamingAll(io, plaintext);

    try atomic.setPermissions(io, permissions);
    try atomic.finalize(io);
}

/// Check an encrypted file without changing it.
/// Quick checks confirm the key and header, but not the rest of the file.
pub fn verifyFile(
    gpa: Allocator,
    io: Io,
    source_path: []const u8,
    derived_keys: crypto.DerivedKeys,
    quick: bool,
) !void {
    const input_file = try Io.Dir.openFile(.cwd(), io, source_path, .{});
    defer input_file.close(io);

    const input_stat = try input_file.stat(io);
    const file_size = input_stat.size;

    if (file_size >= mmap_threshold and builtin.os.tag != .windows) {
        try verifyFileZeroCopy(input_file, gpa, io, file_size, derived_keys, quick);
    } else {
        try verifyFileBuffered(input_file, gpa, io, file_size, derived_keys, quick);
    }
}

fn verifyFileZeroCopy(
    input_file: Io.File,
    gpa: Allocator,
    io: Io,
    file_size: u64,
    derived_keys: crypto.DerivedKeys,
    quick: bool,
) !void {
    io_hints.adviseFile(input_file, 0, @intCast(file_size), .sequential);

    var input_map = Io.File.MemoryMap.create(io, input_file, .{
        .len = file_size,
        .protection = .{ .read = true, .write = false },
        .populate = true,
    }) catch {
        return verifyFileBuffered(input_file, gpa, io, file_size, derived_keys, quick);
    };
    defer {
        io_hints.adviseMemory(input_map.memory.ptr, file_size, .dont_need);
        input_map.destroy(io);
    }

    io_hints.adviseMemory(input_map.memory.ptr, file_size, .sequential);
    io_hints.adviseMemory(input_map.memory.ptr, file_size, .will_need);

    if (quick) {
        try crypto.verifyHeaderOnly(input_map.memory, derived_keys);
    } else {
        try crypto.verify(gpa, input_map.memory, derived_keys);
    }
}

fn verifyFileBuffered(
    input_file: Io.File,
    gpa: Allocator,
    io: Io,
    file_size: u64,
    derived_keys: crypto.DerivedKeys,
    quick: bool,
) !void {
    const encrypted = try readBuffered(input_file, gpa, io, file_size);
    defer gpa.free(encrypted);

    if (quick) {
        try crypto.verifyHeaderOnly(encrypted, derived_keys);
    } else {
        try crypto.verify(gpa, encrypted, derived_keys);
    }
}

test "a file survives an encrypt and decrypt round trip" {
    const gpa = testing.allocator;
    const io = testing.io;

    try Io.Dir.createDirPath(.cwd(), io, "tmp/processor_round_trip");
    defer Io.Dir.deleteTree(.cwd(), io, "tmp/processor_round_trip") catch {};

    const test_data = "Hello, World! This is test data for file encryption.";
    const source_path = "tmp/processor_round_trip/input.txt";
    const encrypted_path = "tmp/processor_round_trip/encrypted.bin";
    const decrypted_path = "tmp/processor_round_trip/decrypted.txt";
    try Io.Dir.writeFile(.cwd(), io, .{ .sub_path = source_path, .data = test_data });

    const derived = crypto.deriveKeys(@splat(42), null);

    try encryptFile(gpa, io, source_path, encrypted_path, derived);
    const encrypted_stat = try Io.Dir.statFile(.cwd(), io, encrypted_path, .{});
    try testing.expectEqual(test_data.len + crypto.overhead_size, encrypted_stat.size);

    try decryptFile(gpa, io, encrypted_path, decrypted_path, derived);
    const content = try Io.Dir.readFileAlloc(.cwd(), io, decrypted_path, gpa, .limited(1024));
    defer gpa.free(content);
    try testing.expectEqualStrings(test_data, content);
}

test "decrypting with the wrong key fails and writes nothing" {
    const gpa = testing.allocator;
    const io = testing.io;

    try Io.Dir.createDirPath(.cwd(), io, "tmp/processor_wrong_key");
    defer Io.Dir.deleteTree(.cwd(), io, "tmp/processor_wrong_key") catch {};

    const source_path = "tmp/processor_wrong_key/input.txt";
    const encrypted_path = "tmp/processor_wrong_key/encrypted.bin";
    const decrypted_path = "tmp/processor_wrong_key/decrypted.txt";
    try Io.Dir.writeFile(.cwd(), io, .{ .sub_path = source_path, .data = "Secret data" });

    const right_key = crypto.deriveKeys(@splat(1), null);
    const wrong_key = crypto.deriveKeys(@splat(2), null);

    try encryptFile(gpa, io, source_path, encrypted_path, right_key);
    try testing.expectError(
        error.InvalidHeaderMac,
        decryptFile(gpa, io, encrypted_path, decrypted_path, wrong_key),
    );
    try testing.expectError(error.FileNotFound, Io.Dir.openFile(.cwd(), io, decrypted_path, .{}));
}

test "a file can be encrypted and decrypted in place through an absolute path" {
    const gpa = testing.allocator;
    const io = testing.io;

    try Io.Dir.createDirPath(.cwd(), io, "tmp/processor_in_place");
    defer Io.Dir.deleteTree(.cwd(), io, "tmp/processor_in_place") catch {};

    const relative_path = "tmp/processor_in_place/data.txt";
    const plaintext = "absolute path data";
    try Io.Dir.writeFile(.cwd(), io, .{ .sub_path = relative_path, .data = plaintext });

    const abs_path = try Io.Dir.realPathFileAlloc(.cwd(), io, relative_path, gpa);
    defer gpa.free(abs_path);

    const derived = crypto.deriveKeys(@splat(9), null);

    try encryptFile(gpa, io, abs_path, abs_path, derived);
    const encrypted_stat = try Io.Dir.statFile(.cwd(), io, relative_path, .{});
    try testing.expectEqual(plaintext.len + crypto.overhead_size, encrypted_stat.size);

    try decryptFile(gpa, io, abs_path, abs_path, derived);
    const content = try Io.Dir.readFileAlloc(.cwd(), io, relative_path, gpa, .limited(1024));
    defer gpa.free(content);
    try testing.expectEqualStrings(plaintext, content);
}

test "destination with .enc suffix keeps the source file" {
    const gpa = testing.allocator;
    const io = testing.io;

    try Io.Dir.createDirPath(.cwd(), io, "tmp/processor_keep_source");
    defer Io.Dir.deleteTree(.cwd(), io, "tmp/processor_keep_source") catch {};

    const source_path = "tmp/processor_keep_source/keep_source.txt";
    const encrypted_path = "tmp/processor_keep_source/keep_source.txt.enc";
    const plaintext = "the source must survive";
    try Io.Dir.writeFile(.cwd(), io, .{ .sub_path = source_path, .data = plaintext });

    const derived = crypto.deriveKeys(@splat(3), null);

    try encryptFile(gpa, io, source_path, encrypted_path, derived);
    _ = try Io.Dir.statFile(.cwd(), io, source_path, .{});

    try decryptFile(gpa, io, encrypted_path, source_path, derived);
    _ = try Io.Dir.statFile(.cwd(), io, encrypted_path, .{});
}

test "symlink at output path does not hijack writes" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;

    const gpa = testing.allocator;
    const io = testing.io;

    Io.Dir.deleteTree(.cwd(), io, "tmp/processor_symlink") catch {};
    try Io.Dir.createDirPath(.cwd(), io, "tmp/processor_symlink");
    defer Io.Dir.deleteTree(.cwd(), io, "tmp/processor_symlink") catch {};

    const source_path = "tmp/processor_symlink/input.txt";
    const sentinel_path = "tmp/processor_symlink/sentinel.txt";
    const dest_path = "tmp/processor_symlink/output.bin";
    const sentinel_content = "DO NOT OVERWRITE ME";
    const plaintext = "secret payload that must land in output_path only";
    try Io.Dir.writeFile(.cwd(), io, .{ .sub_path = source_path, .data = plaintext });
    try Io.Dir.writeFile(.cwd(), io, .{ .sub_path = sentinel_path, .data = sentinel_content });
    try Io.Dir.symLink(.cwd(), io, "sentinel.txt", dest_path, .{});

    const derived = crypto.deriveKeys(@splat(7), null);

    try encryptFile(gpa, io, source_path, dest_path, derived);

    const sentinel = try Io.Dir.readFileAlloc(.cwd(), io, sentinel_path, gpa, .limited(1024));
    defer gpa.free(sentinel);
    try testing.expectEqualStrings(sentinel_content, sentinel);

    const dest_stat = try Io.Dir.statFile(.cwd(), io, dest_path, .{});
    try testing.expectEqual(plaintext.len + crypto.overhead_size, dest_stat.size);
}

test "writeFileAtomic keeps temporary files in the given directory" {
    const gpa = testing.allocator;
    const io = testing.io;

    try Io.Dir.createDirPath(.cwd(), io, "tmp/atomic_tmp_dir/dest");
    try Io.Dir.createDirPath(.cwd(), io, "tmp/atomic_tmp_dir/staging");
    defer Io.Dir.deleteTree(.cwd(), io, "tmp/atomic_tmp_dir") catch {};

    const dest_path = "tmp/atomic_tmp_dir/dest/note.md";
    const permissions: ?Io.File.Permissions =
        if (builtin.os.tag == .windows) null else .fromMode(0o600);
    try writeFileAtomic(gpa, io, dest_path, "hello", permissions, "tmp/atomic_tmp_dir/staging");

    const content = try Io.Dir.readFileAlloc(.cwd(), io, dest_path, gpa, .limited(64));
    defer gpa.free(content);
    try testing.expectEqualStrings("hello", content);

    var dest_dir = try Io.Dir.openDir(.cwd(), io, "tmp/atomic_tmp_dir/dest", .{ .iterate = true });
    defer dest_dir.close(io);
    var dest_it = dest_dir.iterate();
    var count: usize = 0;
    while (try dest_it.next(io)) |_| count += 1;
    try testing.expectEqual(1, count);

    var staging_dir = try Io.Dir.openDir(.cwd(), io, "tmp/atomic_tmp_dir/staging", .{
        .iterate = true,
    });
    defer staging_dir.close(io);
    var staging_it = staging_dir.iterate();
    try testing.expectEqual(null, try staging_it.next(io));
}

test "isTmpName accepts only names made by tmpName" {
    const name = tmpName(0x0123456789abcdef);
    try testing.expectEqualStrings(".tc-0123456789abcdef.tmp", &name);
    try testing.expect(isTmpName(&name));
    try testing.expect(isTmpName(&tmpName(0)));
    try testing.expect(!isTmpName(".tc-0123456789ABCDEF.tmp"));
    try testing.expect(!isTmpName(".tc-0123456789abcde.tmp"));
    try testing.expect(!isTmpName("x.tc-0123456789abcdef.tmp"));
    try testing.expect(!isTmpName("notes.txt"));
}

test "the temporary file fits next to a 255-byte destination" {
    const gpa = testing.allocator;
    const io = testing.io;

    try Io.Dir.createDirPath(.cwd(), io, "tmp/atomic_long");
    defer Io.Dir.deleteTree(.cwd(), io, "tmp/atomic_long") catch {};

    const long_name: [255]u8 = @splat('n');
    const dest_path = "tmp/atomic_long/" ++ long_name;
    try writeFileAtomic(gpa, io, dest_path, "data", null, null);
    const content = try Io.Dir.readFileAlloc(.cwd(), io, dest_path, gpa, .limited(16));
    defer gpa.free(content);
    try testing.expectEqualStrings("data", content);
}

test "initIn stages and publishes through directory handles" {
    const gpa = testing.allocator;
    const io = testing.io;

    try Io.Dir.createDirPath(.cwd(), io, "tmp/atomic_in/dest");
    defer Io.Dir.deleteTree(.cwd(), io, "tmp/atomic_in") catch {};
    var stage = try Io.Dir.openDir(.cwd(), io, "tmp/atomic_in", .{ .iterate = true });
    defer stage.close(io);
    var dest = try Io.Dir.openDir(.cwd(), io, "tmp/atomic_in/dest", .{ .iterate = true });
    defer dest.close(io);

    {
        var atomic = try AtomicOutput.initIn(stage, gpa, io, .{});
        defer atomic.deinit(io);
        try testing.expect(isTmpName(atomic.tmp_path));
        _ = try stage.statFile(io, atomic.tmp_path, .{});
        try atomic.file.writeStreamingAll(io, "moved");
        try atomic.finalizeInto(io, dest, "final");
    }
    const content = try dest.readFileAlloc(io, "final", gpa, .limited(16));
    defer gpa.free(content);
    try testing.expectEqualStrings("moved", content);

    {
        var atomic = try AtomicOutput.initIn(stage, gpa, io, .{});
        atomic.deinit(io);
    }
    var it = stage.iterate();
    var count: usize = 0;
    while (try it.next(io)) |_| count += 1;
    try testing.expectEqual(1, count);
}
