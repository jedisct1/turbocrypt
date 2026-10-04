//! Manage RAF state and I/O for container mounts.
//!
//! Keep nodes at stable addresses because RAF borrows their storage and randomness.
//! In-place RAF updates avoid plaintext staging and deferred write-back,
//! so a node can leave when its last reference closes.
//!
//! After a write fails, retain the error for flush and fsync.
//! Reopening can recover intact records, but it cannot repair a torn one.

const std = @import("std");
const builtin = @import("builtin");
const assert = std.debug.assert;
const testing = std.testing;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const aegis_raf = @import("aegis_raf");
const container = @import("../container.zig");
const crypto = @import("../crypto.zig");
const FaultStorage = @import("FaultStorage.zig");
const faults = @import("faults.zig");
const fuse = @import("fuse.zig");
const Marks = @import("Marks.zig");

pub const Storage = if (builtin.mode == .debug) FaultStorage else aegis_raf.FileStorage;
pub const Raf = aegis_raf.Aegis128X2Raf(Storage);
pub const Table = @import("table.zig").Table(Node);

/// Limit each open file to 128 KiB of write scratch space.
const scratch_chunks = 8;

/// Allow one RAF context per inode, even when case aliases name it.
/// Separate contexts could use stale lengths and overwrite valid records.
pub const Inodes = struct {
    mutex: Io.Mutex = .init,
    map: std.AutoHashMapUnmanaged(Marks.Key, *Node) = .empty,
    gpa: Allocator,
    io: Io,

    pub fn deinit(self: *Inodes) void {
        self.map.deinit(self.gpa);
    }

    fn claim(self: *Inodes, key: Marks.Key, node: *Node) error{ OutOfMemory, FileBusy }!void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        const entry = try self.map.getOrPut(self.gpa, key);
        if (entry.found_existing) {
            if (entry.value_ptr.* != node) return error.FileBusy;
            return;
        }
        entry.value_ptr.* = node;
    }

    fn forget(self: *Inodes, key: Marks.Key, node: *Node) void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        const owner = self.map.get(key) orelse return;
        if (owner == node) _ = self.map.remove(key);
    }

    pub fn count(self: *Inodes) usize {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        return self.map.count();
    }
};

const Claim = struct {
    inodes: *Inodes,
    key: Marks.Key,
};

pub const Node = struct {
    mutex: Io.Mutex = .init,
    /// This path is relative to the backing root.
    path: []u8,
    /// Includes open handles and temporary pins.
    refs: usize = 1,
    /// Mark deletion under the node lock.
    /// The table checks this state under its own lock.
    unlinked: std.atomic.Value(bool) = .init(false),
    /// Set after the backing file opens and RAF authenticates its header.
    opened: bool = false,
    /// Remember whether this handle may write, even on a writable mount.
    writable: bool = false,
    /// Remember the first write-side failure.
    /// Later operations fail with it, and flush or fsync reports it.
    failed: ?anyerror = null,
    /// Hold the claim from before header validation until this context closes.
    claim: ?Claim = null,
    file: Io.File = undefined,
    storage: Storage = undefined,
    /// Keep this alive because RAF borrows it for nonce generation.
    source: std.Random.IoSource = undefined,
    raf: Raf = undefined,

    pub fn retainAtZeroRefs(node: *const Node) bool {
        _ = node;
        return false;
    }

    pub fn deinitData(node: *Node, table: *Table) void {
        node.discard(table.io);
    }

    /// Release resources without discarding the node itself.
    pub fn discard(node: *Node, io: Io) void {
        node.releaseInode();
        if (!node.opened) return;
        node.raf.close();
        node.file.close(io);
        node.opened = false;
        node.failed = null;
    }

    /// Take ownership of a file whose RAF header has been authenticated.
    /// On failure, leave ownership with the caller and release any inode claim.
    ///
    /// Claim the inode before reading its header so an alias cannot retain a length another writer changed.
    ///
    pub fn openWith(
        node: *Node,
        gpa: Allocator,
        io: Io,
        file: Io.File,
        writable: bool,
        inodes: *Inodes,
        raf_key: *const [16]u8,
    ) !void {
        try node.prepare(io, file, inodes);
        errdefer node.releaseInode();
        node.raf = try Raf.open(
            gpa,
            &node.storage,
            node.source.interface(),
            .{ .scratch_chunks = scratch_chunks },
            raf_key,
        );
        node.adopt(file, writable);
    }

    /// Create RAF state in an empty file and then take ownership.
    /// On failure, leave ownership with the caller and release any inode claim.
    pub fn createWith(
        node: *Node,
        gpa: Allocator,
        io: Io,
        file: Io.File,
        inodes: *Inodes,
        raf_key: *const [16]u8,
    ) !void {
        try node.prepare(io, file, inodes);
        errdefer node.releaseInode();
        node.raf = try Raf.create(
            gpa,
            &node.storage,
            node.source.interface(),
            .{ .chunk_size = container.data_chunk_size, .scratch_chunks = scratch_chunks },
            raf_key,
        );
        node.adopt(file, true);
    }

    /// Replace the read-only file without giving up this node's inode claim.
    /// On failure, the caller still owns `file`; otherwise the node takes it.
    pub fn upgradeWritable(node: *Node, io: Io, file: Io.File) !void {
        assert(node.opened and !node.writable);
        const claim = node.claim orelse return error.FileBusy;
        const key = Marks.keyOf(try fuse.statFd(file.handle));
        if (key.dev != claim.key.dev or key.ino != claim.key.ino) return error.FileBusy;

        const old_file = node.file;
        node.storage = .init(file, io);
        node.file = file;
        node.writable = true;
        old_file.close(io);
    }

    fn prepare(node: *Node, io: Io, file: Io.File, inodes: *Inodes) !void {
        assert(!node.opened and node.claim == null);
        const key = Marks.keyOf(try fuse.statFd(file.handle));
        try inodes.claim(key, node);
        node.claim = .{ .inodes = inodes, .key = key };
        node.source = .{ .io = io };
        node.storage = .init(file, io);
    }

    fn adopt(node: *Node, file: Io.File, writable: bool) void {
        node.file = file;
        node.writable = writable;
        node.opened = true;
    }

    fn releaseInode(node: *Node) void {
        const claim = node.claim orelse return;
        claim.inodes.forget(claim.key, node);
        node.claim = null;
    }

    pub fn length(node: *const Node) u64 {
        return node.raf.length();
    }

    /// A read failure does not poison the context, and RAF clears `buffer` before returning it.
    pub fn read(node: *Node, buffer: []u8, offset: u64) !usize {
        return node.raf.read(buffer, offset);
    }

    pub fn write(node: *Node, bytes: []const u8, offset: u64) !usize {
        return node.raf.write(bytes, offset) catch |err| {
            node.recordFailure(err);
            return err;
        };
    }

    pub fn setLength(node: *Node, new_length: u64) !void {
        node.raf.setLength(new_length) catch |err| {
            node.recordFailure(err);
            return err;
        };
    }

    /// Report the first write failure now because clients may postpone errors until close.
    fn recordFailure(node: *Node, err: anyerror) void {
        if (node.failed != null) return;
        node.failed = err;
        std.debug.print(
            "turbocrypt mount: cannot write {s}: {s}; the file reports the error until its last handle closes\n",
            .{ node.path, @errorName(err) },
        );
    }
};

pub const ColdSize = struct {
    size: i64,
    /// Trust only the authenticated size.
    source: enum { authenticated, probed, backing },
};

/// Use the authenticated size when possible, but still list and remove damaged or stray files.
/// Use the stored-file size when probing fails or the claimed size will not fit in stat.
pub fn coldSize(file: Io.File, io: Io, backing_size: i64, raf_key: *const [16]u8) ColdSize {
    const fallback: ColdSize = .{ .size = backing_size, .source = .backing };
    var storage = Storage.init(file, io);
    const verified = Raf.verify(&storage, raf_key) catch null;
    const info = verified orelse aegis_raf.probe(&storage) catch return fallback;
    const size = std.math.cast(i64, info.file_size) orelse return fallback;
    return .{ .size = size, .source = if (verified != null) .authenticated else .probed };
}

const test_root = "tmp/raf_node";

fn openTestRoot(io: Io) !Io.Dir {
    Io.Dir.deleteTree(.cwd(), io, test_root) catch {};
    try Io.Dir.createDirPath(.cwd(), io, test_root);
    return Io.Dir.openDir(.cwd(), io, test_root, .{ .iterate = true });
}

fn testRafKey(seed: u8) [16]u8 {
    return container.deriveRafKey(crypto.deriveKeys(@splat(seed), null));
}

fn createNode(
    table: *Table,
    inodes: *Inodes,
    dir: Io.Dir,
    name: []const u8,
    raf_key: *const [16]u8,
) !*Node {
    const node = try table.attach(name);
    errdefer table.release(node);
    const file = try dir.createFile(table.io, name, .{ .read = true, .exclusive = true });
    node.createWith(table.gpa, table.io, file, inodes, raf_key) catch |err| {
        file.close(table.io);
        return err;
    };
    return node;
}

fn openNode(
    table: *Table,
    inodes: *Inodes,
    dir: Io.Dir,
    name: []const u8,
    raf_key: *const [16]u8,
) !*Node {
    const node = try table.attach(name);
    errdefer table.release(node);
    const file = try dir.openFile(table.io, name, .{ .mode = .read_write });
    node.openWith(table.gpa, table.io, file, true, inodes, raf_key) catch |err| {
        file.close(table.io);
        return err;
    };
    return node;
}

fn flipByte(dir: Io.Dir, io: Io, name: []const u8, offset: u64) !void {
    const file = try dir.openFile(io, name, .{ .mode = .read_write });
    defer file.close(io);
    var byte: [1]u8 = undefined;
    _ = try file.readPositionalAll(io, &byte, offset);
    byte[0] ^= 0x80;
    try file.writePositionalAll(io, &byte, offset);
}

fn patternByte(i: usize) u8 {
    return @truncate(i *% 7 +% i / 251);
}

test "a node writes and reads across chunk boundaries, appends, and resizes with zero filling" {
    const gpa = testing.allocator;
    const io = testing.io;
    var dir = try openTestRoot(io);
    defer dir.close(io);
    defer Io.Dir.deleteTree(.cwd(), io, test_root) catch {};
    const raf_key = testRafKey(41);
    var inodes: Inodes = .{ .gpa = gpa, .io = io };
    defer inodes.deinit();
    var table = Table.init(gpa, io, 0, 0);
    defer table.deinit();

    const chunk = container.data_chunk_size;
    const record_size = Raf.recordSize(chunk);
    const data = try gpa.alloc(u8, 3 * chunk + 100);
    defer gpa.free(data);
    for (data, 0..) |*b, i| b.* = patternByte(i);

    const node = try createNode(&table, &inodes, dir, "f", &raf_key);
    try testing.expectEqual(0, node.length());
    try testing.expectEqual(aegis_raf.header_size, try node.file.length(io));

    try testing.expectEqual(1, try node.write(data[0..1], 0));
    try testing.expectEqual(aegis_raf.header_size + record_size, try node.file.length(io));
    try testing.expectEqual(data.len - 1, try node.write(data[1..], 1));
    try testing.expectEqual(data.len, node.length());
    try testing.expectEqual(aegis_raf.header_size + 4 * record_size, try node.file.length(io));

    const back = try gpa.alloc(u8, data.len + 10);
    defer gpa.free(back);
    try testing.expectEqual(data.len, try node.read(back, 0));
    try testing.expectEqualSlices(u8, data, back[0..data.len]);

    // A cross-chunk update must leave the surrounding plaintext intact.
    try testing.expectEqual(200, try node.read(back[0..200], chunk - 100));
    try testing.expectEqualSlices(u8, data[chunk - 100 ..][0..200], back[0..200]);
    const patch: [50]u8 = @splat('P');
    _ = try node.write(&patch, 2 * chunk - 25);
    try testing.expectEqual(data.len, node.length());
    try testing.expectEqual(data.len, try node.read(back, 0));
    try testing.expectEqualSlices(u8, data[0 .. 2 * chunk - 25], back[0 .. 2 * chunk - 25]);
    try testing.expectEqualSlices(u8, &patch, back[2 * chunk - 25 ..][0..50]);
    try testing.expectEqualSlices(u8, data[2 * chunk + 25 ..], back[2 * chunk + 25 .. data.len]);

    // Growing a file again must not reveal bytes that truncation removed.
    _ = try node.write("tail", node.length());
    try testing.expectEqual(data.len + 4, node.length());
    try node.setLength(chunk + 10);
    try testing.expectEqual(chunk + 10, node.length());
    try testing.expectEqual(aegis_raf.header_size + 2 * record_size, try node.file.length(io));
    try node.setLength(2 * chunk + 10);
    try testing.expectEqual(2 * chunk + 10, try node.read(back, 0));
    try testing.expectEqualSlices(u8, data[0 .. chunk + 10], back[0 .. chunk + 10]);
    for (back[chunk + 10 .. 2 * chunk + 10]) |b| try testing.expectEqual(0, b);
    try testing.expectEqual(0, try node.read(back, 2 * chunk + 10));

    _ = try node.write("far", 3 * chunk);
    try testing.expectEqual(3 * chunk + 3, node.length());
    try testing.expectEqual(chunk, try node.read(back[0..chunk], 2 * chunk));
    for (back[10..chunk]) |b| try testing.expectEqual(0, b);
    try testing.expectEqual(3, try node.read(back[0..3], 3 * chunk));
    try testing.expectEqualStrings("far", back[0..3]);
    table.release(node);
    try testing.expectEqual(0, table.nodes.items.len);

    const again = try openNode(&table, &inodes, dir, "f", &raf_key);
    try testing.expectEqual(3 * chunk + 3, again.length());
    try testing.expectEqual(chunk + 10, try again.read(back[0 .. chunk + 10], 0));
    try testing.expectEqualSlices(u8, data[0 .. chunk + 10], back[0 .. chunk + 10]);
    table.release(again);
    const wrong = testRafKey(42);
    try testing.expectError(
        error.AuthenticationFailed,
        openNode(&table, &inodes, dir, "f", &wrong),
    );
    try testing.expectEqual(0, table.nodes.items.len);
    try testing.expectEqual(0, inodes.count());
}

test "damaged records fail without exposing bytes, and the table cleans up unopened nodes" {
    const gpa = testing.allocator;
    const io = testing.io;
    var dir = try openTestRoot(io);
    defer dir.close(io);
    defer Io.Dir.deleteTree(.cwd(), io, test_root) catch {};
    const raf_key = testRafKey(43);
    var inodes: Inodes = .{ .gpa = gpa, .io = io };
    defer inodes.deinit();
    var table = Table.init(gpa, io, 0, 0);
    defer table.deinit();
    const chunk = container.data_chunk_size;

    const data = try gpa.alloc(u8, 3 * chunk);
    defer gpa.free(data);
    for (data, 0..) |*b, i| b.* = patternByte(i);
    {
        const node = try createNode(&table, &inodes, dir, "g", &raf_key);
        _ = try node.write(data, 0);
        table.release(node);
    }
    const back = try gpa.alloc(u8, data.len);
    defer gpa.free(back);

    // Corruption must stay within its record, and a failed read must reveal no plaintext.
    for ([_]u64{ 0, 1, 2 }) |index| {
        const offset = Raf.chunkOffset(chunk, index) + 16 + 5;
        try flipByte(dir, io, "g", offset);
        const node = try openNode(&table, &inodes, dir, "g", &raf_key);
        @memset(back, 0xAA);
        try testing.expectError(error.AuthenticationFailed, node.read(back, 0));
        for (back) |b| try testing.expectEqual(0, b);
        for ([_]u64{ 0, 1, 2 }) |other| {
            const slice = back[0..chunk];
            if (other == index) {
                try testing.expectError(
                    error.AuthenticationFailed,
                    node.read(slice, other * chunk),
                );
            } else {
                try testing.expectEqual(chunk, try node.read(slice, other * chunk));
                try testing.expectEqualSlices(u8, data[other * chunk ..][0..chunk], slice);
            }
        }
        // A read error leaves the context usable because it changed nothing.
        try testing.expectEqual(null, node.failed);
        table.release(node);
        try flipByte(dir, io, "g", offset);
    }

    // Swapping valid records must fail because authentication binds each record to its chunk.
    {
        const file = try dir.openFile(io, "g", .{ .mode = .read_write });
        defer file.close(io);
        const record_size: usize = @intCast(Raf.recordSize(chunk));
        const first = try gpa.alloc(u8, record_size);
        defer gpa.free(first);
        const second = try gpa.alloc(u8, record_size);
        defer gpa.free(second);
        _ = try file.readPositionalAll(io, first, Raf.chunkOffset(chunk, 0));
        _ = try file.readPositionalAll(io, second, Raf.chunkOffset(chunk, 1));
        try file.writePositionalAll(io, second, Raf.chunkOffset(chunk, 0));
        try file.writePositionalAll(io, first, Raf.chunkOffset(chunk, 1));
    }
    {
        const node = try openNode(&table, &inodes, dir, "g", &raf_key);
        try testing.expectError(error.AuthenticationFailed, node.read(back[0..chunk], 0));
        try testing.expectError(error.AuthenticationFailed, node.read(back[0..chunk], chunk));
        try testing.expectEqual(chunk, try node.read(back[0..chunk], 2 * chunk));
        table.release(node);
    }

    {
        const file = try dir.createFile(io, "other-variant", .{ .read = true, .exclusive = true });
        defer file.close(io);
        var storage = aegis_raf.FileStorage.init(file, io);
        const source: std.Random.IoSource = .{ .io = io };
        var other = try aegis_raf.Aegis128LRaf(aegis_raf.FileStorage).create(
            gpa,
            &storage,
            source.interface(),
            .{ .chunk_size = chunk },
            &raf_key,
        );
        defer other.close();
        _ = try other.write("l", 0);
    }
    try testing.expectError(
        error.AlgorithmMismatch,
        openNode(&table, &inodes, dir, "other-variant", &raf_key),
    );

    const unopened = try table.attach("never");
    try testing.expect(!unopened.opened);
    table.release(unopened);
    try testing.expectEqual(0, table.nodes.items.len);
    try testing.expectEqual(0, inodes.count());
}

test "one inode carries one context: a second node on it is refused until the first closes" {
    const gpa = testing.allocator;
    const io = testing.io;
    var dir = try openTestRoot(io);
    defer dir.close(io);
    defer Io.Dir.deleteTree(.cwd(), io, test_root) catch {};
    const raf_key = testRafKey(47);
    var inodes: Inodes = .{ .gpa = gpa, .io = io };
    defer inodes.deinit();
    var table = Table.init(gpa, io, 0, 0);
    defer table.deinit();

    const first = try createNode(&table, &inodes, dir, "same", &raf_key);
    _ = try first.write("A", 0);
    try testing.expectEqual(1, inodes.count());

    // Use a second table name to model a case alias without needing a case-insensitive filesystem.
    const alias = try table.attach("SAME");
    {
        const file = try dir.openFile(io, "same", .{ .mode = .read_write });
        defer file.close(io);
        try testing.expectError(
            error.FileBusy,
            alias.openWith(gpa, io, file, true, &inodes, &raf_key),
        );
    }
    try testing.expect(!alias.opened);
    try testing.expectEqual(null, alias.claim);
    try testing.expectEqual(1, inodes.count());

    // The alias must observe the final length, not one cached before it claimed the inode.
    _ = try first.write("B", 1);
    table.release(first);
    try testing.expectEqual(0, inodes.count());
    const reopened = try dir.openFile(io, "same", .{ .mode = .read_write });
    try alias.openWith(gpa, io, reopened, true, &inodes, &raf_key);
    try testing.expectEqual(1, inodes.count());
    try testing.expectEqual(2, alias.length());
    _ = try alias.write("C", 2);
    var back: [3]u8 = undefined;
    try testing.expectEqual(3, try alias.read(&back, 0));
    try testing.expectEqualStrings("ABC", &back);

    const other = try createNode(&table, &inodes, dir, "other", &raf_key);
    try testing.expectEqual(2, inodes.count());
    table.release(alias);
    try testing.expectEqual(1, inodes.count());
    table.release(other);
    try testing.expectEqual(0, inodes.count());

    // Even a failed open must release its inode claim.
    const wrong = testRafKey(48);
    const abandoned = try table.attach("abandoned");
    {
        const file = try dir.openFile(io, "same", .{ .mode = .read_write });
        defer file.close(io);
        try testing.expectError(
            error.AuthenticationFailed,
            abandoned.openWith(gpa, io, file, true, &inodes, &wrong),
        );
    }
    try testing.expectEqual(null, abandoned.claim);
    try testing.expectEqual(0, inodes.count());
    table.release(abandoned);
}

test "a read-only node upgrades to a writable handle without changing its inode" {
    const gpa = testing.allocator;
    const io = testing.io;
    var dir = try openTestRoot(io);
    defer dir.close(io);
    defer Io.Dir.deleteTree(.cwd(), io, test_root) catch {};
    const raf_key = testRafKey(49);
    var inodes: Inodes = .{ .gpa = gpa, .io = io };
    defer inodes.deinit();
    var table = Table.init(gpa, io, 0, 0);
    defer table.deinit();

    {
        const created = try createNode(&table, &inodes, dir, "upgrade", &raf_key);
        _ = try created.write("old", 0);
        table.release(created);
    }

    const node = try table.attach("upgrade");
    const read_only = try dir.openFile(io, "upgrade", .{ .mode = .read_only });
    node.openWith(gpa, io, read_only, false, &inodes, &raf_key) catch |err| {
        read_only.close(io);
        return err;
    };
    try testing.expect(!node.writable);
    try testing.expectEqual(1, inodes.count());

    try dir.writeFile(io, .{ .sub_path = "different", .data = "not the same inode" });
    const different = try dir.openFile(io, "different", .{ .mode = .read_write });
    try testing.expectError(error.FileBusy, node.upgradeWritable(io, different));
    different.close(io);
    try testing.expect(!node.writable);
    try testing.expectEqual(1, inodes.count());

    const writable = try dir.openFile(io, "upgrade", .{ .mode = .read_write });
    node.upgradeWritable(io, writable) catch |err| {
        writable.close(io);
        return err;
    };
    try testing.expect(node.writable);
    try testing.expectEqual(1, inodes.count());
    _ = try node.write("new", 0);
    var back: [3]u8 = undefined;
    try testing.expectEqual(3, try node.read(&back, 0));
    try testing.expectEqualStrings("new", &back);

    table.release(node);
    try testing.expectEqual(0, inodes.count());
}

test "the cold size is authenticated, probed, or the backing size, and never an error" {
    const gpa = testing.allocator;
    const io = testing.io;
    var dir = try openTestRoot(io);
    defer dir.close(io);
    defer Io.Dir.deleteTree(.cwd(), io, test_root) catch {};
    const raf_key = testRafKey(44);
    const wrong = testRafKey(45);
    var inodes: Inodes = .{ .gpa = gpa, .io = io };
    defer inodes.deinit();
    var table = Table.init(gpa, io, 0, 0);
    defer table.deinit();

    {
        const node = try createNode(&table, &inodes, dir, "good", &raf_key);
        _ = try node.write("twelve bytes", 0);
        table.release(node);
    }
    {
        const file = try dir.openFile(io, "good", .{});
        defer file.close(io);
        const backing: i64 = @intCast(try file.length(io));
        try testing.expectEqual(
            ColdSize{ .size = 12, .source = .authenticated },
            coldSize(file, io, backing, &raf_key),
        );
        try testing.expectEqual(
            ColdSize{ .size = 12, .source = .probed },
            coldSize(file, io, backing, &wrong),
        );
    }

    try dir.writeFile(io, .{
        .sub_path = "stray",
        .data = "this is not a RAF file at all, just some bytes that happen to be here",
    });
    {
        const file = try dir.openFile(io, "stray", .{});
        defer file.close(io);
        try testing.expectEqual(
            ColdSize{ .size = 70, .source = .backing },
            coldSize(file, io, 70, &raf_key),
        );
    }

    // A header claiming 2^64 - 1 bytes cannot fit in the stat size field.
    {
        const file = try dir.openFile(io, "good", .{ .mode = .read_write });
        defer file.close(io);
        var size: [8]u8 = undefined;
        std.mem.writeInt(u64, &size, std.math.maxInt(u64), .little);
        try file.writePositionalAll(io, &size, 16);
        const backing: i64 = @intCast(try file.length(io));
        try testing.expectEqual(
            ColdSize{ .size = backing, .source = .backing },
            coldSize(file, io, backing, &raf_key),
        );
    }
}

test "a torn write poisons the node, and a fresh open reads what survived" {
    if (builtin.mode != .debug) return error.SkipZigTest;
    const gpa = testing.allocator;
    const io = testing.io;
    var dir = try openTestRoot(io);
    defer dir.close(io);
    defer Io.Dir.deleteTree(.cwd(), io, test_root) catch {};
    defer faults.arm(&.{});
    const raf_key = testRafKey(46);
    var inodes: Inodes = .{ .gpa = gpa, .io = io };
    defer inodes.deinit();
    var table = Table.init(gpa, io, 0, 0);
    defer table.deinit();
    const chunk = container.data_chunk_size;

    const data = try gpa.alloc(u8, 2 * chunk + 100);
    defer gpa.free(data);
    for (data, 0..) |*b, i| b.* = patternByte(i);
    const back = try gpa.alloc(u8, data.len);
    defer gpa.free(back);

    // Fail the resize before touching records when the growth length cannot be set.
    {
        const node = try createNode(&table, &inodes, dir, "h", &raf_key);
        _ = try node.write(data, 0);
        faults.arm(&.{.raf_set_length});
        try testing.expectError(error.NoSpaceLeft, node.write("x", data.len));
        try testing.expectEqual(error.NoSpaceLeft, node.failed.?);
        try testing.expectError(error.ContextFailed, node.write("x", 0));
        try testing.expectError(error.ContextFailed, node.read(back, 0));
        try testing.expectError(error.ContextFailed, node.setLength(0));
        table.release(node);
    }
    {
        const node = try openNode(&table, &inodes, dir, "h", &raf_key);
        try testing.expectEqual(data.len, node.length());
        try testing.expectEqual(data.len, try node.read(back, 0));
        try testing.expectEqualSlices(u8, data, back);
        table.release(node);
    }

    // Tearing the partially filled final record damages its existing bytes as well.
    {
        const node = try openNode(&table, &inodes, dir, "h", &raf_key);
        faults.arm(&.{.raf_writev_short});
        try testing.expectError(error.InputOutput, node.write("more", data.len));
        try testing.expectEqual(error.InputOutput, node.failed.?);
        try testing.expectError(error.ContextFailed, node.read(back, 0));
        table.release(node);
    }
    {
        const node = try openNode(&table, &inodes, dir, "h", &raf_key);
        // The header survived, so complete records before the tear remain readable.
        try testing.expectEqual(2 * chunk, try node.read(back[0 .. 2 * chunk], 0));
        try testing.expectEqualSlices(u8, data[0 .. 2 * chunk], back[0 .. 2 * chunk]);
        try testing.expectError(error.AuthenticationFailed, node.read(back[0..100], 2 * chunk));
        // Rewriting part of this record first authenticates its damaged contents, so it fails.
        try testing.expectError(error.AuthenticationFailed, node.write("fix", 2 * chunk));
        try testing.expectEqual(error.AuthenticationFailed, node.failed.?);
        table.release(node);
    }

    // A failed physical shrink keeps the smaller logical size in a valid header.
    {
        const node = try openNode(&table, &inodes, dir, "h", &raf_key);
        faults.arm(&.{ .raf_set_length_pass, .raf_set_length });
        try testing.expectError(error.NoSpaceLeft, node.setLength(chunk));
        try testing.expectEqual(error.NoSpaceLeft, node.failed.?);
        table.release(node);
        faults.arm(&.{});
    }
    {
        const node = try openNode(&table, &inodes, dir, "h", &raf_key);
        try testing.expectEqual(chunk, node.length());
        try testing.expectEqual(chunk, try node.read(back[0..chunk], 0));
        try testing.expectEqualSlices(u8, data[0..chunk], back[0..chunk]);
        // Setting the same length again completes the physical shrink.
        try node.setLength(chunk);
        try testing.expectEqual(
            aegis_raf.header_size + Raf.recordSize(chunk),
            try node.file.length(io),
        );
        table.release(node);
    }

    // This fault interrupts the header update for a growing scalar write.
    {
        const node = try createNode(&table, &inodes, dir, "i", &raf_key);
        faults.arm(&.{.raf_write_short});
        try testing.expectError(error.InputOutput, node.write("payload", 0));
        try testing.expect(node.failed != null);
        table.release(node);
    }
    {
        // Recovery can use either the intact old header or a fully written new one.
        const node = try openNode(&table, &inodes, dir, "i", &raf_key);
        try testing.expect(node.length() == 0 or node.length() == 7);
        table.release(node);
    }
    try testing.expectEqual(0, table.nodes.items.len);
}
