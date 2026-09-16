//! RAF state and data operations of a container mount.
//!
//! Nodes must stay at stable addresses: RAF borrows their storage and random source.
//! In-place updates need no plaintext staging or write-back, so nodes can close with their last reference.
//!
//! Failed mutations poison the context and remain visible to flush and fsync.
//! Reopening may read surviving records; it doesn't repair torn records.

const std = @import("std");
const builtin = @import("builtin");
const aegis_raf = @import("aegis_raf");
const container = @import("../container.zig");
const fault_storage = @import("fault_storage.zig");
const fuse = @import("fuse.zig");
const node_mod = @import("node.zig");
const table_mod = @import("table.zig");

pub const Storage = if (builtin.mode == .debug) fault_storage.FaultStorage else aegis_raf.FileStorage;
pub const Raf = aegis_raf.Aegis128X2Raf(Storage);
pub const Table = table_mod.Table(Node);

/// Batch writes while limiting scratch space to 128 KiB per open file.
const scratch_chunks = 8;

/// Allow only one RAF context per inode, including through case aliases.
/// Separate contexts could use stale lengths and overwrite each other's records.
pub const Inodes = struct {
    mutex: std.Io.Mutex = .init,
    map: std.AutoHashMapUnmanaged(node_mod.MarkKey, *Node) = .empty,
    allocator: std.mem.Allocator,
    io: std.Io,

    pub fn deinit(self: *Inodes) void {
        self.map.deinit(self.allocator);
    }

    fn claim(self: *Inodes, key: node_mod.MarkKey, node: *Node) error{ OutOfMemory, FileBusy }!void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        const entry = try self.map.getOrPut(self.allocator, key);
        if (entry.found_existing) {
            if (entry.value_ptr.* != node) return error.FileBusy;
            return;
        }
        entry.value_ptr.* = node;
    }

    fn forget(self: *Inodes, key: node_mod.MarkKey, node: *Node) void {
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
    key: node_mod.MarkKey,
};

pub const Node = struct {
    mutex: std.Io.Mutex = .init,
    /// Relative to the backing root.
    path: []u8,
    /// Open handles plus pins.
    refs: usize = 1,
    /// Set under the node lock when the backing entry goes away; the table reads it under its own lock.
    unlinked: std.atomic.Value(bool) = .init(false),
    /// The backing file is open and its header authenticated.
    opened: bool = false,
    /// Records handle access, which may be read-only even on a writable mount.
    writable: bool = false,
    /// The first failed mutation. Later data operations fail, and flush or fsync report this error.
    failed: ?anyerror = null,
    /// Held from before the header is read until the context closes.
    claim: ?Claim = null,
    file: std.Io.File = undefined,
    storage: Storage = undefined,
    /// Must outlive the RAF context, which borrows it to generate nonces.
    source: std.Random.IoSource = undefined,
    raf: Raf = undefined,

    pub fn retainAtZeroRefs(node: *const Node) bool {
        _ = node;
        return false;
    }

    pub fn deinitData(node: *Node, table: *Table) void {
        node.discard(table.io);
    }

    /// Release resources while leaving the node reusable.
    pub fn discard(node: *Node, io: std.Io) void {
        node.releaseInode();
        if (!node.opened) return;
        node.raf.close();
        node.file.close(io);
        node.opened = false;
        node.failed = null;
    }

    /// Adopt an authenticated file; on failure the caller retains it and no inode claim remains.
    ///
    /// Claim before reading the header so an alias can't retain a length made stale by another writer.
    pub fn openWith(node: *Node, file: std.Io.File, writable: bool, inodes: *Inodes, raf_key: *const [16]u8, allocator: std.mem.Allocator, io: std.Io) !void {
        try node.prepare(file, inodes, io);
        errdefer node.releaseInode();
        node.raf = try Raf.open(allocator, &node.storage, node.source.interface(), .{ .scratch_chunks = scratch_chunks }, raf_key);
        node.adopt(file, writable);
    }

    /// Initialize and adopt an empty file; on failure the caller retains it and no inode claim remains.
    pub fn createWith(node: *Node, file: std.Io.File, inodes: *Inodes, raf_key: *const [16]u8, allocator: std.mem.Allocator, io: std.Io) !void {
        try node.prepare(file, inodes, io);
        errdefer node.releaseInode();
        node.raf = try Raf.create(allocator, &node.storage, node.source.interface(), .{ .chunk_size = container.data_chunk_size, .scratch_chunks = scratch_chunks }, raf_key);
        node.adopt(file, true);
    }

    fn prepare(node: *Node, file: std.Io.File, inodes: *Inodes, io: std.Io) !void {
        std.debug.assert(!node.opened and node.claim == null);
        const key = node_mod.markKey(try fuse.statFd(file.handle));
        try inodes.claim(key, node);
        node.claim = .{ .inodes = inodes, .key = key };
        node.source = .{ .io = io };
        node.storage = Storage.init(file, io);
    }

    fn adopt(node: *Node, file: std.Io.File, writable: bool) void {
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

    /// A failed read poisons nothing, and the library leaves zeros in `out`.
    pub fn read(node: *Node, out: []u8, offset: u64) !usize {
        return node.raf.read(out, offset);
    }

    pub fn write(node: *Node, in: []const u8, offset: u64) !usize {
        return node.raf.write(in, offset) catch |err| {
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

    /// Report immediately because some clients defer write errors until close.
    fn recordFailure(node: *Node, err: anyerror) void {
        if (node.failed != null) return;
        node.failed = err;
        std.debug.print("turbocrypt mount: cannot write {s}: {s}; the file reports the error until its last handle closes\n", .{ node.path, @errorName(err) });
    }
};

pub const ColdSize = struct {
    size: i64,
    /// Only `.authenticated` is trusted.
    source: enum { authenticated, probed, backing },
};

/// Prefer authenticated length, but keep damaged and stray files listable and removable.
/// Fall back to backing size if probing fails or the claimed length can't fit in stat.
pub fn coldSize(file: std.Io.File, backing_size: i64, raf_key: *const [16]u8, io: std.Io) ColdSize {
    var storage = Storage.init(file, io);
    const verified = Raf.verify(&storage, raf_key) catch null;
    const info = verified orelse aegis_raf.probe(&storage) catch return .{ .size = backing_size, .source = .backing };
    const size = std.math.cast(i64, info.file_size) orelse return .{ .size = backing_size, .source = .backing };
    return .{ .size = size, .source = if (verified != null) .authenticated else .probed };
}

const testing = std.testing;
const crypto = @import("../crypto.zig");

const test_root = "tmp/raf_node";

fn openTestRoot(io: std.Io) !std.Io.Dir {
    std.Io.Dir.deleteTree(.cwd(), io, test_root) catch {};
    try std.Io.Dir.createDirPath(.cwd(), io, test_root);
    return std.Io.Dir.openDir(.cwd(), io, test_root, .{ .iterate = true });
}

fn testRafKey(seed: u8) [16]u8 {
    return container.deriveRafKey(crypto.deriveKeys(@splat(seed), null));
}

fn createNode(table: *Table, inodes: *Inodes, dir: std.Io.Dir, name: []const u8, raf_key: *const [16]u8) !*Node {
    const node = try table.attach(name);
    errdefer table.release(node);
    const file = try dir.createFile(table.io, name, .{ .read = true, .exclusive = true });
    node.createWith(file, inodes, raf_key, table.allocator, table.io) catch |err| {
        file.close(table.io);
        return err;
    };
    return node;
}

fn openNode(table: *Table, inodes: *Inodes, dir: std.Io.Dir, name: []const u8, raf_key: *const [16]u8) !*Node {
    const node = try table.attach(name);
    errdefer table.release(node);
    const file = try dir.openFile(table.io, name, .{ .mode = .read_write });
    node.openWith(file, true, inodes, raf_key, table.allocator, table.io) catch |err| {
        file.close(table.io);
        return err;
    };
    return node;
}

fn flipByte(dir: std.Io.Dir, io: std.Io, name: []const u8, offset: u64) !void {
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
    const allocator = testing.allocator;
    const io = testing.io;
    var dir = try openTestRoot(io);
    defer dir.close(io);
    defer std.Io.Dir.deleteTree(.cwd(), io, test_root) catch {};
    const raf_key = testRafKey(41);
    var inodes: Inodes = .{ .allocator = allocator, .io = io };
    defer inodes.deinit();
    var table = Table.init(allocator, io, 0, 0);
    defer table.deinit();

    const chunk = container.data_chunk_size;
    const data = try allocator.alloc(u8, 3 * chunk + 100);
    defer allocator.free(data);
    for (data, 0..) |*b, i| b.* = patternByte(i);

    const node = try createNode(&table, &inodes, dir, "f", &raf_key);
    try testing.expectEqual(0, node.length());
    try testing.expectEqual(aegis_raf.header_size, try node.file.length(io));

    try testing.expectEqual(1, try node.write(data[0..1], 0));
    try testing.expectEqual(aegis_raf.header_size + Raf.recordSize(chunk), try node.file.length(io));
    try testing.expectEqual(data.len - 1, try node.write(data[1..], 1));
    try testing.expectEqual(data.len, node.length());
    try testing.expectEqual(aegis_raf.header_size + 4 * Raf.recordSize(chunk), try node.file.length(io));

    const back = try allocator.alloc(u8, data.len + 10);
    defer allocator.free(back);
    try testing.expectEqual(data.len, try node.read(back, 0));
    try testing.expectEqualSlices(u8, data, back[0..data.len]);

    // Partial updates across chunk boundaries must preserve surrounding bytes.
    try testing.expectEqual(200, try node.read(back[0..200], chunk - 100));
    try testing.expectEqualSlices(u8, data[chunk - 100 ..][0..200], back[0..200]);
    const patch: [50]u8 = @splat('P');
    _ = try node.write(&patch, 2 * chunk - 25);
    try testing.expectEqual(data.len, node.length());
    try testing.expectEqual(data.len, try node.read(back, 0));
    try testing.expectEqualSlices(u8, data[0 .. 2 * chunk - 25], back[0 .. 2 * chunk - 25]);
    try testing.expectEqualSlices(u8, &patch, back[2 * chunk - 25 ..][0..50]);
    try testing.expectEqualSlices(u8, data[2 * chunk + 25 ..], back[2 * chunk + 25 .. data.len]);

    // Regrowth must not reveal truncated data.
    _ = try node.write("tail", node.length());
    try testing.expectEqual(data.len + 4, node.length());
    try node.setLength(chunk + 10);
    try testing.expectEqual(chunk + 10, node.length());
    try testing.expectEqual(aegis_raf.header_size + 2 * Raf.recordSize(chunk), try node.file.length(io));
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
    try testing.expectError(error.AuthenticationFailed, openNode(&table, &inodes, dir, "f", &wrong));
    try testing.expectEqual(0, table.nodes.items.len);
    try testing.expectEqual(0, inodes.count());
}

test "damaged records fail without exposing bytes, and the table cleans up unopened nodes" {
    const allocator = testing.allocator;
    const io = testing.io;
    var dir = try openTestRoot(io);
    defer dir.close(io);
    defer std.Io.Dir.deleteTree(.cwd(), io, test_root) catch {};
    const raf_key = testRafKey(43);
    var inodes: Inodes = .{ .allocator = allocator, .io = io };
    defer inodes.deinit();
    var table = Table.init(allocator, io, 0, 0);
    defer table.deinit();
    const chunk = container.data_chunk_size;

    const data = try allocator.alloc(u8, 3 * chunk);
    defer allocator.free(data);
    for (data, 0..) |*b, i| b.* = patternByte(i);
    {
        const node = try createNode(&table, &inodes, dir, "g", &raf_key);
        _ = try node.write(data, 0);
        table.release(node);
    }
    const back = try allocator.alloc(u8, data.len);
    defer allocator.free(back);

    // Corruption must stay local, and failed reads must expose no plaintext.
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
                try testing.expectError(error.AuthenticationFailed, node.read(slice, other * chunk));
            } else {
                try testing.expectEqual(chunk, try node.read(slice, other * chunk));
                try testing.expectEqualSlices(u8, data[other * chunk ..][0..chunk], slice);
            }
        }
        // A read failure is not a mutation: the context stays usable.
        try testing.expectEqual(null, node.failed);
        table.release(node);
        try flipByte(dir, io, "g", offset);
    }

    // Two valid records swapped fail, because the chunk index is authenticated.
    {
        const file = try dir.openFile(io, "g", .{ .mode = .read_write });
        defer file.close(io);
        const record_size: usize = @intCast(Raf.recordSize(chunk));
        const first = try allocator.alloc(u8, record_size);
        defer allocator.free(first);
        const second = try allocator.alloc(u8, record_size);
        defer allocator.free(second);
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
        var other = try aegis_raf.Aegis128LRaf(aegis_raf.FileStorage).create(allocator, &storage, source.interface(), .{ .chunk_size = chunk }, &raf_key);
        defer other.close();
        _ = try other.write("l", 0);
    }
    try testing.expectError(error.AlgorithmMismatch, openNode(&table, &inodes, dir, "other-variant", &raf_key));

    const unopened = try table.attach("never");
    try testing.expect(!unopened.opened);
    table.release(unopened);
    try testing.expectEqual(0, table.nodes.items.len);
    try testing.expectEqual(0, inodes.count());
}

test "one inode carries one context: a second node on it is refused until the first closes" {
    const allocator = testing.allocator;
    const io = testing.io;
    var dir = try openTestRoot(io);
    defer dir.close(io);
    defer std.Io.Dir.deleteTree(.cwd(), io, test_root) catch {};
    const raf_key = testRafKey(47);
    var inodes: Inodes = .{ .allocator = allocator, .io = io };
    defer inodes.deinit();
    var table = Table.init(allocator, io, 0, 0);
    defer table.deinit();

    const first = try createNode(&table, &inodes, dir, "same", &raf_key);
    _ = try first.write("A", 0);
    try testing.expectEqual(1, inodes.count());

    // Simulate a case alias without requiring a case-insensitive filesystem.
    const alias = try table.attach("SAME");
    {
        const file = try dir.openFile(io, "same", .{ .mode = .read_write });
        defer file.close(io);
        try testing.expectError(error.FileBusy, alias.openWith(file, true, &inodes, &raf_key, allocator, io));
    }
    try testing.expect(!alias.opened);
    try testing.expectEqual(null, alias.claim);
    try testing.expectEqual(1, inodes.count());

    // The alias must see the final length, not a value cached before its claim succeeded.
    _ = try first.write("B", 1);
    table.release(first);
    try testing.expectEqual(0, inodes.count());
    const reopened = try dir.openFile(io, "same", .{ .mode = .read_write });
    try alias.openWith(reopened, true, &inodes, &raf_key, allocator, io);
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

    // Authentication failure must release even an incomplete open's claim.
    const wrong = testRafKey(48);
    const abandoned = try table.attach("abandoned");
    {
        const file = try dir.openFile(io, "same", .{ .mode = .read_write });
        defer file.close(io);
        try testing.expectError(error.AuthenticationFailed, abandoned.openWith(file, true, &inodes, &wrong, allocator, io));
    }
    try testing.expectEqual(null, abandoned.claim);
    try testing.expectEqual(0, inodes.count());
    table.release(abandoned);
}

test "the cold size is authenticated, probed, or the backing size, and never an error" {
    const allocator = testing.allocator;
    const io = testing.io;
    var dir = try openTestRoot(io);
    defer dir.close(io);
    defer std.Io.Dir.deleteTree(.cwd(), io, test_root) catch {};
    const raf_key = testRafKey(44);
    const wrong = testRafKey(45);
    var inodes: Inodes = .{ .allocator = allocator, .io = io };
    defer inodes.deinit();
    var table = Table.init(allocator, io, 0, 0);
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
        try testing.expectEqual(ColdSize{ .size = 12, .source = .authenticated }, coldSize(file, backing, &raf_key, io));
        try testing.expectEqual(ColdSize{ .size = 12, .source = .probed }, coldSize(file, backing, &wrong, io));
    }

    try dir.writeFile(io, .{ .sub_path = "stray", .data = "this is not a RAF file at all, just some bytes that happen to be here" });
    {
        const file = try dir.openFile(io, "stray", .{});
        defer file.close(io);
        try testing.expectEqual(ColdSize{ .size = 70, .source = .backing }, coldSize(file, 70, &raf_key, io));
    }

    // A crafted header that claims 2^64 - 1 bytes does not fit the stat field.
    {
        const file = try dir.openFile(io, "good", .{ .mode = .read_write });
        defer file.close(io);
        var size: [8]u8 = undefined;
        std.mem.writeInt(u64, &size, std.math.maxInt(u64), .little);
        try file.writePositionalAll(io, &size, 16);
        const backing: i64 = @intCast(try file.length(io));
        try testing.expectEqual(ColdSize{ .size = backing, .source = .backing }, coldSize(file, backing, &raf_key, io));
    }
}

test "a torn write poisons the node, and a fresh open reads what survived" {
    if (builtin.mode != .debug) return error.SkipZigTest;
    const allocator = testing.allocator;
    const io = testing.io;
    var dir = try openTestRoot(io);
    defer dir.close(io);
    defer std.Io.Dir.deleteTree(.cwd(), io, test_root) catch {};
    defer node_mod.armFaults(&.{});
    const raf_key = testRafKey(46);
    var inodes: Inodes = .{ .allocator = allocator, .io = io };
    defer inodes.deinit();
    var table = Table.init(allocator, io, 0, 0);
    defer table.deinit();
    const chunk = container.data_chunk_size;

    const data = try allocator.alloc(u8, 2 * chunk + 100);
    defer allocator.free(data);
    for (data, 0..) |*b, i| b.* = patternByte(i);
    const back = try allocator.alloc(u8, data.len);
    defer allocator.free(back);

    // A refused length change during growth fails before any record is touched.
    {
        const node = try createNode(&table, &inodes, dir, "h", &raf_key);
        _ = try node.write(data, 0);
        node_mod.armFaults(&.{.raf_set_length});
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

    // A torn record in the partially filled last chunk damages bytes that were already there.
    {
        const node = try openNode(&table, &inodes, dir, "h", &raf_key);
        node_mod.armFaults(&.{.raf_writev_short});
        try testing.expectError(error.InputOutput, node.write("more", data.len));
        try testing.expectEqual(error.InputOutput, node.failed.?);
        try testing.expectError(error.ContextFailed, node.read(back, 0));
        table.release(node);
    }
    {
        const node = try openNode(&table, &inodes, dir, "h", &raf_key);
        // The header did not change, so the whole chunks before the torn one still read.
        try testing.expectEqual(2 * chunk, try node.read(back[0 .. 2 * chunk], 0));
        try testing.expectEqualSlices(u8, data[0 .. 2 * chunk], back[0 .. 2 * chunk]);
        try testing.expectError(error.AuthenticationFailed, node.read(back[0..100], 2 * chunk));
        // A later partial rewrite of that chunk authenticates the damaged record first, and fails.
        try testing.expectError(error.AuthenticationFailed, node.write("fix", 2 * chunk));
        try testing.expectEqual(error.AuthenticationFailed, node.failed.?);
        table.release(node);
    }

    // A shrink whose physical resize fails leaves a valid header with the smaller size.
    {
        const node = try openNode(&table, &inodes, dir, "h", &raf_key);
        node_mod.armFaults(&.{ .raf_set_length_pass, .raf_set_length });
        try testing.expectError(error.NoSpaceLeft, node.setLength(chunk));
        try testing.expectEqual(error.NoSpaceLeft, node.failed.?);
        table.release(node);
        node_mod.armFaults(&.{});
    }
    {
        const node = try openNode(&table, &inodes, dir, "h", &raf_key);
        try testing.expectEqual(chunk, node.length());
        try testing.expectEqual(chunk, try node.read(back[0..chunk], 0));
        try testing.expectEqualSlices(u8, data[0..chunk], back[0..chunk]);
        // Retrying the same size finishes the shrink.
        try node.setLength(chunk);
        try testing.expectEqual(aegis_raf.header_size + Raf.recordSize(chunk), try node.file.length(io));
        table.release(node);
    }

    // A scalar write failure hits the header update of a growing write.
    {
        const node = try createNode(&table, &inodes, dir, "i", &raf_key);
        node_mod.armFaults(&.{.raf_write_short});
        try testing.expectError(error.InputOutput, node.write("payload", 0));
        try testing.expect(node.failed != null);
        table.release(node);
    }
    {
        // The old header survives as the recovery trailer, or the new one landed whole.
        const node = try openNode(&table, &inodes, dir, "i", &raf_key);
        try testing.expect(node.length() == 0 or node.length() == 7);
        table.release(node);
    }
    try testing.expectEqual(0, table.nodes.items.len);
}
