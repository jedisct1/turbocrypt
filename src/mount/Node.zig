//! Manage shared plaintext and durable write-back for whole-file encryption.
//!
//! Whole-file encryption keeps plaintext in memory while a file is open.
//! Handles for one backing path use the same node.
//! Dirty nodes remain after their last close so a failed write-back can be retried.
//!
//! The table lock owns `path` and `refs`; the node lock owns the remaining state.
//! Set `unlinked` while holding the node lock so deletion prevents write-back.

const Node = @This();

const std = @import("std");
const builtin = @import("builtin");
const assert = std.debug.assert;
const testing = std.testing;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const crypto = @import("../crypto.zig");
const processor = @import("../processor.zig");
const faults = @import("faults.zig");
const fuse = @import("fuse.zig");
const Marks = @import("Marks.zig");

mutex: Io.Mutex = .init,
/// This path is relative to the backing root.
path: []u8,
/// Includes open handles and temporary pins.
refs: usize = 1,
/// Prevent write-back after deletion. This is atomic because the table checks it under another lock.
unlinked: std.atomic.Value(bool) = .init(false),
loaded: bool = false,
dirty: bool = false,
/// The slice length is the logical size; the allocation may extend to `plaintext_capacity`.
plaintext: []u8 = &.{},
plaintext_capacity: usize = 0,
/// Reserve this before writing so recovery does not depend on allocating memory.
ciphertext: []u8 = &.{},
/// Keep metadata changes because write-back replaces the backing inode.
mode: ?std.c.mode_t = null,
uid: ?std.c.uid_t = null,
gid: ?std.c.gid_t = null,
/// Track logical timestamps instead of the ciphertext write time.
times: ?Times = null,

pub const Error = error{
    OutOfMemory,
    FileTooBig,
    NoSpaceLeft,
};

pub const overhead = crypto.overhead_size;

pub const Table = @import("table.zig").Table(Node);

const growth_start: usize = 64 * 1024;
const growth_step: usize = 64 * 1024 * 1024;
const map_threshold: u64 = 1024 * 1024;

/// Grow small files cheaply without holding excessive spare space for large ones.
pub fn grownCapacity(current: usize, needed: usize, limit: usize) usize {
    assert(needed <= limit);
    var capacity = @max(current, growth_start);
    while (capacity < needed) {
        capacity = if (capacity < growth_step) capacity * 2 else capacity + growth_step;
    }
    return @min(capacity, limit);
}

pub const Times = struct {
    atime: std.c.timespec,
    mtime: std.c.timespec,
    ctime: std.c.timespec,
};

pub fn len(node: *const Node) usize {
    return node.plaintext.len;
}

pub fn ciphertextSlice(node: *Node) []u8 {
    return node.ciphertext[0 .. node.plaintext.len + overhead];
}

pub fn markModified(node: *Node, now: std.c.timespec) void {
    node.dirty = true;
    if (node.times) |*times| {
        times.mtime = now;
        times.ctime = now;
    }
}

pub fn load(
    node: *Node,
    io: Io,
    table: *Table,
    file: Io.File,
    size: u64,
    keys: crypto.DerivedKeys,
) !void {
    assert(!node.loaded);
    if (size < overhead) return error.InvalidFileSize;
    if (size - overhead > table.max_file_size) return error.FileTooBig;
    const plain_len: usize = @intCast(size - overhead);
    if (!table.budget.charge(plain_len)) return error.OutOfMemory;
    errdefer table.budget.release(plain_len);
    const plaintext = try table.gpa.alloc(u8, plain_len);
    errdefer table.gpa.free(plaintext);
    try decryptInto(io, plaintext, table, file, size, keys);
    node.plaintext = plaintext;
    node.plaintext_capacity = plain_len;
    node.loaded = true;
}

fn decryptInto(
    io: Io,
    output: []u8,
    table: *Table,
    file: Io.File,
    size: u64,
    keys: crypto.DerivedKeys,
) !void {
    if (size >= map_threshold and builtin.os.tag != .windows) {
        var mapped = Io.File.MemoryMap.create(io, file, .{
            .len = @intCast(size),
            .protection = .{ .read = true, .write = false },
            .populate = true,
        }) catch null;
        if (mapped) |*map| {
            defer map.destroy(io);
            return crypto.decryptZeroCopy(output, map.memory, keys);
        }
    }
    const encrypted_len: usize = @intCast(size);
    if (!table.budget.charge(encrypted_len)) return error.OutOfMemory;
    defer table.budget.release(encrypted_len);
    const encrypted = try table.gpa.alloc(u8, encrypted_len);
    defer table.gpa.free(encrypted);
    const read = try file.readPositionalAll(io, encrypted, 0);
    if (read != encrypted_len) return error.InvalidFileSize;
    return crypto.decryptZeroCopy(output, encrypted, keys);
}

fn ensureCiphertext(node: *Node, table: *Table) Error!void {
    if (node.ciphertext.len != 0) return;
    const capacity = node.plaintext_capacity + overhead;
    if (!table.budget.charge(capacity)) return error.NoSpaceLeft;
    errdefer table.budget.release(capacity);
    node.ciphertext = table.gpa.alloc(u8, capacity) catch return error.NoSpaceLeft;
}

/// Do not sacrifice existing data or recovery capacity when a growth allocation fails.
fn grow(node: *Node, table: *Table, needed: usize) Error!void {
    if (needed > table.max_file_size) return error.FileTooBig;
    const old_capacity = node.plaintext_capacity;
    if (needed <= old_capacity) return node.ensureCiphertext(table);

    const new_capacity = grownCapacity(old_capacity, needed, table.max_file_size);
    const new_ciphertext_capacity = new_capacity + overhead;
    // Drop the old ciphertext first so growing never needs more than three buffers.
    const reused = @min(node.ciphertext.len, new_capacity);
    const extra = new_ciphertext_capacity + new_capacity - reused;
    if (!table.budget.charge(extra)) return error.NoSpaceLeft;

    const new_ciphertext = allocMaybeFaulty(
        table.gpa,
        new_ciphertext_capacity,
        .ciphertext_alloc,
    ) catch {
        table.budget.release(extra);
        return error.NoSpaceLeft;
    };
    if (node.ciphertext.len != 0) {
        table.gpa.free(node.ciphertext);
        table.budget.release(node.ciphertext.len - reused);
    }
    node.ciphertext = new_ciphertext;

    const new_plaintext = reallocMaybeFaulty(
        table.gpa,
        node.plaintext.ptr[0..old_capacity],
        new_capacity,
    ) catch {
        table.budget.release(new_capacity);
        return error.NoSpaceLeft;
    };
    node.plaintext = new_plaintext[0..node.plaintext.len];
    node.plaintext_capacity = new_capacity;
    table.budget.release(old_capacity);
}

fn allocMaybeFaulty(gpa: Allocator, n: usize, fault: faults.Kind) ![]u8 {
    if (faults.take(fault)) return error.OutOfMemory;
    return gpa.alloc(u8, n);
}

fn reallocMaybeFaulty(gpa: Allocator, old: []u8, n: usize) ![]u8 {
    if (faults.take(.plaintext_realloc)) return error.OutOfMemory;
    if (old.len == 0) return gpa.alloc(u8, n);
    return gpa.realloc(old, n);
}

/// Return unused memory after truncation; leave the budget charged if shrinking cannot complete.
fn shrink(node: *Node, table: *Table, new_len: usize) void {
    const old_capacity = node.plaintext_capacity;
    const target = if (new_len == 0)
        0
    else
        @min(old_capacity, grownCapacity(0, new_len, table.max_file_size));
    if (target >= old_capacity) return;

    if (target == 0) {
        table.gpa.free(node.plaintext.ptr[0..old_capacity]);
        node.plaintext = &.{};
    } else {
        const moved = table.gpa.realloc(node.plaintext.ptr[0..old_capacity], target) catch return;
        node.plaintext = moved[0..new_len];
    }
    node.plaintext_capacity = target;
    table.budget.release(old_capacity - target);

    if (node.ciphertext.len != 0) {
        const old_ciphertext = node.ciphertext.len;
        const moved = table.gpa.realloc(node.ciphertext, target + overhead) catch return;
        node.ciphertext = moved;
        table.budget.release(old_ciphertext - moved.len);
    }
}

/// Clear gaps so a sparse write cannot reveal old buffer data.
pub fn write(
    node: *Node,
    table: *Table,
    offset: u64,
    data: []const u8,
    now: std.c.timespec,
) Error!void {
    const end = std.math.add(u64, offset, data.len) catch return error.FileTooBig;
    if (end > table.max_file_size) return error.FileTooBig;
    const old_len = node.plaintext.len;
    const new_len: usize = @intCast(@max(end, old_len));
    try node.grow(table, new_len);
    node.plaintext = node.plaintext.ptr[0..new_len];
    const start: usize = @intCast(offset);
    if (start > old_len) @memset(node.plaintext[old_len..start], 0);
    @memcpy(node.plaintext[start..][0..data.len], data);
    node.loaded = true;
    node.markModified(now);
}

/// Zero truncation can start fresh; other sizes need the existing plaintext.
pub fn truncate(node: *Node, table: *Table, new_len: u64, now: std.c.timespec) Error!void {
    if (new_len > table.max_file_size) return error.FileTooBig;
    assert(node.loaded or new_len == 0);
    const n: usize = @intCast(new_len);
    const old_len = node.plaintext.len;
    if (n > old_len) {
        try node.grow(table, n);
        node.plaintext = node.plaintext.ptr[0..n];
        @memset(node.plaintext[old_len..n], 0);
    } else {
        try node.ensureCiphertext(table);
        node.plaintext = node.plaintext.ptr[0..n];
        node.shrink(table, n);
    }
    node.loaded = true;
    node.markModified(now);
}

/// Keep a dirty linked node after its last close so failed write-back remains retryable.
pub fn retainAtZeroRefs(node: *const Node) bool {
    return node.dirty and !node.unlinked.load(.acquire);
}

/// Free the buffers and release their budget after the last handle or pin.
pub fn deinitData(node: *Node, table: *Table) void {
    if (node.plaintext_capacity != 0) {
        table.gpa.free(node.plaintext.ptr[0..node.plaintext_capacity]);
        table.budget.release(node.plaintext_capacity);
    }
    if (node.ciphertext.len != 0) {
        table.gpa.free(node.ciphertext);
        table.budget.release(node.ciphertext.len);
    }
    node.plaintext = &.{};
    node.plaintext_capacity = 0;
    node.ciphertext = &.{};
    node.loaded = false;
}

/// Use these attributes when the node has no pending metadata change.
pub const Fallback = struct {
    mode: std.c.mode_t,
    uid: ?std.c.uid_t,
    gid: ?std.c.gid_t,
};

/// Replace ciphertext atomically without losing the file's logical metadata.
///
/// Call with a dirty, linked node under its lock.
/// Leave it dirty until publication succeeds so a later flush can retry.
/// When requested, also persist the parent directory entry.
pub fn writeBack(
    node: *Node,
    io: Io,
    table: *Table,
    parent: Io.Dir,
    name: []const u8,
    fallback: Fallback,
    keys: crypto.DerivedKeys,
    marks: *Marks,
    durable: bool,
) !void {
    assert(node.loaded and node.ciphertext.len >= node.plaintext.len + overhead);
    crypto.encryptZeroCopy(io, node.ciphertextSlice(), node.plaintext, keys);

    var change = try marks.begin(parent, Marks.keyOf(try fuse.statFd(parent.handle)));
    defer change.deinit();

    var atomic = try processor.AtomicOutput.initIn(parent, table.gpa, io, .{
        .permissions = .fromMode(0o600),
    });
    defer atomic.deinit(io);
    try atomic.file.writeStreamingAll(io, node.ciphertextSlice());

    const fd = atomic.file.handle;
    if (std.c.fchmod(fd, node.mode orelse fallback.mode) != 0) return error.AccessDenied;
    // Skip chown when the new file already has the right owner, particularly an inherited group.
    const current = try fuse.statFd(fd);
    const uid = node.uid orelse fallback.uid orelse current.uid;
    const gid = node.gid orelse fallback.gid orelse current.gid;
    if (uid != current.uid or gid != current.gid) {
        if (std.c.fchown(fd, uid, gid) != 0) return error.PermissionDenied;
    }
    const times = node.times.?;
    const spec: [2]std.c.timespec = .{ times.atime, times.mtime };
    if (std.c.futimens(fd, &spec) != 0) return error.AccessDenied;
    try faults.syncFd(fd, .file_sync);

    try atomic.finalizeInto(io, parent, name);
    node.dirty = false;
    change.commit();

    if (durable) try marks.sync(change.key);
}

const test_now: std.c.timespec = .{ .sec = 1_700_000_000, .nsec = 5 };
const test_times: Times = .{ .atime = test_now, .mtime = test_now, .ctime = test_now };

test "write at an offset zero-fills the gap and truncate goes both ways" {
    var table = Table.init(testing.allocator, testing.io, 1 << 20, 16 << 20);
    defer table.deinit();
    const node = try table.attach("f");
    node.times = test_times;
    node.loaded = true;

    try node.write(&table, 4, "abc", test_now);
    try testing.expectEqualSlices(u8, &.{ 0, 0, 0, 0, 'a', 'b', 'c' }, node.plaintext);
    try testing.expect(node.dirty);
    try testing.expectEqual(64 * 1024, node.plaintext_capacity);
    try testing.expectEqual(64 * 1024 + overhead, node.ciphertext.len);
    try testing.expectEqual(2 * 64 * 1024 + overhead, table.budget.used());

    try node.truncate(&table, 10, test_now);
    try testing.expectEqual(10, node.len());
    try testing.expectEqual(0, node.plaintext[9]);

    try node.truncate(&table, 2, test_now);
    try testing.expectEqualSlices(u8, &.{ 0, 0 }, node.plaintext);

    try node.truncate(&table, 0, test_now);
    try testing.expectEqual(0, node.plaintext_capacity);
    try testing.expectEqual(overhead, node.ciphertext.len);
    try testing.expectEqual(overhead, table.budget.used());

    const big: [200 * 1024]u8 = @splat('x');
    try node.write(&table, 0, &big, test_now);
    try testing.expectEqual(256 * 1024, node.plaintext_capacity);
    try node.truncate(&table, 100, test_now);
    try testing.expectEqual(64 * 1024, node.plaintext_capacity);
    try testing.expectEqual(2 * 64 * 1024 + overhead, table.budget.used());

    node.dirty = false;
    table.release(node);
    try testing.expectEqual(0, table.budget.used());
}

test "the file limit and the mount budget refuse writes" {
    var table = Table.init(testing.allocator, testing.io, 1000, 3 * 1000 + (1 << 20));
    defer table.deinit();
    const a = try table.attach("a");
    a.times = test_times;
    a.loaded = true;
    const data: [1000]u8 = @splat(1);
    try a.write(&table, 0, &data, test_now);
    try testing.expectError(error.FileTooBig, a.write(&table, 1000, "x", test_now));
    try testing.expectError(error.FileTooBig, a.truncate(&table, 1001, test_now));

    var small = Table.init(testing.allocator, testing.io, 1 << 20, 3 * 64 * 1024);
    defer small.deinit();
    const b = try small.attach("b");
    b.times = test_times;
    b.loaded = true;
    try b.write(&small, 0, "one", test_now);
    const c = try small.attach("c");
    c.times = test_times;
    c.loaded = true;
    try testing.expectError(error.NoSpaceLeft, c.write(&small, 0, "two", test_now));
    try testing.expectEqualStrings("one", b.plaintext);
    try testing.expectEqual(0, c.len());
    small.release(c);
    small.release(b);
}

test "a refused growth keeps the data and a usable ciphertext buffer" {
    if (builtin.mode != .debug) return error.SkipZigTest;
    var table = Table.init(testing.allocator, testing.io, 1 << 24, 1 << 26);
    defer table.deinit();
    const node = try table.attach("f");
    node.times = test_times;
    node.loaded = true;
    try node.write(&table, 0, "start", test_now);
    const first = node.ciphertext.ptr;
    const bigger: [70 * 1024]u8 = @splat('y');

    faults.arm(&.{.ciphertext_alloc});
    try testing.expectError(error.NoSpaceLeft, node.write(&table, 0, &bigger, test_now));
    try testing.expectEqualStrings("start", node.plaintext);
    try testing.expectEqual(first, node.ciphertext.ptr);
    try testing.expectEqual(64 * 1024 + overhead, node.ciphertext.len);
    try testing.expectEqual(2 * 64 * 1024 + overhead, table.budget.used());

    faults.arm(&.{.plaintext_realloc});
    try testing.expectError(error.NoSpaceLeft, node.write(&table, 0, &bigger, test_now));
    try testing.expectEqualStrings("start", node.plaintext);
    try testing.expectEqual(64 * 1024, node.plaintext_capacity);
    try testing.expectEqual(128 * 1024 + overhead, node.ciphertext.len);
    try testing.expectEqual(64 * 1024 + 128 * 1024 + overhead, table.budget.used());

    faults.arm(&.{});
    try node.write(&table, 0, &bigger, test_now);
    try testing.expectEqual(128 * 1024, node.plaintext_capacity);
    try testing.expectEqual(2 * 128 * 1024 + overhead, table.budget.used());
    node.dirty = false;
    table.release(node);
}

test "a growth of a dirty node peaks at three buffers" {
    // Allow room for the old plaintext and both replacement buffers.
    const budget = 64 * 1024 + 2 * 128 * 1024 + overhead;
    var table = Table.init(testing.allocator, testing.io, 1 << 20, budget);
    defer table.deinit();
    const node = try table.attach("f");
    node.times = test_times;
    node.loaded = true;
    try node.write(&table, 0, "start", test_now);
    try testing.expectEqual(2 * 64 * 1024 + overhead, table.budget.used());
    const bigger: [70 * 1024]u8 = @splat('y');
    try node.write(&table, 0, &bigger, test_now);
    try testing.expectEqual(2 * 128 * 1024 + overhead, table.budget.used());
    node.dirty = false;
    table.release(node);
}

test "the peak of a growth from an exact-size load is three buffers" {
    const gpa = testing.allocator;
    const io = testing.io;
    const keys = crypto.deriveKeys(@splat(11), null);
    try Io.Dir.createDirPath(.cwd(), io, "tmp/node_peak");
    defer Io.Dir.deleteTree(.cwd(), io, "tmp/node_peak") catch {};
    const plain: [100 * 1024]u8 = @splat('p');
    const encrypted = try crypto.encrypt(gpa, io, &plain, keys);
    defer gpa.free(encrypted);
    try Io.Dir.writeFile(.cwd(), io, .{ .sub_path = "tmp/node_peak/f", .data = encrypted });

    const limit = 200 * 1024;
    var table = Table.init(gpa, io, limit, 3 * limit + (1 << 20));
    defer table.deinit();
    const node = try table.attach("f");
    node.times = test_times;
    const file = try Io.Dir.openFile(.cwd(), io, "tmp/node_peak/f", .{});
    defer file.close(io);
    try node.load(io, &table, file, encrypted.len, keys);
    try testing.expectEqual(plain.len, node.plaintext_capacity);
    try testing.expectEqualSlices(u8, &plain, node.plaintext);

    // Replacing loaded bytes should not grow the plaintext allocation.
    try node.write(&table, 0, "q", test_now);
    try testing.expectEqual('q', node.plaintext[0]);
    try testing.expectEqual(plain.len, node.plaintext_capacity);
    try testing.expectEqual(2 * plain.len + overhead, table.budget.used());

    try node.write(&table, plain.len, "z", test_now);
    try testing.expectEqual(limit, node.plaintext_capacity);
    try testing.expectEqual(2 * limit + overhead, table.budget.used());
    node.dirty = false;
    table.release(node);

    // This budget is exactly enough for the high-water mark.
    var exact = Table.init(gpa, io, limit, plain.len + 2 * limit + overhead);
    defer exact.deinit();
    const fitting = try exact.attach("f");
    fitting.times = test_times;
    try fitting.load(io, &exact, file, encrypted.len, keys);
    try fitting.write(&exact, plain.len, "z", test_now);
    try testing.expectEqual(2 * limit + overhead, exact.budget.used());
    fitting.dirty = false;
    exact.release(fitting);

    // Steady-state capacity alone cannot pay for a growth's old plaintext.
    var tight = Table.init(gpa, io, limit, 2 * limit + overhead);
    defer tight.deinit();
    const other = try tight.attach("f");
    other.times = test_times;
    try other.load(io, &tight, file, encrypted.len, keys);
    try testing.expectError(error.NoSpaceLeft, other.write(&tight, plain.len, "z", test_now));
    try testing.expectEqualSlices(u8, &plain, other.plaintext);
    try testing.expectEqual(plain.len, other.plaintext_capacity);
    tight.release(other);
}

test "load rejects short files and wrong keys" {
    const gpa = testing.allocator;
    const io = testing.io;
    const keys = crypto.deriveKeys(@splat(12), null);
    try Io.Dir.createDirPath(.cwd(), io, "tmp/node_load");
    defer Io.Dir.deleteTree(.cwd(), io, "tmp/node_load") catch {};
    try Io.Dir.writeFile(.cwd(), io, .{ .sub_path = "tmp/node_load/short", .data = "too short" });
    const encrypted = try crypto.encrypt(gpa, io, "secret", keys);
    defer gpa.free(encrypted);
    try Io.Dir.writeFile(.cwd(), io, .{ .sub_path = "tmp/node_load/ok", .data = encrypted });

    var table = Table.init(gpa, io, 1 << 20, 1 << 24);
    defer table.deinit();
    const node = try table.attach("x");
    {
        const file = try Io.Dir.openFile(.cwd(), io, "tmp/node_load/short", .{});
        defer file.close(io);
        try testing.expectError(error.InvalidFileSize, node.load(io, &table, file, 9, keys));
    }
    {
        const file = try Io.Dir.openFile(.cwd(), io, "tmp/node_load/ok", .{});
        defer file.close(io);
        const wrong = crypto.deriveKeys(@splat(13), null);
        try testing.expectError(
            error.InvalidHeaderMac,
            node.load(io, &table, file, encrypted.len, wrong),
        );
        try testing.expectEqual(0, table.budget.used());
        try node.load(io, &table, file, encrypted.len, keys);
        try testing.expectEqualStrings("secret", node.plaintext);
    }
    table.release(node);
}

test "write-back publishes a decryptable file with the recorded attributes and marks the parent" {
    const gpa = testing.allocator;
    const io = testing.io;
    const keys = crypto.deriveKeys(@splat(14), null);
    Io.Dir.deleteTree(.cwd(), io, "tmp/node_flush") catch {};
    try Io.Dir.createDirPath(.cwd(), io, "tmp/node_flush");
    defer Io.Dir.deleteTree(.cwd(), io, "tmp/node_flush") catch {};
    var parent = try Io.Dir.openDir(.cwd(), io, "tmp/node_flush", .{ .iterate = true });
    defer parent.close(io);

    var table = Table.init(gpa, io, 1 << 20, 1 << 24);
    defer table.deinit();
    var marks: Marks = .{ .gpa = gpa, .io = io };
    defer marks.deinit();

    const node = try table.attach("out");
    node.times = test_times;
    node.loaded = true;
    try node.write(&table, 0, "payload", test_now);
    node.mode = 0o640;
    const fallback: Fallback = .{ .mode = 0o644, .uid = null, .gid = null };
    node.mutex.lockUncancelable(io);
    try node.writeBack(io, &table, parent, "out", fallback, keys, &marks, false);
    node.mutex.unlock(io);
    try testing.expect(!node.dirty);
    try testing.expectEqual(1, marks.count());

    const stored = try Io.Dir.readFileAlloc(.cwd(), io, "tmp/node_flush/out", gpa, .limited(1024));
    defer gpa.free(stored);
    const plain = try crypto.decrypt(gpa, stored, keys);
    defer gpa.free(plain);
    try testing.expectEqualStrings("payload", plain);

    var st: fuse.Stat = undefined;
    try testing.expect(fuse.statAt(parent.handle, "out", &st));
    try testing.expectEqual(0o640, st.mode & 0o777);
    try testing.expectEqual(test_now.sec, st.mtime().sec);

    var it = parent.iterate();
    var count: usize = 0;
    while (try it.next(io)) |_| count += 1;
    try testing.expectEqual(1, count);

    try node.write(&table, 7, "!", test_now);
    node.mutex.lockUncancelable(io);
    try node.writeBack(io, &table, parent, "out", fallback, keys, &marks, true);
    node.mutex.unlock(io);
    try testing.expectEqual(0, marks.count());
    const pending = try marks.pendingKeys(gpa);
    defer gpa.free(pending);
    try testing.expectEqual(0, pending.len);
    table.release(node);
}

test "a failed sync keeps the node dirty and the temporary file is gone" {
    if (builtin.mode != .debug) return error.SkipZigTest;
    const gpa = testing.allocator;
    const io = testing.io;
    const keys = crypto.deriveKeys(@splat(15), null);
    Io.Dir.deleteTree(.cwd(), io, "tmp/node_fault") catch {};
    try Io.Dir.createDirPath(.cwd(), io, "tmp/node_fault");
    defer Io.Dir.deleteTree(.cwd(), io, "tmp/node_fault") catch {};
    var parent = try Io.Dir.openDir(.cwd(), io, "tmp/node_fault", .{ .iterate = true });
    defer parent.close(io);

    var table = Table.init(gpa, io, 1 << 20, 1 << 24);
    defer table.deinit();
    var marks: Marks = .{ .gpa = gpa, .io = io };
    defer marks.deinit();
    const node = try table.attach("f");
    node.times = test_times;
    node.loaded = true;
    try node.write(&table, 0, "data", test_now);
    const fallback: Fallback = .{ .mode = 0o600, .uid = null, .gid = null };

    faults.arm(&.{.file_sync});
    node.mutex.lockUncancelable(io);
    try testing.expectError(
        error.InputOutput,
        node.writeBack(io, &table, parent, "f", fallback, keys, &marks, false),
    );
    node.mutex.unlock(io);
    try testing.expect(node.dirty);
    try testing.expectEqual(0, marks.count());
    var it = parent.iterate();
    try testing.expectEqual(null, try it.next(io));

    // Keep failed data after the last close so another flush can retry.
    table.release(node);
    try testing.expectEqual(1, table.nodes.items.len);
    const again = try table.attach("f");
    try testing.expectEqual(node, again);
    try testing.expectEqualStrings("data", again.plaintext);

    // The file can be published even if its directory still needs syncing.
    faults.arm(&.{.dir_sync});
    again.mutex.lockUncancelable(io);
    try testing.expectError(
        error.InputOutput,
        again.writeBack(io, &table, parent, "f", fallback, keys, &marks, true),
    );
    again.mutex.unlock(io);
    try testing.expect(!again.dirty);
    try testing.expectEqual(1, marks.count());
    _ = try parent.statFile(io, "f", .{});
    faults.arm(&.{});
    table.release(again);
    try testing.expectEqual(0, table.nodes.items.len);
}

test "renames re-key a file or a whole subtree and displace the destination node" {
    var table = Table.init(testing.allocator, testing.io, 1 << 20, 1 << 24);
    defer table.deinit();
    const file = try table.attach("d/one");
    const deep = try table.attach("d/sub/two");
    const outside = try table.attach("dx/three");
    const target = try table.attach("x/one");

    var rekey = try table.beginRekey("d", "e", true);
    try testing.expectEqual(2, rekey.nodes.items.len);
    try testing.expectEqual(null, rekey.target);
    rekey.commit();
    try testing.expectEqualStrings("e/one", file.path);
    try testing.expectEqualStrings("e/sub/two", deep.path);
    try testing.expectEqualStrings("dx/three", outside.path);

    var onto = try table.beginRekey("e/sub/two", "x/one", false);
    try testing.expectEqual(1, onto.nodes.items.len);
    try testing.expectEqual(target, onto.target.?);
    onto.commit();
    try testing.expect(target.unlinked.load(.acquire));
    try testing.expectEqualStrings("x/one", deep.path);
    try testing.expectEqual(deep, table.pin("x/one").?);
    table.release(deep);

    var aborted = try table.beginRekey("x/one", "x/four", false);
    aborted.abort();
    try testing.expectEqualStrings("x/one", deep.path);

    var same = try table.beginRekey("x/one", "x/one", false);
    try testing.expectEqual(0, same.nodes.items.len);
    try testing.expectEqual(null, same.target);
    same.commit();
    try testing.expect(!deep.unlinked.load(.acquire));

    table.release(file);
    table.release(deep);
    table.release(outside);
    table.release(target);
    try testing.expectEqual(0, table.nodes.items.len);
}

test "unlink drops a retained node or keeps an unlinked one alive under a pin" {
    var table = Table.init(testing.allocator, testing.io, 1 << 20, 1 << 24);
    defer table.deinit();
    const node = try table.attach("f");
    node.times = test_times;
    node.loaded = true;
    try node.write(&table, 0, "x", test_now);
    table.release(node);
    try testing.expectEqual(1, table.nodes.items.len);

    const pinned = try table.pinAll(testing.allocator);
    defer testing.allocator.free(pinned);
    try testing.expectEqual(1, pinned.len);
    // A deletion cannot free data that another pin still uses.
    const unlinked = table.pin("f").?;
    unlinked.unlinked.store(true, .release);
    table.release(unlinked);
    try testing.expectEqual(1, table.nodes.items.len);
    try testing.expectEqual(null, table.pin("f"));
    for (pinned) |p| table.release(p);
    try testing.expectEqual(0, table.nodes.items.len);
    try testing.expectEqual(0, table.budget.used());

    const retained = try table.attach("g");
    retained.times = test_times;
    retained.loaded = true;
    try retained.write(&table, 0, "y", test_now);
    table.release(retained);
    const gone = table.pin("g").?;
    gone.unlinked.store(true, .release);
    table.release(gone);
    try testing.expectEqual(0, table.nodes.items.len);

    // Replacing a retained target must free its buffers.
    const displaced = try table.attach("h");
    displaced.times = test_times;
    displaced.loaded = true;
    try displaced.write(&table, 0, "z", test_now);
    table.release(displaced);
    const source = try table.attach("i");
    var rekey = try table.beginRekey("i", "h", false);
    rekey.commit();
    try testing.expectEqual(1, table.nodes.items.len);
    try testing.expectEqualStrings("h", source.path);
    table.release(source);
    try testing.expectEqual(0, table.budget.used());
}

test "write and truncate update logical times" {
    var table = Table.init(testing.allocator, testing.io, 1 << 20, 1 << 24);
    defer table.deinit();
    const node = try table.attach("f");
    node.times = test_times;
    node.loaded = true;
    const later: std.c.timespec = .{ .sec = 1_800_000_000, .nsec = 0 };
    try node.write(&table, 0, "a", later);
    try testing.expectEqual(later.sec, node.times.?.mtime.sec);
    try testing.expectEqual(test_now.sec, node.times.?.atime.sec);
    const explicit: std.c.timespec = .{ .sec = 1_000, .nsec = 0 };
    node.times.?.mtime = explicit;
    try node.truncate(&table, 0, later);
    try testing.expectEqual(later.sec, node.times.?.mtime.sec);
    node.dirty = false;
    table.release(node);
}
