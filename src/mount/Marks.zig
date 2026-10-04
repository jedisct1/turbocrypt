//! Remembers directories that still need syncing after a change.
//!
//! Reserve bookkeeping before the change so low memory cannot leave it untracked.
//! Pins keep directory handles valid while a sync is running.
//! Generations keep an older sync from clearing a newer change.

const Marks = @This();

const std = @import("std");
const testing = std.testing;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const faults = @import("faults.zig");
const fuse = @import("fuse.zig");

mutex: Io.Mutex = .init,
map: std.AutoHashMapUnmanaged(Key, Mark) = .empty,
reserved: usize = 0,
generation: u64 = 0,
gpa: Allocator,
io: Io,

/// Use device and inode because a directory can be renamed.
pub const Key = struct {
    dev: u64,
    ino: u64,
};

pub fn keyOf(st: fuse.Stat) Key {
    return .{ .dev = toU64(st.dev), .ino = toU64(st.ino) };
}

fn toU64(x: anytype) u64 {
    return switch (@typeInfo(@TypeOf(x)).int.signedness) {
        .signed => @bitCast(@as(i64, x)),
        .unsigned => x,
    };
}

const Mark = struct {
    dir: Io.Dir,
    generation: u64,
    syncers: u32 = 0,
    clean: bool = false,
    dropped: bool = false,
};

pub const Pinned = struct {
    dir: Io.Dir,
    generation: u64,
};

/// Reserve the mark first so a failed mutation can cancel it automatically.
pub const Change = struct {
    marks: *Marks,
    key: Key,
    handle: Io.Dir,
    done: bool = false,

    pub fn commit(self: *Change) void {
        self.done = true;
        if (!self.marks.commit(self.key, self.handle)) self.handle.close(self.marks.io);
    }

    pub fn deinit(self: *Change) void {
        if (self.done) return;
        self.marks.cancel();
        self.handle.close(self.marks.io);
    }
};

pub fn begin(self: *Marks, dir: Io.Dir, key: Key) !Change {
    try self.reserve();
    errdefer self.cancel();
    // Request iteration so Linux does not return an O_PATH descriptor, which cannot be synced.
    const handle = try dir.openDir(self.io, ".", .{ .iterate = true });
    return .{ .marks = self, .key = key, .handle = handle };
}

pub fn deinit(self: *Marks) void {
    var it = self.map.valueIterator();
    while (it.next()) |mark| mark.dir.close(self.io);
    self.map.deinit(self.gpa);
}

pub fn reserve(self: *Marks) error{OutOfMemory}!void {
    self.mutex.lockUncancelable(self.io);
    defer self.mutex.unlock(self.io);
    try self.map.ensureUnusedCapacity(self.gpa, @intCast(self.reserved + 1));
    self.reserved += 1;
}

pub fn cancel(self: *Marks) void {
    self.mutex.lockUncancelable(self.io);
    defer self.mutex.unlock(self.io);
    self.reserved -= 1;
}

/// Consumes a reservation and reports whether the mark now owns `dir`.
pub fn commit(self: *Marks, key: Key, dir: Io.Dir) bool {
    self.mutex.lockUncancelable(self.io);
    defer self.mutex.unlock(self.io);
    self.reserved -= 1;
    self.generation += 1;
    if (self.map.getPtr(key)) |mark| {
        mark.generation = self.generation;
        mark.clean = false;
        mark.dropped = false;
        return false;
    }
    self.map.putAssumeCapacity(key, .{ .dir = dir, .generation = self.generation });
    return true;
}

/// Keep the handle alive for a pending sync, or return null when none is needed.
pub fn pin(self: *Marks, key: Key) ?Pinned {
    self.mutex.lockUncancelable(self.io);
    defer self.mutex.unlock(self.io);
    const mark = self.map.getPtr(key) orelse return null;
    if (mark.dropped or mark.clean) return null;
    mark.syncers += 1;
    return .{ .dir = mark.dir, .generation = mark.generation };
}

pub fn unpin(self: *Marks, key: Key, generation: u64, synced: bool) void {
    self.mutex.lockUncancelable(self.io);
    const done = blk: {
        const mark = self.map.getPtr(key) orelse break :blk null;
        mark.syncers -= 1;
        if (synced and mark.generation == generation) mark.clean = true;
        break :blk self.takeIfDone(key, mark);
    };
    self.mutex.unlock(self.io);
    if (done) |dir| dir.close(self.io);
}

/// Keep a removed directory marked until active syncs let go.
pub fn drop(self: *Marks, key: Key) void {
    self.mutex.lockUncancelable(self.io);
    const done = blk: {
        const mark = self.map.getPtr(key) orelse break :blk null;
        mark.dropped = true;
        break :blk self.takeIfDone(key, mark);
    };
    self.mutex.unlock(self.io);
    if (done) |dir| dir.close(self.io);
}

/// Return the handle for the caller to close after releasing the lock.
fn takeIfDone(self: *Marks, key: Key, mark: *Mark) ?Io.Dir {
    if (mark.syncers != 0 or !(mark.clean or mark.dropped)) return null;
    const dir = mark.dir;
    _ = self.map.remove(key);
    return dir;
}

/// The caller frees the returned list.
pub fn pendingKeys(self: *Marks, gpa: Allocator) ![]Key {
    self.mutex.lockUncancelable(self.io);
    defer self.mutex.unlock(self.io);
    var list: std.ArrayList(Key) = .empty;
    errdefer list.deinit(gpa);
    var it = self.map.iterator();
    while (it.next()) |entry| {
        const mark = entry.value_ptr;
        if (!mark.clean and !mark.dropped) try list.append(gpa, entry.key_ptr.*);
    }
    return list.toOwnedSlice(gpa);
}

pub fn count(self: *Marks) usize {
    self.mutex.lockUncancelable(self.io);
    defer self.mutex.unlock(self.io);
    return self.map.count();
}

/// Clear the mark only when this sync did not race with another change.
pub fn sync(self: *Marks, key: Key) !void {
    const pinned = self.pin(key) orelse return;
    const result = faults.syncFd(pinned.dir.handle, .dir_sync);
    self.unpin(key, pinned.generation, if (result) true else |_| false);
    return result;
}

test "marks survive a rename of the directory and a sync clears only its own generation" {
    const gpa = testing.allocator;
    const io = testing.io;
    Io.Dir.deleteTree(.cwd(), io, "tmp/node_marks") catch {};
    try Io.Dir.createDirPath(.cwd(), io, "tmp/node_marks/a");
    defer Io.Dir.deleteTree(.cwd(), io, "tmp/node_marks") catch {};
    var marks: Marks = .{ .gpa = gpa, .io = io };
    defer marks.deinit();

    // Request iteration because Linux cannot sync an O_PATH descriptor.
    var dir = try Io.Dir.openDir(.cwd(), io, "tmp/node_marks/a", .{ .iterate = true });
    const key = Marks.keyOf(try fuse.statFd(dir.handle));

    try marks.reserve();
    try testing.expect(marks.commit(key, dir));
    try Io.Dir.rename(.cwd(), "tmp/node_marks/a", .cwd(), "tmp/node_marks/b", io);
    try testing.expectEqual(1, marks.count());

    var other = try Io.Dir.openDir(.cwd(), io, "tmp/node_marks/b", .{});
    try marks.reserve();
    try testing.expect(!marks.commit(key, other));
    other.close(io);

    // A sync that started earlier cannot clear a later change.
    const pinned = marks.pin(key).?;
    try marks.reserve();
    try testing.expect(!marks.commit(key, other));
    marks.unpin(key, pinned.generation, true);
    try testing.expectEqual(1, marks.count());

    try marks.sync(key);
    try testing.expectEqual(0, marks.count());

    // Do not close a removed directory's handle until its sync finishes.
    dir = try Io.Dir.openDir(.cwd(), io, "tmp/node_marks/b", .{ .iterate = true });
    try marks.reserve();
    try testing.expect(marks.commit(key, dir));
    const held = marks.pin(key).?;
    marks.drop(key);
    try testing.expectEqual(1, marks.count());
    marks.unpin(key, held.generation, false);
    try testing.expectEqual(0, marks.count());

    try marks.reserve();
    marks.cancel();
    try testing.expectEqual(0, marks.reserved);
}
