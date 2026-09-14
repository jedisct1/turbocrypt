//! Shared plaintext buffers and durable write-back for whole-file encryption.
//!
//! Whole-file encryption requires buffering plaintext for reads and writes.

const std = @import("std");
const builtin = @import("builtin");
const crypto = @import("../crypto.zig");
const processor = @import("../processor.zig");
const fuse = @import("fuse.zig");

pub const Error = error{
    OutOfMemory,
    FileTooBig,
    NoSpaceLeft,
};

pub const overhead = crypto.overhead_size;

const growth_start: usize = 64 * 1024;
const growth_step: usize = 64 * 1024 * 1024;
const map_threshold: u64 = 1024 * 1024;

/// Amortize small writes while limiting spare capacity for large files.
pub fn grownCapacity(current: usize, needed: usize, limit: usize) usize {
    std.debug.assert(needed <= limit);
    var capacity = @max(current, growth_start);
    while (capacity < needed) {
        capacity = if (capacity < growth_step) capacity * 2 else capacity + growth_step;
    }
    return @min(capacity, limit);
}

/// Inject failures to exercise recovery in Debug builds.
pub const Fault = enum {
    ciphertext_alloc,
    plaintext_realloc,
    file_sync,
    dir_sync,
    /// Sync of a clean file after metadata changes.
    metadata_sync,
    create_write,
};

pub const max_faults = 8;

var faults: [max_faults]?Fault = @splat(null);
var faults_next = std.atomic.Value(usize).init(0);

/// Faults fire once each, in order; arm them before callbacks start.
pub fn armFaults(list: []const Fault) void {
    faults = @splat(null);
    for (list, 0..) |fault, i| {
        if (i < faults.len) faults[i] = fault;
    }
    faults_next.store(0, .seq_cst);
}

/// Keep macOS sidecars from consuming faults intended for the file under test.
pub threadlocal var faults_suppressed: bool = false;

pub fn takeFault(kind: Fault) bool {
    if (builtin.mode != .debug or faults_suppressed) return false;
    const index = faults_next.load(.seq_cst);
    if (index >= faults.len or faults[index] != kind) return false;
    return faults_next.cmpxchgStrong(index, index + 1, .seq_cst, .seq_cst) == null;
}

/// Enforce a shared memory limit across open files.
pub const Budget = struct {
    limit: usize,
    charged: std.atomic.Value(usize) = .init(0),

    pub fn charge(self: *Budget, amount: usize) bool {
        var current = self.charged.load(.monotonic);
        while (true) {
            const next = std.math.add(usize, current, amount) catch return false;
            if (next > self.limit) return false;
            current = self.charged.cmpxchgWeak(current, next, .monotonic, .monotonic) orelse return true;
        }
    }

    pub fn release(self: *Budget, amount: usize) void {
        _ = self.charged.fetchSub(amount, .monotonic);
    }

    pub fn used(self: *Budget) usize {
        return self.charged.load(.monotonic);
    }
};

pub const Times = struct {
    atime: std.c.timespec,
    mtime: std.c.timespec,
    ctime: std.c.timespec,
};

/// Handles on the same path share a node; dirty nodes survive their last close until write-back succeeds.
///
/// The table mutex protects `path` and `refs`; the node mutex protects everything else.
/// Set `unlinked` under the node lock to prevent write-back after deletion.
pub const Node = struct {
    mutex: std.Io.Mutex = .init,
    /// Relative to the backing root.
    path: []u8,
    /// Open handles plus pins.
    refs: usize = 1,
    /// Suppress write-back after deletion; atomic because the table reads it under a different lock.
    unlinked: std.atomic.Value(bool) = .init(false),
    loaded: bool = false,
    dirty: bool = false,
    /// Slice length is the file size; the allocation extends to plaintext_capacity.
    plaintext: []u8 = &.{},
    plaintext_capacity: usize = 0,
    /// Reserved before writes so encryption needs no allocation during recovery.
    ciphertext: []u8 = &.{},
    /// Preserve metadata changes when write-back replaces the backing inode.
    mode: ?std.c.mode_t = null,
    uid: ?std.c.uid_t = null,
    gid: ?std.c.gid_t = null,
    /// Logical file times, independent of when ciphertext is written.
    times: ?Times = null,

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

    pub fn load(node: *Node, table: *Table, file: std.Io.File, size: u64, keys: crypto.DerivedKeys, io: std.Io) !void {
        std.debug.assert(!node.loaded);
        if (size < overhead) return error.InvalidFileSize;
        if (size - overhead > table.max_file_size) return error.FileTooBig;
        const plain_len: usize = @intCast(size - overhead);
        if (!table.budget.charge(plain_len)) return error.OutOfMemory;
        errdefer table.budget.release(plain_len);
        const plaintext = try table.allocator.alloc(u8, plain_len);
        errdefer table.allocator.free(plaintext);
        try decryptInto(plaintext, table, file, size, keys, io);
        node.plaintext = plaintext;
        node.plaintext_capacity = plain_len;
        node.loaded = true;
    }

    fn decryptInto(output: []u8, table: *Table, file: std.Io.File, size: u64, keys: crypto.DerivedKeys, io: std.Io) !void {
        if (size >= map_threshold and builtin.os.tag != .windows) {
            var mapped = std.Io.File.MemoryMap.create(io, file, .{
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
        const encrypted = try table.allocator.alloc(u8, encrypted_len);
        defer table.allocator.free(encrypted);
        const read = try file.readPositionalAll(io, encrypted, 0);
        if (read != encrypted_len) return error.InvalidFileSize;
        return crypto.decryptZeroCopy(output, encrypted, keys);
    }

    fn ensureCiphertext(node: *Node, table: *Table) Error!void {
        if (node.ciphertext.len != 0) return;
        const capacity = node.plaintext_capacity + overhead;
        if (!table.budget.charge(capacity)) return error.NoSpaceLeft;
        errdefer table.budget.release(capacity);
        node.ciphertext = table.allocator.alloc(u8, capacity) catch return error.NoSpaceLeft;
    }

    /// Keep the existing data and enough ciphertext capacity for recovery if any allocation fails.
    fn grow(node: *Node, table: *Table, needed: usize) Error!void {
        if (needed > table.max_file_size) return error.FileTooBig;
        const old_capacity = node.plaintext_capacity;
        if (needed <= old_capacity) return node.ensureCiphertext(table);

        const new_capacity = grownCapacity(old_capacity, needed, table.max_file_size);
        const new_ciphertext_capacity = new_capacity + overhead;
        // Release the old ciphertext before growing plaintext to keep peak memory within three buffers.
        const reused = @min(node.ciphertext.len, new_capacity);
        const extra = new_ciphertext_capacity + new_capacity - reused;
        if (!table.budget.charge(extra)) return error.NoSpaceLeft;

        const new_ciphertext = allocMaybeFaulty(table.allocator, new_ciphertext_capacity, .ciphertext_alloc) catch {
            table.budget.release(extra);
            return error.NoSpaceLeft;
        };
        if (node.ciphertext.len != 0) {
            table.allocator.free(node.ciphertext);
            table.budget.release(node.ciphertext.len - reused);
        }
        node.ciphertext = new_ciphertext;

        const new_plaintext = reallocMaybeFaulty(table.allocator, node.plaintext.ptr[0..old_capacity], new_capacity) catch {
            table.budget.release(new_capacity);
            return error.NoSpaceLeft;
        };
        node.plaintext = new_plaintext[0..node.plaintext.len];
        node.plaintext_capacity = new_capacity;
        table.budget.release(old_capacity);
    }

    fn allocMaybeFaulty(allocator: std.mem.Allocator, n: usize, fault: Fault) ![]u8 {
        if (takeFault(fault)) return error.OutOfMemory;
        return allocator.alloc(u8, n);
    }

    fn reallocMaybeFaulty(allocator: std.mem.Allocator, old: []u8, n: usize) ![]u8 {
        if (takeFault(.plaintext_realloc)) return error.OutOfMemory;
        if (old.len == 0) return allocator.alloc(u8, n);
        return allocator.realloc(old, n);
    }

    /// Reclaim memory after truncation; a failed shrink leaves the buffers charged to the budget.
    fn shrink(node: *Node, table: *Table, new_len: usize) void {
        const old_capacity = node.plaintext_capacity;
        const target = if (new_len == 0) 0 else @min(old_capacity, grownCapacity(0, new_len, table.max_file_size));
        if (target >= old_capacity) return;

        if (target == 0) {
            table.allocator.free(node.plaintext.ptr[0..old_capacity]);
            node.plaintext = &.{};
        } else {
            const moved = table.allocator.realloc(node.plaintext.ptr[0..old_capacity], target) catch return;
            node.plaintext = moved[0..new_len];
        }
        node.plaintext_capacity = target;
        table.budget.release(old_capacity - target);

        if (node.ciphertext.len != 0) {
            const old_ciphertext = node.ciphertext.len;
            const moved = table.allocator.realloc(node.ciphertext, target + overhead) catch return;
            node.ciphertext = moved;
            table.budget.release(old_ciphertext - moved.len);
        }
    }

    /// Zero-fill gaps so writes past EOF cannot expose old buffer contents.
    pub fn write(node: *Node, table: *Table, offset: u64, data: []const u8, now: std.c.timespec) Error!void {
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

    /// Truncating to zero needs no decryption; other sizes require a loaded node.
    pub fn truncate(node: *Node, table: *Table, new_len: u64, now: std.c.timespec) Error!void {
        if (new_len > table.max_file_size) return error.FileTooBig;
        std.debug.assert(node.loaded or new_len == 0);
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

    fn freeBuffers(node: *Node, table: *Table) void {
        if (node.plaintext_capacity != 0) {
            table.allocator.free(node.plaintext.ptr[0..node.plaintext_capacity]);
            table.budget.release(node.plaintext_capacity);
        }
        if (node.ciphertext.len != 0) {
            table.allocator.free(node.ciphertext);
            table.budget.release(node.ciphertext.len);
        }
        node.plaintext = &.{};
        node.plaintext_capacity = 0;
        node.ciphertext = &.{};
        node.loaded = false;
    }
};

/// Backing-file metadata to preserve when the node has no recorded override.
pub const Fallback = struct {
    mode: std.c.mode_t,
    uid: ?std.c.uid_t,
    gid: ?std.c.gid_t,
};

/// Atomically replace the ciphertext while preserving logical metadata.
///
/// The caller must hold the node lock and ensure the node is dirty and linked.
/// Failure before publication leaves it dirty for retry; `durable` also syncs the parent directory.
pub fn writeBack(
    node: *Node,
    table: *Table,
    parent: std.Io.Dir,
    name: []const u8,
    fallback: Fallback,
    keys: crypto.DerivedKeys,
    marks: *Marks,
    durable: bool,
    io: std.Io,
) !void {
    std.debug.assert(node.loaded and node.ciphertext.len >= node.plaintext.len + overhead);
    crypto.encryptZeroCopy(node.ciphertextSlice(), node.plaintext, keys, io);

    var change = try marks.begin(parent, markKey(try fuse.statFd(parent.handle)));
    defer change.deinit();

    var atomic = try processor.AtomicOutput.createIn(parent, .{ .permissions = .fromMode(0o600) }, table.allocator, io);
    defer atomic.deinit(io);
    try atomic.file.writeStreamingAll(io, node.ciphertextSlice());

    const fd = atomic.file.handle;
    if (std.c.fchmod(fd, node.mode orelse fallback.mode) != 0) return error.AccessDenied;
    // Avoid chown when creation already preserved ownership, especially for inherited groups.
    const current = try fuse.statFd(fd);
    const uid = node.uid orelse fallback.uid orelse current.uid;
    const gid = node.gid orelse fallback.gid orelse current.gid;
    if (uid != current.uid or gid != current.gid) {
        if (std.c.fchown(fd, uid, gid) != 0) return error.PermissionDenied;
    }
    const times = node.times.?;
    const spec = [2]std.c.timespec{ times.atime, times.mtime };
    if (std.c.futimens(fd, &spec) != 0) return error.AccessDenied;
    try syncFd(fd, .file_sync);

    try atomic.finalizeInto(parent, name, io);
    node.dirty = false;
    change.commit();

    if (durable) try syncMark(marks, change.key);
}

/// Clear a directory's pending sync only if no newer change arrived.
pub fn syncMark(marks: *Marks, key: MarkKey) !void {
    const pinned = marks.pin(key) orelse return;
    const result = syncFd(pinned.dir.handle, .dir_sync);
    marks.unpin(key, pinned.generation, if (result) true else |_| false);
    return result;
}

/// Ensure changes reach the drive; macOS requires FULLFSYNC beyond File.sync.
pub fn syncFd(fd: std.c.fd_t, fault: Fault) !void {
    if (takeFault(fault)) return error.InputOutput;
    if (std.c.fsync(fd) != 0) return error.InputOutput;
    if (builtin.os.tag == .macos) {
        // APFS and HFS+ support full sync on directories too; do not ignore failures.
        if (std.c.fcntl(fd, std.c.F.FULLFSYNC, @as(c_int, 0)) != 0) return error.InputOutput;
    }
}

/// Directory identity remains valid across renames.
pub const MarkKey = struct {
    dev: u64,
    ino: u64,
};

pub fn markKey(st: fuse.Stat) MarkKey {
    return .{ .dev = toU64(st.dev), .ino = toU64(st.ino) };
}

fn toU64(x: anytype) u64 {
    return switch (@typeInfo(@TypeOf(x)).int.signedness) {
        .signed => @bitCast(@as(i64, x)),
        .unsigned => @intCast(x),
    };
}

const Mark = struct {
    dir: std.Io.Dir,
    generation: u64,
    syncers: u32 = 0,
    clean: bool = false,
    dropped: bool = false,
};

/// Track directory changes until a successful sync covers them.
///
/// Reserve before mutation so recording a change cannot fail for lack of memory.
/// Pins keep descriptors alive during sync, and generations prevent a sync from clearing newer changes.
pub const Marks = struct {
    mutex: std.Io.Mutex = .init,
    map: std.AutoHashMapUnmanaged(MarkKey, Mark) = .empty,
    reserved: usize = 0,
    generation: u64 = 0,
    allocator: std.mem.Allocator,
    io: std.Io,

    pub const Pinned = struct {
        dir: std.Io.Dir,
        generation: u64,
    };

    /// Reserve tracking before a mutation and cancel automatically if it fails.
    pub const Change = struct {
        marks: *Marks,
        key: MarkKey,
        handle: std.Io.Dir,
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

    pub fn begin(self: *Marks, dir: std.Io.Dir, key: MarkKey) !Change {
        try self.reserve();
        errdefer self.cancel();
        // Iteration capability avoids Linux O_PATH descriptors, which cannot be synced.
        const handle = try dir.openDir(self.io, ".", .{ .iterate = true });
        return .{ .marks = self, .key = key, .handle = handle };
    }

    pub fn deinit(self: *Marks) void {
        var it = self.map.valueIterator();
        while (it.next()) |mark| mark.dir.close(self.io);
        self.map.deinit(self.allocator);
    }

    pub fn reserve(self: *Marks) error{OutOfMemory}!void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        try self.map.ensureUnusedCapacity(self.allocator, @intCast(self.reserved + 1));
        self.reserved += 1;
    }

    pub fn cancel(self: *Marks) void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        self.reserved -= 1;
    }

    /// Requires a reservation; returns true if the mark takes ownership of `dir`.
    pub fn commit(self: *Marks, key: MarkKey, dir: std.Io.Dir) bool {
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

    /// Keep the descriptor alive during sync; null if no sync is pending.
    pub fn pin(self: *Marks, key: MarkKey) ?Pinned {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        const mark = self.map.getPtr(key) orelse return null;
        if (mark.dropped or mark.clean) return null;
        mark.syncers += 1;
        return .{ .dir = mark.dir, .generation = mark.generation };
    }

    pub fn unpin(self: *Marks, key: MarkKey, generation: u64, synced: bool) void {
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

    /// Stop tracking a removed directory once outstanding syncs release it.
    pub fn drop(self: *Marks, key: MarkKey) void {
        self.mutex.lockUncancelable(self.io);
        const done = blk: {
            const mark = self.map.getPtr(key) orelse break :blk null;
            mark.dropped = true;
            break :blk self.takeIfDone(key, mark);
        };
        self.mutex.unlock(self.io);
        if (done) |dir| dir.close(self.io);
    }

    /// The caller closes the returned handle outside the lock.
    fn takeIfDone(self: *Marks, key: MarkKey, mark: *Mark) ?std.Io.Dir {
        if (mark.syncers != 0 or !(mark.clean or mark.dropped)) return null;
        const dir = mark.dir;
        _ = self.map.remove(key);
        return dir;
    }

    /// The caller frees the returned list.
    pub fn pendingKeys(self: *Marks, allocator: std.mem.Allocator) ![]MarkKey {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        var list: std.ArrayList(MarkKey) = .empty;
        errdefer list.deinit(allocator);
        var it = self.map.iterator();
        while (it.next()) |entry| {
            if (!entry.value_ptr.clean and !entry.value_ptr.dropped) try list.append(allocator, entry.key_ptr.*);
        }
        return list.toOwnedSlice(allocator);
    }

    pub fn count(self: *Marks) usize {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        return self.map.count();
    }
};

/// Keep node paths and write-back consistent with a backing rename until commit or abort.
pub const Rekey = struct {
    table: *Table,
    nodes: std.ArrayList(*Node) = .empty,
    paths: std.ArrayList([]u8) = .empty,
    /// Open or retained destination displaced by the rename.
    target: ?*Node = null,

    /// Call only after the backing rename succeeds.
    pub fn commit(self: *Rekey) void {
        const allocator = self.table.allocator;
        for (self.nodes.items, self.paths.items) |node, path| {
            allocator.free(node.path);
            node.path = path;
        }
        if (self.target) |target| {
            target.unlinked.store(true, .release);
            // No open handle remains to release this displaced node.
            if (target.refs == 0) {
                target.mutex.unlock(self.table.io);
                self.table.removeLocked(target);
                self.table.destroyNode(target);
                self.target = null;
            }
        }
        self.finish();
    }

    pub fn abort(self: *Rekey) void {
        for (self.paths.items) |path| self.table.allocator.free(path);
        self.finish();
    }

    fn finish(self: *Rekey) void {
        for (self.nodes.items) |node| node.mutex.unlock(self.table.io);
        if (self.target) |target| target.mutex.unlock(self.table.io);
        self.nodes.deinit(self.table.allocator);
        self.paths.deinit(self.table.allocator);
        self.table.mutex.unlock(self.table.io);
    }
};

pub const Table = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    mutex: std.Io.Mutex = .init,
    nodes: std.ArrayList(*Node) = .empty,
    budget: Budget,
    max_file_size: usize,

    pub fn init(allocator: std.mem.Allocator, io: std.Io, max_file_size: usize, memory_limit: usize) Table {
        return .{
            .allocator = allocator,
            .io = io,
            .budget = .{ .limit = memory_limit },
            .max_file_size = max_file_size,
        };
    }

    /// Call after the final write-back, with no callbacks running.
    pub fn deinit(self: *Table) void {
        for (self.nodes.items) |node| self.destroyNode(node);
        self.nodes.deinit(self.allocator);
    }

    /// Share the linked node for this path, or create one; the caller owns a reference.
    pub fn attach(self: *Table, path: []const u8) error{OutOfMemory}!*Node {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        if (self.findLocked(path)) |node| {
            node.refs += 1;
            return node;
        }
        const node = try self.allocator.create(Node);
        errdefer self.allocator.destroy(node);
        node.* = .{ .path = try self.allocator.dupe(u8, path) };
        errdefer self.allocator.free(node.path);
        try self.nodes.append(self.allocator, node);
        return node;
    }

    /// Acquire a reference without creating a node.
    pub fn pin(self: *Table, path: []const u8) ?*Node {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        const node = self.findLocked(path) orelse return null;
        node.refs += 1;
        return node;
    }

    /// Keep nodes alive during enumeration; the caller releases each reference and frees the list.
    pub fn pinAll(self: *Table, allocator: std.mem.Allocator) error{OutOfMemory}![]*Node {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        const list = try allocator.dupe(*Node, self.nodes.items);
        for (list) |node| node.refs += 1;
        return list;
    }

    /// Release a reference, retaining unsaved linked nodes for retry.
    pub fn release(self: *Table, node: *Node) void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        node.refs -= 1;
        if (node.refs != 0) return;
        node.mutex.lockUncancelable(self.io);
        const retain = node.dirty and !node.unlinked.load(.acquire);
        node.mutex.unlock(self.io);
        if (retain) return;
        self.removeLocked(node);
        self.destroyNode(node);
    }

    /// Reserve paths before the backing rename so committing it cannot fail for lack of memory.
    /// Hold the table and affected node locks until commit or abort.
    ///
    /// Lock the destination too, so its pending write-back cannot overwrite the renamed source.
    pub fn beginRekey(self: *Table, old: []const u8, new: []const u8, is_directory: bool) error{OutOfMemory}!Rekey {
        self.mutex.lockUncancelable(self.io);
        errdefer self.mutex.unlock(self.io);
        var rekey: Rekey = .{ .table = self };
        if (std.mem.eql(u8, old, new)) return rekey;
        errdefer {
            for (rekey.paths.items) |path| self.allocator.free(path);
            rekey.paths.deinit(self.allocator);
            rekey.nodes.deinit(self.allocator);
        }
        for (self.nodes.items) |node| {
            if (node.unlinked.load(.acquire)) continue;
            if (pathSuffix(node.path, old, is_directory)) |rest| {
                try rekey.nodes.append(self.allocator, node);
                const path = try std.mem.concat(self.allocator, u8, &.{ new, rest });
                errdefer self.allocator.free(path);
                try rekey.paths.append(self.allocator, path);
            } else if (!is_directory and std.mem.eql(u8, node.path, new)) {
                rekey.target = node;
            }
        }
        for (rekey.nodes.items) |node| node.mutex.lockUncancelable(self.io);
        if (rekey.target) |target| target.mutex.lockUncancelable(self.io);
        return rekey;
    }

    fn findLocked(self: *Table, path: []const u8) ?*Node {
        for (self.nodes.items) |node| {
            if (!node.unlinked.load(.acquire) and std.mem.eql(u8, node.path, path)) return node;
        }
        return null;
    }

    fn removeLocked(self: *Table, node: *Node) void {
        const index = std.mem.indexOfScalar(*Node, self.nodes.items, node).?;
        _ = self.nodes.swapRemove(index);
    }

    fn destroyNode(self: *Table, node: *Node) void {
        node.freeBuffers(self);
        self.allocator.free(node.path);
        self.allocator.destroy(node);
    }
};

/// Match whole components so a directory rename cannot affect similarly prefixed siblings.
fn pathSuffix(path: []const u8, prefix: []const u8, is_directory: bool) ?[]const u8 {
    if (std.mem.eql(u8, path, prefix)) return "";
    if (!is_directory) return null;
    if (path.len > prefix.len and std.mem.startsWith(u8, path, prefix) and path[prefix.len] == '/') return path[prefix.len..];
    return null;
}

const testing = std.testing;

const test_now: std.c.timespec = .{ .sec = 1_700_000_000, .nsec = 5 };
const test_times: Times = .{ .atime = test_now, .mtime = test_now, .ctime = test_now };

test "write at an offset zero-fills the gap and truncate goes both ways" {
    var table = Table.init(testing.allocator, testing.io, 1 << 20, 16 << 20);
    defer table.deinit();
    const node = try table.attach("f");
    node.times = test_times;
    node.loaded = true;

    try node.write(&table, 4, "abc", test_now);
    try testing.expectEqualSlices(u8, &[_]u8{ 0, 0, 0, 0, 'a', 'b', 'c' }, node.plaintext);
    try testing.expect(node.dirty);
    try testing.expectEqual(@as(usize, 64 * 1024), node.plaintext_capacity);
    try testing.expectEqual(@as(usize, 64 * 1024 + overhead), node.ciphertext.len);
    try testing.expectEqual(@as(usize, 2 * 64 * 1024 + overhead), table.budget.used());

    try node.truncate(&table, 10, test_now);
    try testing.expectEqual(@as(usize, 10), node.len());
    try testing.expectEqual(@as(u8, 0), node.plaintext[9]);

    try node.truncate(&table, 2, test_now);
    try testing.expectEqualSlices(u8, &[_]u8{ 0, 0 }, node.plaintext);

    try node.truncate(&table, 0, test_now);
    try testing.expectEqual(@as(usize, 0), node.plaintext_capacity);
    try testing.expectEqual(@as(usize, overhead), node.ciphertext.len);
    try testing.expectEqual(@as(usize, overhead), table.budget.used());

    const big: [200 * 1024]u8 = @splat('x');
    try node.write(&table, 0, &big, test_now);
    try testing.expectEqual(@as(usize, 256 * 1024), node.plaintext_capacity);
    try node.truncate(&table, 100, test_now);
    try testing.expectEqual(@as(usize, 64 * 1024), node.plaintext_capacity);
    try testing.expectEqual(@as(usize, 2 * 64 * 1024 + overhead), table.budget.used());

    node.dirty = false;
    table.release(node);
    try testing.expectEqual(@as(usize, 0), table.budget.used());
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
    try testing.expectEqual(@as(usize, 0), c.len());
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

    armFaults(&.{.ciphertext_alloc});
    try testing.expectError(error.NoSpaceLeft, node.write(&table, 0, &bigger, test_now));
    try testing.expectEqualStrings("start", node.plaintext);
    try testing.expectEqual(first, node.ciphertext.ptr);
    try testing.expectEqual(@as(usize, 64 * 1024 + overhead), node.ciphertext.len);
    try testing.expectEqual(@as(usize, 2 * 64 * 1024 + overhead), table.budget.used());

    armFaults(&.{.plaintext_realloc});
    try testing.expectError(error.NoSpaceLeft, node.write(&table, 0, &bigger, test_now));
    try testing.expectEqualStrings("start", node.plaintext);
    try testing.expectEqual(@as(usize, 64 * 1024), node.plaintext_capacity);
    try testing.expectEqual(@as(usize, 128 * 1024 + overhead), node.ciphertext.len);
    try testing.expectEqual(@as(usize, 64 * 1024 + 128 * 1024 + overhead), table.budget.used());

    armFaults(&.{});
    try node.write(&table, 0, &bigger, test_now);
    try testing.expectEqual(@as(usize, 128 * 1024), node.plaintext_capacity);
    try testing.expectEqual(@as(usize, 2 * 128 * 1024 + overhead), table.budget.used());
    node.dirty = false;
    table.release(node);
}

test "a growth of a dirty node peaks at three buffers" {
    // Budget for old plaintext plus both replacement buffers.
    var table = Table.init(testing.allocator, testing.io, 1 << 20, 64 * 1024 + 2 * 128 * 1024 + overhead);
    defer table.deinit();
    const node = try table.attach("f");
    node.times = test_times;
    node.loaded = true;
    try node.write(&table, 0, "start", test_now);
    try testing.expectEqual(@as(usize, 2 * 64 * 1024 + overhead), table.budget.used());
    const bigger: [70 * 1024]u8 = @splat('y');
    try node.write(&table, 0, &bigger, test_now);
    try testing.expectEqual(@as(usize, 2 * 128 * 1024 + overhead), table.budget.used());
    node.dirty = false;
    table.release(node);
}

test "the peak of a growth from an exact-size load is three buffers" {
    const io = testing.io;
    const keys = crypto.deriveKeys(@splat(11), null);
    try std.Io.Dir.createDirPath(.cwd(), io, "tmp/node_peak");
    defer std.Io.Dir.deleteTree(.cwd(), io, "tmp/node_peak") catch {};
    const plain: [100 * 1024]u8 = @splat('p');
    const encrypted = try crypto.encrypt(&plain, keys, testing.allocator, io);
    defer testing.allocator.free(encrypted);
    try std.Io.Dir.writeFile(.cwd(), io, .{ .sub_path = "tmp/node_peak/f", .data = encrypted });

    const limit = 200 * 1024;
    var table = Table.init(testing.allocator, testing.io, limit, 3 * limit + (1 << 20));
    defer table.deinit();
    const node = try table.attach("f");
    node.times = test_times;
    const file = try std.Io.Dir.openFile(.cwd(), io, "tmp/node_peak/f", .{});
    defer file.close(io);
    try node.load(&table, file, encrypted.len, keys, io);
    try testing.expectEqual(@as(usize, plain.len), node.plaintext_capacity);
    try testing.expectEqualSlices(u8, &plain, node.plaintext);

    // Overwriting loaded data must not grow plaintext capacity.
    try node.write(&table, 0, "q", test_now);
    try testing.expectEqual(@as(u8, 'q'), node.plaintext[0]);
    try testing.expectEqual(@as(usize, plain.len), node.plaintext_capacity);
    try testing.expectEqual(@as(usize, 2 * plain.len + overhead), table.budget.used());

    try node.write(&table, plain.len, "z", test_now);
    try testing.expectEqual(@as(usize, limit), node.plaintext_capacity);
    try testing.expectEqual(@as(usize, 2 * limit + overhead), table.budget.used());
    node.dirty = false;
    table.release(node);

    // Allow growth with exactly the peak budget.
    var exact = Table.init(testing.allocator, testing.io, limit, plain.len + 2 * limit + overhead);
    defer exact.deinit();
    const fitting = try exact.attach("f");
    fitting.times = test_times;
    try fitting.load(&exact, file, encrypted.len, keys, io);
    try fitting.write(&exact, plain.len, "z", test_now);
    try testing.expectEqual(@as(usize, 2 * limit + overhead), exact.budget.used());
    fitting.dirty = false;
    exact.release(fitting);

    // The steady-state budget cannot cover old plaintext during growth.
    var tight = Table.init(testing.allocator, testing.io, limit, 2 * limit + overhead);
    defer tight.deinit();
    const other = try tight.attach("f");
    other.times = test_times;
    try other.load(&tight, file, encrypted.len, keys, io);
    try testing.expectError(error.NoSpaceLeft, other.write(&tight, plain.len, "z", test_now));
    try testing.expectEqualSlices(u8, &plain, other.plaintext);
    try testing.expectEqual(@as(usize, plain.len), other.plaintext_capacity);
    tight.release(other);
}

test "load rejects short files and wrong keys" {
    const io = testing.io;
    const keys = crypto.deriveKeys(@splat(12), null);
    try std.Io.Dir.createDirPath(.cwd(), io, "tmp/node_load");
    defer std.Io.Dir.deleteTree(.cwd(), io, "tmp/node_load") catch {};
    try std.Io.Dir.writeFile(.cwd(), io, .{ .sub_path = "tmp/node_load/short", .data = "too short" });
    const encrypted = try crypto.encrypt("secret", keys, testing.allocator, io);
    defer testing.allocator.free(encrypted);
    try std.Io.Dir.writeFile(.cwd(), io, .{ .sub_path = "tmp/node_load/ok", .data = encrypted });

    var table = Table.init(testing.allocator, testing.io, 1 << 20, 1 << 24);
    defer table.deinit();
    const node = try table.attach("x");
    {
        const file = try std.Io.Dir.openFile(.cwd(), io, "tmp/node_load/short", .{});
        defer file.close(io);
        try testing.expectError(error.InvalidFileSize, node.load(&table, file, 9, keys, io));
    }
    {
        const file = try std.Io.Dir.openFile(.cwd(), io, "tmp/node_load/ok", .{});
        defer file.close(io);
        const wrong = crypto.deriveKeys(@splat(13), null);
        try testing.expectError(error.InvalidHeaderMac, node.load(&table, file, encrypted.len, wrong, io));
        try testing.expectEqual(@as(usize, 0), table.budget.used());
        try node.load(&table, file, encrypted.len, keys, io);
        try testing.expectEqualStrings("secret", node.plaintext);
    }
    table.release(node);
}

test "write-back publishes a decryptable file with the recorded attributes and marks the parent" {
    const io = testing.io;
    const allocator = testing.allocator;
    const keys = crypto.deriveKeys(@splat(14), null);
    std.Io.Dir.deleteTree(.cwd(), io, "tmp/node_flush") catch {};
    try std.Io.Dir.createDirPath(.cwd(), io, "tmp/node_flush");
    defer std.Io.Dir.deleteTree(.cwd(), io, "tmp/node_flush") catch {};
    var parent = try std.Io.Dir.openDir(.cwd(), io, "tmp/node_flush", .{ .iterate = true });
    defer parent.close(io);

    var table = Table.init(allocator, testing.io, 1 << 20, 1 << 24);
    defer table.deinit();
    var marks: Marks = .{ .allocator = allocator, .io = io };
    defer marks.deinit();

    const node = try table.attach("out");
    node.times = test_times;
    node.loaded = true;
    try node.write(&table, 0, "payload", test_now);
    node.mode = 0o640;
    const fallback: Fallback = .{ .mode = 0o644, .uid = null, .gid = null };
    node.mutex.lockUncancelable(testing.io);
    try writeBack(node, &table, parent, "out", fallback, keys, &marks, false, io);
    node.mutex.unlock(testing.io);
    try testing.expect(!node.dirty);
    try testing.expectEqual(@as(usize, 1), marks.count());

    const stored = try std.Io.Dir.readFileAlloc(.cwd(), io, "tmp/node_flush/out", allocator, .limited(1024));
    defer allocator.free(stored);
    const plain = try crypto.decrypt(stored, keys, allocator);
    defer allocator.free(plain);
    try testing.expectEqualStrings("payload", plain);

    var st: fuse.Stat = undefined;
    try testing.expect(fuse.statAt(parent.handle, "out", &st));
    try testing.expectEqual(@as(u32, 0o640), @as(u32, st.mode) & 0o777);
    try testing.expectEqual(test_now.sec, st.mtime().sec);

    var it = parent.iterate();
    var count: usize = 0;
    while (try it.next(io)) |_| count += 1;
    try testing.expectEqual(@as(usize, 1), count);

    try node.write(&table, 7, "!", test_now);
    node.mutex.lockUncancelable(testing.io);
    try writeBack(node, &table, parent, "out", fallback, keys, &marks, true, io);
    node.mutex.unlock(testing.io);
    try testing.expectEqual(@as(usize, 0), marks.count());
    const pending = try marks.pendingKeys(allocator);
    defer allocator.free(pending);
    try testing.expectEqual(@as(usize, 0), pending.len);
    table.release(node);
}

test "a failed sync keeps the node dirty and the temporary file is gone" {
    if (builtin.mode != .debug) return error.SkipZigTest;
    const io = testing.io;
    const allocator = testing.allocator;
    const keys = crypto.deriveKeys(@splat(15), null);
    std.Io.Dir.deleteTree(.cwd(), io, "tmp/node_fault") catch {};
    try std.Io.Dir.createDirPath(.cwd(), io, "tmp/node_fault");
    defer std.Io.Dir.deleteTree(.cwd(), io, "tmp/node_fault") catch {};
    var parent = try std.Io.Dir.openDir(.cwd(), io, "tmp/node_fault", .{ .iterate = true });
    defer parent.close(io);

    var table = Table.init(allocator, testing.io, 1 << 20, 1 << 24);
    defer table.deinit();
    var marks: Marks = .{ .allocator = allocator, .io = io };
    defer marks.deinit();
    const node = try table.attach("f");
    node.times = test_times;
    node.loaded = true;
    try node.write(&table, 0, "data", test_now);
    const fallback: Fallback = .{ .mode = 0o600, .uid = null, .gid = null };

    armFaults(&.{.file_sync});
    node.mutex.lockUncancelable(testing.io);
    try testing.expectError(error.InputOutput, writeBack(node, &table, parent, "f", fallback, keys, &marks, false, io));
    node.mutex.unlock(testing.io);
    try testing.expect(node.dirty);
    try testing.expectEqual(@as(usize, 0), marks.count());
    var it = parent.iterate();
    try testing.expectEqual(@as(?std.Io.Dir.Entry, null), try it.next(io));

    // Failed writes must survive the last close for a later retry.
    table.release(node);
    try testing.expectEqual(@as(usize, 1), table.nodes.items.len);
    const again = try table.attach("f");
    try testing.expectEqual(node, again);
    try testing.expectEqualStrings("data", again.plaintext);

    // Publication succeeds even if the directory still needs syncing.
    armFaults(&.{.dir_sync});
    again.mutex.lockUncancelable(testing.io);
    try testing.expectError(error.InputOutput, writeBack(again, &table, parent, "f", fallback, keys, &marks, true, io));
    again.mutex.unlock(testing.io);
    try testing.expect(!again.dirty);
    try testing.expectEqual(@as(usize, 1), marks.count());
    _ = try parent.statFile(io, "f", .{});
    armFaults(&.{});
    table.release(again);
    try testing.expectEqual(@as(usize, 0), table.nodes.items.len);
}

test "marks survive a rename of the directory and a sync clears only its own generation" {
    const io = testing.io;
    const allocator = testing.allocator;
    std.Io.Dir.deleteTree(.cwd(), io, "tmp/node_marks") catch {};
    try std.Io.Dir.createDirPath(.cwd(), io, "tmp/node_marks/a");
    defer std.Io.Dir.deleteTree(.cwd(), io, "tmp/node_marks") catch {};
    var marks: Marks = .{ .allocator = allocator, .io = io };
    defer marks.deinit();

    // Linux cannot sync the O_PATH descriptor opened without iteration capability.
    var dir = try std.Io.Dir.openDir(.cwd(), io, "tmp/node_marks/a", .{ .iterate = true });
    const key = markKey(try fuse.statFd(dir.handle));

    try marks.reserve();
    try testing.expect(marks.commit(key, dir));
    try std.Io.Dir.rename(.cwd(), "tmp/node_marks/a", .cwd(), "tmp/node_marks/b", io);
    try testing.expectEqual(@as(usize, 1), marks.count());

    var other = try std.Io.Dir.openDir(.cwd(), io, "tmp/node_marks/b", .{});
    try marks.reserve();
    try testing.expect(!marks.commit(key, other));
    other.close(io);

    // A completed sync must not clear changes made after it started.
    const pinned = marks.pin(key).?;
    try marks.reserve();
    try testing.expect(!marks.commit(key, other));
    marks.unpin(key, pinned.generation, true);
    try testing.expectEqual(@as(usize, 1), marks.count());

    try syncMark(&marks, key);
    try testing.expectEqual(@as(usize, 0), marks.count());

    // Removing a directory must not close descriptors still used for sync.
    dir = try std.Io.Dir.openDir(.cwd(), io, "tmp/node_marks/b", .{ .iterate = true });
    try marks.reserve();
    try testing.expect(marks.commit(key, dir));
    const held = marks.pin(key).?;
    marks.drop(key);
    try testing.expectEqual(@as(usize, 1), marks.count());
    marks.unpin(key, held.generation, false);
    try testing.expectEqual(@as(usize, 0), marks.count());

    try marks.reserve();
    marks.cancel();
    try testing.expectEqual(@as(usize, 0), marks.reserved);
}

test "renames re-key a file or a whole subtree and displace the destination node" {
    var table = Table.init(testing.allocator, testing.io, 1 << 20, 1 << 24);
    defer table.deinit();
    const file = try table.attach("d/one");
    const deep = try table.attach("d/sub/two");
    const outside = try table.attach("dx/three");
    const target = try table.attach("x/one");

    var rekey = try table.beginRekey("d", "e", true);
    try testing.expectEqual(@as(usize, 2), rekey.nodes.items.len);
    try testing.expectEqual(@as(?*Node, null), rekey.target);
    rekey.commit();
    try testing.expectEqualStrings("e/one", file.path);
    try testing.expectEqualStrings("e/sub/two", deep.path);
    try testing.expectEqualStrings("dx/three", outside.path);

    var onto = try table.beginRekey("e/sub/two", "x/one", false);
    try testing.expectEqual(@as(usize, 1), onto.nodes.items.len);
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
    try testing.expectEqual(@as(usize, 0), same.nodes.items.len);
    try testing.expectEqual(@as(?*Node, null), same.target);
    same.commit();
    try testing.expect(!deep.unlinked.load(.acquire));

    table.release(file);
    table.release(deep);
    table.release(outside);
    table.release(target);
    try testing.expectEqual(@as(usize, 0), table.nodes.items.len);
}

test "unlink drops a retained node or keeps an unlinked one alive under a pin" {
    var table = Table.init(testing.allocator, testing.io, 1 << 20, 1 << 24);
    defer table.deinit();
    const node = try table.attach("f");
    node.times = test_times;
    node.loaded = true;
    try node.write(&table, 0, "x", test_now);
    table.release(node);
    try testing.expectEqual(@as(usize, 1), table.nodes.items.len);

    const pinned = try table.pinAll(testing.allocator);
    defer testing.allocator.free(pinned);
    try testing.expectEqual(@as(usize, 1), pinned.len);
    // Deletion must preserve data still held by another pin.
    const unlinked = table.pin("f").?;
    unlinked.unlinked.store(true, .release);
    table.release(unlinked);
    try testing.expectEqual(@as(usize, 1), table.nodes.items.len);
    try testing.expectEqual(@as(?*Node, null), table.pin("f"));
    for (pinned) |p| table.release(p);
    try testing.expectEqual(@as(usize, 0), table.nodes.items.len);
    try testing.expectEqual(@as(usize, 0), table.budget.used());

    const retained = try table.attach("g");
    retained.times = test_times;
    retained.loaded = true;
    try retained.write(&table, 0, "y", test_now);
    table.release(retained);
    const gone = table.pin("g").?;
    gone.unlinked.store(true, .release);
    table.release(gone);
    try testing.expectEqual(@as(usize, 0), table.nodes.items.len);

    // Replacing a retained destination must release its buffers.
    const displaced = try table.attach("h");
    displaced.times = test_times;
    displaced.loaded = true;
    try displaced.write(&table, 0, "z", test_now);
    table.release(displaced);
    const source = try table.attach("i");
    var rekey = try table.beginRekey("i", "h", false);
    rekey.commit();
    try testing.expectEqual(@as(usize, 1), table.nodes.items.len);
    try testing.expectEqualStrings("h", source.path);
    table.release(source);
    try testing.expectEqual(@as(usize, 0), table.budget.used());
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
