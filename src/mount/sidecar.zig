//! AppleDouble files that the mount accepts but never stores.
//!
//! On a volume without extended attributes of its own, macOS keeps them in a "._" file next to each file.
//! The encrypted files have no place for them, and the "._" files confuse users.
//! So the mount keeps the sidecars in memory for the life of the mount, and nothing reaches the encrypted folder.
//!
//! A sidecar must outlive its last close.
//! The kernel keeps the vnode in its name cache, and a later attribute write on a vanished file fails with EPERM.

const std = @import("std");
const builtin = @import("builtin");
const table_mod = @import("table.zig");

pub const Error = error{ FileNotFound, NoSpaceLeft, OutOfMemory };

/// Above this many bytes, the oldest closed sidecars go away first.
pub const default_limit: usize = 64 * 1024 * 1024;

/// The kernel names a sidecar after its file, or "._." for the root directory.
pub fn isSidecar(path: []const u8) bool {
    if (builtin.os.tag != .macos) return false;
    return std.mem.startsWith(u8, std.fs.path.basename(path), "._");
}

pub const Entry = struct {
    data: std.ArrayListUnmanaged(u8) = .empty,
    uid: std.c.uid_t,
    gid: std.c.gid_t,
    mtime: std.c.timespec,
    opens: usize = 1,
    /// Removed from the store while still open, so the last close frees it.
    unlinked: bool = false,
};

pub const Stat = struct {
    size: u64,
    uid: std.c.uid_t,
    gid: std.c.gid_t,
    mtime: std.c.timespec,
};

pub const Store = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    limit: usize = default_limit,
    mutex: std.Io.Mutex = .init,
    bytes: usize = 0,
    /// Insertion order is eviction order. The store owns the keys.
    entries: std.StringArrayHashMapUnmanaged(*Entry) = .empty,

    pub fn deinit(s: *Store) void {
        for (s.entries.keys(), s.entries.values()) |path, entry| {
            s.allocator.free(path);
            s.destroy(entry);
        }
        s.entries.deinit(s.allocator);
    }

    /// A missing sidecar is created when the caller intends to write.
    pub fn open(s: *Store, path: []const u8, uid: std.c.uid_t, gid: std.c.gid_t, writable: bool, truncate: bool, now: std.c.timespec) Error!*Entry {
        s.mutex.lockUncancelable(s.io);
        defer s.mutex.unlock(s.io);
        if (s.entries.get(path)) |entry| {
            entry.opens += 1;
            if (truncate) {
                s.bytes -= entry.data.items.len;
                entry.data.clearRetainingCapacity();
                entry.mtime = now;
            }
            return entry;
        }
        if (!writable) return error.FileNotFound;
        try s.makeRoom(path.len);
        const entry = try s.allocator.create(Entry);
        errdefer s.allocator.destroy(entry);
        entry.* = .{ .uid = uid, .gid = gid, .mtime = now };
        const key = try s.allocator.dupe(u8, path);
        errdefer s.allocator.free(key);
        try s.entries.put(s.allocator, key, entry);
        s.bytes += key.len;
        return entry;
    }

    pub fn close(s: *Store, entry: *Entry) void {
        s.mutex.lockUncancelable(s.io);
        defer s.mutex.unlock(s.io);
        entry.opens -= 1;
        if (entry.opens == 0 and entry.unlinked) s.destroy(entry);
    }

    pub fn contains(s: *Store, path: []const u8) bool {
        s.mutex.lockUncancelable(s.io);
        defer s.mutex.unlock(s.io);
        return s.entries.contains(path);
    }

    pub fn stat(s: *Store, path: []const u8) ?Stat {
        s.mutex.lockUncancelable(s.io);
        defer s.mutex.unlock(s.io);
        const entry = s.entries.get(path) orelse return null;
        return .{ .size = entry.data.items.len, .uid = entry.uid, .gid = entry.gid, .mtime = entry.mtime };
    }

    pub fn chown(s: *Store, path: []const u8, uid: std.c.uid_t, gid: std.c.gid_t) Error!void {
        s.mutex.lockUncancelable(s.io);
        defer s.mutex.unlock(s.io);
        const entry = s.entries.get(path) orelse return error.FileNotFound;
        entry.uid = uid;
        entry.gid = gid;
    }

    pub fn touch(s: *Store, path: []const u8, mtime: std.c.timespec) Error!void {
        s.mutex.lockUncancelable(s.io);
        defer s.mutex.unlock(s.io);
        const entry = s.entries.get(path) orelse return error.FileNotFound;
        entry.mtime = mtime;
    }

    pub fn read(s: *Store, entry: *Entry, buf: []u8, offset: u64) usize {
        s.mutex.lockUncancelable(s.io);
        defer s.mutex.unlock(s.io);
        if (offset >= entry.data.items.len) return 0;
        const n: usize = @intCast(@min(buf.len, entry.data.items.len - offset));
        @memcpy(buf[0..n], entry.data.items[@intCast(offset)..][0..n]);
        return n;
    }

    pub fn write(s: *Store, entry: *Entry, bytes: []const u8, offset: u64, now: std.c.timespec) Error!void {
        s.mutex.lockUncancelable(s.io);
        defer s.mutex.unlock(s.io);
        const end = offset + bytes.len;
        if (end > entry.data.items.len) try s.resizeLocked(entry, end);
        @memcpy(entry.data.items[@intCast(offset)..][0..bytes.len], bytes);
        entry.mtime = now;
    }

    pub fn resize(s: *Store, entry: *Entry, size: u64, now: std.c.timespec) Error!void {
        s.mutex.lockUncancelable(s.io);
        defer s.mutex.unlock(s.io);
        try s.resizeLocked(entry, size);
        entry.mtime = now;
    }

    pub fn resizeAt(s: *Store, path: []const u8, size: u64, now: std.c.timespec) Error!void {
        s.mutex.lockUncancelable(s.io);
        defer s.mutex.unlock(s.io);
        const entry = s.entries.get(path) orelse return error.FileNotFound;
        try s.resizeLocked(entry, size);
        entry.mtime = now;
    }

    /// Drop one sidecar. It stays readable through its open handles.
    pub fn remove(s: *Store, path: []const u8) void {
        s.mutex.lockUncancelable(s.io);
        defer s.mutex.unlock(s.io);
        if (s.entries.getIndex(path)) |index| s.removeAt(index);
    }

    /// Drop every sidecar below a removed directory.
    pub fn forget(s: *Store, dir: []const u8) void {
        s.mutex.lockUncancelable(s.io);
        defer s.mutex.unlock(s.io);
        s.forgetTree(dir);
    }

    /// Follow a rename. Whatever the target had before goes away.
    /// A rename that fails halfway drops every sidecar rather than leave the index wrong.
    pub fn move(s: *Store, from: []const u8, to: []const u8) Error!void {
        s.mutex.lockUncancelable(s.io);
        defer s.mutex.unlock(s.io);
        if (s.entries.fetchSwapRemove(from)) |kv| {
            errdefer s.drop(kv.key, kv.value);
            s.forgetTree(to);
            const key = try s.allocator.dupe(u8, to);
            errdefer s.allocator.free(key);
            try s.entries.put(s.allocator, key, kv.value);
            s.bytes = s.bytes - kv.key.len + key.len;
            s.allocator.free(kv.key);
            return;
        }
        for (s.entries.keys()) |path| {
            if (table_mod.pathSuffix(path, from, true) != null) break;
        } else return error.FileNotFound;
        s.forgetTree(to);
        errdefer s.forgetTree("");
        for (s.entries.keys()) |*key| {
            const rest = table_mod.pathSuffix(key.*, from, true) orelse continue;
            const moved = try std.mem.concat(s.allocator, u8, &.{ to, rest });
            s.bytes = s.bytes - key.len + moved.len;
            s.allocator.free(key.*);
            key.* = moved;
        }
        try s.entries.reIndex(s.allocator);
    }

    fn forgetTree(s: *Store, root: []const u8) void {
        var index: usize = 0;
        while (index < s.entries.count()) {
            if (table_mod.pathSuffix(s.entries.keys()[index], root, true) != null) s.removeAt(index) else index += 1;
        }
    }

    fn resizeLocked(s: *Store, entry: *Entry, size: u64) Error!void {
        const old = entry.data.items.len;
        if (size > old) try s.makeRoom(@intCast(size - old));
        try entry.data.resize(s.allocator, @intCast(size));
        if (size > old) @memset(entry.data.items[old..], 0);
        s.bytes = s.bytes - old + entry.data.items.len;
    }

    /// Evict the oldest closed sidecars until the growth fits.
    fn makeRoom(s: *Store, growth: usize) Error!void {
        var index: usize = 0;
        while (s.bytes + growth > s.limit and index < s.entries.count()) {
            if (s.entries.values()[index].opens == 0) s.removeAt(index) else index += 1;
        }
        if (s.bytes + growth > s.limit) return error.NoSpaceLeft;
    }

    fn removeAt(s: *Store, index: usize) void {
        const path = s.entries.keys()[index];
        const entry = s.entries.values()[index];
        s.entries.orderedRemoveAt(index);
        s.drop(path, entry);
    }

    fn drop(s: *Store, path: []const u8, entry: *Entry) void {
        s.bytes -= path.len;
        s.allocator.free(path);
        if (entry.opens == 0) s.destroy(entry) else entry.unlinked = true;
    }

    /// The data stays counted until it is really gone, since an unlinked sidecar keeps it while open.
    fn destroy(s: *Store, entry: *Entry) void {
        s.bytes -= entry.data.items.len;
        entry.data.deinit(s.allocator);
        s.allocator.destroy(entry);
    }
};

const testing = std.testing;
const epoch: std.c.timespec = .{ .sec = 0, .nsec = 0 };

fn sizeOf(s: *Store, path: []const u8) ?u64 {
    const found = s.stat(path) orelse return null;
    return found.size;
}

fn openClosed(s: *Store, path: []const u8) !void {
    s.close(try s.open(path, 0, 0, true, false, epoch));
}

test "a sidecar outlives its last close and keeps what was written" {
    var s: Store = .{ .allocator = testing.allocator, .io = testing.io };
    defer s.deinit();
    try testing.expectError(error.FileNotFound, s.open("/._a", 1, 2, false, false, epoch));
    const entry = try s.open("/._a", 1, 2, true, false, epoch);
    try s.write(entry, "header", 0, epoch);
    try s.write(entry, "xy", 10, epoch);
    var buf: [16]u8 = undefined;
    try testing.expectEqual(12, s.read(entry, &buf, 0));
    try testing.expectEqualStrings("header\x00\x00\x00\x00xy", buf[0..12]);
    try testing.expectEqual(0, s.read(entry, &buf, 12));
    try testing.expectEqual(1, s.stat("/._a").?.uid);
    s.close(entry);

    const again = try s.open("/._a", 1, 2, false, false, epoch);
    try testing.expectEqual(entry, again);
    try testing.expectEqual(12, sizeOf(&s, "/._a"));
    try s.resizeAt("/._a", 4, epoch);
    s.close(again);
    try testing.expectEqual(4, sizeOf(&s, "/._a"));
    try testing.expectEqual("/._a".len + 4, s.bytes);

    const fresh = try s.open("/._a", 1, 2, true, true, epoch);
    try testing.expectEqual(0, sizeOf(&s, "/._a"));
    s.close(fresh);
}

test "a rename moves one sidecar or a tree of them, and a removal drops them" {
    var s: Store = .{ .allocator = testing.allocator, .io = testing.io };
    defer s.deinit();
    try openClosed(&s, "/._d");
    try openClosed(&s, "/d/._f");
    try openClosed(&s, "/dx/._g");
    try openClosed(&s, "/e/._old");
    try openClosed(&s, "/._e");
    try s.move("/d", "/e");
    try s.move("/._d", "/._e");
    try testing.expectEqual(0, sizeOf(&s, "/e/._f"));
    try testing.expectEqual(0, sizeOf(&s, "/._e"));
    try testing.expectEqual(0, sizeOf(&s, "/dx/._g"));
    try testing.expectEqual(null, sizeOf(&s, "/e/._old"));
    try testing.expectEqual(null, sizeOf(&s, "/d/._f"));
    try testing.expectEqual(null, sizeOf(&s, "/._d"));
    try testing.expectError(error.FileNotFound, s.move("/none", "/other"));
    s.forget("/e");
    s.remove("/._e");
    try testing.expectEqual(null, sizeOf(&s, "/e/._f"));
    try testing.expectEqual(null, sizeOf(&s, "/._e"));
    try testing.expectEqual("/dx/._g".len, s.bytes);
}

test "an open sidecar survives its removal until the last close" {
    var s: Store = .{ .allocator = testing.allocator, .io = testing.io };
    defer s.deinit();
    const entry = try s.open("/._a", 0, 0, true, false, epoch);
    try s.write(entry, "data", 0, epoch);
    s.remove("/._a");
    try testing.expectEqual(null, sizeOf(&s, "/._a"));
    try testing.expectEqual(4, s.bytes);
    var buf: [4]u8 = undefined;
    try testing.expectEqual(4, s.read(entry, &buf, 0));
    s.close(entry);
    try testing.expectEqual(0, s.bytes);
}

test "the oldest closed sidecars are evicted first, and open ones stay" {
    var s: Store = .{ .allocator = testing.allocator, .io = testing.io, .limit = 40 };
    defer s.deinit();
    const held = try s.open("/._a", 0, 0, true, false, epoch);
    try s.write(held, "0123456789", 0, epoch);
    const b = try s.open("/._b", 0, 0, true, false, epoch);
    try s.write(b, "0123456789", 0, epoch);
    s.close(b);
    const c = try s.open("/._c", 0, 0, true, false, epoch);
    try s.write(c, "0123456789", 0, epoch);
    try testing.expectEqual(null, sizeOf(&s, "/._b"));
    try testing.expectEqual(10, sizeOf(&s, "/._a"));
    try testing.expectError(error.NoSpaceLeft, s.write(c, "01234567890123456789", 10, epoch));
    s.close(c);
    s.close(held);
}

test "only file names with the AppleDouble prefix are sidecars, and only on macOS" {
    const expected = builtin.os.tag == .macos;
    try testing.expectEqual(expected, isSidecar("/._a"));
    try testing.expectEqual(expected, isSidecar("/dir/._a.txt"));
    try testing.expectEqual(expected, isSidecar("/._."));
    try testing.expect(!isSidecar("/dir/a.txt"));
    try testing.expect(!isSidecar("/._dir/a.txt"));
    try testing.expect(!isSidecar("/.hidden"));
}
