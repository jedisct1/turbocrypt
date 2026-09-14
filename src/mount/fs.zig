//! A decrypted filesystem view confined to the backing root, with permission checks on each caller.

const std = @import("std");
const builtin = @import("builtin");
const crypto = @import("../crypto.zig");
const processor = @import("../processor.zig");
const utils = @import("../utils.zig");
const fuse = @import("fuse.zig");
const names = @import("names.zig");
const node_mod = @import("node.zig");

const Node = node_mod.Node;
const S = std.c.S;
const at_nofollow: u32 = std.c.AT.SYMLINK_NOFOLLOW;

pub const Error = error{
    NotSupported,
    BadHandle,
    UnsafePath,
    OutOfMemory,
};

pub const Options = struct {
    read_only: bool = false,
    allow_other: bool = false,
    max_file_size: usize,
    memory_limit: usize,
    /// Recovery location for ciphertext that cannot be written back at unmount.
    rescue_dir: []const u8,
    /// Notify the daemon parent when the mount is ready.
    ready_fd: ?std.c.fd_t = null,
    /// Paths for the foreground status message.
    backing: []const u8 = &.{},
    mountpoint: []const u8 = &.{},
};

extern "c" fn getgroups(size: c_int, list: [*]std.c.gid_t) c_int;
extern "c" fn fstatvfs(fd: std.c.fd_t, buf: *fuse.Statvfs) c_int;

pub const Mount = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    /// Held open to anchor all backing paths for the lifetime of the mount.
    root: std.Io.Dir,
    keys: crypto.DerivedKeys,
    mapper: names.Mapper,
    options: Options,
    /// The mount process's identity, used to restrict callers and preserve file ownership.
    uid: std.c.uid_t,
    gid: std.c.gid_t,
    groups: []std.c.gid_t,
    table: node_mod.Table,
    marks: node_mod.Marks,
    /// Persistence and internal failures that affect the exit status.
    failures: std.atomic.Value(usize) = .init(0),
    /// At least one file could not be written back at unmount.
    lost: std.atomic.Value(bool) = .init(false),
    /// Distinguish a completed mount from a setup failure.
    up: std.atomic.Value(bool) = .init(false),

    pub fn init(
        m: *Mount,
        allocator: std.mem.Allocator,
        io: std.Io,
        lib: *const fuse.Library,
        root: std.Io.Dir,
        keys: crypto.DerivedKeys,
        mapper: names.Mapper,
        options: Options,
    ) !void {
        m.* = .{
            .allocator = allocator,
            .io = io,
            .root = root,
            .keys = keys,
            .mapper = mapper,
            .options = options,
            .uid = std.c.geteuid(),
            .gid = std.c.getegid(),
            .groups = try ownGroups(allocator),
            .table = node_mod.Table.init(allocator, io, options.max_file_size, options.memory_limit),
            .marks = .{ .allocator = allocator, .io = io },
        };
        lib_ptr = lib;
    }

    pub fn deinit(m: *Mount) void {
        m.table.deinit();
        m.marks.deinit();
        m.allocator.free(m.groups);
        std.crypto.secureZero(u8, std.mem.asBytes(&m.keys));
    }

    pub fn failureCount(m: *Mount) usize {
        return m.failures.load(.seq_cst);
    }

    fn countFailure(m: *Mount) void {
        _ = m.failures.fetchAdd(1, .seq_cst);
    }
};

fn ownGroups(allocator: std.mem.Allocator) ![]std.c.gid_t {
    const count = getgroups(0, undefined);
    if (count <= 0) return allocator.alloc(std.c.gid_t, 0);
    const list = try allocator.alloc(std.c.gid_t, @intCast(count));
    errdefer allocator.free(list);
    const got = getgroups(count, list.ptr);
    if (got < 0) return error.Unexpected;
    return list[0..@intCast(got)];
}

var lib_ptr: *const fuse.Library = undefined;

fn mount() *Mount {
    return fuse.privateData(lib_ptr, Mount);
}

fn context() *fuse.Context {
    return lib_ptr.get_context();
}

pub const operations: fuse.Operations = .{
    .getattr = cGetattr,
    .readlink = cReadlink,
    .mknod = cMknod,
    .mkdir = cMkdir,
    .unlink = cUnlink,
    .rmdir = cRmdir,
    .symlink = cSymlink,
    .rename = cRename,
    .link = cLink,
    .chmod = cChmod,
    .chown = cChown,
    .truncate = cTruncate,
    .open = cOpen,
    .read = cRead,
    .write = cWrite,
    .statfs = cStatfs,
    .flush = cFlush,
    .release = cRelease,
    .fsync = cFsync,
    .setxattr = cSetxattr,
    .getxattr = cGetxattr,
    .listxattr = cListxattr,
    .removexattr = cRemovexattr,
    .opendir = cOpendir,
    .readdir = cReaddir,
    .releasedir = cReleasedir,
    .fsyncdir = cFsyncdir,
    .init = cInit,
    .destroy = cDestroy,
    .access = cAccess,
    .create = cCreate,
    .utimens = cUtimens,
};

pub fn errnoFor(err: anyerror) c_int {
    const e: std.c.E = switch (err) {
        error.FileNotFound => .NOENT,
        error.AccessDenied => .ACCES,
        error.PermissionDenied => .PERM,
        error.PathAlreadyExists => .EXIST,
        error.NoSpaceLeft, error.DiskQuota => .NOSPC,
        error.DirNotEmpty => .NOTEMPTY,
        error.NameTooLong => .NAMETOOLONG,
        error.InvalidHeaderMac, error.AuthenticationFailed, error.InvalidFileSize, error.InputOutput => .IO,
        error.OutOfMemory => .NOMEM,
        error.FileTooBig => .FBIG,
        error.ReadOnlyFileSystem => .ROFS,
        error.IsDir => .ISDIR,
        error.NotDir => .NOTDIR,
        error.NotSupported => .OPNOTSUPP,
        error.BadHandle => .BADF,
        error.UnsafePath => .INVAL,
        error.FileBusy, error.DeviceBusy => .BUSY,
        else => .IO,
    };
    return fuse.negErrno(e);
}

fn noteSidecar(path: [*:0]const u8) void {
    if (builtin.mode != .debug) return;
    const name = std.fs.path.basename(std.mem.span(path));
    node_mod.faults_suppressed = std.mem.startsWith(u8, name, "._");
}

fn result(m: *Mount, r: anyerror!void) c_int {
    r catch |err| return failed(m, err);
    return 0;
}

fn resultSize(m: *Mount, r: anyerror!usize) c_int {
    const n = r catch |err| return failed(m, err);
    return @intCast(n);
}

/// Count unexpected errors as session failures even if the client ignores them.
fn failed(m: *Mount, err: anyerror) c_int {
    const code = errnoFor(err);
    if (code == fuse.negErrno(.IO) and !isDataError(err)) {
        m.countFailure();
        std.debug.print("turbocrypt mount: internal error: {}\n", .{err});
    }
    return code;
}

fn isDataError(err: anyerror) bool {
    return switch (err) {
        error.InvalidHeaderMac, error.AuthenticationFailed, error.InvalidFileSize, error.InputOutput => true,
        else => false,
    };
}

const FileHandle = struct {
    node: *Node,
    read: bool,
    write: bool,
    append: bool,
    /// Preserve access granted at open until the deferred read.
    backing: ?std.Io.File = null,

    fn closeBacking(handle: *FileHandle, io: std.Io) void {
        if (handle.backing) |file| file.close(io);
        handle.backing = null;
    }
};

const DirHandle = struct {
    dir: std.Io.Dir,
    key: node_mod.MarkKey,
};

fn handleOf(comptime T: type, fi: ?*fuse.FileInfo) Error!*T {
    const info = fi orelse return error.BadHandle;
    if (info.fh == 0) return error.BadHandle;
    return @ptrFromInt(info.fh);
}

fn nowSpec(io: std.Io) std.c.timespec {
    const ns = std.Io.Clock.now(.real, io).nanoseconds;
    return .{
        .sec = @intCast(@divFloor(ns, std.time.ns_per_s)),
        .nsec = @intCast(@mod(ns, std.time.ns_per_s)),
    };
}

fn timesOf(st: *const fuse.Stat) node_mod.Times {
    return .{ .atime = st.atime(), .mtime = st.mtime(), .ctime = st.ctime() };
}

fn setTimes(st: *fuse.Stat, times: node_mod.Times) void {
    if (builtin.os.tag == .macos) {
        st.atimespec = times.atime;
        st.mtimespec = times.mtime;
        st.ctimespec = times.ctime;
    } else {
        st.atim = times.atime;
        st.mtim = times.mtime;
        st.ctim = times.ctime;
    }
}

fn withSentinel(name: []const u8, buffer: *[std.fs.max_name_bytes + 1]u8) Error![:0]const u8 {
    if (name.len > std.fs.max_name_bytes) return error.UnsafePath;
    @memcpy(buffer[0..name.len], name);
    buffer[name.len] = 0;
    return buffer[0..name.len :0];
}

/// Never follow symlinks; missing or oversized names return null so lookup can try another spelling.
fn statAt(dir: std.Io.Dir, name: []const u8) Error!?fuse.Stat {
    var buffer: [std.fs.max_name_bytes + 1]u8 = undefined;
    const name_z = withSentinel(name, &buffer) catch return null;
    var st: fuse.Stat = undefined;
    if (!fuse.statAt(dir.handle, name_z, &st)) return null;
    return st;
}

fn modeOf(st: *const fuse.Stat) u32 {
    return st.mode;
}

const Want = struct {
    r: bool = false,
    w: bool = false,
    x: bool = false,
};

/// Check POSIX permissions against the caller's identity, not the mount process's.
pub fn allowedBy(uid: std.c.uid_t, gid: std.c.gid_t, groups: []const std.c.gid_t, st: *const fuse.Stat, want: Want) bool {
    const mode = modeOf(st);
    if (uid == 0) {
        if (!want.x or S.ISDIR(mode)) return true;
        return mode & 0o111 != 0;
    }
    const bits: u32 = if (st.uid == uid)
        (mode >> 6) & 7
    else if (st.gid == gid or std.mem.indexOfScalar(std.c.gid_t, groups, st.gid) != null)
        (mode >> 3) & 7
    else
        mode & 7;
    if (want.r and bits & 4 == 0) return false;
    if (want.w and bits & 2 == 0) return false;
    if (want.x and bits & 1 == 0) return false;
    return true;
}

fn permitted(m: *Mount, st: *const fuse.Stat, want: Want) !bool {
    const ctx = context();
    if (!m.options.allow_other and ctx.uid != m.uid) return false;
    // Avoid querying supplementary groups when they cannot affect the result.
    const groups_decide = ctx.uid != 0 and st.uid != ctx.uid and st.gid != ctx.gid;
    const groups: []std.c.gid_t = if (groups_decide) try callerGroups(m.allocator) else &.{};
    defer m.allocator.free(groups);
    return allowedBy(ctx.uid, ctx.gid, groups, st, want);
}

/// Return an owned group list; unavailable on macOS.
///
/// Retry with the reported size because libfuse returns the full count even when the buffer is too small.
fn callerGroups(allocator: std.mem.Allocator) ![]std.c.gid_t {
    if (builtin.os.tag != .linux) return &.{};
    const getgroups_fn = lib_ptr.getgroups orelse return &.{};
    var list: []std.c.gid_t = &.{};
    while (true) {
        const count = getgroups_fn(@intCast(list.len), list.ptr);
        if (count < 0) {
            allocator.free(list);
            return &.{};
        }
        const total: usize = @intCast(count);
        if (total == list.len) return list;
        allocator.free(list);
        list = try allocator.alloc(std.c.gid_t, total);
    }
}

fn requireAllowed(m: *Mount, st: *const fuse.Stat, want: Want) !void {
    if (!try permitted(m, st, want)) return error.AccessDenied;
}

fn isOwner(st: *const fuse.Stat) bool {
    const ctx = context();
    return ctx.uid == 0 or ctx.uid == st.uid;
}

/// Enforce sticky-directory ownership restrictions on removal and rename.
fn stickyAllows(parent: *const fuse.Stat, entry: *const fuse.Stat) bool {
    if (modeOf(parent) & S.ISVTX == 0) return true;
    const ctx = context();
    return ctx.uid == 0 or ctx.uid == entry.uid or ctx.uid == parent.uid;
}

/// Reject writes whose atomic replacement could not preserve ownership.
///
/// Keeping an inherited group requires no membership; changing owners requires root.
pub fn ownershipReproducibleBy(uid: std.c.uid_t, gid: std.c.gid_t, groups: []const std.c.gid_t, st: *const fuse.Stat, inherited_gid: std.c.gid_t) bool {
    if (uid == 0) return true;
    if (st.uid != uid) return false;
    if (st.gid == inherited_gid or st.gid == gid) return true;
    return std.mem.indexOfScalar(std.c.gid_t, groups, st.gid) != null;
}

fn groupComesFromDirectory(parent: *const fuse.Stat) bool {
    return builtin.os.tag == .macos or modeOf(parent) & S.ISGID != 0;
}

fn inheritedGid(m: *Mount, parent: *const fuse.Stat) std.c.gid_t {
    return if (groupComesFromDirectory(parent)) parent.gid else m.gid;
}

const Ownership = struct {
    uid: std.c.uid_t,
    gid: std.c.gid_t,
};

/// Ensure new entries belong to the caller and can retain their ownership during write-back.
/// Null means creation already gives the required ownership.
///
/// Check parent permissions first; creating for another user requires a mount running as root.
fn requiredOwnership(m: *Mount, parent: *const fuse.Stat) !?Ownership {
    const ctx = context();
    const inherited = inheritedGid(m, parent);
    const gid = if (groupComesFromDirectory(parent)) parent.gid else ctx.gid;
    if (ctx.uid == m.uid and gid == inherited) return null;
    var wanted = std.mem.zeroes(fuse.Stat);
    wanted.uid = ctx.uid;
    wanted.gid = gid;
    if (!ownershipReproducibleBy(m.uid, m.gid, m.groups, &wanted, inherited)) return error.PermissionDenied;
    return .{ .uid = ctx.uid, .gid = gid };
}

fn requireReproducible(m: *Mount, st: *const fuse.Stat, parent: *const fuse.Stat, path: []const u8) !void {
    if (ownershipReproducibleBy(m.uid, m.gid, m.groups, st, inheritedGid(m, parent))) return;
    std.debug.print("turbocrypt mount: {s} is read-only through the mount: owned by uid {d} gid {d}, which the mount cannot give back to a new file\n", .{ path, st.uid, st.gid });
    return error.PermissionDenied;
}

fn requireWritable(m: *Mount) !void {
    if (m.options.read_only) return error.ReadOnlyFileSystem;
}

const Split = struct {
    dir: []const u8,
    name: []const u8,
};

/// The root has no parent/name split.
fn splitPath(path: []const u8) ?Split {
    if (path.len <= 1) return null;
    const cut = std.mem.lastIndexOfScalar(u8, path, '/') orelse return null;
    return .{ .dir = path[0..@max(cut, 1)], .name = path[cut + 1 ..] };
}

const Parent = struct {
    dir: std.Io.Dir,
    /// Relative to the backing root; empty for the root itself.
    backing_path: []u8,
    st: fuse.Stat,

    fn deinit(self: *Parent, m: *Mount) void {
        self.dir.close(m.io);
        m.allocator.free(self.backing_path);
    }

    fn key(self: *const Parent) node_mod.MarkKey {
        return node_mod.markKey(self.st);
    }

    fn childPath(self: *const Parent, m: *Mount, backing_name: []const u8) ![]u8 {
        if (self.backing_path.len == 0) return m.allocator.dupe(u8, backing_name);
        return std.mem.concat(m.allocator, u8, &.{ self.backing_path, "/", backing_name });
    }
};

/// Hide symlinks instead of traversing them.
fn openSubdir(m: *Mount, dir: std.Io.Dir, name: []const u8, iterate: bool) !std.Io.Dir {
    // Linux and macOS report symlinks as SymLinkLoop and NotDir respectively.
    return dir.openDir(m.io, name, .{ .follow_symlinks = false, .iterate = iterate }) catch |err| switch (err) {
        error.SymLinkLoop, error.NotDir => error.FileNotFound,
        else => err,
    };
}

/// Resolve a plaintext directory path without escaping the backing root through symlinks.
/// With `check`, require search permission on every directory traversed.
fn walkParent(m: *Mount, dir_path: []const u8, check: bool) !Parent {
    const io = m.io;
    var dir = try m.root.openDir(io, ".", .{});
    errdefer dir.close(io);
    var backing: std.ArrayList(u8) = .empty;
    errdefer backing.deinit(m.allocator);
    var st = try fuse.statFd(dir.handle);
    if (check) try requireAllowed(m, &st, .{ .x = true });

    var it = std.mem.tokenizeScalar(u8, dir_path, '/');
    while (it.next()) |component| {
        if (!utils.isPlainComponent(component)) return error.UnsafePath;
        const name = try m.mapper.toBacking(m.allocator, component, .directory);
        defer m.allocator.free(name);
        if (names.Mapper.isReserved(name)) return error.FileNotFound;
        const child = try openSubdir(m, dir, name, false);
        dir.close(io);
        dir = child;
        if (check or it.peek() == null) {
            st = try fuse.statFd(dir.handle);
            if (check) try requireAllowed(m, &st, .{ .x = true });
        }
        if (backing.items.len != 0) try backing.append(m.allocator, '/');
        try backing.appendSlice(m.allocator, name);
    }
    return .{ .dir = dir, .backing_path = try backing.toOwnedSlice(m.allocator), .st = st };
}

const Located = struct {
    backing_name: []u8,
    kind: names.Kind,
    st: fuse.Stat,
};

/// In suffix mode, file "x.enc" takes precedence over directory "x".
/// An oversized file spelling must not hide a valid directory spelling.
fn locate(m: *Mount, parent: std.Io.Dir, name: []const u8) !Located {
    if (!utils.isPlainComponent(name)) return error.UnsafePath;
    const file_name: ?[]u8 = m.mapper.toBacking(m.allocator, name, .file) catch |err| switch (err) {
        error.NameTooLong => null,
        else => return err,
    };
    if (file_name) |fname| {
        errdefer m.allocator.free(fname);
        if (names.Mapper.isReserved(fname)) return error.FileNotFound;
        if (try statAt(parent, fname)) |st| {
            if (S.ISREG(modeOf(&st))) return .{ .backing_name = fname, .kind = .file, .st = st };
            if (!m.mapper.kindsDiffer() and S.ISDIR(modeOf(&st))) return .{ .backing_name = fname, .kind = .directory, .st = st };
        }
        m.allocator.free(fname);
    }
    if (!m.mapper.kindsDiffer()) return error.FileNotFound;
    const dir_name = try m.mapper.toBacking(m.allocator, name, .directory);
    if (try statAt(parent, dir_name)) |st| {
        if (S.ISDIR(modeOf(&st))) return .{ .backing_name = dir_name, .kind = .directory, .st = st };
    }
    m.allocator.free(dir_name);
    return error.FileNotFound;
}

const Resolved = struct {
    parent: Parent,
    backing_name: []u8,
    /// Relative to the backing root.
    backing_path: []u8,
    kind: names.Kind,
    st: fuse.Stat,
    is_root: bool,

    fn deinit(self: *Resolved, m: *Mount) void {
        self.parent.deinit(m);
        m.allocator.free(self.backing_name);
        m.allocator.free(self.backing_path);
    }
};

fn resolve(m: *Mount, path: []const u8, check: bool) !Resolved {
    const split = splitPath(path) orelse {
        var parent = try walkParent(m, "/", false);
        errdefer parent.deinit(m);
        return .{
            .parent = parent,
            .backing_name = try m.allocator.dupe(u8, "."),
            .backing_path = try m.allocator.dupe(u8, "."),
            .kind = .directory,
            .st = parent.st,
            .is_root = true,
        };
    };
    var parent = try walkParent(m, split.dir, check);
    errdefer parent.deinit(m);
    const located = try locate(m, parent.dir, split.name);
    errdefer m.allocator.free(located.backing_name);
    const backing_path = try parent.childPath(m, located.backing_name);
    return .{
        .parent = parent,
        .backing_name = located.backing_name,
        .backing_path = backing_path,
        .kind = located.kind,
        .st = located.st,
        .is_root = false,
    };
}

/// Caller-owned parent directory, resolved without following symlinks.
fn parentOf(m: *Mount, backing_path: []const u8) !std.Io.Dir {
    return (try utils.openParentIn(m.io, m.root, backing_path, false)) orelse error.FileNotFound;
}

fn openBackingIn(m: *Mount, parent: std.Io.Dir, backing_path: []const u8, mode: std.Io.Dir.OpenFileOptions.Mode) !std.Io.File {
    return parent.openFile(m.io, std.fs.path.basename(backing_path), .{ .mode = mode, .follow_symlinks = false, .allow_directory = false });
}

/// Load through the original open handle so later permission changes cannot revoke access.
/// The caller must hold the node lock.
///
/// Without a retained handle, reopen the node's current backing path.
fn ensureLoaded(m: *Mount, node: *Node, handle: ?*FileHandle) !void {
    if (node.loaded) {
        if (handle) |h| h.closeBacking(m.io);
        return;
    }
    if (handle) |h| {
        if (h.backing) |file| {
            try loadFrom(m, node, file);
            h.closeBacking(m.io);
            return;
        }
    }
    var parent = try parentOf(m, node.path);
    defer parent.close(m.io);
    const file = try openBackingIn(m, parent, node.path, .read_only);
    defer file.close(m.io);
    try loadFrom(m, node, file);
}

fn loadFrom(m: *Mount, node: *Node, file: std.Io.File) !void {
    const size = (try file.stat(m.io)).size;
    node.load(&m.table, file, size, m.keys, m.io) catch |err| {
        if (isDataError(err)) std.debug.print("turbocrypt mount: cannot decrypt {s}: wrong key or damaged file ({s})\n", .{ node.path, @errorName(err) });
        return err;
    };
}

fn fallbackFor(parent: std.Io.Dir, name: []const u8) !node_mod.Fallback {
    if (try statAt(parent, name)) |st| {
        return .{ .mode = @intCast(modeOf(&st) & 0o7777), .uid = st.uid, .gid = st.gid };
    }
    return .{ .mode = 0o644, .uid = null, .gid = null };
}

/// The caller must hold the node lock.
fn writeBackNode(m: *Mount, node: *Node, durable: bool) !void {
    var parent = try parentOf(m, node.path);
    defer parent.close(m.io);
    const name = std.fs.path.basename(node.path);
    const fallback = try fallbackFor(parent, name);
    try node_mod.writeBack(node, &m.table, parent, name, fallback, m.keys, &m.marks, durable, m.io);
}

/// Retain failed writes for retry and report them even when close cannot return the error.
fn flushNode(m: *Mount, node: *Node, durable: bool) !void {
    if (!node.dirty or node.unlinked.load(.acquire)) return;
    writeBackNode(m, node, durable) catch |err| {
        m.countFailure();
        std.debug.print("turbocrypt mount: cannot write back {s}: {s}; the data stays in memory and the next flush retries\n", .{ node.path, @errorName(err) });
        return err;
    };
}

/// Null if the parent cannot be resolved.
fn parentKeyOf(m: *Mount, backing_path: []const u8) ?node_mod.MarkKey {
    var parent = parentOf(m, backing_path) catch return null;
    defer parent.close(m.io);
    const st = fuse.statFd(parent.handle) catch return null;
    return node_mod.markKey(st);
}

fn getattr(m: *Mount, path: []const u8, st: *fuse.Stat, fi: ?*fuse.FileInfo) !void {
    var resolved = try resolve(m, path, fi == null);
    defer resolved.deinit(m);
    st.* = resolved.st;
    if (resolved.kind != .file) return;

    st.size = if (resolved.st.size >= node_mod.overhead) resolved.st.size - node_mod.overhead else 0;
    const pinned: ?*Node = if (fi == null) m.table.pin(resolved.backing_path) else null;
    defer if (pinned) |p| m.table.release(p);
    const node = if (fi) |info| (try handleOf(FileHandle, info)).node else pinned orelse return;
    node.mutex.lockUncancelable(m.io);
    defer node.mutex.unlock(m.io);
    if (node.loaded) st.size = @intCast(node.len());
    if (node.times) |times| setTimes(st, times);
    if (node.mode) |mode| st.mode = @intCast((modeOf(st) & S.IFMT) | (mode & 0o7777));
    if (node.uid) |uid| st.uid = uid;
    if (node.gid) |gid| st.gid = gid;
}

fn access(m: *Mount, path: []const u8, mask: c_int) !void {
    var resolved = try resolve(m, path, true);
    defer resolved.deinit(m);
    const want: Want = .{ .r = mask & 4 != 0, .w = mask & 2 != 0, .x = mask & 1 != 0 };
    if (want.w) try requireWritable(m);
    try requireAllowed(m, &resolved.st, want);
}

fn opendir(m: *Mount, path: []const u8, fi: *fuse.FileInfo) !void {
    var resolved = try resolve(m, path, true);
    defer resolved.deinit(m);
    if (resolved.kind != .directory) return error.NotDir;
    try requireAllowed(m, &resolved.st, .{ .r = true, .x = true });
    var dir = try openSubdir(m, resolved.parent.dir, resolved.backing_name, true);
    errdefer dir.close(m.io);
    const handle = try m.allocator.create(DirHandle);
    errdefer m.allocator.destroy(handle);
    handle.* = .{ .dir = dir, .key = node_mod.markKey(resolved.st) };
    fi.fh = @intFromPtr(handle);
}

fn readdir(m: *Mount, buf: ?*anyopaque, filler: fuse.FillDir, fi: ?*fuse.FileInfo) !void {
    const handle = try handleOf(DirHandle, fi);
    _ = filler(buf, ".", null, 0, 0);
    _ = filler(buf, "..", null, 0, 0);
    var it = handle.dir.iterate();
    while (try it.next(m.io)) |entry| {
        const kind: names.Kind = switch (entry.kind) {
            .file => .file,
            .directory => .directory,
            else => continue,
        };
        const plain = (try m.mapper.toPlain(m.allocator, entry.name, kind)) orelse continue;
        defer m.allocator.free(plain);
        var buffer: [std.fs.max_name_bytes + 1]u8 = undefined;
        const name_z = withSentinel(plain, &buffer) catch continue;
        var st: fuse.Stat = std.mem.zeroes(fuse.Stat);
        st.mode = if (kind == .file) S.IFREG else S.IFDIR;
        _ = filler(buf, name_z, &st, 0, 0);
    }
}

fn releasedir(m: *Mount, fi: ?*fuse.FileInfo) !void {
    const handle = try handleOf(DirHandle, fi);
    handle.dir.close(m.io);
    m.allocator.destroy(handle);
}

fn openFlags(fi: *const fuse.FileInfo) std.posix.O {
    return @bitCast(@as(u32, @bitCast(fi.flags)));
}

fn attachHandle(m: *Mount, resolved: *const Resolved, fi: *fuse.FileInfo, want: Want, truncate_first: bool) !void {
    const flags = openFlags(fi);
    const node = try m.table.attach(resolved.backing_path);
    errdefer m.table.release(node);
    var backing: ?std.Io.File = null;
    errdefer if (backing) |file| file.close(m.io);
    {
        node.mutex.lockUncancelable(m.io);
        defer node.mutex.unlock(m.io);
        if (node.times == null) node.times = timesOf(&resolved.st);
        if (truncate_first) try node.truncate(&m.table, 0, nowSpec(m.io));
        // Preserve current access for the deferred load; retry at load time if open fails.
        if (!node.loaded) backing = openBackingIn(m, resolved.parent.dir, resolved.backing_path, .read_only) catch null;
    }
    const handle = try m.allocator.create(FileHandle);
    handle.* = .{ .node = node, .read = want.r, .write = want.w, .append = flags.APPEND, .backing = backing };
    fi.fh = @intFromPtr(handle);
}

fn open(m: *Mount, path: []const u8, fi: *fuse.FileInfo) !void {
    const flags = openFlags(fi);
    const want: Want = .{ .r = flags.ACCMODE != .WRONLY, .w = flags.ACCMODE != .RDONLY };
    if (want.w) try requireWritable(m);
    var resolved = try resolve(m, path, true);
    defer resolved.deinit(m);
    if (resolved.kind != .file) return error.IsDir;
    try requireAllowed(m, &resolved.st, want);
    if (want.w) try requireReproducible(m, &resolved.st, &resolved.parent.st, path);
    const truncating = want.w and flags.TRUNC;
    // Reject truncated ciphertext here because a zero-length file may never receive a read request.
    if (resolved.st.size < node_mod.overhead and !truncating) {
        std.debug.print("turbocrypt mount: {s} is too short to be an encrypted file\n", .{path});
        return error.InvalidFileSize;
    }
    if (resolved.st.size - node_mod.overhead > m.options.max_file_size) return error.FileTooBig;
    try attachHandle(m, &resolved, fi, want, truncating);
}

fn create(m: *Mount, path: []const u8, mode: fuse.mode_t, fi: *fuse.FileInfo) !void {
    try requireWritable(m);
    const split = splitPath(path) orelse return error.PathAlreadyExists;
    var parent = try walkParent(m, split.dir, true);
    defer parent.deinit(m);
    try requireAllowed(m, &parent.st, .{ .w = true, .x = true });
    if (!utils.isPlainComponent(split.name)) return error.UnsafePath;
    const backing_name = try m.mapper.toBacking(m.allocator, split.name, .file);
    defer m.allocator.free(backing_name);
    if (names.Mapper.isReserved(backing_name)) return error.PermissionDenied;
    const owner = try requiredOwnership(m, &parent.st);

    // Allocate before publishing so allocation failure leaves no file behind.
    const backing_path = try parent.childPath(m, backing_name);
    defer m.allocator.free(backing_path);
    const handle = try m.allocator.create(FileHandle);
    errdefer m.allocator.destroy(handle);
    const node = try m.table.attach(backing_path);
    errdefer m.table.release(node);
    var change = try m.marks.begin(parent.dir, parent.key());
    defer change.deinit();

    // Publish only a complete ciphertext, even for an empty file.
    {
        var atomic = try processor.AtomicOutput.createIn(parent.dir, .{ .permissions = .fromMode(0o600) }, m.allocator, m.io);
        defer atomic.deinit(m.io);
        var empty: [node_mod.overhead]u8 = undefined;
        crypto.encryptZeroCopy(&empty, "", m.keys, m.io);
        if (node_mod.takeFault(.create_write)) return error.InputOutput;
        try atomic.file.writeStreamingAll(m.io, &empty);
        if (std.c.fchmod(atomic.file.handle, mode) != 0) return error.AccessDenied;
        if (owner) |o| {
            if (std.c.fchown(atomic.file.handle, o.uid, o.gid) != 0) return error.PermissionDenied;
        }
        try std.Io.Dir.hardLink(parent.dir, atomic.tmp_path, parent.dir, backing_name, m.io, .{});
    }
    change.commit();

    const flags = openFlags(fi);
    handle.* = .{ .node = node, .read = flags.ACCMODE != .WRONLY, .write = true, .append = flags.APPEND };
    fi.fh = @intFromPtr(handle);
    node.mutex.lockUncancelable(m.io);
    defer node.mutex.unlock(m.io);
    const now = nowSpec(m.io);
    node.times = .{ .atime = now, .mtime = now, .ctime = now };
    node.mode = mode & 0o7777;
    if (owner) |o| {
        node.uid = o.uid;
        node.gid = o.gid;
    }
    if (node.loaded) {
        // A recreated file must not inherit stale data from a retained node.
        try node.truncate(&m.table, 0, now);
    } else {
        node.loaded = true;
    }
}

fn read(m: *Mount, buf: [*]u8, size: usize, offset: fuse.off_t, fi: ?*fuse.FileInfo) !usize {
    const handle = try handleOf(FileHandle, fi);
    if (!handle.read) return error.BadHandle;
    const node = handle.node;
    node.mutex.lockUncancelable(m.io);
    defer node.mutex.unlock(m.io);
    try ensureLoaded(m, node, handle);
    if (offset < 0) return error.UnsafePath;
    const start: u64 = @intCast(offset);
    if (start >= node.len()) return 0;
    const n: usize = @intCast(@min(size, node.len() - start));
    @memcpy(buf[0..n], node.plaintext[@intCast(start)..][0..n]);
    return n;
}

fn write(m: *Mount, buf: [*]const u8, size: usize, offset: fuse.off_t, fi: ?*fuse.FileInfo) !usize {
    try requireWritable(m);
    const handle = try handleOf(FileHandle, fi);
    if (!handle.write) return error.BadHandle;
    if (offset < 0) return error.UnsafePath;
    const node = handle.node;
    node.mutex.lockUncancelable(m.io);
    defer node.mutex.unlock(m.io);
    try ensureLoaded(m, node, handle);
    const at: u64 = if (handle.append) node.len() else @intCast(offset);
    try node.write(&m.table, at, buf[0..size], nowSpec(m.io));
    return size;
}

fn truncate(m: *Mount, path: []const u8, size: fuse.off_t, fi: ?*fuse.FileInfo) !void {
    try requireWritable(m);
    if (size < 0) return error.UnsafePath;
    const new_len: u64 = @intCast(size);
    if (fi) |info| {
        const handle = try handleOf(FileHandle, info);
        if (!handle.write) return error.BadHandle;
        const node = handle.node;
        node.mutex.lockUncancelable(m.io);
        defer node.mutex.unlock(m.io);
        if (new_len != 0) try ensureLoaded(m, node, handle);
        return node.truncate(&m.table, new_len, nowSpec(m.io));
    }
    var resolved = try resolve(m, path, true);
    defer resolved.deinit(m);
    if (resolved.kind != .file) return error.IsDir;
    try requireAllowed(m, &resolved.st, .{ .w = true });
    try requireReproducible(m, &resolved.st, &resolved.parent.st, path);
    const node = try m.table.attach(resolved.backing_path);
    defer m.table.release(node);
    node.mutex.lockUncancelable(m.io);
    defer node.mutex.unlock(m.io);
    if (node.times == null) node.times = timesOf(&resolved.st);
    if (new_len != 0) try ensureLoaded(m, node, null);
    try node.truncate(&m.table, new_len, nowSpec(m.io));
    // A truncate by path has no later release to flush its changes.
    try flushNode(m, node, false);
}

fn flush(m: *Mount, fi: ?*fuse.FileInfo) !void {
    const handle = try handleOf(FileHandle, fi);
    const node = handle.node;
    node.mutex.lockUncancelable(m.io);
    defer node.mutex.unlock(m.io);
    try flushNode(m, node, false);
}

fn fsync(m: *Mount, fi: ?*fuse.FileInfo) !void {
    const handle = try handleOf(FileHandle, fi);
    const node = handle.node;
    node.mutex.lockUncancelable(m.io);
    defer node.mutex.unlock(m.io);
    if (node.unlinked.load(.acquire)) return;
    if (node.dirty) return flushNode(m, node, true);
    // Sync clean files too: metadata may have changed while no node existed.
    var parent = try parentOf(m, node.path);
    defer parent.close(m.io);
    {
        const file = try openBackingIn(m, parent, node.path, .read_only);
        defer file.close(m.io);
        node_mod.syncFd(file.handle, .metadata_sync) catch |err| {
            m.countFailure();
            std.debug.print("turbocrypt mount: cannot sync {s}: {s}\n", .{ node.path, @errorName(err) });
            return err;
        };
    }
    const key = node_mod.markKey(try fuse.statFd(parent.handle));
    node_mod.syncMark(&m.marks, key) catch |err| {
        m.countFailure();
        std.debug.print("turbocrypt mount: cannot sync the directory of {s}: {s}\n", .{ node.path, @errorName(err) });
        return err;
    };
}

fn release(m: *Mount, fi: ?*fuse.FileInfo) !void {
    const handle = try handleOf(FileHandle, fi);
    const node = handle.node;
    {
        node.mutex.lockUncancelable(m.io);
        defer node.mutex.unlock(m.io);
        flushNode(m, node, false) catch {};
    }
    handle.closeBacking(m.io);
    m.table.release(node);
    m.allocator.destroy(handle);
}

fn fsyncdir(m: *Mount, fi: ?*fuse.FileInfo) !void {
    const handle = try handleOf(DirHandle, fi);
    var first_error: ?anyerror = null;
    const pinned = try m.table.pinAll(m.allocator);
    defer m.allocator.free(pinned);
    for (pinned) |node| {
        defer m.table.release(node);
        node.mutex.lockUncancelable(m.io);
        defer node.mutex.unlock(m.io);
        if (!node.dirty or node.unlinked.load(.acquire)) continue;
        // Directory identity survives a rename while this handle is open.
        const parent_key = parentKeyOf(m, node.path) orelse continue;
        if (parent_key.dev != handle.key.dev or parent_key.ino != handle.key.ino) continue;
        flushNode(m, node, true) catch |err| {
            if (first_error == null) first_error = err;
        };
    }
    if (m.marks.pin(handle.key)) |pinned_mark| {
        const synced = node_mod.syncFd(pinned_mark.dir.handle, .dir_sync);
        m.marks.unpin(handle.key, pinned_mark.generation, if (synced) true else |_| false);
        synced catch |err| {
            m.countFailure();
            if (first_error == null) first_error = err;
        };
    } else {
        node_mod.syncFd(handle.dir.handle, .dir_sync) catch |err| {
            m.countFailure();
            if (first_error == null) first_error = err;
        };
    }
    if (first_error) |err| return err;
}

fn mkdir(m: *Mount, path: []const u8, mode: fuse.mode_t) !void {
    try requireWritable(m);
    const split = splitPath(path) orelse return error.PathAlreadyExists;
    var parent = try walkParent(m, split.dir, true);
    defer parent.deinit(m);
    try requireAllowed(m, &parent.st, .{ .w = true, .x = true });
    if (!utils.isPlainComponent(split.name)) return error.UnsafePath;
    const backing_name = try m.mapper.toBacking(m.allocator, split.name, .directory);
    defer m.allocator.free(backing_name);
    if (names.Mapper.isReserved(backing_name)) return error.PermissionDenied;
    const owner = try requiredOwnership(m, &parent.st);

    var change = try m.marks.begin(parent.dir, parent.key());
    defer change.deinit();
    try parent.dir.createDir(m.io, backing_name, .fromMode(mode & 0o7777));
    if (owner) |o| {
        giveEntry(parent.dir, backing_name, o) catch |err| {
            parent.dir.deleteDir(m.io, backing_name) catch {};
            return err;
        };
    }
    change.commit();
}

fn giveEntry(dir: std.Io.Dir, name: []const u8, owner: Ownership) !void {
    var buffer: [std.fs.max_name_bytes + 1]u8 = undefined;
    const name_z = try withSentinel(name, &buffer);
    if (std.c.fchownat(dir.handle, name_z, owner.uid, owner.gid, at_nofollow) != 0) return error.PermissionDenied;
}

fn unlink(m: *Mount, path: []const u8) !void {
    try requireWritable(m);
    var resolved = try resolve(m, path, true);
    defer resolved.deinit(m);
    if (resolved.kind != .file) return error.IsDir;
    try requireAllowed(m, &resolved.parent.st, .{ .w = true, .x = true });
    if (!stickyAllows(&resolved.parent.st, &resolved.st)) return error.PermissionDenied;

    // Prevent a concurrent write-back from resurrecting the deleted file.
    const node = lockNodeOf(m, &resolved);
    defer unlockNode(m, node);
    var change = try m.marks.begin(resolved.parent.dir, resolved.parent.key());
    defer change.deinit();
    try resolved.parent.dir.deleteFile(m.io, resolved.backing_name);
    change.commit();
    if (node) |n| n.unlinked.store(true, .release);
}

fn rmdir(m: *Mount, path: []const u8) !void {
    try requireWritable(m);
    var resolved = try resolve(m, path, true);
    defer resolved.deinit(m);
    if (resolved.is_root) return error.FileBusy;
    if (resolved.kind != .directory) return error.NotDir;
    try requireAllowed(m, &resolved.parent.st, .{ .w = true, .x = true });
    if (!stickyAllows(&resolved.parent.st, &resolved.st)) return error.PermissionDenied;

    var change = try m.marks.begin(resolved.parent.dir, resolved.parent.key());
    defer change.deinit();
    try resolved.parent.dir.deleteDir(m.io, resolved.backing_name);
    m.marks.drop(node_mod.markKey(resolved.st));
    change.commit();
}

fn rename(m: *Mount, from: []const u8, to: []const u8, flags: c_uint) !void {
    try requireWritable(m);
    if (flags & fuse.rename_exchange != 0) return error.NotSupported;
    var source = try resolve(m, from, true);
    defer source.deinit(m);
    if (source.is_root) return error.FileBusy;
    try requireAllowed(m, &source.parent.st, .{ .w = true, .x = true });
    if (!stickyAllows(&source.parent.st, &source.st)) return error.PermissionDenied;

    const split = splitPath(to) orelse return error.PathAlreadyExists;
    var target_parent = try walkParent(m, split.dir, true);
    defer target_parent.deinit(m);
    try requireAllowed(m, &target_parent.st, .{ .w = true, .x = true });
    if (!utils.isPlainComponent(split.name)) return error.UnsafePath;
    const target_name = try m.mapper.toBacking(m.allocator, split.name, source.kind);
    defer m.allocator.free(target_name);
    if (names.Mapper.isReserved(target_name)) return error.PermissionDenied;
    const noreplace = flags & fuse.rename_noreplace != 0;
    if (noreplace or modeOf(&target_parent.st) & S.ISVTX != 0) {
        if (try statAt(target_parent.dir, target_name)) |existing| {
            if (noreplace) return error.PathAlreadyExists;
            if (!stickyAllows(&target_parent.st, &existing)) return error.PermissionDenied;
        }
    }
    const target_path = try target_parent.childPath(m, target_name);
    defer m.allocator.free(target_path);
    // A rename onto itself must not unlink its own node.
    if (std.mem.eql(u8, source.backing_path, target_path)) return;

    var source_change = try m.marks.begin(source.parent.dir, source.parent.key());
    defer source_change.deinit();
    var target_change = try m.marks.begin(target_parent.dir, target_parent.key());
    defer target_change.deinit();

    var rekey = try m.table.beginRekey(source.backing_path, target_path, source.kind == .directory);
    const renamed = if (noreplace)
        std.Io.Dir.renamePreserve(source.parent.dir, source.backing_name, target_parent.dir, target_name, m.io)
    else
        std.Io.Dir.rename(source.parent.dir, source.backing_name, target_parent.dir, target_name, m.io);
    renamed catch |err| {
        rekey.abort();
        return err;
    };
    rekey.commit();
    source_change.commit();
    target_change.commit();
}

const Recorded = struct {
    mode: ?std.c.mode_t = null,
    uid: ?std.c.uid_t = null,
    gid: ?std.c.gid_t = null,
    atime: ?std.c.timespec = null,
    mtime: ?std.c.timespec = null,
};

/// Pin and lock an existing node so write-back cannot undo a metadata change.
/// Null means no node exists; release with unlockNode.
fn lockNodeOf(m: *Mount, resolved: *const Resolved) ?*Node {
    if (resolved.kind != .file) return null;
    const node = m.table.pin(resolved.backing_path) orelse return null;
    node.mutex.lockUncancelable(m.io);
    return node;
}

fn unlockNode(m: *Mount, node: ?*Node) void {
    const n = node orelse return;
    n.mutex.unlock(m.io);
    m.table.release(n);
}

fn checkMetadataCall(rc: c_int) !void {
    if (rc == 0) return;
    return switch (std.c.errno(rc)) {
        .PERM => error.PermissionDenied,
        .ACCES => error.AccessDenied,
        .ROFS => error.ReadOnlyFileSystem,
        else => error.Unexpected,
    };
}

fn recordOnNode(m: *Mount, node: *Node, values: Recorded) void {
    if (values.mode) |mode| node.mode = mode;
    if (values.uid) |uid| node.uid = uid;
    if (values.gid) |gid| node.gid = gid;
    if (node.times) |*times| {
        if (values.atime) |atime| times.atime = atime;
        if (values.mtime) |mtime| times.mtime = mtime;
        times.ctime = nowSpec(m.io);
    }
}

fn chmod(m: *Mount, path: []const u8, mode: fuse.mode_t) !void {
    try requireWritable(m);
    var resolved = try resolve(m, path, true);
    defer resolved.deinit(m);
    if (!isOwner(&resolved.st)) return error.PermissionDenied;
    var buffer: [std.fs.max_name_bytes + 1]u8 = undefined;
    const name_z = try withSentinel(resolved.backing_name, &buffer);
    const bits: std.c.mode_t = mode & 0o7777;
    const node = lockNodeOf(m, &resolved);
    defer unlockNode(m, node);
    try checkMetadataCall(std.c.fchmodat(resolved.parent.dir.handle, name_z, bits, at_nofollow));
    if (node) |n| recordOnNode(m, n, .{ .mode = bits });
}

fn chown(
    m: *Mount,
    path: []const u8,
    uid: std.c.uid_t,
    gid: std.c.gid_t,
) !void {
    try requireWritable(m);
    var resolved = try resolve(m, path, true);
    defer resolved.deinit(m);
    const ctx = context();
    const unchanged_uid: std.c.uid_t = std.math.maxInt(std.c.uid_t);
    const unchanged_gid: std.c.gid_t = std.math.maxInt(std.c.gid_t);
    const new_uid: ?std.c.uid_t = if (uid != unchanged_uid and uid != resolved.st.uid) uid else null;
    const new_gid: ?std.c.gid_t = if (gid != unchanged_gid and gid != resolved.st.gid) gid else null;
    if (ctx.uid != 0) {
        if (new_uid != null) return error.PermissionDenied;
        if (new_gid) |g| {
            if (ctx.uid != resolved.st.uid) return error.PermissionDenied;
            if (g != ctx.gid) {
                const groups = try callerGroups(m.allocator);
                defer m.allocator.free(groups);
                if (std.mem.indexOfScalar(std.c.gid_t, groups, g) == null) return error.PermissionDenied;
            }
        }
    }
    var buffer: [std.fs.max_name_bytes + 1]u8 = undefined;
    const name_z = try withSentinel(resolved.backing_name, &buffer);
    const node = lockNodeOf(m, &resolved);
    defer unlockNode(m, node);
    try checkMetadataCall(std.c.fchownat(resolved.parent.dir.handle, name_z, new_uid orelse unchanged_uid, new_gid orelse unchanged_gid, at_nofollow));
    if (node) |n| recordOnNode(m, n, .{ .uid = new_uid, .gid = new_gid });
}

fn isNow(ts: std.c.timespec) bool {
    return ts.nsec == std.c.UTIME.NOW.nsec;
}

fn isOmit(ts: std.c.timespec) bool {
    return ts.nsec == std.c.UTIME.OMIT.nsec;
}

fn utimens(m: *Mount, path: []const u8, tv: *const [2]std.c.timespec) !void {
    try requireWritable(m);
    var resolved = try resolve(m, path, true);
    defer resolved.deinit(m);
    const explicit = !((isNow(tv[0]) or isOmit(tv[0])) and (isNow(tv[1]) or isOmit(tv[1])));
    if (explicit) {
        if (!isOwner(&resolved.st)) return error.PermissionDenied;
    } else if (!isOwner(&resolved.st)) {
        try requireAllowed(m, &resolved.st, .{ .w = true });
    }
    var buffer: [std.fs.max_name_bytes + 1]u8 = undefined;
    const name_z = try withSentinel(resolved.backing_name, &buffer);
    const node = lockNodeOf(m, &resolved);
    defer unlockNode(m, node);
    try checkMetadataCall(std.c.utimensat(resolved.parent.dir.handle, name_z, tv, at_nofollow));
    const n = node orelse return;
    const now = nowSpec(m.io);
    recordOnNode(m, n, .{
        .atime = if (isOmit(tv[0])) null else if (isNow(tv[0])) now else tv[0],
        .mtime = if (isOmit(tv[1])) null else if (isNow(tv[1])) now else tv[1],
    });
}

fn statfs(m: *Mount, buf: *fuse.Statvfs) !void {
    if (fstatvfs(m.root.handle, buf) != 0) return error.Unexpected;
    buf.namemax = @intCast(m.mapper.nameMax());
}

/// Enforce the path and inode assumptions required by the callbacks.
fn init(m: *Mount, cfg: *fuse.Config) void {
    const forced = [_]struct { name: []const u8, value: *i32 }{
        .{ .name = "use_ino", .value = &cfg.use_ino },
        .{ .name = "readdir_ino", .value = &cfg.readdir_ino },
        .{ .name = "hard_remove", .value = &cfg.hard_remove },
    };
    for (forced) |field| {
        if (field.value.* != 0) {
            std.debug.print("turbocrypt mount: forcing {s} back to 0\n", .{field.name});
            field.value.* = 0;
        }
    }
    m.up.store(true, .seq_cst);
    if (m.options.ready_fd) |fd| {
        _ = std.c.write(fd, "1", 1);
        _ = std.c.close(fd);
        m.options.ready_fd = null;
        return;
    }
    std.debug.print("Mounted {s} on {s}\nThe command stays here until the volume is unmounted. Stop it with: turbocrypt unmount {s}\n", .{ m.options.backing, m.options.mountpoint, m.options.mountpoint });
}

/// Make pending changes durable at unmount and rescue files that still cannot be written back.
fn destroy(m: *Mount) void {
    // Workers have stopped, so avoid allocating pins that could prevent recovery under memory pressure.
    for (m.table.nodes.items) |node| {
        node.mutex.lockUncancelable(m.io);
        defer node.mutex.unlock(m.io);
        if (!node.dirty or node.unlinked.load(.acquire)) continue;
        if (writeBackNode(m, node, true)) |_| continue else |err| {
            m.countFailure();
            m.lost.store(true, .seq_cst);
            std.debug.print("turbocrypt mount: cannot write back {s} at unmount: {s}\n", .{ node.path, @errorName(err) });
            rescue(m, node);
        }
    }
    const keys = m.marks.pendingKeys(m.allocator) catch {
        m.countFailure();
        std.debug.print("turbocrypt mount: out of memory at unmount, {d} marked directories not synced\n", .{m.marks.count()});
        std.crypto.secureZero(u8, std.mem.asBytes(&m.keys));
        return;
    };
    defer m.allocator.free(keys);
    for (keys) |key| {
        node_mod.syncMark(&m.marks, key) catch |err| {
            m.countFailure();
            std.debug.print("turbocrypt mount: cannot sync a directory at unmount: {s}\n", .{@errorName(err)});
        };
    }
    std.crypto.secureZero(u8, std.mem.asBytes(&m.keys));
}

fn rescue(m: *Mount, node: *Node) void {
    rescueNode(m, node) catch |err| {
        m.countFailure();
        std.debug.print("turbocrypt mount: the rescue copy of {s} failed too ({s}); the data is lost\n", .{ node.path, @errorName(err) });
    };
}

fn rescueNode(m: *Mount, node: *Node) !void {
    const io = m.io;
    try utils.ensureDirectory(m.options.rescue_dir, io);
    var dir = try std.Io.Dir.openDir(.cwd(), io, m.options.rescue_dir, .{});
    defer dir.close(io);
    try dir.setPermissions(io, .fromMode(0o700));
    var rand: u64 = undefined;
    io.random(std.mem.asBytes(&rand));
    var data_name: [16 + 4]u8 = undefined;
    _ = std.fmt.bufPrint(&data_name, "{x:0>16}.enc", .{rand}) catch unreachable;
    var path_name: [16 + 5]u8 = undefined;
    _ = std.fmt.bufPrint(&path_name, "{x:0>16}.path", .{rand}) catch unreachable;
    // A failed write-back may have left stale ciphertext in the buffer.
    crypto.encryptZeroCopy(node.ciphertextSlice(), node.plaintext, m.keys, io);
    try processor.writeFileAtomicIn(dir, &data_name, node.ciphertextSlice(), .fromMode(0o600), null, m.allocator, io);
    try processor.writeFileAtomicIn(dir, &path_name, node.path, .fromMode(0o600), null, m.allocator, io);
    std.debug.print("turbocrypt mount: the ciphertext of {s} is saved as {s}/{s}; decrypt it with the same key\n", .{ node.path, m.options.rescue_dir, data_name });
}

fn cGetattr(path: [*:0]const u8, st: *fuse.Stat, fi: ?*fuse.FileInfo) callconv(.c) c_int {
    const m = mount();
    return result(m, getattr(m, std.mem.span(path), st, fi));
}

fn cReadlink(_: [*:0]const u8, _: [*]u8, _: usize) callconv(.c) c_int {
    return fuse.negErrno(.OPNOTSUPP);
}

fn cMknod(_: [*:0]const u8, _: fuse.mode_t, _: std.c.dev_t) callconv(.c) c_int {
    return fuse.negErrno(.OPNOTSUPP);
}

fn cMkdir(path: [*:0]const u8, mode: fuse.mode_t) callconv(.c) c_int {
    const m = mount();
    return result(m, mkdir(m, std.mem.span(path), mode));
}

fn cUnlink(path: [*:0]const u8) callconv(.c) c_int {
    const m = mount();
    return result(m, unlink(m, std.mem.span(path)));
}

fn cRmdir(path: [*:0]const u8) callconv(.c) c_int {
    const m = mount();
    return result(m, rmdir(m, std.mem.span(path)));
}

fn cSymlink(_: [*:0]const u8, _: [*:0]const u8) callconv(.c) c_int {
    return fuse.negErrno(.OPNOTSUPP);
}

fn cRename(from: [*:0]const u8, to: [*:0]const u8, flags: c_uint) callconv(.c) c_int {
    const m = mount();
    return result(m, rename(m, std.mem.span(from), std.mem.span(to), flags));
}

fn cLink(_: [*:0]const u8, _: [*:0]const u8) callconv(.c) c_int {
    return fuse.negErrno(.OPNOTSUPP);
}

fn cChmod(path: [*:0]const u8, mode: fuse.mode_t, _: ?*fuse.FileInfo) callconv(.c) c_int {
    const m = mount();
    return result(m, chmod(m, std.mem.span(path), mode));
}

fn cChown(path: [*:0]const u8, uid: std.c.uid_t, gid: std.c.gid_t, _: ?*fuse.FileInfo) callconv(.c) c_int {
    const m = mount();
    return result(m, chown(m, std.mem.span(path), uid, gid));
}

fn cTruncate(path: [*:0]const u8, size: fuse.off_t, fi: ?*fuse.FileInfo) callconv(.c) c_int {
    noteSidecar(path);
    const m = mount();
    return result(m, truncate(m, std.mem.span(path), size, fi));
}

fn cOpen(path: [*:0]const u8, fi: *fuse.FileInfo) callconv(.c) c_int {
    const m = mount();
    return result(m, open(m, std.mem.span(path), fi));
}

fn cRead(_: [*:0]const u8, buf: [*]u8, size: usize, offset: fuse.off_t, fi: *fuse.FileInfo) callconv(.c) c_int {
    const m = mount();
    return resultSize(m, read(m, buf, size, offset, fi));
}

fn cWrite(path: [*:0]const u8, buf: [*]const u8, size: usize, offset: fuse.off_t, fi: *fuse.FileInfo) callconv(.c) c_int {
    noteSidecar(path);
    const m = mount();
    return resultSize(m, write(m, buf, size, offset, fi));
}

fn cStatfs(_: [*:0]const u8, buf: *fuse.Statvfs) callconv(.c) c_int {
    const m = mount();
    return result(m, statfs(m, buf));
}

fn cFlush(path: [*:0]const u8, fi: *fuse.FileInfo) callconv(.c) c_int {
    noteSidecar(path);
    const m = mount();
    return result(m, flush(m, fi));
}

fn cRelease(path: [*:0]const u8, fi: *fuse.FileInfo) callconv(.c) c_int {
    noteSidecar(path);
    const m = mount();
    return result(m, release(m, fi));
}

fn cFsync(path: [*:0]const u8, _: c_int, fi: *fuse.FileInfo) callconv(.c) c_int {
    noteSidecar(path);
    const m = mount();
    return result(m, fsync(m, fi));
}

fn cSetxattr(_: [*:0]const u8, _: [*:0]const u8, _: [*]const u8, _: usize, _: c_int) callconv(.c) c_int {
    return fuse.negErrno(.OPNOTSUPP);
}

fn cGetxattr(_: [*:0]const u8, _: [*:0]const u8, _: [*]u8, _: usize) callconv(.c) c_int {
    return fuse.negErrno(.OPNOTSUPP);
}

fn cListxattr(_: [*:0]const u8, _: [*]u8, _: usize) callconv(.c) c_int {
    return fuse.negErrno(.OPNOTSUPP);
}

fn cRemovexattr(_: [*:0]const u8, _: [*:0]const u8) callconv(.c) c_int {
    return fuse.negErrno(.OPNOTSUPP);
}

fn cOpendir(path: [*:0]const u8, fi: *fuse.FileInfo) callconv(.c) c_int {
    const m = mount();
    return result(m, opendir(m, std.mem.span(path), fi));
}

fn cReaddir(_: [*:0]const u8, buf: ?*anyopaque, filler: fuse.FillDir, _: fuse.off_t, fi: *fuse.FileInfo, _: c_uint) callconv(.c) c_int {
    const m = mount();
    return result(m, readdir(m, buf, filler, fi));
}

fn cReleasedir(_: [*:0]const u8, fi: *fuse.FileInfo) callconv(.c) c_int {
    const m = mount();
    return result(m, releasedir(m, fi));
}

fn cFsyncdir(path: [*:0]const u8, _: c_int, fi: *fuse.FileInfo) callconv(.c) c_int {
    noteSidecar(path);
    const m = mount();
    return result(m, fsyncdir(m, fi));
}

fn cInit(_: *fuse.ConnInfo, cfg: *fuse.Config) callconv(.c) ?*anyopaque {
    const m = mount();
    init(m, cfg);
    return @ptrCast(m);
}

fn cDestroy(private: ?*anyopaque) callconv(.c) void {
    const m: *Mount = @ptrCast(@alignCast(private orelse return));
    destroy(m);
}

fn cAccess(path: [*:0]const u8, mask: c_int) callconv(.c) c_int {
    const m = mount();
    return result(m, access(m, std.mem.span(path), mask));
}

fn cCreate(path: [*:0]const u8, mode: fuse.mode_t, fi: *fuse.FileInfo) callconv(.c) c_int {
    noteSidecar(path);
    const m = mount();
    return result(m, create(m, std.mem.span(path), mode, fi));
}

fn cUtimens(path: [*:0]const u8, tv: *const [2]std.c.timespec, _: ?*fuse.FileInfo) callconv(.c) c_int {
    const m = mount();
    return result(m, utimens(m, std.mem.span(path), tv));
}

const testing = std.testing;

fn testStat(mode: u32, uid: u32, gid: u32) fuse.Stat {
    var st: fuse.Stat = std.mem.zeroes(fuse.Stat);
    st.mode = @intCast(mode);
    st.uid = uid;
    st.gid = gid;
    return st;
}

test "filesystem errors map to client errno values" {
    try testing.expectEqual(fuse.negErrno(.NOENT), errnoFor(error.FileNotFound));
    try testing.expectEqual(fuse.negErrno(.ACCES), errnoFor(error.AccessDenied));
    try testing.expectEqual(fuse.negErrno(.PERM), errnoFor(error.PermissionDenied));
    try testing.expectEqual(fuse.negErrno(.EXIST), errnoFor(error.PathAlreadyExists));
    try testing.expectEqual(fuse.negErrno(.NOSPC), errnoFor(error.NoSpaceLeft));
    try testing.expectEqual(fuse.negErrno(.NOTEMPTY), errnoFor(error.DirNotEmpty));
    try testing.expectEqual(fuse.negErrno(.NAMETOOLONG), errnoFor(error.NameTooLong));
    try testing.expectEqual(fuse.negErrno(.IO), errnoFor(error.InvalidHeaderMac));
    try testing.expectEqual(fuse.negErrno(.IO), errnoFor(error.AuthenticationFailed));
    try testing.expectEqual(fuse.negErrno(.IO), errnoFor(error.InvalidFileSize));
    try testing.expectEqual(fuse.negErrno(.NOMEM), errnoFor(error.OutOfMemory));
    try testing.expectEqual(fuse.negErrno(.FBIG), errnoFor(error.FileTooBig));
    try testing.expectEqual(fuse.negErrno(.ROFS), errnoFor(error.ReadOnlyFileSystem));
    try testing.expectEqual(fuse.negErrno(.OPNOTSUPP), errnoFor(error.NotSupported));
    try testing.expectEqual(fuse.negErrno(.IO), errnoFor(error.Unexpected));
}

test "permissions honor owner, group membership and root" {
    const owner_only = testStat(S.IFREG | 0o600, 501, 20);
    try testing.expect(allowedBy(501, 20, &.{}, &owner_only, .{ .r = true, .w = true }));
    try testing.expect(!allowedBy(502, 20, &.{}, &owner_only, .{ .r = true }));
    try testing.expect(!allowedBy(501, 20, &.{}, &owner_only, .{ .x = true }));

    const group_readable = testStat(S.IFREG | 0o640, 501, 80);
    try testing.expect(!allowedBy(502, 20, &.{}, &group_readable, .{ .r = true }));
    try testing.expect(allowedBy(502, 80, &.{}, &group_readable, .{ .r = true }));
    try testing.expect(allowedBy(502, 20, &.{ 12, 80 }, &group_readable, .{ .r = true }));
    try testing.expect(!allowedBy(502, 80, &.{}, &group_readable, .{ .w = true }));

    const world = testStat(S.IFDIR | 0o755, 0, 0);
    try testing.expect(allowedBy(502, 20, &.{}, &world, .{ .r = true, .x = true }));
    try testing.expect(!allowedBy(502, 20, &.{}, &world, .{ .w = true }));

    try testing.expect(allowedBy(0, 0, &.{}, &owner_only, .{ .r = true, .w = true }));
    try testing.expect(!allowedBy(0, 0, &.{}, &owner_only, .{ .x = true }));
    const script = testStat(S.IFREG | 0o700, 501, 20);
    try testing.expect(allowedBy(0, 0, &.{}, &script, .{ .x = true }));
    const locked_dir = testStat(S.IFDIR | 0o000, 501, 20);
    try testing.expect(allowedBy(0, 0, &.{}, &locked_dir, .{ .x = true }));
}

test "replacement ownership permits inherited groups and requires root for other owners" {
    const mine = testStat(S.IFREG | 0o664, 501, 20);
    try testing.expect(ownershipReproducibleBy(501, 20, &.{}, &mine, 20));
    const my_other_group = testStat(S.IFREG | 0o664, 501, 80);
    try testing.expect(!ownershipReproducibleBy(501, 20, &.{}, &my_other_group, 20));
    try testing.expect(ownershipReproducibleBy(501, 20, &.{ 12, 80 }, &my_other_group, 20));
    // An inherited group needs no membership, such as wheel under a macOS system directory.
    const wheel = testStat(S.IFREG | 0o644, 501, 0);
    try testing.expect(!ownershipReproducibleBy(501, 20, &.{}, &wheel, 20));
    try testing.expect(ownershipReproducibleBy(501, 20, &.{}, &wheel, 0));
    const theirs = testStat(S.IFREG | 0o666, 502, 20);
    try testing.expect(!ownershipReproducibleBy(501, 20, &.{}, &theirs, 20));
    try testing.expect(ownershipReproducibleBy(0, 0, &.{}, &theirs, 20));
}
