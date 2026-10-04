//! Present a decrypted filesystem that remains inside the backing root and checks each caller's permissions.

const Mount = @This();

const std = @import("std");
const builtin = @import("builtin");
const mem = std.mem;
const testing = std.testing;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const S = std.c.S;

const container = @import("../container.zig");
const crypto = @import("../crypto.zig");
const processor = @import("../processor.zig");
const fs = @import("../fs.zig");
const fuse = @import("fuse.zig");
const names = @import("names.zig");
const faults = @import("faults.zig");
const Marks = @import("Marks.zig");
const Node = @import("Node.zig");
const raf = @import("raf.zig");
const sidecar = @import("sidecar.zig");

const at_nofollow: u32 = std.c.AT.SYMLINK_NOFOLLOW;

gpa: Allocator,
io: Io,
/// Keep the root open so every backing lookup stays anchored for the mount's life.
root: Io.Dir,
keys: crypto.DerivedKeys,
raf_key: [16]u8,
mapper: names.Mapper,
options: Options,
/// Record the mount process identity to restrict callers and preserve ownership.
uid: std.c.uid_t,
gid: std.c.gid_t,
groups: []std.c.gid_t,
table: Node.Table,
raf_table: raf.Table,
raf_inodes: raf.Inodes,
marks: Marks,
sidecars: sidecar.Store,
/// Count failures that should affect the mount's exit status.
failures: std.atomic.Value(usize) = .init(0),
/// Set when unmount cannot write back one or more files.
lost: std.atomic.Value(bool) = .init(false),
/// Marks a running mount so setup failures are distinguishable from completed sessions.
up: std.atomic.Value(bool) = .init(false),

pub const Error = error{
    NotSupported,
    BadHandle,
    UnsafePath,
    OutOfMemory,
};

/// Choose one storage format for the entire mount.
pub const Format = enum { v1, raf };

pub const Options = struct {
    read_only: bool = false,
    allow_other: bool = false,
    format: Format = .v1,
    max_file_size: usize,
    memory_limit: usize,
    /// Store ciphertext here when unmount cannot write it back.
    rescue_dir: []const u8,
    /// Signal the daemon parent once the mount is ready.
    ready_fd: ?std.c.fd_t = null,
    /// Identify the backing directory and mountpoint in foreground status.
    backing: []const u8 = &.{},
    mountpoint: []const u8 = &.{},
};

extern "c" fn getgroups(size: c_int, list: [*]std.c.gid_t) c_int;
extern "c" fn fstatvfs(fd: std.c.fd_t, buf: *fuse.Statvfs) c_int;

pub fn init(
    m: *Mount,
    gpa: Allocator,
    io: Io,
    lib: *const fuse.Library,
    root: Io.Dir,
    keys: crypto.DerivedKeys,
    mapper: names.Mapper,
    options: Options,
) !void {
    m.* = .{
        .gpa = gpa,
        .io = io,
        .root = root,
        .keys = keys,
        .raf_key = if (options.format == .raf) container.deriveRafKey(keys) else @splat(0),
        .mapper = mapper,
        .options = options,
        .uid = std.c.geteuid(),
        .gid = std.c.getegid(),
        .groups = try ownGroups(gpa),
        .table = .init(gpa, io, options.max_file_size, options.memory_limit),
        .raf_table = .init(gpa, io, 0, 0),
        .raf_inodes = .{ .gpa = gpa, .io = io },
        .marks = .{ .gpa = gpa, .io = io },
        .sidecars = .{ .gpa = gpa, .io = io },
    };
    lib_ptr = lib;
}

pub fn deinit(m: *Mount) void {
    m.table.deinit();
    // Tear down nodes first because their inode claims belong to the registry.
    m.raf_table.deinit();
    m.raf_inodes.deinit();
    m.marks.deinit();
    m.sidecars.deinit();
    m.gpa.free(m.groups);
    std.crypto.secureZero(u8, mem.asBytes(&m.keys));
    std.crypto.secureZero(u8, &m.raf_key);
}

fn isRaf(m: *const Mount) bool {
    return m.options.format == .raf;
}

pub fn failureCount(m: *Mount) usize {
    return m.failures.load(.seq_cst);
}

fn countFailure(m: *Mount) void {
    _ = m.failures.fetchAdd(1, .seq_cst);
}

fn ownGroups(gpa: Allocator) ![]std.c.gid_t {
    const count = getgroups(0, undefined);
    if (count <= 0) return gpa.alloc(std.c.gid_t, 0);
    const list = try gpa.alloc(std.c.gid_t, @intCast(count));
    errdefer gpa.free(list);
    const got = getgroups(count, list.ptr);
    if (got < 0) return error.Unexpected;
    return list[0..@intCast(got)];
}

var lib_ptr: *const fuse.Library = undefined;

fn mount() *Mount {
    return fuse.privateData(lib_ptr, Mount);
}

fn context() *fuse.Context {
    return lib_ptr.getContext();
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
        error.InvalidHeaderMac,
        error.AuthenticationFailed,
        error.InvalidFileSize,
        error.InputOutput,
        error.InvalidHeader,
        error.AlgorithmMismatch,
        error.ShortRead,
        error.ContextFailed,
        => .IO,
        error.Overflow, error.InvalidArgument => .INVAL,
        error.FileExists => .EXIST,
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

fn result(m: *Mount, r: anyerror!void) c_int {
    r catch |err| return failed(m, err);
    return 0;
}

fn resultSize(m: *Mount, r: anyerror!usize) c_int {
    const n = r catch |err| return failed(m, err);
    return @intCast(n);
}

/// Count unexpected I/O failures even when the client does not report them.
fn failed(m: *Mount, err: anyerror) c_int {
    const code = errnoFor(err);
    if (code == fuse.negErrno(.IO) and !isDataError(err)) {
        m.countFailure();
        std.debug.print("turbocrypt mount: internal error: {}\n", .{err});
    }
    return code;
}

/// Treat damaged ciphertext as data loss, not a failure in the mount itself.
fn isDataError(err: anyerror) bool {
    return switch (err) {
        error.InvalidHeaderMac,
        error.AuthenticationFailed,
        error.InvalidFileSize,
        error.InputOutput,
        error.InvalidHeader,
        error.AlgorithmMismatch,
        error.ShortRead,
        error.ContextFailed,
        => true,
        else => false,
    };
}

const FileHandle = struct {
    node: *Node,
    read: bool,
    write: bool,
    append: bool,
    /// Keep the file opened at access check time for a later deferred load.
    backing: ?Io.File = null,

    fn closeBacking(handle: *FileHandle, io: Io) void {
        if (handle.backing) |file| file.close(io);
        handle.backing = null;
    }
};

const RafHandle = struct {
    node: *raf.Node,
    read: bool,
    write: bool,
    append: bool,
};

const DirHandle = struct {
    dir: Io.Dir,
    key: Marks.Key,
};

fn handleOf(comptime T: type, fi: ?*fuse.FileInfo) Error!*T {
    const info = fi orelse return error.BadHandle;
    if (info.fh == 0) return error.BadHandle;
    return @ptrFromInt(info.fh);
}

fn nowSpec(io: Io) std.c.timespec {
    const ns = Io.Clock.now(.real, io).nanoseconds;
    return .{
        .sec = @intCast(@divFloor(ns, std.time.ns_per_s)),
        .nsec = @intCast(@mod(ns, std.time.ns_per_s)),
    };
}

fn timesOf(st: *const fuse.Stat) Node.Times {
    return .{ .atime = st.atime(), .mtime = st.mtime(), .ctime = st.ctime() };
}

fn setTimes(st: *fuse.Stat, times: Node.Times) void {
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

fn withSentinel(name: []const u8, buffer: *[Io.Dir.max_name_bytes + 1]u8) Error![:0]const u8 {
    if (name.len > Io.Dir.max_name_bytes) return error.UnsafePath;
    @memcpy(buffer[0..name.len], name);
    buffer[name.len] = 0;
    return buffer[0..name.len :0];
}

/// Never follow symlinks while looking up a backing entry.
/// Return null for missing or oversized names so another valid spelling can be tried.
fn statAt(dir: Io.Dir, name: []const u8) Error!?fuse.Stat {
    var buffer: [Io.Dir.max_name_bytes + 1]u8 = undefined;
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

/// Apply POSIX permissions to the caller, not to the mount process.
pub fn allowedBy(
    uid: std.c.uid_t,
    gid: std.c.gid_t,
    groups: []const std.c.gid_t,
    st: *const fuse.Stat,
    want: Want,
) bool {
    const mode = modeOf(st);
    if (uid == 0) {
        if (!want.x or S.ISDIR(mode)) return true;
        return mode & 0o111 != 0;
    }
    const bits: u32 = if (st.uid == uid)
        (mode >> 6) & 7
    else if (st.gid == gid or mem.findScalar(std.c.gid_t, groups, st.gid) != null)
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
    // Skip the group lookup unless supplementary groups could change the decision.
    const groups_decide = ctx.uid != 0 and st.uid != ctx.uid and st.gid != ctx.gid;
    const groups: []std.c.gid_t = if (groups_decide) try callerGroups(m.gpa) else &.{};
    defer m.gpa.free(groups);
    return allowedBy(ctx.uid, ctx.gid, groups, st, want);
}

/// Read the caller's supplementary groups when the platform exposes them.
/// The caller frees the result.
fn callerGroups(gpa: Allocator) ![]std.c.gid_t {
    if (builtin.os.tag != .linux) return &.{};
    const getgroups_fn = lib_ptr.getGroups orelse return &.{};
    // libfuse reports the needed count on a short buffer, so grow and retry.
    var list: []std.c.gid_t = &.{};
    while (true) {
        const count = getgroups_fn(@intCast(list.len), list.ptr);
        if (count < 0) {
            gpa.free(list);
            return &.{};
        }
        const total: usize = @intCast(count);
        if (total == list.len) return list;
        gpa.free(list);
        list = try gpa.alloc(std.c.gid_t, total);
    }
}

fn requireAllowed(m: *Mount, st: *const fuse.Stat, want: Want) !void {
    if (!try permitted(m, st, want)) return error.AccessDenied;
}

fn isOwner(st: *const fuse.Stat) bool {
    const ctx = context();
    return ctx.uid == 0 or ctx.uid == st.uid;
}

/// Apply sticky-directory ownership rules before removal or rename.
fn stickyAllows(parent: *const fuse.Stat, entry: *const fuse.Stat) bool {
    if (modeOf(parent) & S.ISVTX == 0) return true;
    const ctx = context();
    return ctx.uid == 0 or ctx.uid == entry.uid or ctx.uid == parent.uid;
}

/// Decide whether a replacement written as `uid` can preserve `st` ownership.
/// An inherited group needs no membership; changing the owner requires root.
pub fn ownershipReproducibleBy(
    uid: std.c.uid_t,
    gid: std.c.gid_t,
    groups: []const std.c.gid_t,
    st: *const fuse.Stat,
    inherited_gid: std.c.gid_t,
) bool {
    if (uid == 0) return true;
    if (st.uid != uid) return false;
    if (st.gid == inherited_gid or st.gid == gid) return true;
    return mem.findScalar(std.c.gid_t, groups, st.gid) != null;
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

/// Find the ownership a new entry needs to remain owned by its caller after write-back.
/// Return null when creation already supplies it.
/// The mount can create an entry for another user only when it runs as root.
///
/// Check parent permissions before calling this.
fn requiredOwnership(m: *Mount, parent: *const fuse.Stat) !?Ownership {
    const ctx = context();
    const inherited = inheritedGid(m, parent);
    const gid = if (groupComesFromDirectory(parent)) parent.gid else ctx.gid;
    if (ctx.uid == m.uid and gid == inherited) return null;
    var wanted = mem.zeroes(fuse.Stat);
    wanted.uid = ctx.uid;
    wanted.gid = gid;
    if (!ownershipReproducibleBy(m.uid, m.gid, m.groups, &wanted, inherited)) {
        return error.PermissionDenied;
    }
    return .{ .uid = ctx.uid, .gid = gid };
}

fn requireReproducible(
    m: *Mount,
    st: *const fuse.Stat,
    parent: *const fuse.Stat,
    path: []const u8,
) !void {
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

/// The root path has no separate parent and name.
fn splitPath(path: []const u8) ?Split {
    if (path.len <= 1) return null;
    const cut = mem.findScalarLast(u8, path, '/') orelse return null;
    return .{ .dir = path[0..@max(cut, 1)], .name = path[cut + 1 ..] };
}

const Parent = struct {
    dir: Io.Dir,
    /// Keep this relative to the backing root; the root itself uses an empty path.
    backing_path: []u8,
    st: fuse.Stat,

    fn deinit(parent: *Parent, m: *Mount) void {
        parent.dir.close(m.io);
        m.gpa.free(parent.backing_path);
    }

    fn key(parent: *const Parent) Marks.Key {
        return Marks.keyOf(parent.st);
    }

    fn childPath(parent: *const Parent, m: *Mount, backing_name: []const u8) ![]u8 {
        if (parent.backing_path.len == 0) return m.gpa.dupe(u8, backing_name);
        return mem.concat(m.gpa, u8, &.{ parent.backing_path, "/", backing_name });
    }
};

/// Refuse symlinks rather than letting them escape the backing root.
fn openSubdir(m: *Mount, dir: Io.Dir, name: []const u8, iterate: bool) !Io.Dir {
    // The platforms report a refused symlink differently, but neither should be visible.
    return dir.openDir(m.io, name, .{
        .follow_symlinks = false,
        .iterate = iterate,
    }) catch |err| switch (err) {
        error.SymLinkLoop, error.NotDir => error.FileNotFound,
        else => err,
    };
}

/// Resolve a visible directory path without following symlinks outside the backing root.
/// When `check` is set, require search permission throughout the walk.
fn walkParent(m: *Mount, dir_path: []const u8, check: bool) !Parent {
    const io = m.io;
    var dir = try m.root.openDir(io, ".", .{});
    errdefer dir.close(io);
    var backing: std.ArrayList(u8) = .empty;
    errdefer backing.deinit(m.gpa);
    var st = try fuse.statFd(dir.handle);
    if (check) try requireAllowed(m, &st, .{ .x = true });

    var it = mem.tokenizeScalar(u8, dir_path, '/');
    while (it.next()) |component| {
        if (!fs.isPlainComponent(component)) return error.UnsafePath;
        const name = try m.mapper.toBacking(m.gpa, component, .directory);
        defer m.gpa.free(name);
        if (names.Mapper.isReserved(name)) return error.FileNotFound;
        const child = try openSubdir(m, dir, name, false);
        dir.close(io);
        dir = child;
        if (check or it.peek() == null) {
            st = try fuse.statFd(dir.handle);
            if (check) try requireAllowed(m, &st, .{ .x = true });
        }
        if (backing.items.len != 0) try backing.append(m.gpa, '/');
        try backing.appendSlice(m.gpa, name);
    }
    return .{ .dir = dir, .backing_path = try backing.toOwnedSlice(m.gpa), .st = st };
}

const Located = struct {
    backing_name: []u8,
    kind: names.Kind,
    st: fuse.Stat,
};

/// In suffix mode, prefer file `x.enc` over directory `x`.
/// An overlong file spelling cannot hide a directory with a valid spelling.
fn locate(m: *Mount, parent: Io.Dir, name: []const u8) !Located {
    if (!fs.isPlainComponent(name)) return error.UnsafePath;
    const maybe_file_name: ?[]u8 = m.mapper.toBacking(m.gpa, name, .file) catch |err| switch (err) {
        error.NameTooLong => null,
        else => return err,
    };
    if (maybe_file_name) |file_name| {
        errdefer m.gpa.free(file_name);
        if (names.Mapper.isReserved(file_name)) return error.FileNotFound;
        if (try statAt(parent, file_name)) |st| {
            if (S.ISREG(modeOf(&st))) {
                return .{ .backing_name = file_name, .kind = .file, .st = st };
            }
            if (!m.mapper.kindsDiffer() and S.ISDIR(modeOf(&st))) {
                return .{ .backing_name = file_name, .kind = .directory, .st = st };
            }
        }
        m.gpa.free(file_name);
    }
    if (!m.mapper.kindsDiffer()) return error.FileNotFound;
    const dir_name = try m.mapper.toBacking(m.gpa, name, .directory);
    if (try statAt(parent, dir_name)) |st| {
        if (S.ISDIR(modeOf(&st))) {
            return .{ .backing_name = dir_name, .kind = .directory, .st = st };
        }
    }
    m.gpa.free(dir_name);
    return error.FileNotFound;
}

const Resolved = struct {
    parent: Parent,
    backing_name: []u8,
    /// Keep this relative to the backing root.
    backing_path: []u8,
    kind: names.Kind,
    st: fuse.Stat,
    is_root: bool,

    fn deinit(resolved: *Resolved, m: *Mount) void {
        resolved.parent.deinit(m);
        m.gpa.free(resolved.backing_name);
        m.gpa.free(resolved.backing_path);
    }
};

fn resolve(m: *Mount, path: []const u8, check: bool) !Resolved {
    const split = splitPath(path) orelse {
        var parent = try walkParent(m, "/", false);
        errdefer parent.deinit(m);
        return .{
            .parent = parent,
            .backing_name = try m.gpa.dupe(u8, "."),
            .backing_path = try m.gpa.dupe(u8, "."),
            .kind = .directory,
            .st = parent.st,
            .is_root = true,
        };
    };
    var parent = try walkParent(m, split.dir, check);
    errdefer parent.deinit(m);
    const located = try locate(m, parent.dir, split.name);
    errdefer m.gpa.free(located.backing_name);
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

/// Return an owned parent handle without following symlinks.
fn parentOf(m: *Mount, backing_path: []const u8) !Io.Dir {
    return (try fs.openParentIn(m.io, m.root, backing_path, false)) orelse error.FileNotFound;
}

fn openBackingIn(
    m: *Mount,
    parent: Io.Dir,
    backing_path: []const u8,
    mode: Io.Dir.OpenFileOptions.Mode,
) !Io.File {
    return parent.openFile(m.io, Io.Dir.path.basename(backing_path), .{
        .mode = mode,
        .follow_symlinks = false,
        .allow_directory = false,
    });
}

/// Load through the file opened with the handle so later permission changes cannot revoke
/// access already granted.
/// Otherwise, open the node at its current backing path.
/// The caller holds the node lock.
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

fn loadFrom(m: *Mount, node: *Node, file: Io.File) !void {
    const size = (try file.stat(m.io)).size;
    node.load(m.io, &m.table, file, size, m.keys) catch |err| {
        if (isDataError(err)) std.debug.print("turbocrypt mount: cannot decrypt {s}: wrong key or damaged file ({s})\n", .{ node.path, @errorName(err) });
        return err;
    };
}

fn fallbackFor(parent: Io.Dir, name: []const u8) !Node.Fallback {
    if (try statAt(parent, name)) |st| {
        return .{ .mode = @intCast(modeOf(&st) & 0o7777), .uid = st.uid, .gid = st.gid };
    }
    return .{ .mode = 0o644, .uid = null, .gid = null };
}

/// The caller holds the node lock.
fn writeBackNode(m: *Mount, node: *Node, durable: bool) !void {
    var parent = try parentOf(m, node.path);
    defer parent.close(m.io);
    const name = Io.Dir.path.basename(node.path);
    const fallback = try fallbackFor(parent, name);
    try node.writeBack(m.io, &m.table, parent, name, fallback, m.keys, &m.marks, durable);
}

/// Keep failed write-backs retryable and report them even when close cannot return an error.
fn flushNode(m: *Mount, node: *Node, durable: bool) !void {
    if (!node.dirty or node.unlinked.load(.acquire)) return;
    writeBackNode(m, node, durable) catch |err| {
        m.countFailure();
        std.debug.print("turbocrypt mount: cannot write back {s}: {s}; the data stays in memory and the next flush retries\n", .{ node.path, @errorName(err) });
        return err;
    };
}

/// Return null when the backing parent is unavailable.
fn parentKeyOf(m: *Mount, backing_path: []const u8) ?Marks.Key {
    var parent = parentOf(m, backing_path) catch return null;
    defer parent.close(m.io);
    const st = fuse.statFd(parent.handle) catch return null;
    return Marks.keyOf(st);
}

fn getattr(m: *Mount, path: []const u8, st: *fuse.Stat, fi: ?*fuse.FileInfo) !void {
    var resolved = try resolve(m, path, fi == null);
    defer resolved.deinit(m);
    st.* = resolved.st;
    if (resolved.kind != .file) return;

    st.size = if (resolved.st.size >= Node.overhead) resolved.st.size - Node.overhead else 0;
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
    const handle = try m.gpa.create(DirHandle);
    errdefer m.gpa.destroy(handle);
    handle.* = .{ .dir = dir, .key = Marks.keyOf(resolved.st) };
    fi.fh = @intFromPtr(handle);
}

fn readdir(m: *Mount, buf: ?*anyopaque, filler: fuse.FillDirFn, fi: ?*fuse.FileInfo) !void {
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
        const plain = (try m.mapper.toPlain(m.gpa, entry.name, kind)) orelse continue;
        defer m.gpa.free(plain);
        if (kind == .file and sidecar.matches(plain)) continue;
        var buffer: [Io.Dir.max_name_bytes + 1]u8 = undefined;
        const name_z = withSentinel(plain, &buffer) catch continue;
        var st = mem.zeroes(fuse.Stat);
        st.mode = if (kind == .file) S.IFREG else S.IFDIR;
        _ = filler(buf, name_z, &st, 0, 0);
    }
}

fn releasedir(m: *Mount, fi: ?*fuse.FileInfo) !void {
    const handle = try handleOf(DirHandle, fi);
    handle.dir.close(m.io);
    m.gpa.destroy(handle);
}

fn openFlags(fi: *const fuse.FileInfo) std.posix.O {
    return @bitCast(fi.flags);
}

fn attachHandle(
    m: *Mount,
    resolved: *const Resolved,
    fi: *fuse.FileInfo,
    want: Want,
    truncate_first: bool,
) !void {
    const flags = openFlags(fi);
    const node = try m.table.attach(resolved.backing_path);
    errdefer m.table.release(node);
    var backing: ?Io.File = null;
    errdefer if (backing) |file| file.close(m.io);
    {
        node.mutex.lockUncancelable(m.io);
        defer node.mutex.unlock(m.io);
        if (node.times == null) node.times = timesOf(&resolved.st);
        if (truncate_first) try node.truncate(&m.table, 0, nowSpec(m.io));
        // Keep the checked access for deferred loading; try the current path if reopening failed.
        if (!node.loaded) {
            const parent = resolved.parent.dir;
            backing = openBackingIn(m, parent, resolved.backing_path, .read_only) catch null;
        }
    }
    const handle = try m.gpa.create(FileHandle);
    handle.* = .{
        .node = node,
        .read = want.r,
        .write = want.w,
        .append = flags.APPEND,
        .backing = backing,
    };
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
    const truncating = want.w and flags.TRUNC;
    if (m.isRaf()) return rafOpen(m, &resolved, fi, want, truncating);
    if (want.w) try requireReproducible(m, &resolved.st, &resolved.parent.st, path);
    // Reject short ciphertext now because an empty file might never be read.
    if (resolved.st.size < Node.overhead and !truncating) {
        std.debug.print("turbocrypt mount: {s} is too short to be an encrypted file\n", .{path});
        return error.InvalidFileSize;
    }
    if (resolved.st.size - Node.overhead > m.options.max_file_size) return error.FileTooBig;
    try attachHandle(m, &resolved, fi, want, truncating);
}

const NewEntry = struct {
    parent: Parent,
    backing_name: []u8,
    owner: ?Ownership,

    fn deinit(entry: *NewEntry, m: *Mount) void {
        entry.parent.deinit(m);
        m.gpa.free(entry.backing_name);
    }
};

/// Verify the caller's directory rights before creating an entry.
fn prepareNewEntry(m: *Mount, path: []const u8, kind: names.Kind) !NewEntry {
    const split = splitPath(path) orelse return error.PathAlreadyExists;
    var parent = try walkParent(m, split.dir, true);
    errdefer parent.deinit(m);
    try requireAllowed(m, &parent.st, .{ .w = true, .x = true });
    if (!fs.isPlainComponent(split.name)) return error.UnsafePath;
    const backing_name = try m.mapper.toBacking(m.gpa, split.name, kind);
    errdefer m.gpa.free(backing_name);
    if (names.Mapper.isReserved(backing_name)) return error.PermissionDenied;
    const owner = try requiredOwnership(m, &parent.st);
    return .{ .parent = parent, .backing_name = backing_name, .owner = owner };
}

fn create(m: *Mount, path: []const u8, mode: fuse.mode_t, fi: *fuse.FileInfo) !void {
    try requireWritable(m);
    var entry = try prepareNewEntry(m, path, .file);
    defer entry.deinit(m);
    const parent = &entry.parent;
    const backing_name = entry.backing_name;
    const owner = entry.owner;

    // Allocate the path before exposing the file so allocation failure leaves no stray entry.
    const backing_path = try parent.childPath(m, backing_name);
    defer m.gpa.free(backing_path);
    if (m.isRaf()) return rafCreate(m, &entry, backing_path, mode, fi);
    const handle = try m.gpa.create(FileHandle);
    errdefer m.gpa.destroy(handle);
    const node = try m.table.attach(backing_path);
    errdefer m.table.release(node);
    var change = try m.marks.begin(parent.dir, parent.key());
    defer change.deinit();

    // Do not expose an empty file until its complete ciphertext exists.
    {
        var atomic = try processor.AtomicOutput.initIn(parent.dir, m.gpa, m.io, .{
            .permissions = .fromMode(0o600),
        });
        defer atomic.deinit(m.io);
        var empty: [Node.overhead]u8 = undefined;
        crypto.encryptZeroCopy(m.io, &empty, "", m.keys);
        if (faults.take(.create_write)) return error.InputOutput;
        try atomic.file.writeStreamingAll(m.io, &empty);
        if (std.c.fchmod(atomic.file.handle, mode) != 0) return error.AccessDenied;
        if (owner) |o| {
            if (std.c.fchown(atomic.file.handle, o.uid, o.gid) != 0) return error.PermissionDenied;
        }
        try Io.Dir.hardLink(parent.dir, atomic.tmp_path, parent.dir, backing_name, m.io, .{});
    }
    change.commit();

    const flags = openFlags(fi);
    handle.* = .{
        .node = node,
        .read = flags.ACCMODE != .WRONLY,
        .write = true,
        .append = flags.APPEND,
    };
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
        // A retained node must not lend old plaintext to the newly created file.
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
        if (m.isRaf()) return rafTruncateHandle(m, info, new_len);
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
    if (m.isRaf()) return rafTruncatePath(m, &resolved, new_len);
    try requireReproducible(m, &resolved.st, &resolved.parent.st, path);
    const node = try m.table.attach(resolved.backing_path);
    defer m.table.release(node);
    node.mutex.lockUncancelable(m.io);
    defer node.mutex.unlock(m.io);
    if (node.times == null) node.times = timesOf(&resolved.st);
    if (new_len != 0) try ensureLoaded(m, node, null);
    try node.truncate(&m.table, new_len, nowSpec(m.io));
    // A path-based truncate has no later release that can flush the change.
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
    // Sync clean files because metadata could have changed without a node.
    var parent = try parentOf(m, node.path);
    defer parent.close(m.io);
    {
        const file = try openBackingIn(m, parent, node.path, .read_only);
        defer file.close(m.io);
        faults.syncFd(file.handle, .metadata_sync) catch |err| {
            m.countFailure();
            std.debug.print("turbocrypt mount: cannot sync {s}: {s}\n", .{
                node.path,
                @errorName(err),
            });
            return err;
        };
    }
    const key = Marks.keyOf(try fuse.statFd(parent.handle));
    m.marks.sync(key) catch |err| {
        m.countFailure();
        std.debug.print("turbocrypt mount: cannot sync the directory of {s}: {s}\n", .{
            node.path,
            @errorName(err),
        });
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
    m.gpa.destroy(handle);
}

fn fsyncdir(m: *Mount, fi: ?*fuse.FileInfo) !void {
    const handle = try handleOf(DirHandle, fi);
    var first_error: ?anyerror = null;
    const pinned = try m.table.pinAll(m.gpa);
    defer m.gpa.free(pinned);
    for (pinned) |node| {
        defer m.table.release(node);
        node.mutex.lockUncancelable(m.io);
        defer node.mutex.unlock(m.io);
        if (!node.dirty or node.unlinked.load(.acquire)) continue;
        // Directory identity remains stable through renames while this handle stays open.
        const parent_key = parentKeyOf(m, node.path) orelse continue;
        if (parent_key.dev != handle.key.dev or parent_key.ino != handle.key.ino) continue;
        flushNode(m, node, true) catch |err| {
            if (first_error == null) first_error = err;
        };
    }
    syncDirHandle(m, handle, &first_error);
    if (first_error) |err| return err;
}

fn syncDirHandle(m: *Mount, handle: *const DirHandle, first_error: *?anyerror) void {
    if (m.marks.pin(handle.key)) |pinned_mark| {
        const synced = faults.syncFd(pinned_mark.dir.handle, .dir_sync);
        m.marks.unpin(handle.key, pinned_mark.generation, if (synced) true else |_| false);
        synced catch |err| {
            m.countFailure();
            if (first_error.* == null) first_error.* = err;
        };
    } else {
        faults.syncFd(handle.dir.handle, .dir_sync) catch |err| {
            m.countFailure();
            if (first_error.* == null) first_error.* = err;
        };
    }
}

fn mkdir(m: *Mount, path: []const u8, mode: fuse.mode_t) !void {
    try requireWritable(m);
    var entry = try prepareNewEntry(m, path, .directory);
    defer entry.deinit(m);
    const parent = &entry.parent;
    const backing_name = entry.backing_name;
    const owner = entry.owner;

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

fn giveEntry(dir: Io.Dir, name: []const u8, owner: Ownership) !void {
    var buffer: [Io.Dir.max_name_bytes + 1]u8 = undefined;
    const name_z = try withSentinel(name, &buffer);
    if (std.c.fchownat(dir.handle, name_z, owner.uid, owner.gid, at_nofollow) != 0) {
        return error.PermissionDenied;
    }
}

fn unlink(m: *Mount, path: []const u8) !void {
    try requireWritable(m);
    var resolved = try resolve(m, path, true);
    defer resolved.deinit(m);
    if (resolved.kind != .file) return error.IsDir;
    try requireAllowed(m, &resolved.parent.st, .{ .w = true, .x = true });
    if (!stickyAllows(&resolved.parent.st, &resolved.st)) return error.PermissionDenied;

    // Mark this before deletion so a racing write-back cannot restore the file.
    // Do not let another open attach to the node after unlinking it.
    const node = lockNodeIn(m, &m.table, &resolved);
    defer unlockNodeIn(m, &m.table, node);
    const raf_node = lockNodeIn(m, &m.raf_table, &resolved);
    defer unlockNodeIn(m, &m.raf_table, raf_node);
    var change = try m.marks.begin(resolved.parent.dir, resolved.parent.key());
    defer change.deinit();
    try resolved.parent.dir.deleteFile(m.io, resolved.backing_name);
    change.commit();
    if (node) |n| n.unlinked.store(true, .release);
    if (raf_node) |n| n.unlinked.store(true, .release);
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
    m.marks.drop(Marks.keyOf(resolved.st));
    change.commit();
    m.sidecars.forget(path);
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
    if (!fs.isPlainComponent(split.name)) return error.UnsafePath;
    const target_name = try m.mapper.toBacking(m.gpa, split.name, source.kind);
    defer m.gpa.free(target_name);
    if (names.Mapper.isReserved(target_name)) return error.PermissionDenied;
    const noreplace = flags & fuse.rename_noreplace != 0;
    if (noreplace or modeOf(&target_parent.st) & S.ISVTX != 0) {
        if (try statAt(target_parent.dir, target_name)) |existing| {
            if (noreplace) return error.PathAlreadyExists;
            if (!stickyAllows(&target_parent.st, &existing)) return error.PermissionDenied;
        }
    }
    const target_path = try target_parent.childPath(m, target_name);
    defer m.gpa.free(target_path);
    // Renaming a path to itself must not unlink the active node.
    if (mem.eql(u8, source.backing_path, target_path)) return;

    var source_change = try m.marks.begin(source.parent.dir, source.parent.key());
    defer source_change.deinit();
    var target_change = try m.marks.begin(target_parent.dir, target_parent.key());
    defer target_change.deinit();

    switch (m.options.format) {
        .v1 => try renameRekeyed(
            &m.table,
            m.io,
            &source,
            &target_parent,
            target_name,
            target_path,
            noreplace,
        ),
        .raf => try renameRekeyed(
            &m.raf_table,
            m.io,
            &source,
            &target_parent,
            target_name,
            target_path,
            noreplace,
        ),
    }
    source_change.commit();
    target_change.commit();
    m.sidecars.move(from, to) catch {};
}

/// Keep backing renames and cached node paths together under concurrent access.
fn renameRekeyed(
    table: anytype,
    io: Io,
    source: *const Resolved,
    target_parent: *const Parent,
    target_name: []const u8,
    target_path: []const u8,
    noreplace: bool,
) !void {
    var rekey = try table.beginRekey(source.backing_path, target_path, source.kind == .directory);
    const source_dir = source.parent.dir;
    const target_dir = target_parent.dir;
    const renamed = if (noreplace)
        Io.Dir.renamePreserve(source_dir, source.backing_name, target_dir, target_name, io)
    else
        Io.Dir.rename(source_dir, source.backing_name, target_dir, target_name, io);
    renamed catch |err| {
        rekey.abort();
        return err;
    };
    rekey.commit();
}

const Recorded = struct {
    mode: ?std.c.mode_t = null,
    uid: ?std.c.uid_t = null,
    gid: ?std.c.gid_t = null,
    atime: ?std.c.timespec = null,
    mtime: ?std.c.timespec = null,
};

/// Pin and lock the resolved file's node so write-back cannot overwrite a metadata change.
/// Return null when no node is cached; release a node with `unlockNodeIn`.
/// Null means no node exists; release with unlockNodeIn.
///
/// RAF metadata writes need no staging because they preserve the backing inode.
fn lockNodeIn(m: *Mount, table: anytype, resolved: *const Resolved) ?*@TypeOf(table.*).Node {
    if (resolved.kind != .file) return null;
    const node = table.pin(resolved.backing_path) orelse return null;
    node.mutex.lockUncancelable(m.io);
    return node;
}

fn unlockNodeIn(m: *Mount, table: anytype, node: anytype) void {
    const n = node orelse return;
    n.mutex.unlock(m.io);
    table.release(n);
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
    var buffer: [Io.Dir.max_name_bytes + 1]u8 = undefined;
    const name_z = try withSentinel(resolved.backing_name, &buffer);
    const bits: std.c.mode_t = mode & 0o7777;
    const node = lockNodeIn(m, &m.table, &resolved);
    defer unlockNodeIn(m, &m.table, node);
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
    const new_uid: ?std.c.uid_t =
        if (uid != unchanged_uid and uid != resolved.st.uid) uid else null;
    const new_gid: ?std.c.gid_t =
        if (gid != unchanged_gid and gid != resolved.st.gid) gid else null;
    if (ctx.uid != 0) {
        if (new_uid != null) return error.PermissionDenied;
        if (new_gid) |g| {
            if (ctx.uid != resolved.st.uid) return error.PermissionDenied;
            if (g != ctx.gid) {
                const groups = try callerGroups(m.gpa);
                defer m.gpa.free(groups);
                if (mem.findScalar(std.c.gid_t, groups, g) == null) {
                    return error.PermissionDenied;
                }
            }
        }
    }
    var buffer: [Io.Dir.max_name_bytes + 1]u8 = undefined;
    const name_z = try withSentinel(resolved.backing_name, &buffer);
    const node = lockNodeIn(m, &m.table, &resolved);
    defer unlockNodeIn(m, &m.table, node);
    try checkMetadataCall(std.c.fchownat(
        resolved.parent.dir.handle,
        name_z,
        new_uid orelse unchanged_uid,
        new_gid orelse unchanged_gid,
        at_nofollow,
    ));
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
    var buffer: [Io.Dir.max_name_bytes + 1]u8 = undefined;
    const name_z = try withSentinel(resolved.backing_name, &buffer);
    const node = lockNodeIn(m, &m.table, &resolved);
    defer unlockNodeIn(m, &m.table, node);
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

/// Reassert callback assumptions that libfuse options could otherwise violate.
fn initSession(m: *Mount, cfg: *fuse.Config) void {
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

/// Finish durable writes at unmount and rescue files that still cannot be stored.
fn destroy(m: *Mount) void {
    defer std.crypto.secureZero(u8, mem.asBytes(&m.keys));
    if (m.isRaf()) return rafDestroy(m);
    // No workers remain, so pins do not protect anything here.
    // Avoid allocating pins because memory pressure must not block recovery.
    for (m.table.nodes.items) |node| {
        node.mutex.lockUncancelable(m.io);
        defer node.mutex.unlock(m.io);
        if (!node.dirty or node.unlinked.load(.acquire)) continue;
        writeBackNode(m, node, true) catch |err| {
            m.countFailure();
            m.lost.store(true, .seq_cst);
            std.debug.print("turbocrypt mount: cannot write back {s} at unmount: {s}\n", .{
                node.path,
                @errorName(err),
            });
            rescue(m, node);
        };
    }
    syncPendingMarks(m);
}

/// Sync directories whose changes have not yet been covered by fsync.
fn syncPendingMarks(m: *Mount) void {
    const keys = m.marks.pendingKeys(m.gpa) catch {
        m.countFailure();
        std.debug.print("turbocrypt mount: out of memory at unmount, {d} marked directories not synced\n", .{m.marks.count()});
        return;
    };
    defer m.gpa.free(keys);
    for (keys) |key| {
        m.marks.sync(key) catch |err| {
            m.countFailure();
            std.debug.print("turbocrypt mount: cannot sync a directory at unmount: {s}\n", .{
                @errorName(err),
            });
        };
    }
}

/// Open RAF files read-write when possible so a later writer can share the same context.
/// Partial RAF updates need read access.
/// Keep a node read-only when the mount or backing file does not allow writes.
fn rafOpenNode(
    m: *Mount,
    node: *raf.Node,
    parent: Io.Dir,
    backing_path: []const u8,
    need_write: bool,
) !void {
    if (node.opened) {
        if (!need_write or node.writable) return;
        const file = try openBackingIn(m, parent, backing_path, .read_write);
        node.upgradeWritable(m.io, file) catch |err| {
            file.close(m.io);
            if (err == error.FileBusy) {
                std.debug.print("turbocrypt mount: {s} changed while it was open; refusing to attach a different backing file\n", .{backing_path});
            }
            return err;
        };
        return;
    }
    var writable = !m.options.read_only;
    const file = if (writable)
        openBackingIn(m, parent, backing_path, .read_write) catch |err| switch (err) {
            error.AccessDenied, error.PermissionDenied, error.ReadOnlyFileSystem => blk: {
                writable = false;
                break :blk try openBackingIn(m, parent, backing_path, .read_only);
            },
            else => return err,
        }
    else
        try openBackingIn(m, parent, backing_path, .read_only);
    node.openWith(m.gpa, m.io, file, writable, &m.raf_inodes, &m.raf_key) catch |err| {
        file.close(m.io);
        if (err == error.FileBusy) {
            std.debug.print("turbocrypt mount: {s} is already open under another name; a container file is open under one name at a time\n", .{backing_path});
        } else if (isDataError(err)) {
            std.debug.print("turbocrypt mount: cannot open {s}: wrong key or not a container file ({s})\n", .{ backing_path, @errorName(err) });
        }
        return err;
    };
}

/// Reject hard links because separate RAF contexts could write the same inode.
fn requireSingleLink(st: *const fuse.Stat, backing_path: []const u8) !void {
    if (st.nlink <= 1) return;
    std.debug.print("turbocrypt mount: {s} has {d} links; a container file must have one\n", .{
        backing_path,
        st.nlink,
    });
    return error.NotSupported;
}

/// Return an open, locked RAF node; the caller unlocks and releases it.
fn rafOpenLocked(m: *Mount, resolved: *const Resolved, need_write: bool) !*raf.Node {
    try requireSingleLink(&resolved.st, resolved.backing_path);
    const node = try m.raf_table.attach(resolved.backing_path);
    errdefer m.raf_table.release(node);
    node.mutex.lockUncancelable(m.io);
    errdefer node.mutex.unlock(m.io);
    try rafOpenNode(m, node, resolved.parent.dir, resolved.backing_path, need_write);
    if (need_write and !node.writable) return error.AccessDenied;
    return node;
}

fn rafOpen(
    m: *Mount,
    resolved: *const Resolved,
    fi: *fuse.FileInfo,
    want: Want,
    truncating: bool,
) !void {
    const node = try rafOpenLocked(m, resolved, want.w);
    errdefer m.raf_table.release(node);
    {
        defer node.mutex.unlock(m.io);
        if (truncating) try node.setLength(0);
    }
    const flags = openFlags(fi);
    const handle = try m.gpa.create(RafHandle);
    handle.* = .{ .node = node, .read = want.r, .write = want.w, .append = flags.APPEND };
    fi.fh = @intFromPtr(handle);
}

/// Do not publish a RAF file until initialization finishes.
fn rafCreate(
    m: *Mount,
    entry: *const NewEntry,
    backing_path: []const u8,
    mode: fuse.mode_t,
    fi: *fuse.FileInfo,
) !void {
    const parent = &entry.parent;
    const handle = try m.gpa.create(RafHandle);
    errdefer m.gpa.destroy(handle);
    const node = try m.raf_table.attach(backing_path);
    errdefer m.raf_table.release(node);
    node.mutex.lockUncancelable(m.io);
    defer node.mutex.unlock(m.io);
    if (node.opened) return error.PathAlreadyExists;
    var change = try m.marks.begin(parent.dir, parent.key());
    defer change.deinit();

    const tmp = try processor.createTmpIn(parent.dir, m.io, .{
        .read = true,
        .permissions = .fromMode(0o600),
    });
    var published = false;
    errdefer if (!published) parent.dir.deleteFile(m.io, &tmp.name) catch {};
    node.createWith(m.gpa, m.io, tmp.file, &m.raf_inodes, &m.raf_key) catch |err| {
        tmp.file.close(m.io);
        return err;
    };
    // If publication fails, leave the shared node ready for a later open.
    errdefer if (!published) node.discard(m.io);
    if (std.c.fchmod(tmp.file.handle, mode) != 0) return error.AccessDenied;
    if (entry.owner) |o| {
        if (std.c.fchown(tmp.file.handle, o.uid, o.gid) != 0) return error.PermissionDenied;
    }
    try Io.Dir.hardLink(parent.dir, &tmp.name, parent.dir, entry.backing_name, m.io, .{});
    published = true;
    parent.dir.deleteFile(m.io, &tmp.name) catch {};
    change.commit();

    const flags = openFlags(fi);
    handle.* = .{
        .node = node,
        .read = flags.ACCMODE != .WRONLY,
        .write = true,
        .append = flags.APPEND,
    };
    fi.fh = @intFromPtr(handle);
}

fn lengthForStat(length: u64, fallback: i64) i64 {
    return std.math.cast(i64, length) orelse fallback;
}

/// Use a live node's length, but leave damaged or stray files visible enough to remove.
fn rafGetattr(m: *Mount, path: []const u8, st: *fuse.Stat, fi: ?*fuse.FileInfo) !void {
    if (fi) |info| {
        const node = (try handleOf(RafHandle, info)).node;
        node.mutex.lockUncancelable(m.io);
        defer node.mutex.unlock(m.io);
        st.* = try fuse.statFd(node.file.handle);
        st.size = lengthForStat(node.length(), st.size);
        return;
    }
    var resolved = try resolve(m, path, true);
    defer resolved.deinit(m);
    st.* = resolved.st;
    if (resolved.kind != .file) return;

    if (m.raf_table.pin(resolved.backing_path)) |node| {
        defer m.raf_table.release(node);
        node.mutex.lockUncancelable(m.io);
        defer node.mutex.unlock(m.io);
        if (node.opened) {
            st.size = lengthForStat(node.length(), st.size);
            return;
        }
    }

    const parent = resolved.parent.dir;
    const file = openBackingIn(m, parent, resolved.backing_path, .read_only) catch |err| {
        std.debug.print("turbocrypt mount: {s} cannot be opened ({s}); its size is the size of the stored file\n", .{ resolved.backing_path, @errorName(err) });
        return;
    };
    defer file.close(m.io);
    const cold = raf.coldSize(file, m.io, st.size, &m.raf_key);
    st.size = cold.size;
    switch (cold.source) {
        .authenticated => {},
        .probed => std.debug.print("turbocrypt mount: {s} does not authenticate; its size comes from the unauthenticated header\n", .{resolved.backing_path}),
        .backing => std.debug.print("turbocrypt mount: {s} is not a container file; its size is the size of the stored file\n", .{resolved.backing_path}),
    }
}

fn rafRead(m: *Mount, buf: [*]u8, size: usize, offset: fuse.off_t, fi: ?*fuse.FileInfo) !usize {
    const handle = try handleOf(RafHandle, fi);
    if (!handle.read) return error.BadHandle;
    if (offset < 0) return error.UnsafePath;
    const node = handle.node;
    node.mutex.lockUncancelable(m.io);
    defer node.mutex.unlock(m.io);
    return node.read(buf[0..size], @intCast(offset));
}

fn rafWrite(
    m: *Mount,
    buf: [*]const u8,
    size: usize,
    offset: fuse.off_t,
    fi: ?*fuse.FileInfo,
) !usize {
    try requireWritable(m);
    const handle = try handleOf(RafHandle, fi);
    if (!handle.write) return error.BadHandle;
    if (offset < 0) return error.UnsafePath;
    const node = handle.node;
    node.mutex.lockUncancelable(m.io);
    defer node.mutex.unlock(m.io);
    // Choose append offsets while locked so concurrent writers cannot overlap.
    const at: u64 = if (handle.append) node.length() else @intCast(offset);
    return node.write(buf[0..size], at);
}

fn rafTruncateHandle(m: *Mount, info: *fuse.FileInfo, new_length: u64) !void {
    const handle = try handleOf(RafHandle, info);
    if (!handle.write) return error.BadHandle;
    const node = handle.node;
    node.mutex.lockUncancelable(m.io);
    defer node.mutex.unlock(m.io);
    try node.setLength(new_length);
}

fn rafTruncatePath(m: *Mount, resolved: *const Resolved, new_length: u64) !void {
    const node = try rafOpenLocked(m, resolved, true);
    defer m.raf_table.release(node);
    defer node.mutex.unlock(m.io);
    try node.setLength(new_length);
}

/// RAF has no buffered data, so flush only returns a write error already recorded.
fn rafFlush(m: *Mount, fi: ?*fuse.FileInfo) !void {
    const handle = try handleOf(RafHandle, fi);
    const node = handle.node;
    node.mutex.lockUncancelable(m.io);
    defer node.mutex.unlock(m.io);
    if (node.failed) |err| return err;
}

/// Sync the file, then persist directory changes that no previous sync covered.
/// An unlinked file still needs its data sync, but has no directory entry to sync.
fn rafFsync(m: *Mount, fi: ?*fuse.FileInfo) !void {
    const handle = try handleOf(RafHandle, fi);
    const node = handle.node;
    node.mutex.lockUncancelable(m.io);
    defer node.mutex.unlock(m.io);
    if (node.failed) |err| return err;
    try rafSyncNode(m, node);
    if (node.unlinked.load(.acquire)) return;
    // Skip parent resolution when no directory change is pending.
    if (m.marks.count() == 0) return;
    const key = parentKeyOf(m, node.path) orelse return;
    m.marks.sync(key) catch |err| {
        m.countFailure();
        std.debug.print("turbocrypt mount: cannot sync the directory of {s}: {s}\n", .{
            node.path,
            @errorName(err),
        });
        return err;
    };
}

/// Keep write failures visible through close; only fsync promises durability.
fn rafRelease(m: *Mount, fi: ?*fuse.FileInfo) !void {
    const handle = try handleOf(RafHandle, fi);
    const node = handle.node;
    const recorded = blk: {
        node.mutex.lockUncancelable(m.io);
        defer node.mutex.unlock(m.io);
        break :blk node.failed;
    };
    m.raf_table.release(node);
    m.gpa.destroy(handle);
    if (recorded) |err| return err;
}

fn rafFsyncdir(m: *Mount, fi: ?*fuse.FileInfo) !void {
    const handle = try handleOf(DirHandle, fi);
    var first_error: ?anyerror = null;
    const pinned = try m.raf_table.pinAll(m.gpa);
    defer m.gpa.free(pinned);
    for (pinned) |node| {
        defer m.raf_table.release(node);
        node.mutex.lockUncancelable(m.io);
        defer node.mutex.unlock(m.io);
        if (!node.opened or !node.writable or node.unlinked.load(.acquire)) continue;
        const parent_key = parentKeyOf(m, node.path) orelse continue;
        if (parent_key.dev != handle.key.dev or parent_key.ino != handle.key.ino) continue;
        if (node.failed) |err| {
            if (first_error == null) first_error = err;
            continue;
        }
        rafSyncNode(m, node) catch |err| {
            if (first_error == null) first_error = err;
        };
    }
    syncDirHandle(m, handle, &first_error);
    if (first_error) |err| return err;
}

/// The caller holds the node lock.
fn rafSyncNode(m: *Mount, node: *raf.Node) !void {
    faults.syncFd(node.file.handle, .file_sync) catch |err| {
        m.countFailure();
        std.debug.print("turbocrypt mount: cannot sync {s}: {s}\n", .{
            node.path,
            @errorName(err),
        });
        return err;
    };
}

/// At unmount, no client handles remain.
/// Report failures from open nodes and sync writable ones before closing.
fn rafDestroy(m: *Mount) void {
    for (m.raf_table.nodes.items) |node| {
        node.mutex.lockUncancelable(m.io);
        defer node.mutex.unlock(m.io);
        if (!node.opened) continue;
        if (node.failed) |err| {
            m.countFailure();
            std.debug.print("turbocrypt mount: {s} had a failed write ({s}) and was still open at unmount\n", .{ node.path, @errorName(err) });
            continue;
        }
        if (node.writable) rafSyncNode(m, node) catch {};
    }
    syncPendingMarks(m);
}

fn rescue(m: *Mount, node: *Node) void {
    rescueNode(m, node) catch |err| {
        m.countFailure();
        std.debug.print("turbocrypt mount: the rescue copy of {s} failed too ({s}); the data is lost\n", .{ node.path, @errorName(err) });
    };
}

fn rescueNode(m: *Mount, node: *Node) !void {
    const io = m.io;
    try fs.ensureDir(io, m.options.rescue_dir);
    var dir = try Io.Dir.openDir(.cwd(), io, m.options.rescue_dir, .{});
    defer dir.close(io);
    try dir.setPermissions(io, .fromMode(0o700));
    var rand: u64 = undefined;
    io.random(mem.asBytes(&rand));
    var data_name: [16 + 4]u8 = undefined;
    _ = mem.print(&data_name, "{x:0>16}.enc", .{rand}) catch unreachable;
    var path_name: [16 + 5]u8 = undefined;
    _ = mem.print(&path_name, "{x:0>16}.path", .{rand}) catch unreachable;
    // Re-encrypt because a failed write-back may have left this buffer stale.
    const ciphertext = node.ciphertextSlice();
    crypto.encryptZeroCopy(io, ciphertext, node.plaintext, m.keys);
    try processor.writeFileAtomicIn(dir, m.gpa, io, &data_name, ciphertext, .fromMode(0o600), null);
    try processor.writeFileAtomicIn(dir, m.gpa, io, &path_name, node.path, .fromMode(0o600), null);
    std.debug.print("turbocrypt mount: the ciphertext of {s} is saved as {s}/{s}; decrypt it with the same key\n", .{ node.path, m.options.rescue_dir, data_name });
}

/// Sidecar handles use a tag bit that normal allocated handles never have.
fn sidecarOf(fi: ?*fuse.FileInfo) ?*sidecar.Entry {
    const info = fi orelse return null;
    if (info.fh & 1 == 0) return null;
    return @ptrFromInt(info.fh & ~@as(u64, 1));
}

fn heldSidecar(m: *Mount, path: []const u8) bool {
    return sidecar.matches(path) and m.sidecars.contains(path);
}

/// Require the parent rights that the sidecar's real file would need.
fn sidecarParentAllowed(m: *Mount, path: []const u8, want: Want) !void {
    const split = splitPath(path) orelse return error.PathAlreadyExists;
    var parent = try walkParent(m, split.dir, true);
    defer parent.deinit(m);
    try requireAllowed(m, &parent.st, want);
}

/// Treat these only as file attributes so a real directory of that name remains visible.
fn sidecarGetattr(m: *Mount, path: []const u8, st: *fuse.Stat) !void {
    const found = m.sidecars.stat(path) orelse {
        var resolved = try resolve(m, path, true);
        defer resolved.deinit(m);
        if (resolved.kind != .directory) return error.FileNotFound;
        st.* = resolved.st;
        return;
    };
    try sidecarParentAllowed(m, path, .{ .x = true });
    st.* = mem.zeroes(fuse.Stat);
    st.mode = S.IFREG | 0o600;
    st.nlink = 1;
    st.uid = found.uid;
    st.gid = found.gid;
    st.size = @intCast(found.size);
    setTimes(st, .{ .atime = found.mtime, .mtime = found.mtime, .ctime = found.mtime });
}

fn sidecarOpen(m: *Mount, path: []const u8, fi: *fuse.FileInfo, creating: bool) !void {
    const flags = openFlags(fi);
    const writable = creating or flags.ACCMODE != .RDONLY;
    if (writable) try requireWritable(m);
    try sidecarParentAllowed(m, path, .{ .w = writable, .x = true });
    const ctx = context();
    const truncating = writable and flags.TRUNC;
    const entry = try m.sidecars.open(path, ctx.uid, ctx.gid, writable, truncating, nowSpec(m.io));
    fi.fh = @intFromPtr(entry) | 1;
}

fn sidecarRead(m: *Mount, entry: *sidecar.Entry, buf: []u8, offset: fuse.off_t) !usize {
    if (offset < 0) return error.UnsafePath;
    return m.sidecars.read(entry, buf, @intCast(offset));
}

fn sidecarWrite(m: *Mount, entry: *sidecar.Entry, bytes: []const u8, offset: fuse.off_t) !usize {
    try requireWritable(m);
    if (offset < 0) return error.UnsafePath;
    try m.sidecars.write(entry, bytes, @intCast(offset), nowSpec(m.io));
    return bytes.len;
}

fn sidecarTruncate(m: *Mount, path: []const u8, size: fuse.off_t, fi: ?*fuse.FileInfo) !void {
    try requireWritable(m);
    if (size < 0) return error.UnsafePath;
    if (sidecarOf(fi)) |entry| return m.sidecars.resize(entry, @intCast(size), nowSpec(m.io));
    try m.sidecars.resizeAt(path, @intCast(size), nowSpec(m.io));
}

/// Remove a real sidecar left by an earlier copy as well as the in-memory one.
fn sidecarUnlink(m: *Mount, path: []const u8) !void {
    m.sidecars.remove(path);
    unlink(m, path) catch |err| if (err != error.FileNotFound) return err;
}

fn cGetattr(path: [*:0]const u8, st: *fuse.Stat, fi: ?*fuse.FileInfo) callconv(.c) c_int {
    const m = mount();
    const p = mem.span(path);
    if (sidecar.matches(p)) return result(m, sidecarGetattr(m, p, st));
    if (m.isRaf()) return result(m, rafGetattr(m, p, st, fi));
    return result(m, getattr(m, p, st, fi));
}

fn cReadlink(_: [*:0]const u8, _: [*]u8, _: usize) callconv(.c) c_int {
    return fuse.negErrno(.OPNOTSUPP);
}

fn cMknod(_: [*:0]const u8, _: fuse.mode_t, _: std.c.dev_t) callconv(.c) c_int {
    return fuse.negErrno(.OPNOTSUPP);
}

fn cMkdir(path: [*:0]const u8, mode: fuse.mode_t) callconv(.c) c_int {
    const m = mount();
    return result(m, mkdir(m, mem.span(path), mode));
}

fn cUnlink(path: [*:0]const u8) callconv(.c) c_int {
    const m = mount();
    const p = mem.span(path);
    if (sidecar.matches(p)) return result(m, sidecarUnlink(m, p));
    return result(m, unlink(m, p));
}

fn cRmdir(path: [*:0]const u8) callconv(.c) c_int {
    const m = mount();
    return result(m, rmdir(m, mem.span(path)));
}

fn cSymlink(_: [*:0]const u8, _: [*:0]const u8) callconv(.c) c_int {
    return fuse.negErrno(.OPNOTSUPP);
}

fn cRename(from: [*:0]const u8, to: [*:0]const u8, flags: c_uint) callconv(.c) c_int {
    const m = mount();
    const source = mem.span(from);
    const target = mem.span(to);
    if (sidecar.matches(source) != sidecar.matches(target)) return fuse.negErrno(.PERM);
    if (sidecar.matches(source)) return result(m, m.sidecars.move(source, target));
    return result(m, rename(m, source, target, flags));
}

fn cLink(_: [*:0]const u8, _: [*:0]const u8) callconv(.c) c_int {
    return fuse.negErrno(.OPNOTSUPP);
}

fn cChmod(path: [*:0]const u8, mode: fuse.mode_t, _: ?*fuse.FileInfo) callconv(.c) c_int {
    const m = mount();
    const p = mem.span(path);
    if (heldSidecar(m, p)) return 0;
    return result(m, chmod(m, p, mode));
}

fn cChown(
    path: [*:0]const u8,
    uid: std.c.uid_t,
    gid: std.c.gid_t,
    _: ?*fuse.FileInfo,
) callconv(.c) c_int {
    const m = mount();
    const p = mem.span(path);
    if (heldSidecar(m, p)) return result(m, m.sidecars.chown(p, uid, gid));
    return result(m, chown(m, p, uid, gid));
}

fn cTruncate(path: [*:0]const u8, size: fuse.off_t, fi: ?*fuse.FileInfo) callconv(.c) c_int {
    const m = mount();
    const p = mem.span(path);
    if (sidecarOf(fi) != null or sidecar.matches(p)) {
        return result(m, sidecarTruncate(m, p, size, fi));
    }
    return result(m, truncate(m, p, size, fi));
}

fn cOpen(path: [*:0]const u8, fi: *fuse.FileInfo) callconv(.c) c_int {
    const m = mount();
    const p = mem.span(path);
    if (sidecar.matches(p)) return result(m, sidecarOpen(m, p, fi, false));
    return result(m, open(m, p, fi));
}

fn cRead(
    _: [*:0]const u8,
    buf: [*]u8,
    size: usize,
    offset: fuse.off_t,
    fi: *fuse.FileInfo,
) callconv(.c) c_int {
    const m = mount();
    if (sidecarOf(fi)) |entry| return resultSize(m, sidecarRead(m, entry, buf[0..size], offset));
    if (m.isRaf()) return resultSize(m, rafRead(m, buf, size, offset, fi));
    return resultSize(m, read(m, buf, size, offset, fi));
}

fn cWrite(
    _: [*:0]const u8,
    buf: [*]const u8,
    size: usize,
    offset: fuse.off_t,
    fi: *fuse.FileInfo,
) callconv(.c) c_int {
    const m = mount();
    if (sidecarOf(fi)) |entry| return resultSize(m, sidecarWrite(m, entry, buf[0..size], offset));
    if (m.isRaf()) return resultSize(m, rafWrite(m, buf, size, offset, fi));
    return resultSize(m, write(m, buf, size, offset, fi));
}

fn cStatfs(_: [*:0]const u8, buf: *fuse.Statvfs) callconv(.c) c_int {
    const m = mount();
    return result(m, statfs(m, buf));
}

fn cFlush(_: [*:0]const u8, fi: *fuse.FileInfo) callconv(.c) c_int {
    const m = mount();
    if (sidecarOf(fi) != null) return 0;
    if (m.isRaf()) return result(m, rafFlush(m, fi));
    return result(m, flush(m, fi));
}

fn cRelease(_: [*:0]const u8, fi: *fuse.FileInfo) callconv(.c) c_int {
    const m = mount();
    if (sidecarOf(fi)) |entry| {
        m.sidecars.close(entry);
        return 0;
    }
    if (m.isRaf()) return result(m, rafRelease(m, fi));
    return result(m, release(m, fi));
}

fn cFsync(_: [*:0]const u8, _: c_int, fi: *fuse.FileInfo) callconv(.c) c_int {
    const m = mount();
    if (sidecarOf(fi) != null) return 0;
    if (m.isRaf()) return result(m, rafFsync(m, fi));
    return result(m, fsync(m, fi));
}

fn cSetxattr(
    _: [*:0]const u8,
    _: [*:0]const u8,
    _: [*]const u8,
    _: usize,
    _: c_int,
) callconv(.c) c_int {
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
    return result(m, opendir(m, mem.span(path), fi));
}

fn cReaddir(
    _: [*:0]const u8,
    buf: ?*anyopaque,
    filler: fuse.FillDirFn,
    _: fuse.off_t,
    fi: *fuse.FileInfo,
    _: c_uint,
) callconv(.c) c_int {
    const m = mount();
    return result(m, readdir(m, buf, filler, fi));
}

fn cReleasedir(_: [*:0]const u8, fi: *fuse.FileInfo) callconv(.c) c_int {
    const m = mount();
    return result(m, releasedir(m, fi));
}

fn cFsyncdir(_: [*:0]const u8, _: c_int, fi: *fuse.FileInfo) callconv(.c) c_int {
    const m = mount();
    if (m.isRaf()) return result(m, rafFsyncdir(m, fi));
    return result(m, fsyncdir(m, fi));
}

fn cInit(_: *fuse.ConnInfo, cfg: *fuse.Config) callconv(.c) ?*anyopaque {
    const m = mount();
    initSession(m, cfg);
    return @ptrCast(m);
}

fn cDestroy(private: ?*anyopaque) callconv(.c) void {
    const m: *Mount = @ptrCast(@alignCast(private orelse return));
    destroy(m);
}

fn cAccess(path: [*:0]const u8, mask: c_int) callconv(.c) c_int {
    const m = mount();
    const p = mem.span(path);
    if (heldSidecar(m, p)) return 0;
    return result(m, access(m, p, mask));
}

fn cCreate(path: [*:0]const u8, mode: fuse.mode_t, fi: *fuse.FileInfo) callconv(.c) c_int {
    const m = mount();
    const p = mem.span(path);
    if (sidecar.matches(p)) return result(m, sidecarOpen(m, p, fi, true));
    return result(m, create(m, p, mode, fi));
}

fn cUtimens(
    path: [*:0]const u8,
    tv: *const [2]std.c.timespec,
    _: ?*fuse.FileInfo,
) callconv(.c) c_int {
    const m = mount();
    const p = mem.span(path);
    if (heldSidecar(m, p)) return result(m, m.sidecars.touch(p, tv[1]));
    return result(m, utimens(m, p, tv));
}

fn testStat(mode: u32, uid: u32, gid: u32) fuse.Stat {
    var st = mem.zeroes(fuse.Stat);
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

    const data_errors = [_]anyerror{
        error.InvalidHeader,
        error.AlgorithmMismatch,
        error.ShortRead,
        error.ContextFailed,
    };
    for (data_errors) |err| {
        try testing.expectEqual(fuse.negErrno(.IO), errnoFor(err));
        try testing.expect(isDataError(err));
    }
    try testing.expect(!isDataError(error.Unexpected));
    try testing.expectEqual(fuse.negErrno(.INVAL), errnoFor(error.Overflow));
    try testing.expectEqual(fuse.negErrno(.INVAL), errnoFor(error.InvalidArgument));
    try testing.expectEqual(fuse.negErrno(.EXIST), errnoFor(error.FileExists));
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
    // Inherited groups need no membership, such as `wheel` under a macOS system directory.
    const wheel = testStat(S.IFREG | 0o644, 501, 0);
    try testing.expect(!ownershipReproducibleBy(501, 20, &.{}, &wheel, 20));
    try testing.expect(ownershipReproducibleBy(501, 20, &.{}, &wheel, 0));
    const theirs = testStat(S.IFREG | 0o666, 502, 20);
    try testing.expect(!ownershipReproducibleBy(501, 20, &.{}, &theirs, 20));
    try testing.expect(ownershipReproducibleBy(0, 0, &.{}, &theirs, 20));
}
