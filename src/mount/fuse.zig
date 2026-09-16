//! FUSE ABI bindings for dynamically loaded fuse-t and statically linked libfuse.
//!
//! Access only fields with stable layouts; tests/fuse_abi.sh checks them against the C headers.

const std = @import("std");
const builtin = @import("builtin");

pub const Error = error{
    LibraryNotFound,
    SymbolMissing,
    CreateFailed,
    MountFailed,
    OutOfMemory,
};

pub const Fuse = opaque {};
pub const Session = opaque {};
pub const ConnInfo = opaque {};
pub const mode_t = std.c.mode_t;
pub const off_t = std.c.off_t;

/// Match libfuse's C stat ABI, which the standard library does not expose on Linux.
pub const Stat = switch (builtin.os.tag) {
    .macos => std.c.Stat,
    .linux => LinuxStat,
    else => void,
};

const LinuxStat = switch (builtin.cpu.arch) {
    .x86_64 => extern struct {
        dev: u64,
        ino: u64,
        nlink: u64,
        mode: u32,
        uid: u32,
        gid: u32,
        pad0: u32 = 0,
        rdev: u64,
        size: i64,
        blksize: i64,
        blocks: i64,
        atim: std.c.timespec,
        mtim: std.c.timespec,
        ctim: std.c.timespec,
        reserved: [3]i64 = @splat(0),

        pub fn atime(self: @This()) std.c.timespec {
            return self.atim;
        }

        pub fn mtime(self: @This()) std.c.timespec {
            return self.mtim;
        }

        pub fn ctime(self: @This()) std.c.timespec {
            return self.ctim;
        }
    },
    .aarch64 => extern struct {
        dev: u64,
        ino: u64,
        mode: u32,
        nlink: u32,
        uid: u32,
        gid: u32,
        rdev: u64,
        pad1: u64 = 0,
        size: i64,
        blksize: i32,
        pad2: i32 = 0,
        blocks: i64,
        atim: std.c.timespec,
        mtim: std.c.timespec,
        ctim: std.c.timespec,
        reserved: [2]u32 = @splat(0),

        pub fn atime(self: @This()) std.c.timespec {
            return self.atim;
        }

        pub fn mtime(self: @This()) std.c.timespec {
            return self.mtim;
        }

        pub fn ctime(self: @This()) std.c.timespec {
            return self.ctim;
        }
    },
    else => @compileError("the mount supports x86_64 and aarch64 on Linux"),
};

/// Inspect the entry itself, never a symlink target; false on failure.
pub fn statAt(dirfd: std.c.fd_t, path: [*:0]const u8, st: *Stat) bool {
    return switch (builtin.os.tag) {
        .macos => std.c.fstatat(dirfd, path, st, std.c.AT.SYMLINK_NOFOLLOW) == 0,
        .linux => statxInto(dirfd, path, std.os.linux.AT.SYMLINK_NOFOLLOW, st),
        else => false,
    };
}

pub fn statFd(fd: std.c.fd_t) error{Unexpected}!Stat {
    var st: Stat = undefined;
    const ok = switch (builtin.os.tag) {
        .macos => std.c.fstat(fd, &st) == 0,
        .linux => statxInto(fd, "", std.os.linux.AT.EMPTY_PATH, &st),
        else => false,
    };
    if (!ok) return error.Unexpected;
    return st;
}

/// Use statx to avoid glibc version dependencies in fstatat symbols.
fn statxInto(dirfd: std.c.fd_t, path: [*:0]const u8, flags: u32, st: *Stat) bool {
    const linux = std.os.linux;
    const request: linux.STATX = .{
        .TYPE = true,
        .MODE = true,
        .NLINK = true,
        .UID = true,
        .GID = true,
        .ATIME = true,
        .MTIME = true,
        .CTIME = true,
        .INO = true,
        .SIZE = true,
        .BLOCKS = true,
    };
    var buf: linux.Statx = undefined;
    if (linux.errno(linux.statx(dirfd, path, flags, request, &buf)) != .SUCCESS) return false;
    st.* = .{
        .dev = linuxDev(buf.dev_major, buf.dev_minor),
        .ino = buf.ino,
        .nlink = buf.nlink,
        .mode = buf.mode,
        .uid = buf.uid,
        .gid = buf.gid,
        .rdev = linuxDev(buf.rdev_major, buf.rdev_minor),
        .size = @intCast(buf.size),
        .blksize = @intCast(buf.blksize),
        .blocks = @intCast(buf.blocks),
        .atim = .{ .sec = @intCast(buf.atime.sec), .nsec = buf.atime.nsec },
        .mtim = .{ .sec = @intCast(buf.mtime.sec), .nsec = buf.mtime.nsec },
        .ctim = .{ .sec = @intCast(buf.ctime.sec), .nsec = buf.ctime.nsec },
    };
    return true;
}

/// Match the device-number encoding shared by glibc and musl.
fn linuxDev(major: u32, minor: u32) u64 {
    const ma: u64 = major;
    const mi: u64 = minor;
    return ((ma & 0xfffff000) << 32) | ((ma & 0xfff) << 8) | ((mi & 0xffffff00) << 12) | (mi & 0xff);
}

pub const rename_noreplace: c_uint = 1;
pub const rename_exchange: c_uint = 2;

pub const Args = extern struct {
    argc: c_int = 0,
    argv: ?[*]?[*:0]u8 = null,
    allocated: c_int = 0,
};

/// Allocated by libfuse; avoid the version-dependent bit word after `flags`.
pub const FileInfo = extern struct {
    flags: i32,
    bits: u32,
    padding2: u32,
    padding3: u32,
    fh: u64,
    lock_owner: u64,
    poll_events: u32,
    backing_id: i32,
    compat_flags: u64,
    reserved: [2]u64,
};

pub const Context = extern struct {
    fuse: ?*Fuse,
    uid: std.c.uid_t,
    gid: std.c.gid_t,
    pid: std.c.pid_t,
    private_data: ?*anyopaque,
    umask: mode_t,
};

/// Bind only the stable prefix; later fuse_config fields moved between versions.
pub const Config = extern struct {
    set_gid: i32,
    gid: u32,
    set_uid: i32,
    uid: u32,
    set_mode: i32,
    umask: u32,
    entry_timeout: f64,
    negative_timeout: f64,
    attr_timeout: f64,
    intr: i32,
    intr_signal: i32,
    remember: i32,
    hard_remove: i32,
    use_ino: i32,
    readdir_ino: i32,
    direct_io: i32,
    kernel_cache: i32,
    auto_cache: i32,
};

/// Match the platform C ABI used by fstatvfs.
pub const Statvfs = switch (builtin.os.tag) {
    .macos => extern struct {
        bsize: c_ulong,
        frsize: c_ulong,
        blocks: u32,
        bfree: u32,
        bavail: u32,
        files: u32,
        ffree: u32,
        favail: u32,
        fsid: c_ulong,
        flag: c_ulong,
        namemax: c_ulong,
    },
    .linux => extern struct {
        bsize: c_ulong,
        frsize: c_ulong,
        blocks: u64,
        bfree: u64,
        bavail: u64,
        files: u64,
        ffree: u64,
        favail: u64,
        fsid: c_ulong,
        flag: c_ulong,
        namemax: c_ulong,
        type: c_uint,
        spare: [5]c_int,
    },
    else => void,
};

pub const FillDirFn = *const fn (?*anyopaque, [*:0]const u8, ?*const Stat, off_t, c_int) callconv(.c) c_int;

pub const GetattrFn = *const fn ([*:0]const u8, *Stat, ?*FileInfo) callconv(.c) c_int;
pub const ReadlinkFn = *const fn ([*:0]const u8, [*]u8, usize) callconv(.c) c_int;
pub const MknodFn = *const fn ([*:0]const u8, mode_t, std.c.dev_t) callconv(.c) c_int;
pub const MkdirFn = *const fn ([*:0]const u8, mode_t) callconv(.c) c_int;
pub const PathFn = *const fn ([*:0]const u8) callconv(.c) c_int;
pub const TwoPathFn = *const fn ([*:0]const u8, [*:0]const u8) callconv(.c) c_int;
pub const RenameFn = *const fn ([*:0]const u8, [*:0]const u8, c_uint) callconv(.c) c_int;
pub const ChmodFn = *const fn ([*:0]const u8, mode_t, ?*FileInfo) callconv(.c) c_int;
pub const ChownFn = *const fn ([*:0]const u8, std.c.uid_t, std.c.gid_t, ?*FileInfo) callconv(.c) c_int;
pub const TruncateFn = *const fn ([*:0]const u8, off_t, ?*FileInfo) callconv(.c) c_int;
pub const FileInfoFn = *const fn ([*:0]const u8, *FileInfo) callconv(.c) c_int;
pub const ReadFn = *const fn ([*:0]const u8, [*]u8, usize, off_t, *FileInfo) callconv(.c) c_int;
pub const WriteFn = *const fn ([*:0]const u8, [*]const u8, usize, off_t, *FileInfo) callconv(.c) c_int;
pub const StatfsFn = *const fn ([*:0]const u8, *Statvfs) callconv(.c) c_int;
pub const FsyncFn = *const fn ([*:0]const u8, c_int, *FileInfo) callconv(.c) c_int;
pub const SetxattrFn = *const fn ([*:0]const u8, [*:0]const u8, [*]const u8, usize, c_int) callconv(.c) c_int;
pub const GetxattrFn = *const fn ([*:0]const u8, [*:0]const u8, [*]u8, usize) callconv(.c) c_int;
pub const ListxattrFn = *const fn ([*:0]const u8, [*]u8, usize) callconv(.c) c_int;
pub const ReaddirFn = *const fn ([*:0]const u8, ?*anyopaque, FillDirFn, off_t, *FileInfo, c_uint) callconv(.c) c_int;
pub const InitFn = *const fn (*ConnInfo, *Config) callconv(.c) ?*anyopaque;
pub const DestroyFn = *const fn (?*anyopaque) callconv(.c) void;
pub const AccessFn = *const fn ([*:0]const u8, c_int) callconv(.c) c_int;
pub const CreateFn = *const fn ([*:0]const u8, mode_t, *FileInfo) callconv(.c) c_int;
pub const LockFn = *const fn ([*:0]const u8, *FileInfo, c_int, ?*anyopaque) callconv(.c) c_int;
pub const UtimensFn = *const fn ([*:0]const u8, *const [2]std.c.timespec, ?*FileInfo) callconv(.c) c_int;
pub const BmapFn = *const fn ([*:0]const u8, usize, *u64) callconv(.c) c_int;
pub const IoctlFn = *const fn ([*:0]const u8, c_uint, ?*anyopaque, *FileInfo, c_uint, ?*anyopaque) callconv(.c) c_int;
pub const PollFn = *const fn ([*:0]const u8, *FileInfo, ?*anyopaque, *c_uint) callconv(.c) c_int;
pub const WriteBufFn = *const fn ([*:0]const u8, ?*anyopaque, off_t, *FileInfo) callconv(.c) c_int;
pub const ReadBufFn = *const fn ([*:0]const u8, *?*anyopaque, usize, off_t, *FileInfo) callconv(.c) c_int;
pub const FlockFn = *const fn ([*:0]const u8, *FileInfo, c_int) callconv(.c) c_int;
pub const FallocateFn = *const fn ([*:0]const u8, c_int, off_t, off_t, *FileInfo) callconv(.c) c_int;
pub const CopyFileRangeFn = *const fn ([*:0]const u8, *FileInfo, off_t, [*:0]const u8, *FileInfo, off_t, usize, c_int) callconv(.c) isize;
pub const LseekFn = *const fn ([*:0]const u8, off_t, c_int, *FileInfo) callconv(.c) off_t;
pub const StatxFn = *const fn ([*:0]const u8, c_int, c_int, ?*anyopaque, ?*FileInfo) callconv(.c) c_int;

/// Older libfuse versions copy only the supported prefix of this layout.
pub const Operations = extern struct {
    getattr: ?GetattrFn = null,
    readlink: ?ReadlinkFn = null,
    mknod: ?MknodFn = null,
    mkdir: ?MkdirFn = null,
    unlink: ?PathFn = null,
    rmdir: ?PathFn = null,
    symlink: ?TwoPathFn = null,
    rename: ?RenameFn = null,
    link: ?TwoPathFn = null,
    chmod: ?ChmodFn = null,
    chown: ?ChownFn = null,
    truncate: ?TruncateFn = null,
    open: ?FileInfoFn = null,
    read: ?ReadFn = null,
    write: ?WriteFn = null,
    statfs: ?StatfsFn = null,
    flush: ?FileInfoFn = null,
    release: ?FileInfoFn = null,
    fsync: ?FsyncFn = null,
    setxattr: ?SetxattrFn = null,
    getxattr: ?GetxattrFn = null,
    listxattr: ?ListxattrFn = null,
    removexattr: ?TwoPathFn = null,
    opendir: ?FileInfoFn = null,
    readdir: ?ReaddirFn = null,
    releasedir: ?FileInfoFn = null,
    fsyncdir: ?FsyncFn = null,
    init: ?InitFn = null,
    destroy: ?DestroyFn = null,
    access: ?AccessFn = null,
    create: ?CreateFn = null,
    lock: ?LockFn = null,
    utimens: ?UtimensFn = null,
    bmap: ?BmapFn = null,
    ioctl: ?IoctlFn = null,
    poll: ?PollFn = null,
    write_buf: ?WriteBufFn = null,
    read_buf: ?ReadBufFn = null,
    flock: ?FlockFn = null,
    fallocate: ?FallocateFn = null,
    copy_file_range: ?CopyFileRangeFn = null,
    lseek: ?LseekFn = null,
    statx: ?StatxFn = null,
    syncfs: ?PathFn = null,
};

pub const GetgroupsFn = *const fn (c_int, [*]std.c.gid_t) callconv(.c) c_int;

/// Omit unused trailing fields to avoid warnings from older libfuse versions.
pub const operations_size = @offsetOf(Operations, "statx");

const static = struct {
    extern fn fuse_opt_add_arg(args: *Args, arg: [*:0]const u8) c_int;
    extern fn fuse_opt_free_args(args: *Args) void;
    extern fn fuse_new_31(args: *Args, op: *const Operations, op_size: usize, user_data: ?*anyopaque) ?*Fuse;
    extern fn fuse_mount(f: *Fuse, mountpoint: [*:0]const u8) c_int;
    extern fn fuse_unmount(f: *Fuse) void;
    extern fn fuse_destroy(f: *Fuse) void;
    extern fn fuse_get_session(f: *Fuse) *Session;
    extern fn fuse_set_signal_handlers(se: *Session) c_int;
    extern fn fuse_remove_signal_handlers(se: *Session) void;
    extern fn fuse_session_exit(se: *Session) void;
    extern fn fuse_loop(f: *Fuse) c_int;
    extern fn fuse_loop_mt_31(f: *Fuse, clone_fd: c_int) c_int;
    extern fn fuse_get_context() *Context;
    extern fn fuse_getgroups(size: c_int, list: [*]std.c.gid_t) c_int;
};

pub const Library = struct {
    dyn: ?std.DynLib,
    optAddArg: *const fn (*Args, [*:0]const u8) callconv(.c) c_int,
    optFreeArgs: *const fn (*Args) callconv(.c) void,
    new: *const fn (*Args, *const Operations, usize, ?*anyopaque) callconv(.c) ?*Fuse,
    mount: *const fn (*Fuse, [*:0]const u8) callconv(.c) c_int,
    unmount: *const fn (*Fuse) callconv(.c) void,
    destroy: *const fn (*Fuse) callconv(.c) void,
    getSession: *const fn (*Fuse) callconv(.c) *Session,
    setSignalHandlers: *const fn (*Session) callconv(.c) c_int,
    removeSignalHandlers: *const fn (*Session) callconv(.c) void,
    sessionExit: *const fn (*Session) callconv(.c) void,
    loop: *const fn (*Fuse) callconv(.c) c_int,
    loopMt: *const fn (*Fuse, c_int) callconv(.c) c_int,
    getContext: *const fn () callconv(.c) *Context,
    getGroups: ?GetgroupsFn,

    const paths: []const [:0]const u8 = switch (builtin.os.tag) {
        .macos => &.{
            "/usr/local/lib/libfuse3.dylib",
            "/Library/Application Support/fuse-t/lib/libfuse3.dylib",
        },
        else => &.{},
    };

    pub fn load() Error!Library {
        if (builtin.os.tag == .linux) {
            return .{
                .dyn = null,
                .optAddArg = static.fuse_opt_add_arg,
                .optFreeArgs = static.fuse_opt_free_args,
                .new = static.fuse_new_31,
                .mount = static.fuse_mount,
                .unmount = static.fuse_unmount,
                .destroy = static.fuse_destroy,
                .getSession = static.fuse_get_session,
                .setSignalHandlers = static.fuse_set_signal_handlers,
                .removeSignalHandlers = static.fuse_remove_signal_handlers,
                .sessionExit = static.fuse_session_exit,
                .loop = static.fuse_loop,
                .loopMt = static.fuse_loop_mt_31,
                .getContext = static.fuse_get_context,
                .getGroups = static.fuse_getgroups,
            };
        }
        var dyn = openAny() orelse return error.LibraryNotFound;
        errdefer dyn.close();
        return .{
            .dyn = dyn,
            .optAddArg = try lookup(&dyn, @FieldType(Library, "optAddArg"), "fuse_opt_add_arg"),
            .optFreeArgs = try lookup(&dyn, @FieldType(Library, "optFreeArgs"), "fuse_opt_free_args"),
            .new = dyn.lookup(@FieldType(Library, "new"), "fuse_new_31") orelse
                try lookup(&dyn, @FieldType(Library, "new"), "fuse_new"),
            .mount = try lookup(&dyn, @FieldType(Library, "mount"), "fuse_mount"),
            .unmount = try lookup(&dyn, @FieldType(Library, "unmount"), "fuse_unmount"),
            .destroy = try lookup(&dyn, @FieldType(Library, "destroy"), "fuse_destroy"),
            .getSession = try lookup(&dyn, @FieldType(Library, "getSession"), "fuse_get_session"),
            .setSignalHandlers = try lookup(&dyn, @FieldType(Library, "setSignalHandlers"), "fuse_set_signal_handlers"),
            .removeSignalHandlers = try lookup(&dyn, @FieldType(Library, "removeSignalHandlers"), "fuse_remove_signal_handlers"),
            .sessionExit = try lookup(&dyn, @FieldType(Library, "sessionExit"), "fuse_session_exit"),
            .loop = try lookup(&dyn, @FieldType(Library, "loop"), "fuse_loop"),
            .loopMt = try lookup(&dyn, @FieldType(Library, "loopMt"), "fuse_loop_mt_31"),
            .getContext = try lookup(&dyn, @FieldType(Library, "getContext"), "fuse_get_context"),
            .getGroups = dyn.lookup(GetgroupsFn, "fuse_getgroups"),
        };
    }

    pub fn unload(self: *Library) void {
        if (self.dyn) |*dyn| dyn.close();
    }

    fn openAny() ?std.DynLib {
        for (paths) |path| {
            return std.DynLib.openZ(path) catch continue;
        }
        return null;
    }

    fn lookup(dyn: *std.DynLib, comptime T: type, name: [:0]const u8) Error!T {
        return dyn.lookup(T, name) orelse error.SymbolMissing;
    }
};

pub const RunOptions = struct {
    /// Include the program name and pass options as "-o" pairs.
    args: []const []const u8,
    /// Must be absolute for mount-table comparisons.
    mountpoint: []const u8,
    operations: *const Operations,
    private_data: ?*anyopaque,
    single_thread: bool,
};

/// Captured before unmount so cleanup cannot hide an unexpected session exit.
pub const Outcome = struct {
    /// Diagnostic only; fuse-t can report a nonzero result after a normal unmount.
    loop_result: c_int,
    signaled: bool,
    still_mounted: bool,
};

var exit_session: ?*Session = null;
var exit_fn: ?*const fn (*Session) callconv(.c) void = null;
var signal_seen = std.atomic.Value(bool).init(false);

fn onSignal(_: std.c.SIG) callconv(.c) void {
    signal_seen.store(true, .seq_cst);
    if (exit_session) |session| exit_fn.?(session);
}

const stop_signals = [_]std.c.SIG{ .TERM, .INT, .HUP };

/// Run the session through cleanup so failure counters are final when this returns.
pub fn run(lib: *const Library, allocator: std.mem.Allocator, io: std.Io, options: RunOptions) Error!Outcome {
    var args: Args = .{};
    defer lib.optFreeArgs(&args);
    for (options.args) |arg| {
        const arg_z = try allocator.dupeSentinel(u8, arg, 0);
        defer allocator.free(arg_z);
        if (lib.optAddArg(&args, arg_z) != 0) return error.OutOfMemory;
    }
    const mountpoint_z = try allocator.dupeSentinel(u8, options.mountpoint, 0);
    defer allocator.free(mountpoint_z);

    const fuse = lib.new(&args, options.operations, operations_size, options.private_data) orelse return error.CreateFailed;
    defer lib.destroy(fuse);
    if (lib.mount(fuse, mountpoint_z) != 0) return error.MountFailed;

    const session = lib.getSession(fuse);
    _ = lib.setSignalHandlers(session);
    exit_session = session;
    exit_fn = lib.sessionExit;
    signal_seen.store(false, .seq_cst);
    var saved: [stop_signals.len]std.c.Sigaction = undefined;
    const act: std.c.Sigaction = .{
        .handler = .{ .handler = onSignal },
        .mask = std.posix.sigemptyset(),
        .flags = 0,
    };
    for (stop_signals, 0..) |sig, i| std.posix.sigaction(sig, &act, &saved[i]);

    const loop_result = if (options.single_thread) lib.loop(fuse) else lib.loopMt(fuse, 0);

    const outcome: Outcome = .{
        .loop_result = loop_result,
        .signaled = signal_seen.load(.seq_cst),
        .still_mounted = isMounted(allocator, io, options.mountpoint),
    };

    for (stop_signals, 0..) |sig, i| std.posix.sigaction(sig, &saved[i], null);
    exit_session = null;
    lib.removeSignalHandlers(session);
    lib.unmount(fuse);
    return outcome;
}

/// Consult the mount table without accessing a mountpoint that could hang after server failure.
pub fn isMounted(allocator: std.mem.Allocator, io: std.Io, mountpoint: []const u8) bool {
    switch (builtin.os.tag) {
        .macos => {
            var list: ?[*]darwin.Statfs = null;
            const count = darwin.mountList(&list, darwin.mnt_nowait);
            if (count <= 0) return false;
            for (list.?[0..@intCast(count)]) |*entry| {
                const name = std.mem.sliceTo(&entry.mntonname, 0);
                if (std.mem.eql(u8, name, mountpoint)) return true;
            }
            return false;
        },
        .linux => {
            const table = std.Io.Dir.readFileAlloc(.cwd(), io, "/proc/self/mounts", allocator, .limited(1 << 20)) catch return false;
            defer allocator.free(table);
            var lines = std.mem.splitScalar(u8, table, '\n');
            while (lines.next()) |line| {
                var fields = std.mem.splitScalar(u8, line, ' ');
                _ = fields.next() orelse continue;
                const escaped = fields.next() orelse continue;
                if (mountEntryMatches(escaped, mountpoint)) return true;
            }
            return false;
        },
        else => return false,
    }
}

/// Decode /proc/self/mounts octal escapes before comparing paths.
fn mountEntryMatches(escaped: []const u8, mountpoint: []const u8) bool {
    var i: usize = 0;
    var j: usize = 0;
    while (i < escaped.len) {
        var c = escaped[i];
        if (c == '\\' and i + 4 <= escaped.len) {
            const digits = escaped[i + 1 .. i + 4];
            c = std.fmt.parseInt(u8, digits, 8) catch return false;
            i += 4;
        } else {
            i += 1;
        }
        if (j >= mountpoint.len or mountpoint[j] != c) return false;
        j += 1;
    }
    return j == mountpoint.len;
}

const darwin = struct {
    const mnt_nowait: c_int = 2;

    /// Match Darwin's statfs ABI with 64-bit inode support.
    const Statfs = extern struct {
        bsize: u32,
        iosize: i32,
        blocks: u64,
        bfree: u64,
        bavail: u64,
        files: u64,
        ffree: u64,
        fsid: [2]i32,
        owner: u32,
        type: u32,
        flags: u32,
        fssubtype: u32,
        fstypename: [16]u8,
        mntonname: [1024]u8,
        mntfromname: [1024]u8,
        flags_ext: u32,
        reserved: [7]u32,
    };

    extern "c" fn getmntinfo(mntbufp: *?[*]Statfs, flags: c_int) c_int;
    extern "c" fn @"getmntinfo$INODE64"(mntbufp: *?[*]Statfs, flags: c_int) c_int;

    const mountList = if (builtin.cpu.arch == .x86_64) @"getmntinfo$INODE64" else getmntinfo;
};

pub fn negErrno(e: std.c.E) c_int {
    return -@as(c_int, @backingInt(e));
}

pub fn privateData(lib: *const Library, comptime T: type) *T {
    return @ptrCast(@alignCast(lib.getContext().private_data.?));
}

/// Emit ABI measurements for comparison with C headers in tests/fuse_abi.sh.
pub fn writeAbi(writer: *std.Io.Writer) !void {
    try writer.print("offsetof fuse_file_info flags {d}\n", .{@offsetOf(FileInfo, "flags")});
    try writer.print("offsetof fuse_file_info fh {d}\n", .{@offsetOf(FileInfo, "fh")});
    inline for (@typeInfo(Context).@"struct".field_names) |name| {
        try writer.print("offsetof fuse_context {s} {d}\n", .{ name, @offsetOf(Context, name) });
    }
    inline for (@typeInfo(Config).@"struct".field_names) |name| {
        try writer.print("offsetof fuse_config {s} {d}\n", .{ name, @offsetOf(Config, name) });
    }
    inline for (@typeInfo(Operations).@"struct".field_names) |name| {
        try writer.print("offsetof fuse_operations {s} {d}\n", .{ name, @offsetOf(Operations, name) });
    }
}

test "the Linux stat layout matches the C library" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const testing = std.testing;
    const expected: usize = if (builtin.cpu.arch == .x86_64) 144 else 128;
    try testing.expectEqual(expected, @sizeOf(Stat));
    try testing.expectEqual(0x801, linuxDev(8, 1));
    try testing.expectEqual(0x1200abcd345ef, linuxDev(0x12345, 0xabcdef));
}

test "FUSE layouts preserve the supported C ABI" {
    const testing = std.testing;
    try testing.expectEqual(44 * @sizeOf(usize), @sizeOf(Operations));
    try testing.expectEqual(27 * @sizeOf(usize), @offsetOf(Operations, "init"));
    try testing.expectEqual(64, @sizeOf(FileInfo));
    try testing.expectEqual(16, @offsetOf(FileInfo, "fh"));
    try testing.expectEqual(40, @sizeOf(Context));
    try testing.expectEqual(24, @offsetOf(Context, "private_data"));
    try testing.expectEqual(80, @offsetOf(Config, "auto_cache"));
    try testing.expectEqual(64, @offsetOf(Config, "use_ino"));
    try testing.expectEqual(24, @sizeOf(Args));
}

test "mount table entries are unescaped before comparison" {
    const testing = std.testing;
    try testing.expect(mountEntryMatches("/mnt/plain", "/mnt/plain"));
    try testing.expect(mountEntryMatches("/mnt/with\\040space", "/mnt/with space"));
    try testing.expect(!mountEntryMatches("/mnt/plain", "/mnt/plain2"));
    try testing.expect(!mountEntryMatches("/mnt/plain2", "/mnt/plain"));
    try testing.expect(!mountEntryMatches("/mnt/\\04", "/mnt/ "));
}
