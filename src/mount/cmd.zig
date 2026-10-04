//! Command handlers for mounting, unmounting, and creating containers.

const std = @import("std");
const builtin = @import("builtin");
const mem = std.mem;
const testing = std.testing;
const Allocator = std.mem.Allocator;
const Io = std.Io;

const Config = @import("../Config.zig");
const container = @import("../container.zig");
const crypto = @import("../crypto.zig");
const key_loader = @import("../key_loader.zig");
const keygen = @import("../keygen.zig");
const processor = @import("../processor.zig");
const fs = @import("../fs.zig");
const fuse = @import("fuse.zig");
const Mount = @import("Mount.zig");
const names = @import("names.zig");
const faults = @import("faults.zig");

pub const Error = error{
    InvalidArguments,
    UnmountFailed,
    MountFailed,
    InitFailed,
};

const default_max_file_size: usize = 1 << 30;
const default_memory_limit: usize = 4 << 30;
const key_check_entries = 1024;

pub const usage_text =
    \\Usage: turbocrypt mount [options] <encrypted-dir> <mountpoint>
    \\       turbocrypt unmount <mountpoint>
    \\
    \\<encrypted-dir> is either a directory of encrypted files, as written by
    \\"turbocrypt encrypt", or a container made by "turbocrypt init".
    \\<mountpoint> is an empty directory where the plain files appear while
    \\the volume is mounted.
    \\
    \\With a directory of encrypted files, each open file is held decrypted in
    \\memory and written back when it closes. With a container, files are read
    \\and written in place, in encrypted chunks, and the size options below do
    \\not apply. The command stays in the foreground until the volume is
    \\unmounted, unless --daemon is given.
    \\
    \\mount does not encrypt an existing directory. To start from plain files,
    \\encrypt them first, then mount the result:
    \\  turbocrypt encrypt documents/ encrypted/
    \\  mkdir ~/Volumes/documents
    \\  turbocrypt mount encrypted/ ~/Volumes/documents
    \\  turbocrypt unmount ~/Volumes/documents
    \\
    \\Options:
    \\  --key <file>, --password, --context <string>
    \\                          As for every other command
    \\  --encrypted-filenames   The encrypted directory has encrypted names
    \\  --enc-suffix            Files in the encrypted directory carry .enc
    \\                          A container records both settings itself
    \\  --read-only             Refuse every change with EROFS
    \\  --daemon                Return once the volume is mounted
    \\  --single-thread         Serve one request at a time, for debugging
    \\  --debug                 Print libfuse and mount diagnostics
    \\  --volname <name>        The volume name (default: the directory name)
    \\  --allow-other           Serve other users, with POSIX permission checks
    \\  --max-file-size <bytes> Largest file that can be opened (default 1 GiB)
    \\  --memory-limit <bytes>  Budget for all open files (default 4 GiB)
    \\  --rescue-dir <dir>      Where unwritable files go at unmount
    \\  --force                 Skip the key check on the first file
    \\  -o <option>             A libfuse or fuse-t option, may be repeated
    \\
    \\Exit status: 0 after a requested unmount, 1 for a setup error,
    \\2 when a file could not be written back, 3 when the session failed.
    \\
;

pub const init_usage_text =
    \\Usage: turbocrypt init [options] <container-dir>
    \\
    \\Create an empty container for "turbocrypt mount". A container is a
    \\directory of encrypted files optimized for random access: the mount
    \\reads and writes them in 16 KiB chunks and keeps no file in memory.
    \\
    \\<container-dir> must not exist yet, or must be an empty directory.
    \\Nothing is converted. To fill it, mount it and copy files into the
    \\mounted view. The key and the context given here are needed at every
    \\mount. The container is a directory, not a disk image, and it has no
    \\fixed capacity.
    \\
    \\Options:
    \\  --key <file>, --password, --context <string>
    \\                          As for every other command
    \\  --encrypted-filenames   Encrypt the names in the container (default:
    \\                          the saved configuration, else plain names)
    \\  --enc-suffix            Give the files in the container a .enc suffix
    \\
    \\Example:
    \\  turbocrypt init --key secret.key encrypted-container/
    \\  mkdir mounted
    \\  turbocrypt mount --key secret.key encrypted-container/ mounted/
    \\  cp -R documents/. mounted/
    \\  turbocrypt unmount mounted/
    \\
;

const DaemonChild = struct {
    ready_fd: std.c.fd_t,
    key_fd: std.c.fd_t,
};

/// Select one mount backend from the reserved root entry.
const Format = Mount.Format;

const CommonOptions = struct {
    key: ?[]const u8 = null,
    password: bool = false,
    context: ?[]const u8 = null,
    /// Leave null until the caller explicitly gives this flag.
    /// Only init and v1 mounts then consult the configuration default.
    encrypted_filenames: ?bool = null,
    enc_suffix: bool = false,

    fn take(self: *CommonOptions, args: []const []const u8, i: *usize) !bool {
        const arg = args[i.*];
        if (mem.eql(u8, arg, "--key")) {
            self.key = try valueOf(args, i);
        } else if (mem.eql(u8, arg, "--password")) {
            self.password = true;
        } else if (mem.eql(u8, arg, "--context")) {
            self.context = try valueOf(args, i);
        } else if (mem.eql(u8, arg, "--encrypted-filenames")) {
            self.encrypted_filenames = true;
        } else if (mem.eql(u8, arg, "--enc-suffix")) {
            self.enc_suffix = true;
        } else {
            return false;
        }
        return true;
    }
};

const MountOptions = struct {
    common: CommonOptions = .{},
    read_only: bool = false,
    daemon: bool = false,
    daemon_child: ?DaemonChild = null,
    single_thread: bool = false,
    debug: bool = false,
    volname: ?[]const u8 = null,
    allow_other: bool = false,
    /// Leave null until v1 defaults are applied.
    /// Containers reject an explicit size limit.
    max_file_size: ?usize = null,
    memory_limit: ?usize = null,
    rescue_dir: ?[]const u8 = null,
    force: bool = false,
    fuse_options: std.ArrayList([]const u8) = .empty,
    backing: []const u8 = &.{},
    mountpoint: []const u8 = &.{},

    fn deinit(self: *MountOptions, gpa: Allocator) void {
        self.fuse_options.deinit(gpa);
    }
};

fn valueOf(args: []const []const u8, i: *usize) ![]const u8 {
    if (i.* + 1 >= args.len) {
        std.debug.print("Error: {s} requires a value\n", .{args[i.*]});
        return error.InvalidArguments;
    }
    i.* += 1;
    return args[i.*];
}

fn parseSize(name: []const u8, value: []const u8) !usize {
    return std.fmt.parseUnsigned(usize, value, 10) catch {
        std.debug.print("Error: {s} needs a size in bytes, got '{s}'\n", .{ name, value });
        return error.InvalidArguments;
    };
}

fn parseFd(value: []const u8) !std.c.fd_t {
    return std.fmt.parseInt(std.c.fd_t, value, 10) catch return error.InvalidArguments;
}

/// Parse command-line syntax without choosing a backend.
/// Apply defaults and validate limits only after the backend is known.
fn parseMountOptions(gpa: Allocator, args: []const []const u8) !MountOptions {
    var opts: MountOptions = .{};
    errdefer opts.deinit(gpa);
    var positional: std.ArrayList([]const u8) = .empty;
    defer positional.deinit(gpa);

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        if (try opts.common.take(args, &i)) continue;
        const arg = args[i];
        if (mem.eql(u8, arg, "--read-only")) {
            opts.read_only = true;
        } else if (mem.eql(u8, arg, "--daemon")) {
            opts.daemon = true;
        } else if (mem.eql(u8, arg, "--daemon-child")) {
            const ready = try parseFd(try valueOf(args, &i));
            const key = try parseFd(try valueOf(args, &i));
            opts.daemon_child = .{ .ready_fd = ready, .key_fd = key };
        } else if (mem.eql(u8, arg, "--single-thread")) {
            opts.single_thread = true;
        } else if (mem.eql(u8, arg, "--debug")) {
            opts.debug = true;
        } else if (mem.eql(u8, arg, "--volname")) {
            opts.volname = try valueOf(args, &i);
        } else if (mem.eql(u8, arg, "--allow-other")) {
            opts.allow_other = true;
        } else if (mem.eql(u8, arg, "--max-file-size")) {
            opts.max_file_size = try parseSize(arg, try valueOf(args, &i));
        } else if (mem.eql(u8, arg, "--memory-limit")) {
            opts.memory_limit = try parseSize(arg, try valueOf(args, &i));
        } else if (mem.eql(u8, arg, "--rescue-dir")) {
            opts.rescue_dir = try valueOf(args, &i);
        } else if (mem.eql(u8, arg, "--force")) {
            opts.force = true;
        } else if (mem.eql(u8, arg, "-o")) {
            const list = try valueOf(args, &i);
            var it = mem.splitScalar(u8, list, ',');
            while (it.next()) |option| {
                if (option.len != 0) try opts.fuse_options.append(gpa, option);
            }
        } else if (mem.startsWith(u8, arg, "-")) {
            std.debug.print("Error: Unknown option '{s}'\n", .{arg});
            return error.InvalidArguments;
        } else {
            try positional.append(gpa, arg);
        }
    }

    if (positional.items.len != 2) {
        std.debug.print("{s}", .{usage_text});
        return error.InvalidArguments;
    }
    opts.backing = positional.items[0];
    opts.mountpoint = positional.items[1];

    for (opts.fuse_options.items) |option| {
        if (refusedOption(option)) |why| {
            std.debug.print("Error: the option '{s}' is refused: {s}\n", .{ option, why });
            return error.InvalidArguments;
        }
    }
    return opts;
}

/// Use plain names if configuration cannot be loaded.
fn configuredEncryptedFilenames(
    gpa: Allocator,
    io: Io,
    environ_map: *const std.process.Environ.Map,
) bool {
    var cfg = Config.load(gpa, io, environ_map) catch return false;
    defer cfg.deinit(gpa);
    return cfg.encrypted_filenames orelse false;
}

fn applyV1Defaults(
    opts: *MountOptions,
    gpa: Allocator,
    io: Io,
    environ_map: *const std.process.Environ.Map,
) !void {
    if (opts.common.encrypted_filenames == null) {
        opts.common.encrypted_filenames = configuredEncryptedFilenames(gpa, io, environ_map);
    }
    const max_file_size = opts.max_file_size orelse default_max_file_size;
    const memory_limit = opts.memory_limit orelse default_memory_limit;
    if (max_file_size == 0) {
        std.debug.print("Error: --max-file-size must not be 0\n", .{});
        return error.InvalidArguments;
    }
    const minimum = minimumMemoryLimit(max_file_size) orelse {
        std.debug.print("Error: --max-file-size {d} is too large\n", .{max_file_size});
        return error.InvalidArguments;
    };
    if (memory_limit < minimum) {
        std.debug.print("Error: --memory-limit must be at least three times the file limit plus 1 MiB, that is {d} bytes\n", .{minimum});
        return error.InvalidArguments;
    }
    opts.max_file_size = max_file_size;
    opts.memory_limit = memory_limit;
}

/// Reject options that only make sense for v1 staging and recovery.
fn refuseV1OnlyOptions(opts: *const MountOptions) !void {
    if (opts.force) {
        std.debug.print("Error: --force does not apply to a container: its descriptor is the key check, and it cannot be skipped\n", .{});
        return error.InvalidArguments;
    }
    const given = [_]struct { set: bool, name: []const u8 }{
        .{ .set = opts.max_file_size != null, .name = "--max-file-size" },
        .{ .set = opts.memory_limit != null, .name = "--memory-limit" },
        .{ .set = opts.rescue_dir != null, .name = "--rescue-dir" },
    };
    for (given) |option| {
        if (!option.set) continue;
        std.debug.print("Error: {s} applies to a directory of ordinary encrypted files, not to a container\n", .{option.name});
        std.debug.print("       A container mount keeps no file in memory and has nothing to rescue at unmount\n", .{});
        return error.InvalidArguments;
    }
}

/// Return the worst-case memory needed to grow one file, or null on overflow.
pub fn minimumMemoryLimit(max_file_size: usize) ?usize {
    const triple = std.math.mul(usize, max_file_size, 3) catch return null;
    return std.math.add(usize, triple, 1 << 20) catch return null;
}

/// A trailing `=` means this option accepts a value.
const common_options = [_][]const u8{
    "noatime",
    "debug",
};

const allowed_options: []const []const u8 = if (builtin.os.tag == .macos)
    &(common_options ++ fuse_t_options)
else
    &(common_options ++ [_][]const u8{"max_read="});

const fuse_t_options = [_][]const u8{
    "volname=",
    "location=",
    "rwsize=",
    "noattrcache",
    "attrcache-timeout=",
    "nfc",
    "nobrowse",
    "nomtime",
    "namedattr",
    "nonamedattr",
    "backend=",
    "listen_addr=",
};

const Refusal = struct {
    name: []const u8,
    why: []const u8,
};

/// Reject options that would defeat permission checks or the mount's cache and path guarantees.
const refused_options = [_]Refusal{
    .{ .name = "use_ino", .why = "the mount relies on the node ids of libfuse" },
    .{ .name = "readdir_ino", .why = "the mount relies on the node ids of libfuse" },
    .{ .name = "hard_remove", .why = "the mount needs the rename of open files that libfuse does without it" },
    .{ .name = "nullpath_ok", .why = "every callback needs a path" },
    .{ .name = "nopath", .why = "every callback needs a path" },
    .{ .name = "modules=", .why = "modules rewrite paths behind the mount" },
    .{ .name = "subdir=", .why = "it rewrites paths behind the mount" },
    .{ .name = "iconv", .why = "it rewrites names behind the mount" },
    .{ .name = "uid=", .why = "the mount checks the real owner and mode" },
    .{ .name = "gid=", .why = "the mount checks the real owner and mode" },
    .{ .name = "umask=", .why = "the mount checks the real owner and mode" },
    .{ .name = "fmask=", .why = "the mount checks the real owner and mode" },
    .{ .name = "dmask=", .why = "the mount checks the real owner and mode" },
    .{ .name = "writeback_cache", .why = "writes from the page cache carry no credentials" },
    .{ .name = "ro", .why = "use --read-only" },
    .{ .name = "allow_other", .why = "use --allow-other" },
    .{ .name = "allow_root", .why = "use --allow-other" },
    .{ .name = "direct_io", .why = "the write-back depends on the default caching" },
    .{ .name = "auto_cache", .why = "the write-back depends on the default caching" },
    .{ .name = "kernel_cache", .why = "the write-back depends on the default caching" },
    .{ .name = "attr_timeout=", .why = "the write-back depends on the default caching" },
    .{ .name = "entry_timeout=", .why = "the write-back depends on the default caching" },
    .{ .name = "negative_timeout=", .why = "the write-back depends on the default caching" },
    .{ .name = "ac_attr_timeout=", .why = "the write-back depends on the default caching" },
};

fn optionMatches(option: []const u8, pattern: []const u8) bool {
    if (mem.endsWith(u8, pattern, "=")) return mem.startsWith(u8, option, pattern);
    return mem.eql(u8, option, pattern);
}

fn givesOption(options: []const []const u8, pattern: []const u8) bool {
    for (options) |option| {
        if (optionMatches(option, pattern)) return true;
    }
    return false;
}

/// Explain why an option is rejected, or return null when it is accepted.
pub fn refusedOption(option: []const u8) ?[]const u8 {
    for (refused_options) |refusal| {
        if (optionMatches(option, refusal.name)) return refusal.why;
    }
    for (allowed_options) |pattern| {
        if (optionMatches(option, pattern)) return null;
    }
    if (builtin.os.tag != .macos) {
        for (fuse_t_options) |pattern| {
            if (optionMatches(option, pattern)) return "it is a fuse-t option, and this is not macOS";
        }
    }
    return "it is not in the list of accepted options";
}

/// Choose a backend from the directory before loading a key.
/// Refuse container subdirectories so they cannot be mistaken for v1 roots.
pub fn selectFormat(gpa: Allocator, io: Io, backing: []const u8) !Format {
    const enclosure = (try container.enclosingRoot(gpa, io, backing)) orelse return .v1;
    defer enclosure.deinit(gpa);
    if (enclosure.isRoot()) return .raf;
    std.debug.print("Error: {s} is inside the container {s}\n", .{ backing, enclosure.root });
    std.debug.print("       A container is mounted at its root: turbocrypt mount {s} <mountpoint>\n", .{enclosure.root});
    return error.InvalidArguments;
}

/// Read filename settings from the authenticated descriptor.
/// Explicit flags must match them; configuration defaults do not apply.
pub fn resolveContainer(
    opts: *const MountOptions,
    io: Io,
    root: Io.Dir,
    descriptor_key: [16]u8,
) !container.Settings {
    const settings = container.readDescriptor(root, io, descriptor_key) catch |err| {
        switch (err) {
            error.DescriptorMissing => std.debug.print("Error: the descriptor {s}/{s} disappeared while the mount started\n", .{ opts.backing, container.descriptor_name }),
            error.AuthenticationFailed => {
                std.debug.print("Error: {s}/{s}: wrong key, wrong context, or damaged descriptor\n", .{ opts.backing, container.descriptor_name });
                std.debug.print("       A container needs the key and the context given to \"turbocrypt init\"\n", .{});
            },
            error.InvalidDescriptor => {
                std.debug.print("Error: {s}/{s} is not a valid container descriptor\n", .{ opts.backing, container.descriptor_name });
                std.debug.print("       If {s} holds ordinary encrypted files, move or delete that file, then mount again.\n", .{opts.backing});
                std.debug.print("       If it is a container, its descriptor is damaged; restore the file from a backup.\n", .{});
            },
            error.UnsupportedDescriptor => std.debug.print("Error: {s}/{s} was written by a newer version of turbocrypt; this build cannot mount it\n", .{ opts.backing, container.descriptor_name }),
            else => std.debug.print("Error: cannot read {s}/{s}: {s}\n", .{ opts.backing, container.descriptor_name, @errorName(err) }),
        }
        return error.MountFailed;
    };
    if (opts.common.encrypted_filenames == true and !settings.encrypted_filenames) {
        std.debug.print("Error: --encrypted-filenames was given, but the container {s} was initialized with plain names\n", .{opts.backing});
        std.debug.print("       The setting of the container applies; drop the option\n", .{});
        return error.InvalidArguments;
    }
    if (opts.common.enc_suffix and !settings.enc_suffix) {
        std.debug.print("Error: --enc-suffix was given, but the container {s} was initialized without the suffix\n", .{opts.backing});
        std.debug.print("       The setting of the container applies; drop the option\n", .{});
        return error.InvalidArguments;
    }
    return settings;
}

pub fn runMount(
    gpa: Allocator,
    io: Io,
    environ_map: *const std.process.Environ.Map,
    args: []const []const u8,
) !void {
    if (args.len == 1 and mem.eql(u8, args[0], "--print-abi")) return printAbi(io);
    if (args.len == 1 and (mem.eql(u8, args[0], "--help") or mem.eql(u8, args[0], "help"))) {
        std.debug.print("{s}", .{usage_text});
        return;
    }
    var opts = try parseMountOptions(gpa, args);
    defer opts.deinit(gpa);

    if (!(fs.isDir(io, opts.backing) catch false)) {
        std.debug.print("Error: the encrypted directory {s} does not exist or is not a directory\n", .{opts.backing});
        return error.InvalidArguments;
    }
    if (!(fs.isDir(io, opts.mountpoint) catch false)) {
        std.debug.print("Error: the mountpoint {s} does not exist or is not a directory\n", .{opts.mountpoint});
        return error.InvalidArguments;
    }
    if (!(isEmptyDir(io, opts.mountpoint) catch true)) {
        std.debug.print("Warning: the mountpoint {s} is not empty. Its own contents are hidden while the volume is mounted.\n         The arguments are <encrypted-dir> <mountpoint>, in that order.\n", .{opts.mountpoint});
    }
    switch (try fs.pathRelation(gpa, io, opts.backing, opts.mountpoint)) {
        .same => {
            std.debug.print("Error: the mountpoint {s} is the encrypted directory itself\n", .{opts.mountpoint});
            return error.InvalidArguments;
        },
        .descendant => {
            std.debug.print("Error: the mountpoint {s} is inside the encrypted directory {s}\n", .{ opts.mountpoint, opts.backing });
            return error.InvalidArguments;
        },
        .other => {},
    }

    const format = try selectFormat(gpa, io, opts.backing);
    if (format == .v1) try applyV1Defaults(&opts, gpa, io, environ_map);

    var lib = fuse.Library.load() catch |err| {
        switch (err) {
            error.LibraryNotFound => std.debug.print("Error: fuse-t is not installed. Get it from https://github.com/macos-fuse-t/fuse-t/releases\n", .{}),
            error.SymbolMissing => std.debug.print("Error: the installed fuse-t is missing an entry point the mount needs\n", .{}),
            else => std.debug.print("Error: cannot load libfuse: {}\n", .{err}),
        }
        return err;
    };
    defer lib.unload();

    if (opts.daemon and opts.daemon_child == null) {
        return runDaemonParent(&opts, gpa, io, environ_map, args);
    }

    var key = try obtainKey(&opts, gpa, io, environ_map);
    const keys = crypto.deriveKeys(key, opts.common.context);
    std.crypto.secureZero(u8, &key);

    var root = try Io.Dir.openDir(.cwd(), io, opts.backing, .{ .iterate = true });
    defer root.close(io);
    if (std.c.flock(root.handle, std.c.LOCK.EX | std.c.LOCK.NB) != 0) {
        std.debug.print("Error: {s} is already mounted by another turbocrypt process\n", .{opts.backing});
        return error.MountFailed;
    }

    const settings: container.Settings = switch (format) {
        .v1 => blk: {
            if (!opts.force) try checkKey(root, gpa, io, opts.backing, opts.mountpoint, keys);
            break :blk .{
                .encrypted_filenames = opts.common.encrypted_filenames orelse false,
                .enc_suffix = opts.common.enc_suffix,
            };
        },
        .raf => blk: {
            var descriptor_key = container.deriveDescriptorKey(keys);
            defer std.crypto.secureZero(u8, &descriptor_key);
            const recorded = try resolveContainer(&opts, io, root, descriptor_key);
            // Report a stray reserved file before explaining that `--force` is unavailable.
            try refuseV1OnlyOptions(&opts);
            break :blk recorded;
        },
    };
    const mapper: names.Mapper = .{
        .enc_suffix = settings.enc_suffix,
        .filename_key = if (settings.encrypted_filenames) keys.filename_key else null,
    };

    const rescue_dir = if (opts.rescue_dir) |dir|
        try gpa.dupe(u8, dir)
    else
        try defaultRescueDir(gpa, environ_map);
    defer gpa.free(rescue_dir);

    if (builtin.mode == .debug) armFaultsFromEnvironment(environ_map);

    const mountpoint = try Io.Dir.realPathFileAlloc(.cwd(), io, opts.mountpoint, gpa);
    defer gpa.free(mountpoint);

    // Clear only the mount process umask so requests retain the client's mask.
    _ = std.c.umask(0);

    var fuse_args: std.ArrayList([]const u8) = .empty;
    defer fuse_args.deinit(gpa);
    try fuse_args.append(gpa, "turbocrypt");
    if (opts.debug) try fuse_args.appendSlice(gpa, &.{ "-o", "debug" });
    if (opts.read_only) try fuse_args.appendSlice(gpa, &.{ "-o", "ro" });
    const volname = if (builtin.os.tag == .macos)
        try gpa.print("volname={s}", .{
            opts.volname orelse Io.Dir.path.basename(mountpoint),
        })
    else
        "";
    defer if (builtin.os.tag == .macos) gpa.free(volname);
    if (builtin.os.tag == .macos) {
        try fuse_args.appendSlice(gpa, &.{ "-o", volname });
        // Use larger requests to reduce per-request overhead for whole-file transfers.
        if (!givesOption(opts.fuse_options.items, "rwsize=")) {
            try fuse_args.appendSlice(gpa, &.{ "-o", "rwsize=1048576" });
        }
        // Ask macOS to compose accented names before the mount receives them.
        // Filename encryption composes names itself, but sidecars and plain-name mounts must use
        // the spelling the kernel supplied.
        if (!givesOption(opts.fuse_options.items, "nfc")) {
            try fuse_args.appendSlice(gpa, &.{ "-o", "nfc" });
        }
    } else {
        try fuse_args.appendSlice(gpa, &.{
            "-o", "default_permissions",
            "-o", "fsname=turbocrypt",
        });
        if (opts.allow_other) try fuse_args.appendSlice(gpa, &.{ "-o", "allow_other" });
    }
    for (opts.fuse_options.items) |option| try fuse_args.appendSlice(gpa, &.{ "-o", option });

    const m = try gpa.create(Mount);
    defer gpa.destroy(m);
    try m.init(gpa, io, &lib, root, keys, mapper, .{
        .read_only = opts.read_only,
        .allow_other = opts.allow_other,
        .format = format,
        .max_file_size = opts.max_file_size orelse default_max_file_size,
        .memory_limit = opts.memory_limit orelse default_memory_limit,
        .rescue_dir = rescue_dir,
        .ready_fd = if (opts.daemon_child) |child| child.ready_fd else null,
        .backing = opts.backing,
        .mountpoint = mountpoint,
    });
    defer m.deinit();

    const outcome = fuse.run(&lib, gpa, io, .{
        .args = fuse_args.items,
        .mountpoint = mountpoint,
        .operations = &Mount.operations,
        .private_data = m,
        .single_thread = opts.single_thread,
    }) catch |err| {
        switch (err) {
            error.CreateFailed => std.debug.print("Error: libfuse refused the mount options\n", .{}),
            error.MountFailed => std.debug.print("Error: cannot mount on {s}\n", .{mountpoint}),
            else => std.debug.print("Error: {}\n", .{err}),
        }
        return error.MountFailed;
    };

    const requested = m.up.load(.seq_cst) and (outcome.signaled or !outcome.still_mounted);
    const failures = m.failureCount();
    const lost = m.lost.load(.seq_cst);
    if (opts.debug) {
        std.debug.print("turbocrypt mount: loop returned {d}, signaled {}, still mounted {}, failures {d}\n", .{
            outcome.loop_result,
            outcome.signaled,
            outcome.still_mounted,
            failures,
        });
    }
    if (fuse.isMounted(gpa, io, mountpoint)) {
        std.debug.print("turbocrypt mount: {s} is still in the mount table; run: umount {s}\n", .{ mountpoint, mountpoint });
    }
    if (lost) {
        std.debug.print("turbocrypt mount: some files could not be written back, see the messages above\n", .{});
        std.process.exit(2);
    }
    if (!requested or failures != 0) {
        if (!requested) std.debug.print("turbocrypt mount: the session ended without an unmount request (loop result {d})\n", .{outcome.loop_result});
        if (failures != 0) std.debug.print("turbocrypt mount: {d} failure(s) during the session\n", .{failures});
        std.process.exit(3);
    }
}

fn isEmptyDir(io: Io, path: []const u8) !bool {
    var dir = try Io.Dir.openDir(.cwd(), io, path, .{ .iterate = true });
    defer dir.close(io);
    var it = dir.iterate();
    return (try it.next(io)) == null;
}

fn obtainKey(
    opts: *MountOptions,
    gpa: Allocator,
    io: Io,
    environ_map: *const std.process.Environ.Map,
) ![16]u8 {
    if (opts.daemon_child) |child| {
        var key: [16]u8 = undefined;
        var got: usize = 0;
        while (got < key.len) {
            const n = std.c.read(child.key_fd, key[got..].ptr, key.len - got);
            if (n <= 0) {
                std.debug.print("Error: no key from the parent process\n", .{});
                return error.MountFailed;
            }
            got += @intCast(n);
        }
        _ = std.c.close(child.key_fd);
        return key;
    }
    return loadKeyFrom(&opts.common, gpa, io, environ_map);
}

fn loadKeyFrom(
    common: *const CommonOptions,
    gpa: Allocator,
    io: Io,
    environ_map: *const std.process.Environ.Map,
) ![16]u8 {
    return key_loader.load(gpa, io, environ_map, common.key, common.password) catch |err| {
        return key_loader.explainLoadError(gpa, environ_map, err, common.key);
    };
}

/// Check the key before the mount can encrypt new files with the wrong one.
///
/// An empty tree passes only after a complete walk finds no regular file.
/// Require `--force` for an incomplete scan, and reject apparent plaintext.
fn checkKey(
    root: Io.Dir,
    gpa: Allocator,
    io: Io,
    backing: []const u8,
    mountpoint: []const u8,
    keys: crypto.DerivedKeys,
) !void {
    var walker = try root.walk(gpa);
    defer walker.deinit();
    var skipped: usize = 0;
    for (0..key_check_entries) |_| {
        const entry = (walker.next(io) catch |err| switch (err) {
            error.AccessDenied => {
                skipped += 1;
                continue;
            },
            else => return err,
        }) orelse {
            if (skipped == 0) return;
            return cannotCheckKey("{d} entries of {s} could not be read or are not encrypted files, and no other file exists", .{ skipped, backing });
        };
        if (entry.kind != .file) continue;
        var buffer: [crypto.overhead_size]u8 = undefined;
        const header = readHeader(io, entry, &buffer) orelse {
            skipped += 1;
            continue;
        };
        crypto.verifyHeaderOnly(header, keys) catch {
            if (looksLikeText(header)) {
                std.debug.print("Error: {s} holds plain files ({s} is not encrypted)\n", .{ backing, entry.path });
                std.debug.print("       The first argument must be a directory of encrypted files.\n", .{});
                std.debug.print("       To create one from these files:\n", .{});
                std.debug.print("         turbocrypt encrypt {s} {s}-encrypted\n", .{ backing, backing });
                std.debug.print("       then mount it:\n", .{});
                std.debug.print("         turbocrypt mount {s}-encrypted {s}\n", .{ backing, mountpoint });
            } else {
                std.debug.print("Error: {s}: wrong decryption key, wrong context, or corrupted file header\n", .{entry.path});
            }
            std.debug.print("       Use --force to mount anyway with this key\n", .{});
            return error.MountFailed;
        };
        return;
    }
    return cannotCheckKey("no readable file among the first {d} entries of {s}", .{ key_check_entries, backing });
}

/// Return null when the header cannot be checked.
/// Return short text-like data so callers can identify likely plaintext.
/// Reject other incomplete headers as unchecked.
fn readHeader(io: Io, entry: Io.Dir.Walker.Entry, buffer: *[crypto.overhead_size]u8) ?[]const u8 {
    const file = entry.dir.openFile(io, entry.basename, .{
        .follow_symlinks = false,
    }) catch return null;
    defer file.close(io);
    const got = file.readPositionalAll(io, buffer, 0) catch return null;
    if (got < buffer.len and !(got > 0 and looksLikeText(buffer[0..got]))) return null;
    return buffer[0..got];
}

fn cannotCheckKey(comptime reason: []const u8, args: anytype) error{MountFailed} {
    std.debug.print("Error: the key cannot be checked: " ++ reason ++ "\n", args);
    std.debug.print("       Use --force to mount anyway with this key\n", .{});
    return error.MountFailed;
}

fn looksLikeText(header: []const u8) bool {
    for (header) |c| {
        if (!std.ascii.isPrint(c) and c != '\n' and c != '\r' and c != '\t') return false;
    }
    return true;
}

fn defaultRescueDir(gpa: Allocator, environ_map: *const std.process.Environ.Map) ![]u8 {
    const app_dir = try Config.getAppDataDir(gpa, environ_map, "turbocrypt");
    defer gpa.free(app_dir);
    return Io.Dir.path.join(gpa, &.{ app_dir, "rescue" });
}

fn armFaultsFromEnvironment(environ_map: *const std.process.Environ.Map) void {
    const value = environ_map.get("TURBOCRYPT_MOUNT_FAULTS") orelse return;
    var list: [faults.max_armed]faults.Kind = undefined;
    var count: usize = 0;
    var it = mem.splitScalar(u8, value, ',');
    while (it.next()) |name| {
        if (name.len == 0 or count == list.len) continue;
        list[count] = std.meta.stringToEnum(faults.Kind, name) orelse {
            std.debug.print("turbocrypt mount: unknown fault '{s}' ignored\n", .{name});
            continue;
        };
        count += 1;
    }
    faults.arm(list[0..count]);
    std.debug.print("turbocrypt mount: {d} fault(s) armed from TURBOCRYPT_MOUNT_FAULTS\n", .{count});
}

/// Prompt for the key while a terminal is still available, then wait for the child mount.
/// Pass the key through a pipe so it never appears in process arguments.
fn runDaemonParent(
    opts: *MountOptions,
    gpa: Allocator,
    io: Io,
    environ_map: *const std.process.Environ.Map,
    args: []const []const u8,
) !void {
    var key = try obtainKey(opts, gpa, io, environ_map);
    defer std.crypto.secureZero(u8, &key);

    var ready: [2]std.c.fd_t = undefined;
    var key_pipe: [2]std.c.fd_t = undefined;
    if (std.c.pipe(&ready) != 0 or std.c.pipe(&key_pipe) != 0) return error.MountFailed;
    _ = std.c.fcntl(ready[0], std.c.F.SETFD, @as(c_int, std.posix.FD_CLOEXEC));
    _ = std.c.fcntl(key_pipe[1], std.c.F.SETFD, @as(c_int, std.posix.FD_CLOEXEC));

    const exe = try std.process.executablePathAlloc(io, gpa);
    defer gpa.free(exe);
    var argv: std.ArrayList([]const u8) = .empty;
    defer argv.deinit(gpa);
    try argv.appendSlice(gpa, &.{ exe, "mount" });
    try argv.appendSlice(gpa, args);
    const ready_text = try gpa.print("{d}", .{ready[1]});
    defer gpa.free(ready_text);
    const key_text = try gpa.print("{d}", .{key_pipe[0]});
    defer gpa.free(key_text);
    try argv.appendSlice(gpa, &.{ "--daemon-child", ready_text, key_text });

    var child = std.process.spawn(io, .{
        .argv = argv.items,
        .stdin = .ignore,
        .stdout = .ignore,
        .stderr = .inherit,
    }) catch |err| {
        std.debug.print("Error: cannot start the mount process: {}\n", .{err});
        return error.MountFailed;
    };
    _ = std.c.close(ready[1]);
    _ = std.c.close(key_pipe[0]);
    _ = std.c.write(key_pipe[1], &key, key.len);
    _ = std.c.close(key_pipe[1]);

    var byte: [1]u8 = undefined;
    const n = std.c.read(ready[0], &byte, 1);
    _ = std.c.close(ready[0]);
    if (n == 1) {
        // The child can report ready before the mount table reflects it.
        const mountpoint = try Io.Dir.realPathFileAlloc(.cwd(), io, opts.mountpoint, gpa);
        defer gpa.free(mountpoint);
        var waited: usize = 0;
        while (!fuse.isMounted(gpa, io, mountpoint) and waited < 100) : (waited += 1) {
            Io.sleep(io, .fromMilliseconds(100), .awake) catch break;
        }
        std.debug.print("Mounted {s} on {s}\n", .{ opts.backing, opts.mountpoint });
        return;
    }
    const term = child.wait(io) catch {
        std.debug.print("Error: the mount process did not start\n", .{});
        return error.MountFailed;
    };
    std.debug.print("Error: the mount process ended before the volume was up ({f})\n", .{term});
    return error.MountFailed;
}

fn printAbi(io: Io) !void {
    var buffer: [4096]u8 = undefined;
    var writer = Io.File.stdout().writer(io, &buffer);
    try fuse.writeAbi(&writer.interface);
    try writer.interface.flush();
}

pub fn runUnmount(gpa: Allocator, io: Io, args: []const []const u8) !void {
    if (args.len != 1 or mem.startsWith(u8, args[0], "--")) {
        std.debug.print("Usage: turbocrypt unmount <mountpoint>\n", .{});
        return error.InvalidArguments;
    }
    const mountpoint = args[0];
    const argv: []const []const u8 = if (builtin.os.tag == .macos)
        &.{ "umount", mountpoint }
    else
        &.{ "fusermount3", "-u", mountpoint };

    const result = std.process.run(gpa, io, .{ .argv = argv }) catch |err| {
        std.debug.print("Error: cannot run {s}: {}\n", .{ argv[0], err });
        return err;
    };
    defer gpa.free(result.stdout);
    defer gpa.free(result.stderr);

    if (result.term.success()) return;
    std.debug.print("{s}", .{result.stderr});
    if (std.ascii.findIgnoreCase(result.stderr, "busy") != null) {
        std.debug.print("Error: a program still has a file open on {s}\n", .{mountpoint});
        if (builtin.os.tag == .macos) {
            std.debug.print("Close it, or run: diskutil unmount force {s}\n", .{mountpoint});
        }
    } else {
        std.debug.print("Error: unmount of {s} failed\n", .{mountpoint});
    }
    return error.UnmountFailed;
}

const InitOptions = struct {
    common: CommonOptions = .{},
    destination: []const u8 = &.{},
};

fn parseInitOptions(args: []const []const u8) !InitOptions {
    var opts: InitOptions = .{};
    var destination: ?[]const u8 = null;
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        if (try opts.common.take(args, &i)) continue;
        const arg = args[i];
        if (mem.startsWith(u8, arg, "-")) {
            std.debug.print("Error: Unknown option '{s}'\n", .{arg});
            return error.InvalidArguments;
        } else if (destination == null) {
            destination = arg;
        } else {
            std.debug.print("{s}", .{init_usage_text});
            return error.InvalidArguments;
        }
    }
    opts.destination = destination orelse {
        std.debug.print("{s}", .{init_usage_text});
        return error.InvalidArguments;
    };
    return opts;
}

pub fn runInit(
    gpa: Allocator,
    io: Io,
    environ_map: *const std.process.Environ.Map,
    args: []const []const u8,
) !void {
    if (args.len == 1 and (mem.eql(u8, args[0], "--help") or mem.eql(u8, args[0], "help"))) {
        std.debug.print("{s}", .{init_usage_text});
        return;
    }
    const opts = try parseInitOptions(args);
    const settings: container.Settings = .{
        .encrypted_filenames = opts.common.encrypted_filenames orelse
            configuredEncryptedFilenames(gpa, io, environ_map),
        .enc_suffix = opts.common.enc_suffix,
    };

    if (try container.enclosingRoot(gpa, io, opts.destination)) |enclosure| {
        defer enclosure.deinit(gpa);
        if (enclosure.isRoot()) {
            std.debug.print("Error: {s} is already a container\n", .{opts.destination});
        } else {
            std.debug.print("Error: {s} is inside the container {s}\n", .{ opts.destination, enclosure.root });
            std.debug.print("       A container cannot be created inside another one\n", .{});
        }
        return error.InvalidArguments;
    }

    var key = try loadKeyFrom(&opts.common, gpa, io, environ_map);
    var keys = crypto.deriveKeys(key, opts.common.context);
    std.crypto.secureZero(u8, &key);
    defer std.crypto.secureZero(u8, mem.asBytes(&keys));
    var descriptor_key = container.deriveDescriptorKey(keys);
    defer std.crypto.secureZero(u8, &descriptor_key);

    if (builtin.mode == .debug) armFaultsFromEnvironment(environ_map);

    try initializeContainer(gpa, io, opts.destination, descriptor_key, settings);
    std.debug.print("Initialized the empty container {s}\n", .{opts.destination});
    std.debug.print("Mount it with the same key and context: turbocrypt mount {s} <mountpoint>\n", .{opts.destination});
}

/// Publish a durable descriptor only in an empty directory protected by the lock.
/// On failure, clean up only names created by this call; never delete recursively.
pub fn initializeContainer(
    gpa: Allocator,
    io: Io,
    destination: []const u8,
    descriptor_key: [16]u8,
    settings: container.Settings,
) !void {
    const created = if (Io.Dir.createDir(.cwd(), io, destination, .fromMode(0o700))) |_|
        true
    else |err| switch (err) {
        error.PathAlreadyExists => false,
        error.FileNotFound => {
            std.debug.print("Error: the parent directory of {s} does not exist\n", .{destination});
            return error.InitFailed;
        },
        else => return failInit(destination, "create", err),
    };
    errdefer if (created) Io.Dir.deleteDir(.cwd(), io, destination) catch {};
    var dir = Io.Dir.openDir(.cwd(), io, destination, .{
        .iterate = true,
        .follow_symlinks = false,
    }) catch |err| switch (err) {
        error.NotDir, error.SymLinkLoop => {
            std.debug.print("Error: {s} is not a directory; a symbolic link is refused too\n", .{destination});
            return error.InvalidArguments;
        },
        else => return failInit(destination, "open", err),
    };
    defer dir.close(io);

    if (std.c.flock(dir.handle, std.c.LOCK.EX | std.c.LOCK.NB) != 0) {
        std.debug.print("Error: {s} is mounted or in use by another turbocrypt process\n", .{destination});
        return error.InitFailed;
    }

    if (!created) {
        var it = dir.iterate();
        if (try it.next(io)) |entry| {
            if (processor.isTmpName(entry.name)) {
                std.debug.print("Error: {s} is not empty: {s} looks like the leftover of an interrupted initialization\n", .{ destination, entry.name });
                std.debug.print("       Check it and remove it yourself, then run init again\n", .{});
            } else {
                std.debug.print("Error: {s} is not empty ({s} is in it)\n", .{ destination, entry.name });
                std.debug.print("       init needs a missing or empty directory; nothing is converted\n", .{});
            }
            return error.InvalidArguments;
        }
    }

    const tmp = processor.createTmpIn(dir, io, .{
        .read = true,
        .permissions = .fromMode(0o600),
    }) catch |err| return failInit(destination, "create the descriptor in", err);
    defer tmp.file.close(io);
    {
        errdefer dir.deleteFile(io, &tmp.name) catch {};
        container.writeDescriptor(tmp.file, io, descriptor_key, settings) catch |err|
            return failInit(destination, "write the descriptor in", err);
        faults.syncFd(tmp.file.handle, .file_sync) catch |err|
            return failInit(destination, "sync the descriptor in", err);
        Io.Dir.hardLink(dir, &tmp.name, dir, container.descriptor_name, io, .{}) catch |err|
            return failInit(destination, "publish the descriptor in", err);
    }
    // Remove the descriptor again if its publication cannot be made durable, allowing a clean retry.
    errdefer dir.deleteFile(io, container.descriptor_name) catch {};
    dir.deleteFile(io, &tmp.name) catch |err|
        return failInit(destination, "remove the temporary name in", err);
    faults.syncFd(dir.handle, .dir_sync) catch |err|
        return failInit(destination, "sync the container directory", err);
    try syncParentOf(gpa, io, destination);
}

fn failInit(destination: []const u8, comptime step: []const u8, err: anyerror) error{InitFailed} {
    std.debug.print("Error: cannot " ++ step ++ " {s}: {s}\n", .{ destination, @errorName(err) });
    return error.InitFailed;
}

fn syncParentOf(gpa: Allocator, io: Io, destination: []const u8) !void {
    const canonical = try Io.Dir.realPathFileAlloc(.cwd(), io, destination, gpa);
    defer gpa.free(canonical);
    const parent_path = Io.Dir.path.dirname(canonical) orelse "/";
    // Request iteration because Linux O_PATH descriptors cannot be synced.
    var parent = Io.Dir.openDir(.cwd(), io, parent_path, .{ .iterate = true }) catch |err|
        return failInit(destination, "open the parent directory of", err);
    defer parent.close(io);
    faults.syncFd(parent.handle, .dir_sync) catch |err|
        return failInit(destination, "sync the parent directory of", err);
}

test "mount options preserve filesystem assumptions and match the platform" {
    if (builtin.os.tag == .macos) {
        try testing.expectEqual(null, refusedOption("noattrcache"));
        try testing.expectEqual(null, refusedOption("volname=Secret"));
        try testing.expectEqual(null, refusedOption("rwsize=1048576"));
    } else {
        try testing.expect(refusedOption("noattrcache") != null);
        try testing.expect(refusedOption("volname=Secret") != null);
    }
    try testing.expectEqual(null, refusedOption("noatime"));
    try testing.expectEqual(null, refusedOption("debug"));
    try testing.expect(refusedOption("use_ino") != null);
    try testing.expect(refusedOption("hard_remove") != null);
    try testing.expect(refusedOption("writeback_cache") != null);
    try testing.expect(refusedOption("allow_other") != null);
    try testing.expect(refusedOption("ro") != null);
    try testing.expect(refusedOption("uid=0") != null);
    try testing.expect(refusedOption("attr_timeout=5") != null);
    try testing.expect(refusedOption("modules=subdir") != null);
    try testing.expect(refusedOption("something_else") != null);
    try testing.expect(refusedOption("volname") != null);
}

test "the memory limit floor follows the growth peak" {
    try testing.expectEqual(3 * (1 << 30) + (1 << 20), minimumMemoryLimit(1 << 30));
    try testing.expectEqual(null, minimumMemoryLimit(std.math.maxInt(usize)));
}

test "the key check needs a readable file within its bound" {
    const gpa = testing.allocator;
    const io = testing.io;
    const root_path = "tmp/mount_cmd_key_check";
    Io.Dir.deleteTree(.cwd(), io, root_path) catch {};
    try Io.Dir.createDirPath(.cwd(), io, root_path);
    defer Io.Dir.deleteTree(.cwd(), io, root_path) catch {};
    var root = try Io.Dir.openDir(.cwd(), io, root_path, .{ .iterate = true });
    defer root.close(io);
    const keys = crypto.deriveKeys(@splat(7), null);
    const other_keys = crypto.deriveKeys(@splat(8), null);

    var name_buffer: [64]u8 = undefined;
    for (0..key_check_entries - 1) |i| {
        const path = try mem.print(&name_buffer, "{s}/d{d}", .{ root_path, i });
        try Io.Dir.createDirPath(.cwd(), io, path);
    }
    try checkKey(root, gpa, io, root_path, "mnt", keys);

    const encrypted = try crypto.encrypt(gpa, io, "", keys);
    defer gpa.free(encrypted);
    try Io.Dir.writeFile(.cwd(), io, .{ .sub_path = root_path ++ "/f", .data = encrypted });
    try checkKey(root, gpa, io, root_path, "mnt", keys);
    try testing.expectError(
        error.MountFailed,
        checkKey(root, gpa, io, root_path, "mnt", other_keys),
    );

    try Io.Dir.deleteFile(.cwd(), io, root_path ++ "/f");
    try Io.Dir.createDirPath(.cwd(), io, root_path ++ "/last");
    try testing.expectError(error.MountFailed, checkKey(root, gpa, io, root_path, "mnt", keys));
}

test "the key check refuses a tree whose files it could not check" {
    const gpa = testing.allocator;
    const io = testing.io;
    const root_path = "tmp/mount_cmd_key_skip";
    Io.Dir.deleteTree(.cwd(), io, root_path) catch {};
    try Io.Dir.createDirPath(.cwd(), io, root_path);
    defer Io.Dir.deleteTree(.cwd(), io, root_path) catch {};
    var root = try Io.Dir.openDir(.cwd(), io, root_path, .{ .iterate = true });
    defer root.close(io);
    const keys = crypto.deriveKeys(@splat(7), null);

    try Io.Dir.writeFile(.cwd(), io, .{ .sub_path = root_path ++ "/junk", .data = "\x00\x01\x02" });
    try testing.expectError(error.MountFailed, checkKey(root, gpa, io, root_path, "mnt", keys));

    const encrypted = try crypto.encrypt(gpa, io, "", keys);
    defer gpa.free(encrypted);
    try Io.Dir.writeFile(.cwd(), io, .{ .sub_path = root_path ++ "/f", .data = encrypted });
    try checkKey(root, gpa, io, root_path, "mnt", keys);
    try Io.Dir.deleteFile(.cwd(), io, root_path ++ "/junk");

    // Root ignores the permission bits this test exercises.
    if (std.c.geteuid() == 0) return error.SkipZigTest;
    if (std.c.chmod(root_path ++ "/f", 0) != 0) return error.Unexpected;
    try testing.expectError(error.MountFailed, checkKey(root, gpa, io, root_path, "mnt", keys));
    if (std.c.chmod(root_path ++ "/f", 0o600) != 0) return error.Unexpected;
    try checkKey(root, gpa, io, root_path, "mnt", keys);

    try Io.Dir.deleteFile(.cwd(), io, root_path ++ "/f");
    try Io.Dir.createDirPath(.cwd(), io, root_path ++ "/closed");
    if (std.c.chmod(root_path ++ "/closed", 0) != 0) return error.Unexpected;
    defer _ = std.c.chmod(root_path ++ "/closed", 0o700);
    try testing.expectError(error.MountFailed, checkKey(root, gpa, io, root_path, "mnt", keys));
}

test "mount options are parsed, and the v1 defaults and limits apply afterwards" {
    const gpa = testing.allocator;
    const io = testing.io;
    const root = "tmp/mount_cmd_options";
    Io.Dir.deleteTree(.cwd(), io, root) catch {};
    try Io.Dir.createDirPath(.cwd(), io, root);
    defer Io.Dir.deleteTree(.cwd(), io, root) catch {};
    var environ_map = try Config.testEnviron(gpa, root);
    defer environ_map.deinit();

    const passing = if (builtin.os.tag == .macos)
        "noattrcache,volname=X"
    else
        "noatime,max_read=4096";
    var opts = try parseMountOptions(gpa, &.{
        "--read-only",
        "-o",
        passing,
        "--max-file-size",
        "1000",
        "--memory-limit",
        "2000000",
        "enc",
        "mnt",
    });
    defer opts.deinit(gpa);
    try testing.expect(opts.read_only);
    try testing.expectEqual(2, opts.fuse_options.items.len);
    try testing.expectEqualStrings("enc", opts.backing);
    try testing.expectEqualStrings("mnt", opts.mountpoint);
    try testing.expectEqual(1000, opts.max_file_size.?);
    try testing.expectEqual(null, opts.common.encrypted_filenames);
    try applyV1Defaults(&opts, gpa, io, &environ_map);
    try testing.expectEqual(1000, opts.max_file_size.?);
    try testing.expectEqual(2000000, opts.memory_limit.?);
    try testing.expectEqual(false, opts.common.encrypted_filenames);

    const cfg: Config = .{ .encrypted_filenames = true };
    try cfg.save(gpa, io, &environ_map);
    var defaulted = try parseMountOptions(gpa, &.{ "enc", "mnt" });
    defer defaulted.deinit(gpa);
    try applyV1Defaults(&defaulted, gpa, io, &environ_map);
    try testing.expectEqual(true, defaulted.common.encrypted_filenames);
    var flagged = try parseMountOptions(
        gpa,
        &.{ "--encrypted-filenames", "--context", "c", "enc", "mnt" },
    );
    defer flagged.deinit(gpa);
    try testing.expectEqual(true, flagged.common.encrypted_filenames);
    try testing.expectEqualStrings("c", flagged.common.context.?);
    try testing.expectEqual(default_max_file_size, defaulted.max_file_size.?);
    try testing.expectEqual(default_memory_limit, defaulted.memory_limit.?);

    var too_small = try parseMountOptions(gpa, &.{
        "--max-file-size", "1000",
        "--memory-limit",  "3000",
        "enc",             "mnt",
    });
    defer too_small.deinit(gpa);
    try testing.expectError(
        error.InvalidArguments,
        applyV1Defaults(&too_small, gpa, io, &environ_map),
    );
    var zero = try parseMountOptions(gpa, &.{ "--max-file-size", "0", "enc", "mnt" });
    defer zero.deinit(gpa);
    try testing.expectError(error.InvalidArguments, applyV1Defaults(&zero, gpa, io, &environ_map));

    try testing.expectError(
        error.InvalidArguments,
        parseMountOptions(gpa, &.{ "-o", "use_ino", "enc", "mnt" }),
    );
    try testing.expectError(
        error.InvalidArguments,
        parseMountOptions(gpa, &.{ "--exclude", "x", "enc", "mnt" }),
    );
    try testing.expectError(error.InvalidArguments, parseMountOptions(gpa, &.{"enc"}));

    // Containers reject these limits even when they equal their usual defaults.
    for ([_][]const []const u8{
        &.{ "--force", "enc", "mnt" },
        &.{ "--max-file-size", "1073741824", "enc", "mnt" },
        &.{ "--rescue-dir", "r", "enc", "mnt" },
    }) |args| {
        var container_opts = try parseMountOptions(gpa, args);
        defer container_opts.deinit(gpa);
        try testing.expectError(error.InvalidArguments, refuseV1OnlyOptions(&container_opts));
    }
    try refuseV1OnlyOptions(&flagged);
}

test "a mountpoint inside the encrypted directory is refused" {
    const gpa = testing.allocator;
    const io = testing.io;
    const root = "tmp/mount_cmd_nesting";
    Io.Dir.deleteTree(.cwd(), io, root) catch {};
    try Io.Dir.createDirPath(.cwd(), io, root ++ "/enc/inside");
    try Io.Dir.createDirPath(.cwd(), io, root ++ "/mnt");
    defer Io.Dir.deleteTree(.cwd(), io, root) catch {};
    var environ_map = try Config.testEnviron(gpa, root);
    defer environ_map.deinit();

    try testing.expectError(
        error.InvalidArguments,
        runMount(gpa, io, &environ_map, &.{ "--force", root ++ "/enc", root ++ "/enc/inside" }),
    );
    try testing.expectError(
        error.InvalidArguments,
        runMount(gpa, io, &environ_map, &.{ "--force", root ++ "/enc", root ++ "/enc" }),
    );
    try testing.expectError(
        error.InvalidArguments,
        runMount(gpa, io, &environ_map, &.{ "--force", root ++ "/missing", root ++ "/mnt" }),
    );
}

fn modeOfPath(io: Io, path: []const u8) !u32 {
    const st = try Io.Dir.statFile(.cwd(), io, path, .{});
    return st.permissions.toMode() & 0o777;
}

test "init creates an empty container and refuses every other destination" {
    const gpa = testing.allocator;
    const io = testing.io;
    const root = "tmp/mount_cmd_init";
    const key_path = root ++ "/key";
    Io.Dir.deleteTree(.cwd(), io, root) catch {};
    try Io.Dir.createDirPath(.cwd(), io, root);
    defer Io.Dir.deleteTree(.cwd(), io, root) catch {};
    var environ_map = try Config.testEnviron(gpa, root);
    defer environ_map.deinit();
    const master: [16]u8 = @splat(21);
    try keygen.writeKeyFile(gpa, io, key_path, master, null);
    const descriptor_key = container.deriveDescriptorKey(crypto.deriveKeys(master, null));

    try runInit(gpa, io, &environ_map, &.{ "--key", key_path, root ++ "/box" });
    try testing.expectEqual(0o700, try modeOfPath(io, root ++ "/box"));
    {
        var box = try Io.Dir.openDir(.cwd(), io, root ++ "/box", .{ .iterate = true });
        defer box.close(io);
        try testing.expectEqual(
            container.Settings{},
            try container.readDescriptor(box, io, descriptor_key),
        );
        var it = box.iterate();
        const only = (try it.next(io)).?;
        try testing.expectEqualStrings(container.descriptor_name, only.name);
        try testing.expectEqual(null, try it.next(io));
        const st = try box.statFile(io, container.descriptor_name, .{});
        try testing.expectEqual(container.descriptor_size, st.size);
    }
    try testing.expectEqual(.raf, try selectFormat(gpa, io, root ++ "/box"));

    try testing.expectError(
        error.InvalidArguments,
        runInit(gpa, io, &environ_map, &.{ "--key", key_path, root ++ "/box" }),
    );
    try testing.expectError(
        error.InvalidArguments,
        runInit(gpa, io, &environ_map, &.{ "--key", key_path, root ++ "/box/inner" }),
    );
    try testing.expect(!fs.pathExists(io, root ++ "/box/inner"));
    try Io.Dir.createDirPath(.cwd(), io, root ++ "/full/sub");
    try testing.expectError(
        error.InvalidArguments,
        runInit(gpa, io, &environ_map, &.{ "--key", key_path, root ++ "/full" }),
    );
    try testing.expect(!fs.pathExists(io, root ++ "/full/" ++ container.descriptor_name));

    try Io.Dir.writeFile(.cwd(), io, .{ .sub_path = root ++ "/file", .data = "x" });
    try testing.expectError(
        error.InvalidArguments,
        runInit(gpa, io, &environ_map, &.{ "--key", key_path, root ++ "/file" }),
    );
    try testing.expectError(
        error.InitFailed,
        runInit(gpa, io, &environ_map, &.{ "--key", key_path, root ++ "/missing/deep" }),
    );
    try testing.expect(!fs.pathExists(io, root ++ "/missing"));
    if (Io.Dir.symLink(.cwd(), io, "empty-target", root ++ "/link", .{ .is_directory = true })) |_| {
        try Io.Dir.createDirPath(.cwd(), io, root ++ "/empty-target");
        try testing.expectError(
            error.InvalidArguments,
            runInit(gpa, io, &environ_map, &.{ "--key", key_path, root ++ "/link" }),
        );
        const descriptor_path = root ++ "/empty-target/" ++ container.descriptor_name;
        try testing.expect(!fs.pathExists(io, descriptor_path));
    } else |_| {}

    try Io.Dir.createDirPath(.cwd(), io, root ++ "/kept");
    if (std.c.chmod(root ++ "/kept", 0o755) != 0) return error.Unexpected;
    try runInit(gpa, io, &environ_map, &.{
        "--key",
        key_path,
        "--encrypted-filenames",
        "--enc-suffix",
        "--context",
        "ctx",
        root ++ "/kept",
    });
    try testing.expectEqual(0o755, try modeOfPath(io, root ++ "/kept"));
    {
        var kept = try Io.Dir.openDir(.cwd(), io, root ++ "/kept", .{});
        defer kept.close(io);
        const ctx_key = container.deriveDescriptorKey(crypto.deriveKeys(master, "ctx"));
        try testing.expectEqual(
            container.Settings{ .encrypted_filenames = true, .enc_suffix = true },
            try container.readDescriptor(kept, io, ctx_key),
        );
        try testing.expectError(
            error.AuthenticationFailed,
            container.readDescriptor(kept, io, descriptor_key),
        );
    }

    const cfg: Config = .{ .encrypted_filenames = true };
    try cfg.save(gpa, io, &environ_map);
    try runInit(gpa, io, &environ_map, &.{ "--key", key_path, root ++ "/defaulted" });
    {
        var defaulted = try Io.Dir.openDir(.cwd(), io, root ++ "/defaulted", .{});
        defer defaulted.close(io);
        try testing.expectEqual(
            container.Settings{ .encrypted_filenames = true },
            try container.readDescriptor(defaulted, io, descriptor_key),
        );
    }

    // Hold the root lock to model another mount using this container.
    try Io.Dir.createDirPath(.cwd(), io, root ++ "/locked");
    {
        var locked = try Io.Dir.openDir(.cwd(), io, root ++ "/locked", .{ .iterate = true });
        defer locked.close(io);
        try testing.expectEqual(0, std.c.flock(locked.handle, std.c.LOCK.EX | std.c.LOCK.NB));
        try testing.expectError(
            error.InitFailed,
            runInit(gpa, io, &environ_map, &.{ "--key", key_path, root ++ "/locked" }),
        );
    }

    try testing.expectError(
        error.InvalidArguments,
        runInit(gpa, io, &environ_map, &.{ "--key", key_path }),
    );
    try testing.expectError(
        error.InvalidArguments,
        runInit(gpa, io, &environ_map, &.{ "--key", key_path, "a", "b" }),
    );
    try testing.expectError(
        error.InvalidArguments,
        runInit(gpa, io, &environ_map, &.{ "--read-only", root ++ "/x" }),
    );
    try runInit(gpa, io, &environ_map, &.{"--help"});
}

test "an interrupted initialization leaves nothing of its own behind" {
    if (builtin.mode != .debug) return error.SkipZigTest;
    const gpa = testing.allocator;
    const io = testing.io;
    const root = "tmp/mount_cmd_init_faults";
    Io.Dir.deleteTree(.cwd(), io, root) catch {};
    try Io.Dir.createDirPath(.cwd(), io, root ++ "/kept");
    defer Io.Dir.deleteTree(.cwd(), io, root) catch {};
    const descriptor_key = container.deriveDescriptorKey(crypto.deriveKeys(@splat(22), null));
    defer faults.arm(&.{});

    faults.arm(&.{.file_sync});
    try testing.expectError(
        error.InitFailed,
        initializeContainer(gpa, io, root ++ "/fresh", descriptor_key, .{}),
    );
    try testing.expect(!fs.pathExists(io, root ++ "/fresh"));

    faults.arm(&.{.file_sync});
    try testing.expectError(
        error.InitFailed,
        initializeContainer(gpa, io, root ++ "/kept", descriptor_key, .{}),
    );
    try testing.expect(try isEmptyDir(io, root ++ "/kept"));

    faults.arm(&.{.dir_sync});
    try testing.expectError(
        error.InitFailed,
        initializeContainer(gpa, io, root ++ "/kept", descriptor_key, .{}),
    );
    try testing.expect(try isEmptyDir(io, root ++ "/kept"));

    faults.arm(&.{});
    try initializeContainer(gpa, io, root ++ "/kept", descriptor_key, .{});
    try testing.expect(!try isEmptyDir(io, root ++ "/kept"));

    // Report a leftover temporary file without deleting evidence of the interrupted initialization.
    try Io.Dir.createDirPath(.cwd(), io, root ++ "/left");
    const leftover = processor.tmpName(1);
    try Io.Dir.writeFile(.cwd(), io, .{
        .sub_path = root ++ "/left/" ++ leftover,
        .data = "partial",
    });
    try testing.expectError(
        error.InvalidArguments,
        initializeContainer(gpa, io, root ++ "/left", descriptor_key, .{}),
    );
    try testing.expect(fs.pathExists(io, root ++ "/left/" ++ leftover));
}

test "the mount decision follows the descriptor and never guesses around a collision" {
    const gpa = testing.allocator;
    const io = testing.io;
    const root = "tmp/mount_cmd_decision";
    const key_path = root ++ "/key";
    Io.Dir.deleteTree(.cwd(), io, root) catch {};
    try Io.Dir.createDirPath(.cwd(), io, root ++ "/plain");
    try Io.Dir.createDirPath(.cwd(), io, root ++ "/stray");
    try Io.Dir.createDirPath(.cwd(), io, root ++ "/mnt");
    defer Io.Dir.deleteTree(.cwd(), io, root) catch {};
    var environ_map = try Config.testEnviron(gpa, root);
    defer environ_map.deinit();
    const master: [16]u8 = @splat(23);
    try keygen.writeKeyFile(gpa, io, key_path, master, null);
    const descriptor_key = container.deriveDescriptorKey(crypto.deriveKeys(master, null));
    try initializeContainer(gpa, io, root ++ "/box", descriptor_key, .{ .enc_suffix = true });
    try Io.Dir.createDirPath(.cwd(), io, root ++ "/box/sub");

    try testing.expectEqual(.v1, try selectFormat(gpa, io, root ++ "/plain"));
    try testing.expectEqual(.raf, try selectFormat(gpa, io, root ++ "/box"));
    try testing.expectError(error.InvalidArguments, selectFormat(gpa, io, root ++ "/box/sub"));
    try testing.expectError(error.InvalidArguments, runMount(gpa, io, &environ_map, &.{
        "--key",
        key_path,
        root ++ "/box/sub",
        root ++ "/mnt",
    }));
    try testing.expectError(error.InvalidArguments, runMount(gpa, io, &environ_map, &.{
        "--key",
        key_path,
        "--force",
        root ++ "/box/sub",
        root ++ "/mnt",
    }));

    // A collision with the reserved descriptor name must never select v1.
    try Io.Dir.writeFile(.cwd(), io, .{
        .sub_path = root ++ "/stray/" ++ container.descriptor_name,
        .data = "mine",
    });
    try testing.expectEqual(.raf, try selectFormat(gpa, io, root ++ "/stray"));
    {
        var stray = try Io.Dir.openDir(.cwd(), io, root ++ "/stray", .{});
        defer stray.close(io);
        var opts = try parseMountOptions(gpa, &.{ root ++ "/stray", root ++ "/mnt" });
        defer opts.deinit(gpa);
        try testing.expectError(
            error.MountFailed,
            resolveContainer(&opts, io, stray, descriptor_key),
        );
    }

    var box = try Io.Dir.openDir(.cwd(), io, root ++ "/box", .{});
    defer box.close(io);
    {
        var opts = try parseMountOptions(gpa, &.{ root ++ "/box", root ++ "/mnt" });
        defer opts.deinit(gpa);
        try testing.expectEqual(
            container.Settings{ .enc_suffix = true },
            try resolveContainer(&opts, io, box, descriptor_key),
        );
        const wrong = container.deriveDescriptorKey(crypto.deriveKeys(@splat(24), null));
        try testing.expectError(error.MountFailed, resolveContainer(&opts, io, box, wrong));
        const other_context = container.deriveDescriptorKey(crypto.deriveKeys(master, "ctx"));
        try testing.expectError(error.MountFailed, resolveContainer(&opts, io, box, other_context));
    }
    {
        var agreeing = try parseMountOptions(
            gpa,
            &.{ "--enc-suffix", root ++ "/box", root ++ "/mnt" },
        );
        defer agreeing.deinit(gpa);
        try testing.expectEqual(
            container.Settings{ .enc_suffix = true },
            try resolveContainer(&agreeing, io, box, descriptor_key),
        );
        var conflicting = try parseMountOptions(
            gpa,
            &.{ "--encrypted-filenames", root ++ "/box", root ++ "/mnt" },
        );
        defer conflicting.deinit(gpa);
        try testing.expectError(
            error.InvalidArguments,
            resolveContainer(&conflicting, io, box, descriptor_key),
        );
    }
}
