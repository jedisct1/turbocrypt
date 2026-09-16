const std = @import("std");
const builtin = @import("builtin");
const config = @import("../config.zig");
const container = @import("../container.zig");
const crypto = @import("../crypto.zig");
const key_loader = @import("../key_loader.zig");
const keygen = @import("../keygen.zig");
const processor = @import("../processor.zig");
const utils = @import("../utils.zig");
const fuse = @import("fuse.zig");
const fs = @import("fs.zig");
const names = @import("names.zig");
const node_mod = @import("node.zig");

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

/// The backend of a mount, chosen once from the reserved name at the root.
const Format = fs.Format;

const CommonOptions = struct {
    key: ?[]const u8 = null,
    password: bool = false,
    context: ?[]const u8 = null,
    /// Null while the flag is absent. Only init and a v1 mount then apply the configuration default.
    encrypted_filenames: ?bool = null,
    enc_suffix: bool = false,

    fn take(self: *CommonOptions, args: []const []const u8, i: *usize) !bool {
        const arg = args[i.*];
        if (std.mem.eql(u8, arg, "--key")) {
            self.key = try valueOf(args, i);
        } else if (std.mem.eql(u8, arg, "--password")) {
            self.password = true;
        } else if (std.mem.eql(u8, arg, "--context")) {
            self.context = try valueOf(args, i);
        } else if (std.mem.eql(u8, arg, "--encrypted-filenames")) {
            self.encrypted_filenames = true;
        } else if (std.mem.eql(u8, arg, "--enc-suffix")) {
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
    /// Null until the v1 defaults apply. A container refuses an explicit value.
    max_file_size: ?usize = null,
    memory_limit: ?usize = null,
    rescue_dir: ?[]const u8 = null,
    force: bool = false,
    fuse_options: std.ArrayList([]const u8) = .empty,
    backing: []const u8 = &.{},
    mountpoint: []const u8 = &.{},

    fn deinit(self: *MountOptions, allocator: std.mem.Allocator) void {
        self.fuse_options.deinit(allocator);
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

/// Parse the command line only. Defaults and the checks on the limits wait for the backend.
fn parseMountOptions(args: []const []const u8, allocator: std.mem.Allocator) !MountOptions {
    var opts: MountOptions = .{};
    errdefer opts.deinit(allocator);
    var positional: std.ArrayList([]const u8) = .empty;
    defer positional.deinit(allocator);

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        if (try opts.common.take(args, &i)) continue;
        const arg = args[i];
        if (std.mem.eql(u8, arg, "--read-only")) {
            opts.read_only = true;
        } else if (std.mem.eql(u8, arg, "--daemon")) {
            opts.daemon = true;
        } else if (std.mem.eql(u8, arg, "--daemon-child")) {
            const ready = try parseFd(try valueOf(args, &i));
            const key = try parseFd(try valueOf(args, &i));
            opts.daemon_child = .{ .ready_fd = ready, .key_fd = key };
        } else if (std.mem.eql(u8, arg, "--single-thread")) {
            opts.single_thread = true;
        } else if (std.mem.eql(u8, arg, "--debug")) {
            opts.debug = true;
        } else if (std.mem.eql(u8, arg, "--volname")) {
            opts.volname = try valueOf(args, &i);
        } else if (std.mem.eql(u8, arg, "--allow-other")) {
            opts.allow_other = true;
        } else if (std.mem.eql(u8, arg, "--max-file-size")) {
            opts.max_file_size = try parseSize(arg, try valueOf(args, &i));
        } else if (std.mem.eql(u8, arg, "--memory-limit")) {
            opts.memory_limit = try parseSize(arg, try valueOf(args, &i));
        } else if (std.mem.eql(u8, arg, "--rescue-dir")) {
            opts.rescue_dir = try valueOf(args, &i);
        } else if (std.mem.eql(u8, arg, "--force")) {
            opts.force = true;
        } else if (std.mem.eql(u8, arg, "-o")) {
            const list = try valueOf(args, &i);
            var it = std.mem.splitScalar(u8, list, ',');
            while (it.next()) |option| {
                if (option.len != 0) try opts.fuse_options.append(allocator, option);
            }
        } else if (std.mem.startsWith(u8, arg, "-")) {
            std.debug.print("Error: Unknown option '{s}'\n", .{arg});
            return error.InvalidArguments;
        } else {
            try positional.append(allocator, arg);
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

/// Fall back to plain names when configuration is unavailable.
fn configuredEncryptedFilenames(allocator: std.mem.Allocator, io: std.Io, environ_map: *const std.process.Environ.Map) bool {
    var cfg = config.load(allocator, io, environ_map) catch return false;
    defer cfg.deinit(allocator);
    return cfg.encrypted_filenames orelse false;
}

fn applyV1Defaults(opts: *MountOptions, allocator: std.mem.Allocator, io: std.Io, environ_map: *const std.process.Environ.Map) !void {
    if (opts.common.encrypted_filenames == null) opts.common.encrypted_filenames = configuredEncryptedFilenames(allocator, io, environ_map);
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

/// Reject options that require v1 staging or recovery.
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

/// Cover the peak memory needed to grow a file; null if the size would overflow.
pub fn minimumMemoryLimit(max_file_size: usize) ?usize {
    const triple = std.math.mul(usize, max_file_size, 3) catch return null;
    return std.math.add(usize, triple, 1 << 20) catch return null;
}

/// A trailing "=" allows an option value.
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

/// These options would bypass permission checks or violate the filesystem's caching and path assumptions.
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
    if (std.mem.endsWith(u8, pattern, "=")) return std.mem.startsWith(u8, option, pattern);
    return std.mem.eql(u8, option, pattern);
}

fn givesOption(options: []const []const u8, pattern: []const u8) bool {
    for (options) |option| {
        if (optionMatches(option, pattern)) return true;
    }
    return false;
}

/// Null means the option is allowed.
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

/// Select the backend before loading a key.
/// Refuse container subdirectories so they can't accidentally mount as v1.
pub fn selectFormat(backing: []const u8, allocator: std.mem.Allocator, io: std.Io) !Format {
    const enclosure = (try container.enclosingRoot(backing, allocator, io)) orelse return .v1;
    defer enclosure.deinit(allocator);
    if (enclosure.isRoot()) return .raf;
    std.debug.print("Error: {s} is inside the container {s}\n", .{ backing, enclosure.root });
    std.debug.print("       A container is mounted at its root: turbocrypt mount {s} <mountpoint>\n", .{enclosure.root});
    return error.InvalidArguments;
}

/// Use authenticated filename settings; explicit flags must agree and config defaults don't apply.
pub fn resolveContainer(opts: *const MountOptions, root: std.Io.Dir, descriptor_key: [16]u8, io: std.Io) !container.Settings {
    const settings = container.readDescriptor(root, descriptor_key, io) catch |err| {
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

pub fn runMount(args: []const []const u8, allocator: std.mem.Allocator, io: std.Io, environ_map: *const std.process.Environ.Map) !void {
    if (args.len == 1 and std.mem.eql(u8, args[0], "--print-abi")) return printAbi(io);
    if (args.len == 1 and (std.mem.eql(u8, args[0], "--help") or std.mem.eql(u8, args[0], "help"))) {
        std.debug.print("{s}", .{usage_text});
        return;
    }
    var opts = try parseMountOptions(args, allocator);
    defer opts.deinit(allocator);

    if (!(utils.isDir(opts.backing, io) catch false)) {
        std.debug.print("Error: the encrypted directory {s} does not exist or is not a directory\n", .{opts.backing});
        return error.InvalidArguments;
    }
    if (!(utils.isDir(opts.mountpoint, io) catch false)) {
        std.debug.print("Error: the mountpoint {s} does not exist or is not a directory\n", .{opts.mountpoint});
        return error.InvalidArguments;
    }
    if (!(isEmptyDir(opts.mountpoint, io) catch true)) {
        std.debug.print("Warning: the mountpoint {s} is not empty. Its own contents are hidden while the volume is mounted.\n         The arguments are <encrypted-dir> <mountpoint>, in that order.\n", .{opts.mountpoint});
    }
    switch (try utils.pathRelation(opts.backing, opts.mountpoint, allocator, io)) {
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

    const format = try selectFormat(opts.backing, allocator, io);
    if (format == .v1) try applyV1Defaults(&opts, allocator, io, environ_map);

    var lib = fuse.Library.load() catch |err| {
        switch (err) {
            error.LibraryNotFound => std.debug.print("Error: fuse-t is not installed. Get it from https://github.com/macos-fuse-t/fuse-t/releases\n", .{}),
            error.SymbolMissing => std.debug.print("Error: the installed fuse-t is missing an entry point the mount needs\n", .{}),
            else => std.debug.print("Error: cannot load libfuse: {}\n", .{err}),
        }
        return err;
    };
    defer lib.unload();

    if (opts.daemon and opts.daemon_child == null) return runDaemonParent(&opts, args, allocator, io, environ_map);

    var key = try obtainKey(&opts, allocator, io, environ_map);
    const keys = crypto.deriveKeys(key, opts.common.context);
    std.crypto.secureZero(u8, &key);

    var root = try std.Io.Dir.openDir(.cwd(), io, opts.backing, .{ .iterate = true });
    defer root.close(io);
    if (std.c.flock(root.handle, std.c.LOCK.EX | std.c.LOCK.NB) != 0) {
        std.debug.print("Error: {s} is already mounted by another turbocrypt process\n", .{opts.backing});
        return error.MountFailed;
    }

    const settings: container.Settings = switch (format) {
        .v1 => blk: {
            if (!opts.force) try checkKey(root, opts.backing, opts.mountpoint, keys, allocator, io);
            break :blk .{ .encrypted_filenames = opts.common.encrypted_filenames orelse false, .enc_suffix = opts.common.enc_suffix };
        },
        .raf => blk: {
            var descriptor_key = container.deriveDescriptorKey(keys);
            defer std.crypto.secureZero(u8, &descriptor_key);
            const recorded = try resolveContainer(&opts, root, descriptor_key, io);
            // Diagnose stray reserved files before rejecting --force.
            try refuseV1OnlyOptions(&opts);
            break :blk recorded;
        },
    };
    const mapper: names.Mapper = .{
        .enc_suffix = settings.enc_suffix,
        .filename_key = if (settings.encrypted_filenames) keys.filename_key else null,
    };

    const rescue_dir = if (opts.rescue_dir) |dir| try allocator.dupe(u8, dir) else try defaultRescueDir(allocator, environ_map);
    defer allocator.free(rescue_dir);

    if (builtin.mode == .debug) armFaultsFromEnvironment(environ_map);

    const mountpoint = try std.Io.Dir.realPathFileAlloc(.cwd(), io, opts.mountpoint, allocator);
    defer allocator.free(mountpoint);

    // Preserve the client's umask without applying the mount process's mask again.
    _ = std.c.umask(0);

    var fuse_args: std.ArrayList([]const u8) = .empty;
    defer fuse_args.deinit(allocator);
    try fuse_args.append(allocator, "turbocrypt");
    if (opts.debug) try fuse_args.appendSlice(allocator, &.{ "-o", "debug" });
    if (opts.read_only) try fuse_args.appendSlice(allocator, &.{ "-o", "ro" });
    const volname = if (builtin.os.tag == .macos)
        try std.fmt.allocPrint(allocator, "volname={s}", .{opts.volname orelse std.fs.path.basename(mountpoint)})
    else
        "";
    defer if (builtin.os.tag == .macos) allocator.free(volname);
    if (builtin.os.tag == .macos) {
        try fuse_args.appendSlice(allocator, &.{ "-o", volname });
        // Larger requests reduce overhead when transferring whole files.
        if (!givesOption(opts.fuse_options.items, "rwsize=")) try fuse_args.appendSlice(allocator, &.{ "-o", "rwsize=1048576" });
        // With nfc, the NFS client composes every accented name before the mount sees it.
        // The composition inside encryptFilename does not reach the sidecar store or a mount with plain names, which use the name the kernel sends.
        if (!givesOption(opts.fuse_options.items, "nfc")) try fuse_args.appendSlice(allocator, &.{ "-o", "nfc" });
    } else {
        try fuse_args.appendSlice(allocator, &.{ "-o", "default_permissions", "-o", "fsname=turbocrypt" });
        if (opts.allow_other) try fuse_args.appendSlice(allocator, &.{ "-o", "allow_other" });
    }
    for (opts.fuse_options.items) |option| try fuse_args.appendSlice(allocator, &.{ "-o", option });

    const m = try allocator.create(fs.Mount);
    defer allocator.destroy(m);
    try m.init(allocator, io, &lib, root, keys, mapper, .{
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

    const outcome = fuse.run(&lib, allocator, io, .{
        .args = fuse_args.items,
        .mountpoint = mountpoint,
        .operations = &fs.operations,
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
        std.debug.print("turbocrypt mount: loop returned {d}, signaled {}, still mounted {}, failures {d}\n", .{ outcome.loop_result, outcome.signaled, outcome.still_mounted, failures });
    }
    if (fuse.isMounted(allocator, io, mountpoint)) {
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

fn isEmptyDir(path: []const u8, io: std.Io) !bool {
    var dir = try std.Io.Dir.openDir(.cwd(), io, path, .{ .iterate = true });
    defer dir.close(io);
    var it = dir.iterate();
    return (try it.next(io)) == null;
}

fn obtainKey(opts: *MountOptions, allocator: std.mem.Allocator, io: std.Io, environ_map: *const std.process.Environ.Map) ![16]u8 {
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
    return loadKeyFrom(&opts.common, allocator, io, environ_map);
}

fn loadKeyFrom(common: *const CommonOptions, allocator: std.mem.Allocator, io: std.Io, environ_map: *const std.process.Environ.Map) ![16]u8 {
    return key_loader.loadKey(allocator, common.key, common.password, io, environ_map) catch |err| {
        return key_loader.explainLoadError(allocator, err, common.key, environ_map);
    };
}

/// Reject a wrong key before new files can be encrypted with it.
///
/// Only a complete walk with no regular files may succeed without checking a header.
/// An inconclusive scan requires --force; plaintext files are refused too.
fn checkKey(root: std.Io.Dir, backing: []const u8, mountpoint: []const u8, keys: crypto.DerivedKeys, allocator: std.mem.Allocator, io: std.Io) !void {
    var walker = try root.walk(allocator);
    defer walker.deinit();
    var seen: usize = 0;
    var skipped: usize = 0;
    while (seen < key_check_entries) : (seen += 1) {
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
        const header = readHeader(entry, &buffer, io) orelse {
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

/// Null means the header cannot be checked; keep short text so it can be diagnosed as plaintext.
fn readHeader(entry: std.Io.Dir.Walker.Entry, buffer: *[crypto.overhead_size]u8, io: std.Io) ?[]const u8 {
    const file = entry.dir.openFile(io, entry.basename, .{ .follow_symlinks = false }) catch return null;
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

fn defaultRescueDir(allocator: std.mem.Allocator, environ_map: *const std.process.Environ.Map) ![]u8 {
    const app_dir = try config.getAppDataDir(allocator, "turbocrypt", environ_map);
    defer allocator.free(app_dir);
    return std.fs.path.join(allocator, &.{ app_dir, "rescue" });
}

fn armFaultsFromEnvironment(environ_map: *const std.process.Environ.Map) void {
    const value = environ_map.get("TURBOCRYPT_MOUNT_FAULTS") orelse return;
    var list: [node_mod.max_faults]node_mod.Fault = undefined;
    var count: usize = 0;
    var it = std.mem.splitScalar(u8, value, ',');
    while (it.next()) |name| {
        if (name.len == 0 or count == list.len) continue;
        list[count] = std.meta.stringToEnum(node_mod.Fault, name) orelse {
            std.debug.print("turbocrypt mount: unknown fault '{s}' ignored\n", .{name});
            continue;
        };
        count += 1;
    }
    node_mod.armFaults(list[0..count]);
    std.debug.print("turbocrypt mount: {d} fault(s) armed from TURBOCRYPT_MOUNT_FAULTS\n", .{count});
}

/// Resolve the key while a password prompt still has a terminal, then wait for the child to mount.
/// A pipe keeps the key out of command-line arguments.
fn runDaemonParent(opts: *MountOptions, args: []const []const u8, allocator: std.mem.Allocator, io: std.Io, environ_map: *const std.process.Environ.Map) !void {
    var key = try obtainKey(opts, allocator, io, environ_map);
    defer std.crypto.secureZero(u8, &key);

    var ready: [2]std.c.fd_t = undefined;
    var key_pipe: [2]std.c.fd_t = undefined;
    if (std.c.pipe(&ready) != 0 or std.c.pipe(&key_pipe) != 0) return error.MountFailed;
    _ = std.c.fcntl(ready[0], std.c.F.SETFD, @as(c_int, std.posix.FD_CLOEXEC));
    _ = std.c.fcntl(key_pipe[1], std.c.F.SETFD, @as(c_int, std.posix.FD_CLOEXEC));

    const exe = try std.process.executablePathAlloc(io, allocator);
    defer allocator.free(exe);
    var argv: std.ArrayList([]const u8) = .empty;
    defer argv.deinit(allocator);
    try argv.appendSlice(allocator, &.{ exe, "mount" });
    try argv.appendSlice(allocator, args);
    const ready_text = try std.fmt.allocPrint(allocator, "{d}", .{ready[1]});
    defer allocator.free(ready_text);
    const key_text = try std.fmt.allocPrint(allocator, "{d}", .{key_pipe[0]});
    defer allocator.free(key_text);
    try argv.appendSlice(allocator, &.{ "--daemon-child", ready_text, key_text });

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
        // The ready signal can arrive before the mount table is updated.
        const mountpoint = try std.Io.Dir.realPathFileAlloc(.cwd(), io, opts.mountpoint, allocator);
        defer allocator.free(mountpoint);
        var waited: usize = 0;
        while (!fuse.isMounted(allocator, io, mountpoint) and waited < 100) : (waited += 1) {
            std.Io.sleep(io, .fromMilliseconds(100), .awake) catch break;
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

fn printAbi(io: std.Io) !void {
    var buffer: [4096]u8 = undefined;
    var writer = std.Io.File.stdout().writer(io, &buffer);
    try fuse.writeAbi(&writer.interface);
    try writer.interface.flush();
}

pub fn runUnmount(args: []const []const u8, allocator: std.mem.Allocator, io: std.Io) !void {
    if (args.len != 1 or std.mem.startsWith(u8, args[0], "--")) {
        std.debug.print("Usage: turbocrypt unmount <mountpoint>\n", .{});
        return error.InvalidArguments;
    }
    const mountpoint = args[0];
    const argv: []const []const u8 = if (builtin.os.tag == .macos)
        &.{ "umount", mountpoint }
    else
        &.{ "fusermount3", "-u", mountpoint };

    const result = std.process.run(allocator, io, .{ .argv = argv }) catch |err| {
        std.debug.print("Error: cannot run {s}: {}\n", .{ argv[0], err });
        return err;
    };
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

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
        if (std.mem.startsWith(u8, arg, "-")) {
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

pub fn runInit(args: []const []const u8, allocator: std.mem.Allocator, io: std.Io, environ_map: *const std.process.Environ.Map) !void {
    if (args.len == 1 and (std.mem.eql(u8, args[0], "--help") or std.mem.eql(u8, args[0], "help"))) {
        std.debug.print("{s}", .{init_usage_text});
        return;
    }
    const opts = try parseInitOptions(args);
    const settings: container.Settings = .{
        .encrypted_filenames = opts.common.encrypted_filenames orelse configuredEncryptedFilenames(allocator, io, environ_map),
        .enc_suffix = opts.common.enc_suffix,
    };

    if (try container.enclosingRoot(opts.destination, allocator, io)) |enclosure| {
        defer enclosure.deinit(allocator);
        if (enclosure.isRoot()) {
            std.debug.print("Error: {s} is already a container\n", .{opts.destination});
        } else {
            std.debug.print("Error: {s} is inside the container {s}\n", .{ opts.destination, enclosure.root });
            std.debug.print("       A container cannot be created inside another one\n", .{});
        }
        return error.InvalidArguments;
    }

    var key = try loadKeyFrom(&opts.common, allocator, io, environ_map);
    var keys = crypto.deriveKeys(key, opts.common.context);
    std.crypto.secureZero(u8, &key);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&keys));
    var descriptor_key = container.deriveDescriptorKey(keys);
    defer std.crypto.secureZero(u8, &descriptor_key);

    if (builtin.mode == .debug) armFaultsFromEnvironment(environ_map);

    try initializeContainer(opts.destination, descriptor_key, settings, allocator, io);
    std.debug.print("Initialized the empty container {s}\n", .{opts.destination});
    std.debug.print("Mount it with the same key and context: turbocrypt mount {s} <mountpoint>\n", .{opts.destination});
}

/// Publish a durable descriptor in an empty, locked directory.
/// Cleanup removes only entries this call created, never recursively.
pub fn initializeContainer(destination: []const u8, descriptor_key: [16]u8, settings: container.Settings, allocator: std.mem.Allocator, io: std.Io) !void {
    const created = if (std.Io.Dir.createDir(.cwd(), io, destination, .fromMode(0o700))) |_| true else |err| switch (err) {
        error.PathAlreadyExists => false,
        error.FileNotFound => {
            std.debug.print("Error: the parent directory of {s} does not exist\n", .{destination});
            return error.InitFailed;
        },
        else => return failInit(destination, "create", err),
    };
    errdefer if (created) std.Io.Dir.deleteDir(.cwd(), io, destination) catch {};
    var dir = std.Io.Dir.openDir(.cwd(), io, destination, .{ .iterate = true, .follow_symlinks = false }) catch |err| switch (err) {
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

    const tmp = processor.createTmpIn(dir, .{ .read = true, .permissions = .fromMode(0o600) }, io) catch |err| return failInit(destination, "create the descriptor in", err);
    defer tmp.file.close(io);
    {
        errdefer dir.deleteFile(io, &tmp.name) catch {};
        container.writeDescriptor(tmp.file, descriptor_key, settings, io) catch |err| return failInit(destination, "write the descriptor in", err);
        node_mod.syncFd(tmp.file.handle, .file_sync) catch |err| return failInit(destination, "sync the descriptor in", err);
        std.Io.Dir.hardLink(dir, &tmp.name, dir, container.descriptor_name, io, .{}) catch |err| return failInit(destination, "publish the descriptor in", err);
    }
    // Allow a clean retry if publication can't be made durable.
    errdefer dir.deleteFile(io, container.descriptor_name) catch {};
    dir.deleteFile(io, &tmp.name) catch |err| return failInit(destination, "remove the temporary name in", err);
    node_mod.syncFd(dir.handle, .dir_sync) catch |err| return failInit(destination, "sync the container directory", err);
    try syncParentOf(destination, allocator, io);
}

fn failInit(destination: []const u8, comptime step: []const u8, err: anyerror) error{InitFailed} {
    std.debug.print("Error: cannot " ++ step ++ " {s}: {s}\n", .{ destination, @errorName(err) });
    return error.InitFailed;
}

fn syncParentOf(destination: []const u8, allocator: std.mem.Allocator, io: std.Io) !void {
    const canonical = try std.Io.Dir.realPathFileAlloc(.cwd(), io, destination, allocator);
    defer allocator.free(canonical);
    const parent_path = std.fs.path.dirname(canonical) orelse "/";
    // Iteration capability avoids Linux O_PATH descriptors, which cannot be synced.
    var parent = std.Io.Dir.openDir(.cwd(), io, parent_path, .{ .iterate = true }) catch |err| return failInit(destination, "open the parent directory of", err);
    defer parent.close(io);
    node_mod.syncFd(parent.handle, .dir_sync) catch |err| return failInit(destination, "sync the parent directory of", err);
}

const testing = std.testing;

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
    const io = testing.io;
    const root_path = "tmp/mount_cmd_key_check";
    std.Io.Dir.deleteTree(.cwd(), io, root_path) catch {};
    try std.Io.Dir.createDirPath(.cwd(), io, root_path);
    defer std.Io.Dir.deleteTree(.cwd(), io, root_path) catch {};
    var root = try std.Io.Dir.openDir(.cwd(), io, root_path, .{ .iterate = true });
    defer root.close(io);
    const keys = crypto.deriveKeys(@splat(7), null);
    const other_keys = crypto.deriveKeys(@splat(8), null);

    var name_buffer: [64]u8 = undefined;
    for (0..key_check_entries - 1) |i| {
        const path = try std.fmt.bufPrint(&name_buffer, "{s}/d{d}", .{ root_path, i });
        try std.Io.Dir.createDirPath(.cwd(), io, path);
    }
    try checkKey(root, root_path, "mnt", keys, testing.allocator, io);

    const encrypted = try crypto.encrypt("", keys, testing.allocator, io);
    defer testing.allocator.free(encrypted);
    try std.Io.Dir.writeFile(.cwd(), io, .{ .sub_path = root_path ++ "/f", .data = encrypted });
    try checkKey(root, root_path, "mnt", keys, testing.allocator, io);
    try testing.expectError(error.MountFailed, checkKey(root, root_path, "mnt", other_keys, testing.allocator, io));

    try std.Io.Dir.deleteFile(.cwd(), io, root_path ++ "/f");
    try std.Io.Dir.createDirPath(.cwd(), io, root_path ++ "/last");
    try testing.expectError(error.MountFailed, checkKey(root, root_path, "mnt", keys, testing.allocator, io));
}

test "the key check refuses a tree whose files it could not check" {
    const io = testing.io;
    const root_path = "tmp/mount_cmd_key_skip";
    std.Io.Dir.deleteTree(.cwd(), io, root_path) catch {};
    try std.Io.Dir.createDirPath(.cwd(), io, root_path);
    defer std.Io.Dir.deleteTree(.cwd(), io, root_path) catch {};
    var root = try std.Io.Dir.openDir(.cwd(), io, root_path, .{ .iterate = true });
    defer root.close(io);
    const keys = crypto.deriveKeys(@splat(7), null);

    try std.Io.Dir.writeFile(.cwd(), io, .{ .sub_path = root_path ++ "/junk", .data = "\x00\x01\x02" });
    try testing.expectError(error.MountFailed, checkKey(root, root_path, "mnt", keys, testing.allocator, io));

    const encrypted = try crypto.encrypt("", keys, testing.allocator, io);
    defer testing.allocator.free(encrypted);
    try std.Io.Dir.writeFile(.cwd(), io, .{ .sub_path = root_path ++ "/f", .data = encrypted });
    try checkKey(root, root_path, "mnt", keys, testing.allocator, io);
    try std.Io.Dir.deleteFile(.cwd(), io, root_path ++ "/junk");

    // Root bypasses the permissions these cases test.
    if (std.c.geteuid() == 0) return error.SkipZigTest;
    if (std.c.chmod(root_path ++ "/f", 0) != 0) return error.Unexpected;
    try testing.expectError(error.MountFailed, checkKey(root, root_path, "mnt", keys, testing.allocator, io));
    if (std.c.chmod(root_path ++ "/f", 0o600) != 0) return error.Unexpected;
    try checkKey(root, root_path, "mnt", keys, testing.allocator, io);

    try std.Io.Dir.deleteFile(.cwd(), io, root_path ++ "/f");
    try std.Io.Dir.createDirPath(.cwd(), io, root_path ++ "/closed");
    if (std.c.chmod(root_path ++ "/closed", 0) != 0) return error.Unexpected;
    defer _ = std.c.chmod(root_path ++ "/closed", 0o700);
    try testing.expectError(error.MountFailed, checkKey(root, root_path, "mnt", keys, testing.allocator, io));
}

test "mount options are parsed, and the v1 defaults and limits apply afterwards" {
    const allocator = testing.allocator;
    const io = testing.io;
    const root = "tmp/mount_cmd_options";
    std.Io.Dir.deleteTree(.cwd(), io, root) catch {};
    try std.Io.Dir.createDirPath(.cwd(), io, root);
    defer std.Io.Dir.deleteTree(.cwd(), io, root) catch {};
    var environ_map = try config.testEnviron(allocator, root);
    defer environ_map.deinit();

    const passing = if (builtin.os.tag == .macos) "noattrcache,volname=X" else "noatime,max_read=4096";
    var opts = try parseMountOptions(&.{ "--read-only", "-o", passing, "--max-file-size", "1000", "--memory-limit", "2000000", "enc", "mnt" }, allocator);
    defer opts.deinit(allocator);
    try testing.expect(opts.read_only);
    try testing.expectEqual(2, opts.fuse_options.items.len);
    try testing.expectEqualStrings("enc", opts.backing);
    try testing.expectEqualStrings("mnt", opts.mountpoint);
    try testing.expectEqual(1000, opts.max_file_size.?);
    try testing.expectEqual(null, opts.common.encrypted_filenames);
    try applyV1Defaults(&opts, allocator, io, &environ_map);
    try testing.expectEqual(1000, opts.max_file_size.?);
    try testing.expectEqual(2000000, opts.memory_limit.?);
    try testing.expectEqual(false, opts.common.encrypted_filenames);

    const cfg: config.Config = .{ .encrypted_filenames = true };
    try config.save(cfg, allocator, io, &environ_map);
    var defaulted = try parseMountOptions(&.{ "enc", "mnt" }, allocator);
    defer defaulted.deinit(allocator);
    try applyV1Defaults(&defaulted, allocator, io, &environ_map);
    try testing.expectEqual(true, defaulted.common.encrypted_filenames);
    var flagged = try parseMountOptions(&.{ "--encrypted-filenames", "--context", "c", "enc", "mnt" }, allocator);
    defer flagged.deinit(allocator);
    try testing.expectEqual(true, flagged.common.encrypted_filenames);
    try testing.expectEqualStrings("c", flagged.common.context.?);
    try testing.expectEqual(default_max_file_size, defaulted.max_file_size.?);
    try testing.expectEqual(default_memory_limit, defaulted.memory_limit.?);

    var too_small = try parseMountOptions(&.{ "--max-file-size", "1000", "--memory-limit", "3000", "enc", "mnt" }, allocator);
    defer too_small.deinit(allocator);
    try testing.expectError(error.InvalidArguments, applyV1Defaults(&too_small, allocator, io, &environ_map));
    var zero = try parseMountOptions(&.{ "--max-file-size", "0", "enc", "mnt" }, allocator);
    defer zero.deinit(allocator);
    try testing.expectError(error.InvalidArguments, applyV1Defaults(&zero, allocator, io, &environ_map));

    try testing.expectError(error.InvalidArguments, parseMountOptions(&.{ "-o", "use_ino", "enc", "mnt" }, allocator));
    try testing.expectError(error.InvalidArguments, parseMountOptions(&.{ "--exclude", "x", "enc", "mnt" }, allocator));
    try testing.expectError(error.InvalidArguments, parseMountOptions(&.{"enc"}, allocator));

    // Even explicitly supplied default limits are invalid for containers.
    for ([_][]const []const u8{
        &.{ "--force", "enc", "mnt" },
        &.{ "--max-file-size", "1073741824", "enc", "mnt" },
        &.{ "--rescue-dir", "r", "enc", "mnt" },
    }) |args| {
        var container_opts = try parseMountOptions(args, allocator);
        defer container_opts.deinit(allocator);
        try testing.expectError(error.InvalidArguments, refuseV1OnlyOptions(&container_opts));
    }
    try refuseV1OnlyOptions(&flagged);
}

test "a mountpoint inside the encrypted directory is refused" {
    const allocator = testing.allocator;
    const io = testing.io;
    const root = "tmp/mount_cmd_nesting";
    std.Io.Dir.deleteTree(.cwd(), io, root) catch {};
    try std.Io.Dir.createDirPath(.cwd(), io, root ++ "/enc/inside");
    try std.Io.Dir.createDirPath(.cwd(), io, root ++ "/mnt");
    defer std.Io.Dir.deleteTree(.cwd(), io, root) catch {};
    var environ_map = try config.testEnviron(allocator, root);
    defer environ_map.deinit();

    try testing.expectError(error.InvalidArguments, runMount(&.{ "--force", root ++ "/enc", root ++ "/enc/inside" }, allocator, io, &environ_map));
    try testing.expectError(error.InvalidArguments, runMount(&.{ "--force", root ++ "/enc", root ++ "/enc" }, allocator, io, &environ_map));
    try testing.expectError(error.InvalidArguments, runMount(&.{ "--force", root ++ "/missing", root ++ "/mnt" }, allocator, io, &environ_map));
}

fn modeOfPath(path: []const u8, io: std.Io) !u32 {
    const st = try std.Io.Dir.statFile(.cwd(), io, path, .{});
    return st.permissions.toMode() & 0o777;
}

test "init creates an empty container and refuses every other destination" {
    const allocator = testing.allocator;
    const io = testing.io;
    const root = "tmp/mount_cmd_init";
    const key_path = root ++ "/key";
    std.Io.Dir.deleteTree(.cwd(), io, root) catch {};
    try std.Io.Dir.createDirPath(.cwd(), io, root);
    defer std.Io.Dir.deleteTree(.cwd(), io, root) catch {};
    var environ_map = try config.testEnviron(allocator, root);
    defer environ_map.deinit();
    const master: [16]u8 = @splat(21);
    try keygen.writeKeyFile(key_path, master, null, allocator, io);
    const descriptor_key = container.deriveDescriptorKey(crypto.deriveKeys(master, null));

    try runInit(&.{ "--key", key_path, root ++ "/box" }, allocator, io, &environ_map);
    try testing.expectEqual(0o700, try modeOfPath(root ++ "/box", io));
    {
        var box = try std.Io.Dir.openDir(.cwd(), io, root ++ "/box", .{ .iterate = true });
        defer box.close(io);
        try testing.expectEqual(container.Settings{}, try container.readDescriptor(box, descriptor_key, io));
        var it = box.iterate();
        const only = (try it.next(io)).?;
        try testing.expectEqualStrings(container.descriptor_name, only.name);
        try testing.expectEqual(null, try it.next(io));
        const st = try box.statFile(io, container.descriptor_name, .{});
        try testing.expectEqual(container.descriptor_size, st.size);
    }
    try testing.expectEqual(.raf, try selectFormat(root ++ "/box", allocator, io));

    try testing.expectError(error.InvalidArguments, runInit(&.{ "--key", key_path, root ++ "/box" }, allocator, io, &environ_map));
    try testing.expectError(error.InvalidArguments, runInit(&.{ "--key", key_path, root ++ "/box/inner" }, allocator, io, &environ_map));
    try testing.expect(!utils.pathExists(root ++ "/box/inner", io));
    try std.Io.Dir.createDirPath(.cwd(), io, root ++ "/full/sub");
    try testing.expectError(error.InvalidArguments, runInit(&.{ "--key", key_path, root ++ "/full" }, allocator, io, &environ_map));
    try testing.expect(!utils.pathExists(root ++ "/full/" ++ container.descriptor_name, io));

    try std.Io.Dir.writeFile(.cwd(), io, .{ .sub_path = root ++ "/file", .data = "x" });
    try testing.expectError(error.InvalidArguments, runInit(&.{ "--key", key_path, root ++ "/file" }, allocator, io, &environ_map));
    try testing.expectError(error.InitFailed, runInit(&.{ "--key", key_path, root ++ "/missing/deep" }, allocator, io, &environ_map));
    try testing.expect(!utils.pathExists(root ++ "/missing", io));
    if (std.Io.Dir.symLink(.cwd(), io, "empty-target", root ++ "/link", .{ .is_directory = true })) |_| {
        try std.Io.Dir.createDirPath(.cwd(), io, root ++ "/empty-target");
        try testing.expectError(error.InvalidArguments, runInit(&.{ "--key", key_path, root ++ "/link" }, allocator, io, &environ_map));
        try testing.expect(!utils.pathExists(root ++ "/empty-target/" ++ container.descriptor_name, io));
    } else |_| {}

    try std.Io.Dir.createDirPath(.cwd(), io, root ++ "/kept");
    if (std.c.chmod(root ++ "/kept", 0o755) != 0) return error.Unexpected;
    try runInit(&.{ "--key", key_path, "--encrypted-filenames", "--enc-suffix", "--context", "ctx", root ++ "/kept" }, allocator, io, &environ_map);
    try testing.expectEqual(0o755, try modeOfPath(root ++ "/kept", io));
    {
        var kept = try std.Io.Dir.openDir(.cwd(), io, root ++ "/kept", .{});
        defer kept.close(io);
        const ctx_key = container.deriveDescriptorKey(crypto.deriveKeys(master, "ctx"));
        try testing.expectEqual(container.Settings{ .encrypted_filenames = true, .enc_suffix = true }, try container.readDescriptor(kept, ctx_key, io));
        try testing.expectError(error.AuthenticationFailed, container.readDescriptor(kept, descriptor_key, io));
    }

    const cfg: config.Config = .{ .encrypted_filenames = true };
    try config.save(cfg, allocator, io, &environ_map);
    try runInit(&.{ "--key", key_path, root ++ "/defaulted" }, allocator, io, &environ_map);
    {
        var defaulted = try std.Io.Dir.openDir(.cwd(), io, root ++ "/defaulted", .{});
        defer defaulted.close(io);
        try testing.expectEqual(container.Settings{ .encrypted_filenames = true }, try container.readDescriptor(defaulted, descriptor_key, io));
    }

    // Simulate a mount holding the root lock.
    try std.Io.Dir.createDirPath(.cwd(), io, root ++ "/locked");
    {
        var locked = try std.Io.Dir.openDir(.cwd(), io, root ++ "/locked", .{ .iterate = true });
        defer locked.close(io);
        try testing.expectEqual(0, std.c.flock(locked.handle, std.c.LOCK.EX | std.c.LOCK.NB));
        try testing.expectError(error.InitFailed, runInit(&.{ "--key", key_path, root ++ "/locked" }, allocator, io, &environ_map));
    }

    try testing.expectError(error.InvalidArguments, runInit(&.{ "--key", key_path }, allocator, io, &environ_map));
    try testing.expectError(error.InvalidArguments, runInit(&.{ "--key", key_path, "a", "b" }, allocator, io, &environ_map));
    try testing.expectError(error.InvalidArguments, runInit(&.{ "--read-only", root ++ "/x" }, allocator, io, &environ_map));
    try runInit(&.{"--help"}, allocator, io, &environ_map);
}

test "an interrupted initialization leaves nothing of its own behind" {
    if (builtin.mode != .debug) return error.SkipZigTest;
    const allocator = testing.allocator;
    const io = testing.io;
    const root = "tmp/mount_cmd_init_faults";
    std.Io.Dir.deleteTree(.cwd(), io, root) catch {};
    try std.Io.Dir.createDirPath(.cwd(), io, root ++ "/kept");
    defer std.Io.Dir.deleteTree(.cwd(), io, root) catch {};
    const descriptor_key = container.deriveDescriptorKey(crypto.deriveKeys(@splat(22), null));
    defer node_mod.armFaults(&.{});

    node_mod.armFaults(&.{.file_sync});
    try testing.expectError(error.InitFailed, initializeContainer(root ++ "/fresh", descriptor_key, .{}, allocator, io));
    try testing.expect(!utils.pathExists(root ++ "/fresh", io));

    node_mod.armFaults(&.{.file_sync});
    try testing.expectError(error.InitFailed, initializeContainer(root ++ "/kept", descriptor_key, .{}, allocator, io));
    try testing.expect(try isEmptyDir(root ++ "/kept", io));

    node_mod.armFaults(&.{.dir_sync});
    try testing.expectError(error.InitFailed, initializeContainer(root ++ "/kept", descriptor_key, .{}, allocator, io));
    try testing.expect(try isEmptyDir(root ++ "/kept", io));

    node_mod.armFaults(&.{});
    try initializeContainer(root ++ "/kept", descriptor_key, .{}, allocator, io);
    try testing.expect(!try isEmptyDir(root ++ "/kept", io));

    // A leftover temporary file is reported, never removed.
    try std.Io.Dir.createDirPath(.cwd(), io, root ++ "/left");
    const leftover = processor.tmpName(1);
    try std.Io.Dir.writeFile(.cwd(), io, .{ .sub_path = root ++ "/left/" ++ leftover, .data = "partial" });
    try testing.expectError(error.InvalidArguments, initializeContainer(root ++ "/left", descriptor_key, .{}, allocator, io));
    try testing.expect(utils.pathExists(root ++ "/left/" ++ leftover, io));
}

test "the mount decision follows the descriptor and never guesses around a collision" {
    const allocator = testing.allocator;
    const io = testing.io;
    const root = "tmp/mount_cmd_decision";
    const key_path = root ++ "/key";
    std.Io.Dir.deleteTree(.cwd(), io, root) catch {};
    try std.Io.Dir.createDirPath(.cwd(), io, root ++ "/plain");
    try std.Io.Dir.createDirPath(.cwd(), io, root ++ "/stray");
    try std.Io.Dir.createDirPath(.cwd(), io, root ++ "/mnt");
    defer std.Io.Dir.deleteTree(.cwd(), io, root) catch {};
    var environ_map = try config.testEnviron(allocator, root);
    defer environ_map.deinit();
    const master: [16]u8 = @splat(23);
    try keygen.writeKeyFile(key_path, master, null, allocator, io);
    const descriptor_key = container.deriveDescriptorKey(crypto.deriveKeys(master, null));
    try initializeContainer(root ++ "/box", descriptor_key, .{ .enc_suffix = true }, allocator, io);
    try std.Io.Dir.createDirPath(.cwd(), io, root ++ "/box/sub");

    try testing.expectEqual(.v1, try selectFormat(root ++ "/plain", allocator, io));
    try testing.expectEqual(.raf, try selectFormat(root ++ "/box", allocator, io));
    try testing.expectError(error.InvalidArguments, selectFormat(root ++ "/box/sub", allocator, io));
    try testing.expectError(error.InvalidArguments, runMount(&.{ "--key", key_path, root ++ "/box/sub", root ++ "/mnt" }, allocator, io, &environ_map));
    try testing.expectError(error.InvalidArguments, runMount(&.{ "--key", key_path, "--force", root ++ "/box/sub", root ++ "/mnt" }, allocator, io, &environ_map));

    // A reserved-name collision must not fall back to v1.
    try std.Io.Dir.writeFile(.cwd(), io, .{ .sub_path = root ++ "/stray/" ++ container.descriptor_name, .data = "mine" });
    try testing.expectEqual(.raf, try selectFormat(root ++ "/stray", allocator, io));
    {
        var stray = try std.Io.Dir.openDir(.cwd(), io, root ++ "/stray", .{});
        defer stray.close(io);
        var opts = try parseMountOptions(&.{ root ++ "/stray", root ++ "/mnt" }, allocator);
        defer opts.deinit(allocator);
        try testing.expectError(error.MountFailed, resolveContainer(&opts, stray, descriptor_key, io));
    }

    var box = try std.Io.Dir.openDir(.cwd(), io, root ++ "/box", .{});
    defer box.close(io);
    {
        var opts = try parseMountOptions(&.{ root ++ "/box", root ++ "/mnt" }, allocator);
        defer opts.deinit(allocator);
        try testing.expectEqual(container.Settings{ .enc_suffix = true }, try resolveContainer(&opts, box, descriptor_key, io));
        const wrong = container.deriveDescriptorKey(crypto.deriveKeys(@splat(24), null));
        try testing.expectError(error.MountFailed, resolveContainer(&opts, box, wrong, io));
        const other_context = container.deriveDescriptorKey(crypto.deriveKeys(master, "ctx"));
        try testing.expectError(error.MountFailed, resolveContainer(&opts, box, other_context, io));
    }
    {
        var agreeing = try parseMountOptions(&.{ "--enc-suffix", root ++ "/box", root ++ "/mnt" }, allocator);
        defer agreeing.deinit(allocator);
        try testing.expectEqual(container.Settings{ .enc_suffix = true }, try resolveContainer(&agreeing, box, descriptor_key, io));
        var conflicting = try parseMountOptions(&.{ "--encrypted-filenames", root ++ "/box", root ++ "/mnt" }, allocator);
        defer conflicting.deinit(allocator);
        try testing.expectError(error.InvalidArguments, resolveContainer(&conflicting, box, descriptor_key, io));
    }
}
