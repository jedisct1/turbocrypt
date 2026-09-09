const std = @import("std");
const builtin = @import("builtin");
const keygen = @import("../keygen.zig");
const processor = @import("../processor.zig");
const utils = @import("../utils.zig");

pub const Error = error{
    GitNotFound,
    NotAGitRepository,
    BareRepository,
    GitCommandFailed,
    RepoLocked,
    Locked,
};

const private_dir_permissions: std.Io.File.Permissions = if (builtin.os.tag == .windows) .default_dir else .fromMode(0o700);

/// A lock older than this is reported as stale instead of as busy.
const stale_lock_ns: i96 = 10 * std.time.ns_per_min;

/// Result of one git command. The caller frees it with deinit.
pub const Output = struct {
    term: std.process.Child.Term,
    stdout: []u8,
    stderr: []u8,

    pub fn ok(self: Output) bool {
        return self.term.success();
    }

    pub fn deinit(self: Output, allocator: std.mem.Allocator) void {
        allocator.free(self.stdout);
        allocator.free(self.stderr);
    }
};

/// Held while a command or a hook changes the store, the state or the exclude file.
/// Released by deleting the lock file.
pub const Lock = struct {
    path: []const u8,
    io: std.Io,

    pub fn release(self: Lock) void {
        std.Io.Dir.deleteFile(.cwd(), self.io, self.path) catch {};
    }
};

/// Everything the git integration needs to know about the repository the command runs in.
/// All paths are absolute.
pub const Repo = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    environ_map: *const std.process.Environ.Map,
    toplevel: []u8,
    git_dir: []u8,
    common_dir: []u8,
    hooks_dir: []u8,
    exclude_path: []u8,
    prefix: []u8,
    private_dir: []u8,
    key_path: []u8,
    state_path: []u8,
    tmp_dir: []u8,
    lock_path: []u8,
    pathspec_path: []u8,
    /// macOS git reports composed (NFC) names while the disk may hold decomposed ones.
    /// User arguments get the same treatment as git gives them, so manifest lines match what git lists.
    precompose: ?bool,

    pub fn open(allocator: std.mem.Allocator, io: std.Io, environ_map: *const std.process.Environ.Map) !Repo {
        return openAt(allocator, io, environ_map, null);
    }

    /// Open the repository that contains `dir` instead of the current directory.
    /// Tests use it; commands use the current directory.
    pub fn openAt(allocator: std.mem.Allocator, io: std.Io, environ_map: *const std.process.Environ.Map, dir: ?[]const u8) !Repo {
        // The bare answer must come first, since the path options fail in a bare repository.
        const paths = try runGit(allocator, io, environ_map, dir, &.{
            "rev-parse",  "--is-bare-repository", "--path-format=absolute", "--show-toplevel", "--git-dir",     "--git-common-dir",
            "--git-path", "hooks",                "--git-path",             "info/exclude",    "--show-prefix",
        });
        defer paths.deinit(allocator);
        var it = std.mem.splitScalar(u8, paths.stdout, '\n');
        if (std.mem.eql(u8, std.mem.trim(u8, it.next() orelse "", " \r"), "true")) {
            std.debug.print("Error: this is a bare repository, it has no working tree to protect\n", .{});
            return Error.BareRepository;
        }
        if (!paths.ok()) {
            std.debug.print("Error: not inside a git repository\n{s}", .{paths.stderr});
            return Error.NotAGitRepository;
        }

        var lines: [6][]const u8 = undefined;
        for (&lines) |*line| {
            line.* = it.next() orelse {
                std.debug.print("Error: unexpected git rev-parse output\n", .{});
                return Error.GitCommandFailed;
            };
        }

        var repo = Repo{
            .allocator = allocator,
            .io = io,
            .environ_map = environ_map,
            .toplevel = &.{},
            .git_dir = &.{},
            .common_dir = &.{},
            .hooks_dir = &.{},
            .exclude_path = &.{},
            .prefix = &.{},
            .private_dir = &.{},
            .key_path = &.{},
            .state_path = &.{},
            .tmp_dir = &.{},
            .lock_path = &.{},
            .pathspec_path = &.{},
            .precompose = null,
        };
        errdefer repo.deinit();

        repo.toplevel = try allocator.dupe(u8, lines[0]);
        repo.git_dir = try allocator.dupe(u8, lines[1]);
        repo.common_dir = try allocator.dupe(u8, lines[2]);
        repo.hooks_dir = try allocator.dupe(u8, lines[3]);
        repo.exclude_path = try allocator.dupe(u8, lines[4]);
        repo.prefix = try allocator.dupe(u8, lines[5]);
        repo.private_dir = try std.fs.path.join(allocator, &.{ repo.git_dir, "turbocrypt" });
        repo.key_path = try std.fs.path.join(allocator, &.{ repo.private_dir, "key" });
        repo.state_path = try std.fs.path.join(allocator, &.{ repo.private_dir, "state" });
        repo.tmp_dir = try std.fs.path.join(allocator, &.{ repo.private_dir, "tmp" });
        repo.lock_path = try std.fs.path.join(allocator, &.{ repo.private_dir, "lock" });
        repo.pathspec_path = try std.fs.path.join(allocator, &.{ repo.private_dir, "pathspec" });
        return repo;
    }

    /// A user-given path in the form git would report it.
    pub fn canonicalArg(self: *Repo, arg: []const u8) ![]u8 {
        if (builtin.os.tag == .macos and self.precompose == null) {
            self.precompose = (try self.configGetBool("core.precomposeunicode")) orelse false;
        }
        if (self.precompose orelse false) return precompose(self.allocator, arg);
        return self.allocator.dupe(u8, arg);
    }

    pub fn deinit(self: *Repo) void {
        const a = self.allocator;
        a.free(self.toplevel);
        a.free(self.git_dir);
        a.free(self.common_dir);
        a.free(self.hooks_dir);
        a.free(self.exclude_path);
        a.free(self.prefix);
        a.free(self.private_dir);
        a.free(self.key_path);
        a.free(self.state_path);
        a.free(self.tmp_dir);
        a.free(self.lock_path);
        a.free(self.pathspec_path);
    }

    /// A linked worktree shares the object store and the config of another checkout.
    /// This version does not support them.
    pub fn isLinkedWorktree(self: *const Repo) bool {
        return !std.mem.eql(u8, self.git_dir, self.common_dir);
    }

    /// Absolute path of a working tree file.
    pub fn absolutePath(self: *const Repo, relative: []const u8) ![]u8 {
        return std.fs.path.join(self.allocator, &.{ self.toplevel, relative });
    }

    /// Run git from the top level.
    /// Every call goes through here so that literal pathspecs are always in effect.
    pub fn run(self: *const Repo, argv: []const []const u8) !Output {
        return runGit(self.allocator, self.io, self.environ_map, self.toplevel, argv);
    }

    /// Run git and return its stdout, or explain the failure and give up.
    pub fn runChecked(self: *const Repo, argv: []const []const u8) ![]u8 {
        const out = try self.run(argv);
        defer self.allocator.free(out.stderr);
        if (!out.ok()) {
            self.allocator.free(out.stdout);
            std.debug.print("Error: git {s} failed ({f}):\n{s}", .{ argv[0], out.term, out.stderr });
            return Error.GitCommandFailed;
        }
        return out.stdout;
    }

    /// NUL separated paths from `git ls-files -z` with extra arguments.
    pub fn lsFilesZ(self: *const Repo, args: []const []const u8) ![][]u8 {
        var argv: std.ArrayList([]const u8) = .empty;
        defer argv.deinit(self.allocator);
        try argv.appendSlice(self.allocator, &.{ "ls-files", "-z" });
        try argv.appendSlice(self.allocator, args);

        const out = try self.runChecked(argv.items);
        defer self.allocator.free(out);
        return splitNul(self.allocator, out);
    }

    /// Stage files, ignored ones included.
    /// Base84 names can end in `~` and match a user's ignore rule, so `-f` is always needed.
    pub fn addForce(self: *const Repo, paths: []const []const u8) !void {
        try self.runWithPathspec(&.{ "add", "-f" }, paths);
    }

    /// Remove files from the index and keep them on disk.
    pub fn rmCached(self: *const Repo, paths: []const []const u8) !void {
        try self.runWithPathspec(&.{ "rm", "-q", "-r", "--cached", "--ignore-unmatch", "-f" }, paths);
    }

    /// Run a command on any number of paths.
    fn runWithPathspec(self: *const Repo, command: []const []const u8, paths: []const []const u8) !void {
        if (paths.len == 0) return;
        try self.ensureDirs();
        var data: std.ArrayList(u8) = .empty;
        defer data.deinit(self.allocator);
        for (paths) |path| {
            try data.appendSlice(self.allocator, path);
            try data.append(self.allocator, 0);
        }
        try processor.writeFileAtomic(self.pathspec_path, data.items, utils.private_file_permissions, null, self.allocator, self.io);

        const from_file = try std.fmt.allocPrint(self.allocator, "--pathspec-from-file={s}", .{self.pathspec_path});
        defer self.allocator.free(from_file);
        var argv: std.ArrayList([]const u8) = .empty;
        defer argv.deinit(self.allocator);
        try argv.appendSlice(self.allocator, command);
        try argv.appendSlice(self.allocator, &.{ from_file, "--pathspec-file-nul" });
        const out = try self.runChecked(argv.items);
        self.allocator.free(out);
    }

    /// True when git would ignore the path.
    /// check-ignore is the one command that rejects the literal pathspec option, so it runs without it.
    pub fn checkIgnore(self: *const Repo, path: []const u8) !bool {
        const out = try runGitWith(self.allocator, self.io, self.environ_map, self.toplevel, &.{ "check-ignore", "-q", "--", path }, false);
        defer out.deinit(self.allocator);
        return switch (out.term) {
            .exited => |code| switch (code) {
                0 => true,
                1 => false,
                else => {
                    std.debug.print("Error: git check-ignore failed:\n{s}", .{out.stderr});
                    return Error.GitCommandFailed;
                },
            },
            else => Error.GitCommandFailed,
        };
    }

    pub fn configGet(self: *const Repo, key: []const u8) !?[]u8 {
        return self.configValue(&.{ "config", "--get", key });
    }

    /// A boolean setting in git's canonical form, so `yes`, `on` and `1` count as true like they do for git.
    pub fn configGetBool(self: *const Repo, key: []const u8) !?bool {
        const value = (try self.configValue(&.{ "config", "--type=bool", "--get", key })) orelse return null;
        defer self.allocator.free(value);
        return std.mem.eql(u8, value, "true");
    }

    /// A path setting with `~` expanded the way git expands it.
    pub fn configGetPath(self: *const Repo, key: []const u8) !?[]u8 {
        return self.configValue(&.{ "config", "--type=path", "--get", key });
    }

    fn configValue(self: *const Repo, argv: []const []const u8) !?[]u8 {
        const out = try self.run(argv);
        defer out.deinit(self.allocator);
        if (!out.ok()) return null;
        return try self.allocator.dupe(u8, std.mem.trim(u8, out.stdout, " \r\n"));
    }

    pub fn configSetLocal(self: *const Repo, key: []const u8, value: []const u8) !void {
        const out = try self.runChecked(&.{ "config", "--local", key, value });
        self.allocator.free(out);
    }

    pub fn loadKey(self: *const Repo) ![16]u8 {
        return keygen.readKeyFile(self.key_path, null, self.io) catch |err| switch (err) {
            error.FileNotFound => return Error.RepoLocked,
            else => return err,
        };
    }

    pub fn saveKey(self: *const Repo, key: [16]u8) !void {
        try self.ensureDirs();
        try keygen.writeKeyFile(self.key_path, key, null, self.allocator, self.io);
    }

    /// Create the private directory and the temp directory, owner only.
    pub fn ensureDirs(self: *const Repo) !void {
        for ([_][]const u8{ self.private_dir, self.tmp_dir }) |dir| {
            std.Io.Dir.createDir(.cwd(), self.io, dir, private_dir_permissions) catch |err| switch (err) {
                error.PathAlreadyExists => {},
                else => return err,
            };
        }
    }

    /// Take the repository lock.
    /// A stale lock is reported, never removed: only the user knows whether the other process is still alive.
    pub fn lock(self: *const Repo) !Lock {
        try self.ensureDirs();
        const file = std.Io.Dir.createFile(.cwd(), self.io, self.lock_path, .{ .exclusive = true }) catch |err| switch (err) {
            error.PathAlreadyExists => {
                const stat = std.Io.Dir.statFile(.cwd(), self.io, self.lock_path, .{}) catch null;
                const age: i96 = if (stat) |st|
                    std.Io.Timestamp.now(self.io, .real).nanoseconds - st.mtime.nanoseconds
                else
                    0;
                if (age > stale_lock_ns) {
                    std.debug.print("Error: stale lock file {s} (older than 10 minutes)\nDelete it when no turbocrypt command is running\n", .{self.lock_path});
                } else {
                    std.debug.print("Error: another turbocrypt git command is running (lock file {s})\n", .{self.lock_path});
                }
                return Error.Locked;
            },
            else => return err,
        };
        file.close(self.io);
        return .{ .path = self.lock_path, .io = self.io };
    }
};

const iconv_failed = std.math.maxInt(usize);

extern "c" fn iconv_open(tocode: [*:0]const u8, fromcode: [*:0]const u8) ?*anyopaque;
extern "c" fn iconv(cd: ?*anyopaque, inbuf: ?*?[*]u8, inbytesleft: ?*usize, outbuf: ?*?[*]u8, outbytesleft: ?*usize) usize;
extern "c" fn iconv_close(cd: ?*anyopaque) c_int;

/// Compose a decomposed UTF-8 name the way git does on macOS, through the UTF-8-MAC converter of libiconv.
/// Anything the converter refuses is returned unchanged, which is also what git does.
pub fn precompose(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    if (builtin.os.tag != .macos) return allocator.dupe(u8, input);
    var ascii = true;
    for (input) |c| {
        if (c >= 0x80) ascii = false;
    }
    if (ascii) return allocator.dupe(u8, input);

    const cd = iconv_open("UTF-8", "UTF-8-MAC");
    if (cd == null or @intFromPtr(cd) == iconv_failed) return allocator.dupe(u8, input);
    defer _ = iconv_close(cd);

    const out = try allocator.alloc(u8, input.len * 2 + 16);
    errdefer allocator.free(out);
    var in_ptr: ?[*]u8 = @constCast(input.ptr);
    var in_left: usize = input.len;
    var out_ptr: ?[*]u8 = out.ptr;
    var out_left: usize = out.len;
    const rc = iconv(cd, &in_ptr, &in_left, &out_ptr, &out_left);
    if (rc == iconv_failed or in_left != 0) {
        allocator.free(out);
        return allocator.dupe(u8, input);
    }
    return allocator.realloc(out, out.len - out_left);
}

/// Run git with literal pathspecs in the given directory, or in the current one.
pub fn runGit(
    allocator: std.mem.Allocator,
    io: std.Io,
    environ_map: *const std.process.Environ.Map,
    cwd: ?[]const u8,
    argv: []const []const u8,
) !Output {
    return runGitWith(allocator, io, environ_map, cwd, argv, true);
}

fn runGitWith(
    allocator: std.mem.Allocator,
    io: std.Io,
    environ_map: *const std.process.Environ.Map,
    cwd: ?[]const u8,
    argv: []const []const u8,
    literal: bool,
) !Output {
    var full: std.ArrayList([]const u8) = .empty;
    defer full.deinit(allocator);
    try full.append(allocator, "git");
    if (literal) try full.append(allocator, "--literal-pathspecs");
    try full.appendSlice(allocator, argv);

    const result = std.process.run(allocator, io, .{
        .argv = full.items,
        .cwd = if (cwd) |c| .{ .path = c } else .inherit,
        .environ_map = environ_map,
    }) catch |err| switch (err) {
        error.FileNotFound => {
            std.debug.print("Error: git was not found in PATH\n", .{});
            return Error.GitNotFound;
        },
        else => return err,
    };
    return .{ .term = result.term, .stdout = result.stdout, .stderr = result.stderr };
}

/// Split NUL separated output into owned strings.
/// A trailing NUL does not produce an empty entry.
pub fn splitNul(allocator: std.mem.Allocator, data: []const u8) ![][]u8 {
    var list: std.ArrayList([]u8) = .empty;
    errdefer {
        for (list.items) |item| allocator.free(item);
        list.deinit(allocator);
    }
    var it = std.mem.tokenizeScalar(u8, data, 0);
    while (it.next()) |item| {
        try list.append(allocator, try allocator.dupe(u8, item));
    }
    return list.toOwnedSlice(allocator);
}

test "precompose composes decomposed names on macOS" {
    const testing = std.testing;
    const allocator = testing.allocator;
    if (builtin.os.tag != .macos) return error.SkipZigTest;

    const composed = try precompose(allocator, "re\u{301}sume\u{301}.md");
    defer allocator.free(composed);
    try testing.expectEqualStrings("r\u{e9}sum\u{e9}.md", composed);

    const plain = try precompose(allocator, "docs/internal.md");
    defer allocator.free(plain);
    try testing.expectEqualStrings("docs/internal.md", plain);
}

test "splitNul drops the trailing terminator" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const parts = try splitNul(allocator, "a\x00b c\x00\x00");
    defer utils.freeList(allocator, parts);
    try testing.expectEqual(@as(usize, 2), parts.len);
    try testing.expectEqualStrings("a", parts[0]);
    try testing.expectEqualStrings("b c", parts[1]);

    const none = try splitNul(allocator, "");
    defer utils.freeList(allocator, none);
    try testing.expectEqual(@as(usize, 0), none.len);
}
