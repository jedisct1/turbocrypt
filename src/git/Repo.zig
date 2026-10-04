//! Describes the Git repository used by the current turbocrypt command.
//! Repository paths are stored as absolute paths to avoid ambiguity.

const Repo = @This();

const std = @import("std");
const builtin = @import("builtin");
const mem = std.mem;
const testing = std.testing;
const Allocator = std.mem.Allocator;
const Io = std.Io;

const keygen = @import("../keygen.zig");
const processor = @import("../processor.zig");
const fs = @import("../fs.zig");
const git = @import("../git.zig");
const unicode = @import("../unicode.zig");

gpa: Allocator,
io: Io,
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
/// Git on macOS reports NFC names even when the filesystem stores decomposed names.
/// Normalize user arguments the same way so manifest paths match Git's view.
precompose: ?bool,

pub const Error = error{
    GitNotFound,
    NotAGitRepository,
    BareRepository,
    GitCommandFailed,
    RepositoryLocked,
    Locked,
};

const private_dir_permissions: Io.File.Permissions = if (builtin.os.tag == .windows)
    .default_dir
else
    .fromMode(0o700);

/// Treat locks older than this as stale so the user gets a useful warning.
const stale_lock_ns: i96 = 10 * std.time.ns_per_min;

/// Captures a Git command result. Call `deinit` when finished with it.
pub const Output = struct {
    term: std.process.Child.Term,
    stdout: []u8,
    stderr: []u8,

    pub fn ok(self: Output) bool {
        return self.term.success();
    }

    pub fn deinit(self: Output, gpa: Allocator) void {
        gpa.free(self.stdout);
        gpa.free(self.stderr);
    }
};

/// Prevents commands and hooks from changing shared repository state at the same time.
/// Removing the lock file releases it.
pub const Lock = struct {
    path: []const u8,
    io: Io,

    pub fn release(self: Lock) void {
        Io.Dir.deleteFile(.cwd(), self.io, self.path) catch {};
    }
};

pub fn open(gpa: Allocator, io: Io, environ_map: *const std.process.Environ.Map) !Repo {
    return openAt(gpa, io, environ_map, null);
}

/// Opens the repository containing `dir`; commands use the current directory.
/// Tests use this to work in isolated repositories.
pub fn openAt(
    gpa: Allocator,
    io: Io,
    environ_map: *const std.process.Environ.Map,
    dir: ?[]const u8,
) !Repo {
    // Ask whether the repository is bare first because bare repositories reject these path queries.
    const paths = try runGit(gpa, io, environ_map, dir, &.{
        "rev-parse",
        "--is-bare-repository",
        "--path-format=absolute",
        "--show-toplevel",
        "--git-dir",
        "--git-common-dir",
        "--git-path",
        "hooks",
        "--git-path",
        "info/exclude",
        "--show-prefix",
    });
    defer paths.deinit(gpa);
    var it = mem.splitScalar(u8, paths.stdout, '\n');
    if (mem.eql(u8, mem.trim(u8, it.next() orelse "", " \r"), "true")) {
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

    var repo: Repo = .{
        .gpa = gpa,
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

    repo.toplevel = try gpa.dupe(u8, lines[0]);
    repo.git_dir = try gpa.dupe(u8, lines[1]);
    repo.common_dir = try gpa.dupe(u8, lines[2]);
    repo.hooks_dir = try gpa.dupe(u8, lines[3]);
    repo.exclude_path = try gpa.dupe(u8, lines[4]);
    repo.prefix = try gpa.dupe(u8, lines[5]);
    repo.private_dir = try Io.Dir.path.join(gpa, &.{ repo.git_dir, "turbocrypt" });
    repo.key_path = try Io.Dir.path.join(gpa, &.{ repo.private_dir, "key" });
    repo.state_path = try Io.Dir.path.join(gpa, &.{ repo.private_dir, "state" });
    repo.tmp_dir = try Io.Dir.path.join(gpa, &.{ repo.private_dir, "tmp" });
    repo.lock_path = try Io.Dir.path.join(gpa, &.{ repo.private_dir, "lock" });
    repo.pathspec_path = try Io.Dir.path.join(gpa, &.{ repo.private_dir, "pathspec" });
    return repo;
}

/// Normalizes a user path to the form Git reports. Caller owns the returned memory.
///
pub fn canonicalArg(self: *Repo, arg: []const u8) ![]u8 {
    if (builtin.os.tag == .macos and self.precompose == null) {
        self.precompose = (try self.configGetBool("core.precomposeunicode")) orelse false;
    }
    if (self.precompose orelse false) {
        if (try unicode.precompose(self.gpa, arg)) |composed| return composed;
    }
    return self.gpa.dupe(u8, arg);
}

pub fn deinit(self: *Repo) void {
    const gpa = self.gpa;
    gpa.free(self.toplevel);
    gpa.free(self.git_dir);
    gpa.free(self.common_dir);
    gpa.free(self.hooks_dir);
    gpa.free(self.exclude_path);
    gpa.free(self.prefix);
    gpa.free(self.private_dir);
    gpa.free(self.key_path);
    gpa.free(self.state_path);
    gpa.free(self.tmp_dir);
    gpa.free(self.lock_path);
    gpa.free(self.pathspec_path);
}

/// Linked worktrees share another checkout's object store and configuration.
/// They are unsupported because that shared state would make synchronization ambiguous.
pub fn isLinkedWorktree(self: *const Repo) bool {
    return !mem.eql(u8, self.git_dir, self.common_dir);
}

/// Returns an absolute path under the repository root. Caller owns the memory.
pub fn absolutePath(self: *const Repo, relative: []const u8) ![]u8 {
    return Io.Dir.path.join(self.gpa, &.{ self.toplevel, relative });
}

/// Runs Git from the repository root with literal pathspecs enabled.
/// Literal pathspecs keep filenames from being interpreted as Git patterns.
pub fn run(self: *const Repo, argv: []const []const u8) !Output {
    return runGit(self.gpa, self.io, self.environ_map, self.toplevel, argv);
}

/// Runs Git and returns stdout, reporting a failed command as a repository error.
/// Caller owns the returned memory.
pub fn runChecked(self: *const Repo, argv: []const []const u8) ![]u8 {
    const out = try self.run(argv);
    defer self.gpa.free(out.stderr);
    if (!out.ok()) {
        self.gpa.free(out.stdout);
        std.debug.print("Error: git {s} failed ({f}):\n{s}", .{ argv[0], out.term, out.stderr });
        return Error.GitCommandFailed;
    }
    return out.stdout;
}

/// Lists NUL-delimited paths from `git ls-files -z`. Free the result with `git.freeList`.
///
pub fn lsFilesNul(self: *const Repo, args: []const []const u8) ![][]u8 {
    var argv: std.ArrayList([]const u8) = .empty;
    defer argv.deinit(self.gpa);
    try argv.appendSlice(self.gpa, &.{ "ls-files", "-z" });
    try argv.appendSlice(self.gpa, args);

    const out = try self.runChecked(argv.items);
    defer self.gpa.free(out);
    return splitNul(self.gpa, out);
}

/// Stages paths even when an ignore rule matches them.
/// Encrypted Base84 names can end in `~`, so `-f` keeps user ignore rules from hiding them.
pub fn addForce(self: *const Repo, paths: []const []const u8) !void {
    try self.runWithPathspec(&.{ "add", "-f" }, paths);
}

/// Removes paths from the index without deleting their working-tree copies.
pub fn rmCached(self: *const Repo, paths: []const []const u8) !void {
    try self.runWithPathspec(&.{ "rm", "-q", "-r", "--cached", "--ignore-unmatch", "-f" }, paths);
}

/// Runs a Git command for any number of paths without hitting command-line length limits.
/// Paths are passed through a file so large batches remain reliable.
fn runWithPathspec(
    self: *const Repo,
    command: []const []const u8,
    paths: []const []const u8,
) !void {
    if (paths.len == 0) return;
    try self.ensureDirs();
    var data: std.ArrayList(u8) = .empty;
    defer data.deinit(self.gpa);
    for (paths) |path| {
        try data.appendSlice(self.gpa, path);
        try data.append(self.gpa, 0);
    }
    try processor.writeFileAtomic(
        self.gpa,
        self.io,
        self.pathspec_path,
        data.items,
        fs.private_file_permissions,
        null,
    );

    const from_file = try self.gpa.print(
        "--pathspec-from-file={s}",
        .{self.pathspec_path},
    );
    defer self.gpa.free(from_file);
    var argv: std.ArrayList([]const u8) = .empty;
    defer argv.deinit(self.gpa);
    try argv.appendSlice(self.gpa, command);
    try argv.appendSlice(self.gpa, &.{ from_file, "--pathspec-file-nul" });
    const out = try self.runChecked(argv.items);
    self.gpa.free(out);
}

/// Reports whether Git would ignore this path.
/// `check-ignore` rejects literal pathspecs, so it is the one Git call that omits them.
///
pub fn checkIgnore(self: *const Repo, path: []const u8) !bool {
    const argv = [_][]const u8{ "check-ignore", "-q", "--", path };
    const out = try runGitWith(self.gpa, self.io, self.environ_map, self.toplevel, &argv, false);
    defer out.deinit(self.gpa);
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

/// Reads a Boolean Git setting using Git's own accepted spellings.
/// Git canonicalizes values first, so `yes`, `on`, and `1` agree with Git itself.
pub fn configGetBool(self: *const Repo, key: []const u8) !?bool {
    const argv = [_][]const u8{ "config", "--type=bool", "--get", key };
    const value = (try self.configValue(&argv)) orelse return null;
    defer self.gpa.free(value);
    return mem.eql(u8, value, "true");
}

/// Reads a path setting after Git expands `~` in its usual way.
pub fn configGetPath(self: *const Repo, key: []const u8) !?[]u8 {
    return self.configValue(&.{ "config", "--type=path", "--get", key });
}

fn configValue(self: *const Repo, argv: []const []const u8) !?[]u8 {
    const out = try self.run(argv);
    defer out.deinit(self.gpa);
    if (!out.ok()) return null;
    return try self.gpa.dupe(u8, mem.trim(u8, out.stdout, " \r\n"));
}

pub fn configSetLocal(self: *const Repo, key: []const u8, value: []const u8) !void {
    const out = try self.runChecked(&.{ "config", "--local", key, value });
    self.gpa.free(out);
}

pub fn loadKey(self: *const Repo) ![16]u8 {
    return keygen.readKeyFile(self.io, self.key_path, null) catch |err| switch (err) {
        error.FileNotFound => return Error.RepositoryLocked,
        else => return err,
    };
}

pub fn saveKey(self: *const Repo, key: [16]u8) !void {
    try self.ensureDirs();
    try keygen.writeKeyFile(self.gpa, self.io, self.key_path, key, null);
}

/// Creates owner-only directories for private repository data and temporary files.
pub fn ensureDirs(self: *const Repo) !void {
    for ([_][]const u8{ self.private_dir, self.tmp_dir }) |dir| {
        Io.Dir.createDir(.cwd(), self.io, dir, private_dir_permissions) catch |err| switch (err) {
            error.PathAlreadyExists => {},
            else => return err,
        };
    }
}

/// Takes the repository lock before changing shared Git integration state.
/// Stale locks are reported rather than removed because only the user can know whether a process lives.
///
pub fn lock(self: *const Repo) !Lock {
    try self.ensureDirs();
    const file = Io.Dir.createFile(.cwd(), self.io, self.lock_path, .{
        .exclusive = true,
    }) catch |err| switch (err) {
        error.PathAlreadyExists => {
            const stat = Io.Dir.statFile(.cwd(), self.io, self.lock_path, .{}) catch null;
            const age: i96 = if (stat) |st|
                Io.Timestamp.now(self.io, .real).nanoseconds - st.mtime.nanoseconds
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

/// Runs Git in the requested directory with literal pathspecs, or in the current directory.
pub fn runGit(
    gpa: Allocator,
    io: Io,
    environ_map: *const std.process.Environ.Map,
    cwd: ?[]const u8,
    argv: []const []const u8,
) !Output {
    return runGitWith(gpa, io, environ_map, cwd, argv, true);
}

fn runGitWith(
    gpa: Allocator,
    io: Io,
    environ_map: *const std.process.Environ.Map,
    cwd: ?[]const u8,
    argv: []const []const u8,
    literal: bool,
) !Output {
    var full: std.ArrayList([]const u8) = .empty;
    defer full.deinit(gpa);
    try full.append(gpa, "git");
    if (literal) try full.append(gpa, "--literal-pathspecs");
    try full.appendSlice(gpa, argv);

    const result = std.process.run(gpa, io, .{
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

/// Splits NUL-delimited output into owned strings.
/// A trailing delimiter does not create an empty path.
/// Free the result with `git.freeList`.
pub fn splitNul(gpa: Allocator, data: []const u8) ![][]u8 {
    var list: std.ArrayList([]u8) = .empty;
    errdefer {
        for (list.items) |item| gpa.free(item);
        list.deinit(gpa);
    }
    var it = mem.tokenizeScalar(u8, data, 0);
    while (it.next()) |item| {
        try list.append(gpa, try gpa.dupe(u8, item));
    }
    return list.toOwnedSlice(gpa);
}

test "splitNul returns no empty entries" {
    const gpa = testing.allocator;

    const parts = try splitNul(gpa, "a\x00b c\x00\x00");
    defer git.freeList(gpa, parts);
    try testing.expectEqual(2, parts.len);
    try testing.expectEqualStrings("a", parts[0]);
    try testing.expectEqualStrings("b c", parts[1]);

    const none = try splitNul(gpa, "");
    defer git.freeList(gpa, none);
    try testing.expectEqual(0, none.len);
}
