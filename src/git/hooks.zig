const std = @import("std");
const crypto = @import("../crypto.zig");
const utils = @import("../utils.zig");
const repo_mod = @import("repo.zig");
const sync = @import("sync.zig");
const manifest_mod = @import("manifest.zig");

const Repo = repo_mod.Repo;

pub const hook_names = [_][]const u8{ "pre-commit", "pre-merge-commit", "post-commit", "post-checkout", "post-merge", "post-rewrite" };

const first_line = "#!/bin/sh";
const second_line = "# Installed by turbocrypt git init. Do not edit.";

pub fn isPreHook(name: []const u8) bool {
    return std.mem.startsWith(u8, name, "pre-");
}

/// The hook script.
/// The binary path is embedded because GUI clients run hooks with a minimal PATH.
/// A post hook must never fail a git command, so a missing binary only stops pre hooks.
pub fn scriptFor(allocator: std.mem.Allocator, name: []const u8, exe_path: []const u8) ![]u8 {
    const quoted = try shellQuote(allocator, exe_path);
    defer allocator.free(quoted);
    return std.fmt.allocPrint(allocator,
        \\{s}
        \\{s}
        \\tc={s}
        \\if [ ! -x "$tc" ]; then tc=$(git config --get turbocrypt.path 2>/dev/null); fi
        \\if [ -z "$tc" ] || [ ! -x "$tc" ]; then tc=turbocrypt; fi
        \\if ! command -v "$tc" >/dev/null 2>&1; then
        \\  echo "turbocrypt: binary not found, set git config turbocrypt.path" >&2
        \\  exit {d}
        \\fi
        \\exec "$tc" git hook {s} "$@"
        \\
    , .{ first_line, second_line, quoted, @intFromBool(isPreHook(name)), name });
}

/// Single-quote a string for sh.
fn shellQuote(allocator: std.mem.Allocator, text: []const u8) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    try out.append(allocator, '\'');
    for (text) |c| {
        if (c == '\'') try out.appendSlice(allocator, "'\\''") else try out.append(allocator, c);
    }
    try out.append(allocator, '\'');
    return out.toOwnedSlice(allocator);
}

pub fn isOurs(text: []const u8) bool {
    return std.mem.startsWith(u8, text, first_line ++ "\n" ++ second_line ++ "\n");
}

/// Write every hook that is free or already ours.
/// A foreign hook is left alone and the user gets the line to add, because a line appended after an `exit 0` would never run.
pub fn install(repo: *const Repo, exe_path: []const u8) !void {
    const allocator = repo.allocator;
    const io = repo.io;

    if (try repo.configGet("core.hooksPath")) |hooks_path| {
        defer allocator.free(hooks_path);
        std.debug.print("core.hooksPath is set to {s}, so the hooks were not installed.\nAdd these calls to your hook manager:\n", .{hooks_path});
        for (hook_names) |name| {
            std.debug.print("  {s}: {s} git hook {s} \"$@\"\n", .{ name, exe_path, name });
        }
        return;
    }

    try utils.ensureDirectory(repo.hooks_dir, io);
    for (hook_names) |name| {
        const path = try std.fs.path.join(allocator, &.{ repo.hooks_dir, name });
        defer allocator.free(path);

        const existing = std.Io.Dir.readFileAlloc(.cwd(), io, path, allocator, .limited(1024 * 1024)) catch |err| switch (err) {
            error.FileNotFound => null,
            else => return err,
        };
        defer if (existing) |e| allocator.free(e);
        if (existing != null and !isOurs(existing.?)) {
            std.debug.print("Hook {s} exists and is not ours, it was left alone. Add this line to it:\n  {s} git hook {s} \"$@\"\n", .{ name, exe_path, name });
            continue;
        }

        const script = try scriptFor(allocator, name, exe_path);
        defer allocator.free(script);
        if (existing != null and std.mem.eql(u8, existing.?, script)) continue;
        try std.Io.Dir.writeFile(.cwd(), io, .{ .sub_path = path, .data = script, .flags = .{ .permissions = .executable_file } });
    }
}

/// Which hooks carry our script.
pub fn installed(repo: *const Repo) ![hook_names.len]bool {
    var result: [hook_names.len]bool = @splat(false);
    for (hook_names, 0..) |name, i| {
        const path = try std.fs.path.join(repo.allocator, &.{ repo.hooks_dir, name });
        defer repo.allocator.free(path);
        const text = std.Io.Dir.readFileAlloc(.cwd(), repo.io, path, repo.allocator, .limited(1024 * 1024)) catch continue;
        defer repo.allocator.free(text);
        result[i] = isOurs(text);
    }
    return result;
}

/// Entry point of `turbocrypt git hook <name>`. Returns the exit code.
/// Post hooks report problems but never fail the git command.
pub fn run(name: []const u8, allocator: std.mem.Allocator, io: std.Io, environ_map: *const std.process.Environ.Map) u8 {
    const pre = isPreHook(name);
    const failure: u8 = if (pre) 1 else 0;

    if (std.mem.eql(u8, name, "post-rewrite")) drainStdin(io);

    var repo = Repo.open(allocator, io, environ_map) catch return failure;
    defer repo.deinit();
    if (repo.isLinkedWorktree()) {
        std.debug.print("turbocrypt: linked worktrees are not supported, private files were not synced\n", .{});
        return 0;
    }
    if (!sync.storeExists(&repo)) return 0;

    const key = repo.loadKey() catch |err| switch (err) {
        repo_mod.Error.RepoLocked => {
            if (pre and plainManifestExists(&repo)) {
                std.debug.print("turbocrypt: this repository is locked, run: turbocrypt git unlock <key-file>\n", .{});
                return 1;
            }
            return 0;
        },
        else => {
            std.debug.print("turbocrypt: cannot read the repository key: {}\n", .{err});
            return failure;
        },
    };
    const keys = crypto.deriveKeys(key, null);

    const lock = repo.lock() catch return failure;
    defer lock.release();

    return if (pre) runPre(&repo, keys, environ_map) else runPost(&repo, keys, name);
}

fn plainManifestExists(repo: *const Repo) bool {
    const path = repo.absolutePath(manifest_mod.manifest_name) catch return false;
    defer repo.allocator.free(path);
    return utils.pathExists(path, repo.io);
}

fn runPre(repo: *const Repo, keys: crypto.DerivedKeys, environ_map: *const std.process.Environ.Map) u8 {
    const allocator = repo.allocator;
    var report = sync.Report{};
    defer report.deinit(allocator);

    const index_file = environ_map.get("GIT_INDEX_FILE") orelse "";
    const partial = std.mem.indexOf(u8, index_file, "next-index") != null;
    const temp_index = std.mem.endsWith(u8, index_file, ".lock");
    const index_was_clean = !partial and indexIsClean(repo);

    sync.encryptSync(repo, keys, .{ .validate_only = partial }, &report) catch |err| {
        printRows(&report);
        switch (err) {
            sync.Error.PrivateFileTracked => std.debug.print("turbocrypt: commit refused, private files are tracked by git\n", .{}),
            sync.Error.SyncAborted => std.debug.print("turbocrypt: commit refused, see the lines above\n", .{}),
            sync.Error.NoManifest => std.debug.print("turbocrypt: no {s} found, run: turbocrypt git decrypt\n", .{manifest_mod.manifest_name}),
            else => std.debug.print("turbocrypt: cannot encrypt private files: {}\n", .{err}),
        }
        return 1;
    };
    printRows(&report);
    if (partial and report.pending > 0) {
        std.debug.print("turbocrypt: {d} private change(s) stay out of this partial commit\n", .{report.pending});
    }
    if (!partial and index_was_clean and report.count(.encrypted) > 0) {
        if (temp_index) {
            std.debug.print("turbocrypt: private files were encrypted. If git reports nothing to commit, run: turbocrypt git encrypt, then commit again\n", .{});
        } else {
            std.debug.print("turbocrypt: private files were staged. If git reports nothing to commit, run git commit again\n", .{});
        }
    }
    return 0;
}

fn runPost(repo: *const Repo, keys: crypto.DerivedKeys, name: []const u8) u8 {
    const allocator = repo.allocator;
    var report = sync.Report{};
    defer report.deinit(allocator);

    sync.decryptSync(repo, keys, .{}, &report) catch |err| {
        printRows(&report);
        std.debug.print("turbocrypt: private files were not synced: {}\n", .{err});
        return 0;
    };
    printRows(&report);

    if (std.mem.eql(u8, name, "post-commit")) {
        var check = sync.Report{};
        defer check.deinit(allocator);
        sync.encryptSync(repo, keys, .{ .validate_only = true }, &check) catch return 0;
        if (check.pending > 0) {
            std.debug.print("turbocrypt: {d} private change(s) are not in this commit\n", .{check.pending});
        }
    }
    return 0;
}

fn indexIsClean(repo: *const Repo) bool {
    const out = repo.run(&.{ "diff-index", "--cached", "--quiet", "HEAD", "--" }) catch return false;
    defer out.deinit(repo.allocator);
    return out.ok();
}

fn drainStdin(io: std.Io) void {
    var buf: [4096]u8 = undefined;
    var reader = std.Io.File.stdin().reader(io, &buf);
    _ = reader.interface.discardRemaining() catch {};
}

/// One line per row, so a hook stays quiet when nothing happened.
/// Ignored files are a status matter, not something to repeat at every commit.
pub fn printRows(report: *const sync.Report) void {
    for (report.rows.items) |row| {
        if (row.kind == .ok or row.kind == .ignored) continue;
        if (row.detail.len == 0) {
            std.debug.print("turbocrypt: {t} {s}\n", .{ row.kind, row.path });
        } else {
            std.debug.print("turbocrypt: {t} {s}: {s}\n", .{ row.kind, row.path, row.detail });
        }
    }
}

test "hook script" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const pre = try scriptFor(allocator, "pre-commit", "/opt/it's/turbocrypt");
    defer allocator.free(pre);
    try testing.expect(isOurs(pre));
    try testing.expect(std.mem.indexOf(u8, pre, "tc='/opt/it'\\''s/turbocrypt'") != null);
    try testing.expect(std.mem.indexOf(u8, pre, "  exit 1\n") != null);
    try testing.expect(std.mem.endsWith(u8, pre, "exec \"$tc\" git hook pre-commit \"$@\"\n"));

    const post = try scriptFor(allocator, "post-merge", "/usr/local/bin/turbocrypt");
    defer allocator.free(post);
    try testing.expect(std.mem.indexOf(u8, post, "  exit 0\n") != null);

    try testing.expect(!isOurs("#!/bin/sh\nexec pre-commit run\n"));
}
