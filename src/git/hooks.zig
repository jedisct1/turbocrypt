//! Installs and runs Git hooks that keep plain files synchronized with the encrypted store.

const std = @import("std");
const mem = std.mem;
const testing = std.testing;
const Allocator = std.mem.Allocator;
const Io = std.Io;

const crypto = @import("../crypto.zig");
const fs = @import("../fs.zig");
const Repo = @import("Repo.zig");
const sync = @import("sync.zig");
const Manifest = @import("Manifest.zig");

pub const names = [_][]const u8{
    "pre-commit",
    "pre-merge-commit",
    "post-commit",
    "post-checkout",
    "post-merge",
    "post-rewrite",
};

const first_line = "#!/bin/sh";
const second_line = "# Installed by turbocrypt git init. Do not edit.";

pub fn isPreHook(name: []const u8) bool {
    return mem.startsWith(u8, name, "pre-");
}

/// Builds one hook script. Caller owns the returned memory.
/// The script embeds the executable path because GUI clients often provide a minimal `PATH`.
/// A missing binary stops pre-hooks but never makes a post-hook fail the Git command.
/// This preserves Git's completed operation while still protecting new commits.
pub fn scriptFor(gpa: Allocator, name: []const u8, exe_path: []const u8) ![]u8 {
    const quoted = try shellQuote(gpa, exe_path);
    defer gpa.free(quoted);
    return gpa.print(
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

/// Quotes `text` as one shell word. Caller owns the returned memory.
///
pub fn shellQuote(gpa: Allocator, text: []const u8) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    try out.append(gpa, '\'');
    for (text) |c| {
        if (c == '\'') try out.appendSlice(gpa, "'\\''") else try out.append(gpa, c);
    }
    try out.append(gpa, '\'');
    return out.toOwnedSlice(gpa);
}

pub fn isOurs(text: []const u8) bool {
    return mem.startsWith(u8, text, first_line ++ "\n" ++ second_line ++ "\n");
}

/// Installs hooks that are absent or already managed by turbocrypt.
/// Existing user hooks are left intact and the user gets an invocation to add.
/// Appending blindly could put it after `exit 0`, where it would never run.
pub fn install(repo: *const Repo, exe_path: []const u8) !void {
    const gpa = repo.gpa;
    const io = repo.io;

    if (try repo.configGet("core.hooksPath")) |hooks_path| {
        defer gpa.free(hooks_path);
        std.debug.print("core.hooksPath is set to {s}, so the hooks were not installed.\nAdd these calls to your hook manager:\n", .{hooks_path});
        for (names) |name| {
            std.debug.print("  {s}: {s} git hook {s} \"$@\"\n", .{ name, exe_path, name });
        }
        return;
    }

    try fs.ensureDir(io, repo.hooks_dir);
    for (names) |name| {
        const path = try Io.Dir.path.join(gpa, &.{ repo.hooks_dir, name });
        defer gpa.free(path);

        const existing = Io.Dir.readFileAlloc(
            .cwd(),
            io,
            path,
            gpa,
            .limited(1024 * 1024),
        ) catch |err| switch (err) {
            error.FileNotFound => null,
            else => return err,
        };
        defer if (existing) |e| gpa.free(e);
        if (existing != null and !isOurs(existing.?)) {
            std.debug.print("Hook {s} exists and is not ours, it was left alone. Add this line to it:\n  {s} git hook {s} \"$@\"\n", .{ name, exe_path, name });
            continue;
        }

        const script = try scriptFor(gpa, name, exe_path);
        defer gpa.free(script);
        if (existing != null and mem.eql(u8, existing.?, script)) continue;
        try Io.Dir.writeFile(.cwd(), io, .{
            .sub_path = path,
            .data = script,
            .flags = .{ .permissions = .executable_file },
        });
    }
}

/// Reports which configured hook files contain turbocrypt's script.
pub fn installed(repo: *const Repo) ![names.len]bool {
    const gpa = repo.gpa;
    const io = repo.io;
    var result: [names.len]bool = @splat(false);
    for (names, 0..) |name, i| {
        const path = try Io.Dir.path.join(gpa, &.{ repo.hooks_dir, name });
        defer gpa.free(path);
        const text = Io.Dir.readFileAlloc(
            .cwd(),
            io,
            path,
            gpa,
            .limited(1024 * 1024),
        ) catch continue;
        defer gpa.free(text);
        result[i] = isOurs(text);
    }
    return result;
}

/// Runs `turbocrypt git hook <name>` and returns its exit code.
/// Post-hooks report problems but do not fail the Git operation that triggered them.
pub fn run(
    gpa: Allocator,
    io: Io,
    environ_map: *const std.process.Environ.Map,
    name: []const u8,
) u8 {
    const pre = isPreHook(name);
    const failure: u8 = if (pre) 1 else 0;

    if (mem.eql(u8, name, "post-rewrite")) drainStdin(io);

    var repo = Repo.open(gpa, io, environ_map) catch return failure;
    defer repo.deinit();
    if (repo.isLinkedWorktree()) {
        std.debug.print("turbocrypt: linked worktrees are not supported, private files were not synced\n", .{});
        return 0;
    }
    if (!sync.storeExists(&repo)) return 0;

    const key = repo.loadKey() catch |err| switch (err) {
        Repo.Error.RepositoryLocked => {
            if (pre and plainManifestExists(&repo)) {
                std.debug.print("turbocrypt: this repository is locked, run: turbocrypt git unlock\n", .{});
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

    return if (pre) runPre(&repo, environ_map, keys) else runPost(&repo, keys, name);
}

fn plainManifestExists(repo: *const Repo) bool {
    const path = repo.absolutePath(Manifest.filename) catch return false;
    defer repo.gpa.free(path);
    return fs.pathExists(repo.io, path);
}

fn runPre(
    repo: *const Repo,
    environ_map: *const std.process.Environ.Map,
    keys: crypto.DerivedKeys,
) u8 {
    const gpa = repo.gpa;
    var report: sync.Report = .{};
    defer report.deinit(gpa);

    const index_file = environ_map.get("GIT_INDEX_FILE") orelse "";
    const partial = mem.find(u8, index_file, "next-index") != null;
    const temp_index = mem.endsWith(u8, index_file, ".lock");
    const index_was_clean = !partial and isIndexClean(repo);

    sync.encrypt(repo, keys, .{ .validate_only = partial }, &report) catch |err| {
        printRows(&report);
        switch (err) {
            sync.Error.PrivateFileTracked => std.debug.print("turbocrypt: commit refused, private files are tracked by git\n", .{}),
            sync.Error.SyncAborted => std.debug.print("turbocrypt: commit refused, see the lines above\n", .{}),
            sync.Error.NoManifest => std.debug.print("turbocrypt: no {s} found, run: turbocrypt git decrypt\n", .{Manifest.filename}),
            else => std.debug.print("turbocrypt: cannot encrypt private files: {}\n", .{err}),
        }
        return 1;
    };
    printRows(&report);
    if (partial and report.pending > 0) {
        std.debug.print(
            "turbocrypt: {d} private change(s) stay out of this partial commit\n",
            .{report.pending},
        );
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
    const gpa = repo.gpa;
    var report: sync.Report = .{};
    defer report.deinit(gpa);

    sync.decrypt(repo, keys, .{}, &report) catch |err| {
        printRows(&report);
        std.debug.print("turbocrypt: private files were not synced: {}\n", .{err});
        return 0;
    };
    printRows(&report);

    if (mem.eql(u8, name, "post-commit")) {
        var check: sync.Report = .{};
        defer check.deinit(gpa);
        sync.encrypt(repo, keys, .{ .validate_only = true }, &check) catch return 0;
        if (check.pending > 0) {
            std.debug.print(
                "turbocrypt: {d} private change(s) are not in this commit\n",
                .{check.pending},
            );
        }
    }
    return 0;
}

fn isIndexClean(repo: *const Repo) bool {
    const out = repo.run(&.{ "diff-index", "--cached", "--quiet", "HEAD", "--" }) catch return false;
    defer out.deinit(repo.gpa);
    return out.ok();
}

fn drainStdin(io: Io) void {
    var buf: [4096]u8 = undefined;
    var reader = Io.File.stdin().reader(io, &buf);
    _ = reader.interface.discardRemaining() catch {};
}

/// Prints only rows that need attention so routine hooks stay quiet.
/// Ignored files belong in status output, not in every commit message.
///
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

test "hook scripts embed the quoted binary path and only pre hooks fail without it" {
    const gpa = testing.allocator;

    const pre = try scriptFor(gpa, "pre-commit", "/opt/it's/turbocrypt");
    defer gpa.free(pre);
    try testing.expect(isOurs(pre));
    try testing.expect(mem.find(u8, pre, "tc='/opt/it'\\''s/turbocrypt'") != null);
    try testing.expect(mem.find(u8, pre, "  exit 1\n") != null);
    try testing.expect(mem.endsWith(u8, pre, "exec \"$tc\" git hook pre-commit \"$@\"\n"));

    const post = try scriptFor(gpa, "post-merge", "/usr/local/bin/turbocrypt");
    defer gpa.free(post);
    try testing.expect(mem.find(u8, post, "  exit 0\n") != null);

    try testing.expect(!isOurs("#!/bin/sh\nexec pre-commit run\n"));
}
