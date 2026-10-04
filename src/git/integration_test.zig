//! Exercises the Git integration against real repositories.

const std = @import("std");
const mem = std.mem;
const testing = std.testing;
const Allocator = std.mem.Allocator;
const Io = std.Io;

const crypto = @import("../crypto.zig");
const filename_crypto = @import("../filename_crypto.zig");
const keygen = @import("../keygen.zig");
const fs = @import("../fs.zig");
const freeList = @import("../git.zig").freeList;
const Repo = @import("Repo.zig");
const Manifest = @import("Manifest.zig");
const sync = @import("sync.zig");
const cmd = @import("cmd.zig");

const Env = struct {
    map: std.process.Environ.Map,

    /// Builds an isolated Git environment for each scenario.
    /// This prevents a developer's global configuration from affecting test results.
    fn init(gpa: Allocator, home: []const u8) !Env {
        var map = try std.process.Environ.createMap(testing.environ, gpa);
        errdefer map.deinit();
        const global = try Io.Dir.path.join(gpa, &.{ home, "gitconfig" });
        defer gpa.free(global);
        try map.put("HOME", home);
        try map.put("GIT_CONFIG_GLOBAL", global);
        try map.put("GIT_CONFIG_NOSYSTEM", "1");
        try map.put("GIT_AUTHOR_NAME", "Test");
        try map.put("GIT_AUTHOR_EMAIL", "test@example.invalid");
        try map.put("GIT_COMMITTER_NAME", "Test");
        try map.put("GIT_COMMITTER_EMAIL", "test@example.invalid");
        return .{ .map = map };
    }

    fn deinit(self: *Env) void {
        self.map.deinit();
    }
};

fn git(
    gpa: Allocator,
    io: Io,
    env: *const Env,
    cwd: []const u8,
    argv: []const []const u8,
) ![]u8 {
    const out = try Repo.runGit(gpa, io, &env.map, cwd, argv);
    defer gpa.free(out.stderr);
    errdefer gpa.free(out.stdout);
    if (!out.ok()) {
        std.debug.print("git {s} failed: {s}\n", .{ argv[0], out.stderr });
        return error.GitFailed;
    }
    return out.stdout;
}

fn gitOk(
    gpa: Allocator,
    io: Io,
    env: *const Env,
    cwd: []const u8,
    argv: []const []const u8,
) !void {
    gpa.free(try git(gpa, io, env, cwd, argv));
}

fn writeFile(gpa: Allocator, io: Io, dir: []const u8, name: []const u8, data: []const u8) !void {
    const path = try Io.Dir.path.join(gpa, &.{ dir, name });
    defer gpa.free(path);
    if (Io.Dir.path.dirname(path)) |parent| try Io.Dir.createDirPath(.cwd(), io, parent);
    try Io.Dir.writeFile(.cwd(), io, .{ .sub_path = path, .data = data });
}

fn readFile(gpa: Allocator, io: Io, dir: []const u8, name: []const u8) ![]u8 {
    const path = try Io.Dir.path.join(gpa, &.{ dir, name });
    defer gpa.free(path);
    return Io.Dir.readFileAlloc(.cwd(), io, path, gpa, .limited(1024 * 1024));
}

fn gitAvailable(gpa: Allocator, io: Io) bool {
    const result = std.process.run(gpa, io, .{
        .argv = &.{ "git", "--version" },
    }) catch return false;
    gpa.free(result.stdout);
    gpa.free(result.stderr);
    return result.term.success();
}

test "a private store round trips through a clone and detects tampering" {
    const gpa = testing.allocator;
    const io = testing.io;
    if (!gitAvailable(gpa, io)) return error.SkipZigTest;

    const test_base = "tmp/git_integration";
    Io.Dir.deleteTree(.cwd(), io, test_base) catch {};
    try Io.Dir.createDirPath(.cwd(), io, test_base ++ "/home");
    defer Io.Dir.deleteTree(.cwd(), io, test_base) catch {};

    const base_abs = try Io.Dir.realPathFileAlloc(.cwd(), io, test_base, gpa);
    defer gpa.free(base_abs);
    const home = try Io.Dir.path.join(gpa, &.{ base_abs, "home" });
    defer gpa.free(home);
    const a = try Io.Dir.path.join(gpa, &.{ base_abs, "a" });
    defer gpa.free(a);
    const b = try Io.Dir.path.join(gpa, &.{ base_abs, "b" });
    defer gpa.free(b);

    var env = try Env.init(gpa, home);
    defer env.deinit();

    try gitOk(gpa, io, &env, base_abs, &.{ "init", "-q", "-b", "main", "a" });
    try writeFile(gpa, io, a, "README.md", "public\n");
    try gitOk(gpa, io, &env, a, &.{ "add", "README.md" });
    try gitOk(gpa, io, &env, a, &.{ "commit", "-qm", "public" });

    var repo_a = try Repo.openAt(gpa, io, &env.map, a);
    defer repo_a.deinit();
    // Git uses `/` separators when it reports the repository root on every platform.
    const a_as_git = try gpa.dupe(u8, a);
    defer gpa.free(a_as_git);
    mem.replaceScalar(u8, a_as_git, Io.Dir.path.sep, '/');
    try testing.expectEqualStrings(a_as_git, repo_a.toplevel);

    const key = keygen.generate(io);
    try repo_a.saveKey(key);
    const keys = crypto.deriveKeys(key, null);
    try cmd.setupStore(&repo_a);

    try writeFile(gpa, io, a, "AGENT.md", "agent notes\n");
    try writeFile(gpa, io, a, "docs/internal.md", "internal\n");
    try writeFile(gpa, io, a, "ops/deploy.sh", "#!/bin/sh\n");
    if (Io.File.Permissions.has_executable_bit) {
        const deploy = try Io.Dir.path.join(gpa, &.{ a, "ops/deploy.sh" });
        defer gpa.free(deploy);
        const deploy_file = try Io.Dir.openFile(.cwd(), io, deploy, .{ .mode = .read_write });
        try deploy_file.setPermissions(io, .fromMode(0o755));
        deploy_file.close(io);
    }

    const manifest_text = Manifest.default_text ++ "/AGENT.md\n/docs/internal.md\n/ops/\n";
    try writeFile(gpa, io, a, Manifest.filename, manifest_text);
    var manifest = try Manifest.parse(gpa, manifest_text);
    defer manifest.deinit(gpa);
    try sync.updateExcludeFile(&repo_a, &.{&manifest}, &.{}, &.{});

    var report: sync.Report = .{};
    defer report.deinit(gpa);
    try sync.encrypt(&repo_a, keys, .{}, &report);
    try testing.expectEqual(4, report.count(.encrypted));
    try gitOk(gpa, io, &env, a, &.{ "commit", "-qm", "private" });

    const tracked = try git(gpa, io, &env, a, &.{ "ls-files", "-z" });
    defer gpa.free(tracked);
    var it = mem.splitScalar(u8, tracked, 0);
    var entries: usize = 0;
    while (it.next()) |path| {
        if (path.len == 0) continue;
        if (mem.eql(u8, path, "README.md")) continue;
        try testing.expect(mem.startsWith(u8, path, ".enc/"));
        if (mem.eql(u8, path, ".enc/.turbocrypt") or
            mem.eql(u8, path, ".enc/.gitattributes") or
            mem.eql(u8, path, ".enc/README.txt")) continue;
        try testing.expect(mem.find(u8, path, "AGENT") == null);
        entries += 1;
    }
    try testing.expectEqual(4, entries);

    var again: sync.Report = .{};
    defer again.deinit(gpa);
    try sync.encrypt(&repo_a, keys, .{}, &again);
    try testing.expectEqual(0, again.count(.encrypted));
    const status = try git(gpa, io, &env, a, &.{ "status", "--porcelain" });
    defer gpa.free(status);
    try testing.expectEqualStrings("", status);

    try gitOk(gpa, io, &env, base_abs, &.{ "clone", "-q", "a", "b" });
    var repo_b = try Repo.openAt(gpa, io, &env.map, b);
    defer repo_b.deinit();
    try repo_b.saveKey(key);
    const store_manifest = try sync.manifestFromStore(&repo_b, keys);
    try testing.expect(store_manifest != null);
    gpa.free(store_manifest.?);
    const wrong = try sync.manifestFromStore(&repo_b, crypto.deriveKeys(@splat(7), null));
    try testing.expect(wrong == null);

    var decrypted: sync.Report = .{};
    defer decrypted.deinit(gpa);
    try sync.decrypt(&repo_b, keys, .{}, &decrypted);
    try testing.expectEqual(4, decrypted.count(.written));
    const agent = try readFile(gpa, io, b, "AGENT.md");
    defer gpa.free(agent);
    try testing.expectEqualStrings("agent notes\n", agent);
    if (Io.File.Permissions.has_executable_bit) {
        const deploy_b = try Io.Dir.path.join(gpa, &.{ b, "ops/deploy.sh" });
        defer gpa.free(deploy_b);
        const deploy_stat = try Io.Dir.statFile(.cwd(), io, deploy_b, .{});
        try testing.expect(deploy_stat.permissions.toMode() & 0o100 != 0);
    }

    const store_b = try sync.keyDirAbs(&repo_b, keys);
    defer gpa.free(store_b);
    var bad: std.ArrayList([]u8) = .empty;
    defer bad.deinit(gpa);
    const files = try sync.listStore(gpa, io, store_b, &bad);
    defer freeList(gpa, files);
    try testing.expectEqual(4, files.len);

    // The manifest confirms the key, so corrupting it aborts before any path is processed.
    // Corrupt two remaining entries to verify that they are reported without being written.
    // This simulates independent damaged ciphertext entries.
    const manifest_cipher = try filename_crypto.encryptPath(
        gpa,
        Manifest.filename,
        keys.filename_key,
        '/',
    );
    defer gpa.free(manifest_cipher);
    var picked: [2][]const u8 = undefined;
    var n: usize = 0;
    for (files) |f| {
        if (n == 2) break;
        if (mem.eql(u8, f, manifest_cipher)) continue;
        picked[n] = f;
        n += 1;
    }
    try testing.expectEqual(2, n);

    const first = try Io.Dir.path.join(gpa, &.{ store_b, picked[0] });
    defer gpa.free(first);
    const second = try Io.Dir.path.join(gpa, &.{ store_b, picked[1] });
    defer gpa.free(second);
    const first_bytes = try Io.Dir.readFileAlloc(.cwd(), io, first, gpa, .limited(1024 * 1024));
    defer gpa.free(first_bytes);
    const second_bytes = try Io.Dir.readFileAlloc(.cwd(), io, second, gpa, .limited(1024 * 1024));
    defer gpa.free(second_bytes);
    try Io.Dir.writeFile(.cwd(), io, .{ .sub_path = first, .data = second_bytes });
    try Io.Dir.writeFile(.cwd(), io, .{ .sub_path = second, .data = first_bytes });

    var swapped: sync.Report = .{};
    defer swapped.deinit(gpa);
    try sync.decrypt(&repo_b, keys, .{}, &swapped);
    try testing.expectEqual(2, swapped.count(.bad));
    try testing.expectEqual(0, swapped.count(.written));
    const agent_after = try readFile(gpa, io, b, "AGENT.md");
    defer gpa.free(agent_after);
    try testing.expectEqualStrings("agent notes\n", agent_after);

    try Io.Dir.writeFile(.cwd(), io, .{ .sub_path = first, .data = first_bytes });
    const flipped = try gpa.dupe(u8, second_bytes);
    defer gpa.free(flipped);
    flipped[crypto.header_size + 1] ^= 0x01;
    try Io.Dir.writeFile(.cwd(), io, .{ .sub_path = second, .data = flipped });
    var corrupted: sync.Report = .{};
    defer corrupted.deinit(gpa);
    try sync.decrypt(&repo_b, keys, .{}, &corrupted);
    try testing.expectEqual(1, corrupted.count(.bad));

    var refused: sync.Report = .{};
    defer refused.deinit(gpa);
    try testing.expectError(sync.Error.SyncAborted, sync.encrypt(&repo_b, keys, .{}, &refused));
    try testing.expectEqual(1, refused.count(.bad));
    const staged = try git(gpa, io, &env, b, &.{ "diff", "--cached", "--name-only" });
    defer gpa.free(staged);
    try testing.expectEqualStrings("", staged);

    var repaired: sync.Report = .{};
    defer repaired.deinit(gpa);
    try sync.encrypt(&repo_b, keys, .{ .force = true }, &repaired);
    try testing.expectEqual(1, repaired.count(.encrypted));
    var clean: sync.Report = .{};
    defer clean.deinit(gpa);
    try sync.decrypt(&repo_b, keys, .{}, &clean);
    try testing.expectEqual(0, clean.count(.bad));
    try gitOk(gpa, io, &env, b, &.{ "commit", "-qm", "repaired" });

    // A second key joins from another clone without learning the first key's private files.
    const c = try Io.Dir.path.join(gpa, &.{ base_abs, "c" });
    defer gpa.free(c);
    try gitOk(gpa, io, &env, base_abs, &.{ "clone", "-q", "a", "c" });
    var repo_c = try Repo.openAt(gpa, io, &env.map, c);
    defer repo_c.deinit();
    const key2 = keygen.generate(io);
    const keys2 = crypto.deriveKeys(key2, null);
    try repo_c.saveKey(key2);
    try testing.expect(try sync.manifestFromStore(&repo_c, keys2) == null);
    try testing.expectEqual(1, try sync.otherKeyCount(&repo_c, keys2));

    try cmd.setupStore(&repo_c);
    try writeFile(gpa, io, c, "mine.md", "mine\n");
    try writeFile(gpa, io, c, Manifest.filename, Manifest.default_text ++ "/mine.md\n");
    var joined: sync.Report = .{};
    defer joined.deinit(gpa);
    try sync.encrypt(&repo_c, keys2, .{}, &joined);
    try testing.expectEqual(2, joined.count(.encrypted));
    try testing.expectEqual(0, joined.count(.bad));
    try gitOk(gpa, io, &env, c, &.{ "commit", "-qm", "second key" });
    const c_tracked = try git(gpa, io, &env, c, &.{ "ls-files", "-z" });
    defer gpa.free(c_tracked);
    try testing.expect(mem.find(u8, c_tracked, "AGENT") == null);
    try testing.expect(mem.find(u8, c_tracked, "mine") == null);

    const ours = try sync.storeEntries(&repo_c, keys2);
    defer sync.freeEntries(gpa, ours);
    try testing.expectEqual(2, ours.len);
    const theirs = try sync.storeEntries(&repo_c, keys);
    defer sync.freeEntries(gpa, theirs);
    try testing.expectEqual(4, theirs.len);

    // Pull the second key's commit and confirm the first key's working tree stays unchanged.
    try gitOk(gpa, io, &env, b, &.{ "pull", "-q", "--no-rebase", c, "main" });
    try testing.expectEqual(1, try sync.otherKeyCount(&repo_b, keys));
    var after_pull: sync.Report = .{};
    defer after_pull.deinit(gpa);
    try sync.decrypt(&repo_b, keys, .{}, &after_pull);
    try testing.expectEqual(0, after_pull.count(.written));
    try testing.expectEqual(0, after_pull.count(.bad));
    try testing.expectEqual(4, after_pull.count(.ok));
    const mine_b = try Io.Dir.path.join(gpa, &.{ b, "mine.md" });
    defer gpa.free(mine_b);
    try testing.expect(!fs.pathExists(io, mine_b));
}

test "store control files replace symbolic links" {
    const gpa = testing.allocator;
    const io = testing.io;
    if (!gitAvailable(gpa, io)) return error.SkipZigTest;

    const test_base = "tmp/git_store_file_symlinks";
    Io.Dir.deleteTree(.cwd(), io, test_base) catch {};
    try Io.Dir.createDirPath(.cwd(), io, test_base ++ "/home");
    defer Io.Dir.deleteTree(.cwd(), io, test_base) catch {};

    const base_abs = try Io.Dir.realPathFileAlloc(.cwd(), io, test_base, gpa);
    defer gpa.free(base_abs);
    const home = try Io.Dir.path.join(gpa, &.{ base_abs, "home" });
    defer gpa.free(home);
    const worktree = try Io.Dir.path.join(gpa, &.{ base_abs, "repo" });
    defer gpa.free(worktree);
    const outside = try Io.Dir.path.join(gpa, &.{ base_abs, "outside" });
    defer gpa.free(outside);
    const store = try Io.Dir.path.join(gpa, &.{ worktree, sync.enc_dir });
    defer gpa.free(store);
    const control_files = .{
        .{ sync.marker_name, sync.marker_text },
        .{ sync.attributes_name, sync.attributes_text },
    };

    var env = try Env.init(gpa, home);
    defer env.deinit();
    try gitOk(gpa, io, &env, base_abs, &.{ "init", "-q", "-b", "main", "repo" });
    try Io.Dir.createDir(.cwd(), io, store, .default_dir);
    inline for (control_files) |file| {
        try writeFile(gpa, io, outside, file[0], "sentinel");
        const target = try Io.Dir.path.join(gpa, &.{ outside, file[0] });
        defer gpa.free(target);
        const link = try Io.Dir.path.join(gpa, &.{ store, file[0] });
        defer gpa.free(link);
        Io.Dir.symLink(.cwd(), io, target, link, .{}) catch |err| {
            if (err == error.Unexpected or err == error.AccessDenied) return error.SkipZigTest;
            return err;
        };
    }

    var repo = try Repo.openAt(gpa, io, &env.map, worktree);
    defer repo.deinit();
    try cmd.writeStoreFiles(&repo);

    inline for (control_files) |file| {
        const target = try readFile(gpa, io, outside, file[0]);
        defer gpa.free(target);
        try testing.expectEqualStrings("sentinel", target);
        const written = try readFile(gpa, io, store, file[0]);
        defer gpa.free(written);
        try testing.expectEqualStrings(file[1], written);
    }
}

test "an unencryptable private name aborts before writing" {
    const gpa = testing.allocator;
    const io = testing.io;
    if (!gitAvailable(gpa, io)) return error.SkipZigTest;

    const test_base = "tmp/git_long_private_name";
    Io.Dir.deleteTree(.cwd(), io, test_base) catch {};
    try Io.Dir.createDirPath(.cwd(), io, test_base ++ "/home");
    defer Io.Dir.deleteTree(.cwd(), io, test_base) catch {};

    const base_abs = try Io.Dir.realPathFileAlloc(.cwd(), io, test_base, gpa);
    defer gpa.free(base_abs);
    const home = try Io.Dir.path.join(gpa, &.{ base_abs, "home" });
    defer gpa.free(home);
    const worktree = try Io.Dir.path.join(gpa, &.{ base_abs, "repo" });
    defer gpa.free(worktree);
    var env = try Env.init(gpa, home);
    defer env.deinit();

    try gitOk(gpa, io, &env, base_abs, &.{ "init", "-q", "-b", "main", "repo" });
    try gitOk(gpa, io, &env, worktree, &.{ "commit", "-qm", "initial", "--allow-empty" });

    var repo = try Repo.openAt(gpa, io, &env.map, worktree);
    defer repo.deinit();
    const keys = crypto.deriveKeys(@splat(11), null);
    try cmd.setupStore(&repo);

    const long_name: [205]u8 = @splat('a');
    const private_path = try gpa.print("private/{s}", .{&long_name});
    defer gpa.free(private_path);
    try writeFile(gpa, io, worktree, private_path, "secret");
    const manifest_text = Manifest.default_text ++ "/private/\n";
    try writeFile(gpa, io, worktree, Manifest.filename, manifest_text);
    var manifest = try Manifest.parse(gpa, manifest_text);
    defer manifest.deinit(gpa);
    try sync.updateExcludeFile(&repo, &.{&manifest}, &.{}, &.{});

    const staged_before = try git(gpa, io, &env, worktree, &.{ "diff", "--cached", "--name-only" });
    defer gpa.free(staged_before);
    var report: sync.Report = .{};
    defer report.deinit(gpa);
    try testing.expectError(sync.Error.SyncAborted, sync.encrypt(&repo, keys, .{}, &report));
    try testing.expectEqual(1, report.count(.bad));
    try testing.expectEqual(0, report.count(.encrypted));
    const staged_after = try git(gpa, io, &env, worktree, &.{ "diff", "--cached", "--name-only" });
    defer gpa.free(staged_after);
    try testing.expectEqualStrings(staged_before, staged_after);

    var status: sync.Report = .{};
    defer status.deinit(gpa);
    try sync.collectStatus(&repo, keys, &status);
    try testing.expectEqual(1, status.count(.bad));
    for (status.rows.items) |row| {
        if (mem.eql(u8, row.path, private_path)) try testing.expectEqual(.bad, row.kind);
    }
}
