const std = @import("std");
const crypto = @import("../crypto.zig");
const filename_crypto = @import("../filename_crypto.zig");
const keygen = @import("../keygen.zig");
const utils = @import("../utils.zig");
const repo_mod = @import("repo.zig");
const manifest_mod = @import("manifest.zig");
const sync = @import("sync.zig");
const cmd = @import("cmd.zig");

const Repo = repo_mod.Repo;

const base = "tmp/git_integration";

const Env = struct {
    map: std.process.Environ.Map,

    /// A private git environment, so nothing from the developer's global config can leak into the scenario.
    fn init(allocator: std.mem.Allocator, home: []const u8) !Env {
        var map = try std.process.Environ.createMap(std.testing.environ, allocator);
        errdefer map.deinit();
        const global = try std.fs.path.join(allocator, &.{ home, "gitconfig" });
        defer allocator.free(global);
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

fn git(allocator: std.mem.Allocator, io: std.Io, env: *const Env, cwd: []const u8, argv: []const []const u8) ![]u8 {
    const out = try repo_mod.runGit(allocator, io, &env.map, cwd, argv);
    defer allocator.free(out.stderr);
    errdefer allocator.free(out.stdout);
    if (!out.ok()) {
        std.debug.print("git {s} failed: {s}\n", .{ argv[0], out.stderr });
        return error.GitFailed;
    }
    return out.stdout;
}

fn gitOk(allocator: std.mem.Allocator, io: std.Io, env: *const Env, cwd: []const u8, argv: []const []const u8) !void {
    allocator.free(try git(allocator, io, env, cwd, argv));
}

fn writeFile(io: std.Io, dir: []const u8, name: []const u8, data: []const u8, allocator: std.mem.Allocator) !void {
    const path = try std.fs.path.join(allocator, &.{ dir, name });
    defer allocator.free(path);
    if (std.fs.path.dirname(path)) |parent| try std.Io.Dir.createDirPath(.cwd(), io, parent);
    try std.Io.Dir.writeFile(.cwd(), io, .{ .sub_path = path, .data = data });
}

fn readFile(io: std.Io, dir: []const u8, name: []const u8, allocator: std.mem.Allocator) ![]u8 {
    const path = try std.fs.path.join(allocator, &.{ dir, name });
    defer allocator.free(path);
    return std.Io.Dir.readFileAlloc(.cwd(), io, path, allocator, .limited(1024 * 1024));
}

fn gitAvailable(allocator: std.mem.Allocator, io: std.Io) bool {
    const result = std.process.run(allocator, io, .{ .argv = &.{ "git", "--version" } }) catch return false;
    allocator.free(result.stdout);
    allocator.free(result.stderr);
    return result.term.success();
}

test "git integration: store round trip, clone, tamper" {
    const testing = std.testing;
    const allocator = testing.allocator;
    const io = testing.io;
    if (!gitAvailable(allocator, io)) return error.SkipZigTest;

    std.Io.Dir.deleteTree(.cwd(), io, base) catch {};
    try std.Io.Dir.createDirPath(.cwd(), io, base ++ "/home");
    defer std.Io.Dir.deleteTree(.cwd(), io, base) catch {};

    const base_abs = try std.Io.Dir.realPathFileAlloc(.cwd(), io, base, allocator);
    defer allocator.free(base_abs);
    const home = try std.fs.path.join(allocator, &.{ base_abs, "home" });
    defer allocator.free(home);
    const a = try std.fs.path.join(allocator, &.{ base_abs, "a" });
    defer allocator.free(a);
    const b = try std.fs.path.join(allocator, &.{ base_abs, "b" });
    defer allocator.free(b);

    var env = try Env.init(allocator, home);
    defer env.deinit();

    try gitOk(allocator, io, &env, base_abs, &.{ "init", "-q", "-b", "main", "a" });
    try writeFile(io, a, "README.md", "public\n", allocator);
    try gitOk(allocator, io, &env, a, &.{ "add", "README.md" });
    try gitOk(allocator, io, &env, a, &.{ "commit", "-qm", "public" });

    var repo_a = try Repo.openAt(allocator, io, &env.map, a);
    defer repo_a.deinit();
    // Git reports the top level with '/' on every platform.
    const a_as_git = try allocator.dupe(u8, a);
    defer allocator.free(a_as_git);
    std.mem.replaceScalar(u8, a_as_git, std.fs.path.sep, '/');
    try testing.expectEqualStrings(a_as_git, repo_a.toplevel);

    const key = keygen.generate(io);
    try repo_a.saveKey(key);
    const keys = crypto.deriveKeys(key, null);
    try cmd.setupStore(&repo_a);

    try writeFile(io, a, "AGENT.md", "agent notes\n", allocator);
    try writeFile(io, a, "docs/internal.md", "internal\n", allocator);
    try writeFile(io, a, "ops/deploy.sh", "#!/bin/sh\n", allocator);
    if (std.Io.File.Permissions.has_executable_bit) {
        const deploy = try std.fs.path.join(allocator, &.{ a, "ops/deploy.sh" });
        defer allocator.free(deploy);
        const deploy_file = try std.Io.Dir.openFile(.cwd(), io, deploy, .{ .mode = .read_write });
        try deploy_file.setPermissions(io, .fromMode(0o755));
        deploy_file.close(io);
    }

    const manifest_text = manifest_mod.default_text ++ "/AGENT.md\n/docs/internal.md\n/ops/\n";
    try writeFile(io, a, manifest_mod.filename, manifest_text, allocator);
    var manifest = try manifest_mod.Manifest.parse(allocator, manifest_text);
    defer manifest.deinit(allocator);
    try sync.updateExcludeFile(&repo_a, &.{&manifest}, &.{}, &.{});

    var report = sync.Report{};
    defer report.deinit(allocator);
    try sync.encrypt(&repo_a, keys, .{}, &report);
    try testing.expectEqual(@as(usize, 4), report.count(.encrypted));
    try gitOk(allocator, io, &env, a, &.{ "commit", "-qm", "private" });

    const tracked = try git(allocator, io, &env, a, &.{ "ls-files", "-z" });
    defer allocator.free(tracked);
    var it = std.mem.splitScalar(u8, tracked, 0);
    var entries: usize = 0;
    while (it.next()) |path| {
        if (path.len == 0) continue;
        if (std.mem.eql(u8, path, "README.md")) continue;
        try testing.expect(std.mem.startsWith(u8, path, ".enc/"));
        if (std.mem.eql(u8, path, ".enc/.turbocrypt") or std.mem.eql(u8, path, ".enc/.gitattributes")) continue;
        try testing.expect(std.mem.indexOf(u8, path, "AGENT") == null);
        entries += 1;
    }
    try testing.expectEqual(@as(usize, 4), entries);

    var again = sync.Report{};
    defer again.deinit(allocator);
    try sync.encrypt(&repo_a, keys, .{}, &again);
    try testing.expectEqual(@as(usize, 0), again.count(.encrypted));
    const status = try git(allocator, io, &env, a, &.{ "status", "--porcelain" });
    defer allocator.free(status);
    try testing.expectEqualStrings("", status);

    try gitOk(allocator, io, &env, base_abs, &.{ "clone", "-q", "a", "b" });
    var repo_b = try Repo.openAt(allocator, io, &env.map, b);
    defer repo_b.deinit();
    try repo_b.saveKey(key);
    const store_manifest = try sync.manifestFromStore(&repo_b, keys);
    try testing.expect(store_manifest != null);
    allocator.free(store_manifest.?);
    const wrong = try sync.manifestFromStore(&repo_b, crypto.deriveKeys(@splat(7), null));
    try testing.expect(wrong == null);

    var decrypted = sync.Report{};
    defer decrypted.deinit(allocator);
    try sync.decrypt(&repo_b, keys, .{}, &decrypted);
    try testing.expectEqual(@as(usize, 4), decrypted.count(.written));
    const agent = try readFile(io, b, "AGENT.md", allocator);
    defer allocator.free(agent);
    try testing.expectEqualStrings("agent notes\n", agent);
    if (std.Io.File.Permissions.has_executable_bit) {
        const deploy_b = try std.fs.path.join(allocator, &.{ b, "ops/deploy.sh" });
        defer allocator.free(deploy_b);
        const deploy_stat = try std.Io.Dir.statFile(.cwd(), io, deploy_b, .{});
        try testing.expect(deploy_stat.permissions.toMode() & 0o100 != 0);
    }

    const store_b = try sync.keyDirAbs(&repo_b, keys);
    defer allocator.free(store_b);
    var bad: std.ArrayList([]u8) = .empty;
    defer bad.deinit(allocator);
    const files = try sync.listStore(allocator, store_b, &bad, io);
    defer utils.freeList(allocator, files);
    try testing.expectEqual(@as(usize, 4), files.len);

    // The manifest entry is the key check, so corrupting it stops a pass before any row is produced.
    // Tamper with two other entries.
    const manifest_cipher = try filename_crypto.encryptPath(allocator, manifest_mod.filename, keys.filename_key, '/');
    defer allocator.free(manifest_cipher);
    var picked: [2][]const u8 = undefined;
    var n: usize = 0;
    for (files) |f| {
        if (n == 2) break;
        if (std.mem.eql(u8, f, manifest_cipher)) continue;
        picked[n] = f;
        n += 1;
    }
    try testing.expectEqual(@as(usize, 2), n);

    const first = try std.fs.path.join(allocator, &.{ store_b, picked[0] });
    defer allocator.free(first);
    const second = try std.fs.path.join(allocator, &.{ store_b, picked[1] });
    defer allocator.free(second);
    const first_bytes = try std.Io.Dir.readFileAlloc(.cwd(), io, first, allocator, .limited(1024 * 1024));
    defer allocator.free(first_bytes);
    const second_bytes = try std.Io.Dir.readFileAlloc(.cwd(), io, second, allocator, .limited(1024 * 1024));
    defer allocator.free(second_bytes);
    try std.Io.Dir.writeFile(.cwd(), io, .{ .sub_path = first, .data = second_bytes });
    try std.Io.Dir.writeFile(.cwd(), io, .{ .sub_path = second, .data = first_bytes });

    var swapped = sync.Report{};
    defer swapped.deinit(allocator);
    try sync.decrypt(&repo_b, keys, .{}, &swapped);
    try testing.expectEqual(@as(usize, 2), swapped.count(.bad));
    try testing.expectEqual(@as(usize, 0), swapped.count(.written));
    const agent_after = try readFile(io, b, "AGENT.md", allocator);
    defer allocator.free(agent_after);
    try testing.expectEqualStrings("agent notes\n", agent_after);

    try std.Io.Dir.writeFile(.cwd(), io, .{ .sub_path = first, .data = first_bytes });
    const flipped = try allocator.dupe(u8, second_bytes);
    defer allocator.free(flipped);
    flipped[crypto.header_size + 1] ^= 0x01;
    try std.Io.Dir.writeFile(.cwd(), io, .{ .sub_path = second, .data = flipped });
    var corrupted = sync.Report{};
    defer corrupted.deinit(allocator);
    try sync.decrypt(&repo_b, keys, .{}, &corrupted);
    try testing.expectEqual(@as(usize, 1), corrupted.count(.bad));

    var refused = sync.Report{};
    defer refused.deinit(allocator);
    try testing.expectError(sync.Error.SyncAborted, sync.encrypt(&repo_b, keys, .{}, &refused));
    try testing.expectEqual(@as(usize, 1), refused.count(.bad));
    const staged = try git(allocator, io, &env, b, &.{ "diff", "--cached", "--name-only" });
    defer allocator.free(staged);
    try testing.expectEqualStrings("", staged);

    var repaired = sync.Report{};
    defer repaired.deinit(allocator);
    try sync.encrypt(&repo_b, keys, .{ .force = true }, &repaired);
    try testing.expectEqual(@as(usize, 1), repaired.count(.encrypted));
    var clean = sync.Report{};
    defer clean.deinit(allocator);
    try sync.decrypt(&repo_b, keys, .{}, &clean);
    try testing.expectEqual(@as(usize, 0), clean.count(.bad));
    try gitOk(allocator, io, &env, b, &.{ "commit", "-qm", "repaired" });

    // A second key joins from another clone and sees none of the first key's files.
    const c = try std.fs.path.join(allocator, &.{ base_abs, "c" });
    defer allocator.free(c);
    try gitOk(allocator, io, &env, base_abs, &.{ "clone", "-q", "a", "c" });
    var repo_c = try Repo.openAt(allocator, io, &env.map, c);
    defer repo_c.deinit();
    const key2 = keygen.generate(io);
    const keys2 = crypto.deriveKeys(key2, null);
    try repo_c.saveKey(key2);
    try testing.expect(try sync.manifestFromStore(&repo_c, keys2) == null);
    try testing.expectEqual(@as(usize, 1), try sync.otherKeyCount(&repo_c, keys2));

    try cmd.setupStore(&repo_c);
    try writeFile(io, c, "mine.md", "mine\n", allocator);
    try writeFile(io, c, manifest_mod.filename, manifest_mod.default_text ++ "/mine.md\n", allocator);
    var joined = sync.Report{};
    defer joined.deinit(allocator);
    try sync.encrypt(&repo_c, keys2, .{}, &joined);
    try testing.expectEqual(@as(usize, 2), joined.count(.encrypted));
    try testing.expectEqual(@as(usize, 0), joined.count(.bad));
    try gitOk(allocator, io, &env, c, &.{ "commit", "-qm", "second key" });
    const c_tracked = try git(allocator, io, &env, c, &.{ "ls-files", "-z" });
    defer allocator.free(c_tracked);
    try testing.expect(std.mem.indexOf(u8, c_tracked, "AGENT") == null);
    try testing.expect(std.mem.indexOf(u8, c_tracked, "mine") == null);

    const ours = try sync.storeEntries(&repo_c, keys2);
    defer sync.freeEntries(allocator, ours);
    try testing.expectEqual(@as(usize, 2), ours.len);
    const theirs = try sync.storeEntries(&repo_c, keys);
    defer sync.freeEntries(allocator, theirs);
    try testing.expectEqual(@as(usize, 4), theirs.len);

    // The first key pulls that commit and nothing changes for it.
    try gitOk(allocator, io, &env, b, &.{ "pull", "-q", "--no-rebase", c, "main" });
    try testing.expectEqual(@as(usize, 1), try sync.otherKeyCount(&repo_b, keys));
    var after_pull = sync.Report{};
    defer after_pull.deinit(allocator);
    try sync.decrypt(&repo_b, keys, .{}, &after_pull);
    try testing.expectEqual(@as(usize, 0), after_pull.count(.written));
    try testing.expectEqual(@as(usize, 0), after_pull.count(.bad));
    try testing.expectEqual(@as(usize, 4), after_pull.count(.ok));
    const mine_b = try std.fs.path.join(allocator, &.{ b, "mine.md" });
    defer allocator.free(mine_b);
    try testing.expect(!utils.pathExists(mine_b, io));
}

test "git integration: an unencryptable private name aborts before writing" {
    const testing = std.testing;
    const allocator = testing.allocator;
    const io = testing.io;
    if (!gitAvailable(allocator, io)) return error.SkipZigTest;

    const test_base = "tmp/git_long_private_name";
    std.Io.Dir.deleteTree(.cwd(), io, test_base) catch {};
    try std.Io.Dir.createDirPath(.cwd(), io, test_base ++ "/home");
    defer std.Io.Dir.deleteTree(.cwd(), io, test_base) catch {};

    const base_abs = try std.Io.Dir.realPathFileAlloc(.cwd(), io, test_base, allocator);
    defer allocator.free(base_abs);
    const home = try std.fs.path.join(allocator, &.{ base_abs, "home" });
    defer allocator.free(home);
    const worktree = try std.fs.path.join(allocator, &.{ base_abs, "repo" });
    defer allocator.free(worktree);
    var env = try Env.init(allocator, home);
    defer env.deinit();

    try gitOk(allocator, io, &env, base_abs, &.{ "init", "-q", "-b", "main", "repo" });
    try gitOk(allocator, io, &env, worktree, &.{ "commit", "-qm", "initial", "--allow-empty" });

    var repo = try Repo.openAt(allocator, io, &env.map, worktree);
    defer repo.deinit();
    const keys = crypto.deriveKeys(@splat(11), null);
    try cmd.setupStore(&repo);

    const long_name: [205]u8 = @splat('a');
    const private_path = try std.fmt.allocPrint(allocator, "private/{s}", .{&long_name});
    defer allocator.free(private_path);
    try writeFile(io, worktree, private_path, "secret", allocator);
    const manifest_text = manifest_mod.default_text ++ "/private/\n";
    try writeFile(io, worktree, manifest_mod.filename, manifest_text, allocator);
    var manifest = try manifest_mod.Manifest.parse(allocator, manifest_text);
    defer manifest.deinit(allocator);
    try sync.updateExcludeFile(&repo, &.{&manifest}, &.{}, &.{});

    const staged_before = try git(allocator, io, &env, worktree, &.{ "diff", "--cached", "--name-only" });
    defer allocator.free(staged_before);
    var report = sync.Report{};
    defer report.deinit(allocator);
    try testing.expectError(sync.Error.SyncAborted, sync.encrypt(&repo, keys, .{}, &report));
    try testing.expectEqual(@as(usize, 1), report.count(.bad));
    try testing.expectEqual(@as(usize, 0), report.count(.encrypted));
    const staged_after = try git(allocator, io, &env, worktree, &.{ "diff", "--cached", "--name-only" });
    defer allocator.free(staged_after);
    try testing.expectEqualStrings(staged_before, staged_after);

    var status = sync.Report{};
    defer status.deinit(allocator);
    try sync.collectStatus(&repo, keys, &status);
    try testing.expectEqual(@as(usize, 1), status.count(.bad));
    for (status.rows.items) |row| {
        if (std.mem.eql(u8, row.path, private_path)) try testing.expectEqual(sync.Row.Kind.bad, row.kind);
    }
}
