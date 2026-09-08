const std = @import("std");
const builtin = @import("builtin");
const crypto = @import("../crypto.zig");
const filename_crypto = @import("../filename_crypto.zig");
const keygen = @import("../keygen.zig");
const prompt = @import("../prompt.zig");
const processor = @import("../processor.zig");
const utils = @import("../utils.zig");
const repo_mod = @import("repo.zig");
const manifest_mod = @import("manifest.zig");
const sync = @import("sync.zig");
const hooks = @import("hooks.zig");

const Repo = repo_mod.Repo;
const Manifest = manifest_mod.Manifest;

pub const usage_text =
    \\Usage: turbocrypt git <subcommand> [options]
    \\
    \\Keep private files in a public git repository. They live encrypted
    \\under .enc/ and appear in clear in your working tree.
    \\
    \\  init [--key <key-file>]        Set up this repository (key, hooks, .enc/, .gitprivate)
    \\  unlock <key-file> [--force]    Set up a clone with the shared key and decrypt .enc/
    \\  export-key <out> [--password]  Write the repository key to a file to share it
    \\  add <path>...                  Make files or directories private
    \\  rm <path>...                   Make files or directories public again
    \\  status                         Show private files and what is out of sync
    \\  encrypt [--force] [<path>...]  Refresh .enc/ from the plain files and stage it
    \\  decrypt [--force] [<path>...]  Refresh the plain files from .enc/
    \\
    \\Examples:
    \\  turbocrypt git init
    \\  turbocrypt git add AGENT.md docs/internal.md ops/
    \\  git commit -m "Add private notes"
    \\  turbocrypt git export-key --password team.key
    \\  turbocrypt git unlock team.key
    \\
;

const Flags = struct {
    force: bool = false,
    password: bool = false,
    key: ?[]const u8 = null,
    positional: []const []const u8,
};

fn parseFlags(args: []const []const u8, allocator: std.mem.Allocator) !Flags {
    var flags = Flags{ .positional = &.{} };
    var positional: std.ArrayList([]const u8) = .empty;
    errdefer positional.deinit(allocator);

    var i: usize = 0;
    var literal = false;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (literal or !std.mem.startsWith(u8, arg, "--")) {
            try positional.append(allocator, arg);
        } else if (std.mem.eql(u8, arg, "--")) {
            literal = true;
        } else if (std.mem.eql(u8, arg, "--force")) {
            flags.force = true;
        } else if (std.mem.eql(u8, arg, "--password")) {
            flags.password = true;
        } else if (std.mem.eql(u8, arg, "--key")) {
            i += 1;
            if (i >= args.len) {
                std.debug.print("Error: --key requires a path\n", .{});
                return error.InvalidArguments;
            }
            flags.key = args[i];
        } else {
            std.debug.print("Error: Unknown option '{s}'\n", .{arg});
            return error.InvalidArguments;
        }
    }
    flags.positional = try positional.toOwnedSlice(allocator);
    return flags;
}

pub fn run(args: []const []const u8, allocator: std.mem.Allocator, io: std.Io, environ_map: *const std.process.Environ.Map) !void {
    if (args.len < 1 or std.mem.eql(u8, args[0], "help") or std.mem.eql(u8, args[0], "--help")) {
        std.debug.print("{s}", .{usage_text});
        if (args.len < 1) return error.InvalidArguments;
        return;
    }
    const sub = args[0];
    const rest = args[1..];

    if (std.mem.eql(u8, sub, "hook")) {
        if (rest.len < 1) {
            std.debug.print("Error: Missing hook name\n", .{});
            return error.InvalidArguments;
        }
        std.process.exit(hooks.run(rest[0], allocator, io, environ_map));
    }

    if (builtin.os.tag == .windows) {
        std.debug.print("Error: turbocrypt git is not available on Windows. The encrypted names use characters that NTFS rejects.\n", .{});
        return error.Unsupported;
    }

    if (std.mem.eql(u8, sub, "init")) return cmdInit(rest, allocator, io, environ_map);
    if (std.mem.eql(u8, sub, "unlock")) return cmdUnlock(rest, allocator, io, environ_map);
    if (std.mem.eql(u8, sub, "export-key")) return cmdExportKey(rest, allocator, io, environ_map);
    if (std.mem.eql(u8, sub, "add")) return cmdAdd(rest, allocator, io, environ_map);
    if (std.mem.eql(u8, sub, "rm")) return cmdRm(rest, allocator, io, environ_map);
    if (std.mem.eql(u8, sub, "status")) return cmdStatus(rest, allocator, io, environ_map);
    if (std.mem.eql(u8, sub, "encrypt")) return cmdSync(.encrypt, rest, allocator, io, environ_map);
    if (std.mem.eql(u8, sub, "decrypt")) return cmdSync(.decrypt, rest, allocator, io, environ_map);

    std.debug.print("Error: Unknown git subcommand '{s}'\n\n{s}", .{ sub, usage_text });
    return error.InvalidArguments;
}

fn openRepo(allocator: std.mem.Allocator, io: std.Io, environ_map: *const std.process.Environ.Map) !Repo {
    var repo = try Repo.open(allocator, io, environ_map);
    errdefer repo.deinit();
    if (repo.isLinkedWorktree()) {
        std.debug.print("Error: linked worktrees are not supported by turbocrypt git. Use the main working tree.\n", .{});
        return error.LinkedWorktree;
    }
    return repo;
}

fn loadKeys(repo: *const Repo) !crypto.DerivedKeys {
    const key = repo.loadKey() catch |err| switch (err) {
        repo_mod.Error.RepoLocked => {
            std.debug.print("Error: this repository has no key yet. Run: turbocrypt git unlock <key-file>\n", .{});
            return err;
        },
        else => {
            std.debug.print("Error: cannot read the repository key {s}: {}\n", .{ repo.key_path, err });
            return err;
        },
    };
    return crypto.deriveKeys(key, null);
}

/// Read a key file, asking for its password when it has one.
fn readKeyFile(allocator: std.mem.Allocator, path: []const u8, io: std.Io) ![16]u8 {
    const protected = prompt.isKeyPasswordProtected(path, io) catch |err| {
        std.debug.print("Error: cannot read key file '{s}': {}\n", .{ path, err });
        return err;
    };
    var password: ?[]u8 = null;
    defer if (password) |pw| {
        std.crypto.secureZero(u8, pw);
        allocator.free(pw);
    };
    if (protected) password = try prompt.promptPassword(allocator, "Key password: ", false, io);
    return keygen.readKeyFile(path, password, io) catch |err| {
        switch (err) {
            error.InvalidPassword => std.debug.print("Error: wrong password\n", .{}),
            else => std.debug.print("Error: cannot read key file '{s}': {}\n", .{ path, err }),
        }
        return err;
    };
}

fn printReport(report: *const sync.Report) void {
    for (report.rows.items) |row| {
        if (row.detail.len == 0) {
            std.debug.print("  {t:<10} {s}\n", .{ row.kind, row.path });
        } else {
            std.debug.print("  {t:<10} {s}  ({s})\n", .{ row.kind, row.path, row.detail });
        }
    }
}

/// Report a failed sync and hand the error back.
fn failSync(report: *const sync.Report, err: anyerror) anyerror {
    printReport(report);
    explainSyncError(err);
    return err;
}

fn explainSyncError(err: anyerror) void {
    switch (err) {
        sync.Error.PrivateFileTracked => std.debug.print("Error: private files are tracked by git, see the lines above\n", .{}),
        sync.Error.SyncAborted => std.debug.print("Error: nothing was changed, see the lines above\n", .{}),
        sync.Error.NoManifest => std.debug.print("Error: no {s} found. Run turbocrypt git init in a new repository, or unlock in a clone\n", .{manifest_mod.manifest_name}),
        sync.Error.WrongKey => std.debug.print("Error: the store does not decrypt with this key: wrong key or corrupted\n", .{}),
        error.CrossDevice => std.debug.print("Error: the git directory and the working tree must be on the same filesystem\n", .{}),
        repo_mod.Error.Locked => {},
        else => std.debug.print("Error: {}\n", .{err}),
    }
}

pub fn writeStoreFiles(repo: *const Repo) !void {
    const allocator = repo.allocator;
    const store = try repo.absolutePath(sync.enc_dir);
    defer allocator.free(store);
    try utils.ensureDirectory(store, repo.io);

    const marker = try std.fs.path.join(allocator, &.{ store, sync.marker_name });
    defer allocator.free(marker);
    try std.Io.Dir.writeFile(.cwd(), repo.io, .{ .sub_path = marker, .data = sync.marker_text });

    const attributes = try std.fs.path.join(allocator, &.{ store, sync.attributes_name });
    defer allocator.free(attributes);
    try std.Io.Dir.writeFile(.cwd(), repo.io, .{ .sub_path = attributes, .data = sync.attributes_text });

    const rel_marker = sync.enc_dir ++ "/" ++ sync.marker_name;
    const rel_attributes = sync.enc_dir ++ "/" ++ sync.attributes_name;
    try repo.addForce(&.{ rel_marker, rel_attributes });
}

/// The exclude block, the manifest and the store files of a new repository.
/// The block comes first so the manifest is never unignored.
pub fn setupStore(repo: *const Repo) !void {
    const allocator = repo.allocator;
    try repo.ensureDirs();
    try sync.updateExcludeFile(repo, &.{}, &.{}, &.{});

    const manifest_path = try repo.absolutePath(manifest_mod.manifest_name);
    defer allocator.free(manifest_path);
    if (!utils.pathExists(manifest_path, repo.io)) {
        try processor.writeFileAtomic(manifest_path, manifest_mod.default_text, .fromMode(0o600), repo.tmp_dir, allocator, repo.io);
    }
    try writeStoreFiles(repo);
}

fn installIntegration(repo: *const Repo) !void {
    const exe = try std.process.executablePathAlloc(repo.io, repo.allocator);
    defer repo.allocator.free(exe);
    try repo.configSetLocal("turbocrypt.path", exe);
    try hooks.install(repo, exe);
}

fn cmdInit(args: []const []const u8, allocator: std.mem.Allocator, io: std.Io, environ_map: *const std.process.Environ.Map) !void {
    const flags = try parseFlags(args, allocator);
    defer allocator.free(flags.positional);
    if (flags.positional.len != 0) {
        std.debug.print("Usage: turbocrypt git init [--key <key-file>]\n", .{});
        return error.InvalidArguments;
    }

    var repo = try openRepo(allocator, io, environ_map);
    defer repo.deinit();
    const lock = try repo.lock();
    defer lock.release();

    if (sync.storeExists(&repo)) {
        if (flags.key) |key_file| return unlockWith(&repo, key_file, flags.force);
        if (!repo.hasKey()) {
            std.debug.print("Error: this repository already has a {s}/ store. Run: turbocrypt git unlock <key-file>\n", .{sync.enc_dir});
            return error.InvalidArguments;
        }
        std.debug.print("Store already set up, refreshing hooks and private files\n", .{});
        try installIntegration(&repo);
        return decryptAll(&repo, false);
    }

    const store = try repo.absolutePath(sync.enc_dir);
    defer allocator.free(store);
    if (std.Io.Dir.statFile(.cwd(), io, store, .{ .follow_symlinks = false })) |stat| {
        if (stat.kind != .directory) {
            std.debug.print("Error: {s} exists and is not a directory\n", .{sync.enc_dir});
            return error.InvalidArguments;
        }
        var dir = try std.Io.Dir.openDir(.cwd(), io, store, .{ .iterate = true });
        defer dir.close(io);
        var it = dir.iterate();
        if (try it.next(io) != null) {
            std.debug.print("Error: {s}/ exists, is not empty and is not a turbocrypt store\n", .{sync.enc_dir});
            return error.InvalidArguments;
        }
    } else |err| switch (err) {
        error.FileNotFound => {},
        else => return err,
    }
    if (try repo.checkIgnore(sync.enc_dir)) {
        std.debug.print("Error: {s}/ is ignored by a gitignore rule. Run: git check-ignore -v {s}\n", .{ sync.enc_dir, sync.enc_dir });
        return error.InvalidArguments;
    }

    try sync.checkSameFilesystem(&repo);
    if (!repo.hasKey()) {
        const key = if (flags.key) |key_file| try readKeyFile(allocator, key_file, io) else keygen.generate(io);
        try repo.saveKey(key);
    }
    const keys = try loadKeys(&repo);

    try setupStore(&repo);
    try installIntegration(&repo);

    var report = sync.Report{};
    defer report.deinit(allocator);
    sync.encryptSync(&repo, keys, .{}, &report) catch |err| return failSync(&report, err);

    std.debug.print(
        \\Private files are set up.
        \\
        \\  Key   : {s}
        \\  Store : {s}/ (staged, commit it)
        \\  List  : {s} (private, edit it or use turbocrypt git add)
        \\
        \\Next steps:
        \\  turbocrypt git add <file-or-directory>
        \\  git commit
        \\  turbocrypt git export-key --password team.key   # to share the key
        \\
    , .{ repo.key_path, sync.enc_dir, manifest_mod.manifest_name });
}

/// The caller holds the repository lock.
fn unlockWith(repo: *const Repo, key_file: []const u8, force: bool) !void {
    const allocator = repo.allocator;
    if (!sync.storeExists(repo)) {
        std.debug.print("Error: no {s}/ store in this repository. Run: turbocrypt git init\n", .{sync.enc_dir});
        return error.InvalidArguments;
    }
    try sync.checkSameFilesystem(repo);
    const key = try readKeyFile(allocator, key_file, repo.io);
    if (repo.hasKey()) {
        const existing = try repo.loadKey();
        if (!std.mem.eql(u8, &existing, &key) and !force) {
            std.debug.print("Error: this repository already has a different key. Use --force to replace it\n", .{});
            return error.InvalidArguments;
        }
    }
    const keys = crypto.deriveKeys(key, null);
    const manifest_text = sync.manifestFromStore(repo, keys) catch |err| {
        explainSyncError(err);
        return err;
    };
    if (manifest_text) |text| allocator.free(text) else {
        std.debug.print("Error: the store has no manifest entry for this key: wrong key\n", .{});
        return sync.Error.WrongKey;
    }

    try repo.saveKey(key);
    try installIntegration(repo);
    try decryptAll(repo, force);
    std.debug.print("Unlocked. Hooks are installed and private files are in place.\n", .{});
}

fn decryptAll(repo: *const Repo, force: bool) !void {
    const allocator = repo.allocator;
    const keys = try loadKeys(repo);

    var report = sync.Report{};
    defer report.deinit(allocator);
    sync.decryptSync(repo, keys, .{ .force = force }, &report) catch |err| return failSync(&report, err);
    printReport(&report);
}

fn cmdUnlock(args: []const []const u8, allocator: std.mem.Allocator, io: std.Io, environ_map: *const std.process.Environ.Map) !void {
    const flags = try parseFlags(args, allocator);
    defer allocator.free(flags.positional);
    if (flags.positional.len != 1) {
        std.debug.print("Usage: turbocrypt git unlock <key-file> [--force]\n", .{});
        return error.InvalidArguments;
    }
    var repo = try openRepo(allocator, io, environ_map);
    defer repo.deinit();
    const lock = try repo.lock();
    defer lock.release();
    try unlockWith(&repo, flags.positional[0], flags.force);
}

fn cmdExportKey(args: []const []const u8, allocator: std.mem.Allocator, io: std.Io, environ_map: *const std.process.Environ.Map) !void {
    const flags = try parseFlags(args, allocator);
    defer allocator.free(flags.positional);
    if (flags.positional.len != 1) {
        std.debug.print("Usage: turbocrypt git export-key <out-file> [--password]\n", .{});
        return error.InvalidArguments;
    }
    var repo = try openRepo(allocator, io, environ_map);
    defer repo.deinit();
    const key = repo.loadKey() catch |err| {
        std.debug.print("Error: this repository has no key\n", .{});
        return err;
    };

    var password: ?[]u8 = null;
    defer if (password) |pw| {
        std.crypto.secureZero(u8, pw);
        allocator.free(pw);
    };
    if (flags.password) password = try prompt.promptPassword(allocator, "Password for the exported key: ", true, io);

    try keygen.writeKeyFile(flags.positional[0], key, password, io);
    std.debug.print("Key written to {s}{s}\n", .{ flags.positional[0], if (password != null) " (password protected)" else "" });
}

fn loadPlainManifest(repo: *const Repo) !Manifest {
    return (try sync.readPlainManifest(repo)) orelse {
        std.debug.print("Error: no {s} in the working tree. Run: turbocrypt git decrypt\n", .{manifest_mod.manifest_name});
        return sync.Error.NoManifest;
    };
}

fn savePlainManifest(repo: *const Repo, manifest: Manifest) !void {
    const allocator = repo.allocator;
    const path = try repo.absolutePath(manifest_mod.manifest_name);
    defer allocator.free(path);
    const text = try manifest.render(allocator);
    defer allocator.free(text);
    try processor.writeFileAtomic(path, text, null, repo.tmp_dir, allocator, repo.io);
}

/// Tracked files at or under a manifest entry, as git sees them.
fn trackedUnder(repo: *const Repo, entry: manifest_mod.Entry) ![][]u8 {
    const all = try repo.lsFilesZ(&.{ "--cached", "--", entry.path });
    defer utils.freeList(repo.allocator, all);

    var list: std.ArrayList([]u8) = .empty;
    errdefer {
        for (list.items) |item| repo.allocator.free(item);
        list.deinit(repo.allocator);
    }
    for (all) |path| {
        if (entry.covers(path)) try list.append(repo.allocator, try repo.allocator.dupe(u8, path));
    }
    return list.toOwnedSlice(repo.allocator);
}

fn cmdAdd(args: []const []const u8, allocator: std.mem.Allocator, io: std.Io, environ_map: *const std.process.Environ.Map) !void {
    const flags = try parseFlags(args, allocator);
    defer allocator.free(flags.positional);
    if (flags.positional.len == 0) {
        std.debug.print("Usage: turbocrypt git add <path>...\n", .{});
        return error.InvalidArguments;
    }
    var repo = try openRepo(allocator, io, environ_map);
    defer repo.deinit();
    const keys = try loadKeys(&repo);
    const lock = try repo.lock();
    defer lock.release();

    var manifest = try loadPlainManifest(&repo);
    defer manifest.deinit(allocator);

    var lines: std.ArrayList([]u8) = .empty;
    defer {
        for (lines.items) |line| allocator.free(line);
        lines.deinit(allocator);
    }
    var refused = false;
    for (flags.positional) |raw_arg| {
        const arg = try repo.canonicalArg(raw_arg);
        defer allocator.free(arg);
        const line = manifest_mod.normalizeUserPath(allocator, repo.toplevel, repo.prefix, arg, io) catch |err| {
            switch (err) {
                manifest_mod.Error.OutsideRepository => std.debug.print("Error: {s} is outside the repository\n", .{arg}),
                manifest_mod.Error.ReservedPath => std.debug.print("Error: {s} must stay tracked in clear for git to work\n", .{arg}),
                manifest_mod.Error.UnsupportedLine => std.debug.print("Error: {s} contains characters that gitignore would misread\n", .{arg}),
                error.IsSymlink => std.debug.print("Error: {s} is a symbolic link\n", .{arg}),
                error.FileNotFound => std.debug.print("Error: {s} does not exist\n", .{arg}),
                else => std.debug.print("Error: {s}: {}\n", .{ arg, err }),
            }
            return err;
        };
        errdefer allocator.free(line);

        const entry = manifest_mod.parseLine(line).?;
        if (!entry.is_dir) try checkAddable(&repo, keys, entry.path);

        const tracked = try trackedUnder(&repo, entry);
        defer utils.freeList(allocator, tracked);
        for (tracked) |path| {
            std.debug.print("Error: {s} is tracked by git. Run: git rm --cached -- '{s}'\n       Earlier commits still contain it in clear.\n", .{ path, path });
            refused = true;
        }
        try lines.append(allocator, line);
    }
    if (refused) return error.PrivateFileTracked;

    var added: usize = 0;
    for (lines.items) |line| {
        if (try manifest.append(allocator, line)) {
            added += 1;
        } else {
            std.debug.print("Already private: {s}\n", .{line});
        }
    }

    try sync.updateExcludeFile(&repo, &.{&manifest}, &.{}, &.{});
    if (added > 0) try savePlainManifest(&repo, manifest);

    var report = sync.Report{};
    defer report.deinit(allocator);
    sync.encryptSync(&repo, keys, .{}, &report) catch |err| return failSync(&report, err);
    printReport(&report);
    std.debug.print("{d} entr{s} added, {d} file(s) encrypted and staged\n", .{ added, if (added == 1) "y" else "ies", report.count(.encrypted) });
}

/// A file that the sync would only report as bad is refused up front, so the manifest never gains a line that cannot be honored.
fn checkAddable(repo: *const Repo, keys: crypto.DerivedKeys, plain: []const u8) !void {
    const allocator = repo.allocator;
    const abs = try repo.absolutePath(plain);
    defer allocator.free(abs);
    const stat = try std.Io.Dir.statFile(.cwd(), repo.io, abs, .{ .follow_symlinks = false });
    if (stat.size > sync.max_file_size) {
        std.debug.print("Error: {s} is larger than 256 MiB\n", .{plain});
        return sync.Error.FileTooLarge;
    }
    const cipher_rel = filename_crypto.encryptPath(allocator, plain, keys.filename_key) catch |err| {
        std.debug.print("Error: {s} has a name that is too long once encrypted, keep components under about 200 bytes\n", .{plain});
        return err;
    };
    allocator.free(cipher_rel);
}

fn cmdRm(args: []const []const u8, allocator: std.mem.Allocator, io: std.Io, environ_map: *const std.process.Environ.Map) !void {
    const flags = try parseFlags(args, allocator);
    defer allocator.free(flags.positional);
    if (flags.positional.len == 0) {
        std.debug.print("Usage: turbocrypt git rm <path>...\n", .{});
        return error.InvalidArguments;
    }
    var repo = try openRepo(allocator, io, environ_map);
    defer repo.deinit();
    const keys = try loadKeys(&repo);
    const lock = try repo.lock();
    defer lock.release();

    var manifest = try loadPlainManifest(&repo);
    defer manifest.deinit(allocator);

    const store_entries = try sync.storeEntries(&repo, keys);
    defer sync.freeEntries(allocator, store_entries);

    var removed_lines: std.ArrayList([]u8) = .empty;
    defer {
        for (removed_lines.items) |line| allocator.free(line);
        removed_lines.deinit(allocator);
    }
    var forget: std.ArrayList(sync.Entry) = .empty;
    defer forget.deinit(allocator);

    for (flags.positional) |raw_arg| {
        const arg = try repo.canonicalArg(raw_arg);
        defer allocator.free(arg);
        const line = try lineForArg(&repo, &manifest, arg);
        defer allocator.free(line);
        const entry = manifest_mod.parseLine(line) orelse {
            std.debug.print("Error: {s} is not a valid path\n", .{arg});
            return error.InvalidArguments;
        };
        if (manifest.remove(allocator, line)) {
            try removed_lines.append(allocator, try allocator.dupe(u8, line));
            for (store_entries) |store_entry| {
                if (entry.covers(store_entry.plain) and manifest.covering(store_entry.plain) == null) try forget.append(allocator, store_entry);
            }
        } else if (manifest.covering(entry.path)) |cover| {
            std.debug.print("{s} stays private through {s}. Move it out of that directory, or remove the directory line.\n", .{ arg, cover });
        } else {
            std.debug.print("{s} was not private\n", .{arg});
        }
    }

    try sync.removeEntries(&repo, forget.items);
    try savePlainManifest(&repo, manifest);

    var report = sync.Report{};
    defer report.deinit(allocator);
    sync.encryptSync(&repo, keys, .{}, &report) catch |err| return failSync(&report, err);

    var removed_entries: std.ArrayList(manifest_mod.Entry) = .empty;
    defer removed_entries.deinit(allocator);
    for (removed_lines.items) |line| {
        if (manifest_mod.parseLine(line)) |entry| try removed_entries.append(allocator, entry);
    }
    const covered_lines = try sync.excludeLinesCoveredBy(&repo, removed_entries.items, &manifest);
    defer utils.freeList(allocator, covered_lines);

    var remove_from_block: std.ArrayList([]const u8) = .empty;
    defer remove_from_block.deinit(allocator);
    for (removed_lines.items) |line| try remove_from_block.append(allocator, line);
    for (covered_lines) |line| try remove_from_block.append(allocator, line);
    try sync.updateExcludeFile(&repo, &.{&manifest}, &.{}, remove_from_block.items);
    for (forget.items) |entry| {
        std.debug.print("  public     {s}  (still on disk, now an ordinary untracked file)\n", .{entry.plain});
    }
    std.debug.print("{d} entr{s} removed from {s}\n", .{ removed_lines.items.len, if (removed_lines.items.len == 1) "y" else "ies", manifest_mod.manifest_name });
}

/// The manifest line for an rm argument.
/// The path may be gone from the disk already, so the file and directory forms are both tried.
fn lineForArg(repo: *const Repo, manifest: *const Manifest, arg: []const u8) ![]u8 {
    const allocator = repo.allocator;
    if (manifest_mod.normalizeUserPath(allocator, repo.toplevel, repo.prefix, arg, repo.io)) |line| {
        return line;
    } else |err| switch (err) {
        error.FileNotFound => {},
        else => return err,
    }
    const relative = try manifest_mod.relativeToToplevel(allocator, repo.toplevel, repo.prefix, arg);
    defer allocator.free(relative);
    const as_dir = try std.fmt.allocPrint(allocator, "/{s}/", .{relative});
    if (manifest.contains(as_dir)) return as_dir;
    allocator.free(as_dir);
    return std.fmt.allocPrint(allocator, "/{s}", .{relative});
}

fn cmdStatus(args: []const []const u8, allocator: std.mem.Allocator, io: std.Io, environ_map: *const std.process.Environ.Map) !void {
    const flags = try parseFlags(args, allocator);
    defer allocator.free(flags.positional);

    var repo = try openRepo(allocator, io, environ_map);
    defer repo.deinit();

    std.debug.print("Repository : {s}\n", .{repo.toplevel});
    if (!sync.storeExists(&repo)) {
        std.debug.print("Store      : none, run turbocrypt git init\n", .{});
        return;
    }
    if (!repo.hasKey()) {
        std.debug.print("Key        : locked, run turbocrypt git unlock <key-file>\n", .{});
        return;
    }
    std.debug.print("Key        : unlocked ({s})\n", .{repo.key_path});

    const which = try hooks.installed(&repo);
    const missing = std.mem.count(bool, &which, &.{false});
    if (missing == 0) {
        std.debug.print("Hooks      : installed\n", .{});
    } else {
        std.debug.print("Hooks      : {d} missing, run turbocrypt git init\n", .{missing});
    }

    const keys = try loadKeys(&repo);
    var report = sync.Report{};
    defer report.deinit(allocator);
    sync.collectStatus(&repo, keys, &report) catch |err| return failSync(&report, err);

    std.debug.print("\n", .{});
    printReport(&report);
    std.debug.print("\n", .{});
    var first = true;
    for (std.meta.tags(sync.Row.Kind)) |kind| {
        const n = report.count(kind);
        if (n > 0) {
            std.debug.print("{s}{d} {t}", .{ if (first) "" else ", ", n, kind });
            first = false;
        }
    }
    std.debug.print("{s}\n", .{if (first) "no private files" else ""});

    if (report.count(.tracked) > 0 or report.count(.conflict) > 0 or report.count(.bad) > 0) {
        std.process.exit(1);
    }
}

/// The encrypt and decrypt commands: one pass in the given direction, limited to the paths given as arguments.
fn cmdSync(direction: sync.Direction, args: []const []const u8, allocator: std.mem.Allocator, io: std.Io, environ_map: *const std.process.Environ.Map) !void {
    const flags = try parseFlags(args, allocator);
    defer allocator.free(flags.positional);
    var repo = try openRepo(allocator, io, environ_map);
    defer repo.deinit();
    const keys = try loadKeys(&repo);

    const only = try relativePaths(&repo, flags.positional);
    defer utils.freeList(allocator, only);

    const lock = try repo.lock();
    defer lock.release();

    var report = sync.Report{};
    defer report.deinit(allocator);
    const options = sync.Options{ .force = flags.force, .only = only };
    switch (direction) {
        .encrypt => sync.encryptSync(&repo, keys, options, &report) catch |err| return failSync(&report, err),
        .decrypt => sync.decryptSync(&repo, keys, options, &report) catch |err| return failSync(&report, err),
    }
    printReport(&report);
    switch (direction) {
        .encrypt => std.debug.print("{d} encrypted, {d} unchanged\n", .{ report.count(.encrypted), report.count(.ok) }),
        .decrypt => std.debug.print("{d} written, {d} deleted, {d} unchanged\n", .{ report.count(.written), report.count(.deleted), report.count(.ok) }),
    }
}

/// Turn user arguments into top-level relative paths, whether or not the files exist.
fn relativePaths(repo: *Repo, args: []const []const u8) ![][]u8 {
    const allocator = repo.allocator;
    var list: std.ArrayList([]u8) = .empty;
    errdefer {
        for (list.items) |item| allocator.free(item);
        list.deinit(allocator);
    }
    for (args) |raw_arg| {
        const arg = try repo.canonicalArg(raw_arg);
        defer allocator.free(arg);
        const relative = manifest_mod.relativeToToplevel(allocator, repo.toplevel, repo.prefix, arg) catch |err| {
            if (err == manifest_mod.Error.OutsideRepository) std.debug.print("Error: {s} is outside the repository\n", .{arg});
            return err;
        };
        errdefer allocator.free(relative);
        try list.append(allocator, relative);
    }
    return list.toOwnedSlice(allocator);
}
