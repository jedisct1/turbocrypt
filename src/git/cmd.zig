//! Implements the `turbocrypt git` command-line interface.

const std = @import("std");
const builtin = @import("builtin");
const mem = std.mem;
const Allocator = std.mem.Allocator;
const Io = std.Io;

const crypto = @import("../crypto.zig");
const filename_crypto = @import("../filename_crypto.zig");
const keygen = @import("../keygen.zig");
const key_loader = @import("../key_loader.zig");
const prompt = @import("../prompt.zig");
const processor = @import("../processor.zig");
const fs = @import("../fs.zig");
const git = @import("../git.zig");
const Repo = @import("Repo.zig");
const Manifest = @import("Manifest.zig");
const sync = @import("sync.zig");
const hooks = @import("hooks.zig");

pub const usage_text =
    \\Usage: turbocrypt git <subcommand> [options]
    \\
    \\Keep private files in a public git repository. They live encrypted
    \\under .enc/ and appear in clear in your working tree.
    \\
    \\  init [--key <key-file>]        Set up this repository for a key: hooks, .enc/ and .gitprivate
    \\  unlock [--key <key-file>]      Set up a clone: hooks and the plain files from .enc/
    \\  export-key <out> [--password]  Write the repository key to a file to share it
    \\  add <path>...                  Make files or directories private
    \\  rm <path>...                   Make files or directories public again
    \\  status                         Show private files and what is out of sync
    \\  show <path>...                 Show where a file lives in .enc/ and its last commit
    \\  encrypt [--force] [<path>...]  Refresh .enc/ from the plain files and stage it
    \\  decrypt [--force] [<path>...]  Refresh the plain files from .enc/
    \\
    \\init and unlock take the key from --key, then TURBOCRYPT_KEY_FILE, then
    \\the config, like every other command, and ask for its password once.
    \\--password forces that prompt. The repository keeps the key it was
    \\given. --force replaces it with a different one.
    \\
    \\Several keys can share a repository. Each one sees its own files and
    \\ignores the others. A key that has no files yet joins with init.
    \\unlock refuses such a key, since it is more likely a wrong one.
    \\
    \\Examples:
    \\  turbocrypt keygen secret.key
    \\  turbocrypt config set-key secret.key
    \\  turbocrypt git init
    \\  turbocrypt git add INTERNAL-DOC.md docs/internal.md ops/
    \\  git commit -m "Add private notes"
    \\  turbocrypt git export-key --password team.key
    \\  turbocrypt git unlock --key team.key
    \\
;

const Flags = struct {
    force: bool = false,
    password: bool = false,
    key: ?[]const u8 = null,
    positional: []const []const u8,
};

/// Lists the options a subcommand accepts.
/// Reject unknown options so a misspelling never changes behavior silently.
const Accepted = struct {
    force: bool = false,
    password: bool = false,
    key: bool = false,
};

fn parseFlags(gpa: Allocator, args: []const []const u8, accepted: Accepted) !Flags {
    var flags: Flags = .{ .positional = &.{} };
    var positional: std.ArrayList([]const u8) = .empty;
    errdefer positional.deinit(gpa);

    var i: usize = 0;
    var literal = false;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (literal or !mem.startsWith(u8, arg, "--")) {
            try positional.append(gpa, arg);
        } else if (mem.eql(u8, arg, "--")) {
            literal = true;
        } else if (accepted.force and mem.eql(u8, arg, "--force")) {
            flags.force = true;
        } else if (accepted.password and mem.eql(u8, arg, "--password")) {
            flags.password = true;
        } else if (mem.eql(u8, arg, "--key")) {
            if (!accepted.key) {
                std.debug.print("Error: --key is for init and unlock only. The other commands use the key bound to this repository\n", .{});
                return error.InvalidArguments;
            }
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
    flags.positional = try positional.toOwnedSlice(gpa);
    return flags;
}

pub fn run(
    gpa: Allocator,
    io: Io,
    environ_map: *const std.process.Environ.Map,
    args: []const []const u8,
) !void {
    if (args.len < 1 or mem.eql(u8, args[0], "help") or mem.eql(u8, args[0], "--help")) {
        std.debug.print("{s}", .{usage_text});
        if (args.len < 1) return error.InvalidArguments;
        return;
    }
    const sub = args[0];
    const rest = args[1..];

    if (mem.eql(u8, sub, "hook")) {
        if (rest.len < 1) {
            std.debug.print("Error: Missing hook name\n", .{});
            return error.InvalidArguments;
        }
        std.process.exit(hooks.run(gpa, io, environ_map, rest[0]));
    }

    if (mem.eql(u8, sub, "init")) return cmdInit(gpa, io, environ_map, rest);
    if (mem.eql(u8, sub, "unlock")) return cmdUnlock(gpa, io, environ_map, rest);
    if (mem.eql(u8, sub, "export-key")) return cmdExportKey(gpa, io, environ_map, rest);
    if (mem.eql(u8, sub, "add")) return cmdAdd(gpa, io, environ_map, rest);
    if (mem.eql(u8, sub, "rm")) return cmdRm(gpa, io, environ_map, rest);
    if (mem.eql(u8, sub, "status")) return cmdStatus(gpa, io, environ_map, rest);
    if (mem.eql(u8, sub, "show")) return cmdShow(gpa, io, environ_map, rest);
    if (mem.eql(u8, sub, "encrypt")) return cmdSync(gpa, io, environ_map, .encrypt, rest);
    if (mem.eql(u8, sub, "decrypt")) return cmdSync(gpa, io, environ_map, .decrypt, rest);

    std.debug.print("Error: Unknown git subcommand '{s}'\n\n{s}", .{ sub, usage_text });
    return error.InvalidArguments;
}

fn openRepo(gpa: Allocator, io: Io, environ_map: *const std.process.Environ.Map) !Repo {
    var repo = try Repo.open(gpa, io, environ_map);
    errdefer repo.deinit();
    if (repo.isLinkedWorktree()) {
        std.debug.print("Error: linked worktrees are not supported by turbocrypt git. Use the main working tree.\n", .{});
        return error.LinkedWorktree;
    }
    return repo;
}

/// Loads the key bound to this repository.
/// A missing key gets setup guidance, but an unreadable key is never replaced from another source.
/// That avoids silently using the wrong key.
fn loadRepoKey(repo: *const Repo) ![16]u8 {
    return repo.loadKey() catch |err| switch (err) {
        Repo.Error.RepositoryLocked => {
            std.debug.print("Error: this repository has no key yet. Run: turbocrypt git unlock\n", .{});
            return err;
        },
        else => {
            std.debug.print(
                "Error: cannot read the repository key {s}: {}\n",
                .{ repo.key_path, err },
            );
            return err;
        },
    };
}

fn loadKeys(repo: *const Repo) !crypto.DerivedKeys {
    return crypto.deriveKeys(try loadRepoKey(repo), null);
}

const Selected = struct {
    key: [16]u8,
    /// Describes where a replacement key came from.
    /// It is null when the repository's existing key remains in use.
    source: ?[]u8,
};

/// Chooses the key for `init` or `unlock`.
/// An existing repository key stays in place unless `--key` selects a different one.
/// Replacing it requires `--force` to prevent an accidental lockout.
/// Environment and configuration sources are considered only before a key is bound.
fn selectKey(repo: *const Repo, flags: Flags) !Selected {
    const gpa = repo.gpa;
    const bound: ?[16]u8 = repo.loadKey() catch |err| switch (err) {
        Repo.Error.RepositoryLocked => null,
        else => {
            std.debug.print(
                "Error: cannot read the repository key {s}: {}\n",
                .{ repo.key_path, err },
            );
            return err;
        },
    };
    if (bound != null and flags.key == null) return .{ .key = bound.?, .source = null };

    const key = key_loader.load(
        gpa,
        repo.io,
        repo.environ_map,
        flags.key,
        flags.password,
    ) catch |err| {
        return key_loader.explainLoadError(gpa, repo.environ_map, err, flags.key);
    };
    if (bound) |current| {
        if (mem.eql(u8, &current, &key)) return .{ .key = key, .source = null };
        if (!flags.force) {
            std.debug.print("Error: this repository already has a different key. Add --force to replace it\n", .{});
            return error.InvalidArguments;
        }
    }
    const source = try key_loader.describeSource(gpa, repo.environ_map, flags.key);
    return .{ .key = key, .source = source };
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

fn failSync(report: *const sync.Report, err: anyerror) anyerror {
    printReport(report);
    explainSyncError(err);
    return err;
}

fn explainSyncError(err: anyerror) void {
    switch (err) {
        sync.Error.PrivateFileTracked => std.debug.print("Error: private files are tracked by git, see the lines above\n", .{}),
        sync.Error.SyncAborted => std.debug.print("Error: nothing was changed, see the lines above\n", .{}),
        sync.Error.NoManifest => std.debug.print("Error: no {s} found. Run turbocrypt git init in a new repository, or unlock in a clone\n", .{Manifest.filename}),
        sync.Error.WrongKey => std.debug.print("Error: the {s} entry of this key in {s}/ does not decrypt: the store is corrupted\n", .{ Manifest.filename, sync.enc_dir }),
        error.CrossDevice => std.debug.print("Error: the git directory and the working tree must be on the same filesystem\n", .{}),
        Repo.Error.Locked => {},
        else => std.debug.print("Error: {}\n", .{err}),
    }
}

/// Creates and stages the store files Git needs to recognize and preserve the encrypted store.
/// An existing README is left alone so users can customize it.
pub fn writeStoreFiles(repo: *const Repo) !void {
    const gpa = repo.gpa;
    const store = try repo.absolutePath(sync.enc_dir);
    defer gpa.free(store);
    try fs.ensureDir(repo.io, store);

    const marker = try Io.Dir.path.join(gpa, &.{ store, sync.marker_name });
    defer gpa.free(marker);
    try processor.writeFileAtomic(gpa, repo.io, marker, sync.marker_text, null, null);

    const attributes = try Io.Dir.path.join(gpa, &.{ store, sync.attributes_name });
    defer gpa.free(attributes);
    // Refresh generated attributes during setup so Git never transforms ciphertext.
    try processor.writeFileAtomic(gpa, repo.io, attributes, sync.attributes_text, null, null);

    const rel_marker = sync.enc_dir ++ "/" ++ sync.marker_name;
    const rel_attributes = sync.enc_dir ++ "/" ++ sync.attributes_name;
    try repo.addForce(&.{ rel_marker, rel_attributes });

    const rel_readme = sync.enc_dir ++ "/" ++ sync.readme_name;
    const readme = try repo.absolutePath(rel_readme);
    defer gpa.free(readme);
    Io.Dir.writeFile(.cwd(), repo.io, .{
        .sub_path = readme,
        .data = sync.readme_text,
        .flags = .{ .exclusive = true },
    }) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };
    const tracked = try repo.lsFilesNul(&.{ "--", rel_readme });
    defer git.freeList(gpa, tracked);
    if (tracked.len == 0) try repo.addForce(&.{rel_readme});
}

/// Sets up the exclude block, manifest, and store files for a new repository.
/// Update exclusions first so the manifest is never briefly visible to Git.
pub fn setupStore(repo: *const Repo) !void {
    const gpa = repo.gpa;
    try repo.ensureDirs();
    try sync.updateExcludeFile(repo, &.{}, &.{}, &.{});

    const manifest_path = try repo.absolutePath(Manifest.filename);
    defer gpa.free(manifest_path);
    if (!fs.pathExists(repo.io, manifest_path)) {
        try processor.writeFileAtomic(
            gpa,
            repo.io,
            manifest_path,
            Manifest.default_text,
            sync.plain_file_permissions,
            repo.tmp_dir,
        );
    }
    try writeStoreFiles(repo);
}

fn installIntegration(repo: *const Repo) !void {
    const exe_path = try std.process.executablePathAlloc(repo.io, repo.gpa);
    defer repo.gpa.free(exe_path);
    // Use forward slashes because `sh` can reliably read Windows paths that way.
    if (builtin.os.tag == .windows) {
        mem.replaceScalar(u8, exe_path, Io.Dir.path.sep_windows, Io.Dir.path.sep_posix);
    }
    try repo.configSetLocal("turbocrypt.path", exe_path);
    try hooks.install(repo, exe_path);
}

fn cmdInit(
    gpa: Allocator,
    io: Io,
    environ_map: *const std.process.Environ.Map,
    args: []const []const u8,
) !void {
    const flags = try parseFlags(gpa, args, .{ .key = true, .password = true, .force = true });
    defer gpa.free(flags.positional);
    if (flags.positional.len != 0) {
        std.debug.print("Usage: turbocrypt git init [--key <key-file>] [--password] [--force]\n", .{});
        return error.InvalidArguments;
    }

    var repo = try openRepo(gpa, io, environ_map);
    defer repo.deinit();
    const lock = try repo.lock();
    defer lock.release();

    if (!sync.storeExists(&repo)) try checkStoreLocation(&repo);
    try setup(&repo, flags, .init);
}

/// Allows a new store only where it will be visible to Git and cannot overwrite other data.
fn checkStoreLocation(repo: *const Repo) !void {
    const gpa = repo.gpa;
    const io = repo.io;
    const store = try repo.absolutePath(sync.enc_dir);
    defer gpa.free(store);
    if (Io.Dir.statFile(.cwd(), io, store, .{ .follow_symlinks = false })) |stat| {
        if (stat.kind != .directory) {
            std.debug.print("Error: {s} exists and is not a directory\n", .{sync.enc_dir});
            return error.InvalidArguments;
        }
        var dir = try Io.Dir.openDir(.cwd(), io, store, .{ .iterate = true });
        defer dir.close(io);
        var it = dir.iterate();
        if (try it.next(io) != null) {
            std.debug.print(
                "Error: {s}/ exists, is not empty and is not a turbocrypt store\n",
                .{sync.enc_dir},
            );
            return error.InvalidArguments;
        }
    } else |err| switch (err) {
        error.FileNotFound => {},
        else => return err,
    }
    if (try repo.checkIgnore(sync.enc_dir)) {
        std.debug.print(
            "Error: {s}/ is ignored by a gitignore rule. Run: git check-ignore -v {s}\n",
            .{ sync.enc_dir, sync.enc_dir },
        );
        return error.InvalidArguments;
    }
}

const Command = enum { init, unlock };

/// Performs the shared setup after `init` or `unlock` has the repository lock.
/// `unlock` rejects an empty key namespace because it is indistinguishable from a wrong key.
fn setup(repo: *const Repo, flags: Flags, command: Command) !void {
    const gpa = repo.gpa;
    const selected = try selectKey(repo, flags);
    defer if (selected.source) |source| gpa.free(source);
    try sync.checkSameFilesystem(repo);
    const keys = crypto.deriveKeys(selected.key, null);

    const manifest_text = sync.manifestFromStore(repo, keys) catch |err| {
        explainSyncError(err);
        return err;
    };
    const has_files = manifest_text != null;
    if (manifest_text) |text| gpa.free(text);

    if (!has_files and command == .unlock) {
        const what: []const u8 = selected.source orelse "the repository key";
        std.debug.print("Error: the store has no files for {s}: wrong key, or a key that is new to this repository\n", .{what});
        std.debug.print("A new key joins with: turbocrypt git init [--key <key-file>]\n", .{});
        return error.InvalidArguments;
    }

    if (selected.source != null) try repo.saveKey(selected.key);
    const key_line = if (selected.source) |source|
        try gpa.print("{s}, copied to {s}", .{ source, repo.key_path })
    else
        try gpa.dupe(u8, repo.key_path);
    defer gpa.free(key_line);

    if (has_files) {
        if (selected.source != null) std.debug.print("Key: {s}\n", .{key_line});
        try installIntegration(repo);
        try decryptAll(repo, keys, flags.force);
        if (command == .init) try writeStoreFiles(repo);
        const outcome: []const u8 = if (selected.source == null) "Refreshed" else "Unlocked";
        std.debug.print("{s}. Hooks are installed and private files are in place.\n", .{outcome});
        return;
    }

    try setupStore(repo);
    try installIntegration(repo);

    var report: sync.Report = .{};
    defer report.deinit(gpa);
    sync.encrypt(repo, keys, .{}, &report) catch |err| return failSync(&report, err);

    const others = try sync.otherKeyCount(repo, keys);
    if (others > 0) {
        std.debug.print("This key is new to the repository. The files of the {d} other key(s) stay encrypted.\n\n", .{others});
    }
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
    , .{ key_line, sync.enc_dir, Manifest.filename });
}

fn decryptAll(repo: *const Repo, keys: crypto.DerivedKeys, force: bool) !void {
    const gpa = repo.gpa;
    var report: sync.Report = .{};
    defer report.deinit(gpa);
    sync.decrypt(repo, keys, .{ .force = force }, &report) catch |err| return failSync(&report, err);
    printReport(&report);
}

fn cmdUnlock(
    gpa: Allocator,
    io: Io,
    environ_map: *const std.process.Environ.Map,
    args: []const []const u8,
) !void {
    const flags = try parseFlags(gpa, args, .{ .key = true, .password = true, .force = true });
    defer gpa.free(flags.positional);
    if (flags.positional.len != 0) {
        std.debug.print("Usage: turbocrypt git unlock [--key <key-file>] [--password] [--force]\n", .{});
        return error.InvalidArguments;
    }
    var repo = try openRepo(gpa, io, environ_map);
    defer repo.deinit();
    const lock = try repo.lock();
    defer lock.release();
    if (!sync.storeExists(&repo)) {
        std.debug.print(
            "Error: no {s}/ store in this repository. Run: turbocrypt git init\n",
            .{sync.enc_dir},
        );
        return error.InvalidArguments;
    }
    try setup(&repo, flags, .unlock);
}

fn cmdExportKey(
    gpa: Allocator,
    io: Io,
    environ_map: *const std.process.Environ.Map,
    args: []const []const u8,
) !void {
    const flags = try parseFlags(gpa, args, .{ .password = true });
    defer gpa.free(flags.positional);
    if (flags.positional.len != 1) {
        std.debug.print("Usage: turbocrypt git export-key <out-file> [--password]\n", .{});
        return error.InvalidArguments;
    }
    var repo = try openRepo(gpa, io, environ_map);
    defer repo.deinit();
    const key = try loadRepoKey(&repo);

    var password: ?[]u8 = null;
    defer if (password) |pw| {
        std.crypto.secureZero(u8, pw);
        gpa.free(pw);
    };
    if (flags.password) {
        password = try prompt.password(gpa, io, "Password for the exported key: ", true);
    }

    try keygen.writeKeyFile(gpa, io, flags.positional[0], key, password);
    std.debug.print("Key written to {s}{s}\n", .{
        flags.positional[0],
        if (password != null) " (password protected)" else "",
    });
}

fn loadPlainManifest(repo: *const Repo) !Manifest {
    return (try sync.readPlainManifest(repo)) orelse {
        std.debug.print(
            "Error: no {s} in the working tree. Run: turbocrypt git decrypt\n",
            .{Manifest.filename},
        );
        return sync.Error.NoManifest;
    };
}

fn savePlainManifest(repo: *const Repo, manifest: Manifest) !void {
    const gpa = repo.gpa;
    const path = try repo.absolutePath(Manifest.filename);
    defer gpa.free(path);
    const text = try manifest.render(gpa);
    defer gpa.free(text);
    try processor.writeFileAtomic(gpa, repo.io, path, text, null, repo.tmp_dir);
}

/// Lists index entries under a manifest path as Git sees them.
fn trackedUnder(repo: *const Repo, entry: Manifest.Entry) ![][]u8 {
    const gpa = repo.gpa;
    const all = try repo.lsFilesNul(&.{ "--cached", "--", entry.path });
    defer git.freeList(gpa, all);

    var list: std.ArrayList([]u8) = .empty;
    errdefer {
        for (list.items) |item| gpa.free(item);
        list.deinit(gpa);
    }
    for (all) |path| {
        if (entry.covers(path)) try list.append(gpa, try gpa.dupe(u8, path));
    }
    return list.toOwnedSlice(gpa);
}

fn cmdAdd(
    gpa: Allocator,
    io: Io,
    environ_map: *const std.process.Environ.Map,
    args: []const []const u8,
) !void {
    const flags = try parseFlags(gpa, args, .{});
    defer gpa.free(flags.positional);
    if (flags.positional.len == 0) {
        std.debug.print("Usage: turbocrypt git add <path>...\n", .{});
        return error.InvalidArguments;
    }
    var repo = try openRepo(gpa, io, environ_map);
    defer repo.deinit();
    const keys = try loadKeys(&repo);
    const lock = try repo.lock();
    defer lock.release();

    var manifest = try loadPlainManifest(&repo);
    defer manifest.deinit(gpa);

    var lines: std.ArrayList([]u8) = .empty;
    defer {
        for (lines.items) |line| gpa.free(line);
        lines.deinit(gpa);
    }
    var refused = false;
    for (flags.positional) |raw_arg| {
        const arg = try repo.canonicalArg(raw_arg);
        defer gpa.free(arg);
        const line = Manifest.normalizeUserPath(
            gpa,
            io,
            repo.toplevel,
            repo.prefix,
            arg,
        ) catch |err| {
            switch (err) {
                Manifest.Error.OutsideRepository => std.debug.print("Error: {s} is outside the repository\n", .{arg}),
                Manifest.Error.ReservedPath => std.debug.print("Error: {s} must stay tracked in clear for git to work\n", .{arg}),
                Manifest.Error.UnsupportedLine => std.debug.print("Error: {s} contains characters that gitignore would misread\n", .{arg}),
                error.IsSymlink => std.debug.print("Error: {s} is a symbolic link\n", .{arg}),
                error.FileNotFound => std.debug.print("Error: {s} does not exist\n", .{arg}),
                else => std.debug.print("Error: {s}: {}\n", .{ arg, err }),
            }
            return err;
        };
        errdefer gpa.free(line);

        const entry = Manifest.parseLine(line).?;
        if (!entry.is_dir) try checkAddable(&repo, keys, entry.path);

        const tracked = try trackedUnder(&repo, entry);
        defer git.freeList(gpa, tracked);
        for (tracked) |path| {
            std.debug.print("Error: {s} is tracked by git. Run: git rm --cached -- '{s}'\n       Earlier commits still contain it in clear.\n", .{ path, path });
            refused = true;
        }
        try lines.append(gpa, line);
    }
    if (refused) return error.PrivateFileTracked;

    var added: usize = 0;
    for (lines.items) |line| {
        if (try manifest.append(gpa, line)) {
            added += 1;
        } else {
            std.debug.print("Already private: {s}\n", .{line});
        }
    }

    try sync.updateExcludeFile(&repo, &.{&manifest}, &.{}, &.{});
    if (added > 0) try savePlainManifest(&repo, manifest);

    var report: sync.Report = .{};
    defer report.deinit(gpa);
    sync.encrypt(&repo, keys, .{}, &report) catch |err| return failSync(&report, err);
    printReport(&report);
    std.debug.print("{d} entr{s} added, {d} file(s) encrypted and staged\n", .{
        added,
        if (added == 1) "y" else "ies",
        report.count(.encrypted),
    });
}

/// Rejects files that synchronization could not safely encrypt.
/// This keeps unusable entries out of the manifest.
fn checkAddable(repo: *const Repo, keys: crypto.DerivedKeys, plain: []const u8) !void {
    const gpa = repo.gpa;
    const abs = try repo.absolutePath(plain);
    defer gpa.free(abs);
    const stat = try Io.Dir.statFile(.cwd(), repo.io, abs, .{ .follow_symlinks = false });
    if (stat.size > sync.max_file_size) {
        std.debug.print("Error: {s} is larger than 256 MiB\n", .{plain});
        return sync.Error.FileTooLarge;
    }
    if (!try sync.nameFits(gpa, keys, plain)) {
        std.debug.print("Error: {s}: {s}\n", .{ plain, sync.long_name_detail });
        return filename_crypto.Error.EncryptedFilenameTooLong;
    }
}

fn cmdRm(
    gpa: Allocator,
    io: Io,
    environ_map: *const std.process.Environ.Map,
    args: []const []const u8,
) !void {
    const flags = try parseFlags(gpa, args, .{});
    defer gpa.free(flags.positional);
    if (flags.positional.len == 0) {
        std.debug.print("Usage: turbocrypt git rm <path>...\n", .{});
        return error.InvalidArguments;
    }
    var repo = try openRepo(gpa, io, environ_map);
    defer repo.deinit();
    const keys = try loadKeys(&repo);
    const lock = try repo.lock();
    defer lock.release();

    var manifest = try loadPlainManifest(&repo);
    defer manifest.deinit(gpa);

    const store_entries = try sync.storeEntries(&repo, keys);
    defer sync.freeEntries(gpa, store_entries);

    var removed_lines: std.ArrayList([]u8) = .empty;
    defer {
        for (removed_lines.items) |line| gpa.free(line);
        removed_lines.deinit(gpa);
    }
    var forget: std.ArrayList(sync.Entry) = .empty;
    defer forget.deinit(gpa);

    for (flags.positional) |raw_arg| {
        const arg = try repo.canonicalArg(raw_arg);
        defer gpa.free(arg);
        const line = try lineForArg(&repo, &manifest, arg);
        defer gpa.free(line);
        const entry = Manifest.parseLine(line) orelse {
            std.debug.print("Error: {s} is not a valid path\n", .{arg});
            return error.InvalidArguments;
        };
        if (manifest.remove(gpa, line)) {
            try removed_lines.append(gpa, try gpa.dupe(u8, line));
            for (store_entries) |store_entry| {
                if (!entry.covers(store_entry.plain)) continue;
                if (manifest.covering(store_entry.plain) != null) continue;
                try forget.append(gpa, store_entry);
            }
        } else if (manifest.covering(entry.path)) |cover| {
            std.debug.print("{s} stays private through {s}. Move it out of that directory, or remove the directory line.\n", .{ arg, cover });
        } else {
            std.debug.print("{s} was not private\n", .{arg});
        }
    }

    try sync.removeEntries(&repo, keys, forget.items);
    try savePlainManifest(&repo, manifest);

    var report: sync.Report = .{};
    defer report.deinit(gpa);
    sync.encrypt(&repo, keys, .{}, &report) catch |err| return failSync(&report, err);

    var removed_entries: std.ArrayList(Manifest.Entry) = .empty;
    defer removed_entries.deinit(gpa);
    for (removed_lines.items) |line| {
        if (Manifest.parseLine(line)) |entry| try removed_entries.append(gpa, entry);
    }
    const covered_lines = try sync.excludeLinesCoveredBy(&repo, removed_entries.items, &manifest);
    defer git.freeList(gpa, covered_lines);

    var remove_from_block: std.ArrayList([]const u8) = .empty;
    defer remove_from_block.deinit(gpa);
    for (removed_lines.items) |line| try remove_from_block.append(gpa, line);
    for (covered_lines) |line| try remove_from_block.append(gpa, line);
    try sync.updateExcludeFile(&repo, &.{&manifest}, &.{}, remove_from_block.items);
    for (forget.items) |entry| {
        std.debug.print(
            "  public     {s}  (still on disk, now an ordinary untracked file)\n",
            .{entry.plain},
        );
    }
    std.debug.print("{d} entr{s} removed from {s}\n", .{
        removed_lines.items.len,
        if (removed_lines.items.len == 1) "y" else "ies",
        Manifest.filename,
    });
}

/// Finds the manifest line for an `rm` argument.
/// Missing paths still work because both file and directory forms are considered.
fn lineForArg(repo: *const Repo, manifest: *const Manifest, arg: []const u8) ![]u8 {
    const gpa = repo.gpa;
    if (Manifest.normalizeUserPath(gpa, repo.io, repo.toplevel, repo.prefix, arg)) |line| {
        return line;
    } else |err| switch (err) {
        error.FileNotFound => {},
        else => return err,
    }
    const relative = try Manifest.relativeToToplevel(gpa, repo.toplevel, repo.prefix, arg);
    defer gpa.free(relative);
    if (manifest.ownLine(relative)) |line| return gpa.dupe(u8, line);
    return gpa.print("/{s}", .{relative});
}

fn cmdStatus(
    gpa: Allocator,
    io: Io,
    environ_map: *const std.process.Environ.Map,
    args: []const []const u8,
) !void {
    const flags = try parseFlags(gpa, args, .{});
    defer gpa.free(flags.positional);
    if (flags.positional.len != 0) {
        std.debug.print("Usage: turbocrypt git status\n", .{});
        return error.InvalidArguments;
    }

    var repo = try openRepo(gpa, io, environ_map);
    defer repo.deinit();

    std.debug.print("Repository : {s}\n", .{repo.toplevel});
    if (!sync.storeExists(&repo)) {
        std.debug.print("Store      : none, run turbocrypt git init\n", .{});
        return;
    }
    const key = repo.loadKey() catch |err| switch (err) {
        Repo.Error.RepositoryLocked => {
            std.debug.print("Key        : locked, run turbocrypt git unlock\n", .{});
            return;
        },
        else => {
            std.debug.print(
                "Key        : cannot read the repository key {s}: {}\n",
                .{ repo.key_path, err },
            );
            return err;
        },
    };
    std.debug.print("Key        : unlocked ({s})\n", .{repo.key_path});

    const which = try hooks.installed(&repo);
    const missing = mem.count(bool, &which, &.{false});
    if (missing == 0) {
        std.debug.print("Hooks      : installed\n", .{});
    } else {
        std.debug.print("Hooks      : {d} missing, run turbocrypt git init\n", .{missing});
    }

    const keys = crypto.deriveKeys(key, null);
    const others = try sync.otherKeyCount(&repo, keys);
    if (others > 0) {
        std.debug.print("Other keys : {d}, their files stay encrypted\n", .{others});
    }

    var report: sync.Report = .{};
    defer report.deinit(gpa);
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

fn cmdShow(
    gpa: Allocator,
    io: Io,
    environ_map: *const std.process.Environ.Map,
    args: []const []const u8,
) !void {
    const flags = try parseFlags(gpa, args, .{});
    defer gpa.free(flags.positional);
    if (flags.positional.len == 0) {
        std.debug.print("Usage: turbocrypt git show <path>...\n", .{});
        return error.InvalidArguments;
    }
    var repo = try openRepo(gpa, io, environ_map);
    defer repo.deinit();
    const keys = try loadKeys(&repo);

    const paths = try relativePaths(&repo, flags.positional);
    defer git.freeList(gpa, paths);

    var ctx = sync.Context.init(&repo, keys) catch |err| {
        explainSyncError(err);
        return err;
    };
    defer ctx.deinit();

    for (paths, 0..) |plain, i| {
        if (i > 0) std.debug.print("\n", .{});
        try showPath(&ctx, plain);
    }
}

/// Shows a path's store location and the related Git state.
/// The store path is shown only when an entry exists on disk, in the index, or in history.
fn showPath(ctx: *const sync.Context, plain: []const u8) !void {
    const gpa = ctx.gpa;
    const abs = try ctx.repo.absolutePath(plain);
    defer gpa.free(abs);
    const on_disk = try diskKind(ctx.io, abs);
    const kind: []const u8 = if (on_disk) |k| switch (k) {
        .file => "file",
        .directory => "directory",
        .sym_link => "symbolic link",
        else => "special file",
    } else "not on disk";
    std.debug.print("Path       : {s} ({s})\n", .{ plain, kind });
    const private = printPrivate(ctx.manifest, plain);

    const cipher_rel = filename_crypto.encryptPath(
        gpa,
        plain,
        ctx.keys.filename_key,
        '/',
    ) catch |err| switch (err) {
        filename_crypto.Error.EncryptedFilenameTooLong => {
            std.debug.print("Entry      : none{s}\n", .{
                if (private) ", " ++ sync.long_name_detail else "",
            });
            return;
        },
        else => return err,
    };
    defer gpa.free(cipher_rel);
    const store_path = try sync.storePath(gpa, &ctx.store_rel, cipher_rel);
    defer gpa.free(store_path);
    const store_abs = try Io.Dir.path.join(gpa, &.{ ctx.store_abs, cipher_rel });
    defer gpa.free(store_abs);

    const entry = try diskKind(ctx.io, store_abs);
    const tracked = trackedAt(ctx, store_path);
    // Treat a failed log lookup as no history, just as in a repository with no commits.
    const log = try ctx.repo.run(&.{ "log", "-1", "--format=%h %cs %s", "--", store_path });
    defer log.deinit(gpa);
    const last = mem.trim(u8, log.stdout, " \r\n");

    if (entry == null and tracked == 0 and last.len == 0) {
        const pending = private and on_disk == .file;
        std.debug.print("Entry      : none{s}\n", .{
            if (pending) ", " ++ sync.pending_detail else "",
        });
        return;
    }
    std.debug.print("Store path : {s}\n", .{store_path});
    if (entry) |k| {
        switch (k) {
            .directory => std.debug.print("Entry      : directory, {d} tracked file(s)\n", .{
                tracked,
            }),
            else => std.debug.print("Entry      : on disk, {s}\n", .{
                if (tracked > 0) "tracked" else "not tracked",
            }),
        }
    } else {
        std.debug.print("Entry      : {s}\n", .{
            if (tracked > 0) "tracked, gone from disk" else "removed",
        });
    }
    std.debug.print("Commit     : {s}\n", .{if (last.len > 0) last else "none"});

    const quoted = try hooks.shellQuote(gpa, store_path);
    defer gpa.free(quoted);
    std.debug.print("History    : git --literal-pathspecs log -- {s}\n", .{quoted});
}

/// Prints whether the manifest makes a path private and identifies the matching line.
fn printPrivate(manifest: ?Manifest, plain: []const u8) bool {
    const m = manifest orelse {
        std.debug.print("Private    : unknown, no {s} found\n", .{Manifest.filename});
        return false;
    };
    if (m.ownLine(plain) != null) {
        std.debug.print("Private    : yes\n", .{});
    } else if (m.covering(plain)) |line| {
        std.debug.print("Private    : yes, through {s}\n", .{line});
    } else {
        std.debug.print("Private    : no, not in {s}\n", .{Manifest.filename});
        return false;
    }
    return true;
}

/// Counts index entries at a store path, including entries beneath a directory.
fn trackedAt(ctx: *const sync.Context, store_path: []const u8) usize {
    const as_dir: Manifest.Entry = .{ .path = store_path, .is_dir = true };
    var n: usize = 0;
    for (ctx.tracked) |path| {
        if (mem.eql(u8, path, store_path) or as_dir.covers(path)) n += 1;
    }
    return n;
}

/// Returns the filesystem kind at a path, or null when it is absent.
fn diskKind(io: Io, abs: []const u8) !?Io.File.Kind {
    const stat = Io.Dir.statFile(.cwd(), io, abs, .{
        .follow_symlinks = false,
    }) catch |err| switch (err) {
        error.FileNotFound, error.NotDir => return null,
        else => return err,
    };
    return stat.kind;
}

/// Runs one encryption or decryption pass, optionally limited to command arguments.
///
fn cmdSync(
    gpa: Allocator,
    io: Io,
    environ_map: *const std.process.Environ.Map,
    direction: sync.Direction,
    args: []const []const u8,
) !void {
    const flags = try parseFlags(gpa, args, .{ .force = true });
    defer gpa.free(flags.positional);
    var repo = try openRepo(gpa, io, environ_map);
    defer repo.deinit();
    const keys = try loadKeys(&repo);

    const only = try relativePaths(&repo, flags.positional);
    defer git.freeList(gpa, only);

    const lock = try repo.lock();
    defer lock.release();

    var report: sync.Report = .{};
    defer report.deinit(gpa);
    const options: sync.Options = .{ .force = flags.force, .only = only };
    switch (direction) {
        .encrypt => sync.encrypt(&repo, keys, options, &report) catch |err| return failSync(&report, err),
        .decrypt => sync.decrypt(&repo, keys, options, &report) catch |err| return failSync(&report, err),
    }
    printReport(&report);
    switch (direction) {
        .encrypt => std.debug.print("{d} encrypted, {d} unchanged\n", .{
            report.count(.encrypted),
            report.count(.ok),
        }),
        .decrypt => std.debug.print("{d} written, {d} deleted, {d} unchanged\n", .{
            report.count(.written),
            report.count(.deleted),
            report.count(.ok),
        }),
    }
}

/// Resolves user arguments to repository-relative paths even when the paths are absent.
fn relativePaths(repo: *Repo, args: []const []const u8) ![][]u8 {
    const gpa = repo.gpa;
    var list: std.ArrayList([]u8) = .empty;
    errdefer {
        for (list.items) |item| gpa.free(item);
        list.deinit(gpa);
    }
    for (args) |raw_arg| {
        const arg = try repo.canonicalArg(raw_arg);
        defer gpa.free(arg);
        const relative = Manifest.relativeToToplevel(
            gpa,
            repo.toplevel,
            repo.prefix,
            arg,
        ) catch |err| {
            if (err == Manifest.Error.OutsideRepository) {
                std.debug.print("Error: {s} is outside the repository\n", .{arg});
            }
            return err;
        };
        errdefer gpa.free(relative);
        try list.append(gpa, relative);
    }
    return list.toOwnedSlice(gpa);
}
