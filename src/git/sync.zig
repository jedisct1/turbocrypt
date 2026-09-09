const std = @import("std");
const builtin = @import("builtin");
const crypto = @import("../crypto.zig");
const filename_crypto = @import("../filename_crypto.zig");
const processor = @import("../processor.zig");
const utils = @import("../utils.zig");
const manifest_mod = @import("manifest.zig");
const repo_mod = @import("repo.zig");

const Repo = repo_mod.Repo;
const Manifest = manifest_mod.Manifest;

pub const enc_dir = ".enc";
pub const marker_name = ".turbocrypt";
pub const marker_text = "turbocrypt-git 1\n";
pub const attributes_name = ".gitattributes";
pub const attributes_text = "* binary -filter -ident -working-tree-encoding -export-subst\n";

/// Private files are documents, so they are processed whole.
/// This bound keeps memory use in check.
pub const max_file_size: u64 = 256 * 1024 * 1024;

pub const long_name_detail = "name too long once encrypted, keep components under about 200 bytes";
pub const pending_detail = "encrypted at the next commit";

const state_version = 1;
const max_state_size = 64 * 1024 * 1024;

pub const Error = error{
    WrongKey,
    NoManifest,
    InvalidState,
    UnsafePath,
    PrivateFileTracked,
    SyncAborted,
    FileTooLarge,
    ChangedDuringSync,
};

pub const plain_file_permissions: std.Io.File.Permissions = if (builtin.os.tag == .windows) .default_file else .fromMode(0o600);
const cipher_file_permissions: std.Io.File.Permissions = if (builtin.os.tag == .windows) .default_file else .fromMode(0o644);
const cipher_exec_permissions: std.Io.File.Permissions = if (builtin.os.tag == .windows) .default_file else .fromMode(0o755);

/// What the last sync saw for one path.
pub const Baseline = struct {
    plain: [crypto.fingerprint_length]u8,
    exec: bool,
    id: [crypto.cipher_id_length]u8,
};

/// The plain file as it is now.
pub const Cur = struct {
    plain: [crypto.fingerprint_length]u8,
    exec: bool,
};

/// The ciphertext entry as it is now.
pub const New = struct {
    id: [crypto.cipher_id_length]u8,
    exec: bool,
    /// False when the header was not written with our key.
    header_ok: bool = true,
};

pub const Values = struct {
    old: ?Baseline,
    new: ?New,
    cur: ?Cur,
    /// Known only after the entry was decrypted and compared.
    cur_eq_new: ?bool = null,

    pub fn newEqOld(v: Values) bool {
        const o = v.old orelse return false;
        const n = v.new orelse return false;
        return std.mem.eql(u8, &o.id, &n.id) and o.exec == n.exec;
    }

    pub fn curEqOld(v: Values) bool {
        const o = v.old orelse return false;
        const c = v.cur orelse return false;
        return std.mem.eql(u8, &o.plain, &c.plain) and o.exec == c.exec;
    }
};

pub const Decision = enum {
    none,
    write_plain,
    delete_plain,
    record,
    drop_baseline,
    conflict,
    encrypt,
    warn_missing,
    warn_removed,
    abort_no_baseline,
    abort_both_changed,
    abort_bad,
    abort_plain,
    need_compare,
};

fn compareOr(v: Values, equal: Decision, different: Decision) Decision {
    const eq = v.cur_eq_new orelse return .need_compare;
    return if (eq) equal else different;
}

/// The decrypt direction: the store is the source, the plain file follows.
pub fn decideDecrypt(v: Values, force: bool) Decision {
    if (v.old == null and v.new == null) return .none;
    if (v.old == null and v.cur == null) return .write_plain;
    if (v.old == null) return compareOr(v, .record, if (force) .write_plain else .conflict);
    if (v.new == null and v.cur == null) return .drop_baseline;
    if (v.new == null) return if (v.curEqOld() or force) .delete_plain else .warn_removed;
    if (v.cur == null) return .write_plain;
    if (v.newEqOld()) return .none;
    if (v.curEqOld()) return .write_plain;
    return compareOr(v, .record, if (force) .write_plain else .conflict);
}

/// The encrypt direction: the plain file is the source, the store follows.
/// A change on both sides is never resolved on its own.
pub fn decideEncrypt(v: Values, force: bool) Decision {
    if (v.old == null and v.new == null and v.cur == null) return .none;
    if (v.old == null and v.new == null) return .encrypt;
    if (v.old == null and v.cur == null) return .warn_missing;
    if (v.old == null) return compareOr(v, .record, if (force) .encrypt else .abort_no_baseline);
    if (v.new == null and v.cur == null) return .drop_baseline;
    if (v.new == null) return if (force) .encrypt else .warn_removed;
    if (v.cur == null) return .warn_missing;
    if (v.newEqOld()) return if (v.curEqOld()) .none else .encrypt;
    if (v.curEqOld()) return .write_plain;
    return compareOr(v, .record, if (force) .encrypt else .abort_both_changed);
}

fn decideFor(v: Values, direction: Direction, force: bool) Decision {
    return switch (direction) {
        .encrypt => decideEncrypt(v, force),
        .decrypt => decideDecrypt(v, force),
    };
}

/// The baselines of every synced path, kept under the git directory.
/// They are keyed, so a file written under another key reads as empty.
pub const State = struct {
    key_id: [crypto.mac_length]u8,
    map: std.StringArrayHashMapUnmanaged(Baseline) = .empty,

    const JsonEntry = struct {
        path: []const u8,
        plain: [2 * crypto.fingerprint_length]u8,
        exec: bool,
        id: [2 * crypto.cipher_id_length]u8,
    };
    const JsonState = struct {
        version: u32,
        key: [2 * crypto.mac_length]u8,
        entries: []JsonEntry,
    };

    pub fn load(allocator: std.mem.Allocator, path: []const u8, key_id: [crypto.mac_length]u8, io: std.Io) !State {
        const text = std.Io.Dir.readFileAlloc(.cwd(), io, path, allocator, .limited(max_state_size)) catch |err| switch (err) {
            error.FileNotFound => return .{ .key_id = key_id },
            else => return err,
        };
        defer allocator.free(text);
        return parse(allocator, text, key_id);
    }

    pub fn parse(allocator: std.mem.Allocator, text: []const u8, key_id: [crypto.mac_length]u8) !State {
        const parsed = std.json.parseFromSlice(JsonState, allocator, text, .{ .ignore_unknown_fields = true }) catch {
            return Error.InvalidState;
        };
        defer parsed.deinit();
        if (parsed.value.version != state_version) return Error.InvalidState;

        var state = State{ .key_id = key_id };
        errdefer state.deinit(allocator);
        var stored: [crypto.mac_length]u8 = undefined;
        _ = std.fmt.hexToBytes(&stored, &parsed.value.key) catch return Error.InvalidState;
        if (!std.mem.eql(u8, &stored, &key_id)) return state;
        for (parsed.value.entries) |entry| {
            var baseline = Baseline{ .plain = undefined, .exec = entry.exec, .id = undefined };
            _ = std.fmt.hexToBytes(&baseline.plain, &entry.plain) catch return Error.InvalidState;
            _ = std.fmt.hexToBytes(&baseline.id, &entry.id) catch return Error.InvalidState;
            try state.put(allocator, entry.path, baseline);
        }
        return state;
    }

    pub fn render(self: State, allocator: std.mem.Allocator) ![]u8 {
        var entries: std.ArrayList(JsonEntry) = .empty;
        defer entries.deinit(allocator);
        var it = self.map.iterator();
        while (it.next()) |kv| {
            try entries.append(allocator, .{
                .path = kv.key_ptr.*,
                .plain = std.fmt.bytesToHex(kv.value_ptr.plain, .lower),
                .exec = kv.value_ptr.exec,
                .id = std.fmt.bytesToHex(kv.value_ptr.id, .lower),
            });
        }
        std.mem.sort(JsonEntry, entries.items, {}, struct {
            fn lessThan(_: void, a: JsonEntry, b: JsonEntry) bool {
                return std.mem.lessThan(u8, a.path, b.path);
            }
        }.lessThan);
        const json = JsonState{ .version = state_version, .key = std.fmt.bytesToHex(self.key_id, .lower), .entries = entries.items };
        return std.json.Stringify.valueAlloc(allocator, json, .{ .whitespace = .indent_2 });
    }

    pub fn save(self: State, allocator: std.mem.Allocator, path: []const u8, tmp_dir: []const u8, io: std.Io) !void {
        const text = try self.render(allocator);
        defer allocator.free(text);
        try processor.writeFileAtomic(path, text, plain_file_permissions, tmp_dir, allocator, io);
    }

    pub fn get(self: State, path: []const u8) ?Baseline {
        return self.map.get(path);
    }

    pub fn put(self: *State, allocator: std.mem.Allocator, path: []const u8, baseline: Baseline) !void {
        if (self.map.getPtr(path)) |existing| {
            existing.* = baseline;
            return;
        }
        const key = try allocator.dupe(u8, path);
        errdefer allocator.free(key);
        try self.map.put(allocator, key, baseline);
    }

    pub fn remove(self: *State, allocator: std.mem.Allocator, path: []const u8) void {
        if (self.map.fetchOrderedRemove(path)) |kv| allocator.free(kv.key);
    }

    pub fn deinit(self: *State, allocator: std.mem.Allocator) void {
        for (self.map.keys()) |key| allocator.free(key);
        self.map.deinit(allocator);
    }
};

pub fn keyDirName(keys: crypto.DerivedKeys) [2 * crypto.mac_length]u8 {
    return std.fmt.bytesToHex(crypto.keyId(keys.key_id_key), .lower);
}

pub const key_dir_len = enc_dir.len + 1 + 2 * crypto.mac_length;

/// The directory of one key inside the store, relative to the top level.
/// A key keeps its entries and its manifest there and never looks into the other directories.
/// This lets people with different keys share a repository.
pub fn keyDirRel(keys: crypto.DerivedKeys) [key_dir_len]u8 {
    var out: [key_dir_len]u8 = undefined;
    @memcpy(out[0 .. enc_dir.len + 1], enc_dir ++ "/");
    @memcpy(out[enc_dir.len + 1 ..], &keyDirName(keys));
    return out;
}

pub fn keyDirAbs(repo: *const Repo, keys: crypto.DerivedKeys) ![]u8 {
    const rel = keyDirRel(keys);
    return repo.absolutePath(&rel);
}

/// Path of a store entry relative to the top level.
pub fn storePath(allocator: std.mem.Allocator, key_dir: []const u8, cipher_rel: []const u8) ![]u8 {
    return std.fmt.allocPrint(allocator, "{s}/{s}", .{ key_dir, cipher_rel });
}

/// A plain path may only name a regular file inside the working tree, reached through real directories.
/// A tracked path is refused too: git owns it, and a checkout would overwrite whatever we write.
pub fn validateDestination(
    allocator: std.mem.Allocator,
    toplevel: []const u8,
    plain: []const u8,
    tracked: []const []const u8,
    io: std.Io,
) !void {
    if (plain.len == 0 or plain[0] == '/') return Error.UnsafePath;
    var it = std.mem.splitScalar(u8, plain, '/');
    while (it.next()) |component| {
        if (!filename_crypto.isSafeComponent(component)) return Error.UnsafePath;
    }
    if (manifest_mod.isReservedPath(plain)) return Error.UnsafePath;
    if (utils.containsString(tracked, plain)) return Error.UnsafePath;

    var end: usize = 0;
    while (std.mem.indexOfScalarPos(u8, plain, end, '/')) |i| : (end = i + 1) {
        const ancestor = try std.fs.path.join(allocator, &.{ toplevel, plain[0..i] });
        defer allocator.free(ancestor);
        const stat = std.Io.Dir.statFile(.cwd(), io, ancestor, .{ .follow_symlinks = false }) catch |err| switch (err) {
            error.FileNotFound => continue,
            else => return err,
        };
        if (stat.kind != .directory) return Error.UnsafePath;
    }
    const full = try std.fs.path.join(allocator, &.{ toplevel, plain });
    defer allocator.free(full);
    const stat = std.Io.Dir.statFile(.cwd(), io, full, .{ .follow_symlinks = false }) catch |err| switch (err) {
        error.FileNotFound => return,
        else => return err,
    };
    if (stat.kind != .file) return Error.UnsafePath;
}

/// Store entries on disk, as paths relative to the key directory.
/// Anything that is not a regular file with a valid name ends up in `bad`.
pub fn listStore(
    allocator: std.mem.Allocator,
    store_abs: []const u8,
    bad: *std.ArrayList([]u8),
    io: std.Io,
) ![][]u8 {
    var files: std.ArrayList([]u8) = .empty;
    errdefer {
        for (files.items) |f| allocator.free(f);
        files.deinit(allocator);
    }
    try listStoreDir(allocator, store_abs, "", &files, bad, io);
    std.mem.sort([]u8, files.items, {}, struct {
        fn lessThan(_: void, a: []u8, b: []u8) bool {
            return std.mem.lessThan(u8, a, b);
        }
    }.lessThan);
    return files.toOwnedSlice(allocator);
}

fn listStoreDir(
    allocator: std.mem.Allocator,
    store_abs: []const u8,
    rel: []const u8,
    files: *std.ArrayList([]u8),
    bad: *std.ArrayList([]u8),
    io: std.Io,
) !void {
    const dir_path = if (rel.len == 0) try allocator.dupe(u8, store_abs) else try std.fs.path.join(allocator, &.{ store_abs, rel });
    defer allocator.free(dir_path);

    var dir = try std.Io.Dir.openDir(.cwd(), io, dir_path, .{ .iterate = true, .follow_symlinks = false });
    defer dir.close(io);

    var it = dir.iterate();
    while (try it.next(io)) |entry| {
        const child = if (rel.len == 0) try allocator.dupe(u8, entry.name) else try std.fmt.allocPrint(allocator, "{s}/{s}", .{ rel, entry.name });
        errdefer allocator.free(child);
        switch (entry.kind) {
            .directory => {
                try listStoreDir(allocator, store_abs, child, files, bad, io);
                allocator.free(child);
            },
            .file => try files.append(allocator, child),
            else => try bad.append(allocator, child),
        }
    }
}

/// One store entry with its plain path.
/// The store path is relative to the key directory.
pub const Entry = struct {
    plain: []u8,
    cipher_rel: []u8,
};

pub fn freeEntries(allocator: std.mem.Allocator, entries: []const Entry) void {
    for (entries) |entry| {
        allocator.free(entry.plain);
        allocator.free(entry.cipher_rel);
    }
    allocator.free(entries);
}

pub const Row = struct {
    kind: Kind,
    path: []u8,
    detail: []u8,

    pub const Kind = enum {
        ok,
        encrypted,
        written,
        deleted,
        modified,
        incoming,
        conflict,
        new,
        missing,
        removed,
        ignored,
        tracked,
        merging,
        bad,
    };
};

pub const Report = struct {
    rows: std.ArrayList(Row) = .empty,
    /// Paths that would change but were not applied, for the partial commit message.
    pending: usize = 0,

    pub fn add(self: *Report, allocator: std.mem.Allocator, kind: Row.Kind, path: []const u8, detail: []const u8) !void {
        const p = try allocator.dupe(u8, path);
        errdefer allocator.free(p);
        const d = try allocator.dupe(u8, detail);
        errdefer allocator.free(d);
        try self.rows.append(allocator, .{ .kind = kind, .path = p, .detail = d });
    }

    pub fn count(self: Report, kind: Row.Kind) usize {
        var n: usize = 0;
        for (self.rows.items) |row| {
            if (row.kind == kind) n += 1;
        }
        return n;
    }

    pub fn deinit(self: *Report, allocator: std.mem.Allocator) void {
        for (self.rows.items) |row| {
            allocator.free(row.path);
            allocator.free(row.detail);
        }
        self.rows.deinit(allocator);
    }
};

pub const Options = struct {
    force: bool = false,
    /// Plan, report, but write nothing. Used for partial commits and status.
    validate_only: bool = false,
    /// Restrict the pass to these plain paths.
    only: []const []const u8 = &.{},
};

const PathInfo = struct {
    plain: []u8,
    cipher_rel: ?[]u8 = null,
    values: Values,
    /// Plain bytes of the entry, kept when it was decrypted for a comparison.
    decrypted: ?[]u8 = null,
    bad: bool = false,
    decision: Decision = .none,
};

/// Everything a pass needs, loaded once.
pub const Context = struct {
    repo: *const Repo,
    keys: crypto.DerivedKeys,
    allocator: std.mem.Allocator,
    io: std.Io,
    state: State,
    /// The plain manifest when it exists, else the store copy.
    manifest: ?Manifest,
    /// The store copy, kept apart because it can be newer than the plain one after a pull.
    /// The exclude block takes both.
    store_manifest: ?Manifest,
    /// The key directory, relative to the top level and absolute.
    store_rel: [key_dir_len]u8,
    store_abs: []u8,
    /// Every path in the index, unmerged ones included.
    tracked: [][]u8,
    /// Store entries git holds unmerged, relative to the key directory.
    unmerged: [][]u8,

    pub fn init(repo: *const Repo, keys: crypto.DerivedKeys) !Context {
        const allocator = repo.allocator;
        const key_id = crypto.keyId(keys.key_id_key);
        var ctx = Context{
            .repo = repo,
            .keys = keys,
            .allocator = allocator,
            .io = repo.io,
            .state = .{ .key_id = key_id },
            .manifest = null,
            .store_manifest = null,
            .store_rel = keyDirRel(keys),
            .store_abs = &.{},
            .tracked = &.{},
            .unmerged = &.{},
        };
        errdefer ctx.deinit();

        ctx.store_abs = try repo.absolutePath(&ctx.store_rel);
        ctx.state = try State.load(allocator, repo.state_path, key_id, repo.io);
        try ctx.loadIndex();
        try ctx.loadManifest();
        return ctx;
    }

    pub fn deinit(self: *Context) void {
        self.state.deinit(self.allocator);
        if (self.manifest) |*m| m.deinit(self.allocator);
        if (self.store_manifest) |*m| m.deinit(self.allocator);
        self.allocator.free(self.store_abs);
        utils.freeList(self.allocator, self.tracked);
        utils.freeList(self.allocator, self.unmerged);
    }

    /// The tracked paths and the unmerged store entries, from one listing of the index.
    fn loadIndex(self: *Context) !void {
        const allocator = self.allocator;
        const lines = try self.repo.lsFilesZ(&.{"--stage"});
        defer utils.freeList(allocator, lines);

        var tracked: std.ArrayList([]u8) = .empty;
        errdefer {
            for (tracked.items) |t| allocator.free(t);
            tracked.deinit(allocator);
        }
        var unmerged: std.ArrayList([]u8) = .empty;
        errdefer {
            for (unmerged.items) |u| allocator.free(u);
            unmerged.deinit(allocator);
        }
        for (lines) |line| {
            const tab = std.mem.indexOfScalar(u8, line, '\t') orelse continue;
            const path = line[tab + 1 ..];
            if (tracked.items.len == 0 or !std.mem.eql(u8, tracked.items[tracked.items.len - 1], path)) {
                try tracked.append(allocator, try allocator.dupe(u8, path));
            }
            if (tab == 0 or line[tab - 1] == '0') continue;
            if (!std.mem.startsWith(u8, path, &self.store_rel) or path.len <= key_dir_len or path[key_dir_len] != '/') continue;
            const rel = path[key_dir_len + 1 ..];
            if (unmerged.items.len == 0 or !std.mem.eql(u8, unmerged.items[unmerged.items.len - 1], rel)) {
                try unmerged.append(allocator, try allocator.dupe(u8, rel));
            }
        }
        self.tracked = try tracked.toOwnedSlice(allocator);
        self.unmerged = try unmerged.toOwnedSlice(allocator);
    }

    /// The plain manifest when it exists, else the one in the store.
    /// Reading the store copy is also the key check.
    /// A wrong key cannot name the entry, and a corrupted one fails to decrypt.
    fn loadManifest(self: *Context) !void {
        const store_text = try manifestFromDir(self.repo, self.store_abs, self.keys);
        defer if (store_text) |text| self.allocator.free(text);
        if (store_text) |text| self.store_manifest = try Manifest.parse(self.allocator, text);

        if (try readPlainManifest(self.repo)) |manifest| {
            self.manifest = manifest;
        } else if (store_text) |text| {
            self.manifest = try Manifest.parse(self.allocator, text);
        }
    }

    fn manifestsForExclude(self: *const Context, buf: *[2]*const Manifest) []const *const Manifest {
        var n: usize = 0;
        if (self.manifest) |*m| {
            buf[n] = m;
            n += 1;
        }
        if (self.store_manifest) |*m| {
            buf[n] = m;
            n += 1;
        }
        return buf[0..n];
    }

    fn isUnmerged(self: *const Context, cipher_rel: []const u8) bool {
        return utils.containsString(self.unmerged, cipher_rel);
    }
};

pub fn readPlainManifest(repo: *const Repo) !?Manifest {
    const allocator = repo.allocator;
    const path = try repo.absolutePath(manifest_mod.manifest_name);
    defer allocator.free(path);
    const text = std.Io.Dir.readFileAlloc(.cwd(), repo.io, path, allocator, .limited(max_file_size)) catch |err| switch (err) {
        error.FileNotFound => return null,
        else => return err,
    };
    defer allocator.free(text);
    return try Manifest.parse(allocator, text);
}

/// Decrypted manifest text from the key directory, or null when the key has no manifest entry.
/// An entry that does not decrypt means a corrupted store, since only the key can name its directory.
pub fn manifestFromStore(repo: *const Repo, keys: crypto.DerivedKeys) !?[]u8 {
    const store_abs = try keyDirAbs(repo, keys);
    defer repo.allocator.free(store_abs);
    return manifestFromDir(repo, store_abs, keys);
}

fn manifestFromDir(repo: *const Repo, store_abs: []const u8, keys: crypto.DerivedKeys) !?[]u8 {
    const allocator = repo.allocator;
    const cipher_rel = try filename_crypto.encryptPath(allocator, manifest_mod.manifest_name, keys.filename_key, '/');
    defer allocator.free(cipher_rel);
    const abs = try std.fs.path.join(allocator, &.{ store_abs, cipher_rel });
    defer allocator.free(abs);

    const encrypted = std.Io.Dir.readFileAlloc(.cwd(), repo.io, abs, allocator, .limited(max_file_size)) catch |err| switch (err) {
        error.FileNotFound => return null,
        else => return err,
    };
    defer allocator.free(encrypted);
    return crypto.decryptBound(encrypted, manifest_mod.manifest_name, keys, allocator) catch return Error.WrongKey;
}

/// Every plain file is written under the git directory and renamed into the working tree, which needs both on one filesystem.
/// Find out before anything else changes.
pub fn checkSameFilesystem(repo: *const Repo) !void {
    const allocator = repo.allocator;
    try repo.ensureDirs();
    const store = try repo.absolutePath(enc_dir);
    defer allocator.free(store);
    try utils.ensureDirectory(store, repo.io);
    const probe = try std.fs.path.join(allocator, &.{ store, ".probe" });
    defer allocator.free(probe);
    defer std.Io.Dir.deleteFile(.cwd(), repo.io, probe) catch {};
    processor.writeFileAtomic(probe, "", null, repo.tmp_dir, allocator, repo.io) catch |err| switch (err) {
        error.CrossDevice => {
            std.debug.print("Error: the git directory and the working tree must be on the same filesystem\n", .{});
            return err;
        },
        else => return err,
    };
}

/// True when the store directory carries our marker.
pub fn storeExists(repo: *const Repo) bool {
    const path = std.fs.path.join(repo.allocator, &.{ repo.toplevel, enc_dir, marker_name }) catch return false;
    defer repo.allocator.free(path);
    return utils.pathExists(path, repo.io);
}

/// How many other keys have a directory in the store, which is all a key holder learns about them.
pub fn otherKeyCount(repo: *const Repo, keys: crypto.DerivedKeys) !usize {
    const allocator = repo.allocator;
    const store = try repo.absolutePath(enc_dir);
    defer allocator.free(store);
    const our_name = keyDirName(keys);

    var dir = std.Io.Dir.openDir(.cwd(), repo.io, store, .{ .iterate = true, .follow_symlinks = false }) catch |err| switch (err) {
        error.FileNotFound => return 0,
        else => return err,
    };
    defer dir.close(repo.io);

    var n: usize = 0;
    var it = dir.iterate();
    while (try it.next(repo.io)) |entry| {
        if (entry.kind == .directory and !std.mem.eql(u8, entry.name, &our_name)) n += 1;
    }
    return n;
}

/// Plain files in the working tree that the manifest makes private.
/// Files that a .gitignore rule ignores are left out and returned apart.
/// This keeps the build output of a private directory out of the store.
pub const Candidates = struct {
    files: [][]u8,
    ignored: [][]u8,

    pub fn deinit(self: Candidates, allocator: std.mem.Allocator) void {
        utils.freeList(allocator, self.files);
        utils.freeList(allocator, self.ignored);
    }
};

pub fn collectCandidates(ctx: *const Context, manifest: Manifest) !Candidates {
    const repo = ctx.repo;
    const allocator = ctx.allocator;

    var files: std.ArrayList([]u8) = .empty;
    errdefer {
        for (files.items) |f| allocator.free(f);
        files.deinit(allocator);
    }
    var ignored: std.ArrayList([]u8) = .empty;
    errdefer {
        for (ignored.items) |f| allocator.free(f);
        ignored.deinit(allocator);
    }

    const entries = try manifest.entries(allocator);
    defer allocator.free(entries);

    const manifest_abs = try repo.absolutePath(manifest_mod.manifest_name);
    defer allocator.free(manifest_abs);
    if (utils.pathExists(manifest_abs, repo.io)) {
        try files.append(allocator, try allocator.dupe(u8, manifest_mod.manifest_name));
    }
    if (entries.len == 0) return .{ .files = try files.toOwnedSlice(allocator), .ignored = try ignored.toOwnedSlice(allocator) };

    // Limit git to the private paths.
    var pathspec: std.ArrayList([]const u8) = .empty;
    defer pathspec.deinit(allocator);
    try pathspec.append(allocator, "--");
    for (entries) |entry| try pathspec.append(allocator, entry.path);

    const private_lines = try renderLines(allocator, manifest);
    defer allocator.free(private_lines);
    const private_file = try std.fs.path.join(allocator, &.{ repo.private_dir, "candidates" });
    defer allocator.free(private_file);
    try processor.writeFileAtomic(private_file, private_lines, utils.private_file_permissions, null, allocator, repo.io);
    const exclude_from = try std.fmt.allocPrint(allocator, "--exclude-from={s}", .{private_file});
    defer allocator.free(exclude_from);

    var argv: std.ArrayList([]const u8) = .empty;
    defer argv.deinit(allocator);
    try argv.appendSlice(allocator, &.{ "--others", "--ignored", exclude_from });
    try argv.appendSlice(allocator, pathspec.items);
    const all = try repo.lsFilesZ(argv.items);
    defer utils.freeList(allocator, all);

    const gitignored = try listGitignored(ctx, pathspec.items);
    defer utils.freeList(allocator, gitignored);
    var ignored_set: std.StringHashMapUnmanaged(void) = .empty;
    defer ignored_set.deinit(allocator);
    for (gitignored) |path| try ignored_set.put(allocator, path, {});

    for (all) |path| {
        if (manifest_mod.isReservedPath(path)) continue;
        if (!manifest_mod.anyCovers(entries, path)) continue;
        if (ignored_set.contains(path)) {
            try ignored.append(allocator, try allocator.dupe(u8, path));
            continue;
        }

        const abs = try repo.absolutePath(path);
        defer allocator.free(abs);
        const stat = std.Io.Dir.statFile(.cwd(), repo.io, abs, .{ .follow_symlinks = false }) catch continue;
        if (stat.kind != .file) continue;
        try files.append(allocator, try allocator.dupe(u8, path));
    }
    return .{ .files = try files.toOwnedSlice(allocator), .ignored = try ignored.toOwnedSlice(allocator) };
}

fn renderLines(allocator: std.mem.Allocator, manifest: Manifest) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    for (manifest.lines.items) |line| {
        if (manifest_mod.parseLine(line) == null) continue;
        try out.appendSlice(allocator, line);
        try out.append(allocator, '\n');
    }
    return out.toOwnedSlice(allocator);
}

/// Untracked files under the pathspec that .gitignore files or the global excludes ignore.
fn listGitignored(ctx: *const Context, pathspec: []const []const u8) ![][]u8 {
    const repo = ctx.repo;
    const allocator = ctx.allocator;

    var argv: std.ArrayList([]const u8) = .empty;
    defer argv.deinit(allocator);
    try argv.appendSlice(allocator, &.{ "--others", "--ignored", "--exclude-per-directory=.gitignore" });

    const global = try globalExcludesFile(ctx);
    defer if (global) |g| allocator.free(g);
    const arg = if (global) |g| try std.fmt.allocPrint(allocator, "--exclude-from={s}", .{g}) else null;
    defer if (arg) |a| allocator.free(a);
    if (arg) |a| try argv.append(allocator, a);
    try argv.appendSlice(allocator, pathspec);

    return repo.lsFilesZ(argv.items);
}

/// The global excludes file, or null when there is none.
/// Git cannot be asked for the default location.
fn globalExcludesFile(ctx: *const Context) !?[]u8 {
    const allocator = ctx.allocator;
    const env = ctx.repo.environ_map;
    if (try ctx.repo.configGetPath("core.excludesFile")) |configured| return configured;
    // Git on Windows falls back to the profile directory.
    const home = env.get("HOME") orelse env.get("USERPROFILE");
    const candidate = if (env.get("XDG_CONFIG_HOME")) |xdg|
        try std.fs.path.join(allocator, &.{ xdg, "git", "ignore" })
    else if (home) |dir|
        try std.fs.path.join(allocator, &.{ dir, ".config", "git", "ignore" })
    else
        return null;
    if (!utils.pathExists(candidate, ctx.io)) {
        allocator.free(candidate);
        return null;
    }
    return candidate;
}

fn isExecutable(permissions: std.Io.File.Permissions) bool {
    if (!std.Io.File.Permissions.has_executable_bit) return false;
    return permissions.toMode() & 0o111 != 0;
}

const Snapshot = struct {
    mac: [crypto.mac_length]u8,
    exec: bool,
};

/// The MAC and the mode of a file, or null when it is absent or not a regular file.
/// The bytes are handed over when asked for.
fn snapshot(ctx: *const Context, abs: []const u8, limit: u64, key: [crypto.key_length]u8, bytes_out: ?*?[]u8) !?Snapshot {
    const stat = std.Io.Dir.statFile(.cwd(), ctx.io, abs, .{ .follow_symlinks = false }) catch |err| switch (err) {
        error.FileNotFound => return null,
        else => return err,
    };
    if (stat.kind != .file) return null;
    if (stat.size > limit) return Error.FileTooLarge;

    const bytes = try std.Io.Dir.readFileAlloc(.cwd(), ctx.io, abs, ctx.allocator, .limited(limit));
    const snap = Snapshot{ .mac = crypto.keyedMac(bytes, key), .exec = isExecutable(stat.permissions) };
    if (bytes_out) |out| out.* = bytes else ctx.allocator.free(bytes);
    return snap;
}

/// The plain file of a path, fingerprinted, or null when it is absent.
fn readCur(ctx: *const Context, plain: []const u8, bytes_out: ?*?[]u8) !?Cur {
    const abs = try ctx.repo.absolutePath(plain);
    defer ctx.allocator.free(abs);
    const snap = (try snapshot(ctx, abs, max_file_size, ctx.keys.fingerprint_key, bytes_out)) orelse return null;
    return .{ .plain = snap.mac, .exec = snap.exec };
}

fn entryPath(ctx: *const Context, cipher_rel: []const u8) ![]u8 {
    return std.fs.path.join(ctx.allocator, &.{ ctx.store_abs, cipher_rel });
}

/// The store entry of a path, identified and header-checked, or null when it is absent.
fn readNew(ctx: *const Context, cipher_rel: []const u8) !?New {
    const abs = try entryPath(ctx, cipher_rel);
    defer ctx.allocator.free(abs);
    var bytes: ?[]u8 = null;
    const snap = (try snapshot(ctx, abs, max_file_size + crypto.overhead_size, ctx.keys.cipher_id_key, &bytes)) orelse return null;
    defer ctx.allocator.free(bytes.?);
    const header_ok = if (crypto.verifyHeaderOnly(bytes.?, ctx.keys)) |_| true else |_| false;
    return .{ .id = snap.mac, .exec = snap.exec, .header_ok = header_ok };
}

fn readEntry(ctx: *const Context, cipher_rel: []const u8) !?[]u8 {
    const abs = try entryPath(ctx, cipher_rel);
    defer ctx.allocator.free(abs);
    return std.Io.Dir.readFileAlloc(.cwd(), ctx.io, abs, ctx.allocator, .limited(max_file_size + crypto.overhead_size)) catch |err| switch (err) {
        error.FileNotFound => null,
        else => return err,
    };
}

/// Gather every path either side knows about, with its three values.
fn analyze(ctx: *const Context, only: []const []const u8, report: *Report) ![]PathInfo {
    const allocator = ctx.allocator;

    var names: std.StringArrayHashMapUnmanaged(void) = .empty;
    defer {
        for (names.keys()) |k| allocator.free(k);
        names.deinit(allocator);
    }
    var ciphers: std.StringArrayHashMapUnmanaged([]u8) = .empty;
    defer {
        for (ciphers.values()) |v| allocator.free(v);
        ciphers.deinit(allocator);
    }

    var bad: std.ArrayList([]u8) = .empty;
    defer {
        for (bad.items) |b| allocator.free(b);
        bad.deinit(allocator);
    }
    const store_files = if (utils.pathExists(ctx.store_abs, ctx.io)) try listStore(allocator, ctx.store_abs, &bad, ctx.io) else try allocator.alloc([]u8, 0);
    defer utils.freeList(allocator, store_files);

    for (store_files) |cipher_rel| {
        const plain = filename_crypto.decryptPathStrict(allocator, cipher_rel, ctx.keys.filename_key) catch {
            try bad.append(allocator, try allocator.dupe(u8, cipher_rel));
            continue;
        };
        errdefer allocator.free(plain);
        if (!names.contains(plain)) {
            try names.put(allocator, plain, {});
            try ciphers.put(allocator, plain, try allocator.dupe(u8, cipher_rel));
        } else {
            allocator.free(plain);
        }
    }
    for (bad.items) |b| {
        const shown = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ &ctx.store_rel, b });
        defer allocator.free(shown);
        try report.add(allocator, .bad, shown, "cannot decrypt the name");
    }

    for (ctx.state.map.keys()) |path| {
        if (!names.contains(path)) try names.put(allocator, try allocator.dupe(u8, path), {});
    }

    if (ctx.manifest) |manifest| {
        const candidates = try collectCandidates(ctx, manifest);
        defer candidates.deinit(allocator);
        for (candidates.files) |path| {
            if (!names.contains(path)) try names.put(allocator, try allocator.dupe(u8, path), {});
        }
        for (candidates.ignored) |path| {
            try report.add(allocator, .ignored, path, "matches a .gitignore rule, not encrypted");
        }
    }

    var infos: std.ArrayList(PathInfo) = .empty;
    errdefer {
        for (infos.items) |*info| freeInfo(allocator, info);
        infos.deinit(allocator);
    }

    const keys = names.keys();
    std.mem.sort([]const u8, keys, {}, struct {
        fn lessThan(_: void, a: []const u8, b: []const u8) bool {
            return std.mem.lessThan(u8, a, b);
        }
    }.lessThan);

    for (keys) |plain| {
        if (only.len > 0 and !utils.containsString(only, plain)) continue;

        var info = PathInfo{ .plain = try allocator.dupe(u8, plain), .values = .{ .old = ctx.state.get(plain), .new = null, .cur = null } };
        errdefer freeInfo(allocator, &info);

        info.cipher_rel = if (ciphers.get(plain)) |c| try allocator.dupe(u8, c) else null;
        info.values.cur = readCur(ctx, plain, null) catch |err| switch (err) {
            Error.FileTooLarge => blk: {
                try report.add(allocator, .bad, plain, "larger than 256 MiB");
                info.bad = true;
                break :blk null;
            },
            else => return err,
        };
        if (info.cipher_rel) |c| {
            info.values.new = readNew(ctx, c) catch |err| switch (err) {
                Error.FileTooLarge => blk: {
                    try report.add(allocator, .bad, plain, "entry larger than 256 MiB");
                    info.bad = true;
                    break :blk null;
                },
                else => return err,
            };
        } else if (info.values.cur != null and !try nameFits(allocator, ctx.keys, plain)) {
            try report.add(allocator, .bad, plain, long_name_detail);
            info.bad = true;
        }
        try infos.append(allocator, info);
    }
    return infos.toOwnedSlice(allocator);
}

/// True when every component of the path still fits a file name once encrypted.
pub fn nameFits(allocator: std.mem.Allocator, keys: crypto.DerivedKeys, plain: []const u8) !bool {
    const cipher = filename_crypto.encryptPath(allocator, plain, keys.filename_key, '/') catch |err| switch (err) {
        filename_crypto.FilenameError.EncryptedFilenameTooLong => return false,
        else => return err,
    };
    allocator.free(cipher);
    return true;
}

fn freeInfo(allocator: std.mem.Allocator, info: *PathInfo) void {
    allocator.free(info.plain);
    if (info.cipher_rel) |c| allocator.free(c);
    freeDecrypted(allocator, info);
}

fn freeDecrypted(allocator: std.mem.Allocator, info: *PathInfo) void {
    if (info.decrypted) |d| allocator.free(d);
    info.decrypted = null;
}

fn freeInfos(allocator: std.mem.Allocator, infos: []PathInfo) void {
    for (infos) |*info| freeInfo(allocator, info);
    allocator.free(infos);
}

/// Decrypt the entry of a path and remember the bytes.
/// Returns false when the entry does not authenticate, which makes the path bad.
fn decryptEntry(ctx: *const Context, info: *PathInfo, report: *Report) !bool {
    if (info.decrypted != null) return true;
    const cipher_rel = info.cipher_rel orelse return false;
    const encrypted = (try readEntry(ctx, cipher_rel)) orelse return false;
    defer ctx.allocator.free(encrypted);

    info.decrypted = crypto.decryptBound(encrypted, info.plain, ctx.keys, ctx.allocator) catch {
        try report.add(ctx.allocator, .bad, info.plain, "entry does not decrypt: wrong key, corrupted, or moved to another path");
        info.bad = true;
        return false;
    };
    return true;
}

/// Answer "cur == new" for one path by decrypting its entry.
fn compare(ctx: *const Context, info: *PathInfo, report: *Report) !void {
    if (!try decryptEntry(ctx, info, report)) return;
    const new = info.values.new orelse return;
    const cur = info.values.cur orelse return;
    const decrypted = crypto.fingerprint(info.decrypted.?, ctx.keys.fingerprint_key);
    info.values.cur_eq_new = std.mem.eql(u8, &decrypted, &cur.plain) and cur.exec == new.exec;
}

/// A bad path stops the encrypt direction and is left alone by the decrypt direction.
/// A bad entry can be replaced from the plain file when forced. A plain file that cannot be encrypted has no such way out.
fn badDecision(info: *const PathInfo, direction: Direction, force: bool) Decision {
    if (direction != .encrypt) return .none;
    if (info.cipher_rel == null) return .abort_plain;
    if (force and info.values.cur != null) return .encrypt;
    return .abort_bad;
}

pub const Direction = enum { encrypt, decrypt };

/// Settle the decision of one path.
/// The decrypted bytes stay only when the plain file will be written from them.
fn decide(ctx: *const Context, info: *PathInfo, direction: Direction, force: bool, report: *Report) !void {
    defer if (info.decision != .write_plain) freeDecrypted(ctx.allocator, info);
    if (info.bad) {
        info.decision = badDecision(info, direction, force);
        return;
    }
    var decision = decideFor(info.values, direction, force);
    if (decision == .need_compare) {
        try compare(ctx, info, report);
        if (info.bad) {
            info.decision = badDecision(info, direction, force);
            return;
        }
        decision = decideFor(info.values, direction, force);
    }
    if (decision == .write_plain and !try decryptEntry(ctx, info, report)) {
        decision = badDecision(info, direction, force);
    }
    info.decision = decision;
}

/// Open the directory that holds `rel` under `root`, one component at a time.
/// Symbolic links are not followed, so a link planted in the tree cannot redirect a write or a delete.
/// Missing directories are created when asked, the root included, otherwise null is returned.
/// The caller closes the handle.
fn openParent(io: std.Io, root: []const u8, rel: []const u8, create: bool) !?std.Io.Dir {
    var dir = std.Io.Dir.openDir(.cwd(), io, root, .{}) catch |err| switch (err) {
        error.FileNotFound => blk: {
            if (!create) return err;
            try utils.ensureDirectory(root, io);
            break :blk try std.Io.Dir.openDir(.cwd(), io, root, .{});
        },
        else => return err,
    };
    errdefer dir.close(io);

    var it = std.mem.splitScalar(u8, rel, '/');
    var component = it.next() orelse return Error.UnsafePath;
    while (it.next()) |next| : (component = next) {
        if (component.len == 0) return Error.UnsafePath;
        const child = dir.openDir(io, component, .{ .follow_symlinks = false }) catch |err| switch (err) {
            error.FileNotFound => blk: {
                if (!create) {
                    dir.close(io);
                    return null;
                }
                try dir.createDir(io, component, .default_dir);
                break :blk try dir.openDir(io, component, .{ .follow_symlinks = false });
            },
            else => return err,
        };
        dir.close(io);
        dir = child;
    }
    return dir;
}

/// Delete `rel` under `root` through directory handles, then remove the directories it leaves empty.
fn deleteThroughHandles(io: std.Io, root: []const u8, rel: []const u8) !void {
    if (try openParent(io, root, rel, false)) |parent| {
        var dir = parent;
        defer dir.close(io);
        dir.deleteFile(io, std.fs.path.basename(rel)) catch |err| switch (err) {
            error.FileNotFound => {},
            else => return err,
        };
    }
    pruneEmptyParents(io, root, rel);
}

fn pruneEmptyParents(io: std.Io, root: []const u8, rel: []const u8) void {
    var ancestor = std.fs.path.dirname(rel);
    while (ancestor) |path| : (ancestor = std.fs.path.dirname(path)) {
        const parent = (openParent(io, root, path, false) catch break) orelse break;
        var dir = parent;
        defer dir.close(io);
        dir.deleteDir(io, std.fs.path.basename(path)) catch break;
    }
}

const SwapError = error{ Unsupported, NotFound, Failed };

/// Swap two directory entries in one step, so the displaced file can still be inspected at the source path.
/// The standard library has no portable call for this, and Windows has no such operation.
fn exchange(allocator: std.mem.Allocator, a_dir: std.Io.Dir, a: []const u8, b_dir: std.Io.Dir, b: []const u8) (SwapError || std.mem.Allocator.Error)!void {
    if (builtin.os.tag != .linux and builtin.os.tag != .macos) return SwapError.Unsupported;

    const a_z = try allocator.dupeSentinel(u8, a, 0);
    defer allocator.free(a_z);
    const b_z = try allocator.dupeSentinel(u8, b, 0);
    defer allocator.free(b_z);
    switch (builtin.os.tag) {
        .linux => {
            const rc = std.os.linux.renameat2(a_dir.handle, a_z, b_dir.handle, b_z, .{ .EXCHANGE = true });
            return switch (std.os.linux.errno(rc)) {
                .SUCCESS => {},
                .NOENT => SwapError.NotFound,
                .INVAL, .OPNOTSUPP, .NOSYS => SwapError.Unsupported,
                else => SwapError.Failed,
            };
        },
        .macos => {
            const rc = std.c.renameatx_np(a_dir.handle, a_z, b_dir.handle, b_z, .{ .SWAP = true });
            return switch (std.c.errno(rc)) {
                .SUCCESS => {},
                .NOENT => SwapError.NotFound,
                .INVAL, .OPNOTSUPP => SwapError.Unsupported,
                else => SwapError.Failed,
            };
        },
        else => unreachable,
    }
}

/// True when the file at `path` is what the analysis saw for the entry.
fn matchesAnalysis(ctx: *const Context, path: []const u8, cur: ?Cur) !bool {
    const now = snapshot(ctx, path, max_file_size, ctx.keys.fingerprint_key, null) catch |err| switch (err) {
        Error.FileTooLarge => return false,
        else => return err,
    };
    const expected = cur orelse return now == null;
    const snap = now orelse return false;
    return std.mem.eql(u8, &snap.mac, &expected.plain) and snap.exec == expected.exec;
}

fn fileHolds(ctx: *const Context, path: []const u8, expected: []const u8) !bool {
    const bytes = std.Io.Dir.readFileAlloc(.cwd(), ctx.io, path, ctx.allocator, .limited(max_file_size)) catch return false;
    defer ctx.allocator.free(bytes);
    return std.mem.eql(u8, bytes, expected);
}

/// A fresh name in the private temporary directory.
fn asidePath(ctx: *const Context, prefix: []const u8, name: []const u8) ![]u8 {
    var rand: u64 = undefined;
    ctx.io.random(std.mem.asBytes(&rand));
    return std.fmt.allocPrint(ctx.allocator, "{s}/{s}.{s}.{x}", .{ ctx.repo.tmp_dir, prefix, name, rand });
}

/// A file that held a save made during the sync is moved aside rather than deleted.
/// The user is told where it is.
fn keepSavedCopy(ctx: *const Context, path: []const u8, plain: []const u8) void {
    const saved = asidePath(ctx, "saved", std.fs.path.basename(plain)) catch return;
    defer ctx.allocator.free(saved);
    std.Io.Dir.renamePreserve(.cwd(), path, .cwd(), saved, ctx.io) catch return;
    std.debug.print("Warning: {s} changed twice while the sync ran. A copy of the newest content is at {s}\n", .{ plain, saved });
}

fn plainPermissions(exec: bool, existing: ?std.Io.File.Permissions) std.Io.File.Permissions {
    if (!std.Io.File.Permissions.has_executable_bit) return .default_file;
    const base = if (existing) |p| p.toMode() else plain_file_permissions.toMode();
    const without = base & ~@as(std.posix.mode_t, 0o111);
    return .fromMode(if (exec) without | 0o100 else without);
}

fn writePlain(ctx: *const Context, info: *PathInfo) !void {
    const allocator = ctx.allocator;
    try validateDestination(allocator, ctx.repo.toplevel, info.plain, ctx.tracked, ctx.io);

    const parent = openParent(ctx.io, ctx.repo.toplevel, info.plain, true) catch return Error.UnsafePath;
    var dir = parent orelse return Error.UnsafePath;
    defer dir.close(ctx.io);
    const name = std.fs.path.basename(info.plain);

    var existing: ?std.Io.File.Permissions = null;
    if (dir.statFile(ctx.io, name, .{ .follow_symlinks = false })) |st| {
        if (st.kind != .file) return Error.UnsafePath;
        existing = st.permissions;
    } else |err| switch (err) {
        error.FileNotFound => {},
        else => return err,
    }
    if ((existing != null) != (info.values.cur != null)) return Error.ChangedDuringSync;

    const exec = info.values.new.?.exec;
    var atomic = try processor.AtomicOutput.create(name, .{}, ctx.repo.tmp_dir, allocator, ctx.io);
    defer atomic.deinit(ctx.io);
    try atomic.file.writeStreamingAll(ctx.io, info.decrypted.?);
    try atomic.setPermissions(ctx.io, plainPermissions(exec, existing));

    if (existing == null) {
        std.Io.Dir.renamePreserve(.cwd(), atomic.tmp_path, dir, name, ctx.io) catch |err| switch (err) {
            error.PathAlreadyExists => return Error.ChangedDuringSync,
            else => return Error.UnsafePath,
        };
        atomic.keep();
        return;
    }

    const old = try takePlace(ctx, &atomic, dir, name, info.plain);
    defer allocator.free(old.path);

    // From here on the old file is out of the tree and must come back to the user whatever happens.
    // A file that cannot even be read counts as changed.
    const matched = matchesAnalysis(ctx, old.path, info.values.cur) catch false;
    if (matched) {
        // An exchanged old file sits at the temporary path and goes away with deinit.
        if (old.aside) std.Io.Dir.deleteFile(.cwd(), ctx.io, old.path) catch {};
        return;
    }

    putBack(ctx, &atomic, dir, name, old) catch {
        keepSavedCopy(ctx, old.path, info.plain);
        atomic.keep();
        return Error.ChangedDuringSync;
    };
    const restored = fileHolds(ctx, atomic.tmp_path, info.decrypted.?) catch false;
    if (!restored) {
        keepSavedCopy(ctx, atomic.tmp_path, info.plain);
        atomic.keep();
    }
    return Error.ChangedDuringSync;
}

/// The old plain file once the new one took its place.
const OldFile = struct {
    path: []u8,
    /// Moved aside rather than exchanged, so the temporary path is free.
    aside: bool,
};

/// Put the new file in place and keep the old one where it can be inspected.
/// Without an exchange, the old file is moved aside first, so a save made in between is never lost.
fn takePlace(ctx: *const Context, atomic: *const processor.AtomicOutput, dir: std.Io.Dir, name: []const u8, plain: []const u8) !OldFile {
    const allocator = ctx.allocator;
    // The copy comes first, since an allocation failure after the exchange would cost the old file.
    const at_tmp = try allocator.dupe(u8, atomic.tmp_path);
    var exchanged = false;
    defer if (!exchanged) allocator.free(at_tmp);

    exchange(allocator, .cwd(), atomic.tmp_path, dir, name) catch |err| switch (err) {
        error.OutOfMemory => return err,
        SwapError.NotFound => return Error.ChangedDuringSync,
        SwapError.Unsupported => return moveAside(ctx, atomic, dir, name, plain),
        SwapError.Failed => return Error.UnsafePath,
    };
    exchanged = true;
    return .{ .path = at_tmp, .aside = false };
}

fn moveAside(ctx: *const Context, atomic: *const processor.AtomicOutput, dir: std.Io.Dir, name: []const u8, plain: []const u8) !OldFile {
    const io = ctx.io;
    const aside = try asidePath(ctx, "old", name);
    errdefer ctx.allocator.free(aside);
    std.Io.Dir.renamePreserve(dir, name, .cwd(), aside, io) catch |err| switch (err) {
        error.FileNotFound => return Error.ChangedDuringSync,
        else => return Error.UnsafePath,
    };
    std.Io.Dir.renamePreserve(.cwd(), atomic.tmp_path, dir, name, io) catch |err| {
        // The old file goes back, or is kept for the user when a save took its name.
        std.Io.Dir.renamePreserve(.cwd(), aside, dir, name, io) catch keepSavedCopy(ctx, aside, plain);
        return if (err == error.PathAlreadyExists) Error.ChangedDuringSync else Error.UnsafePath;
    };
    return .{ .path = aside, .aside = true };
}

/// Undo takePlace: the new file returns to the temporary path and the old file to its name.
/// On failure the old file stays where it is, for the caller to keep.
fn putBack(ctx: *const Context, atomic: *const processor.AtomicOutput, dir: std.Io.Dir, name: []const u8, old: OldFile) !void {
    const io = ctx.io;
    if (!old.aside) return exchange(ctx.allocator, .cwd(), atomic.tmp_path, dir, name);
    try std.Io.Dir.renamePreserve(dir, name, .cwd(), atomic.tmp_path, io);
    std.Io.Dir.renamePreserve(.cwd(), old.path, dir, name, io) catch |err| {
        // A save took the name again, and the store still holds the new content.
        std.Io.Dir.deleteFile(.cwd(), io, atomic.tmp_path) catch {};
        return err;
    };
}

/// Delete a plain file that the analysis found unmodified.
/// The file is moved aside first and inspected.
/// A save that landed in between is put back instead of being lost.
fn deletePlain(ctx: *const Context, info: *const PathInfo) !void {
    const allocator = ctx.allocator;
    const io = ctx.io;
    const parent = (try openParent(io, ctx.repo.toplevel, info.plain, false)) orelse return;
    var dir = parent;
    defer dir.close(io);
    const name = std.fs.path.basename(info.plain);

    const aside = try asidePath(ctx, "displaced", name);
    defer allocator.free(aside);
    std.Io.Dir.renamePreserve(dir, name, .cwd(), aside, io) catch |err| switch (err) {
        error.FileNotFound => return,
        else => return err,
    };

    const matched = matchesAnalysis(ctx, aside, info.values.cur) catch false;
    if (matched) {
        std.Io.Dir.deleteFile(.cwd(), io, aside) catch {};
        pruneEmptyParents(io, ctx.repo.toplevel, info.plain);
        return;
    }

    // The file changed since the analysis.
    // It goes back only into a free name, so a save that landed in the meantime is never overwritten.
    // When the name is taken, the moved file is kept as a copy instead.
    std.Io.Dir.renamePreserve(.cwd(), aside, dir, name, io) catch keepSavedCopy(ctx, aside, info.plain);
    return Error.ChangedDuringSync;
}

fn encryptPlain(ctx: *const Context, info: *PathInfo, stage: *std.ArrayList([]u8)) !void {
    const allocator = ctx.allocator;
    var plain_bytes: ?[]u8 = null;
    const cur = (try readCur(ctx, info.plain, &plain_bytes)) orelse return;
    defer allocator.free(plain_bytes.?);

    const cipher_rel = info.cipher_rel orelse blk: {
        info.cipher_rel = try filename_crypto.encryptPath(allocator, info.plain, ctx.keys.filename_key, '/');
        break :blk info.cipher_rel.?;
    };
    var dir = (try openParent(ctx.io, ctx.store_abs, cipher_rel, true)) orelse return Error.UnsafePath;
    defer dir.close(ctx.io);

    const encrypted = try crypto.encryptBound(plain_bytes.?, info.plain, ctx.keys, allocator, ctx.io);
    defer allocator.free(encrypted);
    const perms = if (cur.exec) cipher_exec_permissions else cipher_file_permissions;
    try processor.writeFileAtomicIn(dir, std.fs.path.basename(cipher_rel), encrypted, perms, ctx.repo.tmp_dir, allocator, ctx.io);

    info.values.new = .{ .id = crypto.ciphertextId(encrypted, ctx.keys.cipher_id_key), .exec = cur.exec };
    info.values.cur = cur;
    try stage.append(allocator, try storePath(allocator, &ctx.store_rel, cipher_rel));
}

fn recordBaseline(ctx: *Context, info: *const PathInfo) !void {
    const cur = info.values.cur orelse return;
    const new = info.values.new orelse return;
    try ctx.state.put(ctx.allocator, info.plain, .{ .plain = cur.plain, .exec = cur.exec, .id = new.id });
}

/// The exclude block holds the lines of every given manifest and the extra plain paths.
/// Lines the block held before stay, except those in `remove`.
///
/// The extra paths are store entries that no manifest covers, for example after a replayed manifest.
/// They must be ignored all the same.
pub fn updateExcludeFile(repo: *const Repo, manifests: []const *const Manifest, extra: []const []const u8, remove: []const []const u8) !void {
    const allocator = repo.allocator;
    const io = repo.io;
    const existing = try readExcludeText(repo);
    defer if (existing) |e| allocator.free(e);

    const previous = try manifest_mod.blockLines(allocator, existing orelse "");
    defer utils.freeList(allocator, previous);

    var add: std.ArrayList([]const u8) = .empty;
    defer add.deinit(allocator);
    try add.append(allocator, "/" ++ manifest_mod.manifest_name);
    for (manifests) |m| {
        for (m.lines.items) |line| {
            if (manifest_mod.parseLine(line) != null) try add.append(allocator, line);
        }
    }
    var extra_lines: std.ArrayList([]u8) = .empty;
    defer {
        for (extra_lines.items) |line| allocator.free(line);
        extra_lines.deinit(allocator);
    }
    for (extra) |plain| {
        if (coveredByAny(manifests, plain)) continue;
        const line = try std.fmt.allocPrint(allocator, "/{s}", .{plain});
        errdefer allocator.free(line);
        if (manifest_mod.parseLine(line) == null) {
            allocator.free(line);
            continue;
        }
        try extra_lines.append(allocator, line);
        try add.append(allocator, line);
    }

    const merged = try manifest_mod.mergeBlockLines(allocator, previous, add.items, remove);
    defer utils.freeList(allocator, merged);

    const text = try manifest_mod.renderExcludeText(allocator, existing, merged);
    defer allocator.free(text);
    if (existing != null and std.mem.eql(u8, existing.?, text)) return;

    if (std.fs.path.dirname(repo.exclude_path)) |dir| try utils.ensureDirectory(dir, io);
    try repo.ensureDirs();
    try processor.writeFileAtomic(repo.exclude_path, text, null, repo.tmp_dir, allocator, io);
}

fn coveredByAny(manifests: []const *const Manifest, plain: []const u8) bool {
    for (manifests) |manifest| {
        if (manifest.covering(plain) != null) return true;
    }
    return false;
}

fn readExcludeText(repo: *const Repo) !?[]u8 {
    return std.Io.Dir.readFileAlloc(.cwd(), repo.io, repo.exclude_path, repo.allocator, .limited(max_state_size)) catch |err| switch (err) {
        error.FileNotFound => null,
        else => return err,
    };
}

/// Exclude block lines that a removed manifest entry covered and that no remaining line covers.
/// `rm` drops them along with the entry itself, so the files become ordinary untracked files.
pub fn excludeLinesCoveredBy(repo: *const Repo, removed: []const manifest_mod.Entry, remaining: *const Manifest) ![][]u8 {
    const allocator = repo.allocator;
    const existing = (try readExcludeText(repo)) orelse return allocator.alloc([]u8, 0);
    defer allocator.free(existing);
    const lines = try manifest_mod.blockLines(allocator, existing);
    defer utils.freeList(allocator, lines);

    var out: std.ArrayList([]u8) = .empty;
    errdefer {
        for (out.items) |line| allocator.free(line);
        out.deinit(allocator);
    }
    for (lines) |line| {
        const entry = manifest_mod.parseLine(line) orelse continue;
        if (std.mem.eql(u8, entry.path, manifest_mod.manifest_name)) continue;
        var covered = false;
        for (removed) |r| {
            if (r.covers(entry.path) or std.mem.eql(u8, r.path, entry.path)) covered = true;
        }
        if (!covered or remaining.covering(entry.path) != null) continue;
        try out.append(allocator, try allocator.dupe(u8, line));
    }
    return out.toOwnedSlice(allocator);
}

/// Forget store entries: delete them, drop them from the index and from the state.
/// Used by `rm`. The plain files are left alone.
pub fn removeEntries(repo: *const Repo, keys: crypto.DerivedKeys, entries: []const Entry) !void {
    const allocator = repo.allocator;
    var state = try State.load(allocator, repo.state_path, crypto.keyId(keys.key_id_key), repo.io);
    defer state.deinit(allocator);
    const key_dir = keyDirRel(keys);
    const store_abs = try repo.absolutePath(&key_dir);
    defer allocator.free(store_abs);

    var staged: std.ArrayList([]u8) = .empty;
    defer {
        for (staged.items) |s| allocator.free(s);
        staged.deinit(allocator);
    }
    for (entries) |entry| {
        try deleteThroughHandles(repo.io, store_abs, entry.cipher_rel);
        state.remove(allocator, entry.plain);
        try staged.append(allocator, try storePath(allocator, &key_dir, entry.cipher_rel));
    }
    try repo.rmCached(staged.items);
    try repo.ensureDirs();
    try state.save(allocator, repo.state_path, repo.tmp_dir, repo.io);
}

/// Every entry of the key with its plain path.
/// Entries whose name does not decrypt are skipped.
pub fn storeEntries(repo: *const Repo, keys: crypto.DerivedKeys) ![]Entry {
    const allocator = repo.allocator;
    const store_abs = try keyDirAbs(repo, keys);
    defer allocator.free(store_abs);
    if (!utils.pathExists(store_abs, repo.io)) return allocator.alloc(Entry, 0);

    var bad: std.ArrayList([]u8) = .empty;
    defer {
        for (bad.items) |b| allocator.free(b);
        bad.deinit(allocator);
    }
    const files = try listStore(allocator, store_abs, &bad, repo.io);
    defer utils.freeList(allocator, files);

    var entries: std.ArrayList(Entry) = .empty;
    errdefer {
        for (entries.items) |entry| {
            allocator.free(entry.plain);
            allocator.free(entry.cipher_rel);
        }
        entries.deinit(allocator);
    }
    for (files) |cipher_rel| {
        const plain = filename_crypto.decryptPathStrict(allocator, cipher_rel, keys.filename_key) catch continue;
        errdefer allocator.free(plain);
        try entries.append(allocator, .{ .plain = plain, .cipher_rel = try allocator.dupe(u8, cipher_rel) });
    }
    return entries.toOwnedSlice(allocator);
}

/// Tracked files that a manifest line makes private, or that have a store entry.
/// They would go public with the next commit, so every commit is refused until they leave the index.
/// Lines that only the exclude block still holds belong to other branches and do not count here.
pub fn violations(ctx: *const Context, infos: []const PathInfo, report: *Report) !usize {
    const allocator = ctx.allocator;
    const entries = try ctx.manifest.?.entries(allocator);
    defer allocator.free(entries);
    var stored: std.StringHashMapUnmanaged(void) = .empty;
    defer stored.deinit(allocator);
    for (infos) |info| {
        if (info.cipher_rel != null) try stored.put(allocator, info.plain, {});
    }

    var n: usize = 0;
    for (ctx.tracked) |path| {
        if (manifest_mod.isReservedPath(path)) continue;
        const covered = std.mem.eql(u8, path, manifest_mod.manifest_name) or
            manifest_mod.anyCovers(entries, path) or
            stored.contains(path);
        if (covered) {
            try report.add(allocator, .tracked, path, "tracked by git, run: git rm --cached -- <path>");
            n += 1;
        }
    }
    return n;
}

/// The context and the analysis of one pass over every path.
const Pass = struct {
    ctx: Context,
    infos: []PathInfo,

    fn init(repo: *const Repo, keys: crypto.DerivedKeys, only: []const []const u8, report: *Report) !Pass {
        var ctx = try Context.init(repo, keys);
        errdefer ctx.deinit();
        if (ctx.manifest == null) return Error.NoManifest;
        const infos = try analyze(&ctx, only, report);
        return .{ .ctx = ctx, .infos = infos };
    }

    fn deinit(self: *Pass) void {
        freeInfos(self.ctx.allocator, self.infos);
        self.ctx.deinit();
    }

    /// Ignore every path that has a store entry, on top of the manifests.
    fn writeExcludeBlock(self: *const Pass) !void {
        const allocator = self.ctx.allocator;
        var extra: std.ArrayList([]const u8) = .empty;
        defer extra.deinit(allocator);
        for (self.infos) |info| {
            if (info.cipher_rel != null) try extra.append(allocator, info.plain);
        }
        var buf: [2]*const Manifest = undefined;
        try updateExcludeFile(self.ctx.repo, self.ctx.manifestsForExclude(&buf), extra.items, &.{});
    }
};

const merging_detail = "edit the plain file, then run: turbocrypt git encrypt --force <path>";

/// Report a decision that needs the user.
/// Returns true when it stops an encrypt pass.
fn reportProblem(allocator: std.mem.Allocator, info: *const PathInfo, report: *Report) !bool {
    switch (info.decision) {
        .abort_no_baseline => try report.add(allocator, .conflict, info.plain, "plain file and entry both exist and differ, no baseline: decrypt --force or encrypt --force"),
        .abort_both_changed => try report.add(allocator, .conflict, info.plain, "changed here and upstream: decrypt --force or encrypt --force"),
        .abort_bad => try report.add(allocator, .conflict, info.plain, "entry cannot be committed as it is: encrypt --force replaces it from the plain file, rm drops it"),
        .abort_plain => {},
        .warn_missing => {
            try report.add(allocator, .missing, info.plain, "entry present, plain file absent: decrypt restores it, rm deletes it");
            return false;
        },
        .warn_removed => {
            try report.add(allocator, .removed, info.plain, "entry removed upstream, plain file kept: decrypt deletes it, add keeps it");
            return false;
        },
        else => return false,
    }
    return true;
}

/// Write the plain file of a path from its decrypted entry and record the baseline.
/// Returns false when the write was refused, with the reason in the report.
fn applyWritePlain(ctx: *Context, info: *PathInfo, report: *Report) !bool {
    const allocator = ctx.allocator;
    const detail: []const u8 = if (info.values.cur != null)
        "entry changed, plain file updated"
    else if (info.values.old != null)
        "was absent, restored"
    else
        "";
    writePlain(ctx, info) catch |err| switch (err) {
        Error.UnsafePath => {
            try report.add(allocator, .bad, info.plain, "destination is not a safe file inside the working tree");
            return false;
        },
        Error.ChangedDuringSync => {
            try report.add(allocator, .conflict, info.plain, "changed while the sync ran, run it again");
            return false;
        },
        else => return err,
    };
    info.values.cur = .{ .plain = crypto.fingerprint(info.decrypted.?, ctx.keys.fingerprint_key), .exec = info.values.new.?.exec };
    try recordBaseline(ctx, info);
    try report.add(allocator, .written, info.plain, detail);
    return true;
}

/// The encrypt direction. Plans every path first, then writes, so an abort changes nothing.
pub fn encryptSync(repo: *const Repo, keys: crypto.DerivedKeys, options: Options, report: *Report) !void {
    const allocator = repo.allocator;
    var pass = try Pass.init(repo, keys, options.only, report);
    defer pass.deinit();
    const ctx = &pass.ctx;

    if (try violations(ctx, pass.infos, report) > 0) return Error.PrivateFileTracked;

    var aborted = false;
    for (pass.infos) |*info| {
        if (info.cipher_rel != null and ctx.isUnmerged(info.cipher_rel.?) and !options.force) {
            try report.add(allocator, .merging, info.plain, merging_detail);
            aborted = true;
            info.decision = .none;
            continue;
        }
        try decide(ctx, info, .encrypt, options.force, report);
        if (try reportProblem(allocator, info, report)) aborted = true;
        switch (info.decision) {
            .encrypt, .write_plain, .record, .delete_plain, .drop_baseline => report.pending += 1,
            else => {},
        }
        if (info.decision == .encrypt and !options.force) {
            if (info.values.new) |new| if (!new.header_ok) {
                try report.add(allocator, .bad, info.plain, "entry was written with another key or is corrupted: encrypt --force replaces it");
                aborted = true;
            };
        }
    }
    if (aborted) return Error.SyncAborted;
    if (options.validate_only) return;

    var stage: std.ArrayList([]u8) = .empty;
    defer {
        for (stage.items) |s| allocator.free(s);
        stage.deinit(allocator);
    }
    for (pass.infos) |*info| {
        switch (info.decision) {
            .encrypt => {
                try encryptPlain(ctx, info, &stage);
                try recordBaseline(ctx, info);
                try report.add(allocator, .encrypted, info.plain, "");
            },
            .write_plain => if (!try applyWritePlain(ctx, info, report)) continue,
            .record => {
                try recordBaseline(ctx, info);
                try report.add(allocator, .ok, info.plain, "");
            },
            .drop_baseline => ctx.state.remove(allocator, info.plain),
            .none => if (info.values.new != null and info.values.cur != null) try report.add(allocator, .ok, info.plain, ""),
            else => {},
        }
        if (info.cipher_rel != null and info.values.new != null and info.decision != .encrypt and !info.bad) {
            try stage.append(allocator, try storePath(allocator, &ctx.store_rel, info.cipher_rel.?));
        }
    }

    try ctx.state.save(allocator, repo.state_path, repo.tmp_dir, ctx.io);
    try pass.writeExcludeBlock();
    try repo.addForce(stage.items);
}

/// The decrypt direction. The exclude block is written before any plain file, so nothing private is ever unignored.
pub fn decryptSync(repo: *const Repo, keys: crypto.DerivedKeys, options: Options, report: *Report) !void {
    const allocator = repo.allocator;
    var pass = try Pass.init(repo, keys, options.only, report);
    defer pass.deinit();
    const ctx = &pass.ctx;

    for (pass.infos) |*info| {
        try decide(ctx, info, .decrypt, options.force, report);
    }
    if (options.validate_only) return;
    try pass.writeExcludeBlock();

    for (pass.infos) |*info| {
        switch (info.decision) {
            .write_plain => _ = try applyWritePlain(ctx, info, report),
            .delete_plain => {
                deletePlain(ctx, info) catch |err| switch (err) {
                    Error.ChangedDuringSync => {
                        try report.add(allocator, .conflict, info.plain, "changed while the sync ran, run it again");
                        continue;
                    },
                    else => return err,
                };
                ctx.state.remove(allocator, info.plain);
                try report.add(allocator, .deleted, info.plain, "entry removed upstream");
            },
            .record => {
                try recordBaseline(ctx, info);
                try report.add(allocator, .ok, info.plain, "");
            },
            .drop_baseline => ctx.state.remove(allocator, info.plain),
            .conflict => try report.add(allocator, .conflict, info.plain, "changed here and upstream: decrypt --force <path> takes the upstream version"),
            .warn_removed => try report.add(allocator, .removed, info.plain, "entry removed upstream, plain file modified and kept"),
            .none => if (info.values.new != null and info.values.cur != null) try report.add(allocator, .ok, info.plain, ""),
            else => {},
        }
    }
    try ctx.state.save(allocator, repo.state_path, repo.tmp_dir, ctx.io);
}

/// Rows for `turbocrypt git status`. Nothing is written.
pub fn collectStatus(repo: *const Repo, keys: crypto.DerivedKeys, report: *Report) !void {
    const allocator = repo.allocator;
    var pass = try Pass.init(repo, keys, &.{}, report);
    defer pass.deinit();
    const ctx = &pass.ctx;

    _ = try violations(ctx, pass.infos, report);

    for (pass.infos) |*info| {
        if (info.cipher_rel != null and ctx.isUnmerged(info.cipher_rel.?)) {
            try report.add(allocator, .merging, info.plain, merging_detail);
            continue;
        }
        try decide(ctx, info, .encrypt, false, report);
        if (try reportProblem(allocator, info, report) or info.bad) continue;
        const v = info.values;
        switch (info.decision) {
            .none => if (v.cur != null) try report.add(allocator, .ok, info.plain, ""),
            .encrypt => if (v.old == null and v.new == null)
                try report.add(allocator, .new, info.plain, "no entry yet, " ++ pending_detail)
            else
                try report.add(allocator, .modified, info.plain, pending_detail),
            .write_plain => try report.add(allocator, .incoming, info.plain, "entry changed, run: turbocrypt git decrypt"),
            .record => try report.add(allocator, .ok, info.plain, "same content on both sides"),
            else => {},
        }
    }
}

test "exchange and rename preserve" {
    const testing = std.testing;
    const io = testing.io;

    try std.Io.Dir.createDirPath(.cwd(), io, "tmp/swap");
    defer std.Io.Dir.deleteTree(.cwd(), io, "tmp/swap") catch {};
    try std.Io.Dir.writeFile(.cwd(), io, .{ .sub_path = "tmp/swap/a", .data = "A" });
    try std.Io.Dir.writeFile(.cwd(), io, .{ .sub_path = "tmp/swap/b", .data = "B" });

    try testing.expectError(error.PathAlreadyExists, std.Io.Dir.renamePreserve(.cwd(), "tmp/swap/a", .cwd(), "tmp/swap/b", io));
    try std.Io.Dir.renamePreserve(.cwd(), "tmp/swap/a", .cwd(), "tmp/swap/c", io);
    try testing.expectError(error.FileNotFound, std.Io.Dir.renamePreserve(.cwd(), "tmp/swap/a", .cwd(), "tmp/swap/d", io));

    exchange(testing.allocator, .cwd(), "tmp/swap/c", .cwd(), "tmp/swap/b") catch |err| switch (err) {
        SwapError.Unsupported => return error.SkipZigTest,
        else => return err,
    };
    const c = try std.Io.Dir.readFileAlloc(.cwd(), io, "tmp/swap/c", testing.allocator, .limited(8));
    defer testing.allocator.free(c);
    try testing.expectEqualStrings("B", c);
}

test "replace without an exchange keeps the old file inspectable" {
    const testing = std.testing;
    const allocator = testing.allocator;
    const io = testing.io;

    try std.Io.Dir.createDirPath(.cwd(), io, "tmp/aside/tree");
    try std.Io.Dir.createDirPath(.cwd(), io, "tmp/aside/tmp");
    defer std.Io.Dir.deleteTree(.cwd(), io, "tmp/aside") catch {};
    try std.Io.Dir.writeFile(.cwd(), io, .{ .sub_path = "tmp/aside/tree/note.md", .data = "old" });

    var env = try std.process.Environ.createMap(testing.environ, allocator);
    defer env.deinit();
    const tmp_dir = try allocator.dupe(u8, "tmp/aside/tmp");
    defer allocator.free(tmp_dir);
    const repo = Repo{
        .allocator = allocator,
        .io = io,
        .environ_map = &env,
        .toplevel = &.{},
        .git_dir = &.{},
        .common_dir = &.{},
        .hooks_dir = &.{},
        .exclude_path = &.{},
        .prefix = &.{},
        .private_dir = &.{},
        .key_path = &.{},
        .state_path = &.{},
        .tmp_dir = tmp_dir,
        .lock_path = &.{},
        .pathspec_path = &.{},
        .precompose = null,
    };
    const ctx = Context{
        .repo = &repo,
        .keys = undefined,
        .allocator = allocator,
        .io = io,
        .state = .{ .key_id = @splat(0) },
        .manifest = null,
        .store_manifest = null,
        .store_rel = undefined,
        .store_abs = &.{},
        .tracked = &.{},
        .unmerged = &.{},
    };

    var dir = try std.Io.Dir.openDir(.cwd(), io, "tmp/aside/tree", .{});
    defer dir.close(io);
    var atomic = try processor.AtomicOutput.create("note.md", .{}, tmp_dir, allocator, io);
    defer atomic.deinit(io);
    try atomic.file.writeStreamingAll(io, "new");

    const old = try moveAside(&ctx, &atomic, dir, "note.md", "note.md");
    defer allocator.free(old.path);
    try testing.expect(old.aside);
    try testing.expect(try fileHolds(&ctx, "tmp/aside/tree/note.md", "new"));
    try testing.expect(try fileHolds(&ctx, old.path, "old"));

    try putBack(&ctx, &atomic, dir, "note.md", old);
    try testing.expect(try fileHolds(&ctx, "tmp/aside/tree/note.md", "old"));
    try testing.expect(try fileHolds(&ctx, atomic.tmp_path, "new"));
}

test "key directory names" {
    const testing = std.testing;

    const a = keyDirRel(crypto.deriveKeys(@splat(1), null));
    const again = keyDirRel(crypto.deriveKeys(@splat(1), null));
    const b = keyDirRel(crypto.deriveKeys(@splat(2), null));

    try testing.expectEqualStrings(&a, &again);
    try testing.expect(!std.mem.eql(u8, &a, &b));
    try testing.expect(std.mem.startsWith(u8, &a, enc_dir ++ "/"));
    for (a[enc_dir.len + 1 ..]) |c| try testing.expect(std.ascii.isHex(c) and !std.ascii.isUpper(c));
}

test "decrypt direction decisions" {
    const testing = std.testing;
    const b1 = Baseline{ .plain = @splat(1), .exec = false, .id = @splat(9) };
    const c_same = Cur{ .plain = @splat(1), .exec = false };
    const c_other = Cur{ .plain = @splat(2), .exec = false };
    const c_exec = Cur{ .plain = @splat(1), .exec = true };
    const n_same = New{ .id = @splat(9), .exec = false };
    const n_other = New{ .id = @splat(8), .exec = false };

    try testing.expectEqual(Decision.none, decideDecrypt(.{ .old = null, .new = null, .cur = c_same }, false));
    try testing.expectEqual(Decision.write_plain, decideDecrypt(.{ .old = null, .new = n_same, .cur = null }, false));
    try testing.expectEqual(Decision.need_compare, decideDecrypt(.{ .old = null, .new = n_same, .cur = c_same }, false));
    try testing.expectEqual(Decision.record, decideDecrypt(.{ .old = null, .new = n_same, .cur = c_same, .cur_eq_new = true }, false));
    try testing.expectEqual(Decision.conflict, decideDecrypt(.{ .old = null, .new = n_same, .cur = c_same, .cur_eq_new = false }, false));
    try testing.expectEqual(Decision.write_plain, decideDecrypt(.{ .old = null, .new = n_same, .cur = c_same, .cur_eq_new = false }, true));
    try testing.expectEqual(Decision.drop_baseline, decideDecrypt(.{ .old = b1, .new = null, .cur = null }, false));
    try testing.expectEqual(Decision.delete_plain, decideDecrypt(.{ .old = b1, .new = null, .cur = c_same }, false));
    try testing.expectEqual(Decision.warn_removed, decideDecrypt(.{ .old = b1, .new = null, .cur = c_other }, false));
    try testing.expectEqual(Decision.delete_plain, decideDecrypt(.{ .old = b1, .new = null, .cur = c_other }, true));
    try testing.expectEqual(Decision.write_plain, decideDecrypt(.{ .old = b1, .new = n_same, .cur = null }, false));
    try testing.expectEqual(Decision.write_plain, decideDecrypt(.{ .old = b1, .new = n_other, .cur = null }, false));
    try testing.expectEqual(Decision.none, decideDecrypt(.{ .old = b1, .new = n_same, .cur = c_other }, false));
    try testing.expectEqual(Decision.write_plain, decideDecrypt(.{ .old = b1, .new = n_other, .cur = c_same }, false));
    try testing.expectEqual(Decision.need_compare, decideDecrypt(.{ .old = b1, .new = n_other, .cur = c_other }, false));
    try testing.expectEqual(Decision.record, decideDecrypt(.{ .old = b1, .new = n_other, .cur = c_other, .cur_eq_new = true }, false));
    try testing.expectEqual(Decision.conflict, decideDecrypt(.{ .old = b1, .new = n_other, .cur = c_other, .cur_eq_new = false }, false));
    try testing.expectEqual(Decision.write_plain, decideDecrypt(.{ .old = b1, .new = n_other, .cur = c_other, .cur_eq_new = false }, true));
    try testing.expectEqual(Decision.write_plain, decideDecrypt(.{ .old = b1, .new = .{ .id = @splat(9), .exec = true }, .cur = c_same }, false));
    try testing.expectEqual(Decision.need_compare, decideDecrypt(.{ .old = b1, .new = n_other, .cur = c_exec }, false));
}

test "encrypt direction decisions" {
    const testing = std.testing;
    const b1 = Baseline{ .plain = @splat(1), .exec = false, .id = @splat(9) };
    const c_same = Cur{ .plain = @splat(1), .exec = false };
    const c_other = Cur{ .plain = @splat(2), .exec = false };
    const c_exec = Cur{ .plain = @splat(1), .exec = true };
    const n_same = New{ .id = @splat(9), .exec = false };
    const n_other = New{ .id = @splat(8), .exec = false };

    try testing.expectEqual(Decision.none, decideEncrypt(.{ .old = null, .new = null, .cur = null }, false));
    try testing.expectEqual(Decision.encrypt, decideEncrypt(.{ .old = null, .new = null, .cur = c_same }, false));
    try testing.expectEqual(Decision.warn_missing, decideEncrypt(.{ .old = null, .new = n_same, .cur = null }, false));
    try testing.expectEqual(Decision.need_compare, decideEncrypt(.{ .old = null, .new = n_same, .cur = c_same }, false));
    try testing.expectEqual(Decision.record, decideEncrypt(.{ .old = null, .new = n_same, .cur = c_same, .cur_eq_new = true }, false));
    try testing.expectEqual(Decision.abort_no_baseline, decideEncrypt(.{ .old = null, .new = n_same, .cur = c_same, .cur_eq_new = false }, false));
    try testing.expectEqual(Decision.encrypt, decideEncrypt(.{ .old = null, .new = n_same, .cur = c_same, .cur_eq_new = false }, true));
    try testing.expectEqual(Decision.drop_baseline, decideEncrypt(.{ .old = b1, .new = null, .cur = null }, false));
    try testing.expectEqual(Decision.warn_removed, decideEncrypt(.{ .old = b1, .new = null, .cur = c_same }, false));
    try testing.expectEqual(Decision.encrypt, decideEncrypt(.{ .old = b1, .new = null, .cur = c_same }, true));
    try testing.expectEqual(Decision.warn_missing, decideEncrypt(.{ .old = b1, .new = n_other, .cur = null }, false));
    try testing.expectEqual(Decision.none, decideEncrypt(.{ .old = b1, .new = n_same, .cur = c_same }, false));
    try testing.expectEqual(Decision.encrypt, decideEncrypt(.{ .old = b1, .new = n_same, .cur = c_other }, false));
    try testing.expectEqual(Decision.encrypt, decideEncrypt(.{ .old = b1, .new = n_same, .cur = c_exec }, false));
    try testing.expectEqual(Decision.write_plain, decideEncrypt(.{ .old = b1, .new = n_other, .cur = c_same }, false));
    try testing.expectEqual(Decision.need_compare, decideEncrypt(.{ .old = b1, .new = n_other, .cur = c_other }, false));
    try testing.expectEqual(Decision.record, decideEncrypt(.{ .old = b1, .new = n_other, .cur = c_other, .cur_eq_new = true }, false));
    try testing.expectEqual(Decision.abort_both_changed, decideEncrypt(.{ .old = b1, .new = n_other, .cur = c_other, .cur_eq_new = false }, false));
    try testing.expectEqual(Decision.encrypt, decideEncrypt(.{ .old = b1, .new = n_other, .cur = c_other, .cur_eq_new = false }, true));
}

test "bad path decisions" {
    const testing = std.testing;
    const cur = Cur{ .plain = @splat(1), .exec = false };

    var plain_only = PathInfo{ .plain = @constCast("a"), .values = .{ .old = null, .new = null, .cur = cur }, .bad = true };
    try testing.expectEqual(Decision.abort_plain, badDecision(&plain_only, .encrypt, true));
    try testing.expectEqual(Decision.none, badDecision(&plain_only, .decrypt, false));
    plain_only.values.cur = null;
    try testing.expectEqual(Decision.abort_plain, badDecision(&plain_only, .encrypt, false));

    var entry = PathInfo{ .plain = @constCast("a"), .cipher_rel = @constCast("b"), .values = .{ .old = null, .new = null, .cur = cur }, .bad = true };
    try testing.expectEqual(Decision.abort_bad, badDecision(&entry, .encrypt, false));
    try testing.expectEqual(Decision.encrypt, badDecision(&entry, .encrypt, true));
    entry.values.cur = null;
    try testing.expectEqual(Decision.abort_bad, badDecision(&entry, .encrypt, true));
    try testing.expectEqual(Decision.none, badDecision(&entry, .decrypt, true));
}

test "state round trip" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const key_id: [crypto.mac_length]u8 = @splat(5);
    var state = State{ .key_id = key_id };
    defer state.deinit(allocator);
    try state.put(allocator, "docs/internal.md", .{ .plain = @splat(0xab), .exec = true, .id = @splat(0xcd) });
    try state.put(allocator, "AGENT.md", .{ .plain = @splat(1), .exec = false, .id = @splat(2) });
    try state.put(allocator, "AGENT.md", .{ .plain = @splat(3), .exec = false, .id = @splat(4) });

    const text = try state.render(allocator);
    defer allocator.free(text);

    var loaded = try State.parse(allocator, text, key_id);
    defer loaded.deinit(allocator);
    try testing.expectEqual(@as(usize, 2), loaded.map.count());
    const doc = loaded.get("docs/internal.md").?;
    try testing.expect(doc.exec);
    try testing.expectEqualSlices(u8, &@as([16]u8, @splat(0xab)), &doc.plain);
    try testing.expectEqualSlices(u8, &@as([16]u8, @splat(0xcd)), &doc.id);
    try testing.expectEqualSlices(u8, &@as([16]u8, @splat(3)), &loaded.get("AGENT.md").?.plain);

    loaded.remove(allocator, "AGENT.md");
    try testing.expect(loaded.get("AGENT.md") == null);

    var other = try State.parse(allocator, text, @splat(6));
    defer other.deinit(allocator);
    try testing.expectEqual(@as(usize, 0), other.map.count());

    try testing.expectError(Error.InvalidState, State.parse(allocator, "{\"version\": 2, \"entries\": []}", key_id));
    try testing.expectError(Error.InvalidState, State.parse(allocator, "not json", key_id));
}

test "destination validation" {
    const testing = std.testing;
    const allocator = testing.allocator;
    const io = testing.io;

    try std.Io.Dir.createDirPath(.cwd(), io, "tmp/sync_dest/real");
    defer std.Io.Dir.deleteTree(.cwd(), io, "tmp/sync_dest") catch {};
    try std.Io.Dir.writeFile(.cwd(), io, .{ .sub_path = "tmp/sync_dest/plainfile", .data = "x" });
    const toplevel = try std.Io.Dir.realPathFileAlloc(.cwd(), io, "tmp/sync_dest", allocator);
    defer allocator.free(toplevel);

    const tracked = [_][]const u8{"tracked.md"};
    try validateDestination(allocator, toplevel, "real/new.md", &tracked, io);
    try validateDestination(allocator, toplevel, "fresh/dir/new.md", &tracked, io);
    try testing.expectError(Error.UnsafePath, validateDestination(allocator, toplevel, "/abs", &tracked, io));
    try testing.expectError(Error.UnsafePath, validateDestination(allocator, toplevel, "../up", &tracked, io));
    try testing.expectError(Error.UnsafePath, validateDestination(allocator, toplevel, "a/../b", &tracked, io));
    try testing.expectError(Error.UnsafePath, validateDestination(allocator, toplevel, ".git/config", &tracked, io));
    try testing.expectError(Error.UnsafePath, validateDestination(allocator, toplevel, "tracked.md", &tracked, io));
    try testing.expectError(Error.UnsafePath, validateDestination(allocator, toplevel, "plainfile/child", &tracked, io));

    const target = try std.fs.path.join(allocator, &.{ toplevel, "real" });
    defer allocator.free(target);
    std.Io.Dir.symLink(.cwd(), io, target, "tmp/sync_dest/link", .{}) catch return error.SkipZigTest;
    try testing.expectError(Error.UnsafePath, validateDestination(allocator, toplevel, "link/new.md", &tracked, io));
    try testing.expectError(Error.UnsafePath, validateDestination(allocator, toplevel, "link", &tracked, io));
}
