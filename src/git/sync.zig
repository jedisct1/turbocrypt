//! Coordinates private files between the working tree and encrypted store.
//! Each path can have a baseline from the last sync, an encrypted entry, and a plain file.
//! A pass compares those versions before changing either side.
//! It chooses a safe outcome for every path first.
//! This avoids partially updating the working tree or store.
//!

const std = @import("std");
const builtin = @import("builtin");
const mem = std.mem;
const testing = std.testing;
const Allocator = std.mem.Allocator;
const Io = std.Io;

const crypto = @import("../crypto.zig");
const filename_crypto = @import("../filename_crypto.zig");
const processor = @import("../processor.zig");
const fs = @import("../fs.zig");
const git = @import("../git.zig");
const Manifest = @import("Manifest.zig");
const Repo = @import("Repo.zig");

pub const enc_dir = ".enc";
pub const marker_name = ".turbocrypt";
pub const marker_text = "turbocrypt-git 1\n";
pub const attributes_name = ".gitattributes";
pub const attributes_text =
    \\* binary -filter -ident -working-tree-encoding -export-subst
    \\/README.txt text diff merge
    \\
;
pub const readme_name = "README.txt";
pub const readme_text = @embedFile("store-readme.txt");

/// Private files are handled as whole documents.
/// The size limit keeps memory use predictable.
pub const max_file_size: u64 = 256 * 1024 * 1024;

pub const long_name_detail = "name too long once encrypted, keep components under about 200 bytes";
pub const pending_detail = "encrypted at the next commit";

const state_version = 1;
const max_state_size = 64 * 1024 * 1024;

/// `readFileAlloc` treats its limit as exclusive, so add one to accept the documented maximum.
fn readLimit(max_size: u64) Io.Limit {
    return .limited64(max_size + 1);
}

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

pub const plain_file_permissions: Io.File.Permissions =
    if (builtin.os.tag == .windows) .default_file else .fromMode(0o600);
const cipher_file_permissions: Io.File.Permissions =
    if (builtin.os.tag == .windows) .default_file else .fromMode(0o644);
const cipher_exec_permissions: Io.File.Permissions =
    if (builtin.os.tag == .windows) .default_file else .fromMode(0o755);

/// Records the version observed at the last successful sync.
pub const Baseline = struct {
    plain: [crypto.fingerprint_length]u8,
    exec: bool,
    id: [crypto.cipher_id_length]u8,
};

/// Describes the plain file currently in the working tree.
pub const Current = struct {
    plain: [crypto.fingerprint_length]u8,
    exec: bool,
};

/// Describes the encrypted entry currently in the store.
pub const New = struct {
    id: [crypto.cipher_id_length]u8,
    exec: bool,
    /// False when this entry was not encrypted with the active key.
    header_ok: bool = true,
};

pub const Values = struct {
    old: ?Baseline,
    new: ?New,
    cur: ?Current,
    /// Set only after decryption confirms whether both versions match.
    cur_eql_new: ?bool = null,

    pub fn newEqlOld(v: Values) bool {
        const o = v.old orelse return false;
        const n = v.new orelse return false;
        return mem.eql(u8, &o.id, &n.id) and o.exec == n.exec;
    }

    pub fn curEqlOld(v: Values) bool {
        const o = v.old orelse return false;
        const c = v.cur orelse return false;
        return mem.eql(u8, &o.plain, &c.plain) and o.exec == c.exec;
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
    const eq = v.cur_eql_new orelse return .need_compare;
    return if (eq) equal else different;
}

/// Chooses a decrypt action, treating the store as the source of truth.
pub fn decideDecrypt(v: Values, force: bool) Decision {
    if (v.old == null and v.new == null) return .none;
    if (v.old == null and v.cur == null) return .write_plain;
    if (v.old == null) return compareOr(v, .record, if (force) .write_plain else .conflict);
    if (v.new == null and v.cur == null) return .drop_baseline;
    if (v.new == null) return if (v.curEqlOld() or force) .delete_plain else .warn_removed;
    if (v.cur == null) return .write_plain;
    if (v.newEqlOld()) return .none;
    if (v.curEqlOld()) return .write_plain;
    return compareOr(v, .record, if (force) .write_plain else .conflict);
}

/// Chooses an encrypt action, treating the plain file as the source of truth.
/// Conflicting changes are never resolved automatically.
pub fn decideEncrypt(v: Values, force: bool) Decision {
    if (v.old == null and v.new == null and v.cur == null) return .none;
    if (v.old == null and v.new == null) return .encrypt;
    if (v.old == null and v.cur == null) return .warn_missing;
    if (v.old == null) return compareOr(v, .record, if (force) .encrypt else .abort_no_baseline);
    if (v.new == null and v.cur == null) return .drop_baseline;
    if (v.new == null) return if (force) .encrypt else .warn_removed;
    if (v.cur == null) return .warn_missing;
    if (v.newEqlOld()) return if (v.curEqlOld()) .none else .encrypt;
    if (v.curEqlOld()) return .write_plain;
    return compareOr(v, .record, if (force) .encrypt else .abort_both_changed);
}

fn decideFor(v: Values, direction: Direction, force: bool) Decision {
    return switch (direction) {
        .encrypt => decideEncrypt(v, force),
        .decrypt => decideDecrypt(v, force),
    };
}

/// Stores the last synchronized version of each path under the Git directory.
/// Keying the state makes another key's entries appear new instead of sharing history.
pub const State = struct {
    key_id: [crypto.mac_length]u8,
    map: std.array_hash_map.String(Baseline) = .empty,

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

    pub fn load(gpa: Allocator, io: Io, path: []const u8, key_id: [crypto.mac_length]u8) !State {
        const limit = readLimit(max_state_size);
        const text = Io.Dir.readFileAlloc(.cwd(), io, path, gpa, limit) catch |err| switch (err) {
            error.FileNotFound => return .{ .key_id = key_id },
            else => return err,
        };
        defer gpa.free(text);
        return parse(gpa, text, key_id);
    }

    pub fn parse(gpa: Allocator, text: []const u8, key_id: [crypto.mac_length]u8) !State {
        const parsed = std.json.parseFromSlice(JsonState, gpa, text, .{
            .ignore_unknown_fields = true,
        }) catch return Error.InvalidState;
        defer parsed.deinit();
        if (parsed.value.version != state_version) return Error.InvalidState;

        var state: State = .{ .key_id = key_id };
        errdefer state.deinit(gpa);
        var stored: [crypto.mac_length]u8 = undefined;
        _ = std.fmt.hexToBytes(&stored, &parsed.value.key) catch return Error.InvalidState;
        if (!mem.eql(u8, &stored, &key_id)) return state;
        for (parsed.value.entries) |entry| {
            var baseline: Baseline = .{ .plain = undefined, .exec = entry.exec, .id = undefined };
            _ = std.fmt.hexToBytes(&baseline.plain, &entry.plain) catch return Error.InvalidState;
            _ = std.fmt.hexToBytes(&baseline.id, &entry.id) catch return Error.InvalidState;
            try state.put(gpa, entry.path, baseline);
        }
        return state;
    }

    pub fn render(self: State, gpa: Allocator) ![]u8 {
        var entries: std.ArrayList(JsonEntry) = .empty;
        defer entries.deinit(gpa);
        var it = self.map.iterator();
        while (it.next()) |kv| {
            try entries.append(gpa, .{
                .path = kv.key_ptr.*,
                .plain = std.fmt.bytesToHex(kv.value_ptr.plain, .lower),
                .exec = kv.value_ptr.exec,
                .id = std.fmt.bytesToHex(kv.value_ptr.id, .lower),
            });
        }
        mem.sort(JsonEntry, entries.items, {}, struct {
            fn lessThan(_: void, a: JsonEntry, b: JsonEntry) bool {
                return mem.lessThan(u8, a.path, b.path);
            }
        }.lessThan);
        const json: JsonState = .{
            .version = state_version,
            .key = std.fmt.bytesToHex(self.key_id, .lower),
            .entries = entries.items,
        };
        return std.json.Stringify.valueAlloc(gpa, json, .{ .whitespace = .indent_2 });
    }

    pub fn save(self: State, gpa: Allocator, io: Io, path: []const u8, tmp_dir: []const u8) !void {
        const text = try self.render(gpa);
        defer gpa.free(text);
        try processor.writeFileAtomic(gpa, io, path, text, plain_file_permissions, tmp_dir);
    }

    pub fn get(self: State, path: []const u8) ?Baseline {
        return self.map.get(path);
    }

    pub fn put(self: *State, gpa: Allocator, path: []const u8, baseline: Baseline) !void {
        if (self.map.getPtr(path)) |existing| {
            existing.* = baseline;
            return;
        }
        const key = try gpa.dupe(u8, path);
        errdefer gpa.free(key);
        try self.map.put(gpa, key, baseline);
    }

    pub fn remove(self: *State, gpa: Allocator, path: []const u8) void {
        if (self.map.fetchOrderedRemove(path)) |kv| gpa.free(kv.key);
    }

    pub fn deinit(self: *State, gpa: Allocator) void {
        for (self.map.keys()) |key| gpa.free(key);
        self.map.deinit(gpa);
    }
};

pub fn keyDirName(keys: crypto.DerivedKeys) [2 * crypto.mac_length]u8 {
    return std.fmt.bytesToHex(crypto.keyId(keys.key_id_key), .lower);
}

pub const key_dir_len = enc_dir.len + 1 + 2 * crypto.mac_length;

/// Returns this key's directory in the store, relative to the repository root.
/// Each key reads and writes only its own manifest and entries.
/// That lets several keys safely share one repository.
pub fn keyDirRel(keys: crypto.DerivedKeys) [key_dir_len]u8 {
    var out: [key_dir_len]u8 = undefined;
    @memcpy(out[0 .. enc_dir.len + 1], enc_dir ++ "/");
    @memcpy(out[enc_dir.len + 1 ..], &keyDirName(keys));
    return out;
}

/// Returns this key's store directory as an absolute path. Caller owns the memory.
///
pub fn keyDirAbs(repo: *const Repo, keys: crypto.DerivedKeys) ![]u8 {
    const rel = keyDirRel(keys);
    return repo.absolutePath(&rel);
}

/// Builds a store-entry path relative to the repository root. Caller owns the memory.
///
pub fn storePath(gpa: Allocator, key_dir: []const u8, cipher_rel: []const u8) ![]u8 {
    return gpa.print("{s}/{s}", .{ key_dir, cipher_rel });
}

/// Accepts only regular files inside real directories beneath the working tree.
/// This prevents paths from escaping through links or special files.
/// Tracked paths are also refused because a checkout could overwrite a private write.
pub fn validateDestination(
    gpa: Allocator,
    io: Io,
    toplevel: []const u8,
    plain: []const u8,
    tracked: []const []const u8,
) !void {
    if (plain.len == 0 or plain[0] == '/') return Error.UnsafePath;
    var it = mem.splitScalar(u8, plain, '/');
    while (it.next()) |component| {
        if (!filename_crypto.isSafeComponent(component)) return Error.UnsafePath;
    }
    if (Manifest.isReservedPath(plain)) return Error.UnsafePath;
    if (git.containsString(tracked, plain)) return Error.UnsafePath;

    const no_follow: Io.Dir.StatFileOptions = .{ .follow_symlinks = false };
    var end: usize = 0;
    while (mem.findScalarPos(u8, plain, end, '/')) |i| : (end = i + 1) {
        const ancestor = try Io.Dir.path.join(gpa, &.{ toplevel, plain[0..i] });
        defer gpa.free(ancestor);
        const stat = Io.Dir.statFile(.cwd(), io, ancestor, no_follow) catch |err| switch (err) {
            error.FileNotFound => continue,
            else => return err,
        };
        if (stat.kind != .directory) return Error.UnsafePath;
    }
    const full = try Io.Dir.path.join(gpa, &.{ toplevel, plain });
    defer gpa.free(full);
    const stat = Io.Dir.statFile(.cwd(), io, full, no_follow) catch |err| switch (err) {
        error.FileNotFound => return,
        else => return err,
    };
    if (stat.kind != .file) return Error.UnsafePath;
}

/// Lists regular store files in sorted key-directory-relative order.
/// Other entry types are returned through `bad` so callers can report them safely.
/// Caller owns the returned paths.
pub fn listStore(
    gpa: Allocator,
    io: Io,
    store_abs: []const u8,
    bad: *std.ArrayList([]u8),
) ![][]u8 {
    var files: std.ArrayList([]u8) = .empty;
    errdefer {
        for (files.items) |f| gpa.free(f);
        files.deinit(gpa);
    }
    try listStoreDir(gpa, io, store_abs, "", &files, bad);
    mem.sort([]u8, files.items, {}, struct {
        fn lessThan(_: void, a: []u8, b: []u8) bool {
            return mem.lessThan(u8, a, b);
        }
    }.lessThan);
    return files.toOwnedSlice(gpa);
}

fn listStoreDir(
    gpa: Allocator,
    io: Io,
    store_abs: []const u8,
    rel: []const u8,
    files: *std.ArrayList([]u8),
    bad: *std.ArrayList([]u8),
) !void {
    const dir_path = if (rel.len == 0)
        try gpa.dupe(u8, store_abs)
    else
        try Io.Dir.path.join(gpa, &.{ store_abs, rel });
    defer gpa.free(dir_path);

    var dir = try Io.Dir.openDir(.cwd(), io, dir_path, .{
        .iterate = true,
        .follow_symlinks = false,
    });
    defer dir.close(io);

    var it = dir.iterate();
    while (try it.next(io)) |entry| {
        const child = if (rel.len == 0)
            try gpa.dupe(u8, entry.name)
        else
            try gpa.print("{s}/{s}", .{ rel, entry.name });
        errdefer gpa.free(child);
        switch (entry.kind) {
            .directory => {
                try listStoreDir(gpa, io, store_abs, child, files, bad);
                gpa.free(child);
            },
            .file => try files.append(gpa, child),
            else => try bad.append(gpa, child),
        }
    }
}

/// Pairs a store entry with the plain path it represents.
/// `cipher_rel` is relative to this key's store directory.
pub const Entry = struct {
    plain: []u8,
    cipher_rel: []u8,
};

pub fn freeEntries(gpa: Allocator, entries: []const Entry) void {
    for (entries) |entry| {
        gpa.free(entry.plain);
        gpa.free(entry.cipher_rel);
    }
    gpa.free(entries);
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
    /// Counts planned changes that were not applied, for partial-commit reporting.
    pending: usize = 0,

    pub fn add(
        self: *Report,
        gpa: Allocator,
        kind: Row.Kind,
        path: []const u8,
        detail: []const u8,
    ) !void {
        const p = try gpa.dupe(u8, path);
        errdefer gpa.free(p);
        const d = try gpa.dupe(u8, detail);
        errdefer gpa.free(d);
        try self.rows.append(gpa, .{ .kind = kind, .path = p, .detail = d });
    }

    pub fn count(self: Report, kind: Row.Kind) usize {
        var n: usize = 0;
        for (self.rows.items) |row| {
            if (row.kind == kind) n += 1;
        }
        return n;
    }

    pub fn deinit(self: *Report, gpa: Allocator) void {
        for (self.rows.items) |row| {
            gpa.free(row.path);
            gpa.free(row.detail);
        }
        self.rows.deinit(gpa);
    }
};

pub const Options = struct {
    force: bool = false,
    /// Computes and reports actions without writing files.
    validate_only: bool = false,
    /// Limits a pass to these plain paths.
    only: []const []const u8 = &.{},
};

const PathInfo = struct {
    plain: []u8,
    cipher_rel: ?[]u8 = null,
    values: Values,
    /// Holds decrypted bytes only while a comparison or plain-file write needs them.
    decrypted: ?[]u8 = null,
    bad: bool = false,
    decision: Decision = .none,
};

/// Holds the repository data loaded once for a synchronization pass.
pub const Context = struct {
    repo: *const Repo,
    keys: crypto.DerivedKeys,
    gpa: Allocator,
    io: Io,
    state: State,
    /// Uses the working-tree manifest when available, otherwise the decrypted store manifest.
    manifest: ?Manifest,
    /// Keeps the store manifest separately because a pull can make it newer than the plain copy.
    /// Both manifests contribute exclusions until they agree again.
    store_manifest: ?Manifest,
    /// Identifies this key's store directory in relative and absolute form.
    store_rel: [key_dir_len]u8,
    store_abs: []u8,
    /// Includes every index path, including unresolved merge entries.
    tracked: [][]u8,
    /// Holds unmerged store entries relative to this key's directory.
    unmerged: [][]u8,

    pub fn init(repo: *const Repo, keys: crypto.DerivedKeys) !Context {
        const gpa = repo.gpa;
        const key_id = crypto.keyId(keys.key_id_key);
        var ctx: Context = .{
            .repo = repo,
            .keys = keys,
            .gpa = gpa,
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
        ctx.state = try State.load(gpa, repo.io, repo.state_path, key_id);
        try ctx.loadIndex();
        try ctx.loadManifest();
        return ctx;
    }

    pub fn deinit(self: *Context) void {
        self.state.deinit(self.gpa);
        if (self.manifest) |*m| m.deinit(self.gpa);
        if (self.store_manifest) |*m| m.deinit(self.gpa);
        self.gpa.free(self.store_abs);
        git.freeList(self.gpa, self.tracked);
        git.freeList(self.gpa, self.unmerged);
    }

    /// Loads tracked paths and unmerged store entries from one index listing.
    fn loadIndex(self: *Context) !void {
        const gpa = self.gpa;
        const lines = try self.repo.lsFilesNul(&.{"--stage"});
        defer git.freeList(gpa, lines);

        var tracked: std.ArrayList([]u8) = .empty;
        errdefer {
            for (tracked.items) |t| gpa.free(t);
            tracked.deinit(gpa);
        }
        var unmerged: std.ArrayList([]u8) = .empty;
        errdefer {
            for (unmerged.items) |u| gpa.free(u);
            unmerged.deinit(gpa);
        }
        for (lines) |line| {
            const tab = mem.findScalar(u8, line, '\t') orelse continue;
            const path = line[tab + 1 ..];
            // Collapse stage-specific duplicates so each unmerged path is handled once.
            const path_repeated = if (tracked.last()) |prev| mem.eql(u8, prev, path) else false;
            if (!path_repeated) try tracked.append(gpa, try gpa.dupe(u8, path));
            if (tab == 0 or line[tab - 1] == '0') continue;
            if (!mem.startsWith(u8, path, &self.store_rel)) continue;
            if (path.len <= key_dir_len or path[key_dir_len] != '/') continue;
            const rel = path[key_dir_len + 1 ..];
            const rel_repeated = if (unmerged.last()) |prev| mem.eql(u8, prev, rel) else false;
            if (!rel_repeated) try unmerged.append(gpa, try gpa.dupe(u8, rel));
        }
        self.tracked = try tracked.toOwnedSlice(gpa);
        self.unmerged = try unmerged.toOwnedSlice(gpa);
    }

    /// Loads the working-tree manifest when present, otherwise the store copy.
    /// Decrypting the store copy also confirms that this key owns it.
    /// A key cannot name another key's entry, and corruption fails authentication.
    fn loadManifest(self: *Context) !void {
        const store_text = try manifestFromDir(self.repo, self.store_abs, self.keys);
        defer if (store_text) |text| self.gpa.free(text);
        if (store_text) |text| self.store_manifest = try Manifest.parse(self.gpa, text);

        if (try readPlainManifest(self.repo)) |manifest| {
            self.manifest = manifest;
        } else if (store_text) |text| {
            self.manifest = try Manifest.parse(self.gpa, text);
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
        return git.containsString(self.unmerged, cipher_rel);
    }
};

pub fn readPlainManifest(repo: *const Repo) !?Manifest {
    const gpa = repo.gpa;
    const path = try repo.absolutePath(Manifest.filename);
    defer gpa.free(path);
    const limit = readLimit(max_file_size);
    const text = Io.Dir.readFileAlloc(.cwd(), repo.io, path, gpa, limit) catch |err| switch (err) {
        error.FileNotFound => return null,
        else => return err,
    };
    defer gpa.free(text);
    return try Manifest.parse(gpa, text);
}

/// Reads this key's decrypted manifest, or null when the key has no stored manifest.
/// A named entry that fails to decrypt indicates corruption because only this key can name it.
/// Caller owns the returned memory.
///
pub fn manifestFromStore(repo: *const Repo, keys: crypto.DerivedKeys) !?[]u8 {
    const store_abs = try keyDirAbs(repo, keys);
    defer repo.gpa.free(store_abs);
    return manifestFromDir(repo, store_abs, keys);
}

fn manifestFromDir(repo: *const Repo, store_abs: []const u8, keys: crypto.DerivedKeys) !?[]u8 {
    const gpa = repo.gpa;
    const io = repo.io;
    const cipher_rel = try filename_crypto.encryptPath(
        gpa,
        Manifest.filename,
        keys.filename_key,
        '/',
    );
    defer gpa.free(cipher_rel);
    const abs = try Io.Dir.path.join(gpa, &.{ store_abs, cipher_rel });
    defer gpa.free(abs);

    const limit = readLimit(max_file_size + crypto.overhead_size);
    const encrypted = Io.Dir.readFileAlloc(.cwd(), io, abs, gpa, limit) catch |err| switch (err) {
        error.FileNotFound => return null,
        else => return err,
    };
    defer gpa.free(encrypted);
    return crypto.decryptBound(gpa, encrypted, Manifest.filename, keys) catch return Error.WrongKey;
}

/// Plain files are staged under Git's directory before being renamed into the working tree.
/// That rename requires both locations to share a filesystem.
/// Check this before synchronization changes anything.
pub fn checkSameFilesystem(repo: *const Repo) !void {
    const gpa = repo.gpa;
    const io = repo.io;
    try repo.ensureDirs();
    const store = try repo.absolutePath(enc_dir);
    defer gpa.free(store);
    try fs.ensureDir(io, store);
    const probe = try Io.Dir.path.join(gpa, &.{ store, ".probe" });
    defer gpa.free(probe);
    defer Io.Dir.deleteFile(.cwd(), io, probe) catch {};
    processor.writeFileAtomic(gpa, io, probe, "", null, repo.tmp_dir) catch |err| switch (err) {
        error.CrossDevice => {
            std.debug.print(
                "Error: the git directory and the working tree must be on the same filesystem\n",
                .{},
            );
            return err;
        },
        else => return err,
    };
}

/// Reports whether the store directory has turbocrypt's marker.
pub fn storeExists(repo: *const Repo) bool {
    const gpa = repo.gpa;
    const path = Io.Dir.path.join(gpa, &.{
        repo.toplevel,
        enc_dir,
        marker_name,
    }) catch return false;
    defer gpa.free(path);
    return fs.pathExists(repo.io, path);
}

/// Counts other key directories, the only information one key holder can learn about them.
///
pub fn otherKeyCount(repo: *const Repo, keys: crypto.DerivedKeys) !usize {
    const gpa = repo.gpa;
    const store = try repo.absolutePath(enc_dir);
    defer gpa.free(store);
    const our_name = keyDirName(keys);

    var dir = Io.Dir.openDir(.cwd(), repo.io, store, .{
        .iterate = true,
        .follow_symlinks = false,
    }) catch |err| switch (err) {
        error.FileNotFound => return 0,
        else => return err,
    };
    defer dir.close(repo.io);

    var n: usize = 0;
    var it = dir.iterate();
    while (try it.next(repo.io)) |entry| {
        if (entry.kind == .directory and !mem.eql(u8, entry.name, &our_name)) n += 1;
    }
    return n;
}

/// Collects manifest-private files from the working tree.
/// Separates files ignored by Git so build output is not silently added to the store.
/// This preserves a user's ignore rules inside private directories.
pub const Candidates = struct {
    files: [][]u8,
    ignored: [][]u8,

    pub fn deinit(self: Candidates, gpa: Allocator) void {
        git.freeList(gpa, self.files);
        git.freeList(gpa, self.ignored);
    }
};

pub fn collectCandidates(ctx: *const Context, manifest: Manifest) !Candidates {
    const repo = ctx.repo;
    const gpa = ctx.gpa;

    var files: std.ArrayList([]u8) = .empty;
    errdefer {
        for (files.items) |f| gpa.free(f);
        files.deinit(gpa);
    }
    var ignored: std.ArrayList([]u8) = .empty;
    errdefer {
        for (ignored.items) |f| gpa.free(f);
        ignored.deinit(gpa);
    }

    const entries = try manifest.entries(gpa);
    defer gpa.free(entries);

    const manifest_abs = try repo.absolutePath(Manifest.filename);
    defer gpa.free(manifest_abs);
    if (fs.pathExists(repo.io, manifest_abs)) {
        try files.append(gpa, try gpa.dupe(u8, Manifest.filename));
    }
    if (entries.len == 0) return .{
        .files = try files.toOwnedSlice(gpa),
        .ignored = try ignored.toOwnedSlice(gpa),
    };

    // Limit Git's scan to manifest-private paths instead of walking the whole repository.
    var pathspec: std.ArrayList([]const u8) = .empty;
    defer pathspec.deinit(gpa);
    try pathspec.append(gpa, "--");
    for (entries) |entry| try pathspec.append(gpa, entry.path);

    const private_lines = try renderLines(gpa, manifest);
    defer gpa.free(private_lines);
    const private_file = try Io.Dir.path.join(gpa, &.{ repo.private_dir, "candidates" });
    defer gpa.free(private_file);
    try processor.writeFileAtomic(
        gpa,
        repo.io,
        private_file,
        private_lines,
        fs.private_file_permissions,
        null,
    );
    const exclude_from = try gpa.print("--exclude-from={s}", .{private_file});
    defer gpa.free(exclude_from);

    var argv: std.ArrayList([]const u8) = .empty;
    defer argv.deinit(gpa);
    try argv.appendSlice(gpa, &.{ "--others", "--ignored", exclude_from });
    try argv.appendSlice(gpa, pathspec.items);
    const all = try repo.lsFilesNul(argv.items);
    defer git.freeList(gpa, all);

    const gitignored = try listGitignored(ctx, pathspec.items);
    defer git.freeList(gpa, gitignored);
    var ignored_set: std.StringHashMapUnmanaged(void) = .empty;
    defer ignored_set.deinit(gpa);
    for (gitignored) |path| try ignored_set.put(gpa, path, {});

    for (all) |path| {
        if (Manifest.isReservedPath(path)) continue;
        if (!Manifest.anyCovers(entries, path)) continue;
        if (ignored_set.contains(path)) {
            try ignored.append(gpa, try gpa.dupe(u8, path));
            continue;
        }

        const abs = try repo.absolutePath(path);
        defer gpa.free(abs);
        const stat = Io.Dir.statFile(.cwd(), repo.io, abs, .{
            .follow_symlinks = false,
        }) catch continue;
        if (stat.kind != .file) continue;
        try files.append(gpa, try gpa.dupe(u8, path));
    }
    return .{ .files = try files.toOwnedSlice(gpa), .ignored = try ignored.toOwnedSlice(gpa) };
}

fn renderLines(gpa: Allocator, manifest: Manifest) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    for (manifest.lines.items) |line| {
        if (Manifest.parseLine(line) == null) continue;
        try out.appendSlice(gpa, line);
        try out.append(gpa, '\n');
    }
    return out.toOwnedSlice(gpa);
}

/// Lists untracked files ignored by `.gitignore` or global exclude rules under the pathspec.
fn listGitignored(ctx: *const Context, pathspec: []const []const u8) ![][]u8 {
    const repo = ctx.repo;
    const gpa = ctx.gpa;

    var argv: std.ArrayList([]const u8) = .empty;
    defer argv.deinit(gpa);
    try argv.appendSlice(gpa, &.{ "--others", "--ignored", "--exclude-per-directory=.gitignore" });

    const global = try globalExcludesFile(ctx);
    defer if (global) |g| gpa.free(g);
    const arg = if (global) |g| try gpa.print("--exclude-from={s}", .{g}) else null;
    defer if (arg) |a| gpa.free(a);
    if (arg) |a| try argv.append(gpa, a);
    try argv.appendSlice(gpa, pathspec);

    return repo.lsFilesNul(argv.items);
}

/// Finds Git's global excludes file when one exists.
/// Git does not expose the default location, so it must be derived from the environment.
fn globalExcludesFile(ctx: *const Context) !?[]u8 {
    const gpa = ctx.gpa;
    const env = ctx.repo.environ_map;
    if (try ctx.repo.configGetPath("core.excludesFile")) |configured| return configured;
    // On Windows, Git uses the profile directory when HOME is unavailable.
    const home = env.get("HOME") orelse env.get("USERPROFILE");
    const candidate = if (env.get("XDG_CONFIG_HOME")) |xdg|
        try Io.Dir.path.join(gpa, &.{ xdg, "git", "ignore" })
    else if (home) |dir|
        try Io.Dir.path.join(gpa, &.{ dir, ".config", "git", "ignore" })
    else
        return null;
    if (!fs.pathExists(ctx.io, candidate)) {
        gpa.free(candidate);
        return null;
    }
    return candidate;
}

fn isExecutable(permissions: Io.File.Permissions) bool {
    if (!Io.File.Permissions.has_executable_bit) return false;
    return permissions.toMode() & 0o111 != 0;
}

const Snapshot = struct {
    mac: [crypto.mac_length]u8,
    exec: bool,
};

/// Captures a regular file's keyed fingerprint and executable mode, or null when absent.
/// Optionally returns the bytes so callers do not need to read the file twice.
fn snapshot(
    ctx: *const Context,
    abs: []const u8,
    limit: u64,
    key: [crypto.key_length]u8,
    bytes_out: ?*?[]u8,
) !?Snapshot {
    const stat = Io.Dir.statFile(.cwd(), ctx.io, abs, .{
        .follow_symlinks = false,
    }) catch |err| switch (err) {
        error.FileNotFound => return null,
        else => return err,
    };
    if (stat.kind != .file) return null;
    if (stat.size > limit) return Error.FileTooLarge;

    const bytes = try Io.Dir.readFileAlloc(.cwd(), ctx.io, abs, ctx.gpa, readLimit(limit));
    const snap: Snapshot = .{
        .mac = crypto.keyedMac(bytes, key),
        .exec = isExecutable(stat.permissions),
    };
    if (bytes_out) |out| out.* = bytes else ctx.gpa.free(bytes);
    return snap;
}

/// Reads the current plain-file fingerprint and mode, or null when the file is absent.
fn readCur(ctx: *const Context, plain: []const u8, bytes_out: ?*?[]u8) !?Current {
    const abs = try ctx.repo.absolutePath(plain);
    defer ctx.gpa.free(abs);
    const key = ctx.keys.fingerprint_key;
    const snap = (try snapshot(ctx, abs, max_file_size, key, bytes_out)) orelse return null;
    return .{ .plain = snap.mac, .exec = snap.exec };
}

fn entryPath(ctx: *const Context, cipher_rel: []const u8) ![]u8 {
    return Io.Dir.path.join(ctx.gpa, &.{ ctx.store_abs, cipher_rel });
}

/// Reads the current encrypted-entry identity and checks its header, or null when absent.
fn readNew(ctx: *const Context, cipher_rel: []const u8) !?New {
    const abs = try entryPath(ctx, cipher_rel);
    defer ctx.gpa.free(abs);
    const limit = max_file_size + crypto.overhead_size;
    var bytes: ?[]u8 = null;
    const snap = (try snapshot(ctx, abs, limit, ctx.keys.cipher_id_key, &bytes)) orelse return null;
    defer ctx.gpa.free(bytes.?);
    const header_ok = if (crypto.verifyHeaderOnly(bytes.?, ctx.keys)) |_| true else |_| false;
    return .{ .id = snap.mac, .exec = snap.exec, .header_ok = header_ok };
}

fn readEntry(ctx: *const Context, cipher_rel: []const u8) !?[]u8 {
    const abs = try entryPath(ctx, cipher_rel);
    defer ctx.gpa.free(abs);
    const limit = readLimit(max_file_size + crypto.overhead_size);
    return Io.Dir.readFileAlloc(.cwd(), ctx.io, abs, ctx.gpa, limit) catch |err| switch (err) {
        error.FileNotFound => null,
        else => return err,
    };
}

/// Collects every path known to the state, store, or working tree with its three versions.
fn analyze(ctx: *const Context, only: []const []const u8, report: *Report) ![]PathInfo {
    const gpa = ctx.gpa;

    var names: std.array_hash_map.String(void) = .empty;
    defer {
        for (names.keys()) |k| gpa.free(k);
        names.deinit(gpa);
    }
    var ciphers: std.array_hash_map.String([]u8) = .empty;
    defer {
        for (ciphers.values()) |v| gpa.free(v);
        ciphers.deinit(gpa);
    }

    var bad: std.ArrayList([]u8) = .empty;
    defer {
        for (bad.items) |b| gpa.free(b);
        bad.deinit(gpa);
    }
    const store_files = if (fs.pathExists(ctx.io, ctx.store_abs))
        try listStore(gpa, ctx.io, ctx.store_abs, &bad)
    else
        try gpa.alloc([]u8, 0);
    defer git.freeList(gpa, store_files);

    for (store_files) |cipher_rel| {
        const plain = filename_crypto.decryptPathStrict(
            gpa,
            cipher_rel,
            ctx.keys.filename_key,
        ) catch {
            try bad.append(gpa, try gpa.dupe(u8, cipher_rel));
            continue;
        };
        errdefer gpa.free(plain);
        if (!names.contains(plain)) {
            try names.put(gpa, plain, {});
            try ciphers.put(gpa, plain, try gpa.dupe(u8, cipher_rel));
        } else {
            gpa.free(plain);
        }
    }
    for (bad.items) |b| {
        const shown = try gpa.print("{s}/{s}", .{ &ctx.store_rel, b });
        defer gpa.free(shown);
        try report.add(gpa, .bad, shown, "cannot decrypt the name");
    }

    for (ctx.state.map.keys()) |path| {
        if (!names.contains(path)) try names.put(gpa, try gpa.dupe(u8, path), {});
    }

    if (ctx.manifest) |manifest| {
        const candidates = try collectCandidates(ctx, manifest);
        defer candidates.deinit(gpa);
        for (candidates.files) |path| {
            if (!names.contains(path)) try names.put(gpa, try gpa.dupe(u8, path), {});
        }
        for (candidates.ignored) |path| {
            try report.add(gpa, .ignored, path, "matches a .gitignore rule, not encrypted");
        }
    }

    var infos: std.ArrayList(PathInfo) = .empty;
    errdefer {
        for (infos.items) |*info| freeInfo(gpa, info);
        infos.deinit(gpa);
    }

    const keys = names.keys();
    mem.sort([]const u8, keys, {}, struct {
        fn lessThan(_: void, a: []const u8, b: []const u8) bool {
            return mem.lessThan(u8, a, b);
        }
    }.lessThan);

    for (keys) |plain| {
        if (only.len > 0 and !git.containsString(only, plain)) continue;

        var info: PathInfo = .{
            .plain = try gpa.dupe(u8, plain),
            .values = .{ .old = ctx.state.get(plain), .new = null, .cur = null },
        };
        errdefer freeInfo(gpa, &info);

        info.cipher_rel = if (ciphers.get(plain)) |c| try gpa.dupe(u8, c) else null;
        info.values.cur = readCur(ctx, plain, null) catch |err| switch (err) {
            Error.FileTooLarge => blk: {
                try report.add(gpa, .bad, plain, "larger than 256 MiB");
                info.bad = true;
                break :blk null;
            },
            else => return err,
        };
        if (info.cipher_rel) |c| {
            info.values.new = readNew(ctx, c) catch |err| switch (err) {
                Error.FileTooLarge => blk: {
                    try report.add(gpa, .bad, plain, "entry larger than 256 MiB");
                    info.bad = true;
                    break :blk null;
                },
                else => return err,
            };
        } else if (info.values.cur != null and !try nameFits(gpa, ctx.keys, plain)) {
            try report.add(gpa, .bad, plain, long_name_detail);
            info.bad = true;
        }
        try infos.append(gpa, info);
    }
    return infos.toOwnedSlice(gpa);
}

/// Reports whether every encrypted path component fits the filesystem filename limit.
pub fn nameFits(gpa: Allocator, keys: crypto.DerivedKeys, plain: []const u8) !bool {
    const key = keys.filename_key;
    const cipher = filename_crypto.encryptPath(gpa, plain, key, '/') catch |err| switch (err) {
        filename_crypto.Error.EncryptedFilenameTooLong => return false,
        else => return err,
    };
    gpa.free(cipher);
    return true;
}

fn freeInfo(gpa: Allocator, info: *PathInfo) void {
    gpa.free(info.plain);
    if (info.cipher_rel) |c| gpa.free(c);
    freeDecrypted(gpa, info);
}

fn freeDecrypted(gpa: Allocator, info: *PathInfo) void {
    if (info.decrypted) |d| gpa.free(d);
    info.decrypted = null;
}

fn freeInfos(gpa: Allocator, infos: []PathInfo) void {
    for (infos) |*info| freeInfo(gpa, info);
    gpa.free(infos);
}

/// Decrypts an entry only once and keeps the bytes for the rest of its decision.
/// Authentication failures mark the path bad so callers do not trust its content.
fn decryptEntry(ctx: *const Context, info: *PathInfo, report: *Report) !bool {
    if (info.decrypted != null) return true;
    const cipher_rel = info.cipher_rel orelse return false;
    const encrypted = (try readEntry(ctx, cipher_rel)) orelse return false;
    defer ctx.gpa.free(encrypted);

    info.decrypted = crypto.decryptBound(ctx.gpa, encrypted, info.plain, ctx.keys) catch {
        try report.add(
            ctx.gpa,
            .bad,
            info.plain,
            "entry does not decrypt: wrong key, corrupted, or moved to another path",
        );
        info.bad = true;
        return false;
    };
    return true;
}

/// Compares the plain and encrypted content for one path after decrypting the entry.
fn compare(ctx: *const Context, info: *PathInfo, report: *Report) !void {
    if (!try decryptEntry(ctx, info, report)) return;
    const new = info.values.new orelse return;
    const cur = info.values.cur orelse return;
    const decrypted = crypto.fingerprint(info.decrypted.?, ctx.keys.fingerprint_key);
    info.values.cur_eql_new = mem.eql(u8, &decrypted, &cur.plain) and cur.exec == new.exec;
}

/// Bad paths stop encryption but are left untouched during decryption.
/// `--force` may replace a bad encrypted entry from a valid plain file.
/// A plain name that cannot be encrypted has no safe forced recovery.
fn badDecision(info: *const PathInfo, direction: Direction, force: bool) Decision {
    if (direction != .encrypt) return .none;
    if (info.cipher_rel == null) return .abort_plain;
    if (force and info.values.cur != null) return .encrypt;
    return .abort_bad;
}

pub const Direction = enum { encrypt, decrypt };

/// Finalizes one path's action for the current pass.
/// Retain decrypted bytes only when the chosen action will write the plain file.
fn decide(
    ctx: *const Context,
    info: *PathInfo,
    direction: Direction,
    force: bool,
    report: *Report,
) !void {
    defer if (info.decision != .write_plain) freeDecrypted(ctx.gpa, info);
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

/// Deletes a path through directory handles, then removes parent directories left empty.
/// This avoids following a path that could change during cleanup.
fn deleteThroughHandles(io: Io, root: []const u8, sub_path: []const u8) !void {
    if (try fs.openParent(io, root, sub_path, false)) |parent| {
        var dir = parent;
        defer dir.close(io);
        dir.deleteFile(io, Io.Dir.path.basename(sub_path)) catch |err| switch (err) {
            error.FileNotFound => {},
            else => return err,
        };
    }
    pruneEmptyParents(io, root, sub_path);
}

fn pruneEmptyParents(io: Io, root: []const u8, sub_path: []const u8) void {
    var ancestor = Io.Dir.path.dirname(sub_path);
    while (ancestor) |path| : (ancestor = Io.Dir.path.dirname(path)) {
        const parent = (fs.openParent(io, root, path, false) catch break) orelse break;
        var dir = parent;
        defer dir.close(io);
        dir.deleteDir(io, Io.Dir.path.basename(path)) catch break;
    }
}

const ExchangeError = error{ Unsupported, NotFound, Failed };

/// Exchanges two directory entries so the displaced file remains available for verification.
/// The platform calls are used because there is no portable standard-library operation.
/// Windows cannot offer the same guarantee, so callers use the safer fallback there.
fn exchange(
    gpa: Allocator,
    a_dir: Io.Dir,
    a: []const u8,
    b_dir: Io.Dir,
    b: []const u8,
) (ExchangeError || Allocator.Error)!void {
    if (builtin.os.tag != .linux and builtin.os.tag != .macos) return ExchangeError.Unsupported;

    const a_z = try gpa.dupeSentinel(u8, a, 0);
    defer gpa.free(a_z);
    const b_z = try gpa.dupeSentinel(u8, b, 0);
    defer gpa.free(b_z);
    switch (builtin.os.tag) {
        .linux => {
            const rc = std.os.linux.renameat2(a_dir.handle, a_z, b_dir.handle, b_z, .{
                .EXCHANGE = true,
            });
            return switch (std.os.linux.errno(rc)) {
                .SUCCESS => {},
                .NOENT => ExchangeError.NotFound,
                .INVAL, .OPNOTSUPP, .NOSYS => ExchangeError.Unsupported,
                else => ExchangeError.Failed,
            };
        },
        .macos => {
            const rc = std.c.renameatx_np(a_dir.handle, a_z, b_dir.handle, b_z, .{ .SWAP = true });
            return switch (std.c.errno(rc)) {
                .SUCCESS => {},
                .NOENT => ExchangeError.NotFound,
                .INVAL, .OPNOTSUPP => ExchangeError.Unsupported,
                else => ExchangeError.Failed,
            };
        },
        else => unreachable,
    }
}

/// Checks whether a file still matches the version examined during analysis.
fn matchesAnalysis(ctx: *const Context, path: []const u8, cur: ?Current) !bool {
    const key = ctx.keys.fingerprint_key;
    const now = snapshot(ctx, path, max_file_size, key, null) catch |err| switch (err) {
        Error.FileTooLarge => return false,
        else => return err,
    };
    const expected = cur orelse return now == null;
    const snap = now orelse return false;
    return mem.eql(u8, &snap.mac, &expected.plain) and snap.exec == expected.exec;
}

fn fileHolds(ctx: *const Context, path: []const u8, expected: []const u8) !bool {
    const limit = readLimit(max_file_size);
    const bytes = Io.Dir.readFileAlloc(.cwd(), ctx.io, path, ctx.gpa, limit) catch return false;
    defer ctx.gpa.free(bytes);
    return mem.eql(u8, bytes, expected);
}

/// Creates a unique path under the private temporary directory.
fn asidePath(ctx: *const Context, tag: []const u8, name: []const u8) ![]u8 {
    var rand: u64 = undefined;
    ctx.io.random(mem.asBytes(&rand));
    return ctx.gpa.print("{s}/{s}.{s}.{x}", .{ ctx.repo.tmp_dir, tag, name, rand });
}

/// Keeps a file written during synchronization instead of deleting it.
/// The warning tells the user where to recover that newer content.
fn keepSavedCopy(ctx: *const Context, path: []const u8, plain: []const u8) void {
    const saved = asidePath(ctx, "saved", Io.Dir.path.basename(plain)) catch return;
    defer ctx.gpa.free(saved);
    Io.Dir.renamePreserve(.cwd(), path, .cwd(), saved, ctx.io) catch return;
    std.debug.print(
        "Warning: {s} changed twice while the sync ran. A copy of the newest content is at {s}\n",
        .{ plain, saved },
    );
}

fn plainPermissions(exec: bool, existing: ?Io.File.Permissions) Io.File.Permissions {
    if (!Io.File.Permissions.has_executable_bit) return .default_file;
    const base = if (existing) |p| p.toMode() else plain_file_permissions.toMode();
    const without = base & ~@as(std.posix.mode_t, 0o111);
    return .fromMode(if (exec) without | 0o100 else without);
}

fn writePlain(ctx: *const Context, info: *PathInfo) !void {
    const gpa = ctx.gpa;
    const io = ctx.io;
    const toplevel = ctx.repo.toplevel;
    try validateDestination(gpa, io, toplevel, info.plain, ctx.tracked);

    const parent = fs.openParent(io, toplevel, info.plain, true) catch return Error.UnsafePath;
    var dir = parent orelse return Error.UnsafePath;
    defer dir.close(io);
    const name = Io.Dir.path.basename(info.plain);

    var existing: ?Io.File.Permissions = null;
    if (dir.statFile(io, name, .{ .follow_symlinks = false })) |st| {
        if (st.kind != .file) return Error.UnsafePath;
        existing = st.permissions;
    } else |err| switch (err) {
        error.FileNotFound => {},
        else => return err,
    }
    if ((existing != null) != (info.values.cur != null)) return Error.ChangedDuringSync;

    const exec = info.values.new.?.exec;
    var atomic = try processor.AtomicOutput.init(gpa, io, name, .{}, ctx.repo.tmp_dir);
    defer atomic.deinit(io);
    try atomic.file.writeStreamingAll(io, info.decrypted.?);
    try atomic.setPermissions(io, plainPermissions(exec, existing));

    if (existing == null) {
        Io.Dir.renamePreserve(.cwd(), atomic.tmp_path, dir, name, io) catch |err| switch (err) {
            error.PathAlreadyExists => return Error.ChangedDuringSync,
            else => return Error.UnsafePath,
        };
        atomic.keep();
        return;
    }

    const old = try takePlace(ctx, &atomic, dir, name, info.plain);
    defer gpa.free(old.path);

    // The displaced file must remain recoverable from this point onward.
    // If it cannot be read, treat it as changed rather than risk discarding it.
    const matched = matchesAnalysis(ctx, old.path, info.values.cur) catch false;
    if (matched) {
        // An exchanged file now sits at the temporary path and will be removed with it.
        if (old.aside) Io.Dir.deleteFile(.cwd(), io, old.path) catch {};
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

/// Describes the prior plain file after a replacement takes its name.
const OldFile = struct {
    path: []u8,
    /// True when the old file was moved aside instead of exchanged.
    aside: bool,
};

/// Replaces the plain file while preserving the old version for verification.
/// Moving it aside first prevents a concurrent save from being lost on platforms without exchange.
fn takePlace(
    ctx: *const Context,
    atomic: *const processor.AtomicOutput,
    dir: Io.Dir,
    name: []const u8,
    plain: []const u8,
) !OldFile {
    const gpa = ctx.gpa;
    // Duplicate the path before exchange so allocation failure cannot strand the old file.
    const at_tmp = try gpa.dupe(u8, atomic.tmp_path);
    var exchanged = false;
    defer if (!exchanged) gpa.free(at_tmp);

    exchange(gpa, .cwd(), atomic.tmp_path, dir, name) catch |err| switch (err) {
        error.OutOfMemory => return err,
        ExchangeError.NotFound => return Error.ChangedDuringSync,
        ExchangeError.Unsupported => return moveAside(ctx, atomic, dir, name, plain),
        ExchangeError.Failed => return Error.UnsafePath,
    };
    exchanged = true;
    return .{ .path = at_tmp, .aside = false };
}

fn moveAside(
    ctx: *const Context,
    atomic: *const processor.AtomicOutput,
    dir: Io.Dir,
    name: []const u8,
    plain: []const u8,
) !OldFile {
    const io = ctx.io;
    const aside = try asidePath(ctx, "old", name);
    errdefer ctx.gpa.free(aside);
    Io.Dir.renamePreserve(dir, name, .cwd(), aside, io) catch |err| switch (err) {
        error.FileNotFound => return Error.ChangedDuringSync,
        else => return Error.UnsafePath,
    };
    Io.Dir.renamePreserve(.cwd(), atomic.tmp_path, dir, name, io) catch |err| {
        // Restore the old file when possible; otherwise preserve it for the user.
        Io.Dir.renamePreserve(.cwd(), aside, dir, name, io) catch keepSavedCopy(ctx, aside, plain);
        return if (err == error.PathAlreadyExists) Error.ChangedDuringSync else Error.UnsafePath;
    };
    return .{ .path = aside, .aside = true };
}

/// Restores the old file and returns the replacement to its temporary path.
/// If restoration fails, leave the old file available for the caller to preserve.
fn putBack(
    ctx: *const Context,
    atomic: *const processor.AtomicOutput,
    dir: Io.Dir,
    name: []const u8,
    old: OldFile,
) !void {
    const io = ctx.io;
    if (!old.aside) return exchange(ctx.gpa, .cwd(), atomic.tmp_path, dir, name);
    try Io.Dir.renamePreserve(dir, name, .cwd(), atomic.tmp_path, io);
    Io.Dir.renamePreserve(.cwd(), old.path, dir, name, io) catch |err| {
        // A concurrent save reclaimed the name, so keep the new content rather than overwrite it.
        Io.Dir.deleteFile(.cwd(), io, atomic.tmp_path) catch {};
        return err;
    };
}

/// Deletes a plain file only after confirming it has not changed since analysis.
/// Move it aside first so a concurrent save can be restored safely.
/// This protects user edits that arrive during synchronization.
fn deletePlain(ctx: *const Context, info: *const PathInfo) !void {
    const gpa = ctx.gpa;
    const io = ctx.io;
    const parent = (try fs.openParent(io, ctx.repo.toplevel, info.plain, false)) orelse return;
    var dir = parent;
    defer dir.close(io);
    const name = Io.Dir.path.basename(info.plain);

    const aside = try asidePath(ctx, "displaced", name);
    defer gpa.free(aside);
    Io.Dir.renamePreserve(dir, name, .cwd(), aside, io) catch |err| switch (err) {
        error.FileNotFound => return,
        else => return err,
    };

    const matched = matchesAnalysis(ctx, aside, info.values.cur) catch false;
    if (matched) {
        Io.Dir.deleteFile(.cwd(), io, aside) catch {};
        pruneEmptyParents(io, ctx.repo.toplevel, info.plain);
        return;
    }

    // The file changed after analysis, so do not delete it.
    // Restore it only into an unused name to avoid overwriting a concurrent save.
    // Otherwise keep the moved copy for the user to recover.
    // This favors preserving data over completing the deletion.
    Io.Dir.renamePreserve(.cwd(), aside, dir, name, io) catch keepSavedCopy(ctx, aside, info.plain);
    return Error.ChangedDuringSync;
}

fn encryptPlain(ctx: *const Context, info: *PathInfo, stage: *std.ArrayList([]u8)) !void {
    const gpa = ctx.gpa;
    const io = ctx.io;
    var plain_bytes: ?[]u8 = null;
    const cur = (try readCur(ctx, info.plain, &plain_bytes)) orelse return;
    defer gpa.free(plain_bytes.?);

    const cipher_rel = info.cipher_rel orelse blk: {
        info.cipher_rel = try filename_crypto.encryptPath(
            gpa,
            info.plain,
            ctx.keys.filename_key,
            '/',
        );
        break :blk info.cipher_rel.?;
    };
    const parent = try fs.openParent(io, ctx.store_abs, cipher_rel, true);
    var dir = parent orelse return Error.UnsafePath;
    defer dir.close(io);

    const encrypted = try crypto.encryptBound(gpa, io, plain_bytes.?, info.plain, ctx.keys);
    defer gpa.free(encrypted);
    const permissions = if (cur.exec) cipher_exec_permissions else cipher_file_permissions;
    try processor.writeFileAtomicIn(
        dir,
        gpa,
        io,
        Io.Dir.path.basename(cipher_rel),
        encrypted,
        permissions,
        ctx.repo.tmp_dir,
    );

    info.values.new = .{
        .id = crypto.ciphertextId(encrypted, ctx.keys.cipher_id_key),
        .exec = cur.exec,
    };
    info.values.cur = cur;
    try stage.append(gpa, try storePath(gpa, &ctx.store_rel, cipher_rel));
}

fn recordBaseline(ctx: *Context, info: *const PathInfo) !void {
    const cur = info.values.cur orelse return;
    const new = info.values.new orelse return;
    try ctx.state.put(ctx.gpa, info.plain, .{ .plain = cur.plain, .exec = cur.exec, .id = new.id });
}

/// Updates the generated exclude block from manifests and uncovered store paths.
/// Existing generated lines remain unless `remove` explicitly drops them.
/// Extra store paths remain ignored when their manifest line has not arrived yet.
/// This can happen after history replay or branch changes.
/// Keeping them ignored prevents private files from appearing as untracked public files.
///
pub fn updateExcludeFile(
    repo: *const Repo,
    manifests: []const *const Manifest,
    extra: []const []const u8,
    remove: []const []const u8,
) !void {
    const gpa = repo.gpa;
    const io = repo.io;
    const existing = try readExcludeText(repo);
    defer if (existing) |e| gpa.free(e);

    const previous = try Manifest.blockLines(gpa, existing orelse "");
    defer git.freeList(gpa, previous);

    var add: std.ArrayList([]const u8) = .empty;
    defer add.deinit(gpa);
    try add.append(gpa, "/" ++ Manifest.filename);
    for (manifests) |m| {
        for (m.lines.items) |line| {
            if (Manifest.parseLine(line) != null) try add.append(gpa, line);
        }
    }
    var extra_lines: std.ArrayList([]u8) = .empty;
    defer {
        for (extra_lines.items) |line| gpa.free(line);
        extra_lines.deinit(gpa);
    }
    for (extra) |plain| {
        if (coveredByAny(manifests, plain)) continue;
        const line = try gpa.print("/{s}", .{plain});
        errdefer gpa.free(line);
        if (Manifest.parseLine(line) == null) {
            gpa.free(line);
            continue;
        }
        try extra_lines.append(gpa, line);
        try add.append(gpa, line);
    }

    const merged = try Manifest.mergeBlockLines(gpa, previous, add.items, remove);
    defer git.freeList(gpa, merged);

    const text = try Manifest.renderExcludeText(gpa, existing, merged);
    defer gpa.free(text);
    if (existing != null and mem.eql(u8, existing.?, text)) return;

    if (Io.Dir.path.dirname(repo.exclude_path)) |dir| try fs.ensureDir(io, dir);
    try repo.ensureDirs();
    try processor.writeFileAtomic(gpa, io, repo.exclude_path, text, null, repo.tmp_dir);
}

fn coveredByAny(manifests: []const *const Manifest, plain: []const u8) bool {
    for (manifests) |manifest| {
        if (manifest.covering(plain) != null) return true;
    }
    return false;
}

fn readExcludeText(repo: *const Repo) !?[]u8 {
    const path = repo.exclude_path;
    const limit = readLimit(max_state_size);
    return Io.Dir.readFileAlloc(.cwd(), repo.io, path, repo.gpa, limit) catch |err| switch (err) {
        error.FileNotFound => null,
        else => return err,
    };
}

/// Finds generated exclude lines covered only by entries being removed.
/// Removing them lets those files become ordinary untracked files after `rm`.
/// Caller owns the returned memory.
pub fn excludeLinesCoveredBy(
    repo: *const Repo,
    removed: []const Manifest.Entry,
    remaining: *const Manifest,
) ![][]u8 {
    const gpa = repo.gpa;
    const existing = (try readExcludeText(repo)) orelse return gpa.alloc([]u8, 0);
    defer gpa.free(existing);
    const lines = try Manifest.blockLines(gpa, existing);
    defer git.freeList(gpa, lines);

    var out: std.ArrayList([]u8) = .empty;
    errdefer {
        for (out.items) |line| gpa.free(line);
        out.deinit(gpa);
    }
    for (lines) |line| {
        const entry = Manifest.parseLine(line) orelse continue;
        if (mem.eql(u8, entry.path, Manifest.filename)) continue;
        var covered = false;
        for (removed) |r| {
            if (r.covers(entry.path) or mem.eql(u8, r.path, entry.path)) covered = true;
        }
        if (!covered or remaining.covering(entry.path) != null) continue;
        try out.append(gpa, try gpa.dupe(u8, line));
    }
    return out.toOwnedSlice(gpa);
}

/// Removes store entries from disk, the index, and synchronization state.
/// `rm` deliberately leaves the corresponding plain files on disk.
pub fn removeEntries(repo: *const Repo, keys: crypto.DerivedKeys, entries: []const Entry) !void {
    const gpa = repo.gpa;
    var state = try State.load(gpa, repo.io, repo.state_path, crypto.keyId(keys.key_id_key));
    defer state.deinit(gpa);
    const key_dir = keyDirRel(keys);
    const store_abs = try repo.absolutePath(&key_dir);
    defer gpa.free(store_abs);

    var staged: std.ArrayList([]u8) = .empty;
    defer {
        for (staged.items) |s| gpa.free(s);
        staged.deinit(gpa);
    }
    for (entries) |entry| {
        try deleteThroughHandles(repo.io, store_abs, entry.cipher_rel);
        state.remove(gpa, entry.plain);
        try staged.append(gpa, try storePath(gpa, &key_dir, entry.cipher_rel));
    }
    try repo.rmCached(staged.items);
    try repo.ensureDirs();
    try state.save(gpa, repo.io, repo.state_path, repo.tmp_dir);
}

/// Lists this key's store entries with their decrypted plain paths.
/// Entries with undecryptable names are skipped because they cannot be identified safely.
/// Caller owns the result and releases it with `freeEntries`.
pub fn storeEntries(repo: *const Repo, keys: crypto.DerivedKeys) ![]Entry {
    const gpa = repo.gpa;
    const store_abs = try keyDirAbs(repo, keys);
    defer gpa.free(store_abs);
    if (!fs.pathExists(repo.io, store_abs)) return gpa.alloc(Entry, 0);

    var bad: std.ArrayList([]u8) = .empty;
    defer {
        for (bad.items) |b| gpa.free(b);
        bad.deinit(gpa);
    }
    const files = try listStore(gpa, repo.io, store_abs, &bad);
    defer git.freeList(gpa, files);

    var entries: std.ArrayList(Entry) = .empty;
    errdefer {
        for (entries.items) |entry| {
            gpa.free(entry.plain);
            gpa.free(entry.cipher_rel);
        }
        entries.deinit(gpa);
    }
    for (files) |cipher_rel| {
        const plain = filename_crypto.decryptPathStrict(
            gpa,
            cipher_rel,
            keys.filename_key,
        ) catch continue;
        errdefer gpa.free(plain);
        try entries.append(gpa, .{ .plain = plain, .cipher_rel = try gpa.dupe(u8, cipher_rel) });
    }
    return entries.toOwnedSlice(gpa);
}

/// Finds index paths that would expose private content in the next commit.
/// A commit is refused until those paths leave the index.
/// Exclude-only lines may belong to another branch and do not count as violations.
/// This avoids blocking unrelated branch state.
pub fn violations(ctx: *const Context, infos: []const PathInfo, report: *Report) !usize {
    const gpa = ctx.gpa;
    const entries = try ctx.manifest.?.entries(gpa);
    defer gpa.free(entries);
    var stored: std.StringHashMapUnmanaged(void) = .empty;
    defer stored.deinit(gpa);
    for (infos) |info| {
        if (info.cipher_rel != null) try stored.put(gpa, info.plain, {});
    }

    var n: usize = 0;
    for (ctx.tracked) |path| {
        if (Manifest.isReservedPath(path)) continue;
        const covered = mem.eql(u8, path, Manifest.filename) or
            Manifest.anyCovers(entries, path) or
            stored.contains(path);
        if (covered) {
            try report.add(gpa, .tracked, path, "tracked by git, run: git rm --cached -- <path>");
            n += 1;
        }
    }
    return n;
}

/// Holds the context and path analysis for one complete synchronization pass.
const Pass = struct {
    ctx: Context,
    infos: []PathInfo,

    fn init(
        repo: *const Repo,
        keys: crypto.DerivedKeys,
        only: []const []const u8,
        report: *Report,
    ) !Pass {
        var ctx = try Context.init(repo, keys);
        errdefer ctx.deinit();
        if (ctx.manifest == null) return Error.NoManifest;
        const infos = try analyze(&ctx, only, report);
        return .{ .ctx = ctx, .infos = infos };
    }

    fn deinit(self: *Pass) void {
        freeInfos(self.ctx.gpa, self.infos);
        self.ctx.deinit();
    }

    /// Adds exclusions for every stored path, even when no manifest currently covers it.
    fn writeExcludeBlock(self: *const Pass) !void {
        const gpa = self.ctx.gpa;
        var extra: std.ArrayList([]const u8) = .empty;
        defer extra.deinit(gpa);
        for (self.infos) |info| {
            if (info.cipher_rel != null) try extra.append(gpa, info.plain);
        }
        var buf: [2]*const Manifest = undefined;
        try updateExcludeFile(self.ctx.repo, self.ctx.manifestsForExclude(&buf), extra.items, &.{});
    }
};

const merging_detail = "edit the plain file, then run: turbocrypt git encrypt --force <path>";

/// Adds a report row for a decision that needs user action.
/// Returns whether the decision aborts encryption.
fn reportProblem(gpa: Allocator, info: *const PathInfo, report: *Report) !bool {
    switch (info.decision) {
        .abort_no_baseline => try report.add(
            gpa,
            .conflict,
            info.plain,
            "plain file and entry both exist and differ, no baseline: decrypt --force or encrypt --force",
        ),
        .abort_both_changed => try report.add(
            gpa,
            .conflict,
            info.plain,
            "changed here and upstream: decrypt --force or encrypt --force",
        ),
        .abort_bad => try report.add(
            gpa,
            .conflict,
            info.plain,
            "entry cannot be committed as it is: encrypt --force replaces it from the plain file, rm drops it",
        ),
        .abort_plain => {},
        .warn_missing => {
            try report.add(
                gpa,
                .missing,
                info.plain,
                "entry present, plain file absent: decrypt restores it, rm deletes it",
            );
            return false;
        },
        .warn_removed => {
            try report.add(
                gpa,
                .removed,
                info.plain,
                "entry removed upstream, plain file kept: decrypt deletes it, add keeps it",
            );
            return false;
        },
        else => return false,
    }
    return true;
}

/// Writes a decrypted entry to the working tree and records its baseline.
/// Returns false for a recoverable refusal after adding the reason to the report.
fn applyWritePlain(ctx: *Context, info: *PathInfo, report: *Report) !bool {
    const gpa = ctx.gpa;
    const detail: []const u8 = if (info.values.cur != null)
        "entry changed, plain file updated"
    else if (info.values.old != null)
        "was absent, restored"
    else
        "";
    writePlain(ctx, info) catch |err| switch (err) {
        Error.UnsafePath => {
            try report.add(
                gpa,
                .bad,
                info.plain,
                "destination is not a safe file inside the working tree",
            );
            return false;
        },
        Error.ChangedDuringSync => {
            try report.add(gpa, .conflict, info.plain, "changed while the sync ran, run it again");
            return false;
        },
        else => return err,
    };
    info.values.cur = .{
        .plain = crypto.fingerprint(info.decrypted.?, ctx.keys.fingerprint_key),
        .exec = info.values.new.?.exec,
    };
    try recordBaseline(ctx, info);
    try report.add(gpa, .written, info.plain, detail);
    return true;
}

/// Synchronizes plain-file changes into the encrypted store.
/// Analyze every path before writing so an abort leaves no partial update.
pub fn encrypt(
    repo: *const Repo,
    keys: crypto.DerivedKeys,
    options: Options,
    report: *Report,
) !void {
    const gpa = repo.gpa;
    var pass = try Pass.init(repo, keys, options.only, report);
    defer pass.deinit();
    const ctx = &pass.ctx;

    if (try violations(ctx, pass.infos, report) > 0) return Error.PrivateFileTracked;

    var aborted = false;
    for (pass.infos) |*info| {
        if (info.cipher_rel != null and ctx.isUnmerged(info.cipher_rel.?) and !options.force) {
            try report.add(gpa, .merging, info.plain, merging_detail);
            aborted = true;
            info.decision = .none;
            continue;
        }
        try decide(ctx, info, .encrypt, options.force, report);
        if (try reportProblem(gpa, info, report)) aborted = true;
        switch (info.decision) {
            .encrypt, .write_plain, .record, .delete_plain, .drop_baseline => report.pending += 1,
            else => {},
        }
        if (info.decision == .encrypt and !options.force) {
            if (info.values.new) |new| if (!new.header_ok) {
                try report.add(
                    gpa,
                    .bad,
                    info.plain,
                    "entry was written with another key or is corrupted: encrypt --force replaces it",
                );
                aborted = true;
            };
        }
    }
    if (aborted) return Error.SyncAborted;
    if (options.validate_only) return;

    var stage: std.ArrayList([]u8) = .empty;
    defer {
        for (stage.items) |s| gpa.free(s);
        stage.deinit(gpa);
    }
    for (pass.infos) |*info| {
        switch (info.decision) {
            .encrypt => {
                try encryptPlain(ctx, info, &stage);
                try recordBaseline(ctx, info);
                try report.add(gpa, .encrypted, info.plain, "");
            },
            .write_plain => if (!try applyWritePlain(ctx, info, report)) continue,
            .record => {
                try recordBaseline(ctx, info);
                try report.add(gpa, .ok, info.plain, "");
            },
            .drop_baseline => ctx.state.remove(gpa, info.plain),
            .none => if (info.values.new != null and info.values.cur != null) {
                try report.add(gpa, .ok, info.plain, "");
            },
            else => {},
        }
        if (info.cipher_rel != null and info.values.new != null and
            info.decision != .encrypt and !info.bad)
        {
            try stage.append(gpa, try storePath(gpa, &ctx.store_rel, info.cipher_rel.?));
        }
    }

    try ctx.state.save(gpa, ctx.io, repo.state_path, repo.tmp_dir);
    try pass.writeExcludeBlock();
    try repo.addForce(stage.items);
}

/// Synchronizes encrypted-store changes into the working tree.
/// Update exclusions first so Git never sees a private file as unignored.
pub fn decrypt(
    repo: *const Repo,
    keys: crypto.DerivedKeys,
    options: Options,
    report: *Report,
) !void {
    const gpa = repo.gpa;
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
                        try report.add(
                            gpa,
                            .conflict,
                            info.plain,
                            "changed while the sync ran, run it again",
                        );
                        continue;
                    },
                    else => return err,
                };
                ctx.state.remove(gpa, info.plain);
                try report.add(gpa, .deleted, info.plain, "entry removed upstream");
            },
            .record => {
                try recordBaseline(ctx, info);
                try report.add(gpa, .ok, info.plain, "");
            },
            .drop_baseline => ctx.state.remove(gpa, info.plain),
            .conflict => try report.add(
                gpa,
                .conflict,
                info.plain,
                "changed here and upstream: decrypt --force <path> takes the upstream version",
            ),
            .warn_removed => try report.add(
                gpa,
                .removed,
                info.plain,
                "entry removed upstream, plain file modified and kept",
            ),
            .none => if (info.values.new != null and info.values.cur != null) {
                try report.add(gpa, .ok, info.plain, "");
            },
            else => {},
        }
    }
    try ctx.state.save(gpa, ctx.io, repo.state_path, repo.tmp_dir);
}

/// Collects `turbocrypt git status` rows without changing files.
pub fn collectStatus(repo: *const Repo, keys: crypto.DerivedKeys, report: *Report) !void {
    const gpa = repo.gpa;
    var pass = try Pass.init(repo, keys, &.{}, report);
    defer pass.deinit();
    const ctx = &pass.ctx;

    _ = try violations(ctx, pass.infos, report);

    for (pass.infos) |*info| {
        if (info.cipher_rel != null and ctx.isUnmerged(info.cipher_rel.?)) {
            try report.add(gpa, .merging, info.plain, merging_detail);
            continue;
        }
        try decide(ctx, info, .encrypt, false, report);
        if (try reportProblem(gpa, info, report) or info.bad) continue;
        const v = info.values;
        switch (info.decision) {
            .none => if (v.cur != null) try report.add(gpa, .ok, info.plain, ""),
            .encrypt => if (v.old == null and v.new == null)
                try report.add(gpa, .new, info.plain, "no entry yet, " ++ pending_detail)
            else
                try report.add(gpa, .modified, info.plain, pending_detail),
            .write_plain => try report.add(
                gpa,
                .incoming,
                info.plain,
                "entry changed, run: turbocrypt git decrypt",
            ),
            .record => try report.add(gpa, .ok, info.plain, "same content on both sides"),
            else => {},
        }
    }
}

test "renamePreserve never overwrites and exchange swaps two files" {
    const gpa = testing.allocator;
    const io = testing.io;

    try Io.Dir.createDirPath(.cwd(), io, "tmp/sync_swap");
    defer Io.Dir.deleteTree(.cwd(), io, "tmp/sync_swap") catch {};
    try Io.Dir.writeFile(.cwd(), io, .{ .sub_path = "tmp/sync_swap/a", .data = "A" });
    try Io.Dir.writeFile(.cwd(), io, .{ .sub_path = "tmp/sync_swap/b", .data = "B" });

    try testing.expectError(
        error.PathAlreadyExists,
        Io.Dir.renamePreserve(.cwd(), "tmp/sync_swap/a", .cwd(), "tmp/sync_swap/b", io),
    );
    try Io.Dir.renamePreserve(.cwd(), "tmp/sync_swap/a", .cwd(), "tmp/sync_swap/c", io);
    try testing.expectError(
        error.FileNotFound,
        Io.Dir.renamePreserve(.cwd(), "tmp/sync_swap/a", .cwd(), "tmp/sync_swap/d", io),
    );

    exchange(gpa, .cwd(), "tmp/sync_swap/c", .cwd(), "tmp/sync_swap/b") catch |err| switch (err) {
        ExchangeError.Unsupported => return error.SkipZigTest,
        else => return err,
    };
    const c = try Io.Dir.readFileAlloc(.cwd(), io, "tmp/sync_swap/c", gpa, .limited(8));
    defer gpa.free(c);
    try testing.expectEqualStrings("B", c);
}

test "replace without an exchange keeps the old file inspectable" {
    const gpa = testing.allocator;
    const io = testing.io;

    try Io.Dir.createDirPath(.cwd(), io, "tmp/sync_aside/tree");
    try Io.Dir.createDirPath(.cwd(), io, "tmp/sync_aside/tmp");
    defer Io.Dir.deleteTree(.cwd(), io, "tmp/sync_aside") catch {};
    try Io.Dir.writeFile(.cwd(), io, .{ .sub_path = "tmp/sync_aside/tree/note.md", .data = "old" });

    var env = try std.process.Environ.createMap(testing.environ, gpa);
    defer env.deinit();
    const tmp_dir = try gpa.dupe(u8, "tmp/sync_aside/tmp");
    defer gpa.free(tmp_dir);
    const repo: Repo = .{
        .gpa = gpa,
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
    const ctx: Context = .{
        .repo = &repo,
        .keys = undefined,
        .gpa = gpa,
        .io = io,
        .state = .{ .key_id = @splat(0) },
        .manifest = null,
        .store_manifest = null,
        .store_rel = undefined,
        .store_abs = &.{},
        .tracked = &.{},
        .unmerged = &.{},
    };

    // Accept the documented size limit because the reader treats its limit as exclusive.
    const note = "tmp/sync_aside/tree/note.md";
    try testing.expect((try snapshot(&ctx, note, 3, @splat(0), null)) != null);

    var dir = try Io.Dir.openDir(.cwd(), io, "tmp/sync_aside/tree", .{});
    defer dir.close(io);
    var atomic = try processor.AtomicOutput.init(gpa, io, "note.md", .{}, tmp_dir);
    defer atomic.deinit(io);
    try atomic.file.writeStreamingAll(io, "new");

    const old = try moveAside(&ctx, &atomic, dir, "note.md", "note.md");
    defer gpa.free(old.path);
    try testing.expect(old.aside);
    try testing.expect(try fileHolds(&ctx, note, "new"));
    try testing.expect(try fileHolds(&ctx, old.path, "old"));

    try putBack(&ctx, &atomic, dir, "note.md", old);
    try testing.expect(try fileHolds(&ctx, note, "old"));
    try testing.expect(try fileHolds(&ctx, atomic.tmp_path, "new"));
}

test "each key gets its own stable, lowercase hex directory in the store" {
    const a = keyDirRel(crypto.deriveKeys(@splat(1), null));
    const again = keyDirRel(crypto.deriveKeys(@splat(1), null));
    const b = keyDirRel(crypto.deriveKeys(@splat(2), null));

    try testing.expectEqualStrings(&a, &again);
    try testing.expect(!mem.eql(u8, &a, &b));
    try testing.expect(mem.startsWith(u8, &a, enc_dir ++ "/"));
    for (a[enc_dir.len + 1 ..]) |c| {
        try testing.expect(std.ascii.isHex(c) and !std.ascii.isUpper(c));
    }
}

test "decrypt decisions take upstream changes unless the plain file changed too" {
    const b1: Baseline = .{ .plain = @splat(1), .exec = false, .id = @splat(9) };
    const c_same: Current = .{ .plain = @splat(1), .exec = false };
    const c_other: Current = .{ .plain = @splat(2), .exec = false };
    const c_exec: Current = .{ .plain = @splat(1), .exec = true };
    const n_same: New = .{ .id = @splat(9), .exec = false };
    const n_other: New = .{ .id = @splat(8), .exec = false };

    try testing.expectEqual(.none, decideDecrypt(.{ .old = null, .new = null, .cur = c_same }, false));
    try testing.expectEqual(.write_plain, decideDecrypt(.{ .old = null, .new = n_same, .cur = null }, false));
    try testing.expectEqual(.need_compare, decideDecrypt(.{ .old = null, .new = n_same, .cur = c_same }, false));
    try testing.expectEqual(.record, decideDecrypt(.{ .old = null, .new = n_same, .cur = c_same, .cur_eql_new = true }, false));
    try testing.expectEqual(.conflict, decideDecrypt(.{ .old = null, .new = n_same, .cur = c_same, .cur_eql_new = false }, false));
    try testing.expectEqual(.write_plain, decideDecrypt(.{ .old = null, .new = n_same, .cur = c_same, .cur_eql_new = false }, true));
    try testing.expectEqual(.drop_baseline, decideDecrypt(.{ .old = b1, .new = null, .cur = null }, false));
    try testing.expectEqual(.delete_plain, decideDecrypt(.{ .old = b1, .new = null, .cur = c_same }, false));
    try testing.expectEqual(.warn_removed, decideDecrypt(.{ .old = b1, .new = null, .cur = c_other }, false));
    try testing.expectEqual(.delete_plain, decideDecrypt(.{ .old = b1, .new = null, .cur = c_other }, true));
    try testing.expectEqual(.write_plain, decideDecrypt(.{ .old = b1, .new = n_same, .cur = null }, false));
    try testing.expectEqual(.write_plain, decideDecrypt(.{ .old = b1, .new = n_other, .cur = null }, false));
    try testing.expectEqual(.none, decideDecrypt(.{ .old = b1, .new = n_same, .cur = c_other }, false));
    try testing.expectEqual(.write_plain, decideDecrypt(.{ .old = b1, .new = n_other, .cur = c_same }, false));
    try testing.expectEqual(.need_compare, decideDecrypt(.{ .old = b1, .new = n_other, .cur = c_other }, false));
    try testing.expectEqual(.record, decideDecrypt(.{ .old = b1, .new = n_other, .cur = c_other, .cur_eql_new = true }, false));
    try testing.expectEqual(.conflict, decideDecrypt(.{ .old = b1, .new = n_other, .cur = c_other, .cur_eql_new = false }, false));
    try testing.expectEqual(.write_plain, decideDecrypt(.{ .old = b1, .new = n_other, .cur = c_other, .cur_eql_new = false }, true));
    try testing.expectEqual(.write_plain, decideDecrypt(.{ .old = b1, .new = .{ .id = @splat(9), .exec = true }, .cur = c_same }, false));
    try testing.expectEqual(.need_compare, decideDecrypt(.{ .old = b1, .new = n_other, .cur = c_exec }, false));
}

test "encrypt decisions stop at a change on both sides unless forced" {
    const b1: Baseline = .{ .plain = @splat(1), .exec = false, .id = @splat(9) };
    const c_same: Current = .{ .plain = @splat(1), .exec = false };
    const c_other: Current = .{ .plain = @splat(2), .exec = false };
    const c_exec: Current = .{ .plain = @splat(1), .exec = true };
    const n_same: New = .{ .id = @splat(9), .exec = false };
    const n_other: New = .{ .id = @splat(8), .exec = false };

    try testing.expectEqual(.none, decideEncrypt(.{ .old = null, .new = null, .cur = null }, false));
    try testing.expectEqual(.encrypt, decideEncrypt(.{ .old = null, .new = null, .cur = c_same }, false));
    try testing.expectEqual(.warn_missing, decideEncrypt(.{ .old = null, .new = n_same, .cur = null }, false));
    try testing.expectEqual(.need_compare, decideEncrypt(.{ .old = null, .new = n_same, .cur = c_same }, false));
    try testing.expectEqual(.record, decideEncrypt(.{ .old = null, .new = n_same, .cur = c_same, .cur_eql_new = true }, false));
    try testing.expectEqual(.abort_no_baseline, decideEncrypt(.{ .old = null, .new = n_same, .cur = c_same, .cur_eql_new = false }, false));
    try testing.expectEqual(.encrypt, decideEncrypt(.{ .old = null, .new = n_same, .cur = c_same, .cur_eql_new = false }, true));
    try testing.expectEqual(.drop_baseline, decideEncrypt(.{ .old = b1, .new = null, .cur = null }, false));
    try testing.expectEqual(.warn_removed, decideEncrypt(.{ .old = b1, .new = null, .cur = c_same }, false));
    try testing.expectEqual(.encrypt, decideEncrypt(.{ .old = b1, .new = null, .cur = c_same }, true));
    try testing.expectEqual(.warn_missing, decideEncrypt(.{ .old = b1, .new = n_other, .cur = null }, false));
    try testing.expectEqual(.none, decideEncrypt(.{ .old = b1, .new = n_same, .cur = c_same }, false));
    try testing.expectEqual(.encrypt, decideEncrypt(.{ .old = b1, .new = n_same, .cur = c_other }, false));
    try testing.expectEqual(.encrypt, decideEncrypt(.{ .old = b1, .new = n_same, .cur = c_exec }, false));
    try testing.expectEqual(.write_plain, decideEncrypt(.{ .old = b1, .new = n_other, .cur = c_same }, false));
    try testing.expectEqual(.need_compare, decideEncrypt(.{ .old = b1, .new = n_other, .cur = c_other }, false));
    try testing.expectEqual(.record, decideEncrypt(.{ .old = b1, .new = n_other, .cur = c_other, .cur_eql_new = true }, false));
    try testing.expectEqual(.abort_both_changed, decideEncrypt(.{ .old = b1, .new = n_other, .cur = c_other, .cur_eql_new = false }, false));
    try testing.expectEqual(.encrypt, decideEncrypt(.{ .old = b1, .new = n_other, .cur = c_other, .cur_eql_new = false }, true));
}

test "a bad path stops the encrypt direction unless force can replace its entry" {
    const cur: Current = .{ .plain = @splat(1), .exec = false };

    var plain_only: PathInfo = .{
        .plain = @constCast("a"),
        .values = .{ .old = null, .new = null, .cur = cur },
        .bad = true,
    };
    try testing.expectEqual(.abort_plain, badDecision(&plain_only, .encrypt, true));
    try testing.expectEqual(.none, badDecision(&plain_only, .decrypt, false));
    plain_only.values.cur = null;
    try testing.expectEqual(.abort_plain, badDecision(&plain_only, .encrypt, false));

    var entry: PathInfo = .{
        .plain = @constCast("a"),
        .cipher_rel = @constCast("b"),
        .values = .{ .old = null, .new = null, .cur = cur },
        .bad = true,
    };
    try testing.expectEqual(.abort_bad, badDecision(&entry, .encrypt, false));
    try testing.expectEqual(.encrypt, badDecision(&entry, .encrypt, true));
    entry.values.cur = null;
    try testing.expectEqual(.abort_bad, badDecision(&entry, .encrypt, true));
    try testing.expectEqual(.none, badDecision(&entry, .decrypt, true));
}

test "state survives a round trip and reads as empty under another key" {
    const gpa = testing.allocator;

    const key_id: [crypto.mac_length]u8 = @splat(5);
    var state: State = .{ .key_id = key_id };
    defer state.deinit(gpa);
    try state.put(gpa, "docs/internal.md", .{
        .plain = @splat(0xab),
        .exec = true,
        .id = @splat(0xcd),
    });
    try state.put(gpa, "AGENT.md", .{ .plain = @splat(1), .exec = false, .id = @splat(2) });
    try state.put(gpa, "AGENT.md", .{ .plain = @splat(3), .exec = false, .id = @splat(4) });

    const text = try state.render(gpa);
    defer gpa.free(text);

    var loaded = try State.parse(gpa, text, key_id);
    defer loaded.deinit(gpa);
    try testing.expectEqual(2, loaded.map.count());
    const doc = loaded.get("docs/internal.md").?;
    try testing.expect(doc.exec);
    try testing.expectEqualSlices(u8, &@as([16]u8, @splat(0xab)), &doc.plain);
    try testing.expectEqualSlices(u8, &@as([16]u8, @splat(0xcd)), &doc.id);
    try testing.expectEqualSlices(u8, &@as([16]u8, @splat(3)), &loaded.get("AGENT.md").?.plain);

    loaded.remove(gpa, "AGENT.md");
    try testing.expect(loaded.get("AGENT.md") == null);

    var other = try State.parse(gpa, text, @splat(6));
    defer other.deinit(gpa);
    try testing.expectEqual(0, other.map.count());

    const future = "{\"version\": 2, \"entries\": []}";
    try testing.expectError(Error.InvalidState, State.parse(gpa, future, key_id));
    try testing.expectError(Error.InvalidState, State.parse(gpa, "not json", key_id));
}

test "validateDestination refuses unsafe, tracked, and symlinked destinations" {
    const gpa = testing.allocator;
    const io = testing.io;

    try Io.Dir.createDirPath(.cwd(), io, "tmp/sync_dest/real");
    defer Io.Dir.deleteTree(.cwd(), io, "tmp/sync_dest") catch {};
    try Io.Dir.writeFile(.cwd(), io, .{ .sub_path = "tmp/sync_dest/plainfile", .data = "x" });
    const toplevel = try Io.Dir.realPathFileAlloc(.cwd(), io, "tmp/sync_dest", gpa);
    defer gpa.free(toplevel);

    const tracked = [_][]const u8{"tracked.md"};
    try validateDestination(gpa, io, toplevel, "real/new.md", &tracked);
    try validateDestination(gpa, io, toplevel, "fresh/dir/new.md", &tracked);
    try testing.expectError(Error.UnsafePath, validateDestination(gpa, io, toplevel, "/abs", &tracked));
    try testing.expectError(Error.UnsafePath, validateDestination(gpa, io, toplevel, "../up", &tracked));
    try testing.expectError(Error.UnsafePath, validateDestination(gpa, io, toplevel, "a/../b", &tracked));
    try testing.expectError(Error.UnsafePath, validateDestination(gpa, io, toplevel, ".git/config", &tracked));
    try testing.expectError(Error.UnsafePath, validateDestination(gpa, io, toplevel, "tracked.md", &tracked));
    try testing.expectError(Error.UnsafePath, validateDestination(gpa, io, toplevel, "plainfile/child", &tracked));

    const target = try Io.Dir.path.join(gpa, &.{ toplevel, "real" });
    defer gpa.free(target);
    Io.Dir.symLink(.cwd(), io, target, "tmp/sync_dest/link", .{}) catch return error.SkipZigTest;
    try testing.expectError(Error.UnsafePath, validateDestination(gpa, io, toplevel, "link/new.md", &tracked));
    try testing.expectError(Error.UnsafePath, validateDestination(gpa, io, toplevel, "link", &tracked));
}
