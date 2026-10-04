//! Shared filesystem helpers that keep commands' paths and writes safe.

const std = @import("std");
const builtin = @import("builtin");
const mem = std.mem;
const testing = std.testing;
const Allocator = std.mem.Allocator;
const Io = std.Io;

const container = @import("container.zig");

/// Restricts secret files to their owner so keys and config data stay private.
pub const private_file_permissions: Io.File.Permissions = if (builtin.os.tag == .windows)
    .default_file
else
    .fromMode(0o600);

pub const WalkCallback = *const fn (
    relative_path: []const u8,
    full_path: []const u8,
    is_directory: bool,
    context: *anyopaque,
) anyerror!void;

/// Includes file links unless `ignore_symlinks` is set, but skips directory links to avoid cycles.
///
/// Stops at nested containers so they are not handled as ordinary input.
/// Callers check the base path and its ancestors before starting the walk.
pub fn walkDir(
    gpa: Allocator,
    io: Io,
    base_path: []const u8,
    callback: WalkCallback,
    context: *anyopaque,
    ignore_symlinks: bool,
) !void {
    var dir = try Io.Dir.openDir(.cwd(), io, base_path, .{ .iterate = true });
    defer dir.close(io);

    var walker = try dir.walk(gpa);
    defer walker.deinit();

    while (try walker.next(io)) |entry| {
        const full_path = try Io.Dir.path.join(gpa, &.{ base_path, entry.path });
        defer gpa.free(full_path);

        if (entry.kind == .directory) {
            if (container.hasDescriptorAt(entry.dir, io, entry.basename)) {
                container.explainRefusal(full_path, full_path);
                return error.ContainerInTree;
            }
            try callback(entry.path, full_path, true, context);
        } else if (entry.kind == .file) {
            try callback(entry.path, full_path, false, context);
        } else if (entry.kind == .sym_link) {
            if (ignore_symlinks) continue;

            const stat = Io.Dir.statFile(.cwd(), io, full_path, .{}) catch |err| {
                std.debug.print("Warning: skipping symlink '{s}' ({})\n", .{ full_path, err });
                continue;
            };

            if (stat.kind == .directory) {
                // Do not follow directory links, which can make the walk loop.
                std.debug.print("Warning: skipping symlinked directory '{s}'\n", .{full_path});
                continue;
            } else if (stat.kind == .file) {
                try callback(entry.path, full_path, false, context);
            }
        }
    }
}

pub fn ensureDir(io: Io, path: []const u8) !void {
    Io.Dir.createDirPath(.cwd(), io, path) catch |err| {
        if (err != error.PathAlreadyExists) return err;
    };
}

pub const PathRelation = enum { same, descendant, other };

/// Resolves possible destinations, including missing path tails, so containment checks use their eventual location.
/// The caller owns the returned memory.
pub fn canonicalizePotentialPath(gpa: Allocator, io: Io, path: []const u8) ![]u8 {
    const canonical = Io.Dir.realPathFileAlloc(.cwd(), io, path, gpa) catch |err| switch (err) {
        error.FileNotFound => {
            const parent = Io.Dir.path.dirname(path) orelse ".";
            const canonical_parent = try canonicalizePotentialPath(gpa, io, parent);
            defer gpa.free(canonical_parent);
            return Io.Dir.path.join(gpa, &.{ canonical_parent, Io.Dir.path.basename(path) });
        },
        else => return err,
    };
    // Return an ordinary owned slice so callers can free it consistently.
    defer gpa.free(canonical);
    return gpa.dupe(u8, canonical);
}

/// Determines whether `candidate` is `parent`, below it, or elsewhere after resolving links.
/// Both paths may be missing.
pub fn pathRelation(
    gpa: Allocator,
    io: Io,
    parent: []const u8,
    candidate: []const u8,
) !PathRelation {
    const cwd = try Io.Dir.realPathFileAlloc(.cwd(), io, ".", gpa);
    defer gpa.free(cwd);
    const parent_canonical = try canonicalizePotentialPath(gpa, io, parent);
    defer gpa.free(parent_canonical);
    const candidate_canonical = try canonicalizePotentialPath(gpa, io, candidate);
    defer gpa.free(candidate_canonical);

    const relative = try Io.Dir.path.relativeAlloc(
        gpa,
        cwd,
        null,
        parent_canonical,
        candidate_canonical,
    );
    defer gpa.free(relative);
    if (relative.len == 0) return .same;
    if (Io.Dir.path.isAbsolute(relative)) return .other;
    const first = relative[0 .. mem.findAny(u8, relative, "/\\") orelse relative.len];
    return if (mem.eql(u8, first, "..")) .other else .descendant;
}

pub fn isPlainComponent(component: []const u8) bool {
    return component.len != 0 and !mem.eql(u8, component, ".") and !mem.eql(u8, component, "..");
}

/// Opens `sub_path`'s parent beneath `root` without letting links redirect writes outside it.
///
/// Rejects empty, dot, and dot-dot components to keep the path contained.
/// Returns null for missing parents unless `create` is set, and for links or non-directories.
/// The caller closes the returned handle.
pub fn openParentIn(io: Io, root: Io.Dir, sub_path: []const u8, create: bool) !?Io.Dir {
    var it = mem.splitScalar(u8, sub_path, '/');
    var component = it.next() orelse return error.UnsafePath;
    var dir = try root.openDir(io, ".", .{});
    errdefer dir.close(io);
    while (true) {
        if (!isPlainComponent(component)) return error.UnsafePath;
        const next = it.next() orelse return dir;
        // Platforms report a refused symlink differently, so handle both forms.
        const child = dir.openDir(io, component, .{ .follow_symlinks = false }) catch |err| switch (err) {
            error.FileNotFound, error.SymLinkLoop, error.NotDir => blk: {
                if (!create or err != error.FileNotFound) {
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
        component = next;
    }
}

/// Opens a parent below the `root` path rather than an existing directory handle.
/// Creates a missing root when `create` is set.
pub fn openParent(io: Io, root: []const u8, sub_path: []const u8, create: bool) !?Io.Dir {
    var dir = Io.Dir.openDir(.cwd(), io, root, .{}) catch |err| switch (err) {
        error.FileNotFound => blk: {
            if (!create) return err;
            try ensureDir(io, root);
            break :blk try Io.Dir.openDir(.cwd(), io, root, .{});
        },
        else => return err,
    };
    defer dir.close(io);
    return openParentIn(io, dir, sub_path, create);
}

pub fn pathExists(io: Io, path: []const u8) bool {
    Io.Dir.access(.cwd(), io, path, .{}) catch return false;
    return true;
}

pub fn isDir(io: Io, path: []const u8) !bool {
    const stat = Io.Dir.statFile(.cwd(), io, path, .{}) catch |err| {
        // Windows reports directories through `IsDir` instead of a file stat.
        if (err == error.IsDir) return true;
        return err;
    };
    return stat.kind == .directory;
}

/// Supports exact paths, suffixes, prefixes, and directory names at any depth.
pub fn matchesExcludePattern(
    relative_path: []const u8,
    patterns: std.ArrayList([]const u8),
) bool {
    for (patterns.items) |pattern| {
        if (matchesPattern(relative_path, pattern)) {
            return true;
        }
    }
    return false;
}

fn matchesPattern(path: []const u8, pattern: []const u8) bool {
    // Match whole directory components so ".git/" does not exclude ".gitignore".
    if (mem.endsWith(u8, pattern, "/")) {
        const dir_name = pattern[0 .. pattern.len - 1];
        var components = Io.Dir.path.componentIterator(path);
        while (components.next()) |component| {
            if (mem.eql(u8, component.name, dir_name)) return true;
        }
        return false;
    }

    if (mem.startsWith(u8, pattern, "*.")) {
        const ext = pattern[1..];
        return mem.endsWith(u8, path, ext);
    }

    if (mem.startsWith(u8, pattern, "*")) {
        const suffix = pattern[1..];
        return mem.endsWith(u8, path, suffix);
    }

    if (mem.endsWith(u8, pattern, "*")) {
        const prefix = pattern[0 .. pattern.len - 1];
        return mem.startsWith(u8, path, prefix);
    }

    return mem.eql(u8, path, pattern);
}

/// Collects paths reported by `walkDir` so tests can inspect them.
const Visited = struct {
    gpa: Allocator,
    files: std.ArrayList([]const u8) = .empty,
    dirs: std.ArrayList([]const u8) = .empty,

    fn deinit(visited: *Visited) void {
        for (visited.files.items) |path| visited.gpa.free(path);
        visited.files.deinit(visited.gpa);
        for (visited.dirs.items) |path| visited.gpa.free(path);
        visited.dirs.deinit(visited.gpa);
    }

    fn record(
        relative_path: []const u8,
        full_path: []const u8,
        is_directory: bool,
        context: *anyopaque,
    ) !void {
        _ = full_path;
        const visited: *Visited = @ptrCast(@alignCast(context));
        const list = if (is_directory) &visited.dirs else &visited.files;
        try list.append(visited.gpa, try visited.gpa.dupe(u8, relative_path));
    }
};

test "walkDir reports files and directories" {
    const gpa = testing.allocator;
    const io = testing.io;

    try ensureDir(io, "tmp/walk_test/subdir");
    defer Io.Dir.deleteTree(.cwd(), io, "tmp/walk_test") catch {};

    {
        var dir = try Io.Dir.openDir(.cwd(), io, "tmp/walk_test", .{});
        defer dir.close(io);
        try dir.writeFile(io, .{ .sub_path = "file1.txt", .data = "test1" });
        try dir.writeFile(io, .{ .sub_path = "subdir/file2.txt", .data = "test2" });
        try dir.writeFile(io, .{ .sub_path = "subdir/file3.txt", .data = "test3" });
    }

    var visited: Visited = .{ .gpa = gpa };
    defer visited.deinit();

    try walkDir(gpa, io, "tmp/walk_test", Visited.record, &visited, false);

    try testing.expectEqual(3, visited.files.items.len);
    try testing.expectEqual(1, visited.dirs.items.len);
}

test "a container inside the tree stops the walk before its callback" {
    const gpa = testing.allocator;
    const io = testing.io;

    try ensureDir(io, "tmp/walk_container/ok");
    try ensureDir(io, "tmp/walk_container/box/inner");
    defer Io.Dir.deleteTree(.cwd(), io, "tmp/walk_container") catch {};
    {
        var dir = try Io.Dir.openDir(.cwd(), io, "tmp/walk_container", .{});
        defer dir.close(io);
        try dir.writeFile(io, .{ .sub_path = "ok/f", .data = "x" });
        const descriptor = "box/" ++ container.descriptor_name;
        try dir.writeFile(io, .{ .sub_path = descriptor, .data = "marker" });
        try dir.writeFile(io, .{ .sub_path = "box/inner/g", .data = "y" });
    }

    var visited: Visited = .{ .gpa = gpa };
    defer visited.deinit();
    try testing.expectError(
        error.ContainerInTree,
        walkDir(gpa, io, "tmp/walk_container", Visited.record, &visited, false),
    );
    for (visited.dirs.items) |path| try testing.expect(!mem.startsWith(u8, path, "box"));
    for (visited.files.items) |path| try testing.expect(!mem.startsWith(u8, path, "box"));
}

test "ensureDir creates nested directories" {
    const io = testing.io;

    try ensureDir(io, "tmp/nested/deeply/nested/path");
    defer Io.Dir.deleteTree(.cwd(), io, "tmp/nested") catch {};

    try testing.expect(try isDir(io, "tmp/nested/deeply/nested/path"));
}

test "pathExists tells existing and missing files apart" {
    const io = testing.io;

    try ensureDir(io, "tmp/path_exists");
    defer Io.Dir.deleteTree(.cwd(), io, "tmp/path_exists") catch {};

    try Io.Dir.writeFile(.cwd(), io, .{ .sub_path = "tmp/path_exists/exists.txt", .data = "" });

    try testing.expect(pathExists(io, "tmp/path_exists/exists.txt"));
    try testing.expect(!pathExists(io, "tmp/path_exists/does_not_exist.txt"));
}

test "symlinks to files are followed unless ignore_symlinks is set" {
    const gpa = testing.allocator;
    const io = testing.io;

    try ensureDir(io, "tmp/symlink_test");
    defer Io.Dir.deleteTree(.cwd(), io, "tmp/symlink_test") catch {};

    var target_dir = try Io.Dir.openDir(.cwd(), io, "tmp/symlink_test", .{});
    defer target_dir.close(io);
    try target_dir.writeFile(io, .{ .sub_path = "target.txt", .data = "target content" });
    target_dir.symLink(io, "target.txt", "link.txt", .{}) catch |err| {
        // Skip where the platform does not allow test symlinks.
        if (err == error.Unexpected) return error.SkipZigTest;
        return err;
    };

    {
        var visited: Visited = .{ .gpa = gpa };
        defer visited.deinit();

        try walkDir(gpa, io, "tmp/symlink_test", Visited.record, &visited, false);

        try testing.expectEqual(2, visited.files.items.len);
    }
    {
        var visited: Visited = .{ .gpa = gpa };
        defer visited.deinit();

        try walkDir(gpa, io, "tmp/symlink_test", Visited.record, &visited, true);

        try testing.expectEqual(1, visited.files.items.len);
        try testing.expectEqualStrings("target.txt", visited.files.items[0]);
    }
}

test "exclude patterns match extensions and whole directory components" {
    const gpa = testing.allocator;

    var patterns: std.ArrayList([]const u8) = .empty;
    defer patterns.deinit(gpa);

    try patterns.append(gpa, "*.log");
    try patterns.append(gpa, "*.tmp");
    try patterns.append(gpa, ".git/");
    try patterns.append(gpa, "node_modules/");

    try testing.expect(matchesExcludePattern("debug.log", patterns));
    try testing.expect(matchesExcludePattern("temp.tmp", patterns));
    try testing.expect(!matchesExcludePattern("data.txt", patterns));

    try testing.expect(matchesExcludePattern(".git/config", patterns));
    try testing.expect(matchesExcludePattern(".git/objects/abc", patterns));
    try testing.expect(matchesExcludePattern("node_modules/package/index.js", patterns));

    try testing.expect(!matchesExcludePattern("src/main.zig", patterns));
    try testing.expect(!matchesExcludePattern("README.md", patterns));

    // Names that only resemble directory patterns must stay included.
    try testing.expect(!matchesExcludePattern(".gitignore", patterns));
    try testing.expect(!matchesExcludePattern(".github/workflows/ci.yml", patterns));
    try testing.expect(matchesExcludePattern("src/.git", patterns));
    try testing.expect(matchesExcludePattern("src/node_modules/x.js", patterns));
    try testing.expect(matchesExcludePattern("my_node_modules/node_modules/x.js", patterns));
    try testing.expect(!matchesExcludePattern("my_node_modules/x.js", patterns));
}

test "pathRelation tells the same place, descendants and other paths apart" {
    const gpa = testing.allocator;
    const io = testing.io;

    try Io.Dir.createDirPath(.cwd(), io, "tmp/relation/source/inner");
    defer Io.Dir.deleteTree(.cwd(), io, "tmp/relation") catch {};

    const base = "tmp/relation/source";
    try testing.expectEqual(.same, try pathRelation(gpa, io, base, base));
    try testing.expectEqual(.same, try pathRelation(gpa, io, base, base ++ "/inner/.."));
    try testing.expectEqual(.descendant, try pathRelation(gpa, io, base, base ++ "/new/deeper"));
    try testing.expectEqual(.other, try pathRelation(gpa, io, base, "tmp/relation/sibling"));
    try testing.expectEqual(.other, try pathRelation(gpa, io, base, "tmp/relation"));
    try testing.expectEqual(.other, try pathRelation(gpa, io, base, base ++ "-two"));
}

test "a missing name without a directory part is canonicalized under the current directory" {
    const gpa = testing.allocator;
    const io = testing.io;

    const cwd = try Io.Dir.realPathFileAlloc(.cwd(), io, ".", gpa);
    defer gpa.free(cwd);
    const expected = try Io.Dir.path.join(gpa, &.{ cwd, "no-such-file-here.txt" });
    defer gpa.free(expected);
    const canonical = try canonicalizePotentialPath(gpa, io, "no-such-file-here.txt");
    defer gpa.free(canonical);
    try testing.expectEqualStrings(expected, canonical);

    const expected_nested = try Io.Dir.path.join(
        gpa,
        &.{ cwd, "no-such-dir-here", "deeper", "file" },
    );
    defer gpa.free(expected_nested);
    const nested = try canonicalizePotentialPath(gpa, io, "no-such-dir-here/deeper/file");
    defer gpa.free(nested);
    try testing.expectEqualStrings(expected_nested, nested);
}

test "openParentIn walks through handles and refuses unsafe components" {
    const io = testing.io;

    try ensureDir(io, "tmp/open_parent/a/b");
    defer Io.Dir.deleteTree(.cwd(), io, "tmp/open_parent") catch {};
    var root = try Io.Dir.openDir(.cwd(), io, "tmp/open_parent", .{});
    defer root.close(io);

    {
        var parent = (try openParentIn(io, root, "a/b/file", false)).?;
        defer parent.close(io);
        const f = try parent.createFile(io, "file", .{});
        f.close(io);
        _ = try Io.Dir.statFile(.cwd(), io, "tmp/open_parent/a/b/file", .{});
    }
    {
        var parent = (try openParentIn(io, root, "top", false)).?;
        defer parent.close(io);
        const f = try parent.createFile(io, "top", .{});
        f.close(io);
        _ = try Io.Dir.statFile(.cwd(), io, "tmp/open_parent/top", .{});
    }
    try testing.expectEqual(null, try openParentIn(io, root, "missing/file", false));
    try testing.expectError(error.UnsafePath, openParentIn(io, root, "a//file", false));
    try testing.expectError(error.UnsafePath, openParentIn(io, root, "a/../file", false));
    try testing.expectError(error.UnsafePath, openParentIn(io, root, "./file", false));
    try testing.expectError(error.UnsafePath, openParentIn(io, root, "", false));

    if (builtin.os.tag == .windows) return;
    root.symLink(io, "a", "link", .{ .is_directory = true }) catch return;
    try testing.expectEqual(null, try openParentIn(io, root, "link/file", false));
    try testing.expectEqual(null, try openParentIn(io, root, "link/file", true));
    try testing.expectEqual(null, try openParent(io, "tmp/open_parent", "link/file", false));

    var created = (try openParentIn(io, root, "new/deeper/file", true)).?;
    created.close(io);
    try testing.expect(try isDir(io, "tmp/open_parent/new/deeper"));
}
