const std = @import("std");
const builtin = @import("builtin");

/// Mode for files that hold secrets, such as keys and the config file
pub const private_file_permissions: std.Io.File.Permissions = if (builtin.os.tag == .windows)
    .default_file
else
    .fromMode(0o600);

pub const WalkCallback = *const fn (
    relative_path: []const u8,
    full_path: []const u8,
    is_directory: bool,
    context: *anyopaque,
) anyerror!void;

/// Links to files count as files, unless ignore_symlinks is set. Links to directories are always skipped.
pub fn walkDirectory(
    base_path: []const u8,
    callback: WalkCallback,
    context: *anyopaque,
    allocator: std.mem.Allocator,
    ignore_symlinks: bool,
    io: std.Io,
) !void {
    var dir = try std.Io.Dir.openDir(.cwd(), io, base_path, .{ .iterate = true });
    defer dir.close(io);

    var walker = try dir.walk(allocator);
    defer walker.deinit();

    while (try walker.next(io)) |entry| {
        const full_path = try std.fs.path.join(allocator, &[_][]const u8{ base_path, entry.path });
        defer allocator.free(full_path);

        if (entry.kind == .directory) {
            try callback(entry.path, full_path, true, context);
        } else if (entry.kind == .file) {
            try callback(entry.path, full_path, false, context);
        } else if (entry.kind == .sym_link) {
            if (ignore_symlinks) {
                continue;
            }

            const stat = std.Io.Dir.statFile(.cwd(), io, full_path, .{}) catch |err| {
                std.debug.print("Warning: skipping symlink '{s}' ({})\n", .{ full_path, err });
                continue;
            };

            if (stat.kind == .directory) {
                // A link to a directory could loop.
                std.debug.print("Warning: skipping symlinked directory '{s}'\n", .{full_path});
                continue;
            } else if (stat.kind == .file) {
                try callback(entry.path, full_path, false, context);
            }
        }
    }
}

pub fn ensureDirectory(path: []const u8, io: std.Io) !void {
    std.Io.Dir.createDirPath(.cwd(), io, path) catch |err| {
        if (err != error.PathAlreadyExists) return err;
    };
}

pub const PathRelation = enum { same, descendant, other };

/// The real path of `path`. A path that does not exist yet builds on the real path of its nearest ancestor.
pub fn canonicalizePotentialPath(path: []const u8, allocator: std.mem.Allocator, io: std.Io) ![]u8 {
    const canonical = std.Io.Dir.realPathFileAlloc(.cwd(), io, path, allocator) catch |err| switch (err) {
        error.FileNotFound => {
            const parent = std.fs.path.dirname(path) orelse return allocator.dupe(u8, path);
            const canonical_parent = try canonicalizePotentialPath(parent, allocator, io);
            defer allocator.free(canonical_parent);
            return std.fs.path.join(allocator, &.{ canonical_parent, std.fs.path.basename(path) });
        },
        else => return err,
    };
    // The real path carries a sentinel, so a plain slice could not free it.
    defer allocator.free(canonical);
    return allocator.dupe(u8, canonical);
}

/// Where `candidate` stands relative to `parent`, symbolic links resolved: the same place, inside it, or elsewhere.
/// Neither path has to exist yet.
pub fn pathRelation(parent: []const u8, candidate: []const u8, allocator: std.mem.Allocator, io: std.Io) !PathRelation {
    const cwd = try std.Io.Dir.realPathFileAlloc(.cwd(), io, ".", allocator);
    defer allocator.free(cwd);
    const parent_canonical = try canonicalizePotentialPath(parent, allocator, io);
    defer allocator.free(parent_canonical);
    const candidate_canonical = try canonicalizePotentialPath(candidate, allocator, io);
    defer allocator.free(candidate_canonical);

    const relative = try std.fs.path.relative(allocator, cwd, null, parent_canonical, candidate_canonical);
    defer allocator.free(relative);
    if (relative.len == 0) return .same;
    if (std.fs.path.isAbsolute(relative)) return .other;
    const first = relative[0 .. std.mem.indexOfAny(u8, relative, "/\\") orelse relative.len];
    return if (std.mem.eql(u8, first, "..")) .other else .descendant;
}

pub fn containsString(list: []const []const u8, needle: []const u8) bool {
    for (list) |item| {
        if (std.mem.eql(u8, item, needle)) return true;
    }
    return false;
}

/// Free a list of owned strings and the list itself.
pub fn freeList(allocator: std.mem.Allocator, list: []const []u8) void {
    for (list) |item| allocator.free(item);
    allocator.free(list);
}

/// Like std.fs.path.dirname, but owned and never null.
pub fn dirname(path: []const u8, allocator: std.mem.Allocator) ![]u8 {
    const dir = std.fs.path.dirname(path) orelse "";
    return try allocator.dupe(u8, dir);
}

pub fn pathExists(path: []const u8, io: std.Io) bool {
    std.Io.Dir.access(.cwd(), io, path, .{}) catch return false;
    return true;
}

pub fn isDirectory(path: []const u8, io: std.Io) !bool {
    const stat = std.Io.Dir.statFile(.cwd(), io, path, .{}) catch |err| {
        // On Windows, statFile returns error.IsDir for a directory.
        if (err == error.IsDir) return true;
        return err;
    };
    return stat.kind == .directory;
}

/// A pattern is an exact path, a "*suffix", a "prefix*", or a "dir/" component at any depth.
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
    // Directory patterns match a whole path component at any depth, so ".git/" does not match ".gitignore".
    if (std.mem.endsWith(u8, pattern, "/")) {
        const dir_name = pattern[0 .. pattern.len - 1];
        var components = std.fs.path.componentIterator(path);
        while (components.next()) |component| {
            if (std.mem.eql(u8, component.name, dir_name)) return true;
        }
        return false;
    }

    if (std.mem.startsWith(u8, pattern, "*.")) {
        const ext = pattern[1..];
        return std.mem.endsWith(u8, path, ext);
    }

    if (std.mem.startsWith(u8, pattern, "*")) {
        const suffix = pattern[1..];
        return std.mem.endsWith(u8, path, suffix);
    }

    if (std.mem.endsWith(u8, pattern, "*")) {
        const prefix = pattern[0 .. pattern.len - 1];
        return std.mem.startsWith(u8, path, prefix);
    }

    return std.mem.eql(u8, path, pattern);
}

test "directory walking" {
    const testing = std.testing;
    const allocator = testing.allocator;
    const io = testing.io;

    try ensureDirectory("tmp/walk_test/subdir", io);
    defer std.Io.Dir.deleteTree(.cwd(), io, "tmp/walk_test") catch {};

    {
        const f1 = try std.Io.Dir.createFile(.cwd(), io, "tmp/walk_test/file1.txt", .{});
        defer f1.close(io);
        try f1.writeStreamingAll(io, "test1");
    }
    {
        const f2 = try std.Io.Dir.createFile(.cwd(), io, "tmp/walk_test/subdir/file2.txt", .{});
        defer f2.close(io);
        try f2.writeStreamingAll(io, "test2");
    }
    {
        const f3 = try std.Io.Dir.createFile(.cwd(), io, "tmp/walk_test/subdir/file3.txt", .{});
        defer f3.close(io);
        try f3.writeStreamingAll(io, "test3");
    }

    const Context = struct {
        files: std.ArrayList([]const u8),
        dirs: std.ArrayList([]const u8),
        alloc: std.mem.Allocator,

        fn callback(
            relative_path: []const u8,
            full_path: []const u8,
            is_directory: bool,
            ctx: *anyopaque,
        ) !void {
            _ = full_path;
            const self: *@This() = @ptrCast(@alignCast(ctx));
            if (is_directory) {
                try self.dirs.append(self.alloc, try self.alloc.dupe(u8, relative_path));
            } else {
                try self.files.append(self.alloc, try self.alloc.dupe(u8, relative_path));
            }
        }
    };

    var ctx = Context{
        .files = .empty,
        .dirs = .empty,
        .alloc = allocator,
    };
    defer {
        for (ctx.files.items) |f| allocator.free(f);
        ctx.files.deinit(allocator);
        for (ctx.dirs.items) |d| allocator.free(d);
        ctx.dirs.deinit(allocator);
    }

    try walkDirectory("tmp/walk_test", Context.callback, &ctx, allocator, false, io);

    try testing.expectEqual(@as(usize, 3), ctx.files.items.len);
    try testing.expectEqual(@as(usize, 1), ctx.dirs.items.len);
}

test "ensureDirectory creates nested directories" {
    const testing = std.testing;
    const io = testing.io;

    try ensureDirectory("tmp/nested/deeply/nested/path", io);
    defer std.Io.Dir.deleteTree(.cwd(), io, "tmp/nested") catch {};

    try testing.expect(try isDirectory("tmp/nested/deeply/nested/path", io));
}

test "dirname extracts directory" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const dir = try dirname("path/to/file.txt", allocator);
    defer allocator.free(dir);

    try testing.expectEqualStrings("path/to", dir);
}

test "pathExists checks existence" {
    const testing = std.testing;
    const io = testing.io;

    try ensureDirectory("tmp", io);
    defer std.Io.Dir.deleteTree(.cwd(), io, "tmp") catch {};

    {
        const f = try std.Io.Dir.createFile(.cwd(), io, "tmp/exists.txt", .{});
        defer f.close(io);
    }
    defer std.Io.Dir.deleteFile(.cwd(), io, "tmp/exists.txt") catch {};

    try testing.expect(pathExists("tmp/exists.txt", io));
    try testing.expect(!pathExists("tmp/does_not_exist.txt", io));
}

test "symlinks to files are followed" {
    const testing = std.testing;
    const allocator = testing.allocator;
    const io = testing.io;

    try ensureDirectory("tmp/symlink_test", io);
    defer std.Io.Dir.deleteTree(.cwd(), io, "tmp/symlink_test") catch {};

    {
        const f = try std.Io.Dir.createFile(.cwd(), io, "tmp/symlink_test/target.txt", .{});
        defer f.close(io);
        try f.writeStreamingAll(io, "target content");
    }

    var target_dir = try std.Io.Dir.openDir(.cwd(), io, "tmp/symlink_test", .{});
    defer target_dir.close(io);
    target_dir.symLink(io, "target.txt", "link.txt", .{}) catch |err| {
        // Some platforms cannot create symbolic links.
        if (err == error.Unexpected) return error.SkipZigTest;
        return err;
    };

    const Context = struct {
        files: std.ArrayList([]const u8),
        alloc: std.mem.Allocator,

        fn callback(
            relative_path: []const u8,
            full_path: []const u8,
            is_directory: bool,
            ctx: *anyopaque,
        ) !void {
            _ = full_path;
            const self: *@This() = @ptrCast(@alignCast(ctx));
            if (!is_directory) {
                try self.files.append(self.alloc, try self.alloc.dupe(u8, relative_path));
            }
        }
    };

    var ctx = Context{
        .files = .empty,
        .alloc = allocator,
    };
    defer {
        for (ctx.files.items) |f| allocator.free(f);
        ctx.files.deinit(allocator);
    }

    try walkDirectory("tmp/symlink_test", Context.callback, &ctx, allocator, false, io);

    try testing.expectEqual(@as(usize, 2), ctx.files.items.len);
}

test "exclude pattern matching" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var patterns: std.ArrayList([]const u8) = .empty;
    defer patterns.deinit(allocator);

    try patterns.append(allocator, "*.log");
    try patterns.append(allocator, "*.tmp");
    try patterns.append(allocator, ".git/");
    try patterns.append(allocator, "node_modules/");

    try testing.expect(matchesExcludePattern("debug.log", patterns));
    try testing.expect(matchesExcludePattern("temp.tmp", patterns));
    try testing.expect(!matchesExcludePattern("data.txt", patterns));

    try testing.expect(matchesExcludePattern(".git/config", patterns));
    try testing.expect(matchesExcludePattern(".git/objects/abc", patterns));
    try testing.expect(matchesExcludePattern("node_modules/package/index.js", patterns));

    try testing.expect(!matchesExcludePattern("src/main.zig", patterns));
    try testing.expect(!matchesExcludePattern("README.md", patterns));

    // Directory patterns only match whole path components.
    try testing.expect(!matchesExcludePattern(".gitignore", patterns));
    try testing.expect(!matchesExcludePattern(".github/workflows/ci.yml", patterns));
    try testing.expect(matchesExcludePattern("src/.git", patterns));
    try testing.expect(matchesExcludePattern("src/node_modules/x.js", patterns));
    try testing.expect(matchesExcludePattern("my_node_modules/node_modules/x.js", patterns));
    try testing.expect(!matchesExcludePattern("my_node_modules/x.js", patterns));
}

test "ignore symlinks flag" {
    const testing = std.testing;
    const allocator = testing.allocator;
    const io = testing.io;

    try ensureDirectory("tmp/ignore_symlinks_test", io);
    defer std.Io.Dir.deleteTree(.cwd(), io, "tmp/ignore_symlinks_test") catch {};

    {
        const f = try std.Io.Dir.createFile(.cwd(), io, "tmp/ignore_symlinks_test/target.txt", .{});
        defer f.close(io);
        try f.writeStreamingAll(io, "target content");
    }

    var target_dir = try std.Io.Dir.openDir(.cwd(), io, "tmp/ignore_symlinks_test", .{});
    defer target_dir.close(io);
    target_dir.symLink(io, "target.txt", "link.txt", .{}) catch |err| {
        // Some platforms cannot create symbolic links.
        if (err == error.Unexpected) return error.SkipZigTest;
        return err;
    };

    {
        const Context = struct {
            files: std.ArrayList([]const u8),
            alloc: std.mem.Allocator,

            fn callback(
                relative_path: []const u8,
                full_path: []const u8,
                is_directory: bool,
                ctx: *anyopaque,
            ) !void {
                _ = full_path;
                const self: *@This() = @ptrCast(@alignCast(ctx));
                if (!is_directory) {
                    try self.files.append(self.alloc, try self.alloc.dupe(u8, relative_path));
                }
            }
        };

        var ctx = Context{
            .files = .empty,
            .alloc = allocator,
        };
        defer {
            for (ctx.files.items) |f| allocator.free(f);
            ctx.files.deinit(allocator);
        }

        try walkDirectory("tmp/ignore_symlinks_test", Context.callback, &ctx, allocator, false, io);

        try testing.expectEqual(@as(usize, 2), ctx.files.items.len);
    }

    {
        const Context = struct {
            files: std.ArrayList([]const u8),
            alloc: std.mem.Allocator,

            fn callback(
                relative_path: []const u8,
                full_path: []const u8,
                is_directory: bool,
                ctx: *anyopaque,
            ) !void {
                _ = full_path;
                const self: *@This() = @ptrCast(@alignCast(ctx));
                if (!is_directory) {
                    try self.files.append(self.alloc, try self.alloc.dupe(u8, relative_path));
                }
            }
        };

        var ctx = Context{
            .files = .empty,
            .alloc = allocator,
        };
        defer {
            for (ctx.files.items) |f| allocator.free(f);
            ctx.files.deinit(allocator);
        }

        try walkDirectory("tmp/ignore_symlinks_test", Context.callback, &ctx, allocator, true, io);

        try testing.expectEqual(@as(usize, 1), ctx.files.items.len);
        try testing.expectEqualStrings("target.txt", ctx.files.items[0]);
    }
}

test "path relation" {
    const testing = std.testing;
    const allocator = testing.allocator;
    const io = testing.io;

    try std.Io.Dir.createDirPath(.cwd(), io, "tmp/relation/source/inner");
    defer std.Io.Dir.deleteTree(.cwd(), io, "tmp/relation") catch {};

    try testing.expectEqual(PathRelation.same, try pathRelation("tmp/relation/source", "tmp/relation/source", allocator, io));
    try testing.expectEqual(PathRelation.same, try pathRelation("tmp/relation/source", "tmp/relation/source/inner/..", allocator, io));
    try testing.expectEqual(PathRelation.descendant, try pathRelation("tmp/relation/source", "tmp/relation/source/new/deeper", allocator, io));
    try testing.expectEqual(PathRelation.other, try pathRelation("tmp/relation/source", "tmp/relation/sibling", allocator, io));
    try testing.expectEqual(PathRelation.other, try pathRelation("tmp/relation/source", "tmp/relation", allocator, io));
    try testing.expectEqual(PathRelation.other, try pathRelation("tmp/relation/source", "tmp/relation/source-two", allocator, io));
}
