const std = @import("std");

/// Callback function type for directory walking
/// Parameters: relative_path, full_path, is_directory
pub const WalkCallback = *const fn (
    relative_path: []const u8,
    full_path: []const u8,
    is_directory: bool,
    context: *anyopaque,
) anyerror!void;

/// Walk a directory recursively and call callback for each file/directory
/// Uses std.fs.Dir.walk() for efficient iteration
pub fn walkDirectory(
    base_path: []const u8,
    callback: WalkCallback,
    context: *anyopaque,
    allocator: std.mem.Allocator,
    ignore_symlinks: bool,
) !void {
    // Open the base directory for walking
    var dir = try std.fs.cwd().openDir(base_path, .{ .iterate = true });
    defer dir.close();

    // Create walker
    var walker = try dir.walk(allocator);
    defer walker.deinit();

    // Iterate over all entries
    while (try walker.next()) |entry| {
        // Construct full path by joining base_path with relative path
        const full_path = try std.fs.path.join(allocator, &[_][]const u8{ base_path, entry.path });
        defer allocator.free(full_path);

        // Handle based on entry kind
        if (entry.kind == .directory) {
            try callback(entry.path, full_path, true, context);
        } else if (entry.kind == .file) {
            try callback(entry.path, full_path, false, context);
        } else if (entry.kind == .sym_link) {
            if (ignore_symlinks) {
                // Skip all symlinks when ignore_symlinks is true
                continue;
            }

            // Follow symlinks to determine their actual type
            const stat = std.fs.cwd().statFile(full_path) catch |err| {
                // Skip broken or inaccessible symlinks
                std.debug.print("Warning: skipping symlink '{s}' ({})\n", .{ full_path, err });
                continue;
            };

            if (stat.kind == .directory) {
                // Skip symlinked directories to avoid circular references
                std.debug.print("Warning: skipping symlinked directory '{s}'\n", .{full_path});
                continue;
            } else if (stat.kind == .file) {
                // Treat symlinked files as regular files
                try callback(entry.path, full_path, false, context);
            }
        }
    }
}

/// Create directory and all parent directories if they don't exist
pub fn ensureDirectory(path: []const u8) !void {
    std.fs.cwd().makePath(path) catch |err| {
        if (err != error.PathAlreadyExists) return err;
    };
}

/// Get the directory part of a path
pub fn dirname(path: []const u8, allocator: std.mem.Allocator) ![]u8 {
    const dir = std.fs.path.dirname(path) orelse "";
    return try allocator.dupe(u8, dir);
}

/// Check if a path exists
pub fn pathExists(path: []const u8) bool {
    std.fs.cwd().access(path, .{}) catch return false;
    return true;
}

/// Check if a path is a directory
pub fn isDirectory(path: []const u8) !bool {
    const stat = std.fs.cwd().statFile(path) catch |err| {
        // On Windows, statFile() returns error.IsDir for directories
        if (err == error.IsDir) return true;
        return err;
    };
    return stat.kind == .directory;
}

/// Check if a path matches any exclude pattern (glob style)
/// Patterns can be:
///   - Exact: "config.env"
///   - Extension: "*.log", "*.tmp"
///   - Directory: "node_modules/", ".git/"
///   - Path component: "temp/" matches "src/temp/file.txt"
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

/// Simple glob pattern matching
fn matchesPattern(path: []const u8, pattern: []const u8) bool {
    // Handle directory patterns: "node_modules/" matches any path starting with it
    if (std.mem.endsWith(u8, pattern, "/")) {
        const dir_name = pattern[0 .. pattern.len - 1];
        // Check if path starts with this directory
        if (std.mem.startsWith(u8, path, dir_name)) {
            return true;
        }
        // Check if path contains this directory as component
        if (std.mem.indexOf(u8, path, dir_name)) |idx| {
            // Verify it's a complete path component
            if (idx == 0 or path[idx - 1] == '/') {
                if (idx + dir_name.len >= path.len or path[idx + dir_name.len] == '/') {
                    return true;
                }
            }
        }
        return false;
    }

    // Handle extension patterns: "*.log"
    if (std.mem.startsWith(u8, pattern, "*.")) {
        const ext = pattern[1..];
        return std.mem.endsWith(u8, path, ext);
    }

    // Handle wildcard patterns: "*something"
    if (std.mem.startsWith(u8, pattern, "*")) {
        const suffix = pattern[1..];
        return std.mem.endsWith(u8, path, suffix);
    }

    // Handle wildcard patterns: "something*"
    if (std.mem.endsWith(u8, pattern, "*")) {
        const prefix = pattern[0 .. pattern.len - 1];
        return std.mem.startsWith(u8, path, prefix);
    }

    // Exact match
    return std.mem.eql(u8, path, pattern);
}

test "directory walking" {
    const testing = std.testing;
    const allocator = testing.allocator;

    // Create test directory structure
    // tmp/walk_test/
    //   file1.txt
    //   subdir/
    //     file2.txt
    //     file3.txt

    try ensureDirectory("tmp/walk_test/subdir");
    defer std.fs.cwd().deleteTree("tmp/walk_test") catch {};

    // Create test files
    {
        const f1 = try std.fs.cwd().createFile("tmp/walk_test/file1.txt", .{});
        defer f1.close();
        try f1.writeAll("test1");
    }
    {
        const f2 = try std.fs.cwd().createFile("tmp/walk_test/subdir/file2.txt", .{});
        defer f2.close();
        try f2.writeAll("test2");
    }
    {
        const f3 = try std.fs.cwd().createFile("tmp/walk_test/subdir/file3.txt", .{});
        defer f3.close();
        try f3.writeAll("test3");
    }

    // Walk and collect files
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
        .files = std.ArrayList([]const u8){},
        .dirs = std.ArrayList([]const u8){},
        .alloc = allocator,
    };
    defer {
        for (ctx.files.items) |f| allocator.free(f);
        ctx.files.deinit(allocator);
        for (ctx.dirs.items) |d| allocator.free(d);
        ctx.dirs.deinit(allocator);
    }

    try walkDirectory("tmp/walk_test", Context.callback, &ctx, allocator, false);

    // Should find 3 files
    try testing.expectEqual(@as(usize, 3), ctx.files.items.len);

    // Should find 1 directory (subdir)
    try testing.expectEqual(@as(usize, 1), ctx.dirs.items.len);
}

test "ensureDirectory creates nested directories" {
    const testing = std.testing;

    try ensureDirectory("tmp/nested/deeply/nested/path");
    defer std.fs.cwd().deleteTree("tmp/nested") catch {};

    // Verify it exists and is a directory
    try testing.expect(try isDirectory("tmp/nested/deeply/nested/path"));
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

    try ensureDirectory("tmp");
    defer std.fs.cwd().deleteTree("tmp") catch {};

    {
        const f = try std.fs.cwd().createFile("tmp/exists.txt", .{});
        defer f.close();
    }
    defer std.fs.cwd().deleteFile("tmp/exists.txt") catch {};

    try testing.expect(pathExists("tmp/exists.txt"));
    try testing.expect(!pathExists("tmp/does_not_exist.txt"));
}

test "symlinks to files are followed" {
    const testing = std.testing;
    const allocator = testing.allocator;

    // Create test directory with a file and a symlink to it
    try ensureDirectory("tmp/symlink_test");
    defer std.fs.cwd().deleteTree("tmp/symlink_test") catch {};

    // Create target file
    {
        const f = try std.fs.cwd().createFile("tmp/symlink_test/target.txt", .{});
        defer f.close();
        try f.writeAll("target content");
    }

    // Create symlink to the file
    const target_dir = try std.fs.cwd().openDir("tmp/symlink_test", .{});
    target_dir.symLink("target.txt", "link.txt", .{}) catch |err| {
        // Skip test if symlinks are not supported on this platform
        if (err == error.Unexpected) return error.SkipZigTest;
        return err;
    };

    // Walk and collect files
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
        .files = std.ArrayList([]const u8){},
        .alloc = allocator,
    };
    defer {
        for (ctx.files.items) |f| allocator.free(f);
        ctx.files.deinit(allocator);
    }

    try walkDirectory("tmp/symlink_test", Context.callback, &ctx, allocator, false);

    // Should find 2 files: target.txt and link.txt (the symlink treated as a file)
    try testing.expectEqual(@as(usize, 2), ctx.files.items.len);
}

test "exclude pattern matching" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var patterns = std.ArrayList([]const u8){};
    defer patterns.deinit(allocator);

    // Add test patterns
    try patterns.append(allocator, "*.log");
    try patterns.append(allocator, "*.tmp");
    try patterns.append(allocator, ".git/");
    try patterns.append(allocator, "node_modules/");

    // Test extension matching
    try testing.expect(matchesExcludePattern("debug.log", patterns));
    try testing.expect(matchesExcludePattern("temp.tmp", patterns));
    try testing.expect(!matchesExcludePattern("data.txt", patterns));

    // Test directory matching
    try testing.expect(matchesExcludePattern(".git/config", patterns));
    try testing.expect(matchesExcludePattern(".git/objects/abc", patterns));
    try testing.expect(matchesExcludePattern("node_modules/package/index.js", patterns));

    // Test non-matches
    try testing.expect(!matchesExcludePattern("src/main.zig", patterns));
    try testing.expect(!matchesExcludePattern("README.md", patterns));
}

test "ignore symlinks flag" {
    const testing = std.testing;
    const allocator = testing.allocator;

    // Create test directory with a file and a symlink to it
    try ensureDirectory("tmp/ignore_symlinks_test");
    defer std.fs.cwd().deleteTree("tmp/ignore_symlinks_test") catch {};

    // Create target file
    {
        const f = try std.fs.cwd().createFile("tmp/ignore_symlinks_test/target.txt", .{});
        defer f.close();
        try f.writeAll("target content");
    }

    // Create symlink to the file
    const target_dir = try std.fs.cwd().openDir("tmp/ignore_symlinks_test", .{});
    target_dir.symLink("target.txt", "link.txt", .{}) catch |err| {
        // Skip test if symlinks are not supported on this platform
        if (err == error.Unexpected) return error.SkipZigTest;
        return err;
    };

    // Test with ignore_symlinks = false (should find both files)
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
            .files = std.ArrayList([]const u8){},
            .alloc = allocator,
        };
        defer {
            for (ctx.files.items) |f| allocator.free(f);
            ctx.files.deinit(allocator);
        }

        try walkDirectory("tmp/ignore_symlinks_test", Context.callback, &ctx, allocator, false);

        // Should find 2 files: target.txt and link.txt (symlink)
        try testing.expectEqual(@as(usize, 2), ctx.files.items.len);
    }

    // Test with ignore_symlinks = true (should find only target.txt)
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
            .files = std.ArrayList([]const u8){},
            .alloc = allocator,
        };
        defer {
            for (ctx.files.items) |f| allocator.free(f);
            ctx.files.deinit(allocator);
        }

        try walkDirectory("tmp/ignore_symlinks_test", Context.callback, &ctx, allocator, true);

        // Should find 1 file: only target.txt (symlink ignored)
        try testing.expectEqual(@as(usize, 1), ctx.files.items.len);
        try testing.expectEqualStrings("target.txt", ctx.files.items[0]);
    }
}
