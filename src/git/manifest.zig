const std = @import("std");
const filename_crypto = @import("../filename_crypto.zig");
const utils = @import("../utils.zig");

pub const manifest_name = ".gitprivate";
pub const begin_marker = "# >>> turbocrypt >>>";
pub const end_marker = "# <<< turbocrypt <<<";
const block_comment = "# Generated from .gitprivate. Do not edit between the markers.";

pub const default_text =
    \\# Private files of this repository, one per line.
    \\# /path/to/file marks one file. /path/to/dir/ marks a whole directory.
    \\# Paths are relative to the repository root. No wildcards, no negation.
    \\# This file is private too. It is never committed in clear.
    \\
;

/// Names that git needs in clear to work at all.
const reserved_names = [_][]const u8{ ".gitignore", ".gitattributes", ".gitmodules" };

pub const Error = error{
    UnsupportedLine,
    ReservedPath,
    OutsideRepository,
};

/// One private path from the manifest, without the leading slash.
pub const Entry = struct {
    path: []const u8,
    is_dir: bool,

    /// True when `plain` is this file, or lives under this directory.
    pub fn covers(self: Entry, plain: []const u8) bool {
        if (self.is_dir) {
            return plain.len > self.path.len and
                std.mem.startsWith(u8, plain, self.path) and
                plain[self.path.len] == '/';
        }
        return std.mem.eql(u8, self.path, plain);
    }
};

/// True when one of the entries covers the path.
pub fn anyCovers(entries: []const Entry, plain: []const u8) bool {
    for (entries) |entry| {
        if (entry.covers(plain)) return true;
    }
    return false;
}

/// Accept only the two line shapes that keep the exclude union sound: `/path/to/file` and `/path/to/dir/`.
/// Comments and blank lines pass.
pub fn checkLine(line: []const u8) Error!void {
    if (parseLine(line) == null and line.len != 0 and line[0] != '#') {
        return Error.UnsupportedLine;
    }
}

/// Returns the entry described by a line, or null for a comment or an empty line.
/// A line that is neither is rejected by checkLine.
pub fn parseLine(line: []const u8) ?Entry {
    if (line.len < 2 or line[0] != '/') return null;
    if (std.mem.indexOfAny(u8, line, "*?[]") != null) return null;
    if (line[line.len - 1] == ' ') return null;

    const body = line[1..];
    const is_dir = body[body.len - 1] == '/';
    const path = if (is_dir) body[0 .. body.len - 1] else body;
    if (path.len == 0) return null;

    var it = std.mem.splitScalar(u8, path, '/');
    while (it.next()) |component| {
        if (!filename_crypto.isSafeComponent(component)) return null;
    }
    return .{ .path = path, .is_dir = is_dir };
}

/// Paths that must never become private: the git and store directories, and the control files git reads in clear.
pub fn isReservedPath(path: []const u8) bool {
    const first = if (std.mem.indexOfScalar(u8, path, '/')) |i| path[0..i] else path;
    if (std.mem.eql(u8, first, ".git") or std.mem.eql(u8, first, ".enc")) return true;
    const last = std.fs.path.basename(path);
    for (reserved_names) |name| {
        if (std.mem.eql(u8, last, name)) return true;
    }
    return false;
}

/// The manifest keeps every line as written, comments included, so a hand-edited file survives an add or an rm untouched apart from the line that changes.
pub const Manifest = struct {
    lines: std.ArrayList([]u8) = .empty,

    pub fn parse(allocator: std.mem.Allocator, text: []const u8) !Manifest {
        var manifest = Manifest{};
        errdefer manifest.deinit(allocator);

        var line_number: usize = 0;
        var it = std.mem.splitScalar(u8, text, '\n');
        while (it.next()) |raw| {
            line_number += 1;
            if (raw.len == 0 and it.peek() == null) break;
            const line = std.mem.trimEnd(u8, raw, "\r");
            checkLine(line) catch |err| {
                std.debug.print("Error: {s} line {d} is not a plain file or directory path: {s}\n", .{ manifest_name, line_number, line });
                return err;
            };
            try manifest.lines.append(allocator, try allocator.dupe(u8, line));
        }
        return manifest;
    }

    pub fn deinit(self: *Manifest, allocator: std.mem.Allocator) void {
        for (self.lines.items) |line| allocator.free(line);
        self.lines.deinit(allocator);
    }

    pub fn render(self: Manifest, allocator: std.mem.Allocator) ![]u8 {
        var out: std.ArrayList(u8) = .empty;
        errdefer out.deinit(allocator);
        for (self.lines.items) |line| {
            try out.appendSlice(allocator, line);
            try out.append(allocator, '\n');
        }
        return out.toOwnedSlice(allocator);
    }

    pub fn contains(self: Manifest, line: []const u8) bool {
        return utils.containsString(self.lines.items, line);
    }

    /// Returns false when the line was already there.
    pub fn append(self: *Manifest, allocator: std.mem.Allocator, line: []const u8) !bool {
        try checkLine(line);
        if (self.contains(line)) return false;
        try self.lines.append(allocator, try allocator.dupe(u8, line));
        return true;
    }

    /// Returns false when no such line exists.
    pub fn remove(self: *Manifest, allocator: std.mem.Allocator, line: []const u8) bool {
        for (self.lines.items, 0..) |existing, i| {
            if (std.mem.eql(u8, existing, line)) {
                allocator.free(self.lines.orderedRemove(i));
                return true;
            }
        }
        return false;
    }

    /// Entries in file order. The slices point into the manifest.
    pub fn entries(self: Manifest, allocator: std.mem.Allocator) ![]Entry {
        var list: std.ArrayList(Entry) = .empty;
        errdefer list.deinit(allocator);
        for (self.lines.items) |line| {
            if (parseLine(line)) |entry| try list.append(allocator, entry);
        }
        return list.toOwnedSlice(allocator);
    }

    /// The line that makes a plain path private, if any.
    pub fn covering(self: Manifest, plain: []const u8) ?[]const u8 {
        for (self.lines.items) |line| {
            if (parseLine(line)) |entry| {
                if (entry.covers(plain)) return line;
            }
        }
        return null;
    }
};

/// A user argument as a path relative to the top level.
///
/// `prefix` is the directory the user ran the command from, relative to the top level, as git reports it.
/// An absolute argument stands on its own.
/// The top level itself and anything outside it are refused.
/// The result has '/' between its components, as git reports paths on every platform.
pub fn relativeToToplevel(
    allocator: std.mem.Allocator,
    toplevel: []const u8,
    prefix: []const u8,
    arg: []const u8,
) ![]u8 {
    // Both sides go through resolve, since git reports the top level with '/'.
    const root = try std.fs.path.resolve(allocator, &.{toplevel});
    defer allocator.free(root);
    const absolute = try std.fs.path.resolve(allocator, &.{ toplevel, prefix, arg });
    defer allocator.free(absolute);
    if (absolute.len <= root.len + 1 or
        !std.mem.startsWith(u8, absolute, root) or
        !std.fs.path.isSep(absolute[root.len]))
    {
        return Error.OutsideRepository;
    }
    const relative = try allocator.dupe(u8, absolute[root.len + 1 ..]);
    std.mem.replaceScalar(u8, relative, std.fs.path.sep, '/');
    return relative;
}

/// Turn a user argument into a manifest line.
/// The path must exist, must be a file or a directory, and must not be one of the reserved paths.
pub fn normalizeUserPath(
    allocator: std.mem.Allocator,
    toplevel: []const u8,
    prefix: []const u8,
    arg: []const u8,
    io: std.Io,
) ![]u8 {
    const relative = try relativeToToplevel(allocator, toplevel, prefix, arg);
    defer allocator.free(relative);
    if (isReservedPath(relative)) return Error.ReservedPath;

    const absolute = try std.fs.path.join(allocator, &.{ toplevel, relative });
    defer allocator.free(absolute);
    const stat = try std.Io.Dir.statFile(.cwd(), io, absolute, .{ .follow_symlinks = false });
    const line = switch (stat.kind) {
        .directory => try std.fmt.allocPrint(allocator, "/{s}/", .{relative}),
        .file => try std.fmt.allocPrint(allocator, "/{s}", .{relative}),
        .sym_link => return error.IsSymlink,
        else => return error.UnsupportedFileType,
    };
    errdefer allocator.free(line);
    try checkLine(line);
    return line;
}

/// Lines between the markers of an exclude file, comments left out.
pub fn blockLines(allocator: std.mem.Allocator, text: []const u8) ![][]u8 {
    var list: std.ArrayList([]u8) = .empty;
    errdefer {
        for (list.items) |line| allocator.free(line);
        list.deinit(allocator);
    }

    var inside = false;
    var it = std.mem.splitScalar(u8, text, '\n');
    while (it.next()) |line| {
        if (std.mem.eql(u8, line, begin_marker)) {
            inside = true;
        } else if (std.mem.eql(u8, line, end_marker)) {
            break;
        } else if (inside and line.len > 0 and line[0] != '#') {
            try list.append(allocator, try allocator.dupe(u8, line));
        }
    }
    return list.toOwnedSlice(allocator);
}

/// (previous + add) - remove, sorted, without duplicates.
pub fn mergeBlockLines(
    allocator: std.mem.Allocator,
    previous: []const []const u8,
    add: []const []const u8,
    remove: []const []const u8,
) ![][]u8 {
    var seen: std.StringHashMapUnmanaged(void) = .empty;
    defer seen.deinit(allocator);
    for (remove) |line| try seen.put(allocator, line, {});

    var list: std.ArrayList([]u8) = .empty;
    errdefer {
        for (list.items) |line| allocator.free(line);
        list.deinit(allocator);
    }
    for ([_][]const []const u8{ previous, add }) |source| {
        for (source) |line| {
            const entry = try seen.getOrPut(allocator, line);
            if (entry.found_existing) continue;
            try list.append(allocator, try allocator.dupe(u8, line));
        }
    }
    std.mem.sort([]u8, list.items, {}, lessThan);
    return list.toOwnedSlice(allocator);
}

fn lessThan(_: void, a: []u8, b: []u8) bool {
    return std.mem.lessThan(u8, a, b);
}

/// Replace the marked block of an exclude file, or append one.
/// Text outside the markers is kept byte for byte.
/// Rendering twice with the same lines gives the same bytes.
pub fn renderExcludeText(allocator: std.mem.Allocator, existing: ?[]const u8, lines: []const []const u8) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);

    const text = existing orelse "";
    const begin = findLineFrom(text, begin_marker, 0);
    if (begin) |b| {
        try out.appendSlice(allocator, text[0..b.start]);
    } else if (text.len > 0) {
        try out.appendSlice(allocator, text);
        if (text[text.len - 1] != '\n') try out.append(allocator, '\n');
    }

    try out.appendSlice(allocator, begin_marker);
    try out.append(allocator, '\n');
    try out.appendSlice(allocator, block_comment);
    try out.append(allocator, '\n');
    for (lines) |line| {
        try out.appendSlice(allocator, line);
        try out.append(allocator, '\n');
    }
    try out.appendSlice(allocator, end_marker);
    try out.append(allocator, '\n');

    if (begin) |b| {
        if (findLineFrom(text, end_marker, b.end)) |e| {
            try out.appendSlice(allocator, text[e.end..]);
        }
    }
    return out.toOwnedSlice(allocator);
}

const LineSpan = struct { start: usize, end: usize };

fn findLineFrom(text: []const u8, needle: []const u8, from: usize) ?LineSpan {
    var pos = from;
    while (pos <= text.len) {
        const line_end = std.mem.indexOfScalarPos(u8, text, pos, '\n') orelse text.len;
        if (std.mem.eql(u8, text[pos..line_end], needle)) {
            return .{ .start = pos, .end = @min(line_end + 1, text.len) };
        }
        if (line_end == text.len) break;
        pos = line_end + 1;
    }
    return null;
}

test "line shapes" {
    const testing = std.testing;

    try checkLine("");
    try checkLine("# a comment");
    try checkLine("/AGENT.md");
    try checkLine("/docs/internal.md");
    try checkLine("/ops/");

    const bad = [_][]const u8{ "AGENT.md", "/", "//", "/a//b", "/*.md", "/a?", "/a[b]", "/a\\b", "/../x", "/a/./b", "!/a", "/a ", "/a\tb", "ops/" };
    for (bad) |line| {
        try testing.expectError(Error.UnsupportedLine, checkLine(line));
    }

    const file = parseLine("/docs/internal.md").?;
    try testing.expectEqualStrings("docs/internal.md", file.path);
    try testing.expect(!file.is_dir);
    try testing.expect(file.covers("docs/internal.md"));
    try testing.expect(!file.covers("docs/internal.md.bak"));

    const dir = parseLine("/ops/").?;
    try testing.expectEqualStrings("ops", dir.path);
    try testing.expect(dir.is_dir);
    try testing.expect(dir.covers("ops/deploy.sh"));
    try testing.expect(dir.covers("ops/a/b"));
    try testing.expect(!dir.covers("ops"));
    try testing.expect(!dir.covers("opsx/a"));
}

test "reserved paths" {
    const testing = std.testing;
    try testing.expect(isReservedPath(".git"));
    try testing.expect(isReservedPath(".git/config"));
    try testing.expect(isReservedPath(".enc/x"));
    try testing.expect(isReservedPath(".gitignore"));
    try testing.expect(isReservedPath("sub/.gitattributes"));
    try testing.expect(!isReservedPath("docs/.gitkeep"));
    try testing.expect(!isReservedPath("AGENT.md"));
}

test "manifest keeps comments and reports bad lines" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var manifest = try Manifest.parse(allocator, default_text ++ "/AGENT.md\n/ops/\n");
    defer manifest.deinit(allocator);

    try testing.expect(manifest.contains("/AGENT.md"));
    try testing.expect(!try manifest.append(allocator, "/AGENT.md"));
    try testing.expect(try manifest.append(allocator, "/docs/internal.md"));
    try testing.expectError(Error.UnsupportedLine, manifest.append(allocator, "*.md"));
    try testing.expect(manifest.remove(allocator, "/AGENT.md"));
    try testing.expect(!manifest.remove(allocator, "/AGENT.md"));

    const rendered = try manifest.render(allocator);
    defer allocator.free(rendered);
    try testing.expectEqualStrings(default_text ++ "/ops/\n/docs/internal.md\n", rendered);

    const list = try manifest.entries(allocator);
    defer allocator.free(list);
    try testing.expectEqual(@as(usize, 2), list.len);
    try testing.expectEqualStrings("/ops/", manifest.covering("ops/x").?);
    try testing.expect(manifest.covering("other") == null);

    try testing.expectError(Error.UnsupportedLine, Manifest.parse(allocator, "/ok\n!/bad\n"));
}

test "user path normalization" {
    const testing = std.testing;
    const allocator = testing.allocator;
    const io = testing.io;

    try std.Io.Dir.createDirPath(.cwd(), io, "tmp/manifest_repo/docs");
    defer std.Io.Dir.deleteTree(.cwd(), io, "tmp/manifest_repo") catch {};
    try std.Io.Dir.writeFile(.cwd(), io, .{ .sub_path = "tmp/manifest_repo/docs/internal.md", .data = "x" });
    try std.Io.Dir.writeFile(.cwd(), io, .{ .sub_path = "tmp/manifest_repo/.gitignore", .data = "" });

    const toplevel = try std.Io.Dir.realPathFileAlloc(.cwd(), io, "tmp/manifest_repo", allocator);
    defer allocator.free(toplevel);

    const from_root = try normalizeUserPath(allocator, toplevel, "", "docs/internal.md", io);
    defer allocator.free(from_root);
    try testing.expectEqualStrings("/docs/internal.md", from_root);

    const from_sub = try normalizeUserPath(allocator, toplevel, "docs/", "internal.md", io);
    defer allocator.free(from_sub);
    try testing.expectEqualStrings("/docs/internal.md", from_sub);

    const dir = try normalizeUserPath(allocator, toplevel, "", "docs", io);
    defer allocator.free(dir);
    try testing.expectEqualStrings("/docs/", dir);

    const absolute = try std.fs.path.join(allocator, &.{ toplevel, "docs" });
    defer allocator.free(absolute);
    const from_abs = try normalizeUserPath(allocator, toplevel, "", absolute, io);
    defer allocator.free(from_abs);
    try testing.expectEqualStrings("/docs/", from_abs);

    try testing.expectError(Error.OutsideRepository, normalizeUserPath(allocator, toplevel, "", "../outside", io));
    try testing.expectError(Error.OutsideRepository, normalizeUserPath(allocator, toplevel, "", ".", io));
    try testing.expectError(Error.ReservedPath, normalizeUserPath(allocator, toplevel, "", ".gitignore", io));
    try testing.expectError(error.FileNotFound, normalizeUserPath(allocator, toplevel, "", "missing", io));
}

test "exclude block rendering" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const lines = [_][]const u8{ "/.gitprivate", "/AGENT.md" };

    const fresh = try renderExcludeText(allocator, null, &lines);
    defer allocator.free(fresh);
    try testing.expectEqualStrings(begin_marker ++ "\n" ++ block_comment ++ "\n/.gitprivate\n/AGENT.md\n" ++ end_marker ++ "\n", fresh);

    const appended = try renderExcludeText(allocator, "*.o", &lines);
    defer allocator.free(appended);
    try testing.expectEqualStrings("*.o\n" ++ begin_marker ++ "\n" ++ block_comment ++ "\n/.gitprivate\n/AGENT.md\n" ++ end_marker ++ "\n", appended);

    const middle = "before\n" ++ begin_marker ++ "\nold\n" ++ end_marker ++ "\nafter\n";
    const replaced = try renderExcludeText(allocator, middle, &lines);
    defer allocator.free(replaced);
    try testing.expectEqualStrings("before\n" ++ begin_marker ++ "\n" ++ block_comment ++ "\n/.gitprivate\n/AGENT.md\n" ++ end_marker ++ "\nafter\n", replaced);

    const again = try renderExcludeText(allocator, replaced, &lines);
    defer allocator.free(again);
    try testing.expectEqualStrings(replaced, again);

    const unterminated = "x\n" ++ begin_marker ++ "\nold\nmore";
    const fixed = try renderExcludeText(allocator, unterminated, &lines);
    defer allocator.free(fixed);
    try testing.expectEqualStrings("x\n" ++ begin_marker ++ "\n" ++ block_comment ++ "\n/.gitprivate\n/AGENT.md\n" ++ end_marker ++ "\n", fixed);
}

test "exclude block union" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const text = begin_marker ++ "\n" ++ block_comment ++ "\n/old.md\n/AGENT.md\n" ++ end_marker ++ "\n";
    const previous = try blockLines(allocator, text);
    defer utils.freeList(allocator, previous);
    try testing.expectEqual(@as(usize, 2), previous.len);

    const merged = try mergeBlockLines(allocator, previous, &.{ "/new.md", "/AGENT.md" }, &.{"/old.md"});
    defer utils.freeList(allocator, merged);
    try testing.expectEqual(@as(usize, 2), merged.len);
    try testing.expectEqualStrings("/AGENT.md", merged[0]);
    try testing.expectEqualStrings("/new.md", merged[1]);
}
