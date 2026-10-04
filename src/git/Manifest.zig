//! Defines the `.gitprivate` manifest for a repository's private paths.
//! It preserves each original line so hand-edited comments and layout survive changes.
//! Adding or removing a path changes only that path's line.
//! This keeps the manifest safe to maintain by hand.

const Manifest = @This();

const std = @import("std");
const mem = std.mem;
const testing = std.testing;
const Allocator = std.mem.Allocator;
const Io = std.Io;

const filename_crypto = @import("../filename_crypto.zig");
const git = @import("../git.zig");

lines: std.ArrayList([]u8) = .empty,

pub const filename = ".gitprivate";
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

/// Names Git must read in cleartext to operate normally.
const reserved_names = [_][]const u8{ ".gitignore", ".gitattributes", ".gitmodules" };

pub const Error = error{
    UnsupportedLine,
    ReservedPath,
    OutsideRepository,
};

/// A private manifest path without its leading slash.
pub const Entry = struct {
    path: []const u8,
    is_dir: bool,

    /// Reports whether this entry includes `plain`.
    pub fn covers(self: Entry, plain: []const u8) bool {
        if (self.is_dir) {
            return plain.len > self.path.len and
                mem.startsWith(u8, plain, self.path) and
                plain[self.path.len] == '/';
        }
        return mem.eql(u8, self.path, plain);
    }
};

pub fn anyCovers(list: []const Entry, plain: []const u8) bool {
    for (list) |entry| {
        if (entry.covers(plain)) return true;
    }
    return false;
}

/// Accept only path forms that can be represented safely in the exclude list.
/// Files use `/path/to/file`; directories use `/path/to/dir/`.
/// Blank lines and comments remain valid so people can annotate the manifest.
pub fn checkLine(line: []const u8) Error!void {
    if (parseLine(line) == null and line.len != 0 and line[0] != '#') {
        return Error.UnsupportedLine;
    }
}

/// Parses a path entry and ignores blank lines or comments.
/// `checkLine` rejects any other line.
pub fn parseLine(line: []const u8) ?Entry {
    if (line.len < 2 or line[0] != '/') return null;
    if (mem.findAny(u8, line, "*?[]") != null) return null;
    if (line[line.len - 1] == ' ') return null;

    const body = line[1..];
    const is_dir = body[body.len - 1] == '/';
    const path = if (is_dir) body[0 .. body.len - 1] else body;
    if (path.len == 0) return null;

    var it = mem.splitScalar(u8, path, '/');
    while (it.next()) |component| {
        if (!filename_crypto.isSafeComponent(component)) return null;
    }
    return .{ .path = path, .is_dir = is_dir };
}

/// Paths that must stay public because Git or turbocrypt needs them in cleartext.
/// This protects Git's metadata, the store, and Git's control files.
pub fn isReservedPath(path: []const u8) bool {
    const first = if (mem.findScalar(u8, path, '/')) |i| path[0..i] else path;
    if (mem.eql(u8, first, ".git") or mem.eql(u8, first, ".enc")) return true;
    const last = Io.Dir.path.basename(path);
    for (reserved_names) |name| {
        if (mem.eql(u8, last, name)) return true;
    }
    return false;
}

pub fn parse(gpa: Allocator, text: []const u8) !Manifest {
    var manifest: Manifest = .{};
    errdefer manifest.deinit(gpa);

    var line_number: usize = 0;
    var it = mem.splitScalar(u8, text, '\n');
    while (it.next()) |raw| {
        line_number += 1;
        if (raw.len == 0 and it.peek() == null) break;
        const line = mem.trimEnd(u8, raw, "\r");
        checkLine(line) catch |err| {
            std.debug.print(
                "Error: {s} line {d} is not a plain file or directory path: {s}\n",
                .{ filename, line_number, line },
            );
            return err;
        };
        try manifest.lines.append(gpa, try gpa.dupe(u8, line));
    }
    return manifest;
}

pub fn deinit(self: *Manifest, gpa: Allocator) void {
    for (self.lines.items) |line| gpa.free(line);
    self.lines.deinit(gpa);
}

pub fn render(self: Manifest, gpa: Allocator) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    for (self.lines.items) |line| {
        try out.appendSlice(gpa, line);
        try out.append(gpa, '\n');
    }
    return out.toOwnedSlice(gpa);
}

pub fn contains(self: Manifest, line: []const u8) bool {
    return git.containsString(self.lines.items, line);
}

/// Returns false when the manifest already contains the line.
pub fn append(self: *Manifest, gpa: Allocator, line: []const u8) !bool {
    try checkLine(line);
    if (self.contains(line)) return false;
    try self.lines.append(gpa, try gpa.dupe(u8, line));
    return true;
}

/// Returns false when the line is absent.
pub fn remove(self: *Manifest, gpa: Allocator, line: []const u8) bool {
    for (self.lines.items, 0..) |existing, i| {
        if (mem.eql(u8, existing, line)) {
            gpa.free(self.lines.orderedRemove(i));
            return true;
        }
    }
    return false;
}

/// Returns manifest entries in file order; their slices borrow from the manifest.
pub fn entries(self: Manifest, gpa: Allocator) ![]Entry {
    var list: std.ArrayList(Entry) = .empty;
    errdefer list.deinit(gpa);
    for (self.lines.items) |line| {
        if (parseLine(line)) |entry| try list.append(gpa, entry);
    }
    return list.toOwnedSlice(gpa);
}

/// Finds the manifest line that makes a plain path private.
pub fn covering(self: Manifest, plain: []const u8) ?[]const u8 {
    for (self.lines.items) |line| {
        if (parseLine(line)) |entry| {
            if (entry.covers(plain)) return line;
        }
    }
    return null;
}

/// Finds the line that names this path directly, as either a file or directory.
pub fn ownLine(self: Manifest, plain: []const u8) ?[]const u8 {
    for (self.lines.items) |line| {
        const entry = parseLine(line) orelse continue;
        if (mem.eql(u8, entry.path, plain)) return line;
    }
    return null;
}

/// Resolves a command argument to a path relative to the repository root.
/// Git supplies `prefix` as the caller's directory relative to that root.
/// Absolute arguments are resolved independently.
/// Paths outside the root, including the root itself, are rejected.
/// The result uses `/` because that is how Git reports paths on every platform.
/// This gives manifest entries one stable spelling.
///
pub fn relativeToToplevel(
    gpa: Allocator,
    toplevel: []const u8,
    prefix: []const u8,
    arg: []const u8,
) ![]u8 {
    // Resolve both paths because Git always reports its top level with `/` separators.
    const root = try Io.Dir.path.resolveAlloc(gpa, &.{toplevel});
    defer gpa.free(root);
    const absolute = try Io.Dir.path.resolveAlloc(gpa, &.{ toplevel, prefix, arg });
    defer gpa.free(absolute);
    if (absolute.len <= root.len + 1 or
        !mem.startsWith(u8, absolute, root) or
        !Io.Dir.path.isSep(absolute[root.len]))
    {
        return Error.OutsideRepository;
    }
    const relative = try gpa.dupe(u8, absolute[root.len + 1 ..]);
    mem.replaceScalar(u8, relative, Io.Dir.path.sep, '/');
    return relative;
}

/// Converts an existing user path into a manifest line.
/// Only files and directories are allowed.
/// Reserved paths stay public so Git can keep working.
pub fn normalizeUserPath(
    gpa: Allocator,
    io: Io,
    toplevel: []const u8,
    prefix: []const u8,
    arg: []const u8,
) ![]u8 {
    const relative = try relativeToToplevel(gpa, toplevel, prefix, arg);
    defer gpa.free(relative);
    if (isReservedPath(relative)) return Error.ReservedPath;

    const absolute = try Io.Dir.path.join(gpa, &.{ toplevel, relative });
    defer gpa.free(absolute);
    const stat = try Io.Dir.statFile(.cwd(), io, absolute, .{ .follow_symlinks = false });
    const line = switch (stat.kind) {
        .directory => try gpa.print("/{s}/", .{relative}),
        .file => try gpa.print("/{s}", .{relative}),
        .sym_link => return error.IsSymlink,
        else => return error.UnsupportedFileType,
    };
    errdefer gpa.free(line);
    try checkLine(line);
    return line;
}

/// Returns non-comment lines from the marked section of an exclude file.
pub fn blockLines(gpa: Allocator, text: []const u8) ![][]u8 {
    var list: std.ArrayList([]u8) = .empty;
    errdefer {
        for (list.items) |line| gpa.free(line);
        list.deinit(gpa);
    }

    var inside = false;
    var it = mem.splitScalar(u8, text, '\n');
    while (it.next()) |line| {
        if (mem.eql(u8, line, begin_marker)) {
            inside = true;
        } else if (mem.eql(u8, line, end_marker)) {
            break;
        } else if (inside and line.len > 0 and line[0] != '#') {
            try list.append(gpa, try gpa.dupe(u8, line));
        }
    }
    return list.toOwnedSlice(gpa);
}

/// Combines prior lines with additions, removes requested lines, and returns sorted unique output.
pub fn mergeBlockLines(
    gpa: Allocator,
    previous: []const []const u8,
    additions: []const []const u8,
    removals: []const []const u8,
) ![][]u8 {
    var seen: std.StringHashMapUnmanaged(void) = .empty;
    defer seen.deinit(gpa);
    for (removals) |line| try seen.put(gpa, line, {});

    var list: std.ArrayList([]u8) = .empty;
    errdefer {
        for (list.items) |line| gpa.free(line);
        list.deinit(gpa);
    }
    for ([_][]const []const u8{ previous, additions }) |source| {
        for (source) |line| {
            const entry = try seen.getOrPut(gpa, line);
            if (entry.found_existing) continue;
            try list.append(gpa, try gpa.dupe(u8, line));
        }
    }
    mem.sort([]u8, list.items, {}, lessThan);
    return list.toOwnedSlice(gpa);
}

fn lessThan(_: void, a: []u8, b: []u8) bool {
    return mem.lessThan(u8, a, b);
}

/// Replaces the marked exclude section or adds it when missing.
/// Everything outside the markers remains byte-for-byte unchanged.
/// Stable output avoids needless changes to a user's exclude file.
pub fn renderExcludeText(
    gpa: Allocator,
    existing: ?[]const u8,
    lines: []const []const u8,
) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);

    const text = existing orelse "";
    const begin = findLineFrom(text, begin_marker, 0);
    if (begin) |b| {
        try out.appendSlice(gpa, text[0..b.start]);
    } else if (text.len > 0) {
        try out.appendSlice(gpa, text);
        if (text[text.len - 1] != '\n') try out.append(gpa, '\n');
    }

    try out.appendSlice(gpa, begin_marker);
    try out.append(gpa, '\n');
    try out.appendSlice(gpa, block_comment);
    try out.append(gpa, '\n');
    for (lines) |line| {
        try out.appendSlice(gpa, line);
        try out.append(gpa, '\n');
    }
    try out.appendSlice(gpa, end_marker);
    try out.append(gpa, '\n');

    if (begin) |b| {
        if (findLineFrom(text, end_marker, b.end)) |e| {
            try out.appendSlice(gpa, text[e.end..]);
        }
    }
    return out.toOwnedSlice(gpa);
}

const LineSpan = struct { start: usize, end: usize };

fn findLineFrom(text: []const u8, needle: []const u8, from: usize) ?LineSpan {
    var pos = from;
    while (pos <= text.len) {
        const line_end = mem.findScalarPos(u8, text, pos, '\n') orelse text.len;
        if (mem.eql(u8, text[pos..line_end], needle)) {
            return .{ .start = pos, .end = @min(line_end + 1, text.len) };
        }
        if (line_end == text.len) break;
        pos = line_end + 1;
    }
    return null;
}

test "only plain file and directory lines are accepted" {
    try checkLine("");
    try checkLine("# a comment");
    try checkLine("/AGENT.md");
    try checkLine("/docs/internal.md");
    try checkLine("/ops/");

    const bad = [_][]const u8{
        "AGENT.md", "/",     "//",     "/a//b", "/*.md", "/a?",   "/a[b]",
        "/a\\b",    "/../x", "/a/./b", "!/a",   "/a ",   "/a\tb", "ops/",
    };
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

test "the git and store directories and the git control files are reserved" {
    try testing.expect(isReservedPath(".git"));
    try testing.expect(isReservedPath(".git/config"));
    try testing.expect(isReservedPath(".enc/x"));
    try testing.expect(isReservedPath(".gitignore"));
    try testing.expect(isReservedPath("sub/.gitattributes"));
    try testing.expect(!isReservedPath("docs/.gitkeep"));
    try testing.expect(!isReservedPath("AGENT.md"));
}

test "manifest keeps comments and reports bad lines" {
    const gpa = testing.allocator;

    var manifest = try Manifest.parse(gpa, default_text ++ "/AGENT.md\n/ops/\n");
    defer manifest.deinit(gpa);

    try testing.expect(manifest.contains("/AGENT.md"));
    try testing.expect(!try manifest.append(gpa, "/AGENT.md"));
    try testing.expect(try manifest.append(gpa, "/docs/internal.md"));
    try testing.expectError(Error.UnsupportedLine, manifest.append(gpa, "*.md"));
    try testing.expect(manifest.remove(gpa, "/AGENT.md"));
    try testing.expect(!manifest.remove(gpa, "/AGENT.md"));

    const rendered = try manifest.render(gpa);
    defer gpa.free(rendered);
    try testing.expectEqualStrings(default_text ++ "/ops/\n/docs/internal.md\n", rendered);

    const list = try manifest.entries(gpa);
    defer gpa.free(list);
    try testing.expectEqual(2, list.len);
    try testing.expectEqualStrings("/ops/", manifest.covering("ops/x").?);
    try testing.expect(manifest.covering("other") == null);

    try testing.expectError(Error.UnsupportedLine, Manifest.parse(gpa, "/ok\n!/bad\n"));
}

test "user arguments become manifest lines relative to the top level" {
    const gpa = testing.allocator;
    const io = testing.io;

    try Io.Dir.createDirPath(.cwd(), io, "tmp/manifest_repo/docs");
    defer Io.Dir.deleteTree(.cwd(), io, "tmp/manifest_repo") catch {};
    try Io.Dir.writeFile(.cwd(), io, .{
        .sub_path = "tmp/manifest_repo/docs/internal.md",
        .data = "x",
    });
    try Io.Dir.writeFile(.cwd(), io, .{ .sub_path = "tmp/manifest_repo/.gitignore", .data = "" });

    const toplevel = try Io.Dir.realPathFileAlloc(.cwd(), io, "tmp/manifest_repo", gpa);
    defer gpa.free(toplevel);

    const from_root = try normalizeUserPath(gpa, io, toplevel, "", "docs/internal.md");
    defer gpa.free(from_root);
    try testing.expectEqualStrings("/docs/internal.md", from_root);

    const from_sub = try normalizeUserPath(gpa, io, toplevel, "docs/", "internal.md");
    defer gpa.free(from_sub);
    try testing.expectEqualStrings("/docs/internal.md", from_sub);

    const dir = try normalizeUserPath(gpa, io, toplevel, "", "docs");
    defer gpa.free(dir);
    try testing.expectEqualStrings("/docs/", dir);

    const absolute = try Io.Dir.path.join(gpa, &.{ toplevel, "docs" });
    defer gpa.free(absolute);
    const from_abs = try normalizeUserPath(gpa, io, toplevel, "", absolute);
    defer gpa.free(from_abs);
    try testing.expectEqualStrings("/docs/", from_abs);

    try testing.expectError(
        Error.OutsideRepository,
        normalizeUserPath(gpa, io, toplevel, "", "../outside"),
    );
    try testing.expectError(
        Error.OutsideRepository,
        normalizeUserPath(gpa, io, toplevel, "", "."),
    );
    try testing.expectError(
        Error.ReservedPath,
        normalizeUserPath(gpa, io, toplevel, "", ".gitignore"),
    );
    try testing.expectError(
        error.FileNotFound,
        normalizeUserPath(gpa, io, toplevel, "", "missing"),
    );
}

test "the exclude block is replaced or appended and the rest is kept" {
    const gpa = testing.allocator;

    const lines = [_][]const u8{ "/.gitprivate", "/AGENT.md" };
    const block = begin_marker ++ "\n" ++ block_comment ++ "\n/.gitprivate\n/AGENT.md\n" ++
        end_marker ++ "\n";

    const fresh = try renderExcludeText(gpa, null, &lines);
    defer gpa.free(fresh);
    try testing.expectEqualStrings(block, fresh);

    const appended = try renderExcludeText(gpa, "*.o", &lines);
    defer gpa.free(appended);
    try testing.expectEqualStrings("*.o\n" ++ block, appended);

    const middle = "before\n" ++ begin_marker ++ "\nold\n" ++ end_marker ++ "\nafter\n";
    const replaced = try renderExcludeText(gpa, middle, &lines);
    defer gpa.free(replaced);
    try testing.expectEqualStrings("before\n" ++ block ++ "after\n", replaced);

    const again = try renderExcludeText(gpa, replaced, &lines);
    defer gpa.free(again);
    try testing.expectEqualStrings(replaced, again);

    const unterminated = "x\n" ++ begin_marker ++ "\nold\nmore";
    const fixed = try renderExcludeText(gpa, unterminated, &lines);
    defer gpa.free(fixed);
    try testing.expectEqualStrings("x\n" ++ block, fixed);
}

test "exclude block lines are read back and merged with additions and removals" {
    const gpa = testing.allocator;

    const text = begin_marker ++ "\n" ++ block_comment ++ "\n/old.md\n/AGENT.md\n" ++
        end_marker ++ "\n";
    const previous = try blockLines(gpa, text);
    defer git.freeList(gpa, previous);
    try testing.expectEqual(2, previous.len);

    const merged = try mergeBlockLines(
        gpa,
        previous,
        &.{ "/new.md", "/AGENT.md" },
        &.{"/old.md"},
    );
    defer git.freeList(gpa, merged);
    try testing.expectEqual(2, merged.len);
    try testing.expectEqualStrings("/AGENT.md", merged[0]);
    try testing.expectEqualStrings("/new.md", merged[1]);
}
