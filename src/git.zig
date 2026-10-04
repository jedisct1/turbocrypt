//! Shared helpers for keeping private files out of a public Git history.

const std = @import("std");
const Allocator = std.mem.Allocator;

pub const cmd = @import("git/cmd.zig");
pub const hooks = @import("git/hooks.zig");
pub const Manifest = @import("git/Manifest.zig");
pub const Repo = @import("git/Repo.zig");
pub const sync = @import("git/sync.zig");

pub fn containsString(list: []const []const u8, needle: []const u8) bool {
    for (list) |item| {
        if (std.mem.eql(u8, item, needle)) return true;
    }
    return false;
}

/// Releases each owned string and then the list that holds them.
pub fn freeList(gpa: Allocator, list: []const []u8) void {
    for (list) |item| gpa.free(item);
    gpa.free(list);
}
