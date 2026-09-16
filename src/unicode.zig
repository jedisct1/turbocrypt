//! Spellings of accented file names on macOS.
//!
//! macOS spells one accented name in two ways. Finder writes "é" as an "e" plus a combining accent, a terminal writes one code point.
//! The system treats both as the same file, so the encrypted names must too. The composed spelling is the canonical one here, as it is for git on macOS.

const std = @import("std");
const builtin = @import("builtin");

const iconv_failed = std.math.maxInt(usize);

/// A path component fits here. Longer inputs, such as whole git paths, go through the allocator.
const max_stack_length = 1024;

/// libiconv is loaded at run time: every macOS install ships it, but Zig cannot link it when it cross-compiles to macOS.
const Libiconv = struct {
    lib: std.DynLib,
    iconv_open: *const fn (tocode: [*:0]const u8, fromcode: [*:0]const u8) callconv(.c) ?*anyopaque,
    iconv: *const fn (cd: ?*anyopaque, inbuf: ?*?[*]u8, inbytesleft: ?*usize, outbuf: ?*?[*]u8, outbytesleft: ?*usize) callconv(.c) usize,
    iconv_close: *const fn (cd: ?*anyopaque) callconv(.c) c_int,

    fn load() error{Unavailable}!Libiconv {
        var lib = std.DynLib.openZ("/usr/lib/libiconv.2.dylib") catch return error.Unavailable;
        errdefer lib.close();
        return .{
            .lib = lib,
            .iconv_open = lib.lookup(@FieldType(Libiconv, "iconv_open"), "iconv_open") orelse return error.Unavailable,
            .iconv = lib.lookup(@FieldType(Libiconv, "iconv"), "iconv") orelse return error.Unavailable,
            .iconv_close = lib.lookup(@FieldType(Libiconv, "iconv_close"), "iconv_close") orelse return error.Unavailable,
        };
    }
};

/// The mount composes names on every lookup, so each thread keeps its converter for the life of the process.
/// A converter descriptor carries state and cannot be shared between threads.
const Converter = struct {
    lib: Libiconv,
    cd: *anyopaque,

    threadlocal var current: ?Converter = null;
    threadlocal var missing = false;

    fn get() ?*Converter {
        if (current) |*converter| return converter;
        if (missing) return null;
        var lib = Libiconv.load() catch {
            missing = true;
            return null;
        };
        const cd = lib.iconv_open("UTF-8", "UTF-8-MAC");
        if (cd == null or @intFromPtr(cd) == iconv_failed) {
            lib.lib.close();
            missing = true;
            return null;
        }
        current = .{ .lib = lib, .cd = cd.? };
        return &current.?;
    }

    /// Convert into `out`, returning the converted bytes, or null when the converter refuses the input.
    fn convert(self: *Converter, input: []const u8, out: []u8) ?[]const u8 {
        _ = self.lib.iconv(self.cd, null, null, null, null);
        var in_ptr: ?[*]u8 = @constCast(input.ptr);
        var in_left: usize = input.len;
        var out_ptr: ?[*]u8 = out.ptr;
        var out_left: usize = out.len;
        const rc = self.lib.iconv(self.cd, &in_ptr, &in_left, &out_ptr, &out_left);
        if (rc == iconv_failed or in_left != 0) return null;
        return out[0 .. out.len - out_left];
    }
};

/// Compose a decomposed UTF-8 name the way git does on macOS, through the UTF-8-MAC converter of libiconv.
/// Returns null when the spelling does not change or the converter refuses the name. An ASCII name then costs nothing. The caller frees the result.
pub fn precompose(allocator: std.mem.Allocator, input: []const u8) error{OutOfMemory}!?[]u8 {
    if (builtin.os.tag != .macos) return null;
    if (isAscii(input)) return null;
    const converter = Converter.get() orelse return null;

    // Composition normally shrinks a name. The extra room keeps an odd case from failing the conversion.
    const needed = input.len * 2 + 16;
    var stack_buf: [max_stack_length]u8 = undefined;
    const on_heap = needed > stack_buf.len;
    const out = if (on_heap) try allocator.alloc(u8, needed) else stack_buf[0..needed];
    defer if (on_heap) allocator.free(out);

    const composed = converter.convert(input, out) orelse return null;
    if (std.mem.eql(u8, composed, input)) return null;
    return try allocator.dupe(u8, composed);
}

fn isAscii(bytes: []const u8) bool {
    for (bytes) |c| {
        if (!std.ascii.isAscii(c)) return false;
    }
    return true;
}

test "precompose composes decomposed names on macOS" {
    const testing = std.testing;
    const allocator = testing.allocator;
    if (builtin.os.tag != .macos) return error.SkipZigTest;

    const composed = (try precompose(allocator, "re\u{301}sume\u{301}.md")).?;
    defer allocator.free(composed);
    try testing.expectEqualStrings("r\u{e9}sum\u{e9}.md", composed);

    try testing.expectEqual(null, try precompose(allocator, "r\u{e9}sum\u{e9}.md"));
    try testing.expectEqual(null, try precompose(allocator, "docs/internal.md"));

    const long: [max_stack_length]u8 = @splat('e');
    const long_composed = (try precompose(allocator, long ++ "\u{301}")).?;
    defer allocator.free(long_composed);
    try testing.expectEqualStrings(long[0 .. long.len - 1] ++ "\u{e9}", long_composed);
}
