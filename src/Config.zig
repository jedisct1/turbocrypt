//! Stores user settings as JSON in the per-user data directory.

const Config = @This();

const std = @import("std");
const builtin = @import("builtin");
const testing = std.testing;
const Allocator = std.mem.Allocator;
const Io = std.Io;

const keygen = @import("keygen.zig");
const processor = @import("processor.zig");
const fs = @import("fs.zig");

/// Holds the default key in the same layout used by key files, with or without a password.
key: ?[]const u8 = null,

/// Leaves worker selection to the available CPUs when unset.
threads: ?u32 = null,

buffer_size: ?usize = null,
exclude_patterns: []const []const u8 = &.{},
ignore_symlinks: ?bool = null,
encrypted_filenames: ?bool = null,

pub const filename = "config.json";

/// AEGIS-128X2 requires 16-byte keys.
pub const key_length = 16;

/// Mirrors the config file while representing the key as hexadecimal text.
const Json = struct {
    key: ?[]const u8 = null,
    threads: ?u32 = null,
    buffer_size: ?usize = null,
    exclude_patterns: []const []const u8 = &.{},
    ignore_symlinks: ?bool = null,
    encrypted_filenames: ?bool = null,
};

pub fn fromJson(gpa: Allocator, json_str: []const u8) !Config {
    const parsed = try std.json.parseFromSlice(Json, gpa, json_str, .{
        .ignore_unknown_fields = true,
    });
    defer parsed.deinit();
    const json = parsed.value;

    var config: Config = .{
        .threads = json.threads,
        .buffer_size = json.buffer_size,
        .ignore_symlinks = json.ignore_symlinks,
        .encrypted_filenames = json.encrypted_filenames,
    };
    errdefer config.deinit(gpa);

    if (config.threads == 0) return error.InvalidConfig;

    if (json.key) |hex_key| {
        const size = hex_key.len / 2;
        const valid_size = size == keygen.plain_key_file_size or keygen.isProtectedFileSize(size);
        if (hex_key.len % 2 != 0 or !valid_size) return error.InvalidKeyFormat;

        const key = try gpa.alloc(u8, size);
        errdefer gpa.free(key);
        _ = try std.fmt.hexToBytes(key, hex_key);
        config.key = key;
    }

    if (json.exclude_patterns.len > 0) {
        const patterns = try gpa.alloc([]const u8, json.exclude_patterns.len);
        var copied: usize = 0;
        errdefer {
            for (patterns[0..copied]) |pattern| gpa.free(pattern);
            gpa.free(patterns);
        }
        for (json.exclude_patterns) |pattern| {
            patterns[copied] = try gpa.dupe(u8, pattern);
            copied += 1;
        }
        config.exclude_patterns = patterns;
    }

    return config;
}

pub fn toJson(config: Config, gpa: Allocator) ![]const u8 {
    const hex_key: ?[]const u8 = if (config.key) |key|
        try gpa.print("{x}", .{key})
    else
        null;
    defer if (hex_key) |hex| gpa.free(hex);

    const json: Json = .{
        .key = hex_key,
        .threads = config.threads,
        .buffer_size = config.buffer_size,
        .exclude_patterns = config.exclude_patterns,
        .ignore_symlinks = config.ignore_symlinks,
        .encrypted_filenames = config.encrypted_filenames,
    };
    return try std.json.Stringify.valueAlloc(gpa, json, .{ .whitespace = .indent_2 });
}

pub fn deinit(config: *Config, gpa: Allocator) void {
    if (config.key) |key| {
        std.crypto.secureZero(u8, @constCast(key));
        gpa.free(key);
    }
    for (config.exclude_patterns) |pattern| gpa.free(pattern);
    if (config.exclude_patterns.len > 0) gpa.free(config.exclude_patterns);
}

/// Finds this app's per-user data directory on the current platform.
/// The caller owns the returned memory.
pub fn getAppDataDir(
    gpa: Allocator,
    environ_map: *const std.process.Environ.Map,
    appname: []const u8,
) ![]const u8 {
    switch (builtin.os.tag) {
        .windows => {
            const local_app_data = environ_map.get("LOCALAPPDATA") orelse
                return error.EnvironmentVariableNotFound;
            return try Io.Dir.path.join(gpa, &.{ local_app_data, appname });
        },
        .macos => {
            const home = environ_map.get("HOME") orelse return error.EnvironmentVariableNotFound;
            return try Io.Dir.path.join(gpa, &.{ home, "Library", "Application Support", appname });
        },
        else => {
            if (environ_map.get("XDG_DATA_HOME")) |xdg_data| {
                return try Io.Dir.path.join(gpa, &.{ xdg_data, appname });
            }
            const home = environ_map.get("HOME") orelse return error.EnvironmentVariableNotFound;
            return try Io.Dir.path.join(gpa, &.{ home, ".local", "share", appname });
        },
    }
}

/// The caller owns the returned memory.
pub fn filePath(gpa: Allocator, environ_map: *const std.process.Environ.Map) ![]const u8 {
    const app_data_dir = try getAppDataDir(gpa, environ_map, "turbocrypt");
    defer gpa.free(app_data_dir);
    return try Io.Dir.path.join(gpa, &.{ app_data_dir, filename });
}

/// Uses the defaults when no config file has been created yet.
pub fn load(gpa: Allocator, io: Io, environ_map: *const std.process.Environ.Map) !Config {
    const config_path = try filePath(gpa, environ_map);
    defer gpa.free(config_path);

    const max_size = 1024 * 1024;
    const json = Io.Dir.readFileAlloc(
        .cwd(),
        io,
        config_path,
        gpa,
        .limited(max_size + 1),
    ) catch |err| switch (err) {
        error.FileNotFound => return .{},
        else => return err,
    };
    defer gpa.free(json);

    return fromJson(gpa, json);
}

pub fn save(
    config: Config,
    gpa: Allocator,
    io: Io,
    environ_map: *const std.process.Environ.Map,
) !void {
    const app_data_dir = try getAppDataDir(gpa, environ_map, "turbocrypt");
    defer gpa.free(app_data_dir);

    Io.Dir.createDirPath(.cwd(), io, app_data_dir) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };

    const config_path = try Io.Dir.path.join(gpa, &.{ app_data_dir, filename });
    defer gpa.free(config_path);

    const json = try config.toJson(gpa);
    defer gpa.free(json);

    try processor.writeFileAtomic(gpa, io, config_path, json, fs.private_file_permissions, null);
}

/// Builds a test environment that keeps the config under `home` on every platform.
pub fn testEnviron(gpa: Allocator, home: []const u8) !std.process.Environ.Map {
    var environ_map: std.process.Environ.Map = .init(gpa);
    errdefer environ_map.deinit();
    try environ_map.put("HOME", home);
    try environ_map.put("XDG_DATA_HOME", home);
    try environ_map.put("LOCALAPPDATA", home);
    return environ_map;
}

test "fromJson rejects values of the wrong type" {
    const gpa = testing.allocator;
    const bad_inputs = [_][]const u8{
        "[]",
        "{\"key\": 42}",
        "{\"key\": \"abc\"}",
        "{\"key\": \"0102\"}",
        "{\"threads\": 0}",
        "{\"threads\": -1}",
        "{\"buffer_size\": 1.5}",
        "{\"exclude_patterns\": [1]}",
        "{\"ignore_symlinks\": \"yes\"}",
        "{\"key\": \"0102030405060708090a0b0c0d0e0f10\", \"encrypted_filenames\": 1}",
    };
    for (bad_inputs) |input| {
        try testing.expect(std.meta.isError(fromJson(gpa, input)));
    }
}

test "an empty exclude list parses to no patterns" {
    const gpa = testing.allocator;
    var config = try fromJson(gpa, "{\"exclude_patterns\": []}");
    defer config.deinit(gpa);
    try testing.expectEqual(0, config.exclude_patterns.len);
}

test "the defaults leave every setting unset" {
    const gpa = testing.allocator;
    var config: Config = .{};
    defer config.deinit(gpa);

    try testing.expect(config.key == null);
    try testing.expect(config.threads == null);
    try testing.expect(config.buffer_size == null);
    try testing.expectEqual(0, config.exclude_patterns.len);
}

test "toJson output parses back to the same settings" {
    const gpa = testing.allocator;
    const key = [_]u8{
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    };
    var config: Config = .{
        .key = try gpa.dupe(u8, &key),
        .threads = 8,
        .buffer_size = 8388608,
        .exclude_patterns = try gpa.dupe([]const u8, &.{
            try gpa.dupe(u8, "*.log"),
            try gpa.dupe(u8, ".git/"),
        }),
    };
    defer config.deinit(gpa);

    const json = try config.toJson(gpa);
    defer gpa.free(json);
    var parsed = try fromJson(gpa, json);
    defer parsed.deinit(gpa);

    try testing.expectEqualSlices(u8, &key, parsed.key.?);
    try testing.expectEqual(8, parsed.threads.?);
    try testing.expectEqual(8388608, parsed.buffer_size.?);
    try testing.expectEqual(2, parsed.exclude_patterns.len);
    try testing.expectEqualStrings("*.log", parsed.exclude_patterns[0]);
    try testing.expectEqualStrings(".git/", parsed.exclude_patterns[1]);
}

test "save does not follow a planted temporary-file symlink" {
    const gpa = testing.allocator;
    const io = testing.io;
    const root = "tmp/config_atomic_symlink";
    const home = root ++ "/home";
    const target_path = root ++ "/target";
    const sentinel = "leave this file alone";

    Io.Dir.deleteTree(.cwd(), io, root) catch {};
    try Io.Dir.createDirPath(.cwd(), io, home);
    defer Io.Dir.deleteTree(.cwd(), io, root) catch {};
    try Io.Dir.writeFile(.cwd(), io, .{ .sub_path = target_path, .data = sentinel });

    var environ_map = try testEnviron(gpa, home);
    defer environ_map.deinit();
    const config_path = try filePath(gpa, &environ_map);
    defer gpa.free(config_path);
    try Io.Dir.createDirPath(.cwd(), io, Io.Dir.path.dirname(config_path).?);
    const planted_path = try gpa.print("{s}.tmp", .{config_path});
    defer gpa.free(planted_path);
    const target_abs = try Io.Dir.realPathFileAlloc(.cwd(), io, target_path, gpa);
    defer gpa.free(target_abs);
    Io.Dir.symLink(.cwd(), io, target_abs, planted_path, .{}) catch |err| {
        if (err == error.Unexpected or err == error.AccessDenied) return error.SkipZigTest;
        return err;
    };

    try save(.{ .threads = 3 }, gpa, io, &environ_map);

    const limit: Io.Limit = .limited(sentinel.len + 1);
    const target = try Io.Dir.readFileAlloc(.cwd(), io, target_path, gpa, limit);
    defer gpa.free(target);
    try testing.expectEqualStrings(sentinel, target);
    const planted = try Io.Dir.statFile(.cwd(), io, planted_path, .{ .follow_symlinks = false });
    try testing.expectEqual(Io.File.Kind.sym_link, planted.kind);
    const saved = try Io.Dir.statFile(.cwd(), io, config_path, .{ .follow_symlinks = false });
    try testing.expectEqual(Io.File.Kind.file, saved.kind);

    var loaded = try load(gpa, io, &environ_map);
    defer loaded.deinit(gpa);
    try testing.expectEqual(3, loaded.threads.?);
}
