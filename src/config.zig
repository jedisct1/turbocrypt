const std = @import("std");
const builtin = @import("builtin");
const keygen = @import("keygen.zig");
const utils = @import("utils.zig");

/// Configuration filename within app data directory
pub const config_filename = "config.json";

/// Key size (16 bytes for AEGIS-128)
pub const key_length = 16;

/// The JSON layout of the config file, with the key as a hex string
const JsonConfig = struct {
    key: ?[]const u8 = null,
    threads: ?u32 = null,
    buffer_size: ?usize = null,
    exclude_patterns: []const []const u8 = &.{},
    ignore_symlinks: ?bool = null,
    encrypted_filenames: ?bool = null,
};

/// TurboCrypt configuration
pub const Config = struct {
    /// Default encryption key (raw bytes in the same format as key file)
    /// - 16 bytes: plain key
    /// - 21 bytes: password-protected (1 byte flag + 16 byte XOR'd key + 4 byte checksum)
    /// Stored as hex in JSON
    key: ?[]const u8 = null,

    /// Default number of worker threads
    /// null means use CPU count (capped at 16)
    threads: ?u32 = null,

    /// Default buffer size in bytes
    /// null means use default (4MB)
    buffer_size: ?usize = null,

    /// Default exclude patterns
    exclude_patterns: []const []const u8 = &[_][]const u8{},

    /// Ignore symbolic links
    ignore_symlinks: ?bool = null,

    /// Encrypt filenames by default
    encrypted_filenames: ?bool = null,

    /// Load config from JSON with proper memory management
    pub fn fromJson(allocator: std.mem.Allocator, json_str: []const u8) !Config {
        const parsed = try std.json.parseFromSlice(JsonConfig, allocator, json_str, .{
            .ignore_unknown_fields = true,
        });
        defer parsed.deinit();
        const json = parsed.value;

        var config = Config{
            .threads = json.threads,
            .buffer_size = json.buffer_size,
            .ignore_symlinks = json.ignore_symlinks,
            .encrypted_filenames = json.encrypted_filenames,
        };
        errdefer config.deinit(allocator);

        if (config.threads == 0) return error.InvalidConfig;

        if (json.key) |hex_key| {
            const size = hex_key.len / 2;
            const valid_size = size == keygen.plain_key_file_size or size == keygen.protected_key_file_size;
            if (hex_key.len % 2 != 0 or !valid_size) {
                return error.InvalidKeyFormat;
            }

            const key = try allocator.alloc(u8, size);
            errdefer allocator.free(key);
            _ = try std.fmt.hexToBytes(key, hex_key);
            config.key = key;
        }

        if (json.exclude_patterns.len > 0) {
            const patterns = try allocator.alloc([]const u8, json.exclude_patterns.len);
            var copied: usize = 0;
            errdefer {
                for (patterns[0..copied]) |pattern| allocator.free(pattern);
                allocator.free(patterns);
            }
            for (json.exclude_patterns) |pattern| {
                patterns[copied] = try allocator.dupe(u8, pattern);
                copied += 1;
            }
            config.exclude_patterns = patterns;
        }

        return config;
    }

    /// Serialize config to JSON string
    pub fn toJson(self: Config, allocator: std.mem.Allocator) ![]const u8 {
        const hex_key: ?[]const u8 = if (self.key) |key|
            try std.fmt.allocPrint(allocator, "{x}", .{key})
        else
            null;
        defer if (hex_key) |hex| allocator.free(hex);

        const json_config = JsonConfig{
            .key = hex_key,
            .threads = self.threads,
            .buffer_size = self.buffer_size,
            .exclude_patterns = self.exclude_patterns,
            .ignore_symlinks = self.ignore_symlinks,
            .encrypted_filenames = self.encrypted_filenames,
        };

        return try std.json.Stringify.valueAlloc(
            allocator,
            json_config,
            .{ .whitespace = .indent_2 },
        );
    }

    /// Free all allocated memory
    pub fn deinit(self: *Config, allocator: std.mem.Allocator) void {
        // Clear key from memory for security and free
        if (self.key) |key| {
            std.crypto.secureZero(u8, @constCast(key));
            allocator.free(key);
        }

        for (self.exclude_patterns) |pattern| {
            allocator.free(pattern);
        }
        if (self.exclude_patterns.len > 0) {
            allocator.free(self.exclude_patterns);
        }
    }
};

/// Get the application data directory for turbocrypt
/// - macOS: ~/Library/Application Support/turbocrypt
/// - Linux: $XDG_DATA_HOME/turbocrypt or ~/.local/share/turbocrypt
/// - Windows: %LOCALAPPDATA%\turbocrypt
fn getAppDataDir(allocator: std.mem.Allocator, appname: []const u8, environ_map: *const std.process.Environ.Map) ![]const u8 {
    const native_os = builtin.os.tag;
    if (native_os == .windows) {
        const local_app_data = environ_map.get("LOCALAPPDATA") orelse return error.EnvironmentVariableNotFound;
        return try std.fs.path.join(allocator, &[_][]const u8{ local_app_data, appname });
    } else if (native_os == .macos) {
        const home = environ_map.get("HOME") orelse return error.EnvironmentVariableNotFound;
        return try std.fs.path.join(allocator, &[_][]const u8{ home, "Library", "Application Support", appname });
    } else {
        // Linux/Unix: use XDG_DATA_HOME or default to ~/.local/share
        if (environ_map.get("XDG_DATA_HOME")) |xdg_data| {
            return try std.fs.path.join(allocator, &[_][]const u8{ xdg_data, appname });
        } else {
            const home = environ_map.get("HOME") orelse return error.EnvironmentVariableNotFound;
            return try std.fs.path.join(allocator, &[_][]const u8{ home, ".local", "share", appname });
        }
    }
}

/// Get the full path to the config file
pub fn getConfigFilePath(allocator: std.mem.Allocator, environ_map: *const std.process.Environ.Map) ![]const u8 {
    const app_data_dir = try getAppDataDir(allocator, "turbocrypt", environ_map);
    defer allocator.free(app_data_dir);

    return try std.fs.path.join(allocator, &[_][]const u8{ app_data_dir, config_filename });
}

/// Load config from file
/// Returns a default config if file doesn't exist
pub fn load(allocator: std.mem.Allocator, io: std.Io, environ_map: *const std.process.Environ.Map) !Config {
    const config_path = try getConfigFilePath(allocator, environ_map);
    defer allocator.free(config_path);

    const max_size = 1024 * 1024; // 1MB max config file
    const json_str = std.Io.Dir.readFileAlloc(
        .cwd(),
        io,
        config_path,
        allocator,
        std.Io.Limit.limited(max_size),
    ) catch |err| {
        // If file doesn't exist, return default config
        if (err == error.FileNotFound) {
            return Config{};
        }
        return err;
    };
    defer allocator.free(json_str);

    return try Config.fromJson(allocator, json_str);
}

/// Save config to file with secure permissions
pub fn save(config: Config, allocator: std.mem.Allocator, io: std.Io, environ_map: *const std.process.Environ.Map) !void {
    // Get app data directory
    const app_data_dir = try getAppDataDir(allocator, "turbocrypt", environ_map);
    defer allocator.free(app_data_dir);

    // Ensure directory exists
    std.Io.Dir.createDirPath(.cwd(), io, app_data_dir) catch |err| switch (err) {
        error.PathAlreadyExists => {}, // That's fine
        else => return err,
    };

    // Get config file path
    const config_path = try std.Io.Dir.path.join(allocator, &[_][]const u8{ app_data_dir, config_filename });
    defer allocator.free(config_path);

    // Serialize to JSON
    const json_str = try config.toJson(allocator);
    defer allocator.free(json_str);

    // Use atomic write with temporary file to avoid permission race
    const temp_path = try std.fmt.allocPrint(allocator, "{s}.tmp", .{config_path});
    defer allocator.free(temp_path);

    const file = try utils.createPrivateFile(temp_path, .{}, io);
    defer file.close(io);

    try file.writeStreamingAll(io, json_str);
    try file.sync(io); // Ensure data is written to disk

    // Atomically rename temp to final path
    try std.Io.Dir.rename(.cwd(), temp_path, .cwd(), config_path, io);
}

test "Config - rejects wrong value types" {
    const allocator = std.testing.allocator;

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
        const result = Config.fromJson(allocator, input);
        try std.testing.expect(std.meta.isError(result));
    }
}

test "Config - empty exclude list" {
    const allocator = std.testing.allocator;

    var config = try Config.fromJson(allocator, "{\"exclude_patterns\": []}");
    defer config.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 0), config.exclude_patterns.len);
}

test "Config - default config" {
    const allocator = std.testing.allocator;

    var config = Config{};
    defer config.deinit(allocator);

    try std.testing.expect(config.key == null);
    try std.testing.expect(config.threads == null);
    try std.testing.expect(config.buffer_size == null);
    try std.testing.expectEqual(@as(usize, 0), config.exclude_patterns.len);
}

test "Config - to/from JSON" {
    const allocator = std.testing.allocator;

    const test_key_data = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10 };
    const test_key = try allocator.dupe(u8, &test_key_data);

    var config = Config{
        .key = test_key,
        .threads = 8,
        .buffer_size = 8388608,
        .exclude_patterns = try allocator.dupe([]const u8, &[_][]const u8{
            try allocator.dupe(u8, "*.log"),
            try allocator.dupe(u8, ".git/"),
        }),
    };

    // Serialize
    const json_str = try config.toJson(allocator);

    // Deserialize
    var config2 = try Config.fromJson(allocator, json_str);

    try std.testing.expectEqualSlices(u8, &test_key_data, config2.key.?);
    try std.testing.expectEqual(@as(u32, 8), config2.threads.?);
    try std.testing.expectEqual(@as(usize, 8388608), config2.buffer_size.?);
    try std.testing.expectEqual(@as(usize, 2), config2.exclude_patterns.len);
    try std.testing.expectEqualStrings("*.log", config2.exclude_patterns[0]);
    try std.testing.expectEqualStrings(".git/", config2.exclude_patterns[1]);

    // Cleanup
    config2.deinit(allocator);
    allocator.free(json_str);
    config.deinit(allocator);
}
