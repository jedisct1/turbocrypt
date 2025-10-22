const std = @import("std");
const builtin = @import("builtin");

/// Configuration filename within app data directory
pub const config_filename = "config.json";

/// Key size (16 bytes for AEGIS-128)
pub const key_length = 16;

/// TurboCrypt configuration
pub const Config = struct {
    /// Default encryption key (raw bytes in the same format as key file)
    /// - 16 bytes: plain key
    /// - 17 bytes: password-protected (1 byte flag + 16 byte XOR'd key)
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

    /// Load config from JSON with proper memory management
    pub fn fromJson(allocator: std.mem.Allocator, json_str: []const u8) !Config {
        const parsed = try std.json.parseFromSlice(
            std.json.Value,
            allocator,
            json_str,
            .{},
        );
        defer parsed.deinit();

        const root = parsed.value.object;

        var config = Config{};

        // Parse key (hex encoded, variable length: 16 or 17 bytes)
        if (root.get("key")) |value| {
            if (value != .null) {
                const hex_key = value.string;

                // Hex string should be 2 chars per byte (32 or 34 chars)
                if (hex_key.len % 2 != 0) {
                    return error.InvalidKeyFormat;
                }

                const decoded_size = hex_key.len / 2;

                // Allocate buffer for decoded key
                const key = try allocator.alloc(u8, decoded_size);
                errdefer allocator.free(key);

                // Decode from hex
                _ = try std.fmt.hexToBytes(key, hex_key);

                config.key = key;
            }
        }

        // Parse threads
        if (root.get("threads")) |value| {
            if (value != .null) {
                config.threads = @intCast(value.integer);
            }
        }

        // Parse buffer_size
        if (root.get("buffer_size")) |value| {
            if (value != .null) {
                config.buffer_size = @intCast(value.integer);
            }
        }

        // Parse exclude_patterns
        if (root.get("exclude_patterns")) |value| {
            if (value == .array) {
                const array = value.array;
                var patterns = try allocator.alloc([]const u8, array.items.len);
                for (array.items, 0..) |item, i| {
                    patterns[i] = try allocator.dupe(u8, item.string);
                }
                config.exclude_patterns = patterns;
            }
        }

        // Parse ignore_symlinks
        if (root.get("ignore_symlinks")) |value| {
            if (value != .null) {
                config.ignore_symlinks = value.bool;
            }
        }

        return config;
    }

    /// Serialize config to JSON string
    pub fn toJson(self: Config, allocator: std.mem.Allocator) ![]const u8 {
        // Create a serialization-friendly struct with key as hex string
        const JsonConfig = struct {
            key: ?[]const u8,
            threads: ?u32,
            buffer_size: ?usize,
            exclude_patterns: []const []const u8,
            ignore_symlinks: ?bool,
        };

        // Convert key to hex string if present
        var hex_key_buf: [42]u8 = undefined; // Max 21 bytes = 42 hex chars
        const hex_key: ?[]const u8 = if (self.key) |key| blk: {
            break :blk std.fmt.bufPrint(&hex_key_buf, "{x}", .{key}) catch unreachable;
        } else null;

        const json_config = JsonConfig{
            .key = hex_key,
            .threads = self.threads,
            .buffer_size = self.buffer_size,
            .exclude_patterns = self.exclude_patterns,
            .ignore_symlinks = self.ignore_symlinks,
        };

        // Use Writer.Allocating for JSON output
        var aw: std.Io.Writer.Allocating = .init(allocator);
        defer aw.deinit();

        var stringify: std.json.Stringify = .{
            .writer = &aw.writer,
            .options = .{ .whitespace = .indent_2 },
        };
        try stringify.write(json_config);

        return try aw.toOwnedSlice();
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

/// Get the full path to the config file
pub fn getConfigFilePath(allocator: std.mem.Allocator) ![]const u8 {
    const app_data_dir = try std.fs.getAppDataDir(allocator, "turbocrypt");
    defer allocator.free(app_data_dir);

    return try std.fs.path.join(allocator, &[_][]const u8{ app_data_dir, config_filename });
}

/// Load config from file
/// Returns a default config if file doesn't exist
pub fn load(allocator: std.mem.Allocator) !Config {
    const config_path = try getConfigFilePath(allocator);
    defer allocator.free(config_path);

    const max_size = 1024 * 1024; // 1MB max config file
    const json_str = std.fs.cwd().readFileAlloc(
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
pub fn save(config: Config, allocator: std.mem.Allocator) !void {
    // Get app data directory
    const app_data_dir = try std.fs.getAppDataDir(allocator, "turbocrypt");
    defer allocator.free(app_data_dir);

    // Ensure directory exists
    std.fs.cwd().makePath(app_data_dir) catch |err| switch (err) {
        error.PathAlreadyExists => {}, // That's fine
        else => return err,
    };

    // Get config file path
    const config_path = try std.fs.path.join(allocator, &[_][]const u8{ app_data_dir, config_filename });
    defer allocator.free(config_path);

    // Serialize to JSON
    const json_str = try config.toJson(allocator);
    defer allocator.free(json_str);

    // Use atomic write with temporary file to avoid permission race
    const temp_path = try std.fmt.allocPrint(allocator, "{s}.tmp", .{config_path});
    defer allocator.free(temp_path);

    // Create temp file and immediately set restrictive permissions
    const file = try std.fs.cwd().createFile(temp_path, .{});
    defer file.close();

    // Set restrictive permissions before writing (owner read/write only)
    // Note: Windows doesn't support Unix-style permissions
    if (builtin.os.tag != .windows) {
        try file.chmod(0o600);
    }

    try file.writeAll(json_str);
    try file.sync(); // Ensure data is written to disk

    // Atomically rename temp to final path
    try std.fs.cwd().rename(temp_path, config_path);
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

    const test_key = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10 };

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
    defer allocator.free(json_str);

    // Deserialize
    var config2 = try Config.fromJson(allocator, json_str);
    defer config2.deinit(allocator);

    try std.testing.expectEqualSlices(u8, &test_key, &config2.key.?);
    try std.testing.expectEqual(@as(u32, 8), config2.threads.?);
    try std.testing.expectEqual(@as(usize, 8388608), config2.buffer_size.?);
    try std.testing.expectEqual(@as(usize, 2), config2.exclude_patterns.len);
    try std.testing.expectEqualStrings("*.log", config2.exclude_patterns[0]);
    try std.testing.expectEqualStrings(".git/", config2.exclude_patterns[1]);

    // Don't deinit config since we want to keep the strings for config2
    allocator.free(config.exclude_patterns);
}
