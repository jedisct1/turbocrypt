const std = @import("std");
const config = @import("config.zig");
const keygen = @import("keygen.zig");
const password = @import("password.zig");

/// Environment variable name for key file path
pub const env_var_name = "TURBOCRYPT_KEY_FILE";

/// Resolve the key file path using the following priority:
/// 1. CLI argument (if provided and not empty)
/// 2. TURBOCRYPT_KEY_FILE environment variable
/// 3. Config file (returns null - key loaded directly from config)
///
/// Returns an owned slice that the caller must free.
/// Returns null if key should be loaded from config.
pub fn resolveKeyPath(allocator: std.mem.Allocator, optional_cli_path: ?[]const u8) !?[]const u8 {
    // Priority 1: CLI argument
    if (optional_cli_path) |cli_path| {
        if (cli_path.len > 0) {
            return try allocator.dupe(u8, cli_path);
        }
    }

    // Priority 2: Environment variable
    if (std.process.getEnvVarOwned(allocator, env_var_name)) |env_path| {
        if (env_path.len > 0) {
            return env_path; // Already owned
        }
        allocator.free(env_path);
    } else |_| {
        // Environment variable not set or error reading it - continue to next priority
    }

    // Priority 3: Config file - return null to signal key should be loaded from config
    return null;
}

/// Resolve the encryption key using the following priority:
/// 1. CLI argument (load from file path)
/// 2. TURBOCRYPT_KEY_FILE environment variable (load from file path)
/// 3. Config file (use stored key)
///
/// Returns error.KeyNotFound if no key is configured.
pub fn resolveKey(allocator: std.mem.Allocator, optional_cli_path: ?[]const u8, password_opt: ?[]const u8) ![16]u8 {
    const key_path = try resolveKeyPath(allocator, optional_cli_path);

    if (key_path) |path| {
        // Load from file
        defer allocator.free(path);
        return try keygen.readKeyFile(path, password_opt);
    } else {
        // Load from config
        var cfg = try config.load(allocator);
        defer cfg.deinit(allocator);

        if (cfg.key) |key_data| {
            // Detect password protection by length (same as file format)
            if (key_data.len == keygen.plain_key_file_size) {
                // Plain key: return as-is
                var key: [16]u8 = undefined;
                @memcpy(&key, key_data);
                return key;
            } else if (key_data.len == keygen.protected_key_file_size) {
                // Password-protected key: flag byte + 16 XOR'd bytes + 4 checksum bytes
                const format_flag = key_data[0];
                if (format_flag != @intFromEnum(keygen.KeyFormat.password_protected)) {
                    return error.InvalidKeyFile;
                }

                // Password is required to decrypt the key
                const pwd = password_opt orelse return error.PasswordRequired;

                // Extract the protected key bytes (skip flag byte)
                var protected_data: [20]u8 = undefined;
                @memcpy(&protected_data, key_data[1..keygen.protected_key_file_size]);

                // Decrypt the key (XOR with Argon2id output and verify checksum)
                return try password.unprotectKey(protected_data, pwd);
            } else {
                return error.InvalidKeyFile;
            }
        }

        return error.KeyNotFound;
    }
}

/// Get the full path to the config file
pub fn getConfigFilePath(allocator: std.mem.Allocator) ![]const u8 {
    return try config.getConfigFilePath(allocator);
}

/// Set the default key in the config file
/// key_data should be in the same format as key files:
/// - 16 bytes: plain key
/// - 21 bytes: password-protected (1 flag byte + 16 XOR'd bytes + 4 checksum bytes)
pub fn setDefaultKey(allocator: std.mem.Allocator, key_data: []const u8) !void {
    // Load existing config
    var cfg = try config.load(allocator);
    defer cfg.deinit(allocator);

    // Free old key if exists
    if (cfg.key) |old_key| {
        allocator.free(old_key);
    }

    // Store new key (duplicate to own the memory)
    cfg.key = try allocator.dupe(u8, key_data);

    // Save config
    try config.save(cfg, allocator);
}

/// Get information about where the key would be loaded from (for user feedback)
pub fn describeKeySource(allocator: std.mem.Allocator, optional_cli_path: ?[]const u8) ![]const u8 {
    // Check CLI argument
    if (optional_cli_path) |cli_path| {
        if (cli_path.len > 0) {
            return try std.fmt.allocPrint(allocator, "CLI argument: {s}", .{cli_path});
        }
    }

    // Check environment variable
    if (std.process.getEnvVarOwned(allocator, env_var_name)) |env_path| {
        defer allocator.free(env_path);
        if (env_path.len > 0) {
            return try std.fmt.allocPrint(allocator, "Environment variable {s}: {s}", .{ env_var_name, env_path });
        }
    } else |_| {}

    // Check config file
    const config_path = try config.getConfigFilePath(allocator);
    defer allocator.free(config_path);

    var cfg = config.load(allocator) catch {
        return try allocator.dupe(u8, "No key configured");
    };
    defer cfg.deinit(allocator);

    if (cfg.key) |key_data| {
        const is_protected = key_data.len == keygen.protected_key_file_size;
        if (is_protected) {
            return try std.fmt.allocPrint(allocator, "Config file ({s}): password-protected key", .{config_path});
        } else {
            return try std.fmt.allocPrint(allocator, "Config file ({s}): key stored directly", .{config_path});
        }
    }

    return try allocator.dupe(u8, "No key configured");
}

test "resolveKeyPath - CLI argument takes priority" {
    const allocator = std.testing.allocator;

    const result = try resolveKeyPath(allocator, "/path/from/cli");
    defer if (result) |path| allocator.free(path);

    try std.testing.expectEqualStrings("/path/from/cli", result.?);
}

test "resolveKeyPath - returns null when no path configured" {
    const allocator = std.testing.allocator;

    const result = try resolveKeyPath(allocator, null);
    try std.testing.expect(result == null);
}
