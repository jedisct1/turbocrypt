const std = @import("std");
const config = @import("config.zig");
const keygen = @import("keygen.zig");
const password = @import("password.zig");
const prompt = @import("prompt.zig");

pub const env_var_name = "TURBOCRYPT_KEY_FILE";

/// The key file path from the --key argument, else from TURBOCRYPT_KEY_FILE.
/// Null means the key comes from the config file. The caller frees the result.
pub fn resolveKeyPath(allocator: std.mem.Allocator, optional_cli_path: ?[]const u8, environ_map: *const std.process.Environ.Map) !?[]const u8 {
    if (optional_cli_path) |cli_path| {
        if (cli_path.len > 0) {
            return try allocator.dupe(u8, cli_path);
        }
    }

    if (environ_map.get(env_var_name)) |env_path| {
        if (env_path.len > 0) {
            return try allocator.dupe(u8, env_path);
        }
    }

    return null;
}

/// The key from the file that resolveKeyPath names, else from the config file.
/// Returns error.KeyNotFound when nothing is configured.
pub fn resolveKey(allocator: std.mem.Allocator, optional_cli_path: ?[]const u8, password_opt: ?[]const u8, io: std.Io, environ_map: *const std.process.Environ.Map) ![16]u8 {
    const key_path = try resolveKeyPath(allocator, optional_cli_path, environ_map);

    if (key_path) |path| {
        defer allocator.free(path);
        return try keygen.readKeyFile(path, password_opt, io);
    } else {
        var cfg = try config.load(allocator, io, environ_map);
        defer cfg.deinit(allocator);

        if (cfg.key) |key_data| {
            // The config stores the key in the key file layout, so the length tells the format.
            if (key_data.len == keygen.plain_key_file_size) {
                var key: [16]u8 = undefined;
                @memcpy(&key, key_data);
                return key;
            } else if (key_data.len == keygen.protected_key_file_size) {
                const format_flag = key_data[0];
                if (format_flag != @backingInt(keygen.KeyFormat.password_protected)) {
                    return error.InvalidKeyFile;
                }

                const pwd = password_opt orelse return error.PasswordRequired;

                var protected_data: [20]u8 = undefined;
                @memcpy(&protected_data, key_data[1..keygen.protected_key_file_size]);

                return try password.unprotectKey(protected_data, pwd);
            } else {
                return error.InvalidKeyFile;
            }
        }

        return error.KeyNotFound;
    }
}

/// Whether the key that resolveKey would use has a password.
pub fn isProtected(allocator: std.mem.Allocator, optional_cli_path: ?[]const u8, io: std.Io, environ_map: *const std.process.Environ.Map) !bool {
    if (try resolveKeyPath(allocator, optional_cli_path, environ_map)) |path| {
        defer allocator.free(path);
        return prompt.isKeyPasswordProtected(path, io);
    }
    var cfg = config.load(allocator, io, environ_map) catch return false;
    defer cfg.deinit(allocator);
    const key_data = cfg.key orelse return false;
    return key_data.len == keygen.protected_key_file_size;
}

/// Resolve the key with the usual precedence and ask for its password when it has one.
/// `ask_password` forces the prompt, for the --password flag.
pub fn loadKey(allocator: std.mem.Allocator, optional_cli_path: ?[]const u8, ask_password: bool, io: std.Io, environ_map: *const std.process.Environ.Map) ![16]u8 {
    var password_buf: ?[]u8 = null;
    defer if (password_buf) |buf| {
        std.crypto.secureZero(u8, buf);
        allocator.free(buf);
    };
    if (ask_password or try isProtected(allocator, optional_cli_path, io, environ_map)) {
        password_buf = try prompt.promptPassword(allocator, "Enter key password", false, io);
    }
    return resolveKey(allocator, optional_cli_path, password_buf, io, environ_map);
}

/// Explain a failed key load, naming the source of the key, and hand the error back.
pub fn explainLoadError(allocator: std.mem.Allocator, err: anyerror, optional_cli_path: ?[]const u8, environ_map: *const std.process.Environ.Map) anyerror {
    switch (err) {
        error.KeyNotFound => std.debug.print(
            \\Error: no encryption key is configured
            \\
            \\Provide a key in one of these ways:
            \\  1. Generate one:                turbocrypt keygen secret.key
            \\  2. Pass it on the command line: --key secret.key
            \\  3. Set an environment variable: export {s}=secret.key
            \\  4. Set a default key:           turbocrypt config set-key secret.key
            \\
        , .{env_var_name}),
        error.PasswordRequired => std.debug.print("Error: this key is password-protected. Use the --password flag\n", .{}),
        error.InvalidPassword => std.debug.print("Error: wrong password\n", .{}),
        else => {
            const source = describeKeySource(allocator, optional_cli_path, environ_map) catch null;
            defer if (source) |s| allocator.free(s);
            std.debug.print("Error: cannot load {s}: {}\n", .{ source orelse "the key", err });
        },
    }
    return err;
}

/// Where resolveKey takes the key from, for messages.
pub fn describeKeySource(allocator: std.mem.Allocator, optional_cli_path: ?[]const u8, environ_map: *const std.process.Environ.Map) ![]u8 {
    if (optional_cli_path) |cli_path| {
        if (cli_path.len > 0) return std.fmt.allocPrint(allocator, "key file {s} (--key)", .{cli_path});
    }
    if (environ_map.get(env_var_name)) |env_path| {
        if (env_path.len > 0) return std.fmt.allocPrint(allocator, "key file {s} ({s})", .{ env_path, env_var_name });
    }
    const config_path = try config.getConfigFilePath(allocator, environ_map);
    defer allocator.free(config_path);
    return std.fmt.allocPrint(allocator, "the default key in {s}", .{config_path});
}

pub fn getConfigFilePath(allocator: std.mem.Allocator, environ_map: *const std.process.Environ.Map) ![]const u8 {
    return try config.getConfigFilePath(allocator, environ_map);
}

test "resolveKeyPath - CLI argument takes priority" {
    const allocator = std.testing.allocator;
    var environ_map = std.process.Environ.Map.init(allocator);
    defer environ_map.deinit();
    try environ_map.put(env_var_name, "/path/from/env");

    const result = try resolveKeyPath(allocator, "/path/from/cli", &environ_map);
    defer if (result) |path| allocator.free(path);

    try std.testing.expectEqualStrings("/path/from/cli", result.?);
}

test "resolveKeyPath - environment variable before config" {
    const allocator = std.testing.allocator;
    var environ_map = std.process.Environ.Map.init(allocator);
    defer environ_map.deinit();
    try environ_map.put(env_var_name, "/path/from/env");

    const result = try resolveKeyPath(allocator, "", &environ_map);
    defer if (result) |path| allocator.free(path);

    try std.testing.expectEqualStrings("/path/from/env", result.?);
}

test "resolveKeyPath - returns null when no path configured" {
    const allocator = std.testing.allocator;
    var environ_map = std.process.Environ.Map.init(allocator);
    defer environ_map.deinit();

    const result = try resolveKeyPath(allocator, null, &environ_map);
    try std.testing.expect(result == null);
}

fn saveConfigKey(allocator: std.mem.Allocator, io: std.Io, environ_map: *const std.process.Environ.Map, key_data: []const u8) !void {
    var cfg = config.Config{ .key = try allocator.dupe(u8, key_data) };
    defer cfg.deinit(allocator);
    try config.save(cfg, allocator, io, environ_map);
}

test "resolveKey - precedence between file sources and the config" {
    const testing = std.testing;
    const allocator = testing.allocator;
    const io = testing.io;
    const home = "tmp/keyloader_precedence";
    std.Io.Dir.deleteTree(.cwd(), io, home) catch {};
    try std.Io.Dir.createDirPath(.cwd(), io, home);
    defer std.Io.Dir.deleteTree(.cwd(), io, home) catch {};

    var environ_map = try config.testEnviron(allocator, home);
    defer environ_map.deinit();
    try testing.expectError(error.KeyNotFound, resolveKey(allocator, null, null, io, &environ_map));
    try testing.expect(!try isProtected(allocator, null, io, &environ_map));

    const config_key: [16]u8 = @splat(1);
    const env_key: [16]u8 = @splat(2);
    const cli_key: [16]u8 = @splat(3);
    try saveConfigKey(allocator, io, &environ_map, &config_key);
    try keygen.writeKeyFile(home ++ "/env.key", env_key, null, allocator, io);
    try keygen.writeKeyFile(home ++ "/cli.key", cli_key, null, allocator, io);

    try testing.expectEqualSlices(u8, &config_key, &try resolveKey(allocator, null, null, io, &environ_map));
    const from_config = try describeKeySource(allocator, null, &environ_map);
    defer allocator.free(from_config);
    try testing.expect(std.mem.startsWith(u8, from_config, "the default key in " ++ home));

    try environ_map.put(env_var_name, home ++ "/env.key");
    try testing.expectEqualSlices(u8, &env_key, &try resolveKey(allocator, null, null, io, &environ_map));
    try testing.expectEqualSlices(u8, &cli_key, &try resolveKey(allocator, home ++ "/cli.key", null, io, &environ_map));

    const from_cli = try describeKeySource(allocator, home ++ "/cli.key", &environ_map);
    defer allocator.free(from_cli);
    try testing.expectEqualStrings("key file " ++ home ++ "/cli.key (--key)", from_cli);
    const from_env = try describeKeySource(allocator, null, &environ_map);
    defer allocator.free(from_env);
    try testing.expectEqualStrings("key file " ++ home ++ "/env.key (" ++ env_var_name ++ ")", from_env);
}

test "resolveKey - password-protected config key" {
    const testing = std.testing;
    const allocator = testing.allocator;
    const io = testing.io;
    const home = "tmp/keyloader_protected";
    std.Io.Dir.deleteTree(.cwd(), io, home) catch {};
    try std.Io.Dir.createDirPath(.cwd(), io, home);
    defer std.Io.Dir.deleteTree(.cwd(), io, home) catch {};

    var environ_map = try config.testEnviron(allocator, home);
    defer environ_map.deinit();

    const key: [16]u8 = @splat(9);
    var stored: [keygen.protected_key_file_size]u8 = undefined;
    stored[0] = @backingInt(keygen.KeyFormat.password_protected);
    stored[1..].* = try password.protectKey(key, "hunter2");
    try saveConfigKey(allocator, io, &environ_map, &stored);

    try testing.expect(try isProtected(allocator, null, io, &environ_map));
    try testing.expectError(error.PasswordRequired, resolveKey(allocator, null, null, io, &environ_map));
    try testing.expectError(error.InvalidPassword, resolveKey(allocator, null, "wrong", io, &environ_map));
    try testing.expectEqualSlices(u8, &key, &try resolveKey(allocator, null, "hunter2", io, &environ_map));
}
