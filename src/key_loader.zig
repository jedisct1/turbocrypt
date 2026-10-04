//! Finds keys from `--key`, `TURBOCRYPT_KEY_FILE`, or the config, in that order.

const std = @import("std");
const testing = std.testing;
const Allocator = std.mem.Allocator;
const Io = std.Io;

const Config = @import("Config.zig");
const keygen = @import("keygen.zig");
const password = @import("password.zig");
const prompt = @import("prompt.zig");

pub const env_var_name = "TURBOCRYPT_KEY_FILE";

/// Chooses the key-file path from `--key` or `TURBOCRYPT_KEY_FILE`.
/// Returns null to use the config key instead.
/// The caller owns the returned memory.
pub fn resolvePath(
    gpa: Allocator,
    environ_map: *const std.process.Environ.Map,
    cli_path: ?[]const u8,
) !?[]const u8 {
    if (cli_path) |explicit| {
        if (explicit.len > 0) return try gpa.dupe(u8, explicit);
    }
    if (environ_map.get(env_var_name)) |env_path| {
        if (env_path.len > 0) return try gpa.dupe(u8, env_path);
    }
    return null;
}

/// Loads the selected key file or falls back to the config key.
/// Returns `error.KeyNotFound` when neither source is configured.
pub fn resolve(
    gpa: Allocator,
    io: Io,
    environ_map: *const std.process.Environ.Map,
    cli_path: ?[]const u8,
    maybe_password: ?[]const u8,
) ![16]u8 {
    if (try resolvePath(gpa, environ_map, cli_path)) |path| {
        defer gpa.free(path);
        return keygen.readKeyFile(io, path, maybe_password);
    }

    var config = try Config.load(gpa, io, environ_map);
    defer config.deinit(gpa);
    const key_data = config.key orelse return error.KeyNotFound;

    // Config keys use key-file layouts, so the length preserves format compatibility.
    if (key_data.len == keygen.plain_key_file_size) {
        var key: [16]u8 = undefined;
        @memcpy(&key, key_data);
        return key;
    } else if (keygen.isProtectedFileSize(key_data.len)) {
        if (key_data[0] != @backingInt(keygen.KeyFormat.password_protected)) {
            return error.InvalidKeyFile;
        }
        const pass = maybe_password orelse return error.PasswordRequired;
        return password.unprotectKey(key_data[1..], pass);
    } else {
        return error.InvalidKeyFile;
    }
}

/// Reports whether the selected key requires a password.
pub fn isProtected(
    gpa: Allocator,
    io: Io,
    environ_map: *const std.process.Environ.Map,
    cli_path: ?[]const u8,
) !bool {
    if (try resolvePath(gpa, environ_map, cli_path)) |path| {
        defer gpa.free(path);
        return prompt.isKeyPasswordProtected(io, path);
    }
    var config = Config.load(gpa, io, environ_map) catch return false;
    defer config.deinit(gpa);
    const key_data = config.key orelse return false;
    return keygen.isProtectedFileSize(key_data.len);
}

/// Loads the selected key and prompts when it is password-protected.
/// `ask_password` also forces the prompt for `--password`.
pub fn load(
    gpa: Allocator,
    io: Io,
    environ_map: *const std.process.Environ.Map,
    cli_path: ?[]const u8,
    ask_password: bool,
) ![16]u8 {
    var password_buf: ?[]u8 = null;
    defer if (password_buf) |buf| {
        std.crypto.secureZero(u8, buf);
        gpa.free(buf);
    };
    if (ask_password or try isProtected(gpa, io, environ_map, cli_path)) {
        password_buf = try prompt.password(gpa, io, "Enter key password", false);
    }
    return resolve(gpa, io, environ_map, cli_path, password_buf);
}

/// Explains a key-loading failure with its source, then returns the original error.
pub fn explainLoadError(
    gpa: Allocator,
    environ_map: *const std.process.Environ.Map,
    err: anyerror,
    cli_path: ?[]const u8,
) anyerror {
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
        error.PasswordRequired => std.debug.print(
            "Error: this key is password-protected. Use the --password flag\n",
            .{},
        ),
        error.InvalidPassword => std.debug.print("Error: wrong password\n", .{}),
        else => {
            const source = describeSource(gpa, environ_map, cli_path) catch null;
            defer if (source) |s| gpa.free(s);
            std.debug.print("Error: cannot load {s}: {}\n", .{ source orelse "the key", err });
        },
    }
    return err;
}

/// Describes the selected key source for user-facing messages.
/// The caller owns the returned memory.
pub fn describeSource(
    gpa: Allocator,
    environ_map: *const std.process.Environ.Map,
    cli_path: ?[]const u8,
) ![]u8 {
    if (cli_path) |explicit| {
        if (explicit.len > 0) return gpa.print("key file {s} (--key)", .{explicit});
    }
    if (environ_map.get(env_var_name)) |env_path| {
        if (env_path.len > 0) {
            return gpa.print("key file {s} ({s})", .{ env_path, env_var_name });
        }
    }
    const config_path = try Config.filePath(gpa, environ_map);
    defer gpa.free(config_path);
    return gpa.print("the default key in {s}", .{config_path});
}

test "resolvePath takes the --key path, then the environment, then nothing" {
    const gpa = testing.allocator;
    var environ_map: std.process.Environ.Map = .init(gpa);
    defer environ_map.deinit();
    try testing.expect(try resolvePath(gpa, &environ_map, null) == null);

    try environ_map.put(env_var_name, "/path/from/env");
    const from_cli = (try resolvePath(gpa, &environ_map, "/path/from/cli")).?;
    defer gpa.free(from_cli);
    try testing.expectEqualStrings("/path/from/cli", from_cli);
    const from_env = (try resolvePath(gpa, &environ_map, "")).?;
    defer gpa.free(from_env);
    try testing.expectEqualStrings("/path/from/env", from_env);
}

fn saveConfigKey(
    gpa: Allocator,
    io: Io,
    environ_map: *const std.process.Environ.Map,
    key_data: []const u8,
) !void {
    var config: Config = .{ .key = try gpa.dupe(u8, key_data) };
    defer config.deinit(gpa);
    try config.save(gpa, io, environ_map);
}

test "resolve prefers the --key file, then the environment, then the config" {
    const gpa = testing.allocator;
    const io = testing.io;
    const home = "tmp/key_loader_precedence";
    Io.Dir.deleteTree(.cwd(), io, home) catch {};
    try Io.Dir.createDirPath(.cwd(), io, home);
    defer Io.Dir.deleteTree(.cwd(), io, home) catch {};
    const env_path = home ++ "/env.key";
    const cli_path = home ++ "/cli.key";

    var environ_map = try Config.testEnviron(gpa, home);
    defer environ_map.deinit();
    try testing.expectError(error.KeyNotFound, resolve(gpa, io, &environ_map, null, null));
    try testing.expect(!try isProtected(gpa, io, &environ_map, null));

    const config_key: [16]u8 = @splat(1);
    const env_key: [16]u8 = @splat(2);
    const cli_key: [16]u8 = @splat(3);
    try saveConfigKey(gpa, io, &environ_map, &config_key);
    try keygen.writeKeyFile(gpa, io, env_path, env_key, null);
    try keygen.writeKeyFile(gpa, io, cli_path, cli_key, null);

    try testing.expectEqualSlices(u8, &config_key, &try resolve(gpa, io, &environ_map, null, null));
    const from_config = try describeSource(gpa, &environ_map, null);
    defer gpa.free(from_config);
    try testing.expect(std.mem.startsWith(u8, from_config, "the default key in " ++ home));

    try environ_map.put(env_var_name, env_path);
    try testing.expectEqualSlices(u8, &env_key, &try resolve(gpa, io, &environ_map, null, null));
    const cli_wins = try resolve(gpa, io, &environ_map, cli_path, null);
    try testing.expectEqualSlices(u8, &cli_key, &cli_wins);

    const from_cli = try describeSource(gpa, &environ_map, cli_path);
    defer gpa.free(from_cli);
    try testing.expectEqualStrings("key file " ++ cli_path ++ " (--key)", from_cli);
    const from_env = try describeSource(gpa, &environ_map, null);
    defer gpa.free(from_env);
    const env_source = "key file " ++ env_path ++ " (" ++ env_var_name ++ ")";
    try testing.expectEqualStrings(env_source, from_env);
}

test "a password-protected key in the config needs its password" {
    const gpa = testing.allocator;
    const io = testing.io;
    const home = "tmp/key_loader_protected";
    Io.Dir.deleteTree(.cwd(), io, home) catch {};
    try Io.Dir.createDirPath(.cwd(), io, home);
    defer Io.Dir.deleteTree(.cwd(), io, home) catch {};

    var environ_map = try Config.testEnviron(gpa, home);
    defer environ_map.deinit();

    const flag = @backingInt(keygen.KeyFormat.password_protected);
    const key: [16]u8 = @splat(9);
    var stored: [keygen.protected_key_file_size]u8 = undefined;
    stored[0] = flag;
    stored[1..].* = try password.protectKey(io, key, "hunter2");
    try saveConfigKey(gpa, io, &environ_map, &stored);

    try testing.expect(try isProtected(gpa, io, &environ_map, null));
    try testing.expectError(error.PasswordRequired, resolve(gpa, io, &environ_map, null, null));
    try testing.expectError(error.InvalidPassword, resolve(gpa, io, &environ_map, null, "wrong"));
    try testing.expectEqualSlices(u8, &key, &try resolve(gpa, io, &environ_map, null, "hunter2"));

    const legacy = password.legacy_test_vector;
    const legacy_stored: [keygen.legacy_protected_key_file_size]u8 =
        [_]u8{flag} ++ legacy.protected;
    try saveConfigKey(gpa, io, &environ_map, &legacy_stored);

    try testing.expect(try isProtected(gpa, io, &environ_map, null));
    try testing.expectError(error.PasswordRequired, resolve(gpa, io, &environ_map, null, null));
    const legacy_key = try resolve(gpa, io, &environ_map, null, legacy.passphrase);
    try testing.expectEqualSlices(u8, &legacy.key, &legacy_key);
}
