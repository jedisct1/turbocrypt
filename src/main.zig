const std = @import("std");
const keygen = @import("keygen.zig");
const keyloader = @import("keyloader.zig");
const config_mod = @import("config.zig");
const crypto = @import("crypto.zig");
const processor = @import("processor.zig");
const utils = @import("utils.zig");
const worker = @import("worker.zig");
const progress = @import("progress.zig");
const filename_crypto = @import("filename_crypto.zig");
const prompt = @import("prompt.zig");
const password = @import("password.zig");
const bench = @import("bench.zig");
const git_cmd = @import("git/cmd.zig");
const build_options = @import("build_options");

const usage_text =
    \\TurboCrypt - High-performance file encryption
    \\
    \\Usage:
    \\  turbocrypt keygen [--password] <output-file>
    \\      Generate a new 128-bit encryption key
    \\      Use --password to protect the key file with a password
    \\
    \\  turbocrypt change-password [--remove-password] <key-file>
    \\      Change or add password protection to an existing key file
    \\      Use --remove-password to remove password protection from a key
    \\
    \\  turbocrypt encrypt [--key <key-file>] [--password] <source> <destination> [options]
    \\      Encrypt a file or directory
    \\
    \\  turbocrypt decrypt [--key <key-file>] [--password] <source> <destination> [options]
    \\      Decrypt a file or directory
    \\
    \\  turbocrypt verify [--key <key-file>] [--password] [--quick] <source> [options]
    \\      Verify integrity of encrypted files without decrypting
    \\      Use --quick to only check header MAC (faster, but doesn't verify data integrity)
    \\
    \\  turbocrypt list [--key <key-file>] [--password] [--encrypted-filenames] <directory> [options]
    \\      List contents of encrypted directory
    \\      If --encrypted-filenames is used, decrypts filenames (requires correct key)
    \\      Shows file sizes and directory structure
    \\
    \\  turbocrypt config set-key <key-file>
    \\      Set the default key file path
    \\
    \\  turbocrypt config set-threads <n>
    \\      Set the default number of worker threads
    \\
    \\  turbocrypt config set-buffer-size <size>
    \\      Set the default buffer size in bytes
    \\
    \\  turbocrypt config add-exclude <pattern>
    \\      Add a default exclude pattern
    \\
    \\  turbocrypt config remove-exclude <pattern>
    \\      Remove a default exclude pattern
    \\
    \\  turbocrypt config set-ignore-symlinks <true|false>
    \\      Set whether to ignore symbolic links by default
    \\
    \\  turbocrypt config set-encrypted-filenames <true|false>
    \\      Set whether to encrypt filenames by default
    \\
    \\  turbocrypt config show
    \\      Show the current configuration
    \\
    \\  turbocrypt git <subcommand> [options]
    \\      Keep private files in a public git repository
    \\      Subcommands: init, unlock, export-key, add, rm, status, encrypt, decrypt
    \\      Run "turbocrypt git help" for details
    \\
    \\  turbocrypt bench
    \\      Run performance benchmarks
    \\
    \\  turbocrypt version
    \\      Show the program version
    \\
    \\Key Resolution (in priority order):
    \\  1. --key flag (if provided)
    \\  2. TURBOCRYPT_KEY_FILE environment variable
    \\  3. Config file (set via 'config set-key')
    \\
    \\Options:
    \\  --key <path>         Path to key file (overrides env var and config)
    \\  --password           Prompt for password (auto-detects password-protected keys)
    \\  --context <string>   Context string for key derivation (creates independent key namespace)
    \\                       Same context must be used for both encryption and decryption
    \\  --threads <n>        Number of worker threads (default: CPU count, max 64)
    \\  --buffer-size <size> Buffer size in bytes (default: 4194304 = 4MB)
    \\  --in-place           Encrypt/decrypt files in place (source overwrites destination)
    \\  --force              Overwrite existing files without prompting
    \\  --enc-suffix         Add ".enc" suffix when encrypting, remove when decrypting
    \\                       (skips files without .enc suffix during decryption)
    \\  --encrypted-filenames      Encrypt filenames
    \\                       (preserves directory structure, encrypts each path component)
    \\                       (incompatible with --in-place)
    \\  --exclude <pattern>  Exclude files matching pattern (can use multiple times)
    \\                       Supports: *.ext (extensions), dir/ (directories),
    \\                       exact/path (exact matches), prefix* (wildcards)
    \\  --ignore-symlinks    Ignore symbolic links (skip them during processing)
    \\  --quick              (verify only) Only check header MAC, skip full verification
    \\                       Faster but doesn't verify data integrity - only checks key correctness
    \\  --dry-run            Show what would be processed without actually encrypting/decrypting
    \\                       Useful for testing exclude patterns and verifying operations
    \\
    \\Examples:
    \\  turbocrypt keygen secret.key
    \\  turbocrypt keygen --password protected.key
    \\  turbocrypt change-password secret.key
    \\  turbocrypt change-password --remove-password protected.key
    \\  turbocrypt config set-key secret.key
    \\  turbocrypt encrypt documents/ encrypted/
    \\  turbocrypt decrypt encrypted/ decrypted/
    \\  turbocrypt verify encrypted/
    \\  turbocrypt verify --quick encrypted/
    \\  turbocrypt encrypt documents/ encrypted/
    \\  turbocrypt encrypt --key other.key documents/ encrypted/
    \\  turbocrypt encrypt --in-place --threads 8 sensitive-data/
    \\  turbocrypt encrypt --exclude "*.log" --exclude ".git/" source/ dest/
    \\  turbocrypt encrypt --context "project-x" documents/ encrypted-x/
    \\  turbocrypt decrypt --context "project-x" encrypted-x/ decrypted/
    \\  export TURBOCRYPT_KEY_FILE=secret.key && turbocrypt encrypt data/ encrypted/
    \\  turbocrypt git init
    \\  turbocrypt git add INTERNAL-DOC.md docs/internal.md
    \\  turbocrypt git unlock --key team.key
    \\
;

fn printUsage() void {
    std.debug.print("{s}\n", .{usage_text});
}

fn printVersion() void {
    std.debug.print("turbocrypt {s}\n", .{build_options.version});
}

const Options = struct {
    key: ?[]const u8 = null,
    password: bool = false,
    context: ?[]const u8 = null,
    threads: ?u32 = null,
    buffer_size: ?usize = null,
    in_place: bool = false,
    force: bool = false,
    enc_suffix: bool = false,
    encrypt_filenames: bool = false,
    ignore_symlinks: bool = false,
    quick: bool = false,
    dry_run: bool = false,
    remove_password: bool = false,
    exclude_patterns: std.ArrayList([]const u8) = .empty,
};

const enc_suffix = ".enc";

fn hasEncSuffix(path: []const u8) bool {
    return std.mem.endsWith(u8, path, enc_suffix);
}

fn addEncSuffix(allocator: std.mem.Allocator, path: []const u8) ![]u8 {
    return try std.mem.concat(allocator, u8, &[_][]const u8{ path, enc_suffix });
}

/// Null when the path has no suffix.
fn stripEncSuffix(allocator: std.mem.Allocator, path: []const u8) !?[]u8 {
    if (!hasEncSuffix(path)) return null;
    return try allocator.dupe(u8, path[0 .. path.len - enc_suffix.len]);
}

/// Add the suffix for encryption, or strip it for decryption. Null when there is none to strip.
fn applyEncSuffix(allocator: std.mem.Allocator, path: []const u8, is_encrypt: bool) !?[]u8 {
    return if (is_encrypt) try addEncSuffix(allocator, path) else try stripEncSuffix(allocator, path);
}

/// Options not given on the command line take their default from the config file.
fn parseOptions(args: []const []const u8, allocator: std.mem.Allocator, io: std.Io, environ_map: *const std.process.Environ.Map) !struct { options: Options, positional: []const []const u8 } {
    var opts = Options{};
    var positional: std.ArrayList([]const u8) = .empty;
    defer positional.deinit(allocator);

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const arg = args[i];

        if (std.mem.eql(u8, arg, "--key")) {
            if (i + 1 >= args.len) {
                std.debug.print("Error: --key requires a value\n", .{});
                return error.InvalidArguments;
            }
            i += 1;
            opts.key = args[i];
        } else if (std.mem.eql(u8, arg, "--context")) {
            if (i + 1 >= args.len) {
                std.debug.print("Error: --context requires a value\n", .{});
                return error.InvalidArguments;
            }
            i += 1;
            opts.context = args[i];
        } else if (std.mem.eql(u8, arg, "--threads")) {
            if (i + 1 >= args.len) {
                std.debug.print("Error: --threads requires a value\n", .{});
                return error.InvalidArguments;
            }
            i += 1;
            const value = args[i];
            const threads = std.fmt.parseUnsigned(u32, value, 10) catch 0;
            if (threads == 0) {
                std.debug.print("Error: Invalid thread count '{s}'\n", .{value});
                return error.InvalidArguments;
            }
            opts.threads = threads;
        } else if (std.mem.eql(u8, arg, "--buffer-size")) {
            if (i + 1 >= args.len) {
                std.debug.print("Error: --buffer-size requires a value\n", .{});
                return error.InvalidArguments;
            }
            i += 1;
            const value = args[i];
            opts.buffer_size = std.fmt.parseUnsigned(usize, value, 10) catch {
                std.debug.print("Error: Invalid buffer size '{s}'\n", .{value});
                return error.InvalidArguments;
            };
        } else if (std.mem.eql(u8, arg, "--in-place")) {
            opts.in_place = true;
        } else if (std.mem.eql(u8, arg, "--force")) {
            opts.force = true;
        } else if (std.mem.eql(u8, arg, "--enc-suffix")) {
            opts.enc_suffix = true;
        } else if (std.mem.eql(u8, arg, "--encrypted-filenames")) {
            opts.encrypt_filenames = true;
        } else if (std.mem.eql(u8, arg, "--ignore-symlinks")) {
            opts.ignore_symlinks = true;
        } else if (std.mem.eql(u8, arg, "--password")) {
            opts.password = true;
        } else if (std.mem.eql(u8, arg, "--quick")) {
            opts.quick = true;
        } else if (std.mem.eql(u8, arg, "--dry-run")) {
            opts.dry_run = true;
        } else if (std.mem.eql(u8, arg, "--remove-password")) {
            opts.remove_password = true;
        } else if (std.mem.eql(u8, arg, "--exclude")) {
            if (i + 1 >= args.len) {
                std.debug.print("Error: --exclude requires a value\n", .{});
                return error.InvalidArguments;
            }
            i += 1;
            const pattern = args[i];
            const pattern_copy = try allocator.dupe(u8, pattern);
            try opts.exclude_patterns.append(allocator, pattern_copy);
        } else if (std.mem.startsWith(u8, arg, "--")) {
            std.debug.print("Error: Unknown option '{s}'\n", .{arg});
            return error.InvalidArguments;
        } else {
            try positional.append(allocator, arg);
        }
    }

    var cfg = config_mod.load(allocator, io, environ_map) catch |err| blk: {
        // A config file that fails to load only costs its defaults.
        if (err != error.FileNotFound) {
            std.debug.print("Warning: Failed to load config file: {}\n", .{err});
        }
        break :blk config_mod.Config{};
    };
    defer cfg.deinit(allocator);

    if (opts.threads == null) {
        opts.threads = cfg.threads;
    }
    if (opts.buffer_size == null) {
        opts.buffer_size = cfg.buffer_size;
    }
    if (!opts.ignore_symlinks and cfg.ignore_symlinks != null) {
        opts.ignore_symlinks = cfg.ignore_symlinks.?;
    }
    if (!opts.encrypt_filenames and cfg.encrypted_filenames != null) {
        opts.encrypt_filenames = cfg.encrypted_filenames.?;
    }

    // Command line patterns replace the config patterns instead of adding to them.
    if (cfg.exclude_patterns.len > 0 and opts.exclude_patterns.items.len == 0) {
        for (cfg.exclude_patterns) |pattern| {
            const pattern_copy = try allocator.dupe(u8, pattern);
            try opts.exclude_patterns.append(allocator, pattern_copy);
        }
    }

    if (opts.in_place and opts.encrypt_filenames) {
        std.debug.print("Error: --in-place and --encrypted-filenames are incompatible\n", .{});
        std.debug.print("       In-place encryption cannot change filenames\n", .{});
        return error.InvalidArguments;
    }

    return .{
        .options = opts,
        .positional = try positional.toOwnedSlice(allocator),
    };
}

fn getThreadCount(opts: Options) !u32 {
    if (opts.threads) |t| return @min(t, 64);
    const cpu_count = try std.Thread.getCpuCount();
    return @as(u32, @intCast(@min(cpu_count, 16)));
}

fn explainConfigError(action: []const u8, err: anyerror, allocator: std.mem.Allocator, environ_map: *const std.process.Environ.Map) void {
    const config_path = config_mod.getConfigFilePath(allocator, environ_map) catch {
        std.debug.print("Error: Cannot {s} the config file: {}\n", .{ action, err });
        return;
    };
    defer allocator.free(config_path);
    std.debug.print("Error: Cannot {s} config file '{s}': {}\n", .{ action, config_path, err });
}

fn loadConfig(allocator: std.mem.Allocator, io: std.Io, environ_map: *const std.process.Environ.Map) !config_mod.Config {
    return config_mod.load(allocator, io, environ_map) catch |err| {
        explainConfigError("read", err, allocator, environ_map);
        return err;
    };
}

fn saveConfig(cfg: config_mod.Config, allocator: std.mem.Allocator, io: std.Io, environ_map: *const std.process.Environ.Map) !void {
    config_mod.save(cfg, allocator, io, environ_map) catch |err| {
        explainConfigError("write", err, allocator, environ_map);
        return err;
    };
}

fn cmdKeygen(args: []const []const u8, allocator: std.mem.Allocator, io: std.Io, environ_map: *const std.process.Environ.Map) !void {
    const parsed = try parseOptions(args, allocator, io, environ_map);
    defer allocator.free(parsed.positional);
    var opts = parsed.options;
    defer {
        for (opts.exclude_patterns.items) |pattern| {
            allocator.free(pattern);
        }
        opts.exclude_patterns.deinit(allocator);
    }

    if (parsed.positional.len < 1) {
        std.debug.print("Error: Missing output file path\n", .{});
        std.debug.print("Usage: turbocrypt keygen [--password] <output-file>\n", .{});
        return error.InvalidArguments;
    }

    const output_path = parsed.positional[0];

    const key = keygen.generate(io);

    var password_buf: ?[]u8 = null;
    defer if (password_buf) |buf| {
        std.crypto.secureZero(u8, buf);
        allocator.free(buf);
    };

    if (opts.password) {
        password_buf = prompt.promptPassword(allocator, "Enter password to protect key", true, io) catch |err| {
            if (err == error.PasswordMismatch) {
                std.debug.print("Error: Passwords do not match\n", .{});
                return error.PasswordMismatch;
            }
            return err;
        };
    }

    try keygen.writeKeyFile(output_path, key, password_buf, allocator, io);

    std.debug.print("Key generated and saved to: {s}\n", .{output_path});
    if (opts.password) {
        std.debug.print("Key is password-protected\n", .{});
    }
    std.debug.print("WARNING: Keep this key file secure! Anyone with access to it can decrypt your files.\n", .{});
    std.debug.print("\nTo set this as your default key, run:\n", .{});
    std.debug.print("  turbocrypt config set-key {s}\n", .{output_path});
}

const ScannedFile = struct {
    source_path: []const u8,
    dest_path: []const u8,
    size: u64,
};

const ScanResult = struct {
    files: std.ArrayList(ScannedFile) = .empty,
    total_bytes: u64 = 0,

    fn deinit(self: *ScanResult, allocator: std.mem.Allocator) void {
        for (self.files.items) |file| {
            allocator.free(file.source_path);
            allocator.free(file.dest_path);
        }
        self.files.deinit(allocator);
    }
};

const ProcessingMode = union(enum) {
    scan_only: ScanResult,
    scan_and_process: struct {
        worker_pool: *worker.WorkerPool,
        progress_tracker: *progress.ProgressTracker,
    },
};

const DirectoryScanContext = struct {
    source_base: []const u8,
    dest_base: []const u8,
    allocator: std.mem.Allocator,
    enc_suffix: bool,
    is_encrypt: bool,
    encrypt_filenames: bool,
    key: [16]u8,
    exclude_patterns: std.ArrayList([]const u8),
    ignore_symlinks: bool,
    dry_run: bool,
    io: std.Io,
    mode: ProcessingMode,

    fn callback(
        relative_path: []const u8,
        full_path: []const u8,
        is_directory: bool,
        context: *anyopaque,
    ) !void {
        const self: *DirectoryScanContext = @ptrCast(@alignCast(context));

        // Excluded directories must not appear in the destination.
        if (utils.matchesExcludePattern(relative_path, self.exclude_patterns)) {
            return;
        }

        if (is_directory) {
            try self.handleDirectory(relative_path);
            return;
        }

        const dest_relative_path = (try self.destRelativePath(relative_path)) orelse return;
        defer self.allocator.free(dest_relative_path);

        const file = try std.Io.Dir.openFile(.cwd(), self.io, full_path, .{});
        defer file.close(self.io);
        const file_size = (try file.stat(self.io)).size;

        switch (self.mode) {
            .scan_only => |*scan| {
                const source_path = try self.allocator.dupe(u8, full_path);
                errdefer self.allocator.free(source_path);
                const dest_path = try std.fs.path.join(self.allocator, &[_][]const u8{ self.dest_base, dest_relative_path });
                errdefer self.allocator.free(dest_path);
                try scan.files.append(self.allocator, .{
                    .source_path = source_path,
                    .dest_path = dest_path,
                    .size = file_size,
                });
                scan.total_bytes += file_size;
            },
            .scan_and_process => |proc| {
                try self.submitFile(full_path, dest_relative_path, file_size, proc.worker_pool, proc.progress_tracker);
            },
        }
    }

    /// Create the matching directory under the destination root.
    fn handleDirectory(self: *DirectoryScanContext, relative_path: []const u8) !void {
        var transformed: ?[]u8 = null;
        defer if (transformed) |name| self.allocator.free(name);
        if (self.encrypt_filenames) {
            transformed = try self.transformPath(relative_path, "directory name");
        }

        if (self.dry_run) return;

        const dest_dir = try std.fs.path.join(self.allocator, &[_][]const u8{ self.dest_base, transformed orelse relative_path });
        defer self.allocator.free(dest_dir);
        utils.ensureDirectory(dest_dir, self.io) catch |err| {
            std.debug.print("\n[ERROR] Failed to create directory: {s}\n", .{dest_dir});
            std.debug.print("        Reason: {}\n", .{err});
            if (self.encrypt_filenames and !self.is_encrypt) {
                std.debug.print("        Suggestion: Directory name may be corrupted or encrypted with a different key\n", .{});
            }
            return err;
        };
    }

    /// Where a file goes, relative to the destination root. Null means the file is skipped.
    /// The .enc suffix belongs to the encrypted name, so it is added before encryption and removed after decryption.
    fn destRelativePath(self: *DirectoryScanContext, relative_path: []const u8) !?[]u8 {
        if (self.is_encrypt) {
            const named = if (self.enc_suffix)
                try addEncSuffix(self.allocator, relative_path)
            else
                try self.allocator.dupe(u8, relative_path);
            if (!self.encrypt_filenames) return named;
            defer self.allocator.free(named);
            return try self.transformPath(named, "filename");
        }

        const named = if (self.encrypt_filenames)
            try self.transformPath(relative_path, "filename")
        else
            try self.allocator.dupe(u8, relative_path);
        if (!self.enc_suffix) return named;
        defer self.allocator.free(named);
        return try stripEncSuffix(self.allocator, named);
    }

    /// Encrypt or decrypt every component of a path, and explain a failure to the user.
    fn transformPath(self: *DirectoryScanContext, path: []const u8, what: []const u8) ![]u8 {
        return (if (self.is_encrypt)
            filename_crypto.encryptPath(self.allocator, path, self.key, std.fs.path.sep)
        else
            filename_crypto.decryptPathForFilesystem(self.allocator, path, self.key, std.fs.path.sep)) catch |err| {
            std.debug.print("\n[ERROR] Failed to {s} {s}: {s}\n", .{
                if (self.is_encrypt) "encrypt" else "decrypt",
                what,
                path,
            });
            std.debug.print("        Reason: {}\n", .{err});
            if (err == filename_crypto.FilenameError.EncryptedFilenameTooLong) {
                std.debug.print("        Suggestion: The {s} is too long. Encrypted names must fit within 255 bytes.\n", .{what});
                std.debug.print("                   Consider shortening it (names of up to 197 bytes always fit).\n", .{});
            } else if (!self.is_encrypt) {
                std.debug.print("        Suggestion: Ensure the {s} was encrypted with --encrypted-filenames using the same key\n", .{what});
            }
            return err;
        };
    }

    fn submitFile(
        self: *DirectoryScanContext,
        full_path: []const u8,
        dest_relative_path: []const u8,
        file_size: u64,
        worker_pool: *worker.WorkerPool,
        progress_tracker: *progress.ProgressTracker,
    ) !void {
        progress_tracker.addTotalFile();
        progress_tracker.addTotalBytes(file_size);

        // The worker pool frees both paths.
        const source_path = try self.allocator.dupe(u8, full_path);
        errdefer self.allocator.free(source_path);
        const dest_path = try std.fs.path.join(self.allocator, &[_][]const u8{ self.dest_base, dest_relative_path });
        errdefer self.allocator.free(dest_path);

        if (!self.dry_run) try self.ensureParent(dest_path, full_path);

        try worker_pool.submitJob(.{
            .source_path = source_path,
            .dest_path = dest_path,
            .operation = if (self.is_encrypt) .encrypt else .decrypt,
            .file_size = file_size,
        });
    }

    fn ensureParent(self: *DirectoryScanContext, dest_path: []const u8, full_path: []const u8) !void {
        const dest_dir = std.fs.path.dirname(dest_path) orelse return;
        utils.ensureDirectory(dest_dir, self.io) catch |err| {
            std.debug.print("\n[ERROR] Failed to create destination directory: {s}\n", .{dest_dir});
            std.debug.print("        For file: {s}\n", .{full_path});
            std.debug.print("        Reason: {}\n", .{err});
            if (self.encrypt_filenames and !self.is_encrypt) {
                std.debug.print("        Suggestion: Filename may be corrupted or encrypted with a different key\n", .{});
            }
            return err;
        };
    }
};

/// The dry run of one file: the source must exist, nothing else is touched.
fn dryRunSingleFile(source_path: []const u8, verb: []const u8, io: std.Io) !void {
    _ = try std.Io.Dir.statFile(.cwd(), io, source_path, .{});
    std.debug.print("[DRY RUN] Would {s} 1 file...\n", .{verb});
}

fn cmdProcess(args: []const []const u8, allocator: std.mem.Allocator, is_encrypt: bool, io: std.Io, environ_map: *const std.process.Environ.Map) !void {
    const op_name = if (is_encrypt) "encrypt" else "decrypt";
    const op_name_cap = if (is_encrypt) "Encrypting" else "Decrypting";
    const op_complete = if (is_encrypt) "Encryption" else "Decryption";

    const parsed = try parseOptions(args, allocator, io, environ_map);
    defer allocator.free(parsed.positional);
    var opts = parsed.options;
    defer {
        for (opts.exclude_patterns.items) |pattern| {
            allocator.free(pattern);
        }
        opts.exclude_patterns.deinit(allocator);
    }

    if (parsed.positional.len < 1) {
        std.debug.print("Error: Missing required arguments\n", .{});
        std.debug.print("Usage: turbocrypt {s} [--key <key-file>] <source> [destination] [options]\n", .{op_name});
        return error.InvalidArguments;
    }

    const source_path = parsed.positional[0];

    const is_dir = utils.isDirectory(source_path, io) catch false;

    var dest_path_buf: ?[]u8 = null;
    defer if (dest_path_buf) |buf| allocator.free(buf);

    const dest_path = if (parsed.positional.len >= 2)
        parsed.positional[1]
    else if (opts.in_place) blk: {
        if (opts.enc_suffix) {
            // The suffix goes on the files, not on the directory.
            if (is_dir) {
                break :blk source_path;
            }
            const transformed = try applyEncSuffix(allocator, source_path, is_encrypt);
            if (transformed) |t| {
                dest_path_buf = t;
                break :blk dest_path_buf.?;
            } else {
                std.debug.print("Error: Source file must have .enc suffix when using --enc-suffix\n", .{});
                return error.InvalidArguments;
            }
        } else {
            break :blk source_path;
        }
    } else {
        std.debug.print("Error: Destination path required (or use --in-place)\n", .{});
        return error.InvalidArguments;
    };

    const relation = try utils.pathRelation(source_path, dest_path, allocator, io);
    if (relation == .same and !opts.in_place) {
        std.debug.print("Error: Source and destination must differ unless --in-place is used\n", .{});
        return error.InvalidArguments;
    }
    if (is_dir and relation == .descendant) {
        std.debug.print("Error: Destination directory must not be inside the source directory\n", .{});
        return error.InvalidArguments;
    }

    const key = keyloader.loadKey(allocator, opts.key, opts.password, io, environ_map) catch |err| {
        return keyloader.explainLoadError(allocator, err, opts.key, environ_map);
    };

    const derived_keys = crypto.deriveKeys(key, opts.context);

    if (is_dir) {
        std.debug.print("{s} directory: {s} -> {s}\n", .{ op_name_cap, source_path, dest_path });

        if (!opts.dry_run) try utils.ensureDirectory(dest_path, io);

        const thread_count = try getThreadCount(opts);

        // In place, the walk must end before any file changes, or it could meet its own output.
        if (opts.in_place) {
            std.debug.print("Scanning files...\n", .{});

            var scan_ctx = DirectoryScanContext{
                .source_base = source_path,
                .dest_base = dest_path,
                .allocator = allocator,
                .enc_suffix = opts.enc_suffix,
                .is_encrypt = is_encrypt,
                .encrypt_filenames = opts.encrypt_filenames,
                .key = derived_keys.filename_key,
                .exclude_patterns = opts.exclude_patterns,
                .ignore_symlinks = opts.ignore_symlinks,
                .dry_run = opts.dry_run,
                .io = io,
                .mode = .{ .scan_only = .{} },
            };
            defer scan_ctx.mode.scan_only.deinit(allocator);

            utils.walkDirectory(source_path, DirectoryScanContext.callback, &scan_ctx, allocator, opts.ignore_symlinks, io) catch |err| {
                std.debug.print("\n[FATAL] Directory scanning failed\n", .{});
                return err;
            };

            const scanned = &scan_ctx.mode.scan_only;
            if (opts.dry_run) {
                std.debug.print("[DRY RUN] Would process {d} files...\n", .{scanned.files.items.len});
            } else {
                std.debug.print("{s} {d} files...\n", .{ op_name_cap, scanned.files.items.len });
            }

            var tracker = progress.ProgressTracker.init(scanned.files.items.len, scanned.total_bytes, io);
            var pool = try worker.WorkerPool.init(allocator, thread_count, derived_keys, &tracker, false, opts.dry_run, io);
            defer pool.deinit();

            try tracker.startDisplay();
            defer tracker.stopDisplay();

            for (scanned.files.items) |file| {
                const source_path_dup = try allocator.dupe(u8, file.source_path);
                errdefer allocator.free(source_path_dup);
                const dest_path_dup = try allocator.dupe(u8, file.dest_path);
                errdefer allocator.free(dest_path_dup);

                try pool.submitJob(.{
                    .source_path = source_path_dup,
                    .dest_path = dest_path_dup,
                    .operation = if (is_encrypt) .encrypt else .decrypt,
                    .file_size = file.size,
                    .delete_source = opts.enc_suffix,
                });
            }

            try pool.waitAll();
            tracker.displayFinal();
            if (pool.hadErrors()) return error.FileProcessingFailed;
        } else {
            if (opts.dry_run) {
                std.debug.print("[DRY RUN] Scanning files...\n", .{});
            } else {
                std.debug.print("Scanning and {s}...\n", .{if (is_encrypt) "encrypting" else "decrypting"});
            }

            var tracker = progress.ProgressTracker.init(0, 0, io);
            var pool = try worker.WorkerPool.init(allocator, thread_count, derived_keys, &tracker, false, opts.dry_run, io);
            defer pool.deinit();

            try tracker.startDisplay();
            defer tracker.stopDisplay();

            // The workers run while the scan goes on.
            try pool.start();

            var ctx = DirectoryScanContext{
                .source_base = source_path,
                .dest_base = dest_path,
                .allocator = allocator,
                .is_encrypt = is_encrypt,
                .enc_suffix = opts.enc_suffix,
                .encrypt_filenames = opts.encrypt_filenames,
                .key = derived_keys.filename_key,
                .exclude_patterns = opts.exclude_patterns,
                .ignore_symlinks = opts.ignore_symlinks,
                .dry_run = opts.dry_run,
                .io = io,
                .mode = .{ .scan_and_process = .{
                    .worker_pool = &pool,
                    .progress_tracker = &tracker,
                } },
            };

            utils.walkDirectory(source_path, DirectoryScanContext.callback, &ctx, allocator, opts.ignore_symlinks, io) catch |err| {
                tracker.stopDisplay();
                pool.finish();
                std.debug.print("\n[FATAL] Directory scanning failed\n", .{});
                return err;
            };

            pool.finish();
            tracker.displayFinal();
            if (pool.hadErrors()) return error.FileProcessingFailed;
        }
    } else {
        if (utils.matchesExcludePattern(source_path, opts.exclude_patterns)) {
            std.debug.print("Skipping excluded file: {s}\n", .{source_path});
            return;
        }

        std.debug.print("{s} file: {s} -> {s}\n", .{ op_name_cap, source_path, dest_path });

        if (opts.dry_run) return dryRunSingleFile(source_path, "process", io);

        if (std.fs.path.dirname(dest_path)) |dest_dir| {
            try utils.ensureDirectory(dest_dir, io);
        }

        if (is_encrypt) {
            processor.encryptFile(source_path, dest_path, derived_keys, allocator, io) catch |err| {
                std.debug.print("\n[ERROR] Encryption failed\n", .{});
                std.debug.print("        File: {s}\n", .{source_path});
                worker.printErrorDetails(err, true);
                return err;
            };
        } else {
            processor.decryptFile(source_path, dest_path, derived_keys, allocator, io) catch |err| {
                std.debug.print("\n[ERROR] Decryption failed\n", .{});
                std.debug.print("        File: {s}\n", .{source_path});
                worker.printErrorDetails(err, false);
                return err;
            };
        }

        // A destination derived by the suffix change replaces the source.
        if (dest_path_buf != null) {
            try std.Io.Dir.deleteFile(.cwd(), io, source_path);
        }
        std.debug.print("{s} complete!\n", .{op_complete});
    }
}

fn cmdEncrypt(args: []const []const u8, allocator: std.mem.Allocator, io: std.Io, environ_map: *const std.process.Environ.Map) !void {
    try cmdProcess(args, allocator, true, io, environ_map);
}

fn cmdDecrypt(args: []const []const u8, allocator: std.mem.Allocator, io: std.Io, environ_map: *const std.process.Environ.Map) !void {
    try cmdProcess(args, allocator, false, io, environ_map);
}

fn cmdVerify(args: []const []const u8, allocator: std.mem.Allocator, io: std.Io, environ_map: *const std.process.Environ.Map) !void {
    const parsed = try parseOptions(args, allocator, io, environ_map);
    defer allocator.free(parsed.positional);
    var opts = parsed.options;
    defer {
        for (opts.exclude_patterns.items) |pattern| {
            allocator.free(pattern);
        }
        opts.exclude_patterns.deinit(allocator);
    }

    if (parsed.positional.len < 1) {
        std.debug.print("Error: Missing required argument\n", .{});
        std.debug.print("Usage: turbocrypt verify [--key <key-file>] <source> [options]\n", .{});
        return error.InvalidArguments;
    }

    const source_path = parsed.positional[0];

    const key = keyloader.loadKey(allocator, opts.key, opts.password, io, environ_map) catch |err| {
        return keyloader.explainLoadError(allocator, err, opts.key, environ_map);
    };

    const derived_keys = crypto.deriveKeys(key, opts.context);

    const is_dir = utils.isDirectory(source_path, io) catch false;

    if (is_dir) {
        std.debug.print("Verifying directory: {s}\n", .{source_path});

        const thread_count = try getThreadCount(opts);

        // The scan runs first so the display shows the file count from the start.
        std.debug.print("Scanning files...\n", .{});

        var scan_ctx = DirectoryScanContext{
            .source_base = source_path,
            .dest_base = source_path, // Not used for verify
            .allocator = allocator,
            .enc_suffix = false, // Verify files with or without the suffix
            .is_encrypt = false, // Not used for verify
            .encrypt_filenames = false,
            .key = derived_keys.filename_key,
            .exclude_patterns = opts.exclude_patterns,
            .ignore_symlinks = opts.ignore_symlinks,
            .dry_run = opts.dry_run,
            .io = io,
            .mode = .{ .scan_only = .{} },
        };
        defer scan_ctx.mode.scan_only.deinit(allocator);

        utils.walkDirectory(source_path, DirectoryScanContext.callback, &scan_ctx, allocator, opts.ignore_symlinks, io) catch |err| {
            std.debug.print("\n[FATAL] Directory scanning failed\n", .{});
            return err;
        };

        const scanned = &scan_ctx.mode.scan_only;
        if (opts.dry_run) {
            std.debug.print("[DRY RUN] Would verify {d} files...\n", .{scanned.files.items.len});
        } else {
            std.debug.print("Verifying {d} files...\n", .{scanned.files.items.len});
        }

        var tracker = progress.ProgressTracker.init(scanned.files.items.len, scanned.total_bytes, io);
        var pool = try worker.WorkerPool.init(allocator, thread_count, derived_keys, &tracker, opts.quick, opts.dry_run, io);
        defer pool.deinit();

        try tracker.startDisplay();
        defer tracker.stopDisplay();

        for (scanned.files.items) |file| {
            const source_path_dup = try allocator.dupe(u8, file.source_path);

            const job = worker.FileJob{
                .source_path = source_path_dup,
                .dest_path = null,
                .operation = .verify,
                .file_size = file.size,
            };

            try pool.submitJob(job);
        }

        try pool.waitAll();
        tracker.displayFinal();

        if (pool.hadErrors()) {
            std.debug.print("\nVerification completed with errors. Some files failed verification.\n", .{});
            std.process.exit(1);
        } else {
            std.debug.print("\nAll files verified successfully!\n", .{});
        }
    } else {
        if (utils.matchesExcludePattern(source_path, opts.exclude_patterns)) {
            std.debug.print("Skipping excluded file: {s}\n", .{source_path});
            return;
        }

        std.debug.print("Verifying file: {s}\n", .{source_path});
        if (opts.dry_run) return dryRunSingleFile(source_path, "verify", io);

        processor.verifyFile(source_path, derived_keys, allocator, opts.quick, io) catch |err| {
            std.debug.print("\n[VERIFY FAILED] {s}\n", .{source_path});
            worker.printErrorDetails(err, false);
            return err;
        };

        std.debug.print("File verified successfully!\n", .{});
    }
}

const ListContext = struct {
    allocator: std.mem.Allocator,
    file_paths: std.ArrayList([]const u8),
    file_sizes: std.ArrayList(u64),
    total_bytes: u64,
    total_files: u64,
    decrypt_filenames: bool,
    filename_key: [16]u8,
    exclude_patterns: std.ArrayList([]const u8),
    io: std.Io,

    fn callback(
        relative_path: []const u8,
        full_path: []const u8,
        is_directory: bool,
        context: *anyopaque,
    ) !void {
        const self: *ListContext = @ptrCast(@alignCast(context));

        if (is_directory) return;

        if (utils.matchesExcludePattern(relative_path, self.exclude_patterns)) {
            return;
        }

        const stat = try std.Io.Dir.statFile(.cwd(), self.io, full_path, .{});
        const file_size = stat.size;

        const path_copy = try self.allocator.dupe(u8, relative_path);
        try self.file_paths.append(self.allocator, path_copy);
        try self.file_sizes.append(self.allocator, file_size);

        self.total_bytes += file_size;
        self.total_files += 1;
    }
};

fn cmdList(args: []const []const u8, allocator: std.mem.Allocator, io: std.Io, environ_map: *const std.process.Environ.Map) !void {
    const parsed = try parseOptions(args, allocator, io, environ_map);
    defer allocator.free(parsed.positional);
    var opts = parsed.options;
    defer {
        for (opts.exclude_patterns.items) |pattern| {
            allocator.free(pattern);
        }
        opts.exclude_patterns.deinit(allocator);
    }

    if (parsed.positional.len < 1) {
        std.debug.print("Error: Missing required argument\n", .{});
        std.debug.print("Usage: turbocrypt list [--key <key-file>] [--encrypted-filenames] <directory> [options]\n", .{});
        return error.InvalidArguments;
    }

    const source_path = parsed.positional[0];

    const is_dir = utils.isDirectory(source_path, io) catch {
        std.debug.print("Error: Path is not a directory: {s}\n", .{source_path});
        return error.InvalidPath;
    };

    if (!is_dir) {
        std.debug.print("Error: Path is not a directory: {s}\n", .{source_path});
        std.debug.print("Usage: turbocrypt list works only with directories\n", .{});
        return error.InvalidPath;
    }

    // Only encrypted names need the key.
    var filename_key: [16]u8 = undefined;
    if (opts.encrypt_filenames) {
        const key = keyloader.loadKey(allocator, opts.key, opts.password, io, environ_map) catch |err| {
            return keyloader.explainLoadError(allocator, err, opts.key, environ_map);
        };

        const derived_keys = crypto.deriveKeys(key, opts.context);
        filename_key = derived_keys.filename_key;
    }

    std.debug.print("Listing contents: {s}\n\n", .{source_path});

    var list_ctx = ListContext{
        .allocator = allocator,
        .file_paths = .empty,
        .file_sizes = .empty,
        .total_bytes = 0,
        .total_files = 0,
        .decrypt_filenames = opts.encrypt_filenames,
        .filename_key = filename_key,
        .exclude_patterns = opts.exclude_patterns,
        .io = io,
    };
    defer {
        for (list_ctx.file_paths.items) |path| allocator.free(path);
        list_ctx.file_paths.deinit(allocator);
        list_ctx.file_sizes.deinit(allocator);
    }

    utils.walkDirectory(source_path, ListContext.callback, &list_ctx, allocator, opts.ignore_symlinks, io) catch |err| {
        std.debug.print("Error: Failed to walk directory\n", .{});
        return err;
    };

    if (list_ctx.total_files == 0) {
        std.debug.print("Directory is empty (or all files excluded by patterns)\n", .{});
        return;
    }

    for (list_ctx.file_paths.items, list_ctx.file_sizes.items) |file_path, file_size| {
        const display_path = if (opts.encrypt_filenames) blk: {
            const decrypted = filename_crypto.decryptPathForFilesystem(allocator, file_path, filename_key, std.fs.path.sep) catch |err| {
                std.debug.print("  {s} ({s}) [decrypt error: {}]\n", .{ file_path, formatSize(file_size), err });
                continue;
            };
            break :blk decrypted;
        } else try allocator.dupe(u8, file_path);
        defer allocator.free(display_path);

        std.debug.print("  {s} ({s})\n", .{ display_path, formatSize(file_size) });
    }

    std.debug.print("\nTotal: {d} file{s}, {s}\n", .{
        list_ctx.total_files,
        if (list_ctx.total_files == 1) "" else "s",
        formatSize(list_ctx.total_bytes),
    });
}

/// The result lives in a thread-local buffer, so the next call overwrites it.
fn formatSize(bytes: u64) []const u8 {
    const kb: f64 = 1024.0;
    const mb: f64 = kb * 1024.0;
    const gb: f64 = mb * 1024.0;
    const tb: f64 = gb * 1024.0;

    const bytes_f: f64 = @floatFromInt(bytes);

    const size_buf = struct {
        threadlocal var buf: [32]u8 = undefined;
    };

    if (bytes_f >= tb) {
        return std.fmt.bufPrint(&size_buf.buf, "{d:.1} TB", .{bytes_f / tb}) catch "?.? TB";
    } else if (bytes_f >= gb) {
        return std.fmt.bufPrint(&size_buf.buf, "{d:.1} GB", .{bytes_f / gb}) catch "?.? GB";
    } else if (bytes_f >= mb) {
        return std.fmt.bufPrint(&size_buf.buf, "{d:.1} MB", .{bytes_f / mb}) catch "?.? MB";
    } else if (bytes_f >= kb) {
        return std.fmt.bufPrint(&size_buf.buf, "{d:.1} KB", .{bytes_f / kb}) catch "?.? KB";
    } else {
        return std.fmt.bufPrint(&size_buf.buf, "{d} bytes", .{bytes}) catch "? bytes";
    }
}

fn cmdChangePassword(args: []const []const u8, allocator: std.mem.Allocator, io: std.Io, environ_map: *const std.process.Environ.Map) !void {
    const parsed = try parseOptions(args, allocator, io, environ_map);
    defer allocator.free(parsed.positional);
    var opts = parsed.options;
    defer {
        for (opts.exclude_patterns.items) |pattern| {
            allocator.free(pattern);
        }
        opts.exclude_patterns.deinit(allocator);
    }

    if (parsed.positional.len < 1) {
        std.debug.print("Error: Missing key file path\n", .{});
        std.debug.print("Usage: turbocrypt change-password [--remove-password] <key-file>\n", .{});
        return error.InvalidArguments;
    }

    const key_path = parsed.positional[0];
    const remove_password = opts.remove_password;

    // The file size tells the format.
    const file_size = blk: {
        const file = try std.Io.Dir.openFile(.cwd(), io, key_path, .{});
        defer file.close(io);
        break :blk (try file.stat(io)).size;
    };

    if (file_size != keygen.plain_key_file_size and file_size != keygen.protected_key_file_size) {
        std.debug.print("Error: Invalid key file size (expected {d} or {d} bytes, got {d})\n", .{ keygen.plain_key_file_size, keygen.protected_key_file_size, file_size });
        return error.InvalidKeyFile;
    }

    const is_protected = file_size == keygen.protected_key_file_size;

    var actual_key: [16]u8 = undefined;

    if (is_protected) {
        std.debug.print("Current key is password-protected\n", .{});

        const old_password_buf = try prompt.promptPassword(allocator, "Enter current password", false, io);
        defer {
            std.crypto.secureZero(u8, old_password_buf);
            allocator.free(old_password_buf);
        }

        actual_key = keygen.readKeyFile(key_path, old_password_buf, io) catch |err| {
            if (err == error.InvalidPassword) {
                std.debug.print("Error: Invalid current password\n", .{});
                return error.InvalidPassword;
            }
            return err;
        };

        if (remove_password) {
            try keygen.writeKeyFile(key_path, actual_key, null, allocator, io);
            std.debug.print("Password protection removed from key file: {s}\n", .{key_path});
            std.debug.print("WARNING: The key is now stored in plain text. Keep it secure!\n", .{});
            return;
        } else {
            const new_password_buf = try prompt.promptPassword(allocator, "Enter new password", true, io);
            defer {
                std.crypto.secureZero(u8, new_password_buf);
                allocator.free(new_password_buf);
            }

            try keygen.writeKeyFile(key_path, actual_key, new_password_buf, allocator, io);
            std.debug.print("Password changed successfully for key file: {s}\n", .{key_path});
        }
    } else {
        if (remove_password) {
            std.debug.print("Error: Key is not password-protected\n", .{});
            return error.InvalidArguments;
        }

        std.debug.print("Current key is not password-protected\n", .{});

        actual_key = try keygen.readKeyFile(key_path, null, io);

        const new_password_buf = try prompt.promptPassword(allocator, "Enter new password", true, io);
        defer {
            std.crypto.secureZero(u8, new_password_buf);
            allocator.free(new_password_buf);
        }

        try keygen.writeKeyFile(key_path, actual_key, new_password_buf, allocator, io);
        std.debug.print("Password protection added to key file: {s}\n", .{key_path});
    }
}

const PatternOp = enum { add, remove };

fn modifyExcludePattern(
    cfg: *config_mod.Config,
    pattern: []const u8,
    op: PatternOp,
    allocator: std.mem.Allocator,
) !void {
    switch (op) {
        .add => {
            for (cfg.exclude_patterns) |existing| {
                if (std.mem.eql(u8, existing, pattern)) {
                    std.debug.print("Pattern '{s}' already in exclude list\n", .{pattern});
                    return;
                }
            }

            var new_patterns = try allocator.alloc([]const u8, cfg.exclude_patterns.len + 1);
            var duped_count: usize = 0;
            errdefer {
                for (new_patterns[0..duped_count]) |p| allocator.free(p);
                allocator.free(new_patterns);
            }
            for (cfg.exclude_patterns, 0..) |old_pattern, i| {
                new_patterns[i] = try allocator.dupe(u8, old_pattern);
                duped_count += 1;
            }
            new_patterns[cfg.exclude_patterns.len] = try allocator.dupe(u8, pattern);

            for (cfg.exclude_patterns) |old_pattern| {
                allocator.free(old_pattern);
            }
            if (cfg.exclude_patterns.len > 0) {
                allocator.free(cfg.exclude_patterns);
            }

            cfg.exclude_patterns = new_patterns;
            std.debug.print("Added exclude pattern: {s}\n", .{pattern});
        },
        .remove => {
            var found_idx: ?usize = null;
            for (cfg.exclude_patterns, 0..) |existing, i| {
                if (std.mem.eql(u8, existing, pattern)) {
                    found_idx = i;
                    break;
                }
            }

            if (found_idx == null) {
                std.debug.print("Pattern '{s}' not found in exclude list\n", .{pattern});
                return;
            }

            if (cfg.exclude_patterns.len == 1) {
                allocator.free(cfg.exclude_patterns[0]);
                allocator.free(cfg.exclude_patterns);
                cfg.exclude_patterns = &[_][]const u8{};
            } else {
                var new_patterns = try allocator.alloc([]const u8, cfg.exclude_patterns.len - 1);
                var new_idx: usize = 0;
                for (cfg.exclude_patterns, 0..) |old_pattern, i| {
                    if (i == found_idx.?) {
                        allocator.free(old_pattern);
                        continue;
                    }
                    // The strings move to the new list.
                    new_patterns[new_idx] = old_pattern;
                    new_idx += 1;
                }

                allocator.free(cfg.exclude_patterns);
                cfg.exclude_patterns = new_patterns;
            }

            std.debug.print("Removed exclude pattern: {s}\n", .{pattern});
        },
    }
}

fn cmdConfig(args: []const []const u8, allocator: std.mem.Allocator, io: std.Io, environ_map: *const std.process.Environ.Map) !void {
    if (args.len < 1) {
        std.debug.print("Error: Missing config subcommand\n", .{});
        std.debug.print("Usage: turbocrypt config <set-key|set-threads|set-buffer-size|add-exclude|remove-exclude|set-ignore-symlinks|set-encrypted-filenames|show>\n", .{});
        return error.InvalidArguments;
    }

    const subcommand = args[0];

    if (std.mem.eql(u8, subcommand, "set-key")) {
        if (args.len < 2) {
            std.debug.print("Error: Missing key file path\n", .{});
            std.debug.print("Usage: turbocrypt config set-key <key-file>\n", .{});
            return error.InvalidArguments;
        }

        const key_path = args[1];

        // One extra byte lets the size check catch an oversized file.
        const max_key_size = keygen.protected_key_file_size + 1;
        const key_data = std.Io.Dir.readFileAlloc(
            .cwd(),
            io,
            key_path,
            allocator,
            std.Io.Limit.limited(max_key_size),
        ) catch |err| {
            std.debug.print("Error: Cannot read key file '{s}': {}\n", .{ key_path, err });
            return err;
        };
        defer allocator.free(key_data);

        if (key_data.len != keygen.plain_key_file_size and key_data.len != keygen.protected_key_file_size) {
            std.debug.print("Error: Invalid key file size (expected {d} or {d} bytes, got {d})\n", .{ keygen.plain_key_file_size, keygen.protected_key_file_size, key_data.len });
            return error.InvalidKeyFile;
        }

        const is_protected = key_data.len == keygen.protected_key_file_size;

        // Make sure the password opens the key before storing it.
        if (is_protected) {
            if (key_data[0] != @backingInt(keygen.KeyFormat.password_protected)) {
                std.debug.print("Error: Invalid password-protected key format\n", .{});
                return error.InvalidKeyFile;
            }

            const password_buf = try prompt.promptPassword(allocator, "Enter key password (to verify)", false, io);
            defer {
                std.crypto.secureZero(u8, password_buf);
                allocator.free(password_buf);
            }

            var protected_data: [20]u8 = undefined;
            @memcpy(&protected_data, key_data[1..keygen.protected_key_file_size]);
            _ = password.unprotectKey(protected_data, password_buf) catch |err| {
                std.debug.print("Error: Cannot decrypt key (wrong password?): {}\n", .{err});
                return err;
            };

            std.debug.print("Password verified successfully.\n", .{});
        }

        // The config keeps the key in the key file layout.
        var cfg = try loadConfig(allocator, io, environ_map);
        defer cfg.deinit(allocator);

        const new_key = try allocator.dupe(u8, key_data);
        if (cfg.key) |old_key| {
            std.crypto.secureZero(u8, @constCast(old_key));
            allocator.free(old_key);
        }
        cfg.key = new_key;
        try saveConfig(cfg, allocator, io, environ_map);

        const config_path = try keyloader.getConfigFilePath(allocator, environ_map);
        defer allocator.free(config_path);

        std.debug.print("Default key has been stored in config\n", .{});
        std.debug.print("Config file location: {s}\n", .{config_path});
        std.debug.print("Config file permissions: 600 (owner read/write only)\n", .{});
        if (is_protected) {
            std.debug.print("\nIMPORTANT: The key is stored password-protected in the config file.\n", .{});
            std.debug.print("           You will need to use --password flag when using this key.\n", .{});
            std.debug.print("           You can delete the original key file if you wish.\n", .{});
            std.debug.print("\nYou can now use encrypt/decrypt with password:\n", .{});
            std.debug.print("  turbocrypt encrypt source/ dest/\n", .{});
        } else {
            std.debug.print("\nIMPORTANT: The key is now stored directly in the config file.\n", .{});
            std.debug.print("           You can delete the original key file if you wish.\n", .{});
            std.debug.print("\nYou can now use encrypt/decrypt without specifying --key:\n", .{});
            std.debug.print("  turbocrypt encrypt source/ dest/\n", .{});
        }
    } else if (std.mem.eql(u8, subcommand, "set-threads")) {
        if (args.len < 2) {
            std.debug.print("Error: Missing thread count\n", .{});
            std.debug.print("Usage: turbocrypt config set-threads <n>\n", .{});
            return error.InvalidArguments;
        }

        const threads = std.fmt.parseUnsigned(u32, args[1], 10) catch {
            std.debug.print("Error: Invalid thread count '{s}'\n", .{args[1]});
            return error.InvalidArguments;
        };

        if (threads == 0 or threads > 64) {
            std.debug.print("Error: Thread count must be between 1 and 64\n", .{});
            return error.InvalidArguments;
        }

        var cfg = try loadConfig(allocator, io, environ_map);
        defer cfg.deinit(allocator);

        cfg.threads = threads;
        try saveConfig(cfg, allocator, io, environ_map);

        std.debug.print("Default thread count set to: {d}\n", .{threads});
    } else if (std.mem.eql(u8, subcommand, "set-buffer-size")) {
        if (args.len < 2) {
            std.debug.print("Error: Missing buffer size\n", .{});
            std.debug.print("Usage: turbocrypt config set-buffer-size <size>\n", .{});
            return error.InvalidArguments;
        }

        const buffer_size = std.fmt.parseUnsigned(usize, args[1], 10) catch {
            std.debug.print("Error: Invalid buffer size '{s}'\n", .{args[1]});
            return error.InvalidArguments;
        };

        if (buffer_size < 4096) {
            std.debug.print("Error: Buffer size must be at least 4096 bytes\n", .{});
            return error.InvalidArguments;
        }

        var cfg = try loadConfig(allocator, io, environ_map);
        defer cfg.deinit(allocator);

        cfg.buffer_size = buffer_size;
        try saveConfig(cfg, allocator, io, environ_map);

        std.debug.print("Default buffer size set to: {d} bytes\n", .{buffer_size});
    } else if (std.mem.eql(u8, subcommand, "add-exclude")) {
        if (args.len < 2) {
            std.debug.print("Error: Missing exclude pattern\n", .{});
            std.debug.print("Usage: turbocrypt config add-exclude <pattern>\n", .{});
            return error.InvalidArguments;
        }

        var cfg = try loadConfig(allocator, io, environ_map);
        defer cfg.deinit(allocator);

        try modifyExcludePattern(&cfg, args[1], .add, allocator);
        try saveConfig(cfg, allocator, io, environ_map);
    } else if (std.mem.eql(u8, subcommand, "remove-exclude")) {
        if (args.len < 2) {
            std.debug.print("Error: Missing exclude pattern\n", .{});
            std.debug.print("Usage: turbocrypt config remove-exclude <pattern>\n", .{});
            return error.InvalidArguments;
        }

        var cfg = try loadConfig(allocator, io, environ_map);
        defer cfg.deinit(allocator);

        try modifyExcludePattern(&cfg, args[1], .remove, allocator);
        try saveConfig(cfg, allocator, io, environ_map);
    } else if (std.mem.eql(u8, subcommand, "set-ignore-symlinks")) {
        if (args.len < 2) {
            std.debug.print("Error: Missing value\n", .{});
            std.debug.print("Usage: turbocrypt config set-ignore-symlinks <true|false>\n", .{});
            return error.InvalidArguments;
        }

        const value_str = args[1];
        const value = if (std.mem.eql(u8, value_str, "true"))
            true
        else if (std.mem.eql(u8, value_str, "false"))
            false
        else {
            std.debug.print("Error: Invalid value '{s}'. Use 'true' or 'false'\n", .{value_str});
            return error.InvalidArguments;
        };

        var cfg = try loadConfig(allocator, io, environ_map);
        defer cfg.deinit(allocator);

        cfg.ignore_symlinks = value;
        try saveConfig(cfg, allocator, io, environ_map);

        std.debug.print("Ignore symlinks set to: {s}\n", .{if (value) "true" else "false"});
    } else if (std.mem.eql(u8, subcommand, "set-encrypted-filenames")) {
        if (args.len < 2) {
            std.debug.print("Error: Missing value\n", .{});
            std.debug.print("Usage: turbocrypt config set-encrypted-filenames <true|false>\n", .{});
            return error.InvalidArguments;
        }

        const value_str = args[1];
        const value = if (std.mem.eql(u8, value_str, "true"))
            true
        else if (std.mem.eql(u8, value_str, "false"))
            false
        else {
            std.debug.print("Error: Invalid value '{s}'. Use 'true' or 'false'\n", .{value_str});
            return error.InvalidArguments;
        };

        var cfg = try loadConfig(allocator, io, environ_map);
        defer cfg.deinit(allocator);

        cfg.encrypted_filenames = value;
        try saveConfig(cfg, allocator, io, environ_map);

        std.debug.print("Encrypt filenames set to: {s}\n", .{if (value) "true" else "false"});
    } else if (std.mem.eql(u8, subcommand, "show")) {
        var cfg = try loadConfig(allocator, io, environ_map);
        defer cfg.deinit(allocator);

        const config_path = try config_mod.getConfigFilePath(allocator, environ_map);
        defer allocator.free(config_path);

        std.debug.print("Current configuration:\n", .{});
        std.debug.print("Config file: {s}\n\n", .{config_path});

        if (cfg.key) |key| {
            const kind = if (key.len == keygen.protected_key_file_size) "password-protected" else "plain";
            std.debug.print("Key: stored in config ({s})\n", .{kind});
        } else {
            std.debug.print("Key: (not set)\n", .{});
        }

        if (cfg.threads) |threads| {
            std.debug.print("Threads: {d}\n", .{threads});
        } else {
            std.debug.print("Threads: (auto - uses CPU count, max 16)\n", .{});
        }

        if (cfg.buffer_size) |size| {
            std.debug.print("Buffer size: {d} bytes\n", .{size});
        } else {
            std.debug.print("Buffer size: (default - 4194304 bytes / 4MB)\n", .{});
        }

        std.debug.print("Exclude patterns: ", .{});
        if (cfg.exclude_patterns.len == 0) {
            std.debug.print("(none)\n", .{});
        } else {
            std.debug.print("\n", .{});
            for (cfg.exclude_patterns) |pattern| {
                std.debug.print("  - {s}\n", .{pattern});
            }
        }

        if (cfg.ignore_symlinks) |ignore| {
            std.debug.print("Ignore symlinks: {s}\n", .{if (ignore) "true" else "false"});
        } else {
            std.debug.print("Ignore symlinks: (default - false)\n", .{});
        }

        if (cfg.encrypted_filenames) |encrypt_names| {
            std.debug.print("Encrypt filenames: {s}\n", .{if (encrypt_names) "true" else "false"});
        } else {
            std.debug.print("Encrypt filenames: (default - false)\n", .{});
        }

        std.debug.print("\nKey resolution priority:\n", .{});
        std.debug.print("  1. --key flag (if provided)\n", .{});
        std.debug.print("  2. {s} environment variable", .{keyloader.env_var_name});
        if (environ_map.get(keyloader.env_var_name)) |env_val| {
            std.debug.print(" (currently: {s})", .{env_val});
        } else {
            std.debug.print(" (not set)", .{});
        }
        std.debug.print("\n  3. Config file\n", .{});
    } else {
        std.debug.print("Error: Unknown config subcommand '{s}'\n", .{subcommand});
        std.debug.print("Usage: turbocrypt config <set-key|set-threads|set-buffer-size|add-exclude|remove-exclude|set-ignore-symlinks|set-encrypted-filenames|show>\n", .{});
        return error.InvalidArguments;
    }
}

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const io = init.io;

    const args = try init.minimal.args.toSlice(init.arena.allocator());

    if (args.len < 2) {
        printUsage();
        return;
    }

    const command = args[1];
    const command_args = args[2..];

    if (std.mem.eql(u8, command, "help") or std.mem.eql(u8, command, "--help") or std.mem.eql(u8, command, "-h")) {
        printUsage();
        return;
    }
    if (std.mem.eql(u8, command, "version") or std.mem.eql(u8, command, "--version") or std.mem.eql(u8, command, "-V")) {
        printVersion();
        return;
    }

    // Fail fast when the system has no secure randomness.
    {
        var dummy: [1]u8 = undefined;
        io.randomSecure(&dummy) catch |err| {
            std.debug.print("FATAL: Secure randomness unavailable: {}\n", .{err});
            std.debug.print("Cannot safely perform cryptographic operations.\n", .{});
            std.process.exit(1);
        };
    }

    if (std.mem.eql(u8, command, "keygen")) {
        cmdKeygen(command_args, allocator, io, init.environ_map) catch {
            std.process.exit(1);
        };
    } else if (std.mem.eql(u8, command, "change-password")) {
        cmdChangePassword(command_args, allocator, io, init.environ_map) catch {
            std.process.exit(1);
        };
    } else if (std.mem.eql(u8, command, "encrypt")) {
        cmdEncrypt(command_args, allocator, io, init.environ_map) catch {
            std.process.exit(1);
        };
    } else if (std.mem.eql(u8, command, "decrypt")) {
        cmdDecrypt(command_args, allocator, io, init.environ_map) catch {
            std.process.exit(1);
        };
    } else if (std.mem.eql(u8, command, "verify")) {
        cmdVerify(command_args, allocator, io, init.environ_map) catch {
            std.process.exit(1);
        };
    } else if (std.mem.eql(u8, command, "list")) {
        cmdList(command_args, allocator, io, init.environ_map) catch {
            std.process.exit(1);
        };
    } else if (std.mem.eql(u8, command, "config")) {
        cmdConfig(command_args, allocator, io, init.environ_map) catch {
            std.process.exit(1);
        };
    } else if (std.mem.eql(u8, command, "git")) {
        git_cmd.run(command_args, allocator, io, init.environ_map) catch {
            std.process.exit(1);
        };
    } else if (std.mem.eql(u8, command, "bench")) {
        bench.run(allocator, io) catch {
            std.process.exit(1);
        };
    } else {
        std.debug.print("Error: Unknown command '{s}'\n\n", .{command});
        printUsage();
        std.process.exit(1);
    }
}

test "directory processing returns an error when a worker fails" {
    const testing = std.testing;
    const allocator = testing.allocator;
    const io = testing.io;
    const root = "tmp/main_worker_failure";
    const source = root ++ "/source";
    const destination = root ++ "/destination";
    const key_path = root ++ "/key";

    std.Io.Dir.deleteTree(.cwd(), io, root) catch {};
    try std.Io.Dir.createDirPath(.cwd(), io, source);
    defer std.Io.Dir.deleteTree(.cwd(), io, root) catch {};
    try std.Io.Dir.writeFile(.cwd(), io, .{ .sub_path = source ++ "/bad.enc", .data = "not ciphertext" });
    try keygen.writeKeyFile(key_path, @splat(7), null, allocator, io);

    var environ_map = try config_mod.testEnviron(allocator, root);
    defer environ_map.deinit();
    const args = [_][]const u8{ "--threads", "1", "--key", key_path, source, destination };
    try testing.expectError(error.FileProcessingFailed, cmdProcess(&args, allocator, false, io, &environ_map));

    const in_place_args = [_][]const u8{ "--in-place", "--threads", "1", "--key", key_path, source };
    try testing.expectError(error.FileProcessingFailed, cmdProcess(&in_place_args, allocator, false, io, &environ_map));
}

test "dry run does not create directory or file destinations" {
    const testing = std.testing;
    const allocator = testing.allocator;
    const io = testing.io;
    const root = "tmp/main_dry_run";
    const source_dir = root ++ "/source";
    const dir_destination = root ++ "/directory-output";
    const file_destination = root ++ "/missing/file.enc";
    const key_path = root ++ "/key";

    std.Io.Dir.deleteTree(.cwd(), io, root) catch {};
    try std.Io.Dir.createDirPath(.cwd(), io, source_dir ++ "/nested");
    defer std.Io.Dir.deleteTree(.cwd(), io, root) catch {};
    try std.Io.Dir.writeFile(.cwd(), io, .{ .sub_path = source_dir ++ "/nested/file", .data = "plain text" });
    try keygen.writeKeyFile(key_path, @splat(8), null, allocator, io);

    var environ_map = try config_mod.testEnviron(allocator, root);
    defer environ_map.deinit();
    const dir_args = [_][]const u8{ "--dry-run", "--threads", "1", "--key", key_path, source_dir, dir_destination };
    try cmdProcess(&dir_args, allocator, true, io, &environ_map);
    try testing.expect(!utils.pathExists(dir_destination, io));

    const file_args = [_][]const u8{ "--dry-run", "--key", key_path, source_dir ++ "/nested/file", file_destination };
    try cmdProcess(&file_args, allocator, true, io, &environ_map);
    try testing.expect(!utils.pathExists(file_destination, io));
    try testing.expect(!utils.pathExists(root ++ "/missing", io));
}

test "dry run does not verify a single file" {
    const testing = std.testing;
    const allocator = testing.allocator;
    const io = testing.io;
    const root = "tmp/main_verify_dry_run";
    const source = root ++ "/not-encrypted";
    const key_path = root ++ "/key";

    std.Io.Dir.deleteTree(.cwd(), io, root) catch {};
    try std.Io.Dir.createDirPath(.cwd(), io, root);
    defer std.Io.Dir.deleteTree(.cwd(), io, root) catch {};
    try std.Io.Dir.writeFile(.cwd(), io, .{ .sub_path = source, .data = "plain text" });
    try keygen.writeKeyFile(key_path, @splat(6), null, allocator, io);

    var environ_map = try config_mod.testEnviron(allocator, root);
    defer environ_map.deinit();
    const args = [_][]const u8{ "--dry-run", "--key", key_path, source };
    try cmdVerify(&args, allocator, io, &environ_map);
}

test "decrypted filenames cannot escape the destination" {
    const testing = std.testing;
    const allocator = testing.allocator;
    const io = testing.io;
    const root = "tmp/main_filename_escape";
    const source = root ++ "/source";
    const destination = root ++ "/destination";
    const plain_path = root ++ "/plain";
    const escaped_path = root ++ "/escaped";
    const key_path = root ++ "/key";
    const key: [16]u8 = @splat(9);
    const derived_keys = crypto.deriveKeys(key, null);

    std.Io.Dir.deleteTree(.cwd(), io, root) catch {};
    try std.Io.Dir.createDirPath(.cwd(), io, source);
    defer std.Io.Dir.deleteTree(.cwd(), io, root) catch {};
    try std.Io.Dir.writeFile(.cwd(), io, .{ .sub_path = plain_path, .data = "secret" });
    try keygen.writeKeyFile(key_path, key, null, allocator, io);

    const planted_name = try filename_crypto.encryptFilename(allocator, "../escaped", derived_keys.filename_key);
    defer allocator.free(planted_name);
    const planted_path = try std.fs.path.join(allocator, &.{ source, planted_name });
    defer allocator.free(planted_path);
    try processor.encryptFile(plain_path, planted_path, derived_keys, allocator, io);

    var environ_map = try config_mod.testEnviron(allocator, root);
    defer environ_map.deinit();
    const args = [_][]const u8{ "--threads", "1", "--encrypted-filenames", "--key", key_path, source, destination };
    try testing.expectError(filename_crypto.StrictError.UnsafeDecryptedFilename, cmdProcess(&args, allocator, false, io, &environ_map));
    try testing.expect(!utils.pathExists(escaped_path, io));
}

test "directory destination cannot be inside the source" {
    const testing = std.testing;
    const allocator = testing.allocator;
    const io = testing.io;
    const root = "tmp/main_destination_overlap";
    const source = root ++ "/source";
    const destination = source ++ "/output";

    std.Io.Dir.deleteTree(.cwd(), io, root) catch {};
    try std.Io.Dir.createDirPath(.cwd(), io, source);
    defer std.Io.Dir.deleteTree(.cwd(), io, root) catch {};
    try std.Io.Dir.writeFile(.cwd(), io, .{ .sub_path = source ++ "/file", .data = "plain" });

    var environ_map = try config_mod.testEnviron(allocator, root);
    defer environ_map.deinit();
    const args = [_][]const u8{ source, destination };
    try testing.expectError(error.InvalidArguments, cmdProcess(&args, allocator, true, io, &environ_map));
    try testing.expect(!utils.pathExists(destination, io));

    const same_args = [_][]const u8{ source, source };
    try testing.expectError(error.InvalidArguments, cmdProcess(&same_args, allocator, true, io, &environ_map));

    const file_path = root ++ "/file";
    try std.Io.Dir.writeFile(.cwd(), io, .{ .sub_path = file_path, .data = "plain" });
    const same_file_args = [_][]const u8{ file_path, file_path };
    try testing.expectError(error.InvalidArguments, cmdProcess(&same_file_args, allocator, true, io, &environ_map));

    const source_link = root ++ "/source-link";
    std.Io.Dir.symLink(.cwd(), io, "source", source_link, .{ .is_directory = true }) catch |err| {
        if (err == error.Unexpected or err == error.AccessDenied) return;
        return err;
    };
    const linked_destination = source_link ++ "/output";
    const linked_args = [_][]const u8{ source, linked_destination };
    try testing.expectError(error.InvalidArguments, cmdProcess(&linked_args, allocator, true, io, &environ_map));
    try testing.expect(!utils.pathExists(linked_destination, io));
}

// Pull in the tests of the imported modules.
test {
    _ = @import("keygen.zig");
    _ = @import("keyloader.zig");
    _ = @import("config.zig");
    _ = @import("crypto.zig");
    _ = @import("processor.zig");
    _ = @import("utils.zig");
    _ = @import("worker.zig");
    _ = @import("progress.zig");
    _ = @import("filename_crypto.zig");
    _ = @import("git/manifest.zig");
    _ = @import("git/repo.zig");
    _ = @import("git/sync.zig");
    _ = @import("git/hooks.zig");
    _ = @import("git/cmd.zig");
    _ = @import("git/integration_test.zig");
}
