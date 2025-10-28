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
    \\  turbocrypt bench
    \\      Run performance benchmarks
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
    \\
;

fn printUsage() void {
    std.debug.print("{s}\n", .{usage_text});
}

/// Handle directory creation with optional filename encryption
fn handleDirectory(
    relative_path: []const u8,
    dest_base: []const u8,
    encrypt_filenames: bool,
    is_encrypt: bool,
    key: [16]u8,
    allocator: std.mem.Allocator,
) !void {
    var dest_relative_path = relative_path;
    var encrypted_path: ?[]u8 = null;
    defer if (encrypted_path) |p| allocator.free(p);

    if (encrypt_filenames) {
        encrypted_path = (if (is_encrypt)
            filename_crypto.encryptPath(allocator, relative_path, key)
        else
            filename_crypto.decryptPath(allocator, relative_path, key)) catch |err| {
            std.debug.print("\n[ERROR] Failed to {s} directory name: {s}\n", .{
                if (is_encrypt) "encrypt" else "decrypt",
                relative_path,
            });
            std.debug.print("        Reason: {}\n", .{err});
            if (err == filename_crypto.FilenameError.EncryptedFilenameTooLong) {
                std.debug.print("        Suggestion: Directory name is too long. Encrypted names must fit within 255 bytes.\n", .{});
                std.debug.print("                   Consider shortening the directory name (max ~205 bytes for encryption).\n", .{});
            } else if (!is_encrypt) {
                std.debug.print("        Suggestion: Ensure the directory was encrypted with --encrypted-filenames using the same key\n", .{});
            }
            return err;
        };
        dest_relative_path = encrypted_path.?;
    }

    const dest_dir = try std.fs.path.join(allocator, &[_][]const u8{ dest_base, dest_relative_path });
    defer allocator.free(dest_dir);
    utils.ensureDirectory(dest_dir) catch |err| {
        std.debug.print("\n[ERROR] Failed to create directory: {s}\n", .{dest_dir});
        std.debug.print("        Reason: {}\n", .{err});
        if (encrypt_filenames and !is_encrypt) {
            std.debug.print("        Suggestion: Directory name may be corrupted or encrypted with a different key\n", .{});
        }
        return err;
    };
}

/// Command-line options for encrypt/decrypt operations
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
    exclude_patterns: std.ArrayList([]const u8) = std.ArrayList([]const u8){},
};

/// Constant for the .enc file extension suffix
const enc_suffix = ".enc";

/// Check if a path has the .enc suffix
fn hasEncSuffix(path: []const u8) bool {
    return std.mem.endsWith(u8, path, enc_suffix);
}

/// Apply .enc suffix transformation based on operation type
/// For encryption: adds ".enc" suffix
/// For decryption: removes ".enc" suffix (if present)
/// Returns owned slice that caller must free, or null if no transformation needed
fn applyEncSuffix(
    allocator: std.mem.Allocator,
    path: []const u8,
    is_encrypt: bool,
) !?[]u8 {
    if (is_encrypt) {
        // Encrypting: add ".enc" suffix
        return try std.mem.concat(allocator, u8, &[_][]const u8{ path, enc_suffix });
    } else {
        // Decrypting: remove ".enc" suffix if present
        if (hasEncSuffix(path)) {
            return try allocator.dupe(u8, path[0 .. path.len - enc_suffix.len]);
        }
        // No suffix to remove, return null to indicate no transformation
        return null;
    }
}

/// Parse command-line options from arguments
/// Returns the parsed options and the remaining positional arguments
fn parseOptions(args: []const []const u8, allocator: std.mem.Allocator) !struct { options: Options, positional: []const []const u8 } {
    var opts = Options{};
    var positional = std.ArrayList([]const u8){};
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
            opts.threads = std.fmt.parseInt(u32, value, 10) catch {
                std.debug.print("Error: Invalid thread count '{s}'\n", .{value});
                return error.InvalidArguments;
            };
        } else if (std.mem.eql(u8, arg, "--buffer-size")) {
            if (i + 1 >= args.len) {
                std.debug.print("Error: --buffer-size requires a value\n", .{});
                return error.InvalidArguments;
            }
            i += 1;
            const value = args[i];
            opts.buffer_size = std.fmt.parseInt(usize, value, 10) catch {
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

    // Load config and apply defaults for unspecified options
    var cfg = config_mod.load(allocator) catch |err| blk: {
        // If config loading fails, that's ok - just don't apply defaults
        if (err != error.FileNotFound) {
            std.debug.print("Warning: Failed to load config file: {}\n", .{err});
        }
        break :blk config_mod.Config{};
    };
    defer cfg.deinit(allocator);

    // Apply config defaults if options not specified on CLI
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

    // Merge config exclude patterns with CLI patterns (CLI patterns have higher priority)
    // Add config patterns first, then CLI patterns
    if (cfg.exclude_patterns.len > 0 and opts.exclude_patterns.items.len == 0) {
        // Only use config patterns if no CLI patterns specified
        for (cfg.exclude_patterns) |pattern| {
            const pattern_copy = try allocator.dupe(u8, pattern);
            try opts.exclude_patterns.append(allocator, pattern_copy);
        }
    }

    // Validate incompatible flag combinations
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

/// Prompt for password if needed (based on key file protection status or --password flag)
/// Returns owned password buffer that caller must zero and free
fn promptForPasswordIfNeeded(allocator: std.mem.Allocator, opts: Options) !?[]u8 {
    // Determine if key is password-protected
    const is_protected = blk: {
        const key_path = try keyloader.resolveKeyPath(allocator, opts.key);
        if (key_path) |path| {
            defer allocator.free(path);
            break :blk try prompt.isKeyPasswordProtected(path);
        } else {
            // Check config-stored key
            var cfg = config_mod.load(allocator) catch break :blk false;
            defer cfg.deinit(allocator);
            if (cfg.key) |key_data| {
                break :blk key_data.len == keygen.protected_key_file_size;
            }
            break :blk false;
        }
    };

    // Prompt if protected or if --password flag is set
    if (is_protected or opts.password) {
        return try prompt.promptPassword(allocator, "Enter key password", false);
    }
    return null;
}

/// Get thread count from options or use default (min(CPU count, 16), capped at 64)
fn getThreadCount(opts: Options) !u32 {
    if (opts.threads) |t| return @min(t, 64);
    const cpu_count = try std.Thread.getCpuCount();
    return @as(u32, @intCast(@min(cpu_count, 16)));
}

/// Handle key loading errors with consistent error messages
/// command_name should be the command being executed (e.g., "encrypt", "decrypt", "verify", "list")
fn handleKeyLoadError(err: anyerror, command_name: []const u8) !void {
    if (err == error.KeyNotFound) {
        std.debug.print("Error: No encryption key configured\n", .{});
        std.debug.print("\nYou can specify a key in one of these ways:\n", .{});
        std.debug.print("  1. Use --key flag:           turbocrypt {s} --key secret.key <source> <dest>\n", .{command_name});
        std.debug.print("  2. Set environment variable: export {s}=secret.key\n", .{keyloader.env_var_name});
        std.debug.print("  3. Set default key:          turbocrypt config set-key secret.key\n", .{});
        return error.KeyNotFound;
    }
    if (err == error.PasswordRequired) {
        std.debug.print("Error: This key file is password-protected. Use --password flag.\n", .{});
        return error.PasswordRequired;
    }
    if (err == error.InvalidPassword) {
        std.debug.print("Error: Invalid password for key file.\n", .{});
        return error.InvalidPassword;
    }
    return err;
}

fn cmdKeygen(args: []const []const u8, allocator: std.mem.Allocator) !void {
    // Parse options (to support --password flag)
    const parsed = try parseOptions(args, allocator);
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

    // Generate key
    const key = keygen.generate();

    // Optionally protect with password
    var password_buf: ?[]u8 = null;
    defer if (password_buf) |buf| {
        // Zero out password before freeing
        @memset(buf, 0);
        allocator.free(buf);
    };

    if (opts.password) {
        password_buf = prompt.promptPassword(allocator, "Enter password to protect key", true) catch |err| {
            if (err == error.PasswordMismatch) {
                std.debug.print("Error: Passwords do not match\n", .{});
                return error.PasswordMismatch;
            }
            return err;
        };
    }

    // Write to file
    try keygen.writeKeyFile(output_path, key, password_buf);

    std.debug.print("Key generated and saved to: {s}\n", .{output_path});
    if (opts.password) {
        std.debug.print("Key is password-protected\n", .{});
    }
    std.debug.print("WARNING: Keep this key file secure! Anyone with access to it can decrypt your files.\n", .{});
    std.debug.print("\nTo set this as your default key, run:\n", .{});
    std.debug.print("  turbocrypt config set-key {s}\n", .{output_path});
}

/// Processing mode for directory scanning
const ProcessingMode = union(enum) {
    /// Scan only - collect file paths for later processing
    scan_only: struct {
        file_paths: std.ArrayList([]const u8),
        file_sizes: std.ArrayList(u64),
        total_bytes: u64,
    },
    /// Scan and process - submit files to worker pool immediately
    scan_and_process: struct {
        worker_pool: *worker.WorkerPool,
        progress_tracker: *progress.ProgressTracker,
    },
};

/// Unified context for directory traversal callbacks
const DirectoryScanContext = struct {
    // Common fields
    source_base: []const u8,
    dest_base: []const u8,
    allocator: std.mem.Allocator,
    enc_suffix: bool,
    is_encrypt: bool,
    encrypt_filenames: bool,
    key: [16]u8,
    exclude_patterns: std.ArrayList([]const u8),
    ignore_symlinks: bool,

    // Mode-specific data
    mode: ProcessingMode,

    fn callback(
        relative_path: []const u8,
        full_path: []const u8,
        is_directory: bool,
        context: *anyopaque,
    ) !void {
        const self: *DirectoryScanContext = @ptrCast(@alignCast(context));

        // Shared logic for directory handling
        if (is_directory) {
            try handleDirectory(
                relative_path,
                self.dest_base,
                self.encrypt_filenames,
                self.is_encrypt,
                self.key,
                self.allocator,
            );
            return;
        }

        // Shared logic for exclude patterns
        if (utils.matchesExcludePattern(relative_path, self.exclude_patterns)) {
            return; // Skip excluded file
        }

        // Shared logic for enc_suffix filtering
        if (self.enc_suffix and !self.is_encrypt) {
            if (!hasEncSuffix(full_path)) {
                return; // Skip this file
            }
        }

        // Shared logic for file size retrieval
        const file = try std.fs.cwd().openFile(full_path, .{});
        defer file.close();
        const file_size = (try file.stat()).size;

        // Mode-specific processing
        switch (self.mode) {
            .scan_only => |*scan| {
                const stored_path = try self.allocator.dupe(u8, full_path);
                try scan.file_paths.append(self.allocator, stored_path);
                try scan.file_sizes.append(self.allocator, file_size);
                scan.total_bytes += file_size;
            },
            .scan_and_process => |proc| {
                try self.processScanAndProcessFile(relative_path, full_path, file_size, proc.worker_pool, proc.progress_tracker);
            },
        }
    }

    fn processScanAndProcessFile(
        self: *DirectoryScanContext,
        relative_path: []const u8,
        full_path: []const u8,
        file_size: u64,
        worker_pool: *worker.WorkerPool,
        progress_tracker: *progress.ProgressTracker,
    ) !void {
        // Update totals in progress tracker (for dynamic discovery)
        progress_tracker.addTotalFile();
        progress_tracker.addTotalBytes(file_size);

        // Compute the destination relative path with suffix handling
        var dest_relative_path: []const u8 = undefined;
        var needs_free = false;

        if (self.enc_suffix) {
            const transformed = try applyEncSuffix(self.allocator, relative_path, self.is_encrypt);
            if (transformed) |t| {
                dest_relative_path = t;
                needs_free = true;
            } else {
                dest_relative_path = relative_path;
            }
        } else {
            dest_relative_path = relative_path;
        }

        // Apply filename encryption if enabled
        var encrypted_relative_path: ?[]u8 = null;
        defer if (encrypted_relative_path) |p| self.allocator.free(p);

        if (self.encrypt_filenames) {
            encrypted_relative_path = (if (self.is_encrypt)
                filename_crypto.encryptPath(self.allocator, dest_relative_path, self.key)
            else
                filename_crypto.decryptPath(self.allocator, dest_relative_path, self.key)) catch |err| {
                if (needs_free) self.allocator.free(dest_relative_path);
                std.debug.print("\n[ERROR] Failed to {s} filename: {s}\n", .{
                    if (self.is_encrypt) "encrypt" else "decrypt",
                    relative_path,
                });
                std.debug.print("        Reason: {}\n", .{err});
                if (err == filename_crypto.FilenameError.EncryptedFilenameTooLong) {
                    std.debug.print("        Suggestion: Filename is too long. Encrypted names must fit within 255 bytes.\n", .{});
                    std.debug.print("                   Consider shortening the filename (max ~205 bytes for encryption).\n", .{});
                } else if (!self.is_encrypt) {
                    std.debug.print("        Suggestion: Ensure the file was encrypted with --encrypted-filenames using the same key\n", .{});
                }
                return err;
            };

            if (needs_free) self.allocator.free(dest_relative_path);
            dest_relative_path = encrypted_relative_path.?;
            needs_free = false; // encrypted_relative_path will be freed by defer
        }

        // Defer freeing dest_relative_path after we've used it
        defer if (needs_free) self.allocator.free(dest_relative_path);

        // Prepare source and destination paths
        // These will be freed by the worker pool after processing
        const source_path = try self.allocator.dupe(u8, full_path);
        const dest_path = try std.fs.path.join(self.allocator, &[_][]const u8{ self.dest_base, dest_relative_path });

        // Ensure destination directory exists
        const dest_dir = try utils.dirname(dest_path, self.allocator);
        defer self.allocator.free(dest_dir);
        if (dest_dir.len > 0) {
            utils.ensureDirectory(dest_dir) catch |err| {
                self.allocator.free(source_path);
                self.allocator.free(dest_path);
                std.debug.print("\n[ERROR] Failed to create destination directory: {s}\n", .{dest_dir});
                std.debug.print("        For file: {s}\n", .{relative_path});
                std.debug.print("        Reason: {}\n", .{err});
                if (self.encrypt_filenames and !self.is_encrypt) {
                    std.debug.print("        Suggestion: Filename may be corrupted or encrypted with a different key\n", .{});
                }
                return err;
            };
        }

        // Submit job to worker pool immediately (concurrent processing)
        const job = worker.FileJob{
            .source_path = source_path,
            .dest_path = dest_path,
            .operation = if (self.is_encrypt) .encrypt else .decrypt,
            .file_size = file_size,
        };

        try worker_pool.submitJob(job);
    }
};

/// Unified encrypt/decrypt processing function
fn cmdProcess(args: []const []const u8, allocator: std.mem.Allocator, is_encrypt: bool) !void {
    const op_name = if (is_encrypt) "encrypt" else "decrypt";
    const op_name_cap = if (is_encrypt) "Encrypting" else "Decrypting";
    const op_complete = if (is_encrypt) "Encryption" else "Decryption";

    // Parse options
    const parsed = try parseOptions(args, allocator);
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

    // Determine destination path
    var dest_path_buf: ?[]u8 = null;
    defer if (dest_path_buf) |buf| allocator.free(buf);

    const dest_path = if (parsed.positional.len >= 2)
        parsed.positional[1]
    else if (opts.in_place) blk: {
        if (opts.enc_suffix) {
            const transformed = try applyEncSuffix(allocator, source_path, is_encrypt);
            if (transformed) |t| {
                dest_path_buf = t;
                break :blk dest_path_buf.?;
            } else {
                // Decrypting but source doesn't have .enc suffix
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

    // Check if we need password (only for file-based keys)
    const password_buf: ?[]u8 = try promptForPasswordIfNeeded(allocator, opts);
    defer if (password_buf) |buf| {
        @memset(buf, 0);
        allocator.free(buf);
    };

    // Load key (from file or config)
    const key = keyloader.resolveKey(allocator, opts.key, password_buf) catch |err| {
        return handleKeyLoadError(err, op_name);
    };

    // Derive keys from master key using TurboSHAKE128
    const derived_keys = crypto.deriveKeys(key, opts.context);

    // Check if source is a file or directory
    const is_dir = utils.isDirectory(source_path) catch false;

    if (is_dir) {
        // Process directory with parallel processing
        std.debug.print("{s} directory: {s} -> {s}\n", .{ op_name_cap, source_path, dest_path });

        // Ensure destination directory exists
        try utils.ensureDirectory(dest_path);

        // Determine thread count (use option or default)
        const thread_count = try getThreadCount(opts);

        // For in-place operations, use two-phase approach to avoid race conditions
        if (opts.in_place) {
            std.debug.print("Scanning files...\n", .{});

            // Phase 1: Scan and collect all file paths
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
                .mode = .{ .scan_only = .{
                    .file_paths = std.ArrayList([]const u8){},
                    .file_sizes = std.ArrayList(u64){},
                    .total_bytes = 0,
                } },
            };
            defer {
                for (scan_ctx.mode.scan_only.file_paths.items) |path| allocator.free(path);
                scan_ctx.mode.scan_only.file_paths.deinit(allocator);
                scan_ctx.mode.scan_only.file_sizes.deinit(allocator);
            }

            utils.walkDirectory(source_path, DirectoryScanContext.callback, &scan_ctx, allocator, opts.ignore_symlinks) catch |err| {
                std.debug.print("\n[FATAL] Directory scanning failed\n", .{});
                return err;
            };

            if (opts.dry_run) {
                std.debug.print("[DRY RUN] Would process {d} files...\n", .{scan_ctx.mode.scan_only.file_paths.items.len});
            } else {
                std.debug.print("{s} {d} files...\n", .{ op_name_cap, scan_ctx.mode.scan_only.file_paths.items.len });
            }

            // Phase 2: Process all collected files
            var tracker = progress.ProgressTracker.init(scan_ctx.mode.scan_only.file_paths.items.len, scan_ctx.mode.scan_only.total_bytes);
            var pool = try worker.WorkerPool.init(allocator, thread_count, derived_keys, &tracker, false, opts.dry_run);
            defer pool.deinit();

            try tracker.startDisplay();
            defer tracker.stopDisplay();

            for (scan_ctx.mode.scan_only.file_paths.items, scan_ctx.mode.scan_only.file_sizes.items) |file_path, file_size| {
                const source_path_dup = try allocator.dupe(u8, file_path);

                // For in-place with enc_suffix, modify destination path
                const dest_path_dup = if (opts.enc_suffix) blk2: {
                    const transformed = try applyEncSuffix(allocator, file_path, is_encrypt);
                    if (transformed) |t| {
                        break :blk2 t;
                    } else {
                        break :blk2 try allocator.dupe(u8, file_path);
                    }
                } else try allocator.dupe(u8, file_path);

                const job = worker.FileJob{
                    .source_path = source_path_dup,
                    .dest_path = dest_path_dup,
                    .operation = if (is_encrypt) .encrypt else .decrypt,
                    .file_size = file_size,
                };

                try pool.submitJob(job);
            }

            pool.waitAll();
            tracker.displayFinal();
        } else {
            // Non-in-place: use concurrent scan-and-process for better performance
            if (opts.dry_run) {
                std.debug.print("[DRY RUN] Scanning files...\n", .{});
            } else {
                std.debug.print("Scanning and {s}...\n", .{if (is_encrypt) "encrypting" else "decrypting"});
            }

            var tracker = progress.ProgressTracker.init(0, 0);
            var pool = try worker.WorkerPool.init(allocator, thread_count, derived_keys, &tracker, false, opts.dry_run);
            defer pool.deinit();

            // Start worker threads BEFORE scanning so they can process files concurrently
            pool.start();

            try tracker.startDisplay();
            defer tracker.stopDisplay();

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
                .mode = .{ .scan_and_process = .{
                    .worker_pool = &pool,
                    .progress_tracker = &tracker,
                } },
            };

            utils.walkDirectory(source_path, DirectoryScanContext.callback, &ctx, allocator, opts.ignore_symlinks) catch |err| {
                tracker.stopDisplay();
                pool.finish();
                std.debug.print("\n[FATAL] Directory scanning failed\n", .{});
                return err;
            };

            pool.finish();
            tracker.displayFinal();
        }
    } else {
        // Process single file (no parallelization needed)

        // Check if single file should be excluded
        if (utils.matchesExcludePattern(source_path, opts.exclude_patterns)) {
            std.debug.print("Skipping excluded file: {s}\n", .{source_path});
            return;
        }

        std.debug.print("{s} file: {s} -> {s}\n", .{ op_name_cap, source_path, dest_path });

        // Ensure destination directory exists
        const dest_dir = try utils.dirname(dest_path, allocator);
        defer allocator.free(dest_dir);
        if (dest_dir.len > 0) {
            try utils.ensureDirectory(dest_dir);
        }

        if (is_encrypt) {
            processor.encryptFile(source_path, dest_path, derived_keys, allocator) catch |err| {
                std.debug.print("\n[ERROR] Encryption failed\n", .{});
                std.debug.print("        File: {s}\n", .{source_path});
                worker.printErrorDetails(err, true);
                return err;
            };
        } else {
            processor.decryptFile(source_path, dest_path, derived_keys, allocator) catch |err| {
                std.debug.print("\n[ERROR] Decryption failed\n", .{});
                std.debug.print("        File: {s}\n", .{source_path});
                worker.printErrorDetails(err, false);
                return err;
            };
        }
        std.debug.print("{s} complete!\n", .{op_complete});
    }
}

fn cmdEncrypt(args: []const []const u8, allocator: std.mem.Allocator) !void {
    try cmdProcess(args, allocator, true);
}

fn cmdDecrypt(args: []const []const u8, allocator: std.mem.Allocator) !void {
    try cmdProcess(args, allocator, false);
}

fn cmdVerify(args: []const []const u8, allocator: std.mem.Allocator) !void {
    // Parse options
    const parsed = try parseOptions(args, allocator);
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

    // Check if we need password (only for file-based keys)
    const password_buf: ?[]u8 = try promptForPasswordIfNeeded(allocator, opts);
    defer if (password_buf) |buf| {
        @memset(buf, 0);
        allocator.free(buf);
    };

    // Load key (from file or config)
    const key = keyloader.resolveKey(allocator, opts.key, password_buf) catch |err| {
        return handleKeyLoadError(err, "verify");
    };

    // Derive keys from master key using TurboSHAKE128
    const derived_keys = crypto.deriveKeys(key, opts.context);

    // Check if source is a file or directory
    const is_dir = utils.isDirectory(source_path) catch false;

    if (is_dir) {
        // Verify directory with parallel processing
        std.debug.print("Verifying directory: {s}\n", .{source_path});

        // Determine thread count
        const thread_count = try getThreadCount(opts);

        // Note: Verify uses two-phase approach (scan then process) because we want to
        // display total file count before verification starts. This could be changed
        // to concurrent scan-and-process if preferred, but would show "Verifying 0 files..."
        // initially and update the count dynamically.

        std.debug.print("Scanning files...\n", .{});

        // Scan and collect all file paths
        var scan_ctx = DirectoryScanContext{
            .source_base = source_path,
            .dest_base = source_path, // Not used for verify
            .allocator = allocator,
            .enc_suffix = false, // Don't filter by .enc suffix for verify
            .is_encrypt = false, // Not used for verify
            .encrypt_filenames = false,
            .key = derived_keys.filename_key,
            .exclude_patterns = opts.exclude_patterns,
            .ignore_symlinks = opts.ignore_symlinks,
            .mode = .{ .scan_only = .{
                .file_paths = std.ArrayList([]const u8){},
                .file_sizes = std.ArrayList(u64){},
                .total_bytes = 0,
            } },
        };
        defer {
            for (scan_ctx.mode.scan_only.file_paths.items) |path| allocator.free(path);
            scan_ctx.mode.scan_only.file_paths.deinit(allocator);
            scan_ctx.mode.scan_only.file_sizes.deinit(allocator);
        }

        utils.walkDirectory(source_path, DirectoryScanContext.callback, &scan_ctx, allocator, opts.ignore_symlinks) catch |err| {
            std.debug.print("\n[FATAL] Directory scanning failed\n", .{});
            return err;
        };

        if (opts.dry_run) {
            std.debug.print("[DRY RUN] Would verify {d} files...\n", .{scan_ctx.mode.scan_only.file_paths.items.len});
        } else {
            std.debug.print("Verifying {d} files...\n", .{scan_ctx.mode.scan_only.file_paths.items.len});
        }

        // Verify all collected files
        var tracker = progress.ProgressTracker.init(scan_ctx.mode.scan_only.file_paths.items.len, scan_ctx.mode.scan_only.total_bytes);
        var pool = try worker.WorkerPool.init(allocator, thread_count, derived_keys, &tracker, opts.quick, opts.dry_run);
        defer pool.deinit();

        try tracker.startDisplay();
        defer tracker.stopDisplay();

        for (scan_ctx.mode.scan_only.file_paths.items, scan_ctx.mode.scan_only.file_sizes.items) |file_path, file_size| {
            const source_path_dup = try allocator.dupe(u8, file_path);

            const job = worker.FileJob{
                .source_path = source_path_dup,
                .dest_path = null, // No destination for verify
                .operation = .verify,
                .file_size = file_size,
            };

            try pool.submitJob(job);
        }

        pool.waitAll();
        tracker.displayFinal();

        if (pool.hadErrors()) {
            std.debug.print("\nVerification completed with errors. Some files failed verification.\n", .{});
            std.process.exit(1);
        } else {
            std.debug.print("\nAll files verified successfully!\n", .{});
        }
    } else {
        // Verify single file
        // Check if single file should be excluded
        if (utils.matchesExcludePattern(source_path, opts.exclude_patterns)) {
            std.debug.print("Skipping excluded file: {s}\n", .{source_path});
            return;
        }

        std.debug.print("Verifying file: {s}\n", .{source_path});

        processor.verifyFile(source_path, derived_keys, allocator, opts.quick) catch |err| {
            std.debug.print("\n[VERIFY FAILED] {s}\n", .{source_path});
            worker.printErrorDetails(err, false);
            return err;
        };

        std.debug.print("File verified successfully!\n", .{});
    }
}

/// Context for listing files (collects file paths and sizes for display)
const ListContext = struct {
    allocator: std.mem.Allocator,
    file_paths: std.ArrayList([]const u8),
    file_sizes: std.ArrayList(u64),
    total_bytes: u64,
    total_files: u64,
    decrypt_filenames: bool,
    filename_key: [16]u8,
    exclude_patterns: std.ArrayList([]const u8),

    fn callback(
        relative_path: []const u8,
        full_path: []const u8,
        is_directory: bool,
        context: *anyopaque,
    ) !void {
        const self: *ListContext = @ptrCast(@alignCast(context));

        // Skip directories
        if (is_directory) return;

        // Check exclude patterns
        if (utils.matchesExcludePattern(relative_path, self.exclude_patterns)) {
            return;
        }

        // Get file size
        const stat = try std.fs.cwd().statFile(full_path);
        const file_size = stat.size;

        // Store path and size for later display
        const path_copy = try self.allocator.dupe(u8, relative_path);
        try self.file_paths.append(self.allocator, path_copy);
        try self.file_sizes.append(self.allocator, file_size);

        self.total_bytes += file_size;
        self.total_files += 1;
    }
};

fn cmdList(args: []const []const u8, allocator: std.mem.Allocator) !void {
    // Parse options
    const parsed = try parseOptions(args, allocator);
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

    // Check if source is a directory
    const is_dir = utils.isDirectory(source_path) catch {
        std.debug.print("Error: Path is not a directory: {s}\n", .{source_path});
        return error.InvalidPath;
    };

    if (!is_dir) {
        std.debug.print("Error: Path is not a directory: {s}\n", .{source_path});
        std.debug.print("Usage: turbocrypt list works only with directories\n", .{});
        return error.InvalidPath;
    }

    // If encrypted filenames are used, we need a key
    var filename_key: [16]u8 = undefined;
    if (opts.encrypt_filenames) {
        // Check if we need password (only for file-based keys)
        const password_buf: ?[]u8 = try promptForPasswordIfNeeded(allocator, opts);
        defer if (password_buf) |buf| {
            @memset(buf, 0);
            allocator.free(buf);
        };

        // Load key (from file or config)
        const key = keyloader.resolveKey(allocator, opts.key, password_buf) catch |err| {
            return handleKeyLoadError(err, "list");
        };

        // Derive keys from master key and use the derived filename_key
        const derived_keys = crypto.deriveKeys(key, opts.context);
        filename_key = derived_keys.filename_key;
    }

    // Scan directory and collect file information
    std.debug.print("Listing contents: {s}\n\n", .{source_path});

    var list_ctx = ListContext{
        .allocator = allocator,
        .file_paths = std.ArrayList([]const u8){},
        .file_sizes = std.ArrayList(u64){},
        .total_bytes = 0,
        .total_files = 0,
        .decrypt_filenames = opts.encrypt_filenames,
        .filename_key = filename_key,
        .exclude_patterns = opts.exclude_patterns,
    };
    defer {
        for (list_ctx.file_paths.items) |path| allocator.free(path);
        list_ctx.file_paths.deinit(allocator);
        list_ctx.file_sizes.deinit(allocator);
    }

    utils.walkDirectory(source_path, ListContext.callback, &list_ctx, allocator, opts.ignore_symlinks) catch |err| {
        std.debug.print("Error: Failed to walk directory\n", .{});
        return err;
    };

    // Display results
    if (list_ctx.total_files == 0) {
        std.debug.print("Directory is empty (or all files excluded by patterns)\n", .{});
        return;
    }

    // Display each file with its size
    for (list_ctx.file_paths.items, list_ctx.file_sizes.items) |file_path, file_size| {
        // Decrypt filename if needed
        const display_path = if (opts.encrypt_filenames) blk: {
            const decrypted = filename_crypto.decryptPath(allocator, file_path, filename_key) catch |err| {
                // If decryption fails, show encrypted name with a marker
                std.debug.print("  {s} ({s}) [decrypt error: {}]\n", .{ file_path, formatSize(file_size), err });
                continue;
            };
            break :blk decrypted;
        } else try allocator.dupe(u8, file_path);
        defer allocator.free(display_path);

        std.debug.print("  {s} ({s})\n", .{ display_path, formatSize(file_size) });
    }

    // Display summary
    std.debug.print("\nTotal: {d} file{s}, {s}\n", .{
        list_ctx.total_files,
        if (list_ctx.total_files == 1) "" else "s",
        formatSize(list_ctx.total_bytes),
    });
}

/// Format file size in human-readable format (bytes, KB, MB, GB, TB)
fn formatSize(bytes: u64) []const u8 {
    const kb: f64 = 1024.0;
    const mb: f64 = kb * 1024.0;
    const gb: f64 = mb * 1024.0;
    const tb: f64 = gb * 1024.0;

    const bytes_f: f64 = @floatFromInt(bytes);

    // Use static buffer for formatting (thread-local, overwritten on each call)
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

fn cmdChangePassword(args: []const []const u8, allocator: std.mem.Allocator) !void {
    // Parse options (to support --remove-password flag)
    const parsed = try parseOptions(args, allocator);
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

    // Read the current key file to determine its format
    const file = try std.fs.cwd().openFile(key_path, .{});
    defer file.close();
    const stat = try file.stat();
    const file_size = stat.size;

    if (file_size != keygen.plain_key_file_size and file_size != keygen.protected_key_file_size) {
        std.debug.print("Error: Invalid key file size (expected {d} or {d} bytes, got {d})\n", .{ keygen.plain_key_file_size, keygen.protected_key_file_size, file_size });
        return error.InvalidKeyFile;
    }

    const is_protected = file_size == keygen.protected_key_file_size;

    // Read the actual key (decrypt if password-protected)
    var actual_key: [16]u8 = undefined;

    if (is_protected) {
        // Password-protected: need old password to decrypt
        std.debug.print("Current key is password-protected\n", .{});

        const old_password_buf = try prompt.promptPassword(allocator, "Enter current password", false);
        defer {
            @memset(old_password_buf, 0);
            allocator.free(old_password_buf);
        }

        // Read and decrypt the key
        actual_key = keygen.readKeyFile(key_path, old_password_buf) catch |err| {
            if (err == error.InvalidPassword) {
                std.debug.print("Error: Invalid current password\n", .{});
                return error.InvalidPassword;
            }
            return err;
        };

        if (remove_password) {
            // Remove password protection: write as plain key
            try keygen.writeKeyFile(key_path, actual_key, null);
            std.debug.print("Password protection removed from key file: {s}\n", .{key_path});
            std.debug.print("WARNING: The key is now stored in plain text. Keep it secure!\n", .{});
            return;
        } else {
            // Change password: prompt for new password
            const new_password_buf = try prompt.promptPassword(allocator, "Enter new password", true);
            defer {
                @memset(new_password_buf, 0);
                allocator.free(new_password_buf);
            }

            try keygen.writeKeyFile(key_path, actual_key, new_password_buf);
            std.debug.print("Password changed successfully for key file: {s}\n", .{key_path});
        }
    } else {
        // Plain key
        if (remove_password) {
            std.debug.print("Error: Key is not password-protected\n", .{});
            return error.InvalidArguments;
        }

        std.debug.print("Current key is not password-protected\n", .{});

        // Read the plain key
        actual_key = try keygen.readKeyFile(key_path, null);

        // Add password protection
        const new_password_buf = try prompt.promptPassword(allocator, "Enter new password", true);
        defer {
            @memset(new_password_buf, 0);
            allocator.free(new_password_buf);
        }

        try keygen.writeKeyFile(key_path, actual_key, new_password_buf);
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
            // Check if pattern already exists
            for (cfg.exclude_patterns) |existing| {
                if (std.mem.eql(u8, existing, pattern)) {
                    std.debug.print("Pattern '{s}' already in exclude list\n", .{pattern});
                    return;
                }
            }

            // Add new pattern
            var new_patterns = try allocator.alloc([]const u8, cfg.exclude_patterns.len + 1);
            for (cfg.exclude_patterns, 0..) |old_pattern, i| {
                new_patterns[i] = try allocator.dupe(u8, old_pattern);
            }
            new_patterns[cfg.exclude_patterns.len] = try allocator.dupe(u8, pattern);

            // Free old patterns
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
            // Find pattern
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

            // Remove pattern
            if (cfg.exclude_patterns.len == 1) {
                // Last pattern - clear the array
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
                    // Move ownership - don't duplicate
                    new_patterns[new_idx] = old_pattern;
                    new_idx += 1;
                }

                // Free old array (but not the strings inside - they've been moved)
                allocator.free(cfg.exclude_patterns);
                cfg.exclude_patterns = new_patterns;
            }

            std.debug.print("Removed exclude pattern: {s}\n", .{pattern});
        },
    }
}

fn cmdConfig(args: []const []const u8, allocator: std.mem.Allocator) !void {
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

        // Read the entire key file
        // We store it in the same format as the file
        const max_key_size = keygen.protected_key_file_size + 1; // Max size + margin
        const key_data = std.fs.cwd().readFileAlloc(
            key_path,
            allocator,
            std.Io.Limit.limited(max_key_size),
        ) catch |err| {
            std.debug.print("Error: Cannot read key file '{s}': {}\n", .{ key_path, err });
            return err;
        };
        defer allocator.free(key_data);

        // Validate key size
        if (key_data.len != keygen.plain_key_file_size and key_data.len != keygen.protected_key_file_size) {
            std.debug.print("Error: Invalid key file size (expected {d} or {d} bytes, got {d})\n", .{ keygen.plain_key_file_size, keygen.protected_key_file_size, key_data.len });
            return error.InvalidKeyFile;
        }

        const is_protected = key_data.len == keygen.protected_key_file_size;

        // If password-protected, verify we can decrypt it
        if (is_protected) {
            // Check format flag
            if (key_data[0] != @intFromEnum(keygen.KeyFormat.password_protected)) {
                std.debug.print("Error: Invalid password-protected key format\n", .{});
                return error.InvalidKeyFile;
            }

            // Prompt for password to verify
            const password_buf = try prompt.promptPassword(allocator, "Enter key password (to verify)", false);
            defer {
                std.crypto.secureZero(u8, password_buf);
                allocator.free(password_buf);
            }

            // Test decrypt to verify password is correct
            var protected_data: [20]u8 = undefined;
            @memcpy(&protected_data, key_data[1..keygen.protected_key_file_size]);
            _ = password.unprotectKey(protected_data, password_buf) catch |err| {
                std.debug.print("Error: Cannot decrypt key (wrong password?): {}\n", .{err});
                return err;
            };

            std.debug.print("Password verified successfully.\n", .{});
        }

        // Save key data to config (in same format as file: 16 or 21 bytes)
        try keyloader.setDefaultKey(allocator, key_data);

        // Get and display config file path
        const config_path = try keyloader.getConfigFilePath(allocator);
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

        // Load config, update, and save
        var cfg = try config_mod.load(allocator);
        defer cfg.deinit(allocator);

        cfg.threads = threads;
        try config_mod.save(cfg, allocator);

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

        // Load config, update, and save
        var cfg = try config_mod.load(allocator);
        defer cfg.deinit(allocator);

        cfg.buffer_size = buffer_size;
        try config_mod.save(cfg, allocator);

        std.debug.print("Default buffer size set to: {d} bytes\n", .{buffer_size});
    } else if (std.mem.eql(u8, subcommand, "add-exclude")) {
        if (args.len < 2) {
            std.debug.print("Error: Missing exclude pattern\n", .{});
            std.debug.print("Usage: turbocrypt config add-exclude <pattern>\n", .{});
            return error.InvalidArguments;
        }

        var cfg = try config_mod.load(allocator);
        defer cfg.deinit(allocator);

        try modifyExcludePattern(&cfg, args[1], .add, allocator);
        try config_mod.save(cfg, allocator);
    } else if (std.mem.eql(u8, subcommand, "remove-exclude")) {
        if (args.len < 2) {
            std.debug.print("Error: Missing exclude pattern\n", .{});
            std.debug.print("Usage: turbocrypt config remove-exclude <pattern>\n", .{});
            return error.InvalidArguments;
        }

        var cfg = try config_mod.load(allocator);
        defer cfg.deinit(allocator);

        try modifyExcludePattern(&cfg, args[1], .remove, allocator);
        try config_mod.save(cfg, allocator);
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

        // Load config, update, and save
        var cfg = try config_mod.load(allocator);
        defer cfg.deinit(allocator);

        cfg.ignore_symlinks = value;
        try config_mod.save(cfg, allocator);

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

        // Load config, update, and save
        var cfg = try config_mod.load(allocator);
        defer cfg.deinit(allocator);

        cfg.encrypted_filenames = value;
        try config_mod.save(cfg, allocator);

        std.debug.print("Encrypt filenames set to: {s}\n", .{if (value) "true" else "false"});
    } else if (std.mem.eql(u8, subcommand, "show")) {
        // Load config
        var cfg = try config_mod.load(allocator);
        defer cfg.deinit(allocator);

        const config_path = try config_mod.getConfigFilePath(allocator);
        defer allocator.free(config_path);

        std.debug.print("Current configuration:\n", .{});
        std.debug.print("Config file: {s}\n\n", .{config_path});

        // Show key
        if (cfg.key) |_| {
            std.debug.print("Key: stored in config (16 bytes)\n", .{});
        } else {
            std.debug.print("Key: (not set)\n", .{});
        }

        // Show threads
        if (cfg.threads) |threads| {
            std.debug.print("Threads: {d}\n", .{threads});
        } else {
            std.debug.print("Threads: (auto - uses CPU count, max 16)\n", .{});
        }

        // Show buffer size
        if (cfg.buffer_size) |size| {
            std.debug.print("Buffer size: {d} bytes\n", .{size});
        } else {
            std.debug.print("Buffer size: (default - 4194304 bytes / 4MB)\n", .{});
        }

        // Show exclude patterns
        std.debug.print("Exclude patterns: ", .{});
        if (cfg.exclude_patterns.len == 0) {
            std.debug.print("(none)\n", .{});
        } else {
            std.debug.print("\n", .{});
            for (cfg.exclude_patterns) |pattern| {
                std.debug.print("  - {s}\n", .{pattern});
            }
        }

        // Show ignore_symlinks
        if (cfg.ignore_symlinks) |ignore| {
            std.debug.print("Ignore symlinks: {s}\n", .{if (ignore) "true" else "false"});
        } else {
            std.debug.print("Ignore symlinks: (default - false)\n", .{});
        }

        // Show encrypted_filenames
        if (cfg.encrypted_filenames) |encrypt_names| {
            std.debug.print("Encrypt filenames: {s}\n", .{if (encrypt_names) "true" else "false"});
        } else {
            std.debug.print("Encrypt filenames: (default - false)\n", .{});
        }

        std.debug.print("\nKey resolution priority:\n", .{});
        std.debug.print("  1. --key flag (if provided)\n", .{});
        std.debug.print("  2. {s} environment variable", .{keyloader.env_var_name});
        if (std.process.getEnvVarOwned(allocator, keyloader.env_var_name)) |env_val| {
            defer allocator.free(env_val);
            std.debug.print(" (currently: {s})", .{env_val});
        } else |_| {
            std.debug.print(" (not set)", .{});
        }
        std.debug.print("\n  3. Config file\n", .{});
    } else {
        std.debug.print("Error: Unknown config subcommand '{s}'\n", .{subcommand});
        std.debug.print("Usage: turbocrypt config <set-key|set-threads|set-buffer-size|add-exclude|remove-exclude|set-ignore-symlinks|set-encrypted-filenames|show>\n", .{});
        return error.InvalidArguments;
    }
}

pub fn main() !void {
    // Use SmpAllocator for release builds, DebugAllocator for debug builds
    const builtin = @import("builtin");

    // Print build mode if Debug
    if (builtin.mode == .Debug) {
        std.debug.print("Debug build\n", .{});
    }

    const use_smp = builtin.mode == .ReleaseFast or builtin.mode == .ReleaseSmall;

    var gpa = std.heap.DebugAllocator(.{}){};
    defer {
        if (!use_smp) _ = gpa.deinit();
    }

    const allocator = if (use_smp)
        std.heap.smp_allocator
    else
        gpa.allocator();

    // Get command-line arguments
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    // Need at least one argument (command)
    if (args.len < 2) {
        printUsage();
        return;
    }

    const command = args[1];
    const command_args = args[2..];

    if (std.mem.eql(u8, command, "keygen")) {
        cmdKeygen(command_args, allocator) catch {
            std.process.exit(1);
        };
    } else if (std.mem.eql(u8, command, "change-password")) {
        cmdChangePassword(command_args, allocator) catch {
            std.process.exit(1);
        };
    } else if (std.mem.eql(u8, command, "encrypt")) {
        cmdEncrypt(command_args, allocator) catch {
            std.process.exit(1);
        };
    } else if (std.mem.eql(u8, command, "decrypt")) {
        cmdDecrypt(command_args, allocator) catch {
            std.process.exit(1);
        };
    } else if (std.mem.eql(u8, command, "verify")) {
        cmdVerify(command_args, allocator) catch {
            std.process.exit(1);
        };
    } else if (std.mem.eql(u8, command, "list")) {
        cmdList(command_args, allocator) catch {
            std.process.exit(1);
        };
    } else if (std.mem.eql(u8, command, "config")) {
        cmdConfig(command_args, allocator) catch {
            std.process.exit(1);
        };
    } else if (std.mem.eql(u8, command, "bench")) {
        bench.run(allocator) catch {
            std.process.exit(1);
        };
    } else if (std.mem.eql(u8, command, "help") or std.mem.eql(u8, command, "--help") or std.mem.eql(u8, command, "-h")) {
        printUsage();
    } else {
        std.debug.print("Error: Unknown command '{s}'\n\n", .{command});
        printUsage();
        std.process.exit(1);
    }
}

// Test references - ensures tests from imported modules are included
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
}
