//! The command-line interface for ordinary file and key operations.
//! Git, mounts, and benchmarks keep their command handling in their own modules.

const std = @import("std");
const mem = std.mem;
const testing = std.testing;
const Allocator = std.mem.Allocator;
const Io = std.Io;

const build_options = @import("build_options");
const keygen = @import("keygen.zig");
const key_loader = @import("key_loader.zig");
const Config = @import("Config.zig");
const container = @import("container.zig");
const crypto = @import("crypto.zig");
const processor = @import("processor.zig");
const fs = @import("fs.zig");
const worker = @import("worker.zig");
const progress = @import("progress.zig");
const filename_crypto = @import("filename_crypto.zig");
const prompt = @import("prompt.zig");
const password = @import("password.zig");
const bench = @import("bench.zig");
const git = @import("git.zig");
const mount_cmd = if (build_options.fuse) @import("mount/cmd.zig") else void;

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
    \\  turbocrypt encrypt [--key <key-file>] [--password] <source> <destination>
    \\                     [options]
    \\      Encrypt a file or directory
    \\
    \\  turbocrypt decrypt [--key <key-file>] [--password] <source> <destination>
    \\                     [options]
    \\      Decrypt a file or directory
    \\
    \\  turbocrypt verify [--key <key-file>] [--password] [--quick] <source> [options]
    \\      Verify integrity of encrypted files without decrypting
    \\      Use --quick to only check the header MAC (faster, but does not verify
    \\      the data)
    \\
    \\  turbocrypt list [--key <key-file>] [--password] [--encrypted-filenames]
    \\                  <directory> [options]
    \\      List contents of encrypted directory
    \\      With --encrypted-filenames, decrypts filenames (requires the right key)
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
++ mount_usage_text ++
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
    \\  --password           Prompt for a password (protected keys are detected)
    \\  --context <string>   Context string for key derivation (an independent key
    \\                       namespace). The same context is needed to decrypt
    \\  --threads <n>        Number of worker threads (default: CPU count, max 64)
    \\  --buffer-size <size> Buffer size in bytes (default: 4194304 = 4MB)
    \\  --in-place           Encrypt/decrypt files in place (the source is replaced)
    \\  --force              Overwrite existing files without prompting
    \\  --enc-suffix         Add ".enc" suffix when encrypting, remove when decrypting
    \\                       (skips files without .enc suffix during decryption)
    \\  --encrypted-filenames      Encrypt filenames
    \\                       (keeps the directory structure, encrypts each component)
    \\                       (incompatible with --in-place)
    \\  --exclude <pattern>  Exclude files matching pattern (can use multiple times)
    \\                       Supports: *.ext (extensions), dir/ (directories),
    \\                       exact/path (exact matches), prefix* (wildcards)
    \\  --ignore-symlinks    Ignore symbolic links (skip them during processing)
    \\  --quick              (verify only) Check the header MAC, skip the full check
    \\                       Faster, but only tells whether the key is right
    \\  --dry-run            Show what would be processed without changing files
    \\                       Useful to test exclude patterns
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
++ mount_examples_text;

const mount_usage_text = if (build_options.fuse)
    \\  turbocrypt mount [options] <encrypted-dir> <mountpoint>
    \\      Show the encrypted files of <encrypted-dir> as plain files at <mountpoint>
    \\      <encrypted-dir> is a directory of encrypted files or a container
    \\      Stays in the foreground until the volume is unmounted, --daemon returns
    \\      at once
    \\      Run "turbocrypt mount --help" for the options
    \\
    \\  turbocrypt unmount <mountpoint>
    \\      Unmount a directory mounted with "turbocrypt mount"
    \\
    \\  turbocrypt init [options] <container-dir>
    \\      Create an empty container for "turbocrypt mount", optimized for
    \\      random access. Fill it by copying files into the mounted view.
    \\      Run "turbocrypt init --help" for the options
    \\
else
    "";

const mount_examples_text = if (build_options.fuse)
    \\  turbocrypt mount encrypted/ ~/Volumes/plain
    \\  turbocrypt unmount ~/Volumes/plain
    \\  turbocrypt init container/ && turbocrypt mount container/ ~/Volumes/plain
    \\
else
    "";

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
    encrypted_filenames: bool = false,
    ignore_symlinks: bool = false,
    quick: bool = false,
    dry_run: bool = false,
    remove_password: bool = false,
    exclude_patterns: std.ArrayList([]const u8) = .empty,

    fn deinit(self: *Options, gpa: Allocator) void {
        for (self.exclude_patterns.items) |pattern| gpa.free(pattern);
        self.exclude_patterns.deinit(gpa);
    }
};

const ParsedArgs = struct {
    options: Options,
    positional: []const []const u8,
};

const enc_extension = ".enc";

fn hasEncSuffix(path: []const u8) bool {
    return mem.endsWith(u8, path, enc_extension);
}

fn addEncSuffix(gpa: Allocator, path: []const u8) ![]u8 {
    return mem.concat(gpa, u8, &.{ path, enc_extension });
}

/// Return null rather than inventing a filename when the suffix is absent.
fn stripEncSuffix(gpa: Allocator, path: []const u8) !?[]u8 {
    if (!hasEncSuffix(path)) return null;
    return try gpa.dupe(u8, path[0 .. path.len - enc_extension.len]);
}

/// Use matching names for suffix-based encryption and decryption.
/// Decryption skips files that do not carry the suffix.
fn applyEncSuffix(gpa: Allocator, path: []const u8, is_encrypt: bool) !?[]u8 {
    return if (is_encrypt) try addEncSuffix(gpa, path) else try stripEncSuffix(gpa, path);
}

/// Let command-line choices win while filling in the remaining settings from the config.
fn parseOptions(
    gpa: Allocator,
    io: Io,
    environ_map: *const std.process.Environ.Map,
    args: []const []const u8,
) !ParsedArgs {
    var opts: Options = .{};
    var positional: std.ArrayList([]const u8) = .empty;
    defer positional.deinit(gpa);

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const arg = args[i];

        if (mem.eql(u8, arg, "--key")) {
            if (i + 1 >= args.len) {
                std.debug.print("Error: --key requires a value\n", .{});
                return error.InvalidArguments;
            }
            i += 1;
            opts.key = args[i];
        } else if (mem.eql(u8, arg, "--context")) {
            if (i + 1 >= args.len) {
                std.debug.print("Error: --context requires a value\n", .{});
                return error.InvalidArguments;
            }
            i += 1;
            opts.context = args[i];
        } else if (mem.eql(u8, arg, "--threads")) {
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
        } else if (mem.eql(u8, arg, "--buffer-size")) {
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
        } else if (mem.eql(u8, arg, "--in-place")) {
            opts.in_place = true;
        } else if (mem.eql(u8, arg, "--force")) {
            opts.force = true;
        } else if (mem.eql(u8, arg, "--enc-suffix")) {
            opts.enc_suffix = true;
        } else if (mem.eql(u8, arg, "--encrypted-filenames")) {
            opts.encrypted_filenames = true;
        } else if (mem.eql(u8, arg, "--ignore-symlinks")) {
            opts.ignore_symlinks = true;
        } else if (mem.eql(u8, arg, "--password")) {
            opts.password = true;
        } else if (mem.eql(u8, arg, "--quick")) {
            opts.quick = true;
        } else if (mem.eql(u8, arg, "--dry-run")) {
            opts.dry_run = true;
        } else if (mem.eql(u8, arg, "--remove-password")) {
            opts.remove_password = true;
        } else if (mem.eql(u8, arg, "--exclude")) {
            if (i + 1 >= args.len) {
                std.debug.print("Error: --exclude requires a value\n", .{});
                return error.InvalidArguments;
            }
            i += 1;
            const pattern_copy = try gpa.dupe(u8, args[i]);
            try opts.exclude_patterns.append(gpa, pattern_copy);
        } else if (mem.startsWith(u8, arg, "--")) {
            std.debug.print("Error: Unknown option '{s}'\n", .{arg});
            return error.InvalidArguments;
        } else {
            try positional.append(gpa, arg);
        }
    }

    var cfg: Config = Config.load(gpa, io, environ_map) catch |err| blk: {
        // A bad config should not prevent an otherwise valid command from running.
        if (err != error.FileNotFound) {
            std.debug.print("Warning: Failed to load config file: {}\n", .{err});
        }
        break :blk .{};
    };
    defer cfg.deinit(gpa);

    if (opts.threads == null) {
        opts.threads = cfg.threads;
    }
    if (opts.buffer_size == null) {
        opts.buffer_size = cfg.buffer_size;
    }
    if (!opts.ignore_symlinks and cfg.ignore_symlinks != null) {
        opts.ignore_symlinks = cfg.ignore_symlinks.?;
    }
    if (!opts.encrypted_filenames and cfg.encrypted_filenames != null) {
        opts.encrypted_filenames = cfg.encrypted_filenames.?;
    }

    // Explicit patterns are an override, not an unexpected extra filter.
    if (cfg.exclude_patterns.len > 0 and opts.exclude_patterns.items.len == 0) {
        for (cfg.exclude_patterns) |pattern| {
            const pattern_copy = try gpa.dupe(u8, pattern);
            try opts.exclude_patterns.append(gpa, pattern_copy);
        }
    }

    if (opts.in_place and opts.encrypted_filenames) {
        std.debug.print("Error: --in-place and --encrypted-filenames are incompatible\n", .{});
        std.debug.print("       In-place encryption cannot change filenames\n", .{});
        return error.InvalidArguments;
    }

    return .{
        .options = opts,
        .positional = try positional.toOwnedSlice(gpa),
    };
}

fn getThreadCount(opts: Options) !u32 {
    if (opts.threads) |t| return @min(t, 64);
    const cpu_count = try std.Thread.getCpuCount();
    return @intCast(@min(cpu_count, 16));
}

fn explainConfigError(
    gpa: Allocator,
    environ_map: *const std.process.Environ.Map,
    action: []const u8,
    err: anyerror,
) void {
    const config_path = Config.filePath(gpa, environ_map) catch {
        std.debug.print("Error: Cannot {s} the config file: {}\n", .{ action, err });
        return;
    };
    defer gpa.free(config_path);
    std.debug.print("Error: Cannot {s} config file '{s}': {}\n", .{ action, config_path, err });
}

fn loadConfig(gpa: Allocator, io: Io, environ_map: *const std.process.Environ.Map) !Config {
    return Config.load(gpa, io, environ_map) catch |err| {
        explainConfigError(gpa, environ_map, "read", err);
        return err;
    };
}

fn saveConfig(
    gpa: Allocator,
    io: Io,
    environ_map: *const std.process.Environ.Map,
    cfg: Config,
) !void {
    cfg.save(gpa, io, environ_map) catch |err| {
        explainConfigError(gpa, environ_map, "write", err);
        return err;
    };
}

fn cmdKeygen(
    gpa: Allocator,
    io: Io,
    environ_map: *const std.process.Environ.Map,
    args: []const []const u8,
) !void {
    const parsed = try parseOptions(gpa, io, environ_map, args);
    defer gpa.free(parsed.positional);
    var opts = parsed.options;
    defer opts.deinit(gpa);

    if (parsed.positional.len != 1) {
        std.debug.print("Error: Expected one output file path\n", .{});
        std.debug.print("Usage: turbocrypt keygen [--password] <output-file>\n", .{});
        return error.InvalidArguments;
    }
    if (opts.dry_run) {
        std.debug.print("Error: --dry-run does not apply to keygen\n", .{});
        return error.InvalidArguments;
    }

    const output_path = parsed.positional[0];

    const key = keygen.generate(io);

    var password_buf: ?[]u8 = null;
    defer if (password_buf) |buf| {
        std.crypto.secureZero(u8, buf);
        gpa.free(buf);
    };

    if (opts.password) {
        password_buf = prompt.password(gpa, io, "Enter password to protect key", true) catch |err| {
            if (err == error.PasswordMismatch) {
                std.debug.print("Error: Passwords do not match\n", .{});
                return error.PasswordMismatch;
            }
            return err;
        };
    }

    try keygen.writeKeyFile(gpa, io, output_path, key, password_buf);

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

    fn deinit(self: *ScanResult, gpa: Allocator) void {
        for (self.files.items) |file| {
            gpa.free(file.source_path);
            gpa.free(file.dest_path);
        }
        self.files.deinit(gpa);
    }
};

const ProcessingMode = union(enum) {
    scan_only: ScanResult,
    scan_and_process: struct {
        worker_pool: *worker.Pool,
        progress_tracker: *progress.Tracker,
    },
};

const DirectoryScanContext = struct {
    gpa: Allocator,
    io: Io,
    dest_base: []const u8,
    enc_suffix: bool,
    is_encrypt: bool,
    encrypted_filenames: bool,
    filename_key: [16]u8,
    exclude_patterns: std.ArrayList([]const u8),
    dry_run: bool,
    mode: ProcessingMode,

    fn callback(
        relative_path: []const u8,
        full_path: []const u8,
        is_directory: bool,
        context: *anyopaque,
    ) !void {
        const self: *DirectoryScanContext = @ptrCast(@alignCast(context));

        // Do not create an empty destination directory for excluded content.
        if (fs.matchesExcludePattern(relative_path, self.exclude_patterns)) {
            return;
        }

        if (is_directory) {
            try self.handleDir(relative_path);
            return;
        }

        const dest_relative_path = (try self.destRelativePath(relative_path)) orelse return;
        defer self.gpa.free(dest_relative_path);

        const file = try Io.Dir.openFile(.cwd(), self.io, full_path, .{});
        defer file.close(self.io);
        const file_size = (try file.stat(self.io)).size;

        switch (self.mode) {
            .scan_only => |*scan| {
                const source_path = try self.gpa.dupe(u8, full_path);
                errdefer self.gpa.free(source_path);
                const dest_path = try Io.Dir.path.join(
                    self.gpa,
                    &.{ self.dest_base, dest_relative_path },
                );
                errdefer self.gpa.free(dest_path);
                try scan.files.append(self.gpa, .{
                    .source_path = source_path,
                    .dest_path = dest_path,
                    .size = file_size,
                });
                scan.total_bytes += file_size;
            },
            .scan_and_process => |proc| {
                try self.submitFile(
                    full_path,
                    dest_relative_path,
                    file_size,
                    proc.worker_pool,
                    proc.progress_tracker,
                );
            },
        }
    }

    /// Mirror a source directory unless this is only a dry run.
    fn handleDir(self: *DirectoryScanContext, relative_path: []const u8) !void {
        var transformed: ?[]u8 = null;
        defer if (transformed) |name| self.gpa.free(name);
        if (self.encrypted_filenames) {
            transformed = try self.transformPath(relative_path, "directory name");
        }

        if (self.dry_run) return;

        const dest_dir = try Io.Dir.path.join(
            self.gpa,
            &.{ self.dest_base, transformed orelse relative_path },
        );
        defer self.gpa.free(dest_dir);
        try self.ensureOutputDir(dest_dir, null);
    }

    fn ensureOutputDir(
        self: *DirectoryScanContext,
        dest_dir: []const u8,
        for_file: ?[]const u8,
    ) !void {
        try refuseContainerDestination(self.io, dest_dir);
        fs.ensureDir(self.io, dest_dir) catch |err| {
            std.debug.print("\n[ERROR] Failed to create directory: {s}\n", .{dest_dir});
            if (for_file) |file| std.debug.print("        For file: {s}\n", .{file});
            std.debug.print("        Reason: {}\n", .{err});
            if (self.encrypted_filenames and !self.is_encrypt) {
                std.debug.print("        Suggestion: The name may be corrupted or encrypted with a different key\n", .{});
            }
            return err;
        };
    }

    /// Choose the destination name for one source file.
    /// A missing suffix means there is nothing to decrypt.
    ///
    /// Apply the suffix before encrypting the name so a round trip restores it.
    fn destRelativePath(self: *DirectoryScanContext, relative_path: []const u8) !?[]u8 {
        if (self.is_encrypt) {
            const named = if (self.enc_suffix)
                try addEncSuffix(self.gpa, relative_path)
            else
                try self.gpa.dupe(u8, relative_path);
            if (!self.encrypted_filenames) return named;
            defer self.gpa.free(named);
            return try self.transformPath(named, "filename");
        }

        const named = if (self.encrypted_filenames)
            try self.transformPath(relative_path, "filename")
        else
            try self.gpa.dupe(u8, relative_path);
        if (!self.enc_suffix) return named;
        defer self.gpa.free(named);
        return stripEncSuffix(self.gpa, named);
    }

    /// Convert a path name and turn invalid encrypted names into useful errors.
    fn transformPath(self: *DirectoryScanContext, path: []const u8, what: []const u8) ![]u8 {
        const sep = Io.Dir.path.sep;
        const result = if (self.is_encrypt)
            filename_crypto.encryptPath(self.gpa, path, self.filename_key, sep)
        else
            filename_crypto.decryptPathForFilesystem(self.gpa, path, self.filename_key, sep);
        return result catch |err| {
            std.debug.print("\n[ERROR] Failed to {s} {s}: {s}\n", .{
                if (self.is_encrypt) "encrypt" else "decrypt",
                what,
                path,
            });
            std.debug.print("        Reason: {}\n", .{err});
            if (err == filename_crypto.Error.EncryptedFilenameTooLong) {
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
        worker_pool: *worker.Pool,
        progress_tracker: *progress.Tracker,
    ) !void {
        progress_tracker.addTotalFile();
        progress_tracker.addTotalBytes(file_size);

        // The pool owns these copies until it has finished the job.
        const source_path = try self.gpa.dupe(u8, full_path);
        errdefer self.gpa.free(source_path);
        const dest_path = try Io.Dir.path.join(self.gpa, &.{ self.dest_base, dest_relative_path });
        errdefer self.gpa.free(dest_path);

        if (!self.dry_run) try self.ensureParent(dest_path, full_path);

        try worker_pool.submitJob(.{
            .source_path = source_path,
            .dest_path = dest_path,
            .operation = if (self.is_encrypt) .encrypt else .decrypt,
            .file_size = file_size,
        });
    }

    fn ensureParent(
        self: *DirectoryScanContext,
        dest_path: []const u8,
        full_path: []const u8,
    ) !void {
        const dest_dir = Io.Dir.path.dirname(dest_path) orelse return;
        try self.ensureOutputDir(dest_dir, full_path);
    }
};

/// Confirm that a file exists without reading it or creating output.
fn dryRunSingleFile(io: Io, source_path: []const u8, verb: []const u8) !void {
    _ = try Io.Dir.statFile(.cwd(), io, source_path, .{});
    std.debug.print("[DRY RUN] Would {s} 1 file...\n", .{verb});
}

/// Keep file commands out of containers, which only the mount supports safely.
fn refuseContainerOperand(gpa: Allocator, io: Io, path: []const u8) !void {
    const enclosure = (try container.enclosingRoot(gpa, io, path)) orelse return;
    defer enclosure.deinit(gpa);
    container.explainRefusal(enclosure.path, enclosure.root);
    return error.InvalidArguments;
}

fn refuseContainerDestination(io: Io, dest_dir: []const u8) !void {
    if (!container.hasDescriptorAt(.cwd(), io, dest_dir)) return;
    container.explainRefusal(dest_dir, dest_dir);
    return error.ContainerInTree;
}

fn cmdProcess(
    gpa: Allocator,
    io: Io,
    environ_map: *const std.process.Environ.Map,
    args: []const []const u8,
    is_encrypt: bool,
) !void {
    const op_name = if (is_encrypt) "encrypt" else "decrypt";
    const op_gerund = if (is_encrypt) "Encrypting" else "Decrypting";
    const op_noun = if (is_encrypt) "Encryption" else "Decryption";

    const parsed = try parseOptions(gpa, io, environ_map, args);
    defer gpa.free(parsed.positional);
    var opts = parsed.options;
    defer opts.deinit(gpa);

    if (parsed.positional.len < 1) {
        std.debug.print("Error: Missing required arguments\n", .{});
        std.debug.print("Usage: turbocrypt {s} [--key <key-file>] <source> [destination] [options]\n", .{op_name});
        return error.InvalidArguments;
    }
    if (parsed.positional.len > 2) {
        std.debug.print("Error: Expected a source and at most one destination\n", .{});
        std.debug.print("Usage: turbocrypt {s} [--key <key-file>] <source> [destination] [options]\n", .{op_name});
        return error.InvalidArguments;
    }

    const source_path = parsed.positional[0];

    const is_dir = fs.isDir(io, source_path) catch false;

    var dest_path_buf: ?[]u8 = null;
    defer if (dest_path_buf) |buf| gpa.free(buf);

    const dest_path = if (parsed.positional.len >= 2)
        parsed.positional[1]
    else if (opts.in_place) blk: {
        // Rename an in-place file, but leave an in-place directory where it is.
        if (!opts.enc_suffix or is_dir) break :blk source_path;
        const renamed = try applyEncSuffix(gpa, source_path, is_encrypt) orelse {
            std.debug.print("Error: Source file must have .enc suffix when using --enc-suffix\n", .{});
            return error.InvalidArguments;
        };
        dest_path_buf = renamed;
        break :blk renamed;
    } else {
        std.debug.print("Error: Destination path required (or use --in-place)\n", .{});
        return error.InvalidArguments;
    };

    const relation = try fs.pathRelation(gpa, io, source_path, dest_path);
    if (relation == .same and !opts.in_place) {
        std.debug.print("Error: Source and destination must differ unless --in-place is used\n", .{});
        return error.InvalidArguments;
    }
    if (is_dir and relation == .descendant) {
        std.debug.print("Error: Destination directory must not be inside the source directory\n", .{});
        return error.InvalidArguments;
    }

    // Refuse unsupported container paths before asking for secrets or changing files.
    try refuseContainerOperand(gpa, io, source_path);
    if (relation != .same) try refuseContainerOperand(gpa, io, dest_path);

    const key = key_loader.load(gpa, io, environ_map, opts.key, opts.password) catch |err| {
        return key_loader.explainLoadError(gpa, environ_map, err, opts.key);
    };

    const derived_keys = crypto.deriveKeys(key, opts.context);

    if (is_dir) {
        std.debug.print("{s} directory: {s} -> {s}\n", .{ op_gerund, source_path, dest_path });

        if (!opts.dry_run) try fs.ensureDir(io, dest_path);

        const thread_count = try getThreadCount(opts);

        // Finish finding inputs before changing any, so the walk cannot find its own output.
        if (opts.in_place) {
            std.debug.print("Scanning files...\n", .{});

            var scan_ctx: DirectoryScanContext = .{
                .gpa = gpa,
                .io = io,
                .dest_base = dest_path,
                .enc_suffix = opts.enc_suffix,
                .is_encrypt = is_encrypt,
                .encrypted_filenames = opts.encrypted_filenames,
                .filename_key = derived_keys.filename_key,
                .exclude_patterns = opts.exclude_patterns,
                .dry_run = opts.dry_run,
                .mode = .{ .scan_only = .{} },
            };
            defer scan_ctx.mode.scan_only.deinit(gpa);

            fs.walkDir(
                gpa,
                io,
                source_path,
                DirectoryScanContext.callback,
                &scan_ctx,
                opts.ignore_symlinks,
            ) catch |err| {
                std.debug.print("\n[FATAL] Directory scanning failed\n", .{});
                return err;
            };

            const scanned = &scan_ctx.mode.scan_only;
            if (opts.dry_run) {
                std.debug.print("[DRY RUN] Would process {d} files...\n", .{
                    scanned.files.items.len,
                });
            } else {
                std.debug.print("{s} {d} files...\n", .{ op_gerund, scanned.files.items.len });
            }

            var tracker = progress.Tracker.init(io, scanned.files.items.len, scanned.total_bytes);
            var pool = try worker.Pool.init(
                gpa,
                io,
                thread_count,
                derived_keys,
                &tracker,
                false,
                opts.dry_run,
            );
            defer pool.deinit();

            try tracker.startDisplay();
            defer tracker.stopDisplay();

            for (scanned.files.items) |file| {
                const source_path_dup = try gpa.dupe(u8, file.source_path);
                errdefer gpa.free(source_path_dup);
                const dest_path_dup = try gpa.dupe(u8, file.dest_path);
                errdefer gpa.free(dest_path_dup);

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
                std.debug.print("Scanning and {s}...\n", .{
                    if (is_encrypt) "encrypting" else "decrypting",
                });
            }

            var tracker = progress.Tracker.init(io, 0, 0);
            var pool = try worker.Pool.init(
                gpa,
                io,
                thread_count,
                derived_keys,
                &tracker,
                false,
                opts.dry_run,
            );
            defer pool.deinit();

            try tracker.startDisplay();
            defer tracker.stopDisplay();

            // Start work now so large directory walks do not hold everything in memory.
            try pool.start();

            var ctx: DirectoryScanContext = .{
                .gpa = gpa,
                .io = io,
                .dest_base = dest_path,
                .is_encrypt = is_encrypt,
                .enc_suffix = opts.enc_suffix,
                .encrypted_filenames = opts.encrypted_filenames,
                .filename_key = derived_keys.filename_key,
                .exclude_patterns = opts.exclude_patterns,
                .dry_run = opts.dry_run,
                .mode = .{ .scan_and_process = .{
                    .worker_pool = &pool,
                    .progress_tracker = &tracker,
                } },
            };

            fs.walkDir(
                gpa,
                io,
                source_path,
                DirectoryScanContext.callback,
                &ctx,
                opts.ignore_symlinks,
            ) catch |err| {
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
        if (fs.matchesExcludePattern(source_path, opts.exclude_patterns)) {
            std.debug.print("Skipping excluded file: {s}\n", .{source_path});
            return;
        }

        std.debug.print("{s} file: {s} -> {s}\n", .{ op_gerund, source_path, dest_path });

        if (opts.dry_run) return dryRunSingleFile(io, source_path, "process");

        if (Io.Dir.path.dirname(dest_path)) |dest_dir| {
            try fs.ensureDir(io, dest_dir);
        }

        if (is_encrypt) {
            processor.encryptFile(gpa, io, source_path, dest_path, derived_keys) catch |err| {
                std.debug.print("\n[ERROR] Encryption failed\n", .{});
                std.debug.print("        File: {s}\n", .{source_path});
                worker.printErrorDetails(err, true);
                return err;
            };
        } else {
            processor.decryptFile(gpa, io, source_path, dest_path, derived_keys) catch |err| {
                std.debug.print("\n[ERROR] Decryption failed\n", .{});
                std.debug.print("        File: {s}\n", .{source_path});
                worker.printErrorDetails(err, false);
                return err;
            };
        }

        // Suffix mode has already published the renamed file, so retire the old name.
        if (dest_path_buf != null) {
            try Io.Dir.deleteFile(.cwd(), io, source_path);
        }
        std.debug.print("{s} complete!\n", .{op_noun});
    }
}

fn cmdEncrypt(
    gpa: Allocator,
    io: Io,
    environ_map: *const std.process.Environ.Map,
    args: []const []const u8,
) !void {
    try cmdProcess(gpa, io, environ_map, args, true);
}

fn cmdDecrypt(
    gpa: Allocator,
    io: Io,
    environ_map: *const std.process.Environ.Map,
    args: []const []const u8,
) !void {
    try cmdProcess(gpa, io, environ_map, args, false);
}

fn cmdVerify(
    gpa: Allocator,
    io: Io,
    environ_map: *const std.process.Environ.Map,
    args: []const []const u8,
) !void {
    const parsed = try parseOptions(gpa, io, environ_map, args);
    defer gpa.free(parsed.positional);
    var opts = parsed.options;
    defer opts.deinit(gpa);

    if (parsed.positional.len != 1) {
        std.debug.print("Error: Expected one source path\n", .{});
        std.debug.print("Usage: turbocrypt verify [--key <key-file>] <source> [options]\n", .{});
        return error.InvalidArguments;
    }

    const source_path = parsed.positional[0];
    try refuseContainerOperand(gpa, io, source_path);

    const key = key_loader.load(gpa, io, environ_map, opts.key, opts.password) catch |err| {
        return key_loader.explainLoadError(gpa, environ_map, err, opts.key);
    };

    const derived_keys = crypto.deriveKeys(key, opts.context);

    const is_dir = fs.isDir(io, source_path) catch false;

    if (is_dir) {
        std.debug.print("Verifying directory: {s}\n", .{source_path});

        const thread_count = try getThreadCount(opts);

        // Count first so progress starts with an honest total.
        std.debug.print("Scanning files...\n", .{});

        var scan_ctx: DirectoryScanContext = .{
            .gpa = gpa,
            .io = io,
            .dest_base = source_path, // Verification never builds a destination path.
            .enc_suffix = false, // Consider encrypted files whether or not they use the suffix.
            .is_encrypt = false, // Verification does not transform file names.
            .encrypted_filenames = false,
            .filename_key = derived_keys.filename_key,
            .exclude_patterns = opts.exclude_patterns,
            .dry_run = opts.dry_run,
            .mode = .{ .scan_only = .{} },
        };
        defer scan_ctx.mode.scan_only.deinit(gpa);

        fs.walkDir(
            gpa,
            io,
            source_path,
            DirectoryScanContext.callback,
            &scan_ctx,
            opts.ignore_symlinks,
        ) catch |err| {
            std.debug.print("\n[FATAL] Directory scanning failed\n", .{});
            return err;
        };

        const scanned = &scan_ctx.mode.scan_only;
        if (opts.dry_run) {
            std.debug.print("[DRY RUN] Would verify {d} files...\n", .{scanned.files.items.len});
        } else {
            std.debug.print("Verifying {d} files...\n", .{scanned.files.items.len});
        }

        var tracker = progress.Tracker.init(io, scanned.files.items.len, scanned.total_bytes);
        var pool = try worker.Pool.init(
            gpa,
            io,
            thread_count,
            derived_keys,
            &tracker,
            opts.quick,
            opts.dry_run,
        );
        defer pool.deinit();

        try tracker.startDisplay();
        defer tracker.stopDisplay();

        for (scanned.files.items) |file| {
            const source_path_dup = try gpa.dupe(u8, file.source_path);
            try pool.submitJob(.{
                .source_path = source_path_dup,
                .dest_path = null,
                .operation = .verify,
                .file_size = file.size,
            });
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
        if (fs.matchesExcludePattern(source_path, opts.exclude_patterns)) {
            std.debug.print("Skipping excluded file: {s}\n", .{source_path});
            return;
        }

        std.debug.print("Verifying file: {s}\n", .{source_path});
        if (opts.dry_run) return dryRunSingleFile(io, source_path, "verify");

        processor.verifyFile(gpa, io, source_path, derived_keys, opts.quick) catch |err| {
            std.debug.print("\n[VERIFY FAILED] {s}\n", .{source_path});
            worker.printErrorDetails(err, false);
            return err;
        };

        std.debug.print("File verified successfully!\n", .{});
    }
}

const ListContext = struct {
    gpa: Allocator,
    io: Io,
    exclude_patterns: std.ArrayList([]const u8),
    file_paths: std.ArrayList([]const u8) = .empty,
    file_sizes: std.ArrayList(u64) = .empty,
    total_bytes: u64 = 0,
    total_files: u64 = 0,

    fn callback(
        relative_path: []const u8,
        full_path: []const u8,
        is_directory: bool,
        context: *anyopaque,
    ) !void {
        const self: *ListContext = @ptrCast(@alignCast(context));

        if (is_directory) return;

        if (fs.matchesExcludePattern(relative_path, self.exclude_patterns)) {
            return;
        }

        const stat = try Io.Dir.statFile(.cwd(), self.io, full_path, .{});
        const file_size = stat.size;

        const path_copy = try self.gpa.dupe(u8, relative_path);
        try self.file_paths.append(self.gpa, path_copy);
        try self.file_sizes.append(self.gpa, file_size);

        self.total_bytes += file_size;
        self.total_files += 1;
    }
};

fn cmdList(
    gpa: Allocator,
    io: Io,
    environ_map: *const std.process.Environ.Map,
    args: []const []const u8,
) !void {
    const parsed = try parseOptions(gpa, io, environ_map, args);
    defer gpa.free(parsed.positional);
    var opts = parsed.options;
    defer opts.deinit(gpa);

    if (parsed.positional.len != 1) {
        std.debug.print("Error: Expected one directory path\n", .{});
        std.debug.print("Usage: turbocrypt list [--key <key-file>] [--encrypted-filenames] <directory> [options]\n", .{});
        return error.InvalidArguments;
    }

    const source_path = parsed.positional[0];

    const is_dir = fs.isDir(io, source_path) catch {
        std.debug.print("Error: Path is not a directory: {s}\n", .{source_path});
        return error.InvalidPath;
    };

    if (!is_dir) {
        std.debug.print("Error: Path is not a directory: {s}\n", .{source_path});
        std.debug.print("Usage: turbocrypt list works only with directories\n", .{});
        return error.InvalidPath;
    }
    try refuseContainerOperand(gpa, io, source_path);

    // Plain listings should work without asking for an unrelated key.
    var filename_key: [16]u8 = undefined;
    if (opts.encrypted_filenames) {
        const key = key_loader.load(gpa, io, environ_map, opts.key, opts.password) catch |err| {
            return key_loader.explainLoadError(gpa, environ_map, err, opts.key);
        };

        const derived_keys = crypto.deriveKeys(key, opts.context);
        filename_key = derived_keys.filename_key;
    }

    std.debug.print("Listing contents: {s}\n\n", .{source_path});

    var list_ctx: ListContext = .{
        .gpa = gpa,
        .io = io,
        .exclude_patterns = opts.exclude_patterns,
    };
    defer {
        for (list_ctx.file_paths.items) |path| gpa.free(path);
        list_ctx.file_paths.deinit(gpa);
        list_ctx.file_sizes.deinit(gpa);
    }

    fs.walkDir(
        gpa,
        io,
        source_path,
        ListContext.callback,
        &list_ctx,
        opts.ignore_symlinks,
    ) catch |err| {
        std.debug.print("Error: Failed to walk directory\n", .{});
        return err;
    };

    if (list_ctx.total_files == 0) {
        std.debug.print("Directory is empty (or all files excluded by patterns)\n", .{});
        return;
    }

    for (list_ctx.file_paths.items, list_ctx.file_sizes.items) |file_path, file_size| {
        const display_path = if (opts.encrypted_filenames) blk: {
            const decrypted = filename_crypto.decryptPathForFilesystem(
                gpa,
                file_path,
                filename_key,
                Io.Dir.path.sep,
            ) catch |err| {
                std.debug.print("  {s} ({s}) [decrypt error: {}]\n", .{
                    file_path,
                    formatSize(file_size),
                    err,
                });
                continue;
            };
            break :blk decrypted;
        } else try gpa.dupe(u8, file_path);
        defer gpa.free(display_path);

        std.debug.print("  {s} ({s})\n", .{ display_path, formatSize(file_size) });
    }

    std.debug.print("\nTotal: {d} file{s}, {s}\n", .{
        list_ctx.total_files,
        if (list_ctx.total_files == 1) "" else "s",
        formatSize(list_ctx.total_bytes),
    });
}

/// The returned view is temporary and changes with the next call on this thread.
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
        return mem.print(&size_buf.buf, "{d:.1} TB", .{bytes_f / tb}) catch "?.? TB";
    } else if (bytes_f >= gb) {
        return mem.print(&size_buf.buf, "{d:.1} GB", .{bytes_f / gb}) catch "?.? GB";
    } else if (bytes_f >= mb) {
        return mem.print(&size_buf.buf, "{d:.1} MB", .{bytes_f / mb}) catch "?.? MB";
    } else if (bytes_f >= kb) {
        return mem.print(&size_buf.buf, "{d:.1} KB", .{bytes_f / kb}) catch "?.? KB";
    } else {
        return mem.print(&size_buf.buf, "{d} bytes", .{bytes}) catch "? bytes";
    }
}

fn cmdChangePassword(
    gpa: Allocator,
    io: Io,
    environ_map: *const std.process.Environ.Map,
    args: []const []const u8,
) !void {
    const parsed = try parseOptions(gpa, io, environ_map, args);
    defer gpa.free(parsed.positional);
    var opts = parsed.options;
    defer opts.deinit(gpa);

    if (parsed.positional.len != 1) {
        std.debug.print("Error: Expected one key file path\n", .{});
        std.debug.print("Usage: turbocrypt change-password [--remove-password] <key-file>\n", .{});
        return error.InvalidArguments;
    }
    if (opts.dry_run) {
        std.debug.print("Error: --dry-run does not apply to change-password\n", .{});
        return error.InvalidArguments;
    }

    const key_path = parsed.positional[0];
    const remove_password = opts.remove_password;

    // The two key formats have distinct sizes.
    const file_size = blk: {
        const file = try Io.Dir.openFile(.cwd(), io, key_path, .{});
        defer file.close(io);
        break :blk (try file.stat(io)).size;
    };

    if (file_size != keygen.plain_key_file_size and !keygen.isProtectedFileSize(file_size)) {
        std.debug.print("Error: Invalid key file size (expected {d}, {d}, or {d} bytes, got {d})\n", .{
            keygen.plain_key_file_size,
            keygen.legacy_protected_key_file_size,
            keygen.protected_key_file_size,
            file_size,
        });
        return error.InvalidKeyFile;
    }

    const is_protected = keygen.isProtectedFileSize(file_size);

    var actual_key: [16]u8 = undefined;

    if (is_protected) {
        std.debug.print("Current key is password-protected\n", .{});

        const old_password_buf = try prompt.password(gpa, io, "Enter current password", false);
        defer {
            std.crypto.secureZero(u8, old_password_buf);
            gpa.free(old_password_buf);
        }

        actual_key = keygen.readKeyFile(io, key_path, old_password_buf) catch |err| {
            if (err == error.InvalidPassword) {
                std.debug.print("Error: Invalid current password\n", .{});
                return error.InvalidPassword;
            }
            return err;
        };

        if (remove_password) {
            try keygen.writeKeyFile(gpa, io, key_path, actual_key, null);
            std.debug.print("Password protection removed from key file: {s}\n", .{key_path});
            std.debug.print("WARNING: The key is now stored in plain text. Keep it secure!\n", .{});
            return;
        } else {
            const new_password_buf = try prompt.password(gpa, io, "Enter new password", true);
            defer {
                std.crypto.secureZero(u8, new_password_buf);
                gpa.free(new_password_buf);
            }

            try keygen.writeKeyFile(gpa, io, key_path, actual_key, new_password_buf);
            std.debug.print("Password changed successfully for key file: {s}\n", .{key_path});
        }
    } else {
        if (remove_password) {
            std.debug.print("Error: Key is not password-protected\n", .{});
            return error.InvalidArguments;
        }

        std.debug.print("Current key is not password-protected\n", .{});

        actual_key = try keygen.readKeyFile(io, key_path, null);

        const new_password_buf = try prompt.password(gpa, io, "Enter new password", true);
        defer {
            std.crypto.secureZero(u8, new_password_buf);
            gpa.free(new_password_buf);
        }

        try keygen.writeKeyFile(gpa, io, key_path, actual_key, new_password_buf);
        std.debug.print("Password protection added to key file: {s}\n", .{key_path});
    }
}

const PatternOp = enum { add, remove };

fn modifyExcludePattern(
    cfg: *Config,
    gpa: Allocator,
    pattern: []const u8,
    op: PatternOp,
) !void {
    switch (op) {
        .add => {
            for (cfg.exclude_patterns) |existing| {
                if (mem.eql(u8, existing, pattern)) {
                    std.debug.print("Pattern '{s}' already in exclude list\n", .{pattern});
                    return;
                }
            }

            var new_patterns = try gpa.alloc([]const u8, cfg.exclude_patterns.len + 1);
            var duped_count: usize = 0;
            errdefer {
                for (new_patterns[0..duped_count]) |p| gpa.free(p);
                gpa.free(new_patterns);
            }
            for (cfg.exclude_patterns, 0..) |old_pattern, i| {
                new_patterns[i] = try gpa.dupe(u8, old_pattern);
                duped_count += 1;
            }
            new_patterns[cfg.exclude_patterns.len] = try gpa.dupe(u8, pattern);

            for (cfg.exclude_patterns) |old_pattern| {
                gpa.free(old_pattern);
            }
            if (cfg.exclude_patterns.len > 0) {
                gpa.free(cfg.exclude_patterns);
            }

            cfg.exclude_patterns = new_patterns;
            std.debug.print("Added exclude pattern: {s}\n", .{pattern});
        },
        .remove => {
            var found_index: ?usize = null;
            for (cfg.exclude_patterns, 0..) |existing, i| {
                if (mem.eql(u8, existing, pattern)) {
                    found_index = i;
                    break;
                }
            }

            if (found_index == null) {
                std.debug.print("Pattern '{s}' not found in exclude list\n", .{pattern});
                return;
            }

            if (cfg.exclude_patterns.len == 1) {
                gpa.free(cfg.exclude_patterns[0]);
                gpa.free(cfg.exclude_patterns);
                cfg.exclude_patterns = &.{};
            } else {
                var new_patterns = try gpa.alloc([]const u8, cfg.exclude_patterns.len - 1);
                var new_index: usize = 0;
                for (cfg.exclude_patterns, 0..) |old_pattern, i| {
                    if (i == found_index.?) {
                        gpa.free(old_pattern);
                        continue;
                    }
                    // Keep ownership with the replacement list.
                    new_patterns[new_index] = old_pattern;
                    new_index += 1;
                }

                gpa.free(cfg.exclude_patterns);
                cfg.exclude_patterns = new_patterns;
            }

            std.debug.print("Removed exclude pattern: {s}\n", .{pattern});
        },
    }
}

fn cmdConfig(
    gpa: Allocator,
    io: Io,
    environ_map: *const std.process.Environ.Map,
    args: []const []const u8,
) !void {
    if (args.len < 1) {
        std.debug.print("Error: Missing config subcommand\n", .{});
        std.debug.print("Usage: turbocrypt config <set-key|set-threads|set-buffer-size|add-exclude|remove-exclude|set-ignore-symlinks|set-encrypted-filenames|show>\n", .{});
        return error.InvalidArguments;
    }

    const subcommand = args[0];

    if (mem.eql(u8, subcommand, "set-key")) {
        if (args.len != 2) {
            std.debug.print("Error: Expected one key file path\n", .{});
            std.debug.print("Usage: turbocrypt config set-key <key-file>\n", .{});
            return error.InvalidArguments;
        }

        const key_path = args[1];

        // Read one byte past the largest valid key so oversized files are rejected.
        const max_key_size = keygen.protected_key_file_size + 1;
        const key_data = Io.Dir.readFileAlloc(
            .cwd(),
            io,
            key_path,
            gpa,
            .limited(max_key_size),
        ) catch |err| {
            std.debug.print("Error: Cannot read key file '{s}': {}\n", .{ key_path, err });
            return err;
        };
        defer gpa.free(key_data);

        if (key_data.len != keygen.plain_key_file_size and
            !keygen.isProtectedFileSize(key_data.len))
        {
            std.debug.print("Error: Invalid key file size (expected {d}, {d}, or {d} bytes, got {d})\n", .{
                keygen.plain_key_file_size,
                keygen.legacy_protected_key_file_size,
                keygen.protected_key_file_size,
                key_data.len,
            });
            return error.InvalidKeyFile;
        }

        const is_protected = keygen.isProtectedFileSize(key_data.len);

        // Check the password now rather than saving a key the user cannot unlock.
        if (is_protected) {
            if (key_data[0] != @backingInt(keygen.KeyFormat.password_protected)) {
                std.debug.print("Error: Invalid password-protected key format\n", .{});
                return error.InvalidKeyFile;
            }

            const password_buf = try prompt.password(
                gpa,
                io,
                "Enter key password (to verify)",
                false,
            );
            defer {
                std.crypto.secureZero(u8, password_buf);
                gpa.free(password_buf);
            }

            _ = password.unprotectKey(key_data[1..], password_buf) catch |err| {
                std.debug.print("Error: Cannot decrypt key (wrong password?): {}\n", .{err});
                return err;
            };

            std.debug.print("Password verified successfully.\n", .{});
        }

        // Store protected keys exactly as they appear on disk.
        var cfg = try loadConfig(gpa, io, environ_map);
        defer cfg.deinit(gpa);

        const new_key = try gpa.dupe(u8, key_data);
        if (cfg.key) |old_key| {
            std.crypto.secureZero(u8, @constCast(old_key));
            gpa.free(old_key);
        }
        cfg.key = new_key;
        try saveConfig(gpa, io, environ_map, cfg);

        const config_path = try Config.filePath(gpa, environ_map);
        defer gpa.free(config_path);

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
    } else if (mem.eql(u8, subcommand, "set-threads")) {
        if (args.len != 2) {
            std.debug.print("Error: Expected one thread count\n", .{});
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

        var cfg = try loadConfig(gpa, io, environ_map);
        defer cfg.deinit(gpa);

        cfg.threads = threads;
        try saveConfig(gpa, io, environ_map, cfg);

        std.debug.print("Default thread count set to: {d}\n", .{threads});
    } else if (mem.eql(u8, subcommand, "set-buffer-size")) {
        if (args.len != 2) {
            std.debug.print("Error: Expected one buffer size\n", .{});
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

        var cfg = try loadConfig(gpa, io, environ_map);
        defer cfg.deinit(gpa);

        cfg.buffer_size = buffer_size;
        try saveConfig(gpa, io, environ_map, cfg);

        std.debug.print("Default buffer size set to: {d} bytes\n", .{buffer_size});
    } else if (mem.eql(u8, subcommand, "add-exclude")) {
        if (args.len != 2) {
            std.debug.print("Error: Expected one exclude pattern\n", .{});
            std.debug.print("Usage: turbocrypt config add-exclude <pattern>\n", .{});
            return error.InvalidArguments;
        }

        var cfg = try loadConfig(gpa, io, environ_map);
        defer cfg.deinit(gpa);

        try modifyExcludePattern(&cfg, gpa, args[1], .add);
        try saveConfig(gpa, io, environ_map, cfg);
    } else if (mem.eql(u8, subcommand, "remove-exclude")) {
        if (args.len != 2) {
            std.debug.print("Error: Expected one exclude pattern\n", .{});
            std.debug.print("Usage: turbocrypt config remove-exclude <pattern>\n", .{});
            return error.InvalidArguments;
        }

        var cfg = try loadConfig(gpa, io, environ_map);
        defer cfg.deinit(gpa);

        try modifyExcludePattern(&cfg, gpa, args[1], .remove);
        try saveConfig(gpa, io, environ_map, cfg);
    } else if (mem.eql(u8, subcommand, "set-ignore-symlinks")) {
        if (args.len != 2) {
            std.debug.print("Error: Expected one value\n", .{});
            std.debug.print("Usage: turbocrypt config set-ignore-symlinks <true|false>\n", .{});
            return error.InvalidArguments;
        }

        const value_str = args[1];
        const value = if (mem.eql(u8, value_str, "true"))
            true
        else if (mem.eql(u8, value_str, "false"))
            false
        else {
            std.debug.print("Error: Invalid value '{s}'. Use 'true' or 'false'\n", .{value_str});
            return error.InvalidArguments;
        };

        var cfg = try loadConfig(gpa, io, environ_map);
        defer cfg.deinit(gpa);

        cfg.ignore_symlinks = value;
        try saveConfig(gpa, io, environ_map, cfg);

        std.debug.print("Ignore symlinks set to: {s}\n", .{if (value) "true" else "false"});
    } else if (mem.eql(u8, subcommand, "set-encrypted-filenames")) {
        if (args.len != 2) {
            std.debug.print("Error: Expected one value\n", .{});
            std.debug.print("Usage: turbocrypt config set-encrypted-filenames <true|false>\n", .{});
            return error.InvalidArguments;
        }

        const value_str = args[1];
        const value = if (mem.eql(u8, value_str, "true"))
            true
        else if (mem.eql(u8, value_str, "false"))
            false
        else {
            std.debug.print("Error: Invalid value '{s}'. Use 'true' or 'false'\n", .{value_str});
            return error.InvalidArguments;
        };

        var cfg = try loadConfig(gpa, io, environ_map);
        defer cfg.deinit(gpa);

        cfg.encrypted_filenames = value;
        try saveConfig(gpa, io, environ_map, cfg);

        std.debug.print("Encrypt filenames set to: {s}\n", .{if (value) "true" else "false"});
    } else if (mem.eql(u8, subcommand, "show")) {
        if (args.len != 1) {
            std.debug.print("Usage: turbocrypt config show\n", .{});
            return error.InvalidArguments;
        }
        var cfg = try loadConfig(gpa, io, environ_map);
        defer cfg.deinit(gpa);

        const config_path = try Config.filePath(gpa, environ_map);
        defer gpa.free(config_path);

        std.debug.print("Current configuration:\n", .{});
        std.debug.print("Config file: {s}\n\n", .{config_path});

        if (cfg.key) |key| {
            const kind = if (keygen.isProtectedFileSize(key.len)) "password-protected" else "plain";
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
        std.debug.print("  2. {s} environment variable", .{key_loader.env_var_name});
        if (environ_map.get(key_loader.env_var_name)) |env_val| {
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

fn cmdBench(gpa: Allocator, io: Io, args: []const []const u8) !void {
    if (args.len != 0) {
        std.debug.print("Usage: turbocrypt bench\n", .{});
        return error.InvalidArguments;
    }
    try bench.run(gpa, io);
}

fn noMountSupport() noreturn {
    std.debug.print("Error: this build of turbocrypt has no mount support\n", .{});
    std.process.exit(1);
}

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;

    const args = try init.minimal.args.toSlice(init.arena.allocator());

    if (args.len < 2) {
        printUsage();
        return;
    }

    const command = args[1];
    const command_args = args[2..];

    if (mem.eql(u8, command, "help") or mem.eql(u8, command, "--help") or
        mem.eql(u8, command, "-h"))
    {
        printUsage();
        return;
    }
    if (mem.eql(u8, command, "version") or mem.eql(u8, command, "--version") or
        mem.eql(u8, command, "-V"))
    {
        printVersion();
        return;
    }

    // Do not begin an operation that cannot obtain secure random bytes.
    {
        var dummy: [1]u8 = undefined;
        io.randomSecure(&dummy) catch |err| {
            std.debug.print("FATAL: Secure randomness unavailable: {}\n", .{err});
            std.debug.print("Cannot safely perform cryptographic operations.\n", .{});
            std.process.exit(1);
        };
    }

    if (mem.eql(u8, command, "keygen")) {
        cmdKeygen(gpa, io, init.environ_map, command_args) catch {
            std.process.exit(1);
        };
    } else if (mem.eql(u8, command, "change-password")) {
        cmdChangePassword(gpa, io, init.environ_map, command_args) catch {
            std.process.exit(1);
        };
    } else if (mem.eql(u8, command, "encrypt")) {
        cmdEncrypt(gpa, io, init.environ_map, command_args) catch {
            std.process.exit(1);
        };
    } else if (mem.eql(u8, command, "decrypt")) {
        cmdDecrypt(gpa, io, init.environ_map, command_args) catch {
            std.process.exit(1);
        };
    } else if (mem.eql(u8, command, "verify")) {
        cmdVerify(gpa, io, init.environ_map, command_args) catch {
            std.process.exit(1);
        };
    } else if (mem.eql(u8, command, "list")) {
        cmdList(gpa, io, init.environ_map, command_args) catch {
            std.process.exit(1);
        };
    } else if (mem.eql(u8, command, "config")) {
        cmdConfig(gpa, io, init.environ_map, command_args) catch {
            std.process.exit(1);
        };
    } else if (mem.eql(u8, command, "git")) {
        git.cmd.run(gpa, io, init.environ_map, command_args) catch {
            std.process.exit(1);
        };
    } else if (mem.eql(u8, command, "bench")) {
        cmdBench(gpa, io, command_args) catch {
            std.process.exit(1);
        };
    } else if (mem.eql(u8, command, "mount")) {
        if (comptime !build_options.fuse) noMountSupport();
        mount_cmd.runMount(gpa, io, init.environ_map, command_args) catch {
            std.process.exit(1);
        };
    } else if (mem.eql(u8, command, "unmount")) {
        if (comptime !build_options.fuse) noMountSupport();
        mount_cmd.runUnmount(gpa, io, command_args) catch {
            std.process.exit(1);
        };
    } else if (mem.eql(u8, command, "init")) {
        if (comptime !build_options.fuse) noMountSupport();
        mount_cmd.runInit(gpa, io, init.environ_map, command_args) catch {
            std.process.exit(1);
        };
    } else {
        std.debug.print("Error: Unknown command '{s}'\n\n", .{command});
        printUsage();
        std.process.exit(1);
    }
}

test "commands reject unsupported arguments before side effects" {
    const gpa = testing.allocator;
    const io = testing.io;
    const root = "tmp/main_extra_arguments";
    const key_path = root ++ "/key";

    Io.Dir.deleteTree(.cwd(), io, root) catch {};
    try Io.Dir.createDirPath(.cwd(), io, root);
    defer Io.Dir.deleteTree(.cwd(), io, root) catch {};
    var environ_map = try Config.testEnviron(gpa, root);
    defer environ_map.deinit();

    try testing.expectError(
        error.InvalidArguments,
        cmdKeygen(gpa, io, &environ_map, &.{ key_path, "ignored" }),
    );
    try testing.expectError(
        error.InvalidArguments,
        cmdKeygen(gpa, io, &environ_map, &.{ "--dry-run", key_path }),
    );
    try testing.expect(!fs.pathExists(io, key_path));
    try testing.expectError(
        error.InvalidArguments,
        cmdProcess(gpa, io, &environ_map, &.{ "source", "destination", "ignored" }, true),
    );
    try testing.expectError(
        error.InvalidArguments,
        cmdVerify(gpa, io, &environ_map, &.{ "source", "ignored" }),
    );
    try testing.expectError(
        error.InvalidArguments,
        cmdList(gpa, io, &environ_map, &.{ "directory", "ignored" }),
    );
    try testing.expectError(
        error.InvalidArguments,
        cmdChangePassword(gpa, io, &environ_map, &.{ key_path, "ignored" }),
    );
    try testing.expectError(
        error.InvalidArguments,
        cmdConfig(gpa, io, &environ_map, &.{ "set-threads", "2", "ignored" }),
    );
    const config_path = try Config.filePath(gpa, &environ_map);
    defer gpa.free(config_path);
    try testing.expect(!fs.pathExists(io, config_path));
    try testing.expectError(error.InvalidArguments, cmdBench(gpa, io, &.{"ignored"}));

    const key: [keygen.key_length]u8 = @splat(0x5a);
    try keygen.writeKeyFile(gpa, io, key_path, key, null);
    try testing.expectError(
        error.InvalidArguments,
        cmdChangePassword(gpa, io, &environ_map, &.{ "--dry-run", key_path }),
    );
    try testing.expectEqualSlices(u8, &key, &try keygen.readKeyFile(io, key_path, null));
}

test "directory processing returns an error when a worker fails" {
    const gpa = testing.allocator;
    const io = testing.io;
    const root = "tmp/main_worker_failure";
    const source = root ++ "/source";
    const destination = root ++ "/destination";
    const key_path = root ++ "/key";

    Io.Dir.deleteTree(.cwd(), io, root) catch {};
    try Io.Dir.createDirPath(.cwd(), io, source);
    defer Io.Dir.deleteTree(.cwd(), io, root) catch {};
    try Io.Dir.writeFile(.cwd(), io, .{
        .sub_path = source ++ "/bad.enc",
        .data = "not ciphertext",
    });
    try keygen.writeKeyFile(gpa, io, key_path, @splat(7), null);

    var environ_map = try Config.testEnviron(gpa, root);
    defer environ_map.deinit();
    const args = [_][]const u8{ "--threads", "1", "--key", key_path, source, destination };
    try testing.expectError(
        error.FileProcessingFailed,
        cmdProcess(gpa, io, &environ_map, &args, false),
    );

    const in_place_args = [_][]const u8{
        "--in-place", "--threads", "1", "--key", key_path, source,
    };
    try testing.expectError(
        error.FileProcessingFailed,
        cmdProcess(gpa, io, &environ_map, &in_place_args, false),
    );
}

test "dry run creates no destination and does not verify a single file" {
    const gpa = testing.allocator;
    const io = testing.io;
    const root = "tmp/main_dry_run";
    const source_dir = root ++ "/source";
    const dir_destination = root ++ "/directory-output";
    const file_destination = root ++ "/missing/file.enc";
    const plain_file = root ++ "/not-encrypted";
    const key_path = root ++ "/key";

    Io.Dir.deleteTree(.cwd(), io, root) catch {};
    try Io.Dir.createDirPath(.cwd(), io, source_dir ++ "/nested");
    defer Io.Dir.deleteTree(.cwd(), io, root) catch {};
    try Io.Dir.writeFile(.cwd(), io, .{
        .sub_path = source_dir ++ "/nested/file",
        .data = "plain text",
    });
    try Io.Dir.writeFile(.cwd(), io, .{ .sub_path = plain_file, .data = "plain text" });
    try keygen.writeKeyFile(gpa, io, key_path, @splat(8), null);

    var environ_map = try Config.testEnviron(gpa, root);
    defer environ_map.deinit();
    const dir_args = [_][]const u8{
        "--dry-run", "--threads", "1", "--key", key_path, source_dir, dir_destination,
    };
    try cmdProcess(gpa, io, &environ_map, &dir_args, true);
    try testing.expect(!fs.pathExists(io, dir_destination));

    const file_args = [_][]const u8{
        "--dry-run", "--key", key_path, source_dir ++ "/nested/file", file_destination,
    };
    try cmdProcess(gpa, io, &environ_map, &file_args, true);
    try testing.expect(!fs.pathExists(io, file_destination));
    try testing.expect(!fs.pathExists(io, root ++ "/missing"));

    // This confirms dry-run verification never reads the file as ciphertext.
    const verify_args = [_][]const u8{ "--dry-run", "--key", key_path, plain_file };
    try cmdVerify(gpa, io, &environ_map, &verify_args);
}

test "decrypted filenames cannot escape the destination" {
    const gpa = testing.allocator;
    const io = testing.io;
    const root = "tmp/main_filename_escape";
    const source = root ++ "/source";
    const destination = root ++ "/destination";
    const plain_path = root ++ "/plain";
    const escaped_path = root ++ "/escaped";
    const key_path = root ++ "/key";
    const key: [16]u8 = @splat(9);
    const derived_keys = crypto.deriveKeys(key, null);

    Io.Dir.deleteTree(.cwd(), io, root) catch {};
    try Io.Dir.createDirPath(.cwd(), io, source);
    defer Io.Dir.deleteTree(.cwd(), io, root) catch {};
    try Io.Dir.writeFile(.cwd(), io, .{ .sub_path = plain_path, .data = "secret" });
    try keygen.writeKeyFile(gpa, io, key_path, key, null);

    const planted_name = try filename_crypto.encrypt(gpa, "../escaped", derived_keys.filename_key);
    defer gpa.free(planted_name);
    const planted_path = try Io.Dir.path.join(gpa, &.{ source, planted_name });
    defer gpa.free(planted_path);
    try processor.encryptFile(gpa, io, plain_path, planted_path, derived_keys);

    var environ_map = try Config.testEnviron(gpa, root);
    defer environ_map.deinit();
    const args = [_][]const u8{
        "--threads", "1", "--encrypted-filenames", "--key", key_path, source, destination,
    };
    try testing.expectError(
        filename_crypto.StrictError.UnsafeDecryptedFilename,
        cmdProcess(gpa, io, &environ_map, &args, false),
    );
    try testing.expect(!fs.pathExists(io, escaped_path));
}

test "the destination cannot be the source or inside it" {
    const gpa = testing.allocator;
    const io = testing.io;
    const root = "tmp/main_destination_overlap";
    const source = root ++ "/source";
    const destination = source ++ "/output";

    Io.Dir.deleteTree(.cwd(), io, root) catch {};
    try Io.Dir.createDirPath(.cwd(), io, source);
    defer Io.Dir.deleteTree(.cwd(), io, root) catch {};
    try Io.Dir.writeFile(.cwd(), io, .{ .sub_path = source ++ "/file", .data = "plain" });

    var environ_map = try Config.testEnviron(gpa, root);
    defer environ_map.deinit();
    const args = [_][]const u8{ source, destination };
    try testing.expectError(error.InvalidArguments, cmdProcess(gpa, io, &environ_map, &args, true));
    try testing.expect(!fs.pathExists(io, destination));

    const same_args = [_][]const u8{ source, source };
    try testing.expectError(
        error.InvalidArguments,
        cmdProcess(gpa, io, &environ_map, &same_args, true),
    );

    const file_path = root ++ "/file";
    try Io.Dir.writeFile(.cwd(), io, .{ .sub_path = file_path, .data = "plain" });
    const same_file_args = [_][]const u8{ file_path, file_path };
    try testing.expectError(
        error.InvalidArguments,
        cmdProcess(gpa, io, &environ_map, &same_file_args, true),
    );

    const source_link = root ++ "/source-link";
    Io.Dir.symLink(.cwd(), io, "source", source_link, .{ .is_directory = true }) catch |err| {
        if (err == error.Unexpected or err == error.AccessDenied) return;
        return err;
    };
    const linked_destination = source_link ++ "/output";
    const linked_args = [_][]const u8{ source, linked_destination };
    try testing.expectError(
        error.InvalidArguments,
        cmdProcess(gpa, io, &environ_map, &linked_args, true),
    );
    try testing.expect(!fs.pathExists(io, linked_destination));
}

test "the ordinary commands stop at a container operand before touching anything" {
    const gpa = testing.allocator;
    const io = testing.io;
    const root = "tmp/main_container_operand";
    const box = root ++ "/box";
    const plain = root ++ "/plain";
    const key_path = root ++ "/key";

    Io.Dir.deleteTree(.cwd(), io, root) catch {};
    try Io.Dir.createDirPath(.cwd(), io, box ++ "/sub");
    try Io.Dir.createDirPath(.cwd(), io, plain);
    defer Io.Dir.deleteTree(.cwd(), io, root) catch {};
    try Io.Dir.writeFile(.cwd(), io, .{
        .sub_path = box ++ "/" ++ container.descriptor_name,
        .data = "marker",
    });
    try Io.Dir.writeFile(.cwd(), io, .{ .sub_path = box ++ "/sub/f", .data = "data" });
    try Io.Dir.writeFile(.cwd(), io, .{ .sub_path = plain ++ "/p", .data = "plain" });
    try keygen.writeKeyFile(gpa, io, key_path, @splat(31), null);
    var environ_map = try Config.testEnviron(gpa, root);
    defer environ_map.deinit();

    try testing.expectError(
        error.InvalidArguments,
        cmdProcess(gpa, io, &environ_map, &.{ "--key", key_path, box, root ++ "/out" }, true),
    );
    const sub_args = [_][]const u8{ "--key", key_path, box ++ "/sub", root ++ "/out" };
    try testing.expectError(
        error.InvalidArguments,
        cmdProcess(gpa, io, &environ_map, &sub_args, false),
    );
    const file_args = [_][]const u8{ "--key", key_path, box ++ "/sub/f", root ++ "/out/f" };
    try testing.expectError(
        error.InvalidArguments,
        cmdProcess(gpa, io, &environ_map, &file_args, false),
    );
    try testing.expect(!fs.pathExists(io, root ++ "/out"));

    // Unsupported containers must not leave a partial destination behind.
    try testing.expectError(
        error.InvalidArguments,
        cmdProcess(gpa, io, &environ_map, &.{ "--key", key_path, plain, box }, true),
    );
    try testing.expectError(
        error.InvalidArguments,
        cmdProcess(gpa, io, &environ_map, &.{ "--key", key_path, plain, box ++ "/new" }, true),
    );
    const new_file_args = [_][]const u8{ "--key", key_path, plain ++ "/p", box ++ "/new/p" };
    try testing.expectError(
        error.InvalidArguments,
        cmdProcess(gpa, io, &environ_map, &new_file_args, true),
    );
    try testing.expect(!fs.pathExists(io, box ++ "/new"));
    try testing.expectError(
        error.InvalidArguments,
        cmdProcess(gpa, io, &environ_map, &.{ "--in-place", "--key", key_path, box }, true),
    );
    try testing.expect(!fs.pathExists(io, box ++ "/sub/" ++ container.descriptor_name));

    try testing.expectError(
        error.InvalidArguments,
        cmdVerify(gpa, io, &environ_map, &.{ "--key", key_path, box }),
    );
    try testing.expectError(
        error.InvalidArguments,
        cmdVerify(gpa, io, &environ_map, &.{ "--key", key_path, box ++ "/sub/f" }),
    );
    try testing.expectError(error.InvalidArguments, cmdList(gpa, io, &environ_map, &.{box}));
    try testing.expectError(
        error.InvalidArguments,
        cmdList(gpa, io, &environ_map, &.{box ++ "/sub"}),
    );
}

test "a container met during the walk or in the output tree stops the command" {
    const gpa = testing.allocator;
    const io = testing.io;
    const root = "tmp/main_container_tree";
    const source = root ++ "/source";
    const key_path = root ++ "/key";

    Io.Dir.deleteTree(.cwd(), io, root) catch {};
    try Io.Dir.createDirPath(.cwd(), io, source ++ "/nested");
    try Io.Dir.createDirPath(.cwd(), io, source ++ "/ok");
    defer Io.Dir.deleteTree(.cwd(), io, root) catch {};
    try Io.Dir.writeFile(.cwd(), io, .{ .sub_path = source ++ "/ok/a", .data = "a" });
    try Io.Dir.writeFile(.cwd(), io, .{
        .sub_path = source ++ "/nested/" ++ container.descriptor_name,
        .data = "marker",
    });
    try Io.Dir.writeFile(.cwd(), io, .{ .sub_path = source ++ "/nested/b", .data = "b" });
    try keygen.writeKeyFile(gpa, io, key_path, @splat(32), null);
    var environ_map = try Config.testEnviron(gpa, root);
    defer environ_map.deinit();

    // Both traversal modes must stop before processing a nested container.
    const out_args = [_][]const u8{ "--threads", "1", "--key", key_path, source, root ++ "/out" };
    try testing.expectError(
        error.ContainerInTree,
        cmdProcess(gpa, io, &environ_map, &out_args, true),
    );
    try testing.expect(!fs.pathExists(io, root ++ "/out/nested"));
    const in_place_args = [_][]const u8{
        "--in-place", "--threads", "1", "--key", key_path, source,
    };
    try testing.expectError(
        error.ContainerInTree,
        cmdProcess(gpa, io, &environ_map, &in_place_args, true),
    );
    try testing.expectError(
        error.ContainerInTree,
        cmdVerify(gpa, io, &environ_map, &.{ "--key", key_path, source }),
    );
    try testing.expectError(error.ContainerInTree, cmdList(gpa, io, &environ_map, &.{source}));

    // A transformed destination must be just as safe as a path from the command line.
    try Io.Dir.deleteTree(.cwd(), io, source ++ "/nested");
    Io.Dir.deleteTree(.cwd(), io, root ++ "/out") catch {};
    try Io.Dir.createDirPath(.cwd(), io, root ++ "/out/ok");
    try Io.Dir.writeFile(.cwd(), io, .{
        .sub_path = root ++ "/out/ok/" ++ container.descriptor_name,
        .data = "marker",
    });
    try testing.expectError(
        error.ContainerInTree,
        cmdProcess(gpa, io, &environ_map, &out_args, true),
    );
    try testing.expect(!fs.pathExists(io, root ++ "/out/ok/a"));
}

// Include tests that belong to the command-line dependencies.
test {
    _ = @import("keygen.zig");
    _ = @import("key_loader.zig");
    _ = @import("Config.zig");
    _ = @import("crypto.zig");
    _ = @import("container.zig");
    _ = @import("processor.zig");
    _ = @import("fs.zig");
    _ = @import("git.zig");
    _ = @import("worker.zig");
    _ = @import("progress.zig");
    _ = @import("filename_crypto.zig");
    _ = @import("unicode.zig");
    _ = @import("git/Manifest.zig");
    _ = @import("git/Repo.zig");
    _ = @import("git/sync.zig");
    _ = @import("git/hooks.zig");
    _ = @import("git/cmd.zig");
    _ = @import("git/integration_test.zig");
    if (build_options.fuse) {
        _ = @import("mount/fuse.zig");
        _ = @import("mount/names.zig");
        _ = @import("mount/table.zig");
        _ = @import("mount/sidecar.zig");
        _ = @import("mount/faults.zig");
        _ = @import("mount/Marks.zig");
        _ = @import("mount/Node.zig");
        _ = @import("mount/raf.zig");
        _ = @import("mount/Mount.zig");
        _ = @import("mount/cmd.zig");
    }
}
