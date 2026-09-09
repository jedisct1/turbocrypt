const std = @import("std");
const crypto = @import("crypto.zig");
const keygen = @import("keygen.zig");
const processor = @import("processor.zig");
const progress = @import("progress.zig");
const worker = @import("worker.zig");

const max_temp_dir_attempts = 16;

fn createTempDir(allocator: std.mem.Allocator, io: std.Io) ![]u8 {
    var attempt: usize = 0;
    while (attempt < max_temp_dir_attempts) : (attempt += 1) {
        var random: u64 = undefined;
        io.random(std.mem.asBytes(&random));
        const path = try std.fmt.allocPrint(allocator, ".turbocrypt-bench-{x}", .{random});
        errdefer allocator.free(path);
        std.Io.Dir.createDir(.cwd(), io, path, .default_dir) catch |err| switch (err) {
            error.PathAlreadyExists => {
                allocator.free(path);
                continue;
            },
            else => return err,
        };
        return path;
    }
    return error.TempDirCollision;
}

const BenchConfig = struct {
    warmup_iterations: usize = 3,
    measured_iterations: usize = 10,
};

const BenchStats = struct {
    durations_ns: std.ArrayList(u64) = .empty,

    fn deinit(self: *BenchStats, allocator: std.mem.Allocator) void {
        self.durations_ns.deinit(allocator);
    }

    fn add(self: *BenchStats, duration_ns: u64, allocator: std.mem.Allocator) !void {
        try self.durations_ns.append(allocator, duration_ns);
    }

    fn mean(self: BenchStats) u64 {
        if (self.durations_ns.items.len == 0) return 0;
        var sum: u64 = 0;
        for (self.durations_ns.items) |d| sum += d;
        return sum / self.durations_ns.items.len;
    }

    fn min(self: BenchStats) u64 {
        if (self.durations_ns.items.len == 0) return 0;
        return std.mem.min(u64, self.durations_ns.items);
    }

    fn max(self: BenchStats) u64 {
        if (self.durations_ns.items.len == 0) return 0;
        return std.mem.max(u64, self.durations_ns.items);
    }

    fn stddev(self: BenchStats) f64 {
        if (self.durations_ns.items.len < 2) return 0.0;
        const mean_val = @as(f64, @floatFromInt(self.mean()));
        var variance: f64 = 0.0;
        for (self.durations_ns.items) |d| {
            const diff = @as(f64, @floatFromInt(d)) - mean_val;
            variance += diff * diff;
        }
        variance /= @as(f64, @floatFromInt(self.durations_ns.items.len));
        return @sqrt(variance);
    }
};

const BenchResult = struct {
    operation: []const u8,
    buffer_size: usize,
    threads: ?u32,
    file_count: usize,
    total_bytes: u64,
    duration_ns: u64,

    fn throughputMbps(self: BenchResult) f64 {
        const duration_s = @as(f64, @floatFromInt(self.duration_ns)) / 1_000_000_000.0;
        const mb = @as(f64, @floatFromInt(self.total_bytes)) / (1024.0 * 1024.0);
        const mbps = mb / duration_s;
        return mbps * 8.0; // Megabits, not megabytes.
    }

    fn print(self: BenchResult) void {
        const mb = @as(f64, @floatFromInt(self.total_bytes)) / (1024.0 * 1024.0);
        const duration_s = @as(f64, @floatFromInt(self.duration_ns)) / 1_000_000_000.0;

        if (self.threads) |t| {
            std.debug.print("  {s:<12} | {d:>8} MB | {d:>3} threads | {d:>9.2} Mb/s | {d:>6.2}s\n", .{
                self.operation,
                @as(u64, @intFromFloat(mb)),
                t,
                self.throughputMbps(),
                duration_s,
            });
        } else {
            std.debug.print("  {s:<12} | {d:>8} MB | {s:>11} | {d:>9.2} Mb/s | {d:>6.2}s\n", .{
                self.operation,
                @as(u64, @intFromFloat(mb)),
                "single",
                self.throughputMbps(),
                duration_s,
            });
        }
    }

    fn printWithStats(self: BenchResult, stats: BenchStats) void {
        const mb = @as(f64, @floatFromInt(self.total_bytes)) / (1024.0 * 1024.0);
        const mean_s = @as(f64, @floatFromInt(stats.mean())) / 1_000_000_000.0;
        const min_s = @as(f64, @floatFromInt(stats.min())) / 1_000_000_000.0;
        const max_s = @as(f64, @floatFromInt(stats.max())) / 1_000_000_000.0;
        const stddev_s = stats.stddev() / 1_000_000_000.0;

        const mean_throughput = (mb / mean_s) * 8.0;

        if (self.threads) |t| {
            std.debug.print("  {s:<12} | {d:>8} MB | {d:>3} threads | {d:>9.2} Mb/s | {d:>6.2}s ±{d:>5.2}s (min: {d:.2}s, max: {d:.2}s)\n", .{
                self.operation,
                @as(u64, @intFromFloat(mb)),
                t,
                mean_throughput,
                mean_s,
                stddev_s,
                min_s,
                max_s,
            });
        } else {
            std.debug.print("  {s:<12} | {d:>8} MB | {s:>11} | {d:>9.2} Mb/s | {d:>6.2}s ±{d:>5.2}s (min: {d:.2}s, max: {d:.2}s)\n", .{
                self.operation,
                @as(u64, @intFromFloat(mb)),
                "single",
                mean_throughput,
                mean_s,
                stddev_s,
                min_s,
                max_s,
            });
        }
    }
};

fn benchSingleThreaded(allocator: std.mem.Allocator, derived_keys: crypto.DerivedKeys, config: BenchConfig, io: std.Io) !void {
    std.debug.print("\n*** Single-Threaded Benchmarks (In-Memory) ***\n", .{});
    std.debug.print("Pure cryptographic operations without file I/O overhead\n", .{});
    std.debug.print("Running {d} warmup + {d} measured iterations per test\n\n", .{ config.warmup_iterations, config.measured_iterations });
    std.debug.print("  {s:<12} | {s:>11} | {s:>11} | {s:>14} | {s:>7}\n", .{
        "Operation",
        "Size",
        "Threads",
        "Throughput",
        "Time (mean ± stddev)",
    });
    std.debug.print("  {s:-<12}-+-{s:-<11}-+-{s:-<11}-+-{s:-<14}-+-{s:-<40}\n", .{ "", "", "", "", "" });

    const test_sizes = [_]usize{
        1 * 1024 * 1024,
        10 * 1024 * 1024,
        100 * 1024 * 1024,
    };

    for (test_sizes) |size| {
        const plaintext = try allocator.alloc(u8, size);
        defer allocator.free(plaintext);
        io.random(plaintext);

        const ciphertext = try allocator.alloc(u8, size + crypto.overhead_size);
        defer allocator.free(ciphertext);

        const decrypted = try allocator.alloc(u8, size);
        defer allocator.free(decrypted);

        var encrypt_stats = BenchStats{};
        defer encrypt_stats.deinit(allocator);

        for (0..config.warmup_iterations) |_| {
            crypto.encryptZeroCopy(ciphertext, plaintext, derived_keys, io);
            std.mem.doNotOptimizeAway(&ciphertext);
        }

        for (0..config.measured_iterations) |_| {
            const start_time = std.Io.Clock.Timestamp.now(io, .awake);
            crypto.encryptZeroCopy(ciphertext, plaintext, derived_keys, io);
            const encrypt_time: u64 = @intCast(start_time.untilNow(io).raw.nanoseconds);
            std.mem.doNotOptimizeAway(&ciphertext);
            try encrypt_stats.add(encrypt_time, allocator);
        }

        const encrypt_result = BenchResult{
            .operation = "Encrypt",
            .buffer_size = size,
            .threads = null,
            .file_count = 1,
            .total_bytes = size,
            .duration_ns = encrypt_stats.mean(),
        };
        encrypt_result.printWithStats(encrypt_stats);

        var decrypt_stats = BenchStats{};
        defer decrypt_stats.deinit(allocator);

        for (0..config.warmup_iterations) |_| {
            try crypto.decryptZeroCopy(decrypted, ciphertext, derived_keys);
            std.mem.doNotOptimizeAway(&decrypted);
        }

        for (0..config.measured_iterations) |_| {
            const start_time = std.Io.Clock.Timestamp.now(io, .awake);
            try crypto.decryptZeroCopy(decrypted, ciphertext, derived_keys);
            const decrypt_time: u64 = @intCast(start_time.untilNow(io).raw.nanoseconds);
            std.mem.doNotOptimizeAway(&decrypted);
            try decrypt_stats.add(decrypt_time, allocator);
        }

        const decrypt_result = BenchResult{
            .operation = "Decrypt",
            .buffer_size = size,
            .threads = null,
            .file_count = 1,
            .total_bytes = size,
            .duration_ns = decrypt_stats.mean(),
        };
        decrypt_result.printWithStats(decrypt_stats);

        if (!std.mem.eql(u8, plaintext, decrypted)) {
            return error.DecryptionMismatch;
        }
    }
}

const ThreadContext = struct {
    inputs: []const []u8,
    outputs: []const []u8,
    derived_keys: crypto.DerivedKeys,
    io: std.Io,
    error_occurred: bool = false,

    fn encryptThread(ctx: *ThreadContext) void {
        for (ctx.inputs, ctx.outputs) |input, output| {
            crypto.encryptZeroCopy(output, input, ctx.derived_keys, ctx.io);
        }
    }

    fn decryptThread(ctx: *ThreadContext) void {
        for (ctx.inputs, ctx.outputs) |input, output| {
            crypto.decryptZeroCopy(output, input, ctx.derived_keys) catch {
                ctx.error_occurred = true;
                return;
            };
        }
    }
};

/// Hand each thread its group of chunks, run `entry` on all of them, and wait.
/// Returns false when a thread reported an error.
fn runOnThreads(
    threads: []std.Thread,
    contexts: []ThreadContext,
    inputs: []const []u8,
    outputs: []const []u8,
    chunks_per_thread: usize,
    derived_keys: crypto.DerivedKeys,
    io: std.Io,
    comptime entry: fn (*ThreadContext) void,
) !bool {
    for (threads, contexts, 0..) |*thread, *context, i| {
        const start = i * chunks_per_thread;
        context.* = .{
            .inputs = inputs[start .. start + chunks_per_thread],
            .outputs = outputs[start .. start + chunks_per_thread],
            .derived_keys = derived_keys,
            .io = io,
        };
        thread.* = try std.Thread.spawn(.{}, entry, .{context});
    }
    for (threads) |thread| thread.join();
    std.mem.doNotOptimizeAway(outputs);
    for (contexts) |context| {
        if (context.error_occurred) return false;
    }
    return true;
}

fn benchMultiThreadedInMemory(allocator: std.mem.Allocator, derived_keys: crypto.DerivedKeys, config: BenchConfig, io: std.Io) !void {
    std.debug.print("\n*** Multi-Threaded Benchmarks (In-Memory) ***\n", .{});
    std.debug.print("Parallel cryptographic operations without file I/O\n", .{});
    std.debug.print("Throughput = total Mb/s across all threads\n", .{});
    std.debug.print("Running {d} warmup + {d} measured iterations per test\n\n", .{ config.warmup_iterations, config.measured_iterations });
    std.debug.print("  {s:<12} | {s:>11} | {s:>11} | {s:>14} | {s:>7}\n", .{
        "Operation",
        "Size",
        "Threads",
        "Throughput",
        "Time (mean ± stddev)",
    });
    std.debug.print("  {s:-<12}-+-{s:-<11}-+-{s:-<11}-+-{s:-<14}-+-{s:-<40}\n", .{ "", "", "", "", "" });

    const chunk_size = 50 * 1024 * 1024;
    const chunks_per_thread = 2;

    const cpu_count = try std.Thread.getCpuCount();
    const thread_counts = [_]u32{ 1, 2, 4, 8, @min(@as(u32, @intCast(cpu_count)), 16) };

    for (thread_counts) |thread_count| {
        const total_chunks = thread_count * chunks_per_thread;
        const total_size = total_chunks * chunk_size;

        // The buffers are allocated once, outside the timed loops.
        var test_data: std.ArrayList([]u8) = .empty;
        defer {
            for (test_data.items) |data| allocator.free(data);
            test_data.deinit(allocator);
        }

        for (0..total_chunks) |_| {
            const data = try allocator.alloc(u8, chunk_size);
            io.random(data);
            try test_data.append(allocator, data);
        }

        var encrypted_outputs: std.ArrayList([]u8) = .empty;
        defer {
            for (encrypted_outputs.items) |output| allocator.free(output);
            encrypted_outputs.deinit(allocator);
        }

        for (0..total_chunks) |_| {
            const output = try allocator.alloc(u8, chunk_size + crypto.overhead_size);
            try encrypted_outputs.append(allocator, output);
        }

        var decrypted_outputs: std.ArrayList([]u8) = .empty;
        defer {
            for (decrypted_outputs.items) |output| allocator.free(output);
            decrypted_outputs.deinit(allocator);
        }

        for (0..total_chunks) |_| {
            const output = try allocator.alloc(u8, chunk_size);
            try decrypted_outputs.append(allocator, output);
        }

        const contexts = try allocator.alloc(ThreadContext, thread_count);
        defer allocator.free(contexts);

        const threads = try allocator.alloc(std.Thread, thread_count);
        defer allocator.free(threads);

        var encrypt_stats = BenchStats{};
        defer encrypt_stats.deinit(allocator);

        for (0..config.warmup_iterations) |_| {
            _ = try runOnThreads(threads, contexts, test_data.items, encrypted_outputs.items, chunks_per_thread, derived_keys, io, ThreadContext.encryptThread);
        }

        for (0..config.measured_iterations) |_| {
            const start_time = std.Io.Clock.Timestamp.now(io, .awake);

            const ok = try runOnThreads(threads, contexts, test_data.items, encrypted_outputs.items, chunks_per_thread, derived_keys, io, ThreadContext.encryptThread);

            const encrypt_time: u64 = @intCast(start_time.untilNow(io).raw.nanoseconds);
            try encrypt_stats.add(encrypt_time, allocator);
            if (!ok) return error.EncryptionFailed;
        }

        const encrypt_result = BenchResult{
            .operation = "Encrypt",
            .buffer_size = chunk_size,
            .threads = thread_count,
            .file_count = total_chunks,
            .total_bytes = total_size,
            .duration_ns = encrypt_stats.mean(),
        };
        encrypt_result.printWithStats(encrypt_stats);

        var decrypt_stats = BenchStats{};
        defer decrypt_stats.deinit(allocator);

        for (0..config.warmup_iterations) |_| {
            _ = try runOnThreads(threads, contexts, encrypted_outputs.items, decrypted_outputs.items, chunks_per_thread, derived_keys, io, ThreadContext.decryptThread);
        }

        for (0..config.measured_iterations) |_| {
            const start_time = std.Io.Clock.Timestamp.now(io, .awake);

            const ok = try runOnThreads(threads, contexts, encrypted_outputs.items, decrypted_outputs.items, chunks_per_thread, derived_keys, io, ThreadContext.decryptThread);

            const decrypt_time: u64 = @intCast(start_time.untilNow(io).raw.nanoseconds);
            try decrypt_stats.add(decrypt_time, allocator);
            if (!ok) return error.DecryptionFailed;
        }

        const decrypt_result = BenchResult{
            .operation = "Decrypt",
            .buffer_size = chunk_size,
            .threads = thread_count,
            .file_count = total_chunks,
            .total_bytes = total_size,
            .duration_ns = decrypt_stats.mean(),
        };
        decrypt_result.printWithStats(decrypt_stats);
    }
}

fn benchMultiThreaded(allocator: std.mem.Allocator, derived_keys: crypto.DerivedKeys, tmp_dir: []const u8, config: BenchConfig, io: std.Io) !void {
    std.debug.print("\n*** Multi-Threaded Benchmarks (File I/O) ***\n", .{});
    std.debug.print("Real-world file encryption with parallel processing\n", .{});
    std.debug.print("Throughput = total Mb/s across all threads\n", .{});
    std.debug.print("Running {d} warmup + {d} measured iterations per test\n\n", .{ config.warmup_iterations, config.measured_iterations });
    std.debug.print("  {s:<12} | {s:>11} | {s:>11} | {s:>14} | {s:>7}\n", .{
        "Operation",
        "Size",
        "Threads",
        "Throughput",
        "Time (mean ± stddev)",
    });
    std.debug.print("  {s:-<12}-+-{s:-<11}-+-{s:-<11}-+-{s:-<14}-+-{s:-<40}\n", .{ "", "", "", "", "" });

    // A large data set keeps the timings meaningful with many threads.
    const file_count = 20;
    const file_size = 50 * 1024 * 1024;
    const total_size = file_count * file_size;

    const cpu_count = try std.Thread.getCpuCount();
    const thread_counts = [_]u32{ 1, 2, 4, 8, @min(@as(u32, @intCast(cpu_count)), 16) };

    // The input files are created once, outside the timed loops.
    std.debug.print("\nGenerating {d} × {d}MB test files...\n", .{ file_count, file_size / (1024 * 1024) });

    var file_paths: std.ArrayList([]u8) = .empty;
    defer {
        for (file_paths.items) |path| allocator.free(path);
        file_paths.deinit(allocator);
    }

    var file_sizes: std.ArrayList(u64) = .empty;
    defer file_sizes.deinit(allocator);

    for (0..file_count) |i| {
        const path = try std.fmt.allocPrint(allocator, "{s}/bench_input_{d}.dat", .{ tmp_dir, i });
        try file_paths.append(allocator, path);
        try file_sizes.append(allocator, file_size);

        const file = try std.Io.Dir.createFile(.cwd(), io, path, .{});
        defer file.close(io);

        const data = try allocator.alloc(u8, file_size);
        defer allocator.free(data);
        io.random(data);
        try file.writeStreamingAll(io, data);
    }

    std.debug.print("Test files ready. Starting benchmarks...\n", .{});

    for (thread_counts) |thread_count| {
        var encrypt_stats = BenchStats{};
        defer encrypt_stats.deinit(allocator);

        for (0..config.warmup_iterations) |_| {
            var tracker = progress.ProgressTracker.init(file_count, total_size, io);
            var pool = try worker.WorkerPool.init(allocator, thread_count, derived_keys, &tracker, false, false, io);
            defer pool.deinit();

            for (file_paths.items, file_sizes.items) |path, size| {
                const source = try allocator.dupe(u8, path);
                const dest = try std.fmt.allocPrint(allocator, "{s}.enc", .{path});

                const job = worker.FileJob{
                    .source_path = source,
                    .dest_path = dest,
                    .operation = .encrypt,
                    .file_size = size,
                };
                try pool.submitJob(job);
            }
            try pool.waitAll();
            if (pool.hadErrors()) return error.BenchmarkFileProcessingFailed;

            for (file_paths.items) |path| {
                const enc_path = try std.fmt.allocPrint(allocator, "{s}.enc", .{path});
                defer allocator.free(enc_path);
                std.Io.Dir.deleteFile(.cwd(), io, enc_path) catch {};
            }
        }

        for (0..config.measured_iterations) |_| {
            const start_time = std.Io.Clock.Timestamp.now(io, .awake);
            {
                var tracker = progress.ProgressTracker.init(file_count, total_size, io);
                var pool = try worker.WorkerPool.init(allocator, thread_count, derived_keys, &tracker, false, false, io);
                defer pool.deinit();

                for (file_paths.items, file_sizes.items) |path, size| {
                    const source = try allocator.dupe(u8, path);
                    const dest = try std.fmt.allocPrint(allocator, "{s}.enc", .{path});

                    const job = worker.FileJob{
                        .source_path = source,
                        .dest_path = dest,
                        .operation = .encrypt,
                        .file_size = size,
                    };
                    try pool.submitJob(job);
                }
                try pool.waitAll();
                if (pool.hadErrors()) return error.BenchmarkFileProcessingFailed;
            }
            const encrypt_time: u64 = @intCast(start_time.untilNow(io).raw.nanoseconds);
            try encrypt_stats.add(encrypt_time, allocator);

            for (file_paths.items) |path| {
                const enc_path = try std.fmt.allocPrint(allocator, "{s}.enc", .{path});
                defer allocator.free(enc_path);
                std.Io.Dir.deleteFile(.cwd(), io, enc_path) catch {};
            }
        }

        const encrypt_result = BenchResult{
            .operation = "Encrypt",
            .buffer_size = file_size,
            .threads = thread_count,
            .file_count = file_count,
            .total_bytes = total_size,
            .duration_ns = encrypt_stats.mean(),
        };
        encrypt_result.printWithStats(encrypt_stats);

        var decrypt_stats = BenchStats{};
        defer decrypt_stats.deinit(allocator);

        // The decrypt passes need encrypted inputs.
        {
            var tracker = progress.ProgressTracker.init(file_count, total_size, io);
            var pool = try worker.WorkerPool.init(allocator, thread_count, derived_keys, &tracker, false, false, io);
            defer pool.deinit();

            for (file_paths.items, file_sizes.items) |path, size| {
                const source = try allocator.dupe(u8, path);
                const dest = try std.fmt.allocPrint(allocator, "{s}.enc", .{path});

                const job = worker.FileJob{
                    .source_path = source,
                    .dest_path = dest,
                    .operation = .encrypt,
                    .file_size = size,
                };
                try pool.submitJob(job);
            }
            try pool.waitAll();
            if (pool.hadErrors()) return error.BenchmarkFileProcessingFailed;
        }

        for (0..config.warmup_iterations) |_| {
            var tracker = progress.ProgressTracker.init(file_count, total_size, io);
            var pool = try worker.WorkerPool.init(allocator, thread_count, derived_keys, &tracker, false, false, io);
            defer pool.deinit();

            for (file_paths.items, file_sizes.items) |path, size| {
                const source = try std.fmt.allocPrint(allocator, "{s}.enc", .{path});
                const dest = try std.fmt.allocPrint(allocator, "{s}.dec", .{path});

                const job = worker.FileJob{
                    .source_path = source,
                    .dest_path = dest,
                    .operation = .decrypt,
                    .file_size = size + crypto.overhead_size,
                };
                try pool.submitJob(job);
            }
            try pool.waitAll();
            if (pool.hadErrors()) return error.BenchmarkFileProcessingFailed;

            for (file_paths.items) |path| {
                const dec_path = try std.fmt.allocPrint(allocator, "{s}.dec", .{path});
                defer allocator.free(dec_path);
                std.Io.Dir.deleteFile(.cwd(), io, dec_path) catch {};
            }
        }

        for (0..config.measured_iterations) |_| {
            const start_time = std.Io.Clock.Timestamp.now(io, .awake);
            {
                var tracker = progress.ProgressTracker.init(file_count, total_size, io);
                var pool = try worker.WorkerPool.init(allocator, thread_count, derived_keys, &tracker, false, false, io);
                defer pool.deinit();

                for (file_paths.items, file_sizes.items) |path, size| {
                    const source = try std.fmt.allocPrint(allocator, "{s}.enc", .{path});
                    const dest = try std.fmt.allocPrint(allocator, "{s}.dec", .{path});

                    const job = worker.FileJob{
                        .source_path = source,
                        .dest_path = dest,
                        .operation = .decrypt,
                        .file_size = size + crypto.overhead_size,
                    };
                    try pool.submitJob(job);
                }
                try pool.waitAll();
                if (pool.hadErrors()) return error.BenchmarkFileProcessingFailed;
            }
            const decrypt_time: u64 = @intCast(start_time.untilNow(io).raw.nanoseconds);
            try decrypt_stats.add(decrypt_time, allocator);

            for (file_paths.items) |path| {
                const dec_path = try std.fmt.allocPrint(allocator, "{s}.dec", .{path});
                defer allocator.free(dec_path);
                std.Io.Dir.deleteFile(.cwd(), io, dec_path) catch {};
            }
        }

        const decrypt_result = BenchResult{
            .operation = "Decrypt",
            .buffer_size = file_size,
            .threads = thread_count,
            .file_count = file_count,
            .total_bytes = total_size,
            .duration_ns = decrypt_stats.mean(),
        };
        decrypt_result.printWithStats(decrypt_stats);

        for (file_paths.items) |path| {
            const enc_path = try std.fmt.allocPrint(allocator, "{s}.enc", .{path});
            defer allocator.free(enc_path);
            std.Io.Dir.deleteFile(.cwd(), io, enc_path) catch {};
        }
    }

    for (file_paths.items) |path| {
        std.Io.Dir.deleteFile(.cwd(), io, path) catch {};
    }
}

pub fn run(allocator: std.mem.Allocator, io: std.Io) !void {
    std.debug.print("\nTurboCrypt Performance Benchmark\n", .{});
    std.debug.print("================================\n", .{});

    // The in-memory passes are fast, so they need more iterations.
    const in_memory_config = BenchConfig{
        .warmup_iterations = 10,
        .measured_iterations = 250,
    };

    const file_io_config = BenchConfig{
        .warmup_iterations = 3,
        .measured_iterations = 10,
    };

    const key = keygen.generate(io);
    const derived_keys = crypto.deriveKeys(key, null);

    const tmp_dir = try createTempDir(allocator, io);
    defer allocator.free(tmp_dir);
    defer std.Io.Dir.deleteTree(.cwd(), io, tmp_dir) catch {};

    try benchSingleThreaded(allocator, derived_keys, in_memory_config, io);
    try benchMultiThreadedInMemory(allocator, derived_keys, in_memory_config, io);
    try benchMultiThreaded(allocator, derived_keys, tmp_dir, file_io_config, io);

    std.debug.print("\nBenchmark completed!\n", .{});
    std.debug.print("Note: Results may vary based on CPU, memory speed, and system load.\n", .{});
}

test "benchmark files use an isolated temporary directory" {
    const testing = std.testing;
    const allocator = testing.allocator;
    const io = testing.io;

    const tmp_dir = try createTempDir(allocator, io);
    defer allocator.free(tmp_dir);
    defer std.Io.Dir.deleteTree(.cwd(), io, tmp_dir) catch {};
    try testing.expect(std.mem.startsWith(u8, tmp_dir, ".turbocrypt-bench-"));

    const test_file = try std.fs.path.join(allocator, &.{ tmp_dir, "bench_input_0.dat" });
    defer allocator.free(test_file);
    try std.Io.Dir.writeFile(.cwd(), io, .{ .sub_path = test_file, .data = "temporary" });

    const data = try std.Io.Dir.readFileAlloc(.cwd(), io, test_file, allocator, .limited(9));
    defer allocator.free(data);
    try testing.expectEqualStrings("temporary", data);
}

test "benchmark thread context processes every assigned chunk" {
    const testing = std.testing;
    const io = testing.io;
    const derived_keys = crypto.deriveKeys(@splat(0x2a), null);
    var input_a = [_]u8{ 1, 2, 3 };
    var input_b = [_]u8{ 4, 5, 6, 7 };
    var encrypted_a: [input_a.len + crypto.overhead_size]u8 = undefined;
    var encrypted_b: [input_b.len + crypto.overhead_size]u8 = undefined;
    var decrypted_a: [input_a.len]u8 = undefined;
    var decrypted_b: [input_b.len]u8 = undefined;
    var inputs = [_][]u8{ &input_a, &input_b };
    var encrypted = [_][]u8{ &encrypted_a, &encrypted_b };
    var decrypted = [_][]u8{ &decrypted_a, &decrypted_b };

    var context = ThreadContext{
        .inputs = &inputs,
        .outputs = &encrypted,
        .derived_keys = derived_keys,
        .io = io,
    };
    context.encryptThread();
    context = .{
        .inputs = &encrypted,
        .outputs = &decrypted,
        .derived_keys = derived_keys,
        .io = io,
    };
    context.decryptThread();

    try testing.expect(!context.error_occurred);
    try testing.expectEqualSlices(u8, &input_a, &decrypted_a);
    try testing.expectEqualSlices(u8, &input_b, &decrypted_b);
}
