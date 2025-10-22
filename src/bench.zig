const std = @import("std");
const crypto = @import("crypto.zig");
const keygen = @import("keygen.zig");
const processor = @import("processor.zig");
const worker = @import("worker.zig");
const progress = @import("progress.zig");

/// Benchmark configuration
const BenchConfig = struct {
    warmup_iterations: usize = 3,
    measured_iterations: usize = 10,
};

/// Statistics for multiple benchmark iterations
const BenchStats = struct {
    durations_ns: std.ArrayListUnmanaged(u64) = .{},

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
        var m = self.durations_ns.items[0];
        for (self.durations_ns.items[1..]) |d| {
            if (d < m) m = d;
        }
        return m;
    }

    fn max(self: BenchStats) u64 {
        if (self.durations_ns.items.len == 0) return 0;
        var m = self.durations_ns.items[0];
        for (self.durations_ns.items[1..]) |d| {
            if (d > m) m = d;
        }
        return m;
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

/// Benchmark result for a single test
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
        return mbps * 8.0; // Convert MB/s to Mb/s (megabits per second)
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

/// Benchmark single-threaded encryption/decryption with different data sizes
fn benchSingleThreaded(allocator: std.mem.Allocator, derived_keys: crypto.DerivedKeys, config: BenchConfig) !void {
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
        1 * 1024 * 1024, // 1 MB
        10 * 1024 * 1024, // 10 MB
        100 * 1024 * 1024, // 100 MB
    };

    for (test_sizes) |size| {
        // Generate random data
        const plaintext = try allocator.alloc(u8, size);
        defer allocator.free(plaintext);
        std.crypto.random.bytes(plaintext);

        // Allocate output buffers
        const ciphertext = try allocator.alloc(u8, size + crypto.overhead_size);
        defer allocator.free(ciphertext);

        const decrypted = try allocator.alloc(u8, size);
        defer allocator.free(decrypted);

        // Benchmark encryption with multiple iterations
        var encrypt_stats = BenchStats{};
        defer encrypt_stats.deinit(allocator);

        // Warmup
        for (0..config.warmup_iterations) |_| {
            crypto.encryptZeroCopy(ciphertext, plaintext, derived_keys);
            std.mem.doNotOptimizeAway(&ciphertext);
        }

        // Measured iterations
        for (0..config.measured_iterations) |_| {
            var timer = try std.time.Timer.start();
            crypto.encryptZeroCopy(ciphertext, plaintext, derived_keys);
            const encrypt_time = timer.read();
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

        // Benchmark decryption with multiple iterations
        var decrypt_stats = BenchStats{};
        defer decrypt_stats.deinit(allocator);

        // Warmup
        for (0..config.warmup_iterations) |_| {
            try crypto.decryptZeroCopy(decrypted, ciphertext, derived_keys);
            std.mem.doNotOptimizeAway(&decrypted);
        }

        // Measured iterations
        for (0..config.measured_iterations) |_| {
            var timer = try std.time.Timer.start();
            try crypto.decryptZeroCopy(decrypted, ciphertext, derived_keys);
            const decrypt_time = timer.read();
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

        // Verify correctness
        if (!std.mem.eql(u8, plaintext, decrypted)) {
            return error.DecryptionMismatch;
        }
    }
}

/// Context for multi-threaded in-memory encryption
const ThreadContext = struct {
    input: []const u8,
    output: []u8,
    derived_keys: crypto.DerivedKeys,
    error_occurred: bool = false,

    fn encryptThread(ctx: *ThreadContext) void {
        crypto.encryptZeroCopy(ctx.output, ctx.input, ctx.derived_keys);
    }

    fn decryptThread(ctx: *ThreadContext) void {
        crypto.decryptZeroCopy(ctx.output, ctx.input, ctx.derived_keys) catch {
            ctx.error_occurred = true;
            return;
        };
    }
};

/// Benchmark multi-threaded in-memory encryption/decryption
fn benchMultiThreadedInMemory(allocator: std.mem.Allocator, derived_keys: crypto.DerivedKeys, config: BenchConfig) !void {
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

    // Test configuration: N chunks per thread
    const chunk_size = 50 * 1024 * 1024; // 50 MB per chunk
    const chunks_per_thread = 2;

    // Get CPU count for thread scaling test
    const cpu_count = try std.Thread.getCpuCount();
    const thread_counts = [_]u32{ 1, 2, 4, 8, @min(@as(u32, @intCast(cpu_count)), 16) };

    for (thread_counts) |thread_count| {
        const total_chunks = thread_count * chunks_per_thread;
        const total_size = total_chunks * chunk_size;

        // Pre-allocate all test data (reused across iterations)
        var test_data = std.ArrayList([]u8){};
        defer {
            for (test_data.items) |data| allocator.free(data);
            test_data.deinit(allocator);
        }

        for (0..total_chunks) |_| {
            const data = try allocator.alloc(u8, chunk_size);
            std.crypto.random.bytes(data);
            try test_data.append(allocator, data);
        }

        // Pre-allocate output buffers for encryption (reused across iterations)
        var encrypted_outputs = std.ArrayList([]u8){};
        defer {
            for (encrypted_outputs.items) |output| allocator.free(output);
            encrypted_outputs.deinit(allocator);
        }

        for (0..total_chunks) |_| {
            const output = try allocator.alloc(u8, chunk_size + crypto.overhead_size);
            try encrypted_outputs.append(allocator, output);
        }

        // Pre-allocate output buffers for decryption (reused across iterations)
        var decrypted_outputs = std.ArrayList([]u8){};
        defer {
            for (decrypted_outputs.items) |output| allocator.free(output);
            decrypted_outputs.deinit(allocator);
        }

        for (0..total_chunks) |_| {
            const output = try allocator.alloc(u8, chunk_size);
            try decrypted_outputs.append(allocator, output);
        }

        // Pre-allocate thread contexts and handles (reused across iterations)
        var contexts = try allocator.alloc(ThreadContext, thread_count);
        defer allocator.free(contexts);

        var threads = try allocator.alloc(std.Thread, thread_count);
        defer allocator.free(threads);

        // Benchmark encryption with multiple iterations
        var encrypt_stats = BenchStats{};
        defer encrypt_stats.deinit(allocator);

        // Warmup
        for (0..config.warmup_iterations) |_| {
            // Launch threads for first chunk of each thread
            for (0..thread_count) |i| {
                const start_chunk = i * chunks_per_thread;
                contexts[i] = ThreadContext{
                    .input = test_data.items[start_chunk],
                    .output = encrypted_outputs.items[start_chunk],
                    .derived_keys = derived_keys,
                };
                threads[i] = try std.Thread.spawn(.{}, ThreadContext.encryptThread, .{&contexts[i]});
            }
            for (threads) |thread| thread.join();

            // Process remaining chunks
            for (0..thread_count) |i| {
                const start_chunk = i * chunks_per_thread;
                for (1..chunks_per_thread) |j| {
                    const chunk_idx = start_chunk + j;
                    crypto.encryptZeroCopy(
                        encrypted_outputs.items[chunk_idx],
                        test_data.items[chunk_idx],
                        derived_keys,
                    );
                    std.mem.doNotOptimizeAway(&encrypted_outputs.items[chunk_idx]);
                }
            }
        }

        // Measured iterations
        for (0..config.measured_iterations) |_| {
            var timer = try std.time.Timer.start();

            // Launch threads for first chunk of each thread
            for (0..thread_count) |i| {
                const start_chunk = i * chunks_per_thread;
                contexts[i] = ThreadContext{
                    .input = test_data.items[start_chunk],
                    .output = encrypted_outputs.items[start_chunk],
                    .derived_keys = derived_keys,
                };
                threads[i] = try std.Thread.spawn(.{}, ThreadContext.encryptThread, .{&contexts[i]});
            }
            for (threads) |thread| thread.join();

            // Process remaining chunks
            for (0..thread_count) |i| {
                const start_chunk = i * chunks_per_thread;
                for (1..chunks_per_thread) |j| {
                    const chunk_idx = start_chunk + j;
                    crypto.encryptZeroCopy(
                        encrypted_outputs.items[chunk_idx],
                        test_data.items[chunk_idx],
                        derived_keys,
                    );
                    std.mem.doNotOptimizeAway(&encrypted_outputs.items[chunk_idx]);
                }
            }

            const encrypt_time = timer.read();
            try encrypt_stats.add(encrypt_time, allocator);

            // Check for errors
            for (contexts) |*ctx| {
                if (ctx.error_occurred) {
                    return error.EncryptionFailed;
                }
            }
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

        // Benchmark decryption with multiple iterations
        var decrypt_stats = BenchStats{};
        defer decrypt_stats.deinit(allocator);

        // Warmup
        for (0..config.warmup_iterations) |_| {
            // Launch decryption threads
            for (0..thread_count) |i| {
                const start_chunk = i * chunks_per_thread;
                contexts[i] = ThreadContext{
                    .input = encrypted_outputs.items[start_chunk],
                    .output = decrypted_outputs.items[start_chunk],
                    .derived_keys = derived_keys,
                };
                threads[i] = try std.Thread.spawn(.{}, ThreadContext.decryptThread, .{&contexts[i]});
            }
            for (threads) |thread| thread.join();

            // Process remaining chunks
            for (0..thread_count) |i| {
                const start_chunk = i * chunks_per_thread;
                for (1..chunks_per_thread) |j| {
                    const chunk_idx = start_chunk + j;
                    try crypto.decryptZeroCopy(
                        decrypted_outputs.items[chunk_idx],
                        encrypted_outputs.items[chunk_idx],
                        derived_keys,
                    );
                    std.mem.doNotOptimizeAway(&decrypted_outputs.items[chunk_idx]);
                }
            }
        }

        // Measured iterations
        for (0..config.measured_iterations) |_| {
            var timer = try std.time.Timer.start();

            // Launch decryption threads
            for (0..thread_count) |i| {
                const start_chunk = i * chunks_per_thread;
                contexts[i] = ThreadContext{
                    .input = encrypted_outputs.items[start_chunk],
                    .output = decrypted_outputs.items[start_chunk],
                    .derived_keys = derived_keys,
                };
                threads[i] = try std.Thread.spawn(.{}, ThreadContext.decryptThread, .{&contexts[i]});
            }
            for (threads) |thread| thread.join();

            // Process remaining chunks
            for (0..thread_count) |i| {
                const start_chunk = i * chunks_per_thread;
                for (1..chunks_per_thread) |j| {
                    const chunk_idx = start_chunk + j;
                    try crypto.decryptZeroCopy(
                        decrypted_outputs.items[chunk_idx],
                        encrypted_outputs.items[chunk_idx],
                        derived_keys,
                    );
                    std.mem.doNotOptimizeAway(&decrypted_outputs.items[chunk_idx]);
                }
            }

            const decrypt_time = timer.read();
            try decrypt_stats.add(decrypt_time, allocator);

            // Check for errors
            for (contexts) |*ctx| {
                if (ctx.error_occurred) {
                    return error.DecryptionFailed;
                }
            }
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

/// Benchmark multi-threaded file processing
fn benchMultiThreaded(allocator: std.mem.Allocator, derived_keys: crypto.DerivedKeys, tmp_dir: []const u8, config: BenchConfig) !void {
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

    // Test configuration: 20 files of 50 MB each = 1000 MB total
    // Larger dataset ensures accurate timing even with fast multi-threading
    const file_count = 20;
    const file_size = 50 * 1024 * 1024;
    const total_size = file_count * file_size;

    // Get CPU count for thread scaling test
    const cpu_count = try std.Thread.getCpuCount();
    const thread_counts = [_]u32{ 1, 2, 4, 8, @min(@as(u32, @intCast(cpu_count)), 16) };

    // Pre-create all test files once (outside timing loop)
    std.debug.print("\nGenerating {d} × {d}MB test files...\n", .{ file_count, file_size / (1024 * 1024) });

    var file_paths = std.ArrayList([]u8){};
    defer {
        for (file_paths.items) |path| allocator.free(path);
        file_paths.deinit(allocator);
    }

    var file_sizes = std.ArrayList(u64){};
    defer file_sizes.deinit(allocator);

    for (0..file_count) |i| {
        const path = try std.fmt.allocPrint(allocator, "{s}/bench_input_{d}.dat", .{ tmp_dir, i });
        try file_paths.append(allocator, path);
        try file_sizes.append(allocator, file_size);

        // Create file with random data
        const file = try std.fs.cwd().createFile(path, .{});
        defer file.close();

        const data = try allocator.alloc(u8, file_size);
        defer allocator.free(data);
        std.crypto.random.bytes(data);
        try file.writeAll(data);
    }

    std.debug.print("Test files ready. Starting benchmarks...\n", .{});

    for (thread_counts) |thread_count| {
        // Benchmark encryption with multiple iterations
        var encrypt_stats = BenchStats{};
        defer encrypt_stats.deinit(allocator);

        // Warmup
        for (0..config.warmup_iterations) |_| {
            var tracker = progress.ProgressTracker.init(file_count, total_size);
            var pool = try worker.WorkerPool.init(allocator, thread_count, derived_keys, &tracker);
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
            pool.waitAll();

            // Cleanup encrypted files
            for (file_paths.items) |path| {
                const enc_path = try std.fmt.allocPrint(allocator, "{s}.enc", .{path});
                defer allocator.free(enc_path);
                std.fs.cwd().deleteFile(enc_path) catch {};
            }
        }

        // Measured iterations
        for (0..config.measured_iterations) |_| {
            var timer = try std.time.Timer.start();
            {
                var tracker = progress.ProgressTracker.init(file_count, total_size);
                var pool = try worker.WorkerPool.init(allocator, thread_count, derived_keys, &tracker);
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
                pool.waitAll();
            }
            const encrypt_time = timer.read();
            try encrypt_stats.add(encrypt_time, allocator);

            // Cleanup encrypted files for next iteration
            for (file_paths.items) |path| {
                const enc_path = try std.fmt.allocPrint(allocator, "{s}.enc", .{path});
                defer allocator.free(enc_path);
                std.fs.cwd().deleteFile(enc_path) catch {};
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

        // Benchmark decryption with multiple iterations
        var decrypt_stats = BenchStats{};
        defer decrypt_stats.deinit(allocator);

        // Create encrypted files for decryption benchmark
        {
            var tracker = progress.ProgressTracker.init(file_count, total_size);
            var pool = try worker.WorkerPool.init(allocator, thread_count, derived_keys, &tracker);
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
            pool.waitAll();
        }

        // Warmup
        for (0..config.warmup_iterations) |_| {
            var tracker = progress.ProgressTracker.init(file_count, total_size);
            var pool = try worker.WorkerPool.init(allocator, thread_count, derived_keys, &tracker);
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
            pool.waitAll();

            // Cleanup decrypted files
            for (file_paths.items) |path| {
                const dec_path = try std.fmt.allocPrint(allocator, "{s}.dec", .{path});
                defer allocator.free(dec_path);
                std.fs.cwd().deleteFile(dec_path) catch {};
            }
        }

        // Measured iterations
        for (0..config.measured_iterations) |_| {
            var timer = try std.time.Timer.start();
            {
                var tracker = progress.ProgressTracker.init(file_count, total_size);
                var pool = try worker.WorkerPool.init(allocator, thread_count, derived_keys, &tracker);
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
                pool.waitAll();
            }
            const decrypt_time = timer.read();
            try decrypt_stats.add(decrypt_time, allocator);

            // Cleanup decrypted files for next iteration
            for (file_paths.items) |path| {
                const dec_path = try std.fmt.allocPrint(allocator, "{s}.dec", .{path});
                defer allocator.free(dec_path);
                std.fs.cwd().deleteFile(dec_path) catch {};
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

        // Cleanup encrypted files
        for (file_paths.items) |path| {
            const enc_path = try std.fmt.allocPrint(allocator, "{s}.enc", .{path});
            defer allocator.free(enc_path);
            std.fs.cwd().deleteFile(enc_path) catch {};
        }
    }

    // Cleanup original test files
    for (file_paths.items) |path| {
        std.fs.cwd().deleteFile(path) catch {};
    }
}

/// Run all benchmarks
pub fn run(allocator: std.mem.Allocator) !void {
    std.debug.print("\nTurboCrypt Performance Benchmark\n", .{});
    std.debug.print("================================\n", .{});

    // Configure benchmark iterations - in-memory tests need more iterations since they're fast
    const in_memory_config = BenchConfig{
        .warmup_iterations = 10,
        .measured_iterations = 250,
    };

    const file_io_config = BenchConfig{
        .warmup_iterations = 3,
        .measured_iterations = 10,
    };

    // Generate a random key for testing
    const key = keygen.generate();
    const derived_keys = crypto.deriveKeys(key, null);

    // Ensure tmp/ directory exists
    const tmp_dir = "tmp";
    std.fs.cwd().makeDir(tmp_dir) catch |err| {
        if (err != error.PathAlreadyExists) return err;
    };

    // Run single-threaded benchmarks
    try benchSingleThreaded(allocator, derived_keys, in_memory_config);

    // Run multi-threaded in-memory benchmarks
    try benchMultiThreadedInMemory(allocator, derived_keys, in_memory_config);

    // Run multi-threaded file I/O benchmarks
    try benchMultiThreaded(allocator, derived_keys, tmp_dir, file_io_config);

    std.debug.print("\nBenchmark completed!\n", .{});
    std.debug.print("Note: Results may vary based on CPU, memory speed, and system load.\n", .{});
}
