const std = @import("std");
const crypto = @import("crypto.zig");
const keygen = @import("keygen.zig");
const processor = @import("processor.zig");
const worker = @import("worker.zig");
const progress = @import("progress.zig");

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
};

/// Benchmark single-threaded encryption/decryption with different data sizes
fn benchSingleThreaded(allocator: std.mem.Allocator, key: [16]u8) !void {
    std.debug.print("\n*** Single-Threaded Benchmarks (In-Memory) ***\n", .{});
    std.debug.print("Pure cryptographic operations without file I/O overhead\n\n", .{});
    std.debug.print("  {s:<12} | {s:>11} | {s:>11} | {s:>14} | {s:>7}\n", .{
        "Operation",
        "Size",
        "Threads",
        "Throughput",
        "Time",
    });
    std.debug.print("  {s:-<12}-+-{s:-<11}-+-{s:-<11}-+-{s:-<14}-+-{s:-<7}\n", .{ "", "", "", "", "" });

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

        // Benchmark encryption
        var timer = try std.time.Timer.start();
        const ciphertext = try crypto.encrypt(plaintext, key, allocator);
        defer allocator.free(ciphertext);
        const encrypt_time = timer.read();
        std.mem.doNotOptimizeAway(&ciphertext);

        const encrypt_result = BenchResult{
            .operation = "Encrypt",
            .buffer_size = size,
            .threads = null,
            .file_count = 1,
            .total_bytes = size,
            .duration_ns = encrypt_time,
        };
        encrypt_result.print();

        // Benchmark decryption
        timer.reset();
        const decrypted = try crypto.decrypt(ciphertext, key, allocator);
        defer allocator.free(decrypted);
        const decrypt_time = timer.read();
        std.mem.doNotOptimizeAway(&decrypted);

        const decrypt_result = BenchResult{
            .operation = "Decrypt",
            .buffer_size = size,
            .threads = null,
            .file_count = 1,
            .total_bytes = size,
            .duration_ns = decrypt_time,
        };
        decrypt_result.print();

        // Verify correctness
        if (!std.mem.eql(u8, plaintext, decrypted)) {
            return error.DecryptionMismatch;
        }
    }
}

/// Context for multi-threaded in-memory encryption
const ThreadContext = struct {
    data: []u8,
    key: [16]u8,
    allocator: std.mem.Allocator,
    result: ?[]u8 = null,
    error_occurred: bool = false,

    fn encryptThread(ctx: *ThreadContext) void {
        ctx.result = crypto.encrypt(ctx.data, ctx.key, ctx.allocator) catch {
            ctx.error_occurred = true;
            return;
        };
    }

    fn decryptThread(ctx: *ThreadContext) void {
        ctx.result = crypto.decrypt(ctx.data, ctx.key, ctx.allocator) catch {
            ctx.error_occurred = true;
            return;
        };
    }
};

/// Benchmark multi-threaded in-memory encryption/decryption
fn benchMultiThreadedInMemory(allocator: std.mem.Allocator, key: [16]u8) !void {
    std.debug.print("\n*** Multi-Threaded Benchmarks (In-Memory) ***\n", .{});
    std.debug.print("Parallel cryptographic operations without file I/O\n", .{});
    std.debug.print("Throughput = total Mb/s across all threads\n\n", .{});
    std.debug.print("  {s:<12} | {s:>11} | {s:>11} | {s:>14} | {s:>7}\n", .{
        "Operation",
        "Size",
        "Threads",
        "Throughput",
        "Time",
    });
    std.debug.print("  {s:-<12}-+-{s:-<11}-+-{s:-<11}-+-{s:-<14}-+-{s:-<7}\n", .{ "", "", "", "", "" });

    // Test configuration: N chunks per thread
    const chunk_size = 50 * 1024 * 1024; // 50 MB per chunk
    const chunks_per_thread = 2;

    // Get CPU count for thread scaling test
    const cpu_count = try std.Thread.getCpuCount();
    const thread_counts = [_]u32{ 1, 2, 4, 8, @min(@as(u32, @intCast(cpu_count)), 16) };

    for (thread_counts) |thread_count| {
        const total_chunks = thread_count * chunks_per_thread;
        const total_size = total_chunks * chunk_size;

        // Pre-allocate all test data
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

        // Benchmark encryption
        var contexts = try allocator.alloc(ThreadContext, thread_count);
        defer allocator.free(contexts);

        var threads = try allocator.alloc(std.Thread, thread_count);
        defer allocator.free(threads);

        var timer = try std.time.Timer.start();

        // Launch threads
        for (0..thread_count) |i| {
            // Each thread gets chunks_per_thread chunks
            const start_chunk = i * chunks_per_thread;

            // For simplicity, we'll have each thread process one chunk at a time
            // and measure the total work across all chunks
            contexts[i] = ThreadContext{
                .data = test_data.items[start_chunk],
                .key = key,
                .allocator = allocator,
            };

            threads[i] = try std.Thread.spawn(.{}, ThreadContext.encryptThread, .{&contexts[i]});
        }

        // Wait for all threads
        for (threads) |thread| {
            thread.join();
        }

        // Process remaining chunks for each thread
        for (0..thread_count) |i| {
            const start_chunk = i * chunks_per_thread;
            for (1..chunks_per_thread) |j| {
                const chunk_idx = start_chunk + j;
                const encrypted = try crypto.encrypt(test_data.items[chunk_idx], key, allocator);
                defer allocator.free(encrypted);
                std.mem.doNotOptimizeAway(&encrypted);
            }
        }

        const encrypt_time = timer.read();

        // Cleanup encryption results
        for (contexts) |*ctx| {
            if (ctx.result) |result| {
                allocator.free(result);
                ctx.result = null;
            }
            if (ctx.error_occurred) {
                return error.EncryptionFailed;
            }
        }

        const encrypt_result = BenchResult{
            .operation = "Encrypt",
            .buffer_size = chunk_size,
            .threads = thread_count,
            .file_count = total_chunks,
            .total_bytes = total_size,
            .duration_ns = encrypt_time,
        };
        encrypt_result.print();

        // Benchmark decryption - first encrypt all data
        var encrypted_data = std.ArrayList([]u8){};
        defer {
            for (encrypted_data.items) |data| allocator.free(data);
            encrypted_data.deinit(allocator);
        }

        for (test_data.items) |data| {
            const encrypted = try crypto.encrypt(data, key, allocator);
            try encrypted_data.append(allocator, encrypted);
        }

        timer.reset();

        // Launch decryption threads
        for (0..thread_count) |i| {
            const start_chunk = i * chunks_per_thread;
            contexts[i] = ThreadContext{
                .data = encrypted_data.items[start_chunk],
                .key = key,
                .allocator = allocator,
            };

            threads[i] = try std.Thread.spawn(.{}, ThreadContext.decryptThread, .{&contexts[i]});
        }

        // Wait for all threads
        for (threads) |thread| {
            thread.join();
        }

        // Process remaining chunks
        for (0..thread_count) |i| {
            const start_chunk = i * chunks_per_thread;
            for (1..chunks_per_thread) |j| {
                const chunk_idx = start_chunk + j;
                const decrypted = try crypto.decrypt(encrypted_data.items[chunk_idx], key, allocator);
                defer allocator.free(decrypted);
                std.mem.doNotOptimizeAway(&decrypted);
            }
        }

        const decrypt_time = timer.read();

        // Cleanup decryption results
        for (contexts) |*ctx| {
            if (ctx.result) |result| {
                allocator.free(result);
                ctx.result = null;
            }
            if (ctx.error_occurred) {
                return error.DecryptionFailed;
            }
        }

        const decrypt_result = BenchResult{
            .operation = "Decrypt",
            .buffer_size = chunk_size,
            .threads = thread_count,
            .file_count = total_chunks,
            .total_bytes = total_size,
            .duration_ns = decrypt_time,
        };
        decrypt_result.print();
    }
}

/// Benchmark multi-threaded file processing
fn benchMultiThreaded(allocator: std.mem.Allocator, key: [16]u8, tmp_dir: []const u8) !void {
    std.debug.print("\n*** Multi-Threaded Benchmarks (File I/O) ***\n", .{});
    std.debug.print("Real-world file encryption with parallel processing\n", .{});
    std.debug.print("Throughput = total Mb/s across all threads\n\n", .{});
    std.debug.print("  {s:<12} | {s:>11} | {s:>11} | {s:>14} | {s:>7}\n", .{
        "Operation",
        "Size",
        "Threads",
        "Throughput",
        "Time",
    });
    std.debug.print("  {s:-<12}-+-{s:-<11}-+-{s:-<11}-+-{s:-<14}-+-{s:-<7}\n", .{ "", "", "", "", "" });

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
        // Benchmark encryption - time only the actual encryption work
        var timer = try std.time.Timer.start();
        {
            var tracker = progress.ProgressTracker.init(file_count, total_size);
            var pool = try worker.WorkerPool.init(allocator, thread_count, key, &tracker);
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

        const encrypt_result = BenchResult{
            .operation = "Encrypt",
            .buffer_size = file_size,
            .threads = thread_count,
            .file_count = file_count,
            .total_bytes = total_size,
            .duration_ns = encrypt_time,
        };
        encrypt_result.print();

        // Benchmark decryption
        timer.reset();
        {
            var tracker = progress.ProgressTracker.init(file_count, total_size);
            var pool = try worker.WorkerPool.init(allocator, thread_count, key, &tracker);
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

        const decrypt_result = BenchResult{
            .operation = "Decrypt",
            .buffer_size = file_size,
            .threads = thread_count,
            .file_count = file_count,
            .total_bytes = total_size,
            .duration_ns = decrypt_time,
        };
        decrypt_result.print();

        // Cleanup encrypted/decrypted files (but keep original input files for next test)
        for (file_paths.items) |path| {
            const enc_path = try std.fmt.allocPrint(allocator, "{s}.enc", .{path});
            defer allocator.free(enc_path);
            std.fs.cwd().deleteFile(enc_path) catch {};
            const dec_path = try std.fmt.allocPrint(allocator, "{s}.dec", .{path});
            defer allocator.free(dec_path);
            std.fs.cwd().deleteFile(dec_path) catch {};
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

    // Generate a random key for testing
    const key = keygen.generate();

    // Ensure tmp/ directory exists
    const tmp_dir = "tmp";
    std.fs.cwd().makeDir(tmp_dir) catch |err| {
        if (err != error.PathAlreadyExists) return err;
    };

    // Run single-threaded benchmarks
    try benchSingleThreaded(allocator, key);

    // Run multi-threaded in-memory benchmarks
    try benchMultiThreadedInMemory(allocator, key);

    // Run multi-threaded file I/O benchmarks
    try benchMultiThreaded(allocator, key, tmp_dir);

    std.debug.print("\nBenchmark completed!\n", .{});
    std.debug.print("Note: Results may vary based on CPU, memory speed, and system load.\n", .{});
}
