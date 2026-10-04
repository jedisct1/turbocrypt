//! Benchmarks for the work TurboCrypt does most often.

const std = @import("std");
const mem = std.mem;
const testing = std.testing;
const Allocator = std.mem.Allocator;
const Io = std.Io;

const crypto = @import("crypto.zig");
const keygen = @import("keygen.zig");
const progress = @import("progress.zig");
const worker = @import("worker.zig");

const max_tmp_dir_attempts = 16;

fn createTmpDir(gpa: Allocator, io: Io) ![]u8 {
    for (0..max_tmp_dir_attempts) |_| {
        var random: u64 = undefined;
        io.random(mem.asBytes(&random));
        const path = try gpa.print(".turbocrypt-bench-{x}", .{random});
        errdefer gpa.free(path);
        Io.Dir.createDir(.cwd(), io, path, .default_dir) catch |err| switch (err) {
            error.PathAlreadyExists => {
                gpa.free(path);
                continue;
            },
            else => return err,
        };
        return path;
    }
    return error.TmpDirCollision;
}

const Config = struct {
    warmup_iterations: usize = 3,
    measured_iterations: usize = 10,
};

const Stats = struct {
    durations_ns: std.ArrayList(u64) = .empty,

    fn deinit(self: *Stats, gpa: Allocator) void {
        self.durations_ns.deinit(gpa);
    }

    fn add(self: *Stats, gpa: Allocator, duration_ns: u64) !void {
        try self.durations_ns.append(gpa, duration_ns);
    }

    fn mean(self: Stats) u64 {
        if (self.durations_ns.items.len == 0) return 0;
        var sum: u64 = 0;
        for (self.durations_ns.items) |d| sum += d;
        return sum / self.durations_ns.items.len;
    }

    fn min(self: Stats) u64 {
        if (self.durations_ns.items.len == 0) return 0;
        return mem.min(u64, self.durations_ns.items);
    }

    fn max(self: Stats) u64 {
        if (self.durations_ns.items.len == 0) return 0;
        return mem.max(u64, self.durations_ns.items);
    }

    fn stdDev(self: Stats) f64 {
        if (self.durations_ns.items.len < 2) return 0.0;
        const mean_ns: f64 = @floatFromInt(self.mean());
        var variance: f64 = 0.0;
        for (self.durations_ns.items) |d| {
            const diff = @as(f64, @floatFromInt(d)) - mean_ns;
            variance += diff * diff;
        }
        variance /= @floatFromInt(self.durations_ns.items.len);
        return @sqrt(variance);
    }
};

const Result = struct {
    operation: []const u8,
    threads: ?u32,
    total_bytes: u64,

    fn print(self: Result, stats: Stats) void {
        const mb = @as(f64, @floatFromInt(self.total_bytes)) / (1024.0 * 1024.0);
        const mean_s = @as(f64, @floatFromInt(stats.mean())) / 1_000_000_000.0;
        const min_s = @as(f64, @floatFromInt(stats.min())) / 1_000_000_000.0;
        const max_s = @as(f64, @floatFromInt(stats.max())) / 1_000_000_000.0;
        const stddev_s = stats.stdDev() / 1_000_000_000.0;

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

fn printTableHeader(config: Config) void {
    std.debug.print("Running {d} warmup + {d} measured iterations per test\n\n", .{
        config.warmup_iterations,
        config.measured_iterations,
    });
    std.debug.print("  {s:<12} | {s:>11} | {s:>11} | {s:>14} | {s:>7}\n", .{
        "Operation",
        "Size",
        "Threads",
        "Throughput",
        "Time (mean ± stddev)",
    });
    std.debug.print(
        "  {s:-<12}-+-{s:-<11}-+-{s:-<11}-+-{s:-<14}-+-{s:-<40}\n",
        .{ "", "", "", "", "" },
    );
}

fn benchSingleThreaded(
    gpa: Allocator,
    io: Io,
    derived_keys: crypto.DerivedKeys,
    config: Config,
) !void {
    std.debug.print("\n*** Single-Threaded Benchmarks (In-Memory) ***\n", .{});
    std.debug.print("Pure cryptographic operations without file I/O overhead\n", .{});
    printTableHeader(config);

    const test_sizes = [_]usize{
        1 * 1024 * 1024,
        10 * 1024 * 1024,
        100 * 1024 * 1024,
    };

    for (test_sizes) |size| {
        const plaintext = try gpa.alloc(u8, size);
        defer gpa.free(plaintext);
        io.random(plaintext);

        const ciphertext = try gpa.alloc(u8, size + crypto.overhead_size);
        defer gpa.free(ciphertext);

        const decrypted = try gpa.alloc(u8, size);
        defer gpa.free(decrypted);

        var encrypt_stats: Stats = .{};
        defer encrypt_stats.deinit(gpa);

        for (0..config.warmup_iterations) |_| {
            crypto.encryptZeroCopy(io, ciphertext, plaintext, derived_keys);
            mem.doNotOptimizeAway(&ciphertext);
        }

        for (0..config.measured_iterations) |_| {
            const start_time = Io.Clock.Timestamp.now(io, .awake);
            crypto.encryptZeroCopy(io, ciphertext, plaintext, derived_keys);
            const encrypt_ns: u64 = @intCast(start_time.untilNow(io).raw.nanoseconds);
            mem.doNotOptimizeAway(&ciphertext);
            try encrypt_stats.add(gpa, encrypt_ns);
        }

        const encrypt_result: Result = .{
            .operation = "Encrypt",
            .threads = null,
            .total_bytes = size,
        };
        encrypt_result.print(encrypt_stats);

        var decrypt_stats: Stats = .{};
        defer decrypt_stats.deinit(gpa);

        for (0..config.warmup_iterations) |_| {
            try crypto.decryptZeroCopy(decrypted, ciphertext, derived_keys);
            mem.doNotOptimizeAway(&decrypted);
        }

        for (0..config.measured_iterations) |_| {
            const start_time = Io.Clock.Timestamp.now(io, .awake);
            try crypto.decryptZeroCopy(decrypted, ciphertext, derived_keys);
            const decrypt_ns: u64 = @intCast(start_time.untilNow(io).raw.nanoseconds);
            mem.doNotOptimizeAway(&decrypted);
            try decrypt_stats.add(gpa, decrypt_ns);
        }

        const decrypt_result: Result = .{
            .operation = "Decrypt",
            .threads = null,
            .total_bytes = size,
        };
        decrypt_result.print(decrypt_stats);

        if (!mem.eql(u8, plaintext, decrypted)) {
            return error.DecryptionMismatch;
        }
    }
}

const ThreadContext = struct {
    inputs: []const []u8,
    outputs: []const []u8,
    derived_keys: crypto.DerivedKeys,
    io: Io,
    error_occurred: bool = false,

    fn encryptThread(ctx: *ThreadContext) void {
        for (ctx.inputs, ctx.outputs) |input, output| {
            crypto.encryptZeroCopy(ctx.io, output, input, ctx.derived_keys);
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

/// Divide the work evenly and wait until every thread has finished.
/// A failed decrypt makes the whole pass fail.
fn runOnThreads(
    io: Io,
    threads: []std.Thread,
    contexts: []ThreadContext,
    inputs: []const []u8,
    outputs: []const []u8,
    chunks_per_thread: usize,
    derived_keys: crypto.DerivedKeys,
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
    mem.doNotOptimizeAway(outputs);
    for (contexts) |context| {
        if (context.error_occurred) return false;
    }
    return true;
}

fn benchMultiThreadedInMemory(
    gpa: Allocator,
    io: Io,
    derived_keys: crypto.DerivedKeys,
    config: Config,
) !void {
    std.debug.print("\n*** Multi-Threaded Benchmarks (In-Memory) ***\n", .{});
    std.debug.print("Parallel cryptographic operations without file I/O\n", .{});
    std.debug.print("Throughput = total Mb/s across all threads\n", .{});
    printTableHeader(config);

    const chunk_size = 50 * 1024 * 1024;
    const chunks_per_thread = 2;

    const cpu_count = try std.Thread.getCpuCount();
    const thread_counts = [_]u32{ 1, 2, 4, 8, @intCast(@min(cpu_count, 16)) };

    for (thread_counts) |thread_count| {
        const total_chunks = thread_count * chunks_per_thread;
        const total_size = total_chunks * chunk_size;

        // Keep allocation time out of the measurements.
        var test_data: std.ArrayList([]u8) = .empty;
        defer {
            for (test_data.items) |data| gpa.free(data);
            test_data.deinit(gpa);
        }

        for (0..total_chunks) |_| {
            const data = try gpa.alloc(u8, chunk_size);
            io.random(data);
            try test_data.append(gpa, data);
        }

        var encrypted_outputs: std.ArrayList([]u8) = .empty;
        defer {
            for (encrypted_outputs.items) |output| gpa.free(output);
            encrypted_outputs.deinit(gpa);
        }

        for (0..total_chunks) |_| {
            const output = try gpa.alloc(u8, chunk_size + crypto.overhead_size);
            try encrypted_outputs.append(gpa, output);
        }

        var decrypted_outputs: std.ArrayList([]u8) = .empty;
        defer {
            for (decrypted_outputs.items) |output| gpa.free(output);
            decrypted_outputs.deinit(gpa);
        }

        for (0..total_chunks) |_| {
            const output = try gpa.alloc(u8, chunk_size);
            try decrypted_outputs.append(gpa, output);
        }

        const contexts = try gpa.alloc(ThreadContext, thread_count);
        defer gpa.free(contexts);

        const threads = try gpa.alloc(std.Thread, thread_count);
        defer gpa.free(threads);

        var encrypt_stats: Stats = .{};
        defer encrypt_stats.deinit(gpa);

        for (0..config.warmup_iterations) |_| {
            _ = try runOnThreads(
                io,
                threads,
                contexts,
                test_data.items,
                encrypted_outputs.items,
                chunks_per_thread,
                derived_keys,
                ThreadContext.encryptThread,
            );
        }

        for (0..config.measured_iterations) |_| {
            const start_time = Io.Clock.Timestamp.now(io, .awake);

            const ok = try runOnThreads(
                io,
                threads,
                contexts,
                test_data.items,
                encrypted_outputs.items,
                chunks_per_thread,
                derived_keys,
                ThreadContext.encryptThread,
            );

            const encrypt_ns: u64 = @intCast(start_time.untilNow(io).raw.nanoseconds);
            try encrypt_stats.add(gpa, encrypt_ns);
            if (!ok) return error.EncryptionFailed;
        }

        const encrypt_result: Result = .{
            .operation = "Encrypt",
            .threads = thread_count,
            .total_bytes = total_size,
        };
        encrypt_result.print(encrypt_stats);

        var decrypt_stats: Stats = .{};
        defer decrypt_stats.deinit(gpa);

        for (0..config.warmup_iterations) |_| {
            _ = try runOnThreads(
                io,
                threads,
                contexts,
                encrypted_outputs.items,
                decrypted_outputs.items,
                chunks_per_thread,
                derived_keys,
                ThreadContext.decryptThread,
            );
        }

        for (0..config.measured_iterations) |_| {
            const start_time = Io.Clock.Timestamp.now(io, .awake);

            const ok = try runOnThreads(
                io,
                threads,
                contexts,
                encrypted_outputs.items,
                decrypted_outputs.items,
                chunks_per_thread,
                derived_keys,
                ThreadContext.decryptThread,
            );

            const decrypt_ns: u64 = @intCast(start_time.untilNow(io).raw.nanoseconds);
            try decrypt_stats.add(gpa, decrypt_ns);
            if (!ok) return error.DecryptionFailed;
        }

        const decrypt_result: Result = .{
            .operation = "Decrypt",
            .threads = thread_count,
            .total_bytes = total_size,
        };
        decrypt_result.print(decrypt_stats);
    }
}

/// Shared inputs for one pass through the file benchmark.
const FileSet = struct {
    gpa: Allocator,
    io: Io,
    derived_keys: crypto.DerivedKeys,
    paths: []const []u8,
    sizes: []const u64,
    total_size: u64,

    /// Measure one operation across the whole file set.
    /// Separate output suffixes keep each pass from overwriting its inputs.
    fn process(self: FileSet, thread_count: u32, comptime operation: worker.Operation) !void {
        const gpa = self.gpa;
        var tracker = progress.Tracker.init(self.io, self.paths.len, self.total_size);
        var pool = try worker.Pool.init(
            gpa,
            self.io,
            thread_count,
            self.derived_keys,
            &tracker,
            false,
            false,
        );
        defer pool.deinit();

        for (self.paths, self.sizes) |path, size| {
            switch (operation) {
                .encrypt => {
                    const source = try gpa.dupe(u8, path);
                    const dest = try gpa.print("{s}.enc", .{path});
                    try pool.submitJob(.{
                        .source_path = source,
                        .dest_path = dest,
                        .operation = .encrypt,
                        .file_size = size,
                    });
                },
                .decrypt => {
                    const source = try gpa.print("{s}.enc", .{path});
                    const dest = try gpa.print("{s}.dec", .{path});
                    try pool.submitJob(.{
                        .source_path = source,
                        .dest_path = dest,
                        .operation = .decrypt,
                        .file_size = size + crypto.overhead_size,
                    });
                },
                .verify => @compileError("the benchmark does not time verification"),
            }
        }
        try pool.waitAll();
        if (pool.hadErrors()) return error.BenchmarkFileProcessingFailed;
    }

    fn deleteOutputs(self: FileSet, comptime suffix: []const u8) !void {
        for (self.paths) |path| {
            const output_path = try self.gpa.print("{s}" ++ suffix, .{path});
            defer self.gpa.free(output_path);
            Io.Dir.deleteFile(.cwd(), self.io, output_path) catch {};
        }
    }
};

fn benchMultiThreaded(
    gpa: Allocator,
    io: Io,
    derived_keys: crypto.DerivedKeys,
    tmp_dir: []const u8,
    config: Config,
) !void {
    std.debug.print("\n*** Multi-Threaded Benchmarks (File I/O) ***\n", .{});
    std.debug.print("Real-world file encryption with parallel processing\n", .{});
    std.debug.print("Throughput = total Mb/s across all threads\n", .{});
    printTableHeader(config);

    // Give every worker enough data for useful timings.
    const file_count = 20;
    const file_size = 50 * 1024 * 1024;
    const total_size = file_count * file_size;

    const cpu_count = try std.Thread.getCpuCount();
    const thread_counts = [_]u32{ 1, 2, 4, 8, @intCast(@min(cpu_count, 16)) };

    // Create the inputs before timing the file work.
    std.debug.print("\nGenerating {d} × {d}MB test files...\n", .{
        file_count,
        file_size / (1024 * 1024),
    });

    var file_paths: std.ArrayList([]u8) = .empty;
    defer {
        for (file_paths.items) |path| gpa.free(path);
        file_paths.deinit(gpa);
    }

    var file_sizes: std.ArrayList(u64) = .empty;
    defer file_sizes.deinit(gpa);

    for (0..file_count) |i| {
        const path = try gpa.print("{s}/bench_input_{d}.dat", .{ tmp_dir, i });
        try file_paths.append(gpa, path);
        try file_sizes.append(gpa, file_size);

        const file = try Io.Dir.createFile(.cwd(), io, path, .{});
        defer file.close(io);

        const data = try gpa.alloc(u8, file_size);
        defer gpa.free(data);
        io.random(data);
        try file.writeStreamingAll(io, data);
    }

    std.debug.print("Test files ready. Starting benchmarks...\n", .{});

    const files: FileSet = .{
        .gpa = gpa,
        .io = io,
        .derived_keys = derived_keys,
        .paths = file_paths.items,
        .sizes = file_sizes.items,
        .total_size = total_size,
    };

    for (thread_counts) |thread_count| {
        var encrypt_stats: Stats = .{};
        defer encrypt_stats.deinit(gpa);

        for (0..config.warmup_iterations) |_| {
            try files.process(thread_count, .encrypt);
            try files.deleteOutputs(".enc");
        }

        for (0..config.measured_iterations) |_| {
            const start_time = Io.Clock.Timestamp.now(io, .awake);
            try files.process(thread_count, .encrypt);
            const encrypt_ns: u64 = @intCast(start_time.untilNow(io).raw.nanoseconds);
            try encrypt_stats.add(gpa, encrypt_ns);

            try files.deleteOutputs(".enc");
        }

        const encrypt_result: Result = .{
            .operation = "Encrypt",
            .threads = thread_count,
            .total_bytes = total_size,
        };
        encrypt_result.print(encrypt_stats);

        var decrypt_stats: Stats = .{};
        defer decrypt_stats.deinit(gpa);

        // Produce ciphertext once for the decrypt passes.
        try files.process(thread_count, .encrypt);

        for (0..config.warmup_iterations) |_| {
            try files.process(thread_count, .decrypt);
            try files.deleteOutputs(".dec");
        }

        for (0..config.measured_iterations) |_| {
            const start_time = Io.Clock.Timestamp.now(io, .awake);
            try files.process(thread_count, .decrypt);
            const decrypt_ns: u64 = @intCast(start_time.untilNow(io).raw.nanoseconds);
            try decrypt_stats.add(gpa, decrypt_ns);

            try files.deleteOutputs(".dec");
        }

        const decrypt_result: Result = .{
            .operation = "Decrypt",
            .threads = thread_count,
            .total_bytes = total_size,
        };
        decrypt_result.print(decrypt_stats);

        try files.deleteOutputs(".enc");
    }

    for (file_paths.items) |path| {
        Io.Dir.deleteFile(.cwd(), io, path) catch {};
    }
}

pub fn run(gpa: Allocator, io: Io) !void {
    std.debug.print("\nTurboCrypt Performance Benchmark\n", .{});
    std.debug.print("================================\n", .{});

    // Short in-memory runs need more samples to settle down.
    const in_memory_config: Config = .{
        .warmup_iterations = 10,
        .measured_iterations = 250,
    };

    const file_io_config: Config = .{
        .warmup_iterations = 3,
        .measured_iterations = 10,
    };

    const key = keygen.generate(io);
    const derived_keys = crypto.deriveKeys(key, null);

    const tmp_dir = try createTmpDir(gpa, io);
    defer gpa.free(tmp_dir);
    defer Io.Dir.deleteTree(.cwd(), io, tmp_dir) catch {};

    try benchSingleThreaded(gpa, io, derived_keys, in_memory_config);
    try benchMultiThreadedInMemory(gpa, io, derived_keys, in_memory_config);
    try benchMultiThreaded(gpa, io, derived_keys, tmp_dir, file_io_config);

    std.debug.print("\nBenchmark completed!\n", .{});
    std.debug.print("Note: Results may vary based on CPU, memory speed, and system load.\n", .{});
}

test "benchmark files use an isolated temporary directory" {
    const gpa = testing.allocator;
    const io = testing.io;

    const tmp_dir = try createTmpDir(gpa, io);
    defer gpa.free(tmp_dir);
    defer Io.Dir.deleteTree(.cwd(), io, tmp_dir) catch {};
    try testing.expect(mem.startsWith(u8, tmp_dir, ".turbocrypt-bench-"));

    const test_file = try Io.Dir.path.join(gpa, &.{ tmp_dir, "bench_input_0.dat" });
    defer gpa.free(test_file);
    try Io.Dir.writeFile(.cwd(), io, .{ .sub_path = test_file, .data = "temporary" });

    const data = try Io.Dir.readFileAlloc(.cwd(), io, test_file, gpa, .limited(10));
    defer gpa.free(data);
    try testing.expectEqualStrings("temporary", data);
}

test "benchmark thread context processes every assigned chunk" {
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

    var context: ThreadContext = .{
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
