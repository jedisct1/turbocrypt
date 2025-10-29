const std = @import("std");
const processor = @import("processor.zig");
const crypto = @import("crypto.zig");
const progress = @import("progress.zig");

/// Print user-friendly error details with context and suggestions
pub fn printErrorDetails(err: anyerror, is_encrypt: bool) void {
    std.debug.print("        Reason: ", .{});

    switch (err) {
        error.InvalidHeaderMAC => {
            std.debug.print("Wrong decryption key, wrong context, or corrupted file header\n", .{});
            std.debug.print("        Suggestion: Verify you're using the correct key file and context (if any)\n", .{});
        },
        error.AuthenticationFailed => {
            std.debug.print("Authentication failed - file may be corrupted or wrong key\n", .{});
            std.debug.print("        Suggestion: Verify the file hasn't been modified and you're using the correct key\n", .{});
        },
        error.FileNotFound => {
            std.debug.print("File not found\n", .{});
            std.debug.print("        Suggestion: Check that the file path is correct\n", .{});
        },
        error.AccessDenied => {
            std.debug.print("Permission denied\n", .{});
            std.debug.print("        Suggestion: Check file permissions and ensure you have read/write access\n", .{});
        },
        error.OutOfMemory => {
            std.debug.print("Out of memory\n", .{});
            std.debug.print("        Suggestion: The file may be too large for available memory\n", .{});
        },
        error.IsDir => {
            std.debug.print("Path is a directory, not a file\n", .{});
            std.debug.print("        Suggestion: This shouldn't happen - may be a symlink issue\n", .{});
        },
        error.InvalidFileSize => {
            if (is_encrypt) {
                std.debug.print("File size issue during encryption\n", .{});
            } else {
                std.debug.print("File is too small to be a valid encrypted file\n", .{});
                std.debug.print("        Suggestion: File may be truncated or corrupted (minimum size: 48 bytes)\n", .{});
            }
        },
        error.DiskQuota => {
            std.debug.print("Disk quota exceeded\n", .{});
            std.debug.print("        Suggestion: Free up disk space or increase quota\n", .{});
        },
        error.NoSpaceLeft => {
            std.debug.print("No space left on device\n", .{});
            std.debug.print("        Suggestion: Free up disk space on the destination drive\n", .{});
        },
        else => {
            std.debug.print("{}\n", .{err});
            std.debug.print("        Suggestion: Check file permissions, disk space, and file integrity\n", .{});
        },
    }
}

/// Handle job processing error with consistent error reporting
fn handleJobError(
    worker: *WorkerPool,
    job: FileJob,
    err: anyerror,
    error_prefix: []const u8,
    is_encrypt: bool,
) void {
    // Do I/O outside the mutex to avoid deadlock
    std.debug.print("\n{s} {s}\n", .{ error_prefix, job.source_path });
    printErrorDetails(err, is_encrypt);

    // Only hold mutex for state updates
    worker.error_mutex.lock();
    worker.has_errors = true;
    worker.progress_tracker.addFileFailed();
    worker.error_mutex.unlock();
}

/// Operation type for file processing
pub const Operation = enum {
    encrypt,
    decrypt,
    verify,
};

/// File processing job
pub const FileJob = struct {
    source_path: []const u8,
    dest_path: ?[]const u8, // null for verify operations
    operation: Operation,
    file_size: u64,
};

/// Thread-safe work queue with batch popping capability
const WorkQueue = struct {
    mutex: std.Thread.Mutex,
    items: std.ArrayList(FileJob),
    allocator: std.mem.Allocator,
    done: bool,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) Self {
        return .{
            .mutex = .{},
            .items = std.ArrayList(FileJob){},
            .allocator = allocator,
            .done = false,
        };
    }

    pub fn deinit(self: *Self) void {
        self.items.deinit(self.allocator);
    }

    /// Add a job to the queue
    pub fn push(self: *Self, job: FileJob) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        try self.items.append(self.allocator, job);
    }

    /// Pop a batch of up to max_count items from the queue
    /// Returns an owned slice that caller must free, or null if done
    /// Returns empty slice if queue is empty but not done yet
    pub fn popBatch(self: *Self, max_count: usize) !?[]FileJob {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.items.items.len == 0) {
            if (self.done) return null;
            // Return empty slice, but not done yet
            return try self.allocator.alloc(FileJob, 0);
        }

        const batch_size = @min(max_count, self.items.items.len);

        // Allocate and copy batch items so caller owns them
        const batch = try self.allocator.alloc(FileJob, batch_size);
        @memcpy(batch, self.items.items[0..batch_size]);

        // Move remaining items forward
        const remaining = self.items.items.len - batch_size;
        if (remaining > 0) {
            @memcpy(self.items.items[0..remaining], self.items.items[batch_size..]);
        }
        self.items.shrinkRetainingCapacity(remaining);

        return batch;
    }

    /// Mark queue as done (no more items will be added)
    pub fn markDone(self: *Self) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.done = true;
    }

    /// Check if queue is empty and done
    pub fn isEmpty(self: *Self) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.items.items.len == 0 and self.done;
    }
};

/// Batch size for work queue processing
const BATCH_SIZE: usize = 16;
const PROGRESS_UPDATE_INTERVAL: usize = 10; // Update progress every N files

/// Context for parallel file processing
pub const WorkerPool = struct {
    allocator: std.mem.Allocator,
    work_queue: WorkQueue,
    threads: []std.Thread,
    thread_count: u32,
    derived_keys: crypto.DerivedKeys,
    progress_tracker: *progress.ProgressTracker,
    error_mutex: std.Thread.Mutex,
    has_errors: bool,
    quick_verify: bool,
    dry_run: bool,

    const Self = @This();

    /// Initialize worker pool with batch processing
    pub fn init(
        allocator: std.mem.Allocator,
        thread_count: u32,
        derived_keys: crypto.DerivedKeys,
        progress_tracker: *progress.ProgressTracker,
        quick_verify: bool,
        dry_run: bool,
    ) !Self {
        const threads = try allocator.alloc(std.Thread, thread_count);
        errdefer allocator.free(threads);

        return Self{
            .allocator = allocator,
            .work_queue = WorkQueue.init(allocator),
            .threads = threads,
            .thread_count = thread_count,
            .derived_keys = derived_keys,
            .progress_tracker = progress_tracker,
            .error_mutex = .{},
            .has_errors = false,
            .quick_verify = quick_verify,
            .dry_run = dry_run,
        };
    }

    /// Clean up worker pool
    pub fn deinit(self: *Self) void {
        self.work_queue.deinit();
        self.allocator.free(self.threads);
    }

    /// Worker thread entry point - processes batches of files
    fn workerThread(worker: *WorkerPool) void {
        // Create thread-local arena allocator to avoid contention
        var thread_arena = std.heap.ArenaAllocator.init(worker.allocator);
        defer thread_arena.deinit();
        const thread_allocator = thread_arena.allocator();

        // Local progress counters to minimize lock contention
        var local_files_processed: u64 = 0;
        var local_bytes_processed: u64 = 0;

        while (true) {
            // Try to get a batch of jobs
            const maybe_batch = worker.work_queue.popBatch(BATCH_SIZE) catch |err| {
                std.debug.print("[ERROR] Failed to pop batch: {}\n", .{err});
                break;
            };

            const batch = maybe_batch orelse break;
            defer worker.allocator.free(batch);

            if (batch.len == 0) {
                // Queue is empty but not done yet, sleep briefly and retry
                std.Thread.sleep(1_000_000); // 1ms
                continue;
            }

            // Process entire batch
            for (batch, 0..) |job, idx| {
                // Free paths allocated by main thread
                defer worker.allocator.free(job.source_path);
                defer if (job.dest_path) |dp| worker.allocator.free(dp);

                // Process the file using thread-local allocator
                // Skip actual processing in dry-run mode
                if (!worker.dry_run) {
                    switch (job.operation) {
                        .encrypt => {
                            processor.encryptFile(
                                job.source_path,
                                job.dest_path.?,
                                worker.derived_keys,
                                thread_allocator,
                            ) catch |err| {
                                handleJobError(worker, job, err, "[ERROR] Failed to encrypt:", true);
                                continue; // Continue with remaining files in batch
                            };
                        },
                        .decrypt => {
                            processor.decryptFile(
                                job.source_path,
                                job.dest_path.?,
                                worker.derived_keys,
                                thread_allocator,
                            ) catch |err| {
                                handleJobError(worker, job, err, "[ERROR] Failed to decrypt:", false);
                                continue; // Continue with remaining files in batch
                            };
                        },
                        .verify => {
                            processor.verifyFile(
                                job.source_path,
                                worker.derived_keys,
                                thread_allocator,
                                worker.quick_verify,
                            ) catch |err| {
                                handleJobError(worker, job, err, "[VERIFY FAILED]", false);
                                continue; // Continue with remaining files in batch
                            };
                        },
                    }
                }

                // Update local counters
                local_files_processed += 1;
                local_bytes_processed += job.file_size;

                // Periodically flush progress to global tracker
                if ((idx + 1) % PROGRESS_UPDATE_INTERVAL == 0 or idx == batch.len - 1) {
                    if (local_files_processed > 0) {
                        worker.progress_tracker.addFilesProcessed(local_files_processed);
                        worker.progress_tracker.addBytesProcessed(local_bytes_processed);
                        local_files_processed = 0;
                        local_bytes_processed = 0;
                    }
                }
            }

            // Clear the arena after processing batch to reuse memory
            _ = thread_arena.reset(.retain_capacity);
        }

        // Flush any remaining local progress
        if (local_files_processed > 0) {
            worker.progress_tracker.addFilesProcessed(local_files_processed);
            worker.progress_tracker.addBytesProcessed(local_bytes_processed);
        }
    }

    /// Submit a file processing job to the queue
    pub fn submitJob(self: *Self, job: FileJob) !void {
        try self.work_queue.push(job);
    }

    /// Start worker threads (call this before submitting jobs for concurrent processing)
    pub fn start(self: *Self) void {
        for (self.threads) |*thread| {
            thread.* = std.Thread.spawn(.{}, workerThread, .{self}) catch |err| {
                std.debug.print("[ERROR] Failed to spawn worker thread: {}\n", .{err});
                continue;
            };
        }

        // Small delay to ensure workers are started and waiting
        std.Thread.sleep(1_000_000); // 1ms
    }

    /// Mark queue as done and wait for all worker threads to complete
    pub fn finish(self: *Self) void {
        // Mark queue as done (no more jobs will be added)
        self.work_queue.markDone();

        // Wait for all threads to complete
        for (self.threads) |thread| {
            thread.join();
        }
    }

    /// Start worker threads and wait for all jobs to complete (convenience method)
    /// For backward compatibility with two-phase processing
    pub fn waitAll(self: *Self) void {
        self.start();
        self.finish();
    }

    /// Check if any errors occurred
    pub fn hadErrors(self: *Self) bool {
        self.error_mutex.lock();
        defer self.error_mutex.unlock();
        return self.has_errors;
    }
};

test "worker pool initialization" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const key: [crypto.key_length]u8 = @splat(42);
    const derived = crypto.deriveKeys(key, null);
    var tracker = progress.ProgressTracker.init(0, 0);

    var pool = try WorkerPool.init(allocator, 4, derived, &tracker, false, false);
    defer pool.deinit();

    try testing.expect(!pool.hadErrors());
}
