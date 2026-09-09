const std = @import("std");
const processor = @import("processor.zig");
const crypto = @import("crypto.zig");
const progress = @import("progress.zig");

pub fn printErrorDetails(err: anyerror, is_encrypt: bool) void {
    std.debug.print("        Reason: ", .{});

    switch (err) {
        error.InvalidHeaderMac => {
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

fn handleJobError(
    worker: *Pool,
    job: FileJob,
    err: anyerror,
    error_prefix: []const u8,
    is_encrypt: bool,
) void {
    // Print outside the error mutex.
    std.debug.print("\n{s} {s}\n", .{ error_prefix, job.source_path });
    printErrorDetails(err, is_encrypt);

    worker.markError();
    worker.progress_tracker.addFileFailed();
}

pub const Operation = enum {
    encrypt,
    decrypt,
    verify,
};

pub const FileJob = struct {
    source_path: []const u8,
    dest_path: ?[]const u8, // null for verify operations
    operation: Operation,
    file_size: u64,
    /// Remove the source file once the output is complete
    delete_source: bool = false,
};

const WorkQueue = struct {
    mutex: std.Io.Mutex,
    items: std.ArrayList(FileJob),
    allocator: std.mem.Allocator,
    done: bool,
    io: std.Io,

    pub fn init(allocator: std.mem.Allocator, io: std.Io) WorkQueue {
        return .{
            .mutex = std.Io.Mutex.init,
            .items = .empty,
            .allocator = allocator,
            .done = false,
            .io = io,
        };
    }

    pub fn deinit(self: *WorkQueue) void {
        for (self.items.items) |job| {
            self.allocator.free(job.source_path);
            if (job.dest_path) |dest_path| self.allocator.free(dest_path);
        }
        self.items.deinit(self.allocator);
    }

    pub fn push(self: *WorkQueue, job: FileJob) !void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        try self.items.append(self.allocator, job);
    }

    /// Null means the queue is done. An empty slice means more jobs can still come.
    /// The caller frees the result.
    pub fn popBatch(self: *WorkQueue, max_count: usize) !?[]FileJob {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);

        if (self.items.items.len == 0) {
            if (self.done) return null;
            return try self.allocator.alloc(FileJob, 0);
        }

        const batch_size = @min(max_count, self.items.items.len);

        const batch = try self.allocator.alloc(FileJob, batch_size);
        @memcpy(batch, self.items.items[0..batch_size]);

        const remaining = self.items.items.len - batch_size;
        if (remaining > 0 and batch_size > 0) {
            @memmove(self.items.items[0..remaining], self.items.items[batch_size..]);
        }
        self.items.shrinkRetainingCapacity(remaining);

        return batch;
    }

    pub fn markDone(self: *WorkQueue) void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        self.done = true;
    }

    pub fn isEmpty(self: *WorkQueue) bool {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        return self.items.items.len == 0 and self.done;
    }
};

const max_batch_size: usize = 16;
const progress_update_interval: usize = 10;

pub const Pool = struct {
    allocator: std.mem.Allocator,
    work_queue: WorkQueue,
    threads: []std.Thread,
    spawned_count: usize,
    thread_count: u32,
    derived_keys: crypto.DerivedKeys,
    progress_tracker: *progress.Tracker,
    error_mutex: std.Io.Mutex,
    has_errors: bool,
    quick_verify: bool,
    dry_run: bool,
    io: std.Io,

    pub fn init(
        allocator: std.mem.Allocator,
        thread_count: u32,
        derived_keys: crypto.DerivedKeys,
        progress_tracker: *progress.Tracker,
        quick_verify: bool,
        dry_run: bool,
        io: std.Io,
    ) !Pool {
        const threads = try allocator.alloc(std.Thread, thread_count);
        errdefer allocator.free(threads);

        return Pool{
            .allocator = allocator,
            .work_queue = WorkQueue.init(allocator, io),
            .threads = threads,
            .spawned_count = 0,
            .thread_count = thread_count,
            .derived_keys = derived_keys,
            .progress_tracker = progress_tracker,
            .error_mutex = std.Io.Mutex.init,
            .has_errors = false,
            .quick_verify = quick_verify,
            .dry_run = dry_run,
            .io = io,
        };
    }

    /// Threads still running would touch the queue after it is gone, so they are joined first.
    pub fn deinit(self: *Pool) void {
        self.finish();
        self.work_queue.deinit();
        self.allocator.free(self.threads);
    }

    fn workerThread(worker: *Pool) void {
        // A thread-local arena keeps the workers from contending on the allocator.
        var thread_arena = std.heap.ArenaAllocator.init(worker.allocator);
        defer thread_arena.deinit();
        const thread_allocator = thread_arena.allocator();

        // Local counters keep the atomic traffic low.
        var local_files_processed: u64 = 0;
        var local_bytes_processed: u64 = 0;

        while (true) {
            const maybe_batch = worker.work_queue.popBatch(max_batch_size) catch |err| {
                std.debug.print("[ERROR] Failed to pop batch: {}\n", .{err});
                worker.markError();
                break;
            };

            const batch = maybe_batch orelse break;
            defer worker.allocator.free(batch);

            if (batch.len == 0) {
                worker.io.sleep(std.Io.Duration.fromNanoseconds(1_000_000), .awake) catch {};
                continue;
            }

            for (batch, 0..) |job, idx| {
                // The job owns its paths.
                defer worker.allocator.free(job.source_path);
                defer if (job.dest_path) |dp| worker.allocator.free(dp);

                if (!worker.dry_run) {
                    switch (job.operation) {
                        .encrypt => {
                            processor.encryptFile(
                                job.source_path,
                                job.dest_path.?,
                                worker.derived_keys,
                                thread_allocator,
                                worker.io,
                            ) catch |err| {
                                handleJobError(worker, job, err, "[ERROR] Failed to encrypt:", true);
                                continue;
                            };
                        },
                        .decrypt => {
                            processor.decryptFile(
                                job.source_path,
                                job.dest_path.?,
                                worker.derived_keys,
                                thread_allocator,
                                worker.io,
                            ) catch |err| {
                                handleJobError(worker, job, err, "[ERROR] Failed to decrypt:", false);
                                continue;
                            };
                        },
                        .verify => {
                            processor.verifyFile(
                                job.source_path,
                                worker.derived_keys,
                                thread_allocator,
                                worker.quick_verify,
                                worker.io,
                            ) catch |err| {
                                handleJobError(worker, job, err, "[VERIFY FAILED]", false);
                                continue;
                            };
                        },
                    }

                    if (job.delete_source) {
                        std.Io.Dir.deleteFile(.cwd(), worker.io, job.source_path) catch |err| {
                            handleJobError(worker, job, err, "[ERROR] Failed to remove source file:", job.operation == .encrypt);
                            continue;
                        };
                    }
                }

                local_files_processed += 1;
                local_bytes_processed += job.file_size;

                if ((idx + 1) % progress_update_interval == 0 or idx == batch.len - 1) {
                    if (local_files_processed > 0) {
                        worker.progress_tracker.addFilesProcessed(local_files_processed);
                        worker.progress_tracker.addBytesProcessed(local_bytes_processed);
                        local_files_processed = 0;
                        local_bytes_processed = 0;
                    }
                }
            }

            _ = thread_arena.reset(.retain_capacity);
        }

        if (local_files_processed > 0) {
            worker.progress_tracker.addFilesProcessed(local_files_processed);
            worker.progress_tracker.addBytesProcessed(local_bytes_processed);
        }
    }

    pub fn submitJob(self: *Pool, job: FileJob) !void {
        try self.work_queue.push(job);
    }

    /// Fewer threads than asked for is a warning. None at all is an error, since the jobs would never run.
    pub fn start(self: *Pool) !void {
        for (self.threads[0..self.thread_count]) |*thread| {
            thread.* = std.Thread.spawn(.{}, workerThread, .{self}) catch |err| {
                if (self.spawned_count == 0) {
                    std.debug.print("[ERROR] Failed to spawn worker thread: {}\n", .{err});
                    return err;
                }
                std.debug.print("[WARNING] Could not start worker thread {d} of {d}, continuing with {d}: {}\n", .{ self.spawned_count + 1, self.thread_count, self.spawned_count, err });
                break;
            };
            self.spawned_count += 1;
        }

        // Give the workers time to start.
        self.io.sleep(std.Io.Duration.fromNanoseconds(1_000_000), .awake) catch {};
    }

    pub fn finish(self: *Pool) void {
        self.work_queue.markDone();

        for (self.threads[0..self.spawned_count]) |thread| {
            thread.join();
        }
        self.spawned_count = 0;
    }

    /// Start the threads and wait for every job, for callers that queue all their jobs first.
    pub fn waitAll(self: *Pool) !void {
        try self.start();
        self.finish();
    }

    fn markError(self: *Pool) void {
        self.error_mutex.lockUncancelable(self.io);
        self.has_errors = true;
        self.error_mutex.unlock(self.io);
    }

    pub fn hadErrors(self: *Pool) bool {
        self.error_mutex.lockUncancelable(self.io);
        defer self.error_mutex.unlock(self.io);
        return self.has_errors;
    }
};

test "worker pool initialization" {
    const testing = std.testing;
    const allocator = testing.allocator;
    const io = testing.io;

    const key: [crypto.key_length]u8 = @splat(42);
    const derived = crypto.deriveKeys(key, null);
    var tracker = progress.Tracker.init(0, 0, io);

    var pool = try Pool.init(allocator, 4, derived, &tracker, false, false, io);
    defer pool.deinit();

    try testing.expect(!pool.hadErrors());
}

test "worker pool releases jobs that were never started" {
    const testing = std.testing;
    const allocator = testing.allocator;
    const io = testing.io;
    const derived = crypto.deriveKeys(@splat(42), null);
    var tracker = progress.Tracker.init(0, 0, io);
    var pool = try Pool.init(allocator, 1, derived, &tracker, false, false, io);
    defer pool.deinit();

    const source = try allocator.dupe(u8, "source");
    errdefer allocator.free(source);
    const destination = try allocator.dupe(u8, "destination");
    errdefer allocator.free(destination);
    try pool.submitJob(.{
        .source_path = source,
        .dest_path = destination,
        .operation = .encrypt,
        .file_size = 0,
    });
}
