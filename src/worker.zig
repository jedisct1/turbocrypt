//! Background workers for file encryption, decryption, and verification.

const std = @import("std");
const testing = std.testing;
const Allocator = std.mem.Allocator;
const Io = std.Io;

const crypto = @import("crypto.zig");
const processor = @import("processor.zig");
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
    pool: *Pool,
    job: FileJob,
    err: anyerror,
    error_prefix: []const u8,
    is_encrypt: bool,
) void {
    // Keep slow terminal output from blocking other workers that hit an error.
    std.debug.print("\n{s} {s}\n", .{ error_prefix, job.source_path });
    printErrorDetails(err, is_encrypt);

    pool.markError();
    pool.progress_tracker.addFileFailed();
}

pub const Operation = enum {
    encrypt,
    decrypt,
    verify,
};

pub const FileJob = struct {
    source_path: []const u8,
    /// Verification reads the source and does not need a destination.
    dest_path: ?[]const u8,
    operation: Operation,
    file_size: u64,
    /// Suffix mode removes the old name after its replacement is safely published.
    delete_source: bool = false,
};

const WorkQueue = struct {
    mutex: Io.Mutex,
    jobs: std.ArrayList(FileJob),
    gpa: Allocator,
    done: bool,
    io: Io,

    pub fn init(gpa: Allocator, io: Io) WorkQueue {
        return .{
            .mutex = .init,
            .jobs = .empty,
            .gpa = gpa,
            .done = false,
            .io = io,
        };
    }

    pub fn deinit(self: *WorkQueue) void {
        for (self.jobs.items) |job| {
            self.gpa.free(job.source_path);
            if (job.dest_path) |dest_path| self.gpa.free(dest_path);
        }
        self.jobs.deinit(self.gpa);
    }

    pub fn push(self: *WorkQueue, job: FileJob) !void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        try self.jobs.append(self.gpa, job);
    }

    /// Wait for a batch, returning null only after no more jobs can arrive.
    /// The caller frees each returned batch.
    pub fn popBatch(self: *WorkQueue, max_count: usize) !?[]FileJob {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);

        if (self.jobs.items.len == 0) {
            if (self.done) return null;
            return try self.gpa.alloc(FileJob, 0);
        }

        const batch_size = @min(max_count, self.jobs.items.len);

        const batch = try self.gpa.alloc(FileJob, batch_size);
        @memcpy(batch, self.jobs.items[0..batch_size]);

        const remaining = self.jobs.items.len - batch_size;
        if (remaining > 0 and batch_size > 0) {
            @memmove(self.jobs.items[0..remaining], self.jobs.items[batch_size..]);
        }
        self.jobs.shrinkRetainingCapacity(remaining);

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
        return self.jobs.items.len == 0 and self.done;
    }
};

const max_batch_size: usize = 16;
const progress_update_interval: usize = 10;

pub const Pool = struct {
    gpa: Allocator,
    work_queue: WorkQueue,
    threads: []std.Thread,
    spawned_count: usize,
    thread_count: u32,
    derived_keys: crypto.DerivedKeys,
    progress_tracker: *progress.Tracker,
    error_mutex: Io.Mutex,
    has_errors: bool,
    quick_verify: bool,
    dry_run: bool,
    io: Io,

    pub fn init(
        gpa: Allocator,
        io: Io,
        thread_count: u32,
        derived_keys: crypto.DerivedKeys,
        progress_tracker: *progress.Tracker,
        quick_verify: bool,
        dry_run: bool,
    ) !Pool {
        const threads = try gpa.alloc(std.Thread, thread_count);
        errdefer gpa.free(threads);

        return .{
            .gpa = gpa,
            .work_queue = .init(gpa, io),
            .threads = threads,
            .spawned_count = 0,
            .thread_count = thread_count,
            .derived_keys = derived_keys,
            .progress_tracker = progress_tracker,
            .error_mutex = .init,
            .has_errors = false,
            .quick_verify = quick_verify,
            .dry_run = dry_run,
            .io = io,
        };
    }

    /// Stop the workers before freeing the queue they still use.
    pub fn deinit(self: *Pool) void {
        self.finish();
        self.work_queue.deinit();
        self.gpa.free(self.threads);
    }

    fn workerThread(pool: *Pool) void {
        // Give each worker private scratch space instead of making them compete for allocations.
        var arena_state = std.heap.ArenaAllocator.init(pool.gpa);
        defer arena_state.deinit();
        const arena = arena_state.allocator();

        // Report progress in batches so bookkeeping does not dominate small jobs.
        var local_files_processed: u64 = 0;
        var local_bytes_processed: u64 = 0;

        while (true) {
            const maybe_batch = pool.work_queue.popBatch(max_batch_size) catch |err| {
                std.debug.print("[ERROR] Failed to pop batch: {}\n", .{err});
                pool.markError();
                break;
            };

            const batch = maybe_batch orelse break;
            defer pool.gpa.free(batch);

            if (batch.len == 0) {
                pool.io.sleep(.fromNanoseconds(1_000_000), .awake) catch {};
                continue;
            }

            for (batch, 0..) |job, i| {
                // Free these paths here because the queue transferred ownership to this worker.
                defer pool.gpa.free(job.source_path);
                defer if (job.dest_path) |dest| pool.gpa.free(dest);

                if (!pool.dry_run) {
                    switch (job.operation) {
                        .encrypt => {
                            processor.encryptFile(
                                arena,
                                pool.io,
                                job.source_path,
                                job.dest_path.?,
                                pool.derived_keys,
                            ) catch |err| {
                                handleJobError(pool, job, err, "[ERROR] Failed to encrypt:", true);
                                continue;
                            };
                        },
                        .decrypt => {
                            processor.decryptFile(
                                arena,
                                pool.io,
                                job.source_path,
                                job.dest_path.?,
                                pool.derived_keys,
                            ) catch |err| {
                                handleJobError(pool, job, err, "[ERROR] Failed to decrypt:", false);
                                continue;
                            };
                        },
                        .verify => {
                            processor.verifyFile(
                                arena,
                                pool.io,
                                job.source_path,
                                pool.derived_keys,
                                pool.quick_verify,
                            ) catch |err| {
                                handleJobError(pool, job, err, "[VERIFY FAILED]", false);
                                continue;
                            };
                        },
                    }

                    if (job.delete_source) {
                        Io.Dir.deleteFile(.cwd(), pool.io, job.source_path) catch |err| {
                            handleJobError(
                                pool,
                                job,
                                err,
                                "[ERROR] Failed to remove source file:",
                                job.operation == .encrypt,
                            );
                            continue;
                        };
                    }
                }

                local_files_processed += 1;
                local_bytes_processed += job.file_size;

                if ((i + 1) % progress_update_interval == 0 or i == batch.len - 1) {
                    if (local_files_processed > 0) {
                        pool.progress_tracker.addFilesProcessed(local_files_processed);
                        pool.progress_tracker.addBytesProcessed(local_bytes_processed);
                        local_files_processed = 0;
                        local_bytes_processed = 0;
                    }
                }
            }

            _ = arena_state.reset(.retain_capacity);
        }

        if (local_files_processed > 0) {
            pool.progress_tracker.addFilesProcessed(local_files_processed);
            pool.progress_tracker.addBytesProcessed(local_bytes_processed);
        }
    }

    pub fn submitJob(self: *Pool, job: FileJob) !void {
        try self.work_queue.push(job);
    }

    /// Keep working if some workers cannot start.
    /// Fail only when there is no worker left to process the queue.
    pub fn start(self: *Pool) !void {
        for (self.threads[0..self.thread_count]) |*thread| {
            thread.* = std.Thread.spawn(.{}, workerThread, .{self}) catch |err| {
                if (self.spawned_count == 0) {
                    std.debug.print("[ERROR] Failed to spawn worker thread: {}\n", .{err});
                    return err;
                }
                std.debug.print("[WARNING] Could not start worker thread {d} of {d}, continuing with {d}: {}\n", .{
                    self.spawned_count + 1,
                    self.thread_count,
                    self.spawned_count,
                    err,
                });
                break;
            };
            self.spawned_count += 1;
        }

        // Let the workers begin before the caller adds more work.
        self.io.sleep(.fromNanoseconds(1_000_000), .awake) catch {};
    }

    pub fn finish(self: *Pool) void {
        self.work_queue.markDone();

        for (self.threads[0..self.spawned_count]) |thread| {
            thread.join();
        }
        self.spawned_count = 0;
    }

    /// Run a queue that was filled before any worker started.
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

test "a new pool has no errors" {
    const gpa = testing.allocator;
    const io = testing.io;
    const derived = crypto.deriveKeys(@splat(42), null);
    var tracker = progress.Tracker.init(io, 0, 0);

    var pool = try Pool.init(gpa, io, 4, derived, &tracker, false, false);
    defer pool.deinit();

    try testing.expect(!pool.hadErrors());
}

test "pool frees jobs that were never started" {
    const gpa = testing.allocator;
    const io = testing.io;
    const derived = crypto.deriveKeys(@splat(42), null);
    var tracker = progress.Tracker.init(io, 0, 0);
    var pool = try Pool.init(gpa, io, 1, derived, &tracker, false, false);
    defer pool.deinit();

    const source = try gpa.dupe(u8, "source");
    errdefer gpa.free(source);
    const dest = try gpa.dupe(u8, "destination");
    errdefer gpa.free(dest);
    try pool.submitJob(.{
        .source_path = source,
        .dest_path = dest,
        .operation = .encrypt,
        .file_size = 0,
    });
}
