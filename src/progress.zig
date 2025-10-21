const std = @import("std");

/// Thread-safe progress tracker for file processing operations
pub const ProgressTracker = struct {
    files_processed: std.atomic.Value(u64),
    files_failed: std.atomic.Value(u64),
    bytes_processed: std.atomic.Value(u64),
    total_files: std.atomic.Value(u64),
    total_bytes: std.atomic.Value(u64),
    start_time: i64,
    last_update_time: std.atomic.Value(i64),
    display_thread: ?std.Thread,
    should_stop: std.atomic.Value(bool),
    mutex: std.Thread.Mutex,

    const Self = @This();

    /// Initialize a new progress tracker
    pub fn init(total_files: u64, total_bytes: u64) Self {
        return Self{
            .files_processed = std.atomic.Value(u64).init(0),
            .files_failed = std.atomic.Value(u64).init(0),
            .bytes_processed = std.atomic.Value(u64).init(0),
            .total_files = std.atomic.Value(u64).init(total_files),
            .total_bytes = std.atomic.Value(u64).init(total_bytes),
            .start_time = std.time.milliTimestamp(),
            .last_update_time = std.atomic.Value(i64).init(std.time.milliTimestamp()),
            .display_thread = null,
            .should_stop = std.atomic.Value(bool).init(false),
            .mutex = std.Thread.Mutex{},
        };
    }

    /// Increment files processed counter
    pub fn addFileProcessed(self: *Self) void {
        _ = self.files_processed.fetchAdd(1, .monotonic);
    }

    /// Add multiple files to processed counter (batch update)
    pub fn addFilesProcessed(self: *Self, count: u64) void {
        _ = self.files_processed.fetchAdd(count, .monotonic);
    }

    /// Increment files failed counter
    pub fn addFileFailed(self: *Self) void {
        _ = self.files_failed.fetchAdd(1, .monotonic);
    }

    /// Add bytes processed
    pub fn addBytesProcessed(self: *Self, bytes: u64) void {
        _ = self.bytes_processed.fetchAdd(bytes, .monotonic);
    }

    /// Add to total files (for dynamic discovery during scanning)
    pub fn addTotalFile(self: *Self) void {
        _ = self.total_files.fetchAdd(1, .monotonic);
    }

    /// Add to total bytes (for dynamic discovery during scanning)
    pub fn addTotalBytes(self: *Self, bytes: u64) void {
        _ = self.total_bytes.fetchAdd(bytes, .monotonic);
    }

    /// Get total files count
    pub fn getTotalFiles(self: *Self) u64 {
        return self.total_files.load(.monotonic);
    }

    /// Get total bytes count
    pub fn getTotalBytes(self: *Self) u64 {
        return self.total_bytes.load(.monotonic);
    }

    /// Get current files processed count
    pub fn getFilesProcessed(self: *Self) u64 {
        return self.files_processed.load(.monotonic);
    }

    /// Get current files failed count
    pub fn getFilesFailed(self: *Self) u64 {
        return self.files_failed.load(.monotonic);
    }

    /// Get current bytes processed count
    pub fn getBytesProcessed(self: *Self) u64 {
        return self.bytes_processed.load(.monotonic);
    }

    /// Calculate current throughput in Mb/s (megabits per second)
    pub fn getThroughput(self: *Self) f64 {
        const now = std.time.milliTimestamp();
        const elapsed_ms = now - self.start_time;
        if (elapsed_ms <= 0) return 0.0;

        const bytes = @as(f64, @floatFromInt(self.getBytesProcessed()));
        const elapsed_s = @as(f64, @floatFromInt(elapsed_ms)) / 1000.0;
        const bits = bytes * 8.0;
        const megabits = bits / (1000.0 * 1000.0);
        return megabits / elapsed_s;
    }

    /// Format bytes to human-readable string (KB, MB, GB)
    fn formatBytes(bytes: u64, buf: []u8) []const u8 {
        const fb = @as(f64, @floatFromInt(bytes));

        if (bytes < 1024) {
            return std.fmt.bufPrint(buf, "{d} B", .{bytes}) catch "? B";
        } else if (bytes < 1024 * 1024) {
            return std.fmt.bufPrint(buf, "{d:.1} KB", .{fb / 1024.0}) catch "? KB";
        } else if (bytes < 1024 * 1024 * 1024) {
            return std.fmt.bufPrint(buf, "{d:.1} MB", .{fb / (1024.0 * 1024.0)}) catch "? MB";
        } else {
            return std.fmt.bufPrint(buf, "{d:.2} GB", .{fb / (1024.0 * 1024.0 * 1024.0)}) catch "? GB";
        }
    }

    /// Display current progress (thread-safe)
    pub fn display(self: *Self) void {
        // Read all atomic values without locking (reads are lock-free)
        const files_done = self.getFilesProcessed();
        const files_failed = self.getFilesFailed();
        const bytes_done = self.getBytesProcessed();
        const total_files = self.getTotalFiles();
        const total_bytes = self.getTotalBytes();
        const throughput = self.getThroughput();

        const file_percent = if (total_files > 0)
            (@as(f64, @floatFromInt(files_done)) / @as(f64, @floatFromInt(total_files))) * 100.0
        else
            0.0;

        var bytes_done_buf: [32]u8 = undefined;
        var total_bytes_buf: [32]u8 = undefined;

        const bytes_done_str = formatBytes(bytes_done, &bytes_done_buf);
        const total_bytes_str = formatBytes(total_bytes, &total_bytes_buf);

        // Lock only for the printf to avoid interleaved output
        // This is much faster than locking for the entire computation
        self.mutex.lock();
        defer self.mutex.unlock();

        // Use \r to overwrite the same line
        std.debug.print("\rProcessing: {d}/{d} files ({d:.1}%) | {s} / {s} | {d:.1} Mb/s", .{
            files_done,
            total_files,
            file_percent,
            bytes_done_str,
            total_bytes_str,
            throughput,
        });

        if (files_failed > 0) {
            std.debug.print(" | Failed: {d}", .{files_failed});
        }
    }

    /// Display final summary
    pub fn displayFinal(self: *Self) void {
        // Read all values without locking first
        const files_done = self.getFilesProcessed();
        const files_failed = self.getFilesFailed();
        const bytes_done = self.getBytesProcessed();
        const total_files = self.getTotalFiles();

        const now = std.time.milliTimestamp();
        const elapsed_ms = now - self.start_time;
        const elapsed_s = @as(f64, @floatFromInt(elapsed_ms)) / 1000.0;

        var bytes_buf: [32]u8 = undefined;
        const bytes_str = formatBytes(bytes_done, &bytes_buf);

        // Compute throughput
        var avg_throughput: f64 = 0.0;
        if (elapsed_s > 0) {
            const bits = @as(f64, @floatFromInt(bytes_done)) * 8.0;
            const megabits = bits / (1000.0 * 1000.0);
            avg_throughput = megabits / elapsed_s;
        }

        // Lock only for output
        self.mutex.lock();
        defer self.mutex.unlock();

        std.debug.print("\n\nCompleted in {d:.2}s\n", .{elapsed_s});
        std.debug.print("Files processed: {d}/{d}\n", .{ files_done, total_files });
        if (files_failed > 0) {
            std.debug.print("Files failed: {d}\n", .{files_failed});
        }
        std.debug.print("Total data processed: {s}\n", .{bytes_str});

        if (elapsed_s > 0) {
            std.debug.print("Average throughput: {d:.1} Mb/s\n", .{avg_throughput});
        }
    }

    /// Display update thread function
    fn displayUpdateThread(self: *Self) void {
        while (!self.should_stop.load(.acquire)) {
            self.display();
            std.Thread.sleep(100 * std.time.ns_per_ms); // Update every 100ms
        }
    }

    /// Start background display updates
    pub fn startDisplay(self: *Self) !void {
        self.should_stop.store(false, .release);
        self.display_thread = try std.Thread.spawn(.{}, displayUpdateThread, .{self});
    }

    /// Stop background display updates
    pub fn stopDisplay(self: *Self) void {
        self.should_stop.store(true, .release);
        if (self.display_thread) |thread| {
            thread.join();
            self.display_thread = null;
        }
    }
};

test "progress tracker basic operations" {
    const testing = std.testing;

    var tracker = ProgressTracker.init(100, 1024 * 1024 * 100);

    // Test initial state
    try testing.expectEqual(@as(u64, 0), tracker.getFilesProcessed());
    try testing.expectEqual(@as(u64, 0), tracker.getFilesFailed());
    try testing.expectEqual(@as(u64, 0), tracker.getBytesProcessed());

    // Test incrementing
    tracker.addFileProcessed();
    tracker.addBytesProcessed(1024 * 1024);
    try testing.expectEqual(@as(u64, 1), tracker.getFilesProcessed());
    try testing.expectEqual(@as(u64, 1024 * 1024), tracker.getBytesProcessed());

    // Test failed counter
    tracker.addFileFailed();
    try testing.expectEqual(@as(u64, 1), tracker.getFilesFailed());
}
