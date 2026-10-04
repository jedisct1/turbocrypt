const std = @import("std");
const testing = std.testing;
const Io = std.Io;

/// Tracks progress safely while a background thread refreshes the display.
pub const Tracker = struct {
    files_processed: std.atomic.Value(u64),
    files_failed: std.atomic.Value(u64),
    bytes_processed: std.atomic.Value(u64),
    total_files: std.atomic.Value(u64),
    total_bytes: std.atomic.Value(u64),
    start_time: Io.Clock.Timestamp,
    display_thread: ?std.Thread,
    should_stop: std.atomic.Value(bool),
    mutex: Io.Mutex,
    io: Io,

    pub fn init(io: Io, total_files: u64, total_bytes: u64) Tracker {
        return .{
            .files_processed = .init(0),
            .files_failed = .init(0),
            .bytes_processed = .init(0),
            .total_files = .init(total_files),
            .total_bytes = .init(total_bytes),
            .start_time = .now(io, .awake),
            .display_thread = null,
            .should_stop = .init(false),
            .mutex = .init,
            .io = io,
        };
    }

    pub fn addFileProcessed(self: *Tracker) void {
        _ = self.files_processed.fetchAdd(1, .monotonic);
    }

    pub fn addFilesProcessed(self: *Tracker, count: u64) void {
        _ = self.files_processed.fetchAdd(count, .monotonic);
    }

    pub fn addFileFailed(self: *Tracker) void {
        _ = self.files_failed.fetchAdd(1, .monotonic);
    }

    pub fn addBytesProcessed(self: *Tracker, bytes: u64) void {
        _ = self.bytes_processed.fetchAdd(bytes, .monotonic);
    }

    pub fn addTotalFile(self: *Tracker) void {
        _ = self.total_files.fetchAdd(1, .monotonic);
    }

    pub fn addTotalBytes(self: *Tracker, bytes: u64) void {
        _ = self.total_bytes.fetchAdd(bytes, .monotonic);
    }

    pub fn getTotalFiles(self: *Tracker) u64 {
        return self.total_files.load(.monotonic);
    }

    pub fn getTotalBytes(self: *Tracker) u64 {
        return self.total_bytes.load(.monotonic);
    }

    pub fn getFilesProcessed(self: *Tracker) u64 {
        return self.files_processed.load(.monotonic);
    }

    pub fn getFilesFailed(self: *Tracker) u64 {
        return self.files_failed.load(.monotonic);
    }

    pub fn getBytesProcessed(self: *Tracker) u64 {
        return self.bytes_processed.load(.monotonic);
    }

    /// Returns average throughput since tracking began, in megabits per second.
    pub fn getThroughput(self: *Tracker) f64 {
        const elapsed = self.start_time.untilNow(self.io);
        const elapsed_ns = elapsed.raw.nanoseconds;
        if (elapsed_ns <= 0) return 0.0;

        const bytes: f64 = @floatFromInt(self.getBytesProcessed());
        const elapsed_s = @as(f64, @floatFromInt(elapsed_ns)) / 1_000_000_000.0;
        const bits = bytes * 8.0;
        const megabits = bits / (1000.0 * 1000.0);
        return megabits / elapsed_s;
    }

    fn formatBytes(bytes: u64, buf: []u8) []const u8 {
        const fb: f64 = @floatFromInt(bytes);

        if (bytes < 1024) {
            return std.mem.print(buf, "{d} B", .{bytes}) catch "? B";
        } else if (bytes < 1024 * 1024) {
            return std.mem.print(buf, "{d:.1} KB", .{fb / 1024.0}) catch "? KB";
        } else if (bytes < 1024 * 1024 * 1024) {
            return std.mem.print(buf, "{d:.1} MB", .{fb / (1024.0 * 1024.0)}) catch "? MB";
        } else {
            const gb = fb / (1024.0 * 1024.0 * 1024.0);
            return std.mem.print(buf, "{d:.2} GB", .{gb}) catch "? GB";
        }
    }

    pub fn display(self: *Tracker) void {
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

        // Keep live and final status output from mixing together.
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);

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

    pub fn displayFinal(self: *Tracker) void {
        const files_done = self.getFilesProcessed();
        const files_failed = self.getFilesFailed();
        const bytes_done = self.getBytesProcessed();
        const total_files = self.getTotalFiles();

        const elapsed = self.start_time.untilNow(self.io);
        const elapsed_ns = elapsed.raw.nanoseconds;
        const elapsed_s = @as(f64, @floatFromInt(elapsed_ns)) / 1_000_000_000.0;

        var bytes_buf: [32]u8 = undefined;
        const bytes_str = formatBytes(bytes_done, &bytes_buf);

        var avg_throughput: f64 = 0.0;
        if (elapsed_s > 0) {
            const bits = @as(f64, @floatFromInt(bytes_done)) * 8.0;
            const megabits = bits / (1000.0 * 1000.0);
            avg_throughput = megabits / elapsed_s;
        }

        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);

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

    fn displayUpdateThread(self: *Tracker) void {
        while (!self.should_stop.load(.acquire)) {
            self.display();
            self.io.sleep(.fromMilliseconds(100), .awake) catch {};
        }
    }

    pub fn startDisplay(self: *Tracker) !void {
        self.should_stop.store(false, .release);
        self.display_thread = try std.Thread.spawn(.{}, displayUpdateThread, .{self});
    }

    pub fn stopDisplay(self: *Tracker) void {
        self.should_stop.store(true, .release);
        if (self.display_thread) |thread| {
            thread.join();
            self.display_thread = null;
        }
    }
};

test "tracker counts processed files, bytes and failures" {
    const io = testing.io;

    var tracker = Tracker.init(io, 100, 1024 * 1024 * 100);

    try testing.expectEqual(0, tracker.getFilesProcessed());
    try testing.expectEqual(0, tracker.getFilesFailed());
    try testing.expectEqual(0, tracker.getBytesProcessed());

    tracker.addFileProcessed();
    tracker.addBytesProcessed(1024 * 1024);
    try testing.expectEqual(1, tracker.getFilesProcessed());
    try testing.expectEqual(1024 * 1024, tracker.getBytesProcessed());

    tracker.addFileFailed();
    try testing.expectEqual(1, tracker.getFilesFailed());
}
