const std = @import("std");
const builtin = @import("builtin");

/// Platform-specific I/O optimization hints
/// Provides unified interface for fadvise, madvise, and related optimizations
/// Advice for file access patterns
pub const FileAdvice = enum {
    sequential, // Sequential access pattern
    random, // Random access pattern
    willneed, // Will need this data soon (prefetch)
    dontneed, // Won't need this data anymore (drop cache)
    noreuse, // Data will be accessed only once
};

/// Advise kernel about file access pattern (Linux: fadvise, macOS: fcntl F_RDADVISE)
pub fn adviseFile(file: std.fs.File, offset: i64, len: i64, advice: FileAdvice) void {
    switch (builtin.os.tag) {
        .linux => {
            const linux_advice: usize = switch (advice) {
                .sequential => std.os.linux.POSIX_FADV.SEQUENTIAL,
                .random => std.os.linux.POSIX_FADV.RANDOM,
                .willneed => std.os.linux.POSIX_FADV.WILLNEED,
                .dontneed => std.os.linux.POSIX_FADV.DONTNEED,
                .noreuse => std.os.linux.POSIX_FADV.NOREUSE,
            };
            _ = std.os.linux.fadvise(file.handle, offset, len, linux_advice);
        },
        .macos, .ios, .tvos, .watchos => {
            // macOS uses fcntl with F_RDADVISE for prefetching
            // and F_RDAHEAD for sequential hints
            // For simplicity, we'll use F_RDAHEAD for sequential access
            // Note: macOS has limited support compared to Linux fadvise
            switch (advice) {
                .sequential, .willneed => {
                    // Enable read-ahead (enabled by default, but we can be explicit)
                    // F_RDAHEAD = 45
                    _ = std.c.fcntl(file.handle, 45, @as(c_int, 1));
                },
                .dontneed => {
                    // macOS doesn't have a direct equivalent to DONTNEED
                    // We could use F_NOCACHE (48) but it's more aggressive
                    // Skip for now to avoid breaking cache for future reads
                },
                else => {},
            }
        },
        else => {
            // No support on other platforms (Windows, etc.)
        },
    }
}

/// Enhanced memory advice with additional hints
pub const MemoryAdvice = enum {
    sequential, // Sequential access pattern
    random, // Random access pattern
    willneed, // Will need this data soon
    dontneed, // Won't need this data anymore
};

/// Advise kernel about memory-mapped region access pattern
pub fn adviseMemory(ptr: [*]align(std.heap.page_size_min) u8, len: usize, advice: MemoryAdvice) void {
    // madvise is supported on both Linux and macOS
    if (builtin.os.tag == .windows) return;

    const posix_advice: u32 = switch (advice) {
        .sequential => std.posix.MADV.SEQUENTIAL,
        .random => std.posix.MADV.RANDOM,
        .willneed => std.posix.MADV.WILLNEED,
        .dontneed => std.posix.MADV.DONTNEED,
    };

    std.posix.madvise(ptr, len, posix_advice) catch {};
}

/// Flush memory-mapped data asynchronously (non-blocking)
pub fn flushAsync(mapped: []align(std.heap.page_size_min) u8) void {
    if (builtin.os.tag == .windows) return;
    std.posix.msync(mapped, std.posix.MSF.ASYNC) catch {};
}

/// Flush memory-mapped data synchronously (blocking until written)
pub fn flushSync(mapped: []align(std.heap.page_size_min) u8) void {
    if (builtin.os.tag == .windows) return;
    std.posix.msync(mapped, std.posix.MSF.SYNC) catch {};
}

/// Sync file data to disk (metadata may not be synced)
pub fn syncFileData(file: std.fs.File) void {
    switch (builtin.os.tag) {
        .linux => {
            // fdatasync - sync data but not necessarily metadata (faster than fsync)
            _ = std.os.linux.fdatasync(@as(i32, @intCast(file.handle)));
        },
        .macos, .ios, .tvos, .watchos => {
            // macOS uses F_FULLFSYNC for true sync, but it's very slow
            // Use fcntl(F_FULLFSYNC) for durability
            // F_FULLFSYNC = 51
            _ = std.c.fcntl(file.handle, 51, @as(c_int, 0));
        },
        else => {
            // Fallback to fsync on other platforms
            file.sync() catch {};
        },
    }
}
