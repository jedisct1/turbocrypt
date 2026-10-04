//! Provides best-effort access hints and flushes for files and mappings.
//!
//! These operations only affect performance, so failures do not change correctness.

const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;

pub const FileAdvice = enum {
    sequential,
    random,
    will_need,
    dont_need,
    no_reuse,
};

pub fn adviseFile(file: Io.File, offset: i64, len: i64, advice: FileAdvice) void {
    switch (builtin.os.tag) {
        .linux => {
            const linux_advice: usize = switch (advice) {
                .sequential => std.os.linux.POSIX_FADV.SEQUENTIAL,
                .random => std.os.linux.POSIX_FADV.RANDOM,
                .will_need => std.os.linux.POSIX_FADV.WILLNEED,
                .dont_need => std.os.linux.POSIX_FADV.DONTNEED,
                .no_reuse => std.os.linux.POSIX_FADV.NOREUSE,
            };
            _ = std.os.linux.fadvise(file.handle, offset, len, linux_advice);
        },
        .macos, .ios, .tvos, .watchos => {
            // Use read-ahead because macOS has no fadvise equivalent.
            // Avoid F_NOCACHE because it can penalize reads that follow.
            switch (advice) {
                .sequential, .will_need => {
                    _ = std.c.fcntl(file.handle, std.c.F.RDAHEAD, @as(c_int, 1));
                },
                else => {},
            }
        },
        else => {},
    }
}

pub const MemoryAdvice = enum {
    sequential,
    random,
    will_need,
    dont_need,
};

pub fn adviseMemory(
    ptr: [*]align(std.heap.page_size_min) u8,
    len: usize,
    advice: MemoryAdvice,
) void {
    if (builtin.os.tag == .windows) return;

    const posix_advice: u32 = switch (advice) {
        .sequential => std.posix.MADV.SEQUENTIAL,
        .random => std.posix.MADV.RANDOM,
        .will_need => std.posix.MADV.WILLNEED,
        .dont_need => std.posix.MADV.DONTNEED,
    };

    std.posix.madvise(ptr, len, posix_advice) catch {};
}

pub fn flushAsync(mapped: []align(std.heap.page_size_min) u8) void {
    if (builtin.os.tag == .windows) return;
    std.posix.msync(mapped, std.posix.MSF.ASYNC) catch {};
}

pub fn flushSync(mapped: []align(std.heap.page_size_min) u8) void {
    if (builtin.os.tag == .windows) return;
    std.posix.msync(mapped, std.posix.MSF.SYNC) catch {};
}

/// Request that file data reach stable storage without forcing metadata updates.
pub fn syncFileData(file: Io.File) void {
    switch (builtin.os.tag) {
        .macos, .ios, .tvos, .watchos => {
            // Use F_FULLFSYNC so macOS also asks the drive to flush its cache.
            _ = std.c.fcntl(file.handle, std.c.F.FULLFSYNC, @as(c_int, 0));
        },
        else => {
            std.posix.fdatasync(file.handle) catch {};
        },
    }
}
