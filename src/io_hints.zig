const std = @import("std");
const builtin = @import("builtin");

pub const FileAdvice = enum {
    sequential,
    random,
    willneed,
    dontneed,
    noreuse,
};

pub fn adviseFile(file: std.Io.File, offset: i64, len: i64, advice: FileAdvice) void {
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
            // macOS has no fadvise. Read-ahead covers the sequential hints.
            // F_NOCACHE is the closest thing to DONTNEED, but it also hurts later reads.
            switch (advice) {
                .sequential, .willneed => {
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
    willneed,
    dontneed,
};

pub fn adviseMemory(ptr: [*]align(std.heap.page_size_min) u8, len: usize, advice: MemoryAdvice) void {
    if (builtin.os.tag == .windows) return;

    const posix_advice: u32 = switch (advice) {
        .sequential => std.posix.MADV.SEQUENTIAL,
        .random => std.posix.MADV.RANDOM,
        .willneed => std.posix.MADV.WILLNEED,
        .dontneed => std.posix.MADV.DONTNEED,
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

/// Push the file data to the disk. The metadata can stay behind.
pub fn syncFileData(file: std.Io.File) void {
    switch (builtin.os.tag) {
        .macos, .ios, .tvos, .watchos => {
            // On macOS, only F_FULLFSYNC makes the drive flush its cache.
            _ = std.c.fcntl(file.handle, std.c.F.FULLFSYNC, @as(c_int, 0));
        },
        else => {
            std.posix.fdatasync(file.handle) catch {};
        },
    }
}
