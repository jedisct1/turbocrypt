//! Inject failures into mount recovery tests.
//!
//! Only enable injected failures in Debug builds.

const std = @import("std");
const builtin = @import("builtin");

pub const Kind = enum {
    ciphertext_alloc,
    plaintext_realloc,
    file_sync,
    dir_sync,
    /// Fail syncing a clean file after metadata changes.
    metadata_sync,
    create_write,
    /// Write only part of the next RAF storage update, then fail.
    raf_write_short,
    /// Tear the next RAF record between vector buffers.
    raf_writev_short,
    raf_set_length,
    /// Let one resize through to reach the later fault.
    raf_set_length_pass,
};

pub const max_armed = 8;

var armed: [max_armed]?Kind = @splat(null);
var next: std.atomic.Value(usize) = .init(0);

/// Consume armed failures in order; arm them before callbacks run.
pub fn arm(list: []const Kind) void {
    armed = @splat(null);
    for (list, 0..) |fault, i| {
        if (i < armed.len) armed[i] = fault;
    }
    next.store(0, .seq_cst);
}

/// Consume and report the next armed fault only when it matches `kind`.
pub fn take(kind: Kind) bool {
    if (builtin.mode != .debug) return false;
    const index = next.load(.seq_cst);
    if (index >= armed.len or armed[index] != kind) return false;
    return next.cmpxchgStrong(index, index + 1, .seq_cst, .seq_cst) == null;
}

/// Force data to stable storage; macOS needs FULLFSYNC in addition to fsync.
pub fn syncFd(fd: std.c.fd_t, fault: Kind) !void {
    if (take(fault)) return error.InputOutput;
    if (std.c.fsync(fd) != 0) return error.InputOutput;
    if (builtin.os.tag == .macos) {
        // Full sync also works on APFS and HFS+ directories, so its failure matters.
        if (std.c.fcntl(fd, std.c.F.FULLFSYNC, @as(c_int, 0)) != 0) return error.InputOutput;
    }
}
