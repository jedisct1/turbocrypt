//! Provides Debug-only storage failures for RAF recovery tests.
//!
//! RAF chooses its storage type at compile time, so tests need this wrapper to inject faults at runtime.
//! Sync failures are injected separately through `faults.syncFd`.

const FaultStorage = @This();

const std = @import("std");
const Io = std.Io;
const aegis_raf = @import("aegis_raf");
const faults = @import("faults.zig");

inner: aegis_raf.FileStorage,

pub const Error = aegis_raf.FileStorage.Error;

pub fn init(file: Io.File, io: Io) FaultStorage {
    return .{ .inner = .init(file, io) };
}

pub fn readPositionalAll(self: *FaultStorage, buffer: []u8, offset: u64) Error!usize {
    return self.inner.readPositionalAll(buffer, offset);
}

pub fn writePositionalAll(self: *FaultStorage, bytes: []const u8, offset: u64) Error!void {
    if (faults.take(.raf_write_short)) {
        try self.inner.writePositionalAll(bytes[0 .. bytes.len / 2], offset);
        return error.InputOutput;
    }
    return self.inner.writePositionalAll(bytes, offset);
}

pub fn readPositionalVecAll(self: *FaultStorage, buffers: [][]u8, offset: u64) Error!usize {
    return self.inner.readPositionalVecAll(buffers, offset);
}

/// Makes a partial record so tests confirm mixed ciphertext and tags are rejected.
pub fn writePositionalVecAll(self: *FaultStorage, buffers: [][]const u8, offset: u64) Error!void {
    if (faults.take(.raf_writev_short)) {
        var written: u64 = 0;
        if (buffers.len > 0) {
            try self.inner.writePositionalAll(buffers[0], offset);
            written += buffers[0].len;
        }
        if (buffers.len > 1) {
            const torn = buffers[1][0 .. buffers[1].len / 2];
            try self.inner.writePositionalAll(torn, offset + written);
        }
        return error.InputOutput;
    }
    return self.inner.writePositionalVecAll(buffers, offset);
}

pub fn length(self: *FaultStorage) Error!u64 {
    return self.inner.length();
}

pub fn setLength(self: *FaultStorage, new_length: u64) Error!void {
    if (faults.take(.raf_set_length)) return error.NoSpaceLeft;
    _ = faults.take(.raf_set_length_pass);
    return self.inner.setLength(new_length);
}

pub fn sync(self: *FaultStorage) Error!void {
    return self.inner.sync();
}
