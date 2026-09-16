//! Inject torn writes and failed resizes in Debug builds.
//!
//! RAF fixes storage at compile time, so runtime fault injection needs this wrapper.
//! Sync faults belong to the mount's `syncFd` helper.

const std = @import("std");
const aegis_raf = @import("aegis_raf");
const node_mod = @import("node.zig");

pub const FaultStorage = struct {
    pub const Error = aegis_raf.FileStorage.Error;

    inner: aegis_raf.FileStorage,

    pub fn init(file: std.Io.File, io: std.Io) FaultStorage {
        return .{ .inner = aegis_raf.FileStorage.init(file, io) };
    }

    pub fn readPositionalAll(self: *FaultStorage, buffer: []u8, offset: u64) Error!usize {
        return self.inner.readPositionalAll(buffer, offset);
    }

    pub fn writePositionalAll(self: *FaultStorage, bytes: []const u8, offset: u64) Error!void {
        if (node_mod.takeFault(.raf_write_short)) {
            try self.inner.writePositionalAll(bytes[0 .. bytes.len / 2], offset);
            return error.InputOutput;
        }
        return self.inner.writePositionalAll(bytes, offset);
    }

    pub fn readPositionalVecAll(self: *FaultStorage, buffers: [][]u8, offset: u64) Error!usize {
        return self.inner.readPositionalVecAll(buffers, offset);
    }

    /// Tear a record after its nonce to test rejection of mixed ciphertext and tags.
    pub fn writePositionalVecAll(self: *FaultStorage, buffers: [][]const u8, offset: u64) Error!void {
        if (node_mod.takeFault(.raf_writev_short)) {
            var written: u64 = 0;
            if (buffers.len > 0) {
                try self.inner.writePositionalAll(buffers[0], offset);
                written += buffers[0].len;
            }
            if (buffers.len > 1) {
                try self.inner.writePositionalAll(buffers[1][0 .. buffers[1].len / 2], offset + written);
            }
            return error.InputOutput;
        }
        return self.inner.writePositionalVecAll(buffers, offset);
    }

    pub fn length(self: *FaultStorage) Error!u64 {
        return self.inner.length();
    }

    pub fn setLength(self: *FaultStorage, new_length: u64) Error!void {
        if (node_mod.takeFault(.raf_set_length)) return error.NoSpaceLeft;
        _ = node_mod.takeFault(.raf_set_length_pass);
        return self.inner.setLength(new_length);
    }

    pub fn sync(self: *FaultStorage) Error!void {
        return self.inner.sync();
    }
};
