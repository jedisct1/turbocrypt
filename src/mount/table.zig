//! Share open-node ownership between the two mount backends.
//!
//! One backing path maps to one node, even as it is renamed.
//!
//! A node type must provide the following state:
//!
//! `path` is owned by the table and stays relative to the backing root.
//! `refs` starts at one and is protected by the table mutex.
//! `mutex` starts initialized and guards node-specific state.
//! `unlinked` starts false and tells the table to omit the node.
//! `retainAtZeroRefs` decides retention while both locks are held.
//! `deinitData` releases the node resources when the table drops it.
//!
//!
//!
//!
//!
//! New nodes start as `.{ .path = owned_path }`, so every other field needs a safe default.

const std = @import("std");
const mem = std.mem;
const testing = std.testing;
const Allocator = std.mem.Allocator;
const Io = std.Io;

/// Bound v1 plaintext staging across all open files.
/// RAF nodes do not charge this budget.
pub const Budget = struct {
    limit: usize,
    charged: std.atomic.Value(usize) = .init(0),

    /// Reject a charge without changing the total when it would exceed the budget.
    pub fn charge(self: *Budget, amount: usize) bool {
        var current = self.charged.load(.monotonic);
        while (true) {
            const next = std.math.add(usize, current, amount) catch return false;
            if (next > self.limit) return false;
            current = self.charged.cmpxchgWeak(current, next, .monotonic, .monotonic) orelse
                return true;
        }
    }

    pub fn release(self: *Budget, amount: usize) void {
        _ = self.charged.fetchSub(amount, .monotonic);
    }

    pub fn used(self: *Budget) usize {
        return self.charged.load(.monotonic);
    }
};

pub fn Table(comptime NodeType: type) type {
    return struct {
        pub const Node = NodeType;

        gpa: Allocator,
        io: Io,
        mutex: Io.Mutex = .init,
        nodes: std.ArrayList(*NodeType) = .empty,
        budget: Budget,
        max_file_size: usize,

        /// Hold node paths steady while a backing rename is either committed or abandoned.
        pub const Rekey = struct {
            table: *Table(NodeType),
            nodes: std.ArrayList(*NodeType) = .empty,
            paths: std.ArrayList([]u8) = .empty,
            /// The rename's displaced destination, if it remains open or retained.
            target: ?*NodeType = null,

            /// Commit only after the backing rename succeeds.
            pub fn commit(self: *Rekey) void {
                const gpa = self.table.gpa;
                for (self.nodes.items, self.paths.items) |node, path| {
                    gpa.free(node.path);
                    node.path = path;
                }
                if (self.target) |target| {
                    target.unlinked.store(true, .release);
                    // No handle remains to release this displaced node.
                    if (target.refs == 0) {
                        target.mutex.unlock(self.table.io);
                        self.table.removeLocked(target);
                        self.table.destroyNode(target);
                        self.target = null;
                    }
                }
                self.finish();
            }

            pub fn abort(self: *Rekey) void {
                for (self.paths.items) |path| self.table.gpa.free(path);
                self.finish();
            }

            fn finish(self: *Rekey) void {
                for (self.nodes.items) |node| node.mutex.unlock(self.table.io);
                if (self.target) |target| target.mutex.unlock(self.table.io);
                self.nodes.deinit(self.table.gpa);
                self.paths.deinit(self.table.gpa);
                self.table.mutex.unlock(self.table.io);
            }
        };

        pub fn init(
            gpa: Allocator,
            io: Io,
            max_file_size: usize,
            memory_limit: usize,
        ) Table(NodeType) {
            return .{
                .gpa = gpa,
                .io = io,
                .budget = .{ .limit = memory_limit },
                .max_file_size = max_file_size,
            };
        }

        /// Tear down the table only after all callbacks have stopped.
        pub fn deinit(self: *Table(NodeType)) void {
            for (self.nodes.items) |node| self.destroyNode(node);
            self.nodes.deinit(self.gpa);
        }

        /// Reuse a linked node for this path, or create one and return the caller's reference.
        pub fn attach(self: *Table(NodeType), path: []const u8) error{OutOfMemory}!*NodeType {
            self.mutex.lockUncancelable(self.io);
            defer self.mutex.unlock(self.io);
            if (self.findLocked(path)) |node| {
                node.refs += 1;
                return node;
            }
            const node = try self.gpa.create(NodeType);
            errdefer self.gpa.destroy(node);
            node.* = .{ .path = try self.gpa.dupe(u8, path) };
            errdefer self.gpa.free(node.path);
            try self.nodes.append(self.gpa, node);
            return node;
        }

        /// Add a reference only if the node already exists.
        pub fn pin(self: *Table(NodeType), path: []const u8) ?*NodeType {
            self.mutex.lockUncancelable(self.io);
            defer self.mutex.unlock(self.io);
            const node = self.findLocked(path) orelse return null;
            node.refs += 1;
            return node;
        }

        /// Pin each node so it survives the caller's iteration.
        /// The caller releases every pin and frees the returned list.
        pub fn pinAll(self: *Table(NodeType), gpa: Allocator) error{OutOfMemory}![]*NodeType {
            self.mutex.lockUncancelable(self.io);
            defer self.mutex.unlock(self.io);
            const list = try gpa.dupe(*NodeType, self.nodes.items);
            for (list) |node| node.refs += 1;
            return list;
        }

        /// Drop a reference.
        /// The node decides whether zero references should keep it alive.
        pub fn release(self: *Table(NodeType), node: *NodeType) void {
            self.mutex.lockUncancelable(self.io);
            defer self.mutex.unlock(self.io);
            node.refs -= 1;
            if (node.refs != 0) return;
            node.mutex.lockUncancelable(self.io);
            const retain = node.retainAtZeroRefs();
            node.mutex.unlock(self.io);
            if (retain) return;
            self.removeLocked(node);
            self.destroyNode(node);
        }

        /// Allocate replacement paths before renaming so memory pressure cannot split backing paths from node paths.
        /// Keep the table and affected nodes locked until the rename either commits or aborts.
        ///
        /// Lock the destination too, so its pending write-back cannot replace the renamed source.
        pub fn beginRekey(
            self: *Table(NodeType),
            old: []const u8,
            new: []const u8,
            is_directory: bool,
        ) error{OutOfMemory}!Rekey {
            self.mutex.lockUncancelable(self.io);
            errdefer self.mutex.unlock(self.io);
            var rekey: Rekey = .{ .table = self };
            if (mem.eql(u8, old, new)) return rekey;
            errdefer {
                for (rekey.paths.items) |path| self.gpa.free(path);
                rekey.paths.deinit(self.gpa);
                rekey.nodes.deinit(self.gpa);
            }
            for (self.nodes.items) |node| {
                if (node.unlinked.load(.acquire)) continue;
                if (pathSuffix(node.path, old, is_directory)) |rest| {
                    try rekey.nodes.append(self.gpa, node);
                    const path = try mem.concat(self.gpa, u8, &.{ new, rest });
                    errdefer self.gpa.free(path);
                    try rekey.paths.append(self.gpa, path);
                } else if (!is_directory and mem.eql(u8, node.path, new)) {
                    rekey.target = node;
                }
            }
            for (rekey.nodes.items) |node| node.mutex.lockUncancelable(self.io);
            if (rekey.target) |target| target.mutex.lockUncancelable(self.io);
            return rekey;
        }

        fn findLocked(self: *Table(NodeType), path: []const u8) ?*NodeType {
            for (self.nodes.items) |node| {
                if (!node.unlinked.load(.acquire) and mem.eql(u8, node.path, path)) return node;
            }
            return null;
        }

        fn removeLocked(self: *Table(NodeType), node: *NodeType) void {
            const index = mem.findScalar(*NodeType, self.nodes.items, node).?;
            _ = self.nodes.swapRemove(index);
        }

        fn destroyNode(self: *Table(NodeType), node: *NodeType) void {
            node.deinitData(self);
            self.gpa.free(node.path);
            self.gpa.destroy(node);
        }
    };
}

/// Match complete path components so renaming `a` never catches `ab`.
pub fn pathSuffix(path: []const u8, prefix: []const u8, is_directory: bool) ?[]const u8 {
    if (mem.eql(u8, path, prefix)) return "";
    if (!is_directory) return null;
    if (path.len > prefix.len and mem.startsWith(u8, path, prefix) and path[prefix.len] == '/') {
        return path[prefix.len..];
    }
    return null;
}

const TestNode = struct {
    mutex: Io.Mutex = .init,
    path: []u8,
    refs: usize = 1,
    unlinked: std.atomic.Value(bool) = .init(false),
    retain: bool = false,
    cleaned: *bool = &cleaned_sink,

    var cleaned_sink: bool = false;

    pub fn retainAtZeroRefs(node: *const TestNode) bool {
        return node.retain and !node.unlinked.load(.acquire);
    }

    pub fn deinitData(node: *TestNode, table: *Table(TestNode)) void {
        _ = table;
        node.cleaned.* = true;
    }
};

test "the generic table shares, pins, retains and destroys nodes of any type" {
    var table = Table(TestNode).init(testing.allocator, testing.io, 1, 1);
    defer table.deinit();
    var cleaned = false;

    const a = try table.attach("a");
    a.cleaned = &cleaned;
    try testing.expectEqual(a, try table.attach("a"));
    try testing.expectEqual(2, a.refs);
    try testing.expectEqual(a, table.pin("a").?);
    try testing.expectEqual(null, table.pin("b"));
    table.release(a);
    table.release(a);
    try testing.expect(!cleaned);

    a.retain = true;
    table.release(a);
    try testing.expect(!cleaned);
    try testing.expectEqual(1, table.nodes.items.len);
    const again = table.pin("a").?;
    try testing.expectEqual(a, again);
    again.unlinked.store(true, .release);
    table.release(again);
    try testing.expect(cleaned);
    try testing.expectEqual(0, table.nodes.items.len);
}

test "the generic table re-keys a subtree and displaces a destination" {
    var table = Table(TestNode).init(testing.allocator, testing.io, 1, 1);
    defer table.deinit();
    const file = try table.attach("d/one");
    const deep = try table.attach("d/sub/two");
    const outside = try table.attach("dx/three");
    const target = try table.attach("x/one");
    var target_cleaned = false;
    target.cleaned = &target_cleaned;

    var rekey = try table.beginRekey("d", "e", true);
    try testing.expectEqual(2, rekey.nodes.items.len);
    try testing.expectEqual(null, rekey.target);
    rekey.commit();
    try testing.expectEqualStrings("e/one", file.path);
    try testing.expectEqualStrings("e/sub/two", deep.path);
    try testing.expectEqualStrings("dx/three", outside.path);

    var aborted = try table.beginRekey("e/one", "e/four", false);
    aborted.abort();
    try testing.expectEqualStrings("e/one", file.path);

    // A displaced target without handles can be destroyed at commit.
    target.retain = true;
    table.release(target);
    try testing.expectEqual(4, table.nodes.items.len);
    try testing.expect(!target_cleaned);
    var onto = try table.beginRekey("e/sub/two", "x/one", false);
    try testing.expectEqual(target, onto.target.?);
    onto.commit();
    try testing.expect(target_cleaned);
    try testing.expectEqualStrings("x/one", deep.path);
    try testing.expectEqual(3, table.nodes.items.len);

    const pinned = try table.pinAll(testing.allocator);
    defer testing.allocator.free(pinned);
    try testing.expectEqual(3, pinned.len);
    for (pinned) |node| table.release(node);
    table.release(file);
    table.release(deep);
    table.release(outside);
    try testing.expectEqual(0, table.nodes.items.len);
}
