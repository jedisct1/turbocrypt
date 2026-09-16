//! The table of open nodes, shared by the two mount backends.
//!
//! Share nodes by backing path and keep their paths consistent across renames.
//!
//! A node type gives the table these members:
//!
//! +------------------+-----------------------------------------------------------------+
//! | Member           | Type and behavior                                               |
//! +------------------+-----------------------------------------------------------------+
//! | path             | []u8, relative to the backing root; the table owns it            |
//! | refs             | usize, initially 1; protected by the table mutex                 |
//! | mutex            | std.Io.Mutex, initially .init                                    |
//! | unlinked         | std.atomic.Value(bool), initially false                          |
//! | retainAtZeroRefs | fn (*const Node) bool; called with both mutexes held             |
//! | deinitData       | fn (*Node, *Table(Node)) void; frees what the node owns          |
//! +------------------+-----------------------------------------------------------------+
//!
//! Nodes are initialized with `.{ .path = owned_path }`; all other fields need safe defaults.

const std = @import("std");

/// Limit plaintext staging across v1 files. RAF nodes leave the budget untouched.
pub const Budget = struct {
    limit: usize,
    charged: std.atomic.Value(usize) = .init(0),

    pub fn charge(self: *Budget, amount: usize) bool {
        var current = self.charged.load(.monotonic);
        while (true) {
            const next = std.math.add(usize, current, amount) catch return false;
            if (next > self.limit) return false;
            current = self.charged.cmpxchgWeak(current, next, .monotonic, .monotonic) orelse return true;
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

        allocator: std.mem.Allocator,
        io: std.Io,
        mutex: std.Io.Mutex = .init,
        nodes: std.ArrayList(*NodeType) = .empty,
        budget: Budget,
        max_file_size: usize,

        /// Keep node paths consistent with a backing rename until commit or abort.
        pub const Rekey = struct {
            table: *Table(NodeType),
            nodes: std.ArrayList(*NodeType) = .empty,
            paths: std.ArrayList([]u8) = .empty,
            /// Open or retained destination displaced by the rename.
            target: ?*NodeType = null,

            /// Call only after the backing rename succeeds.
            pub fn commit(self: *Rekey) void {
                const allocator = self.table.allocator;
                for (self.nodes.items, self.paths.items) |node, path| {
                    allocator.free(node.path);
                    node.path = path;
                }
                if (self.target) |target| {
                    target.unlinked.store(true, .release);
                    // No open handle remains to release this displaced node.
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
                for (self.paths.items) |path| self.table.allocator.free(path);
                self.finish();
            }

            fn finish(self: *Rekey) void {
                for (self.nodes.items) |node| node.mutex.unlock(self.table.io);
                if (self.target) |target| target.mutex.unlock(self.table.io);
                self.nodes.deinit(self.table.allocator);
                self.paths.deinit(self.table.allocator);
                self.table.mutex.unlock(self.table.io);
            }
        };

        pub fn init(allocator: std.mem.Allocator, io: std.Io, max_file_size: usize, memory_limit: usize) Table(NodeType) {
            return .{
                .allocator = allocator,
                .io = io,
                .budget = .{ .limit = memory_limit },
                .max_file_size = max_file_size,
            };
        }

        /// Call with no callbacks running.
        pub fn deinit(self: *Table(NodeType)) void {
            for (self.nodes.items) |node| self.destroyNode(node);
            self.nodes.deinit(self.allocator);
        }

        /// Share the linked node for this path, or create one; the caller owns a reference.
        pub fn attach(self: *Table(NodeType), path: []const u8) error{OutOfMemory}!*NodeType {
            self.mutex.lockUncancelable(self.io);
            defer self.mutex.unlock(self.io);
            if (self.findLocked(path)) |node| {
                node.refs += 1;
                return node;
            }
            const node = try self.allocator.create(NodeType);
            errdefer self.allocator.destroy(node);
            node.* = .{ .path = try self.allocator.dupe(u8, path) };
            errdefer self.allocator.free(node.path);
            try self.nodes.append(self.allocator, node);
            return node;
        }

        /// Acquire a reference without creating a node.
        pub fn pin(self: *Table(NodeType), path: []const u8) ?*NodeType {
            self.mutex.lockUncancelable(self.io);
            defer self.mutex.unlock(self.io);
            const node = self.findLocked(path) orelse return null;
            node.refs += 1;
            return node;
        }

        /// Keep nodes alive during enumeration; the caller releases each reference and frees the list.
        pub fn pinAll(self: *Table(NodeType), allocator: std.mem.Allocator) error{OutOfMemory}![]*NodeType {
            self.mutex.lockUncancelable(self.io);
            defer self.mutex.unlock(self.io);
            const list = try allocator.dupe(*NodeType, self.nodes.items);
            for (list) |node| node.refs += 1;
            return list;
        }

        /// Release a reference. The node decides whether it survives its last reference.
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

        /// Reserve paths before the backing rename so committing it cannot fail for lack of memory.
        /// Hold the table and affected node locks until commit or abort.
        ///
        /// Lock the destination too, so its pending write-back cannot overwrite the renamed source.
        pub fn beginRekey(self: *Table(NodeType), old: []const u8, new: []const u8, is_directory: bool) error{OutOfMemory}!Rekey {
            self.mutex.lockUncancelable(self.io);
            errdefer self.mutex.unlock(self.io);
            var rekey: Rekey = .{ .table = self };
            if (std.mem.eql(u8, old, new)) return rekey;
            errdefer {
                for (rekey.paths.items) |path| self.allocator.free(path);
                rekey.paths.deinit(self.allocator);
                rekey.nodes.deinit(self.allocator);
            }
            for (self.nodes.items) |node| {
                if (node.unlinked.load(.acquire)) continue;
                if (pathSuffix(node.path, old, is_directory)) |rest| {
                    try rekey.nodes.append(self.allocator, node);
                    const path = try std.mem.concat(self.allocator, u8, &.{ new, rest });
                    errdefer self.allocator.free(path);
                    try rekey.paths.append(self.allocator, path);
                } else if (!is_directory and std.mem.eql(u8, node.path, new)) {
                    rekey.target = node;
                }
            }
            for (rekey.nodes.items) |node| node.mutex.lockUncancelable(self.io);
            if (rekey.target) |target| target.mutex.lockUncancelable(self.io);
            return rekey;
        }

        fn findLocked(self: *Table(NodeType), path: []const u8) ?*NodeType {
            for (self.nodes.items) |node| {
                if (!node.unlinked.load(.acquire) and std.mem.eql(u8, node.path, path)) return node;
            }
            return null;
        }

        fn removeLocked(self: *Table(NodeType), node: *NodeType) void {
            const index = std.mem.indexOfScalar(*NodeType, self.nodes.items, node).?;
            _ = self.nodes.swapRemove(index);
        }

        fn destroyNode(self: *Table(NodeType), node: *NodeType) void {
            node.deinitData(self);
            self.allocator.free(node.path);
            self.allocator.destroy(node);
        }
    };
}

/// Match whole components so a directory rename cannot affect similarly prefixed siblings.
pub fn pathSuffix(path: []const u8, prefix: []const u8, is_directory: bool) ?[]const u8 {
    if (std.mem.eql(u8, path, prefix)) return "";
    if (!is_directory) return null;
    if (path.len > prefix.len and std.mem.startsWith(u8, path, prefix) and path[prefix.len] == '/') return path[prefix.len..];
    return null;
}

const testing = std.testing;

const TestNode = struct {
    mutex: std.Io.Mutex = .init,
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

    // A displaced destination without handles is destroyed at commit.
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
