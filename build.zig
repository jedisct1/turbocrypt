const std = @import("std");

const version = @import("build.zig.zon").version;

const libfuse_sources = [_][]const u8{
    "fuse.c",
    "fuse_loop.c",
    "fuse_loop_mt.c",
    "fuse_lowlevel.c",
    "fuse_opt.c",
    "fuse_signals.c",
    "buffer.c",
    "cuse_lowlevel.c",
    "helper.c",
    "modules/subdir.c",
    "mount_util.c",
    "fuse_log.c",
    "compat.c",
    "util.c",
    "mount.c",
};

// Match libfuse's Meson build without shared-library symbol versioning.
const libfuse_flags = [_][]const u8{
    "-D_REENTRANT",
    "-DHAVE_LIBFUSE_PRIVATE_CONFIG_H",
    "-D_GNU_SOURCE",
    "-D_FILE_OFFSET_BITS=64",
    "-DFUSE_USE_VERSION=317",
    "-DFUSERMOUNT_DIR=\"/usr/bin\"",
    "-Wno-sign-compare",
    "-fno-strict-aliasing",
};

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const hctr2 = b.dependency("hctr2", .{
        .target = target,
        .optimize = optimize,
    });

    const base84 = b.dependency("base84", .{
        .target = target,
        .optimize = optimize,
    });

    const aegis_raf = b.dependency("aegis_raf", .{
        .target = target,
        .optimize = optimize,
    });

    const fuse_default = target.result.os.tag == .macos or target.result.os.tag == .linux;
    const fuse = b.option(bool, "fuse", "Build the mount command (default: on for macOS and Linux)") orelse fuse_default;

    const build_options = b.addOptions();
    build_options.addOption([]const u8, "version", version);
    build_options.addOption(bool, "fuse", fuse);

    const exe = b.addExecutable(.{
        .name = "turbocrypt",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "hctr2", .module = hctr2.module("hctr2") },
                .{ .name = "base84", .module = base84.module("base84") },
                .{ .name = "aegis_raf", .module = aegis_raf.module("aegis_raf") },
                .{ .name = "build_options", .module = build_options.createModule() },
            },
        }),
    });

    // The console API needs libc on Windows.
    if (target.result.os.tag == .windows) {
        exe.root_module.link_libc = true;
    }

    // macOS git turns decomposed file names into their composed form.
    // The git integration does the same through libiconv, which it loads with dlopen.
    if (target.result.os.tag == .macos) {
        exe.root_module.link_libc = true;
    }

    if (fuse and target.result.os.tag == .linux) {
        exe.root_module.link_libc = true;
        // Bundle LGPL-2.1 libfuse so Linux releases need no shared library.
        // The checked-in configuration headers replace Meson's generated headers.
        if (b.lazyDependency("libfuse", .{})) |libfuse| {
            exe.root_module.addIncludePath(libfuse.path("include"));
            exe.root_module.addIncludePath(libfuse.path("lib"));
            exe.root_module.addIncludePath(b.path("src/mount/libfuse"));
            exe.root_module.addCSourceFiles(.{
                .root = libfuse.path("lib"),
                .files = &libfuse_sources,
                .flags = &libfuse_flags,
            });
        }
    }

    b.installArtifact(exe);

    const run_step = b.step("run", "Run the app");
    const run_cmd = b.addRunArtifact(exe);
    run_step.dependOn(&run_cmd.step);
    run_cmd.step.dependOn(b.getInstallStep());
    run_cmd.addPassthruArgs();

    const exe_tests = b.addTest(.{
        .root_module = exe.root_module,
    });
    const run_exe_tests = b.addRunArtifact(exe_tests);
    const test_step = b.step("test", "Run tests");
    test_step.dependOn(&run_exe_tests.step);

    // The git scenario drives the installed binary through real hooks, which unit tests cannot do.
    const git_e2e = b.addSystemCommand(&.{ "sh", "tests/git_e2e.sh" });
    git_e2e.addArtifactArg(exe);
    git_e2e.has_side_effects = true;
    const git_e2e_step = b.step("test-git", "Run the git integration scenario with real hooks");
    git_e2e_step.dependOn(&git_e2e.step);

    // Skip when the host lacks the FUSE runtime needed for a real mount.
    const mount_e2e = b.addSystemCommand(&.{ "sh", "tests/mount_e2e.sh" });
    mount_e2e.addArtifactArg(exe);
    mount_e2e.has_side_effects = true;
    const mount_e2e_step = b.step("test-mount", "Run the mount scenario through FUSE");
    mount_e2e_step.dependOn(&mount_e2e.step);
}
