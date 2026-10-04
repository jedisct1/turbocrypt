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

// Keep the bundled libfuse build aligned with Meson while avoiding shared-library symbol versioning.
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
    const fuse = b.option(
        bool,
        "fuse",
        "Build the mount command (default: on for macOS and Linux)",
    ) orelse fuse_default;
    const fuse_t_static = b.option(
        []const u8,
        "fuse-t-static",
        "Path to fuse-t's static libfuse3.a (macOS only)",
    );
    const macos_sdk = b.option(
        []const u8,
        "macos-sdk",
        "macOS SDK path for static fuse-t framework dependencies",
    );
    if (fuse_t_static != null and (!fuse or target.result.os.tag != .macos)) {
        @panic("-Dfuse-t-static requires a macOS target with -Dfuse=true");
    }

    const build_options = b.addOptions();
    build_options.addOption([]const u8, "version", version);
    build_options.addOption(bool, "fuse", fuse);
    build_options.addOption(bool, "fuse_t_static", fuse_t_static != null);

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

    // Link libc on Windows because the console API depends on it.
    if (target.result.os.tag == .windows) {
        exe.root_module.link_libc = true;
    }

    // Link libc on macOS so the Git integration can normalize file names through libiconv.
    if (target.result.os.tag == .macos) {
        exe.root_module.link_libc = true;
    }

    if (fuse_t_static) |path| {
        const sdk = macos_sdk orelse
            @panic("-Dfuse-t-static requires -Dmacos-sdk (xcrun --show-sdk-path)");
        exe.root_module.addSystemFrameworkPath(.{
            .cwd_relative = b.pathJoin(&.{ sdk, "System/Library/Frameworks" }),
        });
        exe.root_module.addObjectFile(.{ .cwd_relative = path });
        exe.root_module.linkFramework("CoreFoundation", .{});
        exe.root_module.linkFramework("DiskArbitration", .{});
    }

    if (fuse and target.result.os.tag == .linux) {
        exe.root_module.link_libc = true;
        // Bundle libfuse so Linux releases work without a system shared library.
        // Use checked-in configuration headers to keep this build independent of Meson.
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

    // Exercise installed Git hooks because unit tests cannot cover their integration.
    const git_e2e = b.addSystemCommand(&.{ "sh", "tests/git_e2e.sh" });
    git_e2e.addArtifactArg(exe);
    git_e2e.has_side_effects = true;
    const git_e2e_step = b.step("test-git", "Run the git integration scenario with real hooks");
    git_e2e_step.dependOn(&git_e2e.step);

    // Let the mount scenario skip hosts that do not provide a FUSE runtime.
    const mount_e2e = b.addSystemCommand(&.{ "sh", "tests/mount_e2e.sh" });
    mount_e2e.addArtifactArg(exe);
    mount_e2e.has_side_effects = true;
    const mount_e2e_step = b.step("test-mount", "Run the mount scenario through FUSE");
    mount_e2e_step.dependOn(&mount_e2e.step);
}
