const std = @import("std");

const version = @import("build.zig.zon").version;

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

    const build_options = b.addOptions();
    build_options.addOption([]const u8, "version", version);

    const exe = b.addExecutable(.{
        .name = "turbocrypt",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "hctr2", .module = hctr2.module("hctr2") },
                .{ .name = "base84", .module = base84.module("base84") },
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
}
