const std = @import("std");
const Builder = @import("std").build.Builder;

const pam = std.build.Pkg{
    .name = "pam",
    .path = "./exports.zig",
};

pub fn build(b: *Builder) void {
    const mode = b.standardReleaseOptions();
    const lib = b.addSharedLibrary("module", "examples/test.zig", .unversioned);
    lib.setBuildMode(mode);
    lib.addIncludeDir("/usr/include/");
    lib.addPackage(pam);
    lib.install();
}
