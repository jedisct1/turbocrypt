#! /bin/sh

# Check stable field offsets and version-specific struct sizes against the C headers.

set -u

root=$(cd "$(dirname "$0")/.." && pwd)
if [ $# -ge 1 ]; then
    bin="$1"
else
    bin="$root/zig-out/bin/turbocrypt"
fi

fail() { printf 'fuse_abi: %s\n' "$*" >&2; exit 1; }

# Prefer headers matching the runtime: installed fuse-t on macOS, bundled libfuse on Linux.
if [ "$(uname)" = Darwin ]; then
    candidates="/usr/local/include/fuse3 /Library/Application\ Support/fuse-t/include/fuse3 $(ls -d "$root"/zig-pkg/*/include 2>/dev/null)"
else
    candidates="$(ls -d "$root"/zig-pkg/*/include 2>/dev/null) /usr/include/fuse3"
fi
inc=""
eval "set -- $candidates"
for dir in "$@"; do
    if [ -f "$dir/fuse.h" ] && [ -f "$dir/fuse_lowlevel.h" ]; then
        inc="$dir"
        break
    fi
done
if [ -z "$inc" ]; then
    echo "fuse_abi: fuse3/fuse.h not found, skipping"
    exit 0
fi

work=$(mktemp -d) || fail "mktemp"
trap 'rm -rf "$work"' EXIT

zig cc -Werror -D_FILE_OFFSET_BITS=64 -I"$inc" -I"$root/src/mount/libfuse" -o "$work/fuse_abi" "$root/tests/fuse_abi.c" || fail "the C file does not compile against $inc"
"$work/fuse_abi" > "$work/c.txt" || fail "the C program failed"
"$bin" mount --print-abi > "$work/zig.txt" || fail "$bin mount --print-abi failed"

version=$(awk '$1 == "FUSE_VERSION" { print $2 }' "$work/c.txt")
[ -n "$version" ] || fail "no FUSE_VERSION in the C output"

if [ "$version" -ge 317 ]; then file_info=64; else file_info=40; fi
if [ "$version" -ge 319 ]; then operations=352
elif [ "$version" -ge 318 ]; then operations=344
else operations=336; fi

expect_size() {
    actual=$(awk -v name="$1" '$1 == "sizeof" && $2 == name { print $3 }' "$work/c.txt")
    [ "$actual" = "$2" ] || fail "sizeof $1 is $actual, expected $2 for libfuse $version"
}
expect_size fuse_operations "$operations"
expect_size fuse_file_info "$file_info"
expect_size fuse_context 40

grep '^offsetof' "$work/c.txt" > "$work/offsets.txt"
missing=$(grep -Fxvf "$work/zig.txt" "$work/offsets.txt")
[ -z "$missing" ] || fail "the binding disagrees with the header:
$missing"

count=$(wc -l < "$work/offsets.txt" | tr -d ' ')
echo "fuse_abi: $count offsets agree with libfuse $version at $inc"
