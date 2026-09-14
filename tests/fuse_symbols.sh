#! /bin/sh

# Check the entry points needed by the mount in fuse-t on macOS or the supplied Linux binary.

set -u

fail() { printf 'fuse_symbols: %s\n' "$*" >&2; exit 1; }

case "$(uname)" in
    Darwin)
        lib=/usr/local/lib/libfuse3.dylib
        [ -f "$lib" ] || lib="/Library/Application Support/fuse-t/lib/libfuse3.dylib"
        [ -f "$lib" ] || fail "fuse-t is not installed"
        symbols=$(nm -gU "$lib" | awk '{ print $3 }' | sed 's/^_//') ;;
    Linux)
        lib="${1:-zig-out/bin/turbocrypt}"
        [ -f "$lib" ] || fail "no binary at $lib"
        symbols=$(nm --defined-only "$lib" | awk '$2 ~ /^[TtWw]$/ { print $3 }') ;;
    *)
        echo "fuse_symbols: unsupported system, skipping"
        exit 0 ;;
esac

required="fuse_opt_add_arg fuse_opt_free_args fuse_mount fuse_unmount fuse_destroy fuse_get_session fuse_set_signal_handlers fuse_remove_signal_handlers fuse_session_exit fuse_loop fuse_loop_mt_31 fuse_get_context"
missing=""
for symbol in $required; do
    echo "$symbols" | grep -qx "$symbol" || missing="$missing $symbol"
done
[ -z "$missing" ] || fail "missing in $lib:$missing"

if echo "$symbols" | grep -qx "fuse_new_31"; then
    echo "fuse_symbols: $lib has every entry point, with fuse_new_31"
elif echo "$symbols" | grep -qx "fuse_new"; then
    echo "fuse_symbols: $lib has every entry point, with fuse_new"
else
    fail "neither fuse_new_31 nor fuse_new in $lib"
fi
