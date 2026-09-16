#! /bin/sh

# Exercise a real mount; skip if the required FUSE runtime is unavailable.
# Run separately from zig build test because they share temporary fixtures.

set -u

root=$(cd "$(dirname "$0")/.." && pwd)
if [ $# -ge 1 ]; then
    bin="$1"
else
    bin="$root/zig-out/bin/turbocrypt"
fi
# Some checks run the binary from another directory, so its path must be absolute.
bin="$(cd "$(dirname "$bin")" && pwd)/$(basename "$bin")"
work="$root/tmp/mount_e2e"
export HOME="$work/home"
export XDG_DATA_HOME="$work/home/data"
unset TURBOCRYPT_KEY_FILE
unset TURBOCRYPT_MOUNT_FAULTS

if ! "$bin" mount --print-abi >/dev/null 2>&1; then
    echo "mount_e2e: this build has no mount support, skipping (build with -Dfuse=true)"
    exit 0
fi

case "$(uname)" in
    Darwin)
        if [ ! -f /usr/local/lib/libfuse3.dylib ] && [ ! -f "/Library/Application Support/fuse-t/lib/libfuse3.dylib" ]; then
            echo "mount_e2e: fuse-t is not installed, skipping"
            exit 0
        fi
        macos=1
        # Make attribute changes visible immediately.
        fresh_attrs="-o noattrcache"
        accepted_opt="noattrcache" ;;
    Linux)
        if ! command -v fusermount3 >/dev/null 2>&1 || [ ! -e /dev/fuse ]; then
            echo "mount_e2e: fusermount3 or /dev/fuse is missing, skipping"
            exit 0
        fi
        macos=0
        fresh_attrs=""
        accepted_opt="noatime" ;;
    *)
        echo "mount_e2e: unsupported system, skipping"
        exit 0 ;;
esac

current=""
step() { current="$*"; printf '== %s\n' "$*"; }
fail() { printf 'FAILED at "%s": %s\n' "$current" "$*" >&2; cleanup; exit 1; }
expect_eq() { [ "$1" = "$2" ] || fail "expected '$2', got '$1'"; }
expect_file() { [ -f "$1" ] || fail "missing file $1"; }
expect_no_file() { [ ! -e "$1" ] || fail "unexpected file $1"; }
expect_content() { expect_file "$1"; expect_eq "$(cat "$1")" "$2"; }
expect_refused() {
    pattern=$1; what=$2; shift 2
    "$@" > "$work/refused.log" 2>&1 && fail "$what succeeded"
    grep -q "$pattern" "$work/refused.log" || fail "no message for $what: $(cat "$work/refused.log")"
}
expect_eio() { cat "$1" 2>&1 | grep -qi "input/output" || fail "$2"; }
size_of() { stat -c %s "$1" 2>/dev/null || stat -f %z "$1"; }
quiet() { "$@" >/dev/null 2>&1; }
if command -v uv >/dev/null 2>&1; then py() { uv run --quiet python3 "$@"; }; else py() { python3 "$@"; }; fi
nap() { perl -e 'select(undef, undef, undef, 0.2)'; }
mode() { stat -c %a "$1" 2>/dev/null || stat -f %Lp "$1"; }
mtime() { stat -c %Y "$1" 2>/dev/null || stat -f %m "$1"; }
sha() { shasum -a 256 "$1" | cut -d' ' -f1; }

mnt="$work/mnt"
enc="$work/enc"
box="$work/box"
plain="$work/plain"
key="$work/secret.key"
mount_pid=""
mount_log="$work/mount.log"
backing="$enc"

is_mounted() { mount | grep -q " on $mnt "; }

wait_until() {
    message="$1"; shift
    n=0
    while ! "$@"; do
        nap
        n=$((n + 1))
        [ $n -gt 100 ] && fail "$message"
    done
}
not_mounted() { ! is_mounted; }

# Keep injected faults local to each mount process.
faults=""
mount_fs() {
    : > "$mount_log"
    if [ -n "$faults" ]; then
        TURBOCRYPT_MOUNT_FAULTS="$faults" "$bin" mount --key "$key" "$@" "$backing" "$mnt" > "$mount_log" 2>&1 &
    else
        "$bin" mount --key "$key" "$@" "$backing" "$mnt" > "$mount_log" 2>&1 &
    fi
    mount_pid=$!
    n=0
    while ! is_mounted; do
        if ! kill -0 "$mount_pid" 2>/dev/null; then
            wait "$mount_pid"
            return $?
        fi
        nap
        n=$((n + 1))
        [ $n -gt 100 ] && fail "the mount did not appear"
    done
    return 0
}

wait_exit() {
    n=0
    while kill -0 "$mount_pid" 2>/dev/null; do
        nap
        n=$((n + 1))
        [ $n -gt 150 ] && fail "the mount process did not exit"
    done
    wait "$mount_pid"
    status=$?
    mount_pid=""
    return $status
}

# The client can report the volume busy for a moment after a burst of file operations.
unmount_fs() {
    n=0
    while ! "$bin" unmount "$mnt" > "$work/unmount.log" 2>&1; do
        grep -qi "busy" "$work/unmount.log" || { cat "$work/unmount.log"; fail "unmount failed"; }
        n=$((n + 1))
        [ $n -gt 25 ] && { cat "$work/unmount.log"; fail "the volume stayed busy"; }
        nap
    done
    wait_exit
}

expect_unmount() {
    unmount_fs
    expect_eq "$?" "$1"
}

cleanup() {
    if is_mounted; then
        umount "$mnt" 2>/dev/null || diskutil unmount force "$mnt" >/dev/null 2>&1 || fusermount3 -u "$mnt" 2>/dev/null
    fi
    if [ -n "$mount_pid" ] && kill -0 "$mount_pid" 2>/dev/null; then
        kill "$mount_pid" 2>/dev/null
    fi
    pkill -f "mount --key $key" 2>/dev/null
    if [ -n "${ramdev:-}" ]; then
        if [ "$macos" = 1 ]; then
            hdiutil detach "$ramdev" >/dev/null 2>&1
        fi
    fi
}

fresh_tree() {
    rm -rf "$enc" "$plain" "$mnt" "$work/dec"
    mkdir -p "$plain/sub/deeper" "$mnt"
    echo "hello world" > "$plain/hello.txt"
    head -c 100000 /dev/urandom > "$plain/sub/random.bin"
    echo "deep" > "$plain/sub/deeper/d.txt"
    : > "$plain/empty"
    quiet "$bin" encrypt --key "$key" "$@" "$plain" "$enc" || fail "encrypt"
}

if is_mounted; then
    umount "$mnt" 2>/dev/null
fi
rm -rf "$work"
mkdir -p "$work/home"
quiet "$bin" keygen "$key" || fail "keygen"

step "scenario 1: list, read and compare in the three name modes"
for names in "" "--encrypted-filenames" "--enc-suffix" "--encrypted-filenames --enc-suffix"; do
    fresh_tree $names
    mount_fs $names || fail "mount with '$names'"
    expect_eq "$(ls "$mnt" | tr '\n' ' ')" "empty hello.txt sub "
    expect_eq "$(ls "$mnt/sub" | tr '\n' ' ')" "deeper random.bin "
    expect_content "$mnt/hello.txt" "hello world"
    expect_content "$mnt/sub/deeper/d.txt" "deep"
    cmp -s "$mnt/sub/random.bin" "$plain/sub/random.bin" || fail "random.bin differs"
    expect_eq "$(size_of "$mnt/empty")" "0"
    expect_eq "$(size_of "$mnt/hello.txt")" "12"
    expect_unmount 0
done

step "scenario 2: create, append, write at offsets, truncate, then verify and decrypt"
fresh_tree
mount_fs || fail "mount"
echo "line one" > "$mnt/new.txt"
echo "line two" >> "$mnt/new.txt"
printf 'XX' | dd of="$mnt/new.txt" bs=1 seek=5 conv=notrunc 2>/dev/null
expect_eq "$(cat "$mnt/new.txt" | tr '\n' '|')" "line XXe|line two|"
printf 'Z' | dd of="$mnt/new.txt" bs=1 seek=40 conv=notrunc 2>/dev/null
expect_eq "$(size_of "$mnt/new.txt")" "41"
truncate -s 4 "$mnt/new.txt"
expect_content "$mnt/new.txt" "line"
truncate -s 6 "$mnt/new.txt"
expect_eq "$(od -An -c "$mnt/new.txt" | tr -d ' \n')" 'line\0\0'
expect_unmount 0
quiet "$bin" verify --key "$key" "$enc" || fail "verify after writes"
quiet "$bin" decrypt --key "$key" "$enc" "$work/dec" || fail "decrypt after writes"
expect_eq "$(od -An -c "$work/dec/new.txt" | tr -d ' \n')" 'line\0\0'

step "scenario 3: a 64 MiB file, and mmap through the mount"
head -c 67108864 /dev/urandom > "$work/big.bin"
mount_fs || fail "mount"
cp "$work/big.bin" "$mnt/big.bin"
expect_eq "$(sha "$mnt/big.bin")" "$(sha "$work/big.bin")"
if command -v python3 >/dev/null 2>&1; then
    cat > "$work/mm.py" <<'PY'
import mmap, sys
with open(sys.argv[1], "r+b") as f:
    mm = mmap.mmap(f.fileno(), 0)
    assert mm[:11] == b"hello world"
    mm[0:5] = b"HELLO"
    mm.flush()
    mm.close()
PY
    py "$work/mm.py" "$mnt/hello.txt" || fail "mmap"
    expect_content "$mnt/hello.txt" "HELLO world"
fi
expect_unmount 0
quiet "$bin" decrypt --key "$key" "$enc" "$work/dec2" || fail "decrypt"
expect_eq "$(sha "$work/dec2/big.bin")" "$(sha "$work/big.bin")"

step "scenario 4: mv and rm, closed and open"
fresh_tree
mount_fs || fail "mount"
mv "$mnt/hello.txt" "$mnt/renamed.txt"
expect_no_file "$mnt/hello.txt"
expect_content "$mnt/renamed.txt" "hello world"
expect_eq "$( (exec 3<"$mnt/renamed.txt"; mv "$mnt/renamed.txt" "$mnt/open-moved.txt"; cat <&3) )" "hello world"
expect_content "$mnt/open-moved.txt" "hello world"
rm "$mnt/open-moved.txt"
expect_no_file "$mnt/open-moved.txt"
echo "to delete" > "$mnt/gone.txt"
( exec 3<"$mnt/gone.txt"; rm "$mnt/gone.txt"; expect_eq "$(cat <&3)" "to delete" )
expect_no_file "$mnt/gone.txt"
expect_unmount 0
expect_eq "$(ls "$enc" | grep -c nfs)" "0"

step "scenario 5: mkdir and rmdir"
mount_fs || fail "mount"
mkdir "$mnt/d1"
echo x > "$mnt/d1/f"
rmdir "$mnt/d1" 2>/dev/null && fail "rmdir of a non-empty directory succeeded"
rm "$mnt/d1/f"
rmdir "$mnt/d1"
expect_no_file "$enc/d1"
mkdir -p "$mnt/a/b/c"
expect_eq "$(ls "$enc/a/b")" "c"
expect_unmount 0

step "scenario 6: chmod, and cp -p keeps the mtime"
mount_fs $fresh_attrs || fail "mount"
chmod 600 "$mnt/empty"
expect_eq "$(mode "$mnt/empty")" "600"
expect_eq "$(mode "$enc/empty")" "600"
touch -t 202001010000 "$plain/hello.txt"
cp -p "$plain/hello.txt" "$mnt/copied.txt" 2>/dev/null
expect_eq "$(mtime "$mnt/copied.txt")" "$(mtime "$plain/hello.txt")"
expect_unmount 0
expect_eq "$(mtime "$enc/copied.txt")" "$(mtime "$plain/hello.txt")"

step "scenario 7: a second process reads a file right after the first one closed it"
mount_fs || fail "mount"
sh -c "echo first > '$mnt/handoff.txt'"
expect_eq "$(sh -c "cat '$mnt/handoff.txt'")" "first"
sh -c "echo second > '$mnt/handoff.txt'"
expect_eq "$(sh -c "cat '$mnt/handoff.txt'")" "second"
expect_unmount 0

step "scenario 8: a wrong key is refused, --force mounts and reads give EIO"
fresh_tree
quiet "$bin" keygen "$work/wrong.key" || fail "keygen"
"$bin" mount --key "$work/wrong.key" "$enc" "$mnt" > "$mount_log" 2>&1 && fail "mount with the wrong key succeeded"
if [ "$(id -u)" != 0 ]; then
    chmod 000 "$enc/hello.txt" "$enc/empty" "$enc/sub/random.bin" "$enc/sub/deeper/d.txt"
    "$bin" mount --key "$key" "$enc" "$mnt" > "$work/unchecked.log" 2>&1 && fail "mount with unreadable files succeeded"
    grep -q "cannot be checked" "$work/unchecked.log" || fail "no message about the unchecked key: $(cat "$work/unchecked.log")"
    chmod 644 "$enc/hello.txt" "$enc/empty" "$enc/sub/random.bin" "$enc/sub/deeper/d.txt"
fi
grep -q "wrong decryption key" "$mount_log" || fail "no wrong-key message"
"$bin" mount --key "$work/wrong.key" --force "$enc" "$mnt" > "$mount_log" 2>&1 &
mount_pid=$!
wait_until "no mount with --force" is_mounted
out=$(cat "$mnt/hello.txt" 2>&1) && fail "read with the wrong key succeeded"
echo "$out" | grep -qi "input/output" || fail "no EIO with the wrong key: $out"
grep -q "cannot decrypt" "$mount_log" || fail "no message for the failed decryption"
expect_unmount 0

step "scenario 9: --read-only refuses writes with EROFS"
mount_fs --read-only || fail "mount"
touch "$mnt/nope" 2>&1 | grep -qi "read-only" || fail "touch did not fail with EROFS"
expect_content "$mnt/hello.txt" "hello world"
expect_unmount 0

step "scenario 10: two writers on different files at the same time"
mount_fs || fail "mount"
( i=0; while [ $i -lt 200 ]; do echo "a$i" >> "$mnt/wa.txt"; i=$((i + 1)); done ) &
wa=$!
( i=0; while [ $i -lt 200 ]; do echo "b$i" >> "$mnt/wb.txt"; i=$((i + 1)); done ) &
wb=$!
wait $wa; wait $wb
expect_eq "$(wc -l < "$mnt/wa.txt" | tr -d ' ')" "200"
expect_eq "$(wc -l < "$mnt/wb.txt" | tr -d ' ')" "200"
expect_eq "$(tail -1 "$mnt/wb.txt")" "b199"
expect_unmount 0

step "scenario 11: SIGTERM unmounts cleanly with status 0"
mount_fs || fail "mount"
expect_content "$mnt/hello.txt" "hello world"
kill -TERM "$mount_pid"
wait_exit
expect_eq "$?" "0"
is_mounted && fail "still mounted after SIGTERM"

step "scenario 12: --daemon returns once the volume is mounted"
"$bin" mount --key "$key" --daemon "$enc" "$mnt" > "$mount_log" 2>&1 || fail "daemon mount failed: $(cat "$mount_log")"
is_mounted || fail "not mounted after --daemon returned"
expect_content "$mnt/hello.txt" "hello world"
echo "daemon write" > "$mnt/daemon.txt"
"$bin" unmount "$mnt" || fail "unmount"
wait_until "still mounted" not_mounted
no_daemon_child() { ! pgrep -f "mount --key $key.*daemon-child" > /dev/null; }
wait_until "daemon child still running" no_daemon_child
quiet "$bin" decrypt --key "$key" "$enc" "$work/dec3" || fail "decrypt"
expect_content "$work/dec3/daemon.txt" "daemon write"
"$bin" mount --key "$work/wrong.key" --daemon "$enc" "$mnt" > "$mount_log" 2>&1 && fail "daemon mount with the wrong key succeeded"
is_mounted && fail "mounted after a failed daemon mount"

step "scenario 13: files below 48 bytes show size 0 and give EIO"
printf 'tiny' > "$enc/short"
mount_fs || fail "mount"
expect_eq "$(wc -c < "$mnt/short" 2>/dev/null | tr -d ' ')" ""
cat "$mnt/short" 2>&1 | grep -qi "input/output" || fail "no EIO for a short file"
expect_unmount 0
rm -f "$enc/short"

step "scenario 14: rename a directory while a descendant is open and dirty"
mount_fs || fail "mount"
mkdir "$mnt/dir1"
(
    exec 3>"$mnt/dir1/live.txt"
    printf 'live data' >&3
    mv "$mnt/dir1" "$mnt/dir2"
    printf ' more' >&3
    exec 3>&-
)
expect_no_file "$mnt/dir1"
expect_content "$mnt/dir2/live.txt" "live data more"
expect_content "$enc/dir2/live.txt" "$(cat "$enc/dir2/live.txt")"
expect_unmount 0
expect_no_file "$enc/dir1"
quiet "$bin" decrypt --key "$key" "$enc/dir2/live.txt" "$work/live.txt" || fail "decrypt"
expect_content "$work/live.txt" "live data more"

step "scenario 15: rename over an open destination"
mount_fs || fail "mount"
echo "old" > "$mnt/dest.txt"
echo "new" > "$mnt/src.txt"
expect_eq "$( (exec 3<"$mnt/dest.txt"; mv "$mnt/src.txt" "$mnt/dest.txt"; cat <&3) )" "old"
expect_content "$mnt/dest.txt" "new"
expect_no_file "$mnt/src.txt"
expect_unmount 0
expect_eq "$(ls "$enc" | grep -c "src.txt")" "0"

step "scenario 16: two processes append to the same file"
mount_fs || fail "mount"
( i=0; while [ $i -lt 100 ]; do echo "x$i" >> "$mnt/shared.txt"; i=$((i + 1)); done ) &
xa=$!
( i=0; while [ $i -lt 100 ]; do echo "y$i" >> "$mnt/shared.txt"; i=$((i + 1)); done ) &
xb=$!
wait $xa; wait $xb
expect_eq "$(wc -l < "$mnt/shared.txt" | tr -d ' ')" "200"
expect_eq "$(sort "$mnt/shared.txt" | uniq -d | wc -l | tr -d ' ')" "0"
expect_unmount 0

step "scenario 19: long names in both name modes"
long255=$(printf '%0255d' 0 | tr 0 n)
long197=$(printf '%0197d' 0 | tr 0 m)
mount_fs || fail "mount"
echo "long" > "$mnt/$long255"
expect_content "$mnt/$long255" "long"
mv "$mnt/$long255" "$mnt/${long255%n}x"
expect_content "$mnt/${long255%n}x" "long"
rm "$mnt/${long255%n}x"
expect_unmount 0
fresh_tree --encrypted-filenames
mount_fs --encrypted-filenames || fail "mount"
echo "long" > "$mnt/$long197"
expect_content "$mnt/$long197" "long"
mv "$mnt/$long197" "$mnt/${long197%m}x"
rm "$mnt/${long197%m}x"
( echo "too long" > "$mnt/$long255" ) 2>&1 | grep -qi "too long" || fail "a 255-byte name was accepted with encrypted names"
expect_unmount 0
quiet "$bin" verify --key "$key" "$enc" || fail "verify"
# An oversized file spelling must not hide a valid directory spelling.
fresh_tree --enc-suffix
mkdir "$enc/$long255" || fail "mkdir in the backing tree"
mount_fs --enc-suffix || fail "mount"
[ -d "$mnt/$long255" ] || fail "a 255-byte directory is hidden in suffix mode"
mkdir "$mnt/${long255%n}x" || fail "mkdir of a 255-byte name in suffix mode"
[ -d "$enc/${long255%n}x" ] || fail "the directory was not created under its own name"
( echo "too long" > "$mnt/${long255%nnn}" ) 2>&1 | grep -qi "too long" || fail "a 252-byte file name was accepted in suffix mode"
expect_unmount 0
# Create through encrypt because the client's conservative name limit rejects this directory at mkdir.
long203=$(printf '%0203d' 0 | tr 0 d)
rm -rf "$enc" "$plain" "$mnt"
mkdir -p "$plain/$long203" "$mnt"
echo "in" > "$plain/$long203/f.txt"
quiet "$bin" encrypt --key "$key" --encrypted-filenames --enc-suffix "$plain" "$enc" || fail "encrypt"
mount_fs --encrypted-filenames --enc-suffix || fail "mount"
[ -d "$mnt/$long203" ] || fail "a 203-byte directory is hidden with encrypted names and the suffix"
expect_content "$mnt/$long203/f.txt" "in"
expect_unmount 0
quiet "$bin" verify --key "$key" "$enc" || fail "verify"

step "scenario 24: a same-size overwrite is seen by another process"
fresh_tree
mount_fs || fail "mount"
echo "AAAA" > "$mnt/same.txt"
expect_eq "$(sh -c "cat '$mnt/same.txt'")" "AAAA"
echo "BBBB" > "$mnt/same.txt"
expect_eq "$(sh -c "cat '$mnt/same.txt'")" "BBBB"
expect_unmount 0

step "scenario 28 and 34: refused and accepted -o options"
for opt in use_ino hard_remove writeback_cache allow_other; do
    "$bin" mount --key "$key" -o "$opt" "$enc" "$mnt" > "$mount_log" 2>&1 && fail "-o $opt was accepted"
    grep -q "'$opt'" "$mount_log" || fail "the message does not name $opt"
    is_mounted && fail "mounted with -o $opt"
done
mount_fs -o "$accepted_opt" || fail "mount with -o $accepted_opt"
expect_content "$mnt/hello.txt" "hello world"
expect_unmount 0

step "scenario 31: links, FIFOs and sockets in the backing tree are hidden"
ln -s hello.txt "$enc/link"
mkfifo "$enc/fifo"
mount_fs || fail "mount"
expect_eq "$(ls "$mnt" | grep -c "link\|fifo")" "0"
cat "$mnt/link" 2>&1 | grep -qi "no such file" || fail "the link is visible"
cat "$mnt/fifo" 2>&1 | grep -qi "no such file" || fail "the fifo is visible"
expect_unmount 0
"$bin" list "$enc" 2>&1 | grep -q "link" || fail "list hides the link"
rm -f "$enc/link" "$enc/fifo"

step "scenario 32: an empty tree mounts and a created file reads back"
rm -rf "$enc" && mkdir "$enc"
mount_fs || fail "mount of an empty tree"
echo "first" > "$mnt/first.txt"
expect_content "$mnt/first.txt" "first"
expect_unmount 0
quiet "$bin" verify --key "$key" "$enc" || fail "verify"

step "scenario 33: a mountpoint inside the encrypted directory is refused"
mkdir -p "$enc/inside"
"$bin" mount --key "$key" "$enc" "$enc/inside" > "$mount_log" 2>&1 && fail "nested mountpoint accepted"
grep -q "inside" "$mount_log" || fail "the message does not name the paths"
rmdir "$enc/inside"

step "scenario 36: the umask of the client applies once"
fresh_tree
umask 022
mount_fs || fail "mount"
(umask 077; mkdir "$mnt/d077"; touch "$mnt/f077")
expect_eq "$(mode "$enc/d077")" "700"
expect_eq "$(mode "$enc/f077")" "600"
(umask 022; mkdir "$mnt/d022"; touch "$mnt/f022")
expect_eq "$(mode "$enc/d022")" "755"
expect_eq "$(mode "$enc/f022")" "644"
expect_unmount 0
umask 077
mount_fs || fail "mount"
(umask 022; mkdir "$mnt/d022b"; touch "$mnt/f022b")
expect_eq "$(mode "$enc/d022b")" "755"
expect_eq "$(mode "$enc/f022b")" "644"
expect_unmount 0
umask 022

if [ "$macos" = 1 ]; then
    step "scenario 37: a file the mount cannot own again is read-only through the mount"
    # Choose a group the mount can neither inherit nor restore through membership.
    other_gid=$(dscl . -list /Groups PrimaryGroupID 2>/dev/null | awk '$2 > 100 && $2 < 400 { print $2; exit }')
    dir_gid=$(stat -f %g "$enc")
    if [ -n "$other_gid" ] && [ "$other_gid" != "$dir_gid" ] && ! id -G | tr ' ' '\n' | grep -qx "$other_gid"; then
        if chgrp "$other_gid" "$enc/hello.txt" 2>/dev/null; then
            mount_fs || fail "mount"
            expect_content "$mnt/hello.txt" "hello world"
            sh -c "echo x >> '$mnt/hello.txt'" 2>&1 | grep -qi "not permitted" || fail "a write to a file with a foreign group was accepted"
            grep -q "read-only through the mount" "$mount_log" || fail "no ownership message"
            expect_unmount 0
        else
            echo "   (cannot chgrp to $other_gid, skipped)"
        fi
    else
        echo "   (no suitable group, skipped)"
    fi
fi

step "scenario 23: files that fit one by one but not together"
fresh_tree
i=0
while [ $i -lt 5 ]; do
    head -c 1100000 /dev/urandom > "$plain/f$i.bin"
    quiet "$bin" encrypt --key "$key" "$plain/f$i.bin" "$enc/f$i.bin"
    i=$((i + 1))
done
# Four files fit the minimum budget; a fifth must fail.
# Files above the mmap threshold avoid a transient ciphertext allocation during load.
mount_fs --max-file-size 1153434 --memory-limit 4508878 || fail "mount"
cat > "$work/budget.py" <<'PY'
import os, sys, errno
mnt = sys.argv[1]
fds = []
for i in range(4):
    fd = os.open(f"{mnt}/f{i}.bin", os.O_RDWR)
    os.pread(fd, 1, 0)
    fds.append(fd)
fifth = os.open(f"{mnt}/f4.bin", os.O_RDWR)
try:
    os.pread(fifth, 1, 0)
    print("fifth load succeeded")
except OSError as e:
    print("fifth load failed with", errno.errorcode.get(e.errno, e.errno))
# macOS buffers NFS writes, so force the request through with fsync.
try:
    os.pwrite(fds[0], b"x", 0)
    os.fsync(fds[0])
    print("write with four loaded succeeded")
except OSError as e:
    print("write with four loaded failed with", errno.errorcode.get(e.errno, e.errno))
os.close(fifth)
os.close(fds[3])
# Linux may release the file's memory after close returns.
import time
for attempt in range(50):
    try:
        os.pwrite(fds[0], b"x", 0)
        os.fsync(fds[0])
        break
    except OSError as e:
        if e.errno != errno.ENOSPC or attempt == 49:
            raise
        time.sleep(0.1)
print("write after two closes ok")
for fd in fds[:3]:
    os.close(fd)
PY
out=$(py "$work/budget.py" "$mnt" 2>&1)
# NFS maps ENOMEM to EIO on macOS.
echo "$out" | grep -q "fifth load failed with \(ENOMEM\|EIO\)" || fail "the fifth load did not fail: $out"
echo "$out" | grep -q "write with four loaded failed with ENOSPC" || fail "the write did not fail with ENOSPC: $out"
echo "$out" | grep -q "write after two closes ok" || fail "the write after the closes failed: $out"
expect_unmount 0
quiet "$bin" verify --key "$key" "$enc" || fail "verify"
quiet "$bin" decrypt --key "$key" "$enc/f0.bin" "$work/f0.bin" || fail "decrypt"
expect_eq "$(head -c 1 "$work/f0.bin")" "x"

faults_armed() { grep -q "fault(s) armed" "$mount_log"; }
faults=file_sync; mount_fs || fail "mount"
if faults_armed; then
    step "scenario 18: a failed file sync keeps the node dirty and the next fsync succeeds"
    cat > "$work/fsync.py" <<'PY'
import os, sys
fd = os.open(sys.argv[1], os.O_WRONLY | os.O_CREAT | os.O_TRUNC)
os.write(fd, b"synced data")
try:
    os.fsync(fd)
    print("first fsync succeeded")
except OSError as e:
    print("first fsync failed:", e.errno)
os.fsync(fd)
print("second fsync ok")
os.close(fd)
PY
    out=$(py "$work/fsync.py" "$mnt/synced.txt" 2>&1)
    # fuse-t hides fsync errors from the client; check the mount's log and exit status on macOS.
    if [ "$macos" = 1 ]; then
        grep -q "cannot write back synced.txt" "$mount_log" || fail "the armed fault did not fire: $out"
    else
        echo "$out" | grep -q "first fsync failed" || fail "the armed fault did not fire: $out"
    fi
    echo "$out" | grep -q "second fsync ok" || fail "the second fsync failed: $out"
    expect_content "$mnt/synced.txt" "synced data"
    expect_unmount 3
    quiet "$bin" verify --key "$key" "$enc" || fail "verify"

    faults=""
    step "scenario 25: an interrupted create leaves nothing behind"
    faults=create_write; mount_fs || fail "mount"
    touch "$mnt/interrupted.txt" 2>/dev/null && fail "the create succeeded despite the fault"
    expect_no_file "$enc/interrupted.txt"
    expect_eq "$(ls -a "$enc" | grep -c '^\.tc-')" "0"
    touch "$mnt/interrupted.txt" || fail "the second create failed"
    expect_file "$enc/interrupted.txt"
    # A rejected create must not count as a session failure.
    expect_unmount 0

    if [ "$macos" = 1 ]; then
        echo "   (the NFS client of macOS sends no FSYNC for a file without pending writes, so scenarios 26, 27 and 30 run on Linux only)"
    fi
fi
if faults_armed && [ "$macos" = 0 ]; then
    faults=""
    step "scenario 26 and 30: fsync on a clean node syncs the file and the marked directory"
    cat > "$work/flushsync.py" <<'PY'
import os, sys
fd = os.open(sys.argv[1], os.O_WRONLY | os.O_CREAT | os.O_TRUNC)
os.write(fd, b"flushed then synced")
os.close(fd)
fd = os.open(sys.argv[1], os.O_RDWR)
os.fchmod(fd, 0o640)
try:
    os.fsync(fd)
    print("fsync succeeded")
except OSError as e:
    print("fsync failed:", e.errno)
os.fsync(fd)
print("second fsync ok")
os.close(fd)
PY
    faults=metadata_sync; mount_fs || fail "mount"
    out=$(py "$work/flushsync.py" "$mnt/flushed.txt" 2>&1)
    if [ "$macos" = 1 ]; then
        grep -q "cannot sync flushed.txt" "$mount_log" || fail "the file sync fault did not fire on a clean node: $out"
    else
        echo "$out" | grep -q "fsync failed" || fail "the file sync fault did not fire on a clean node: $out"
    fi
    expect_unmount 3
    faults=dir_sync; mount_fs || fail "mount"
    out=$(py "$work/flushsync.py" "$mnt/flushed2.txt" 2>&1)
    if [ "$macos" = 1 ]; then
        grep -q "cannot sync the directory of flushed2.txt" "$mount_log" || fail "the directory sync fault did not fire after a flush: $out"
    else
        echo "$out" | grep -q "fsync failed" || fail "the directory sync fault did not fire after a flush: $out"
    fi
    echo "$out" | grep -q "second fsync ok" || fail "the second fsync failed: $out"
    expect_unmount 3
    expect_eq "$(mode "$enc/flushed2.txt")" "640"

    faults=""
    step "scenario 27: fsync after a directory rename syncs the new directory"
    cat > "$work/renamesync.py" <<'PY'
import os, sys
mnt = sys.argv[1]
os.mkdir(os.path.join(mnt, "ra"))
fd = os.open(os.path.join(mnt, "ra", "file"), os.O_WRONLY | os.O_CREAT)
os.write(fd, b"in a")
os.close(fd)
os.rename(os.path.join(mnt, "ra"), os.path.join(mnt, "rb"))
fd = os.open(os.path.join(mnt, "rb", "file"), os.O_RDWR)
try:
    os.fsync(fd)
    print("fsync succeeded")
except OSError as e:
    print("fsync failed:", e.errno)
os.fsync(fd)
print("second fsync ok")
os.close(fd)
PY
    faults=dir_sync; mount_fs || fail "mount"
    out=$(py "$work/renamesync.py" "$mnt" 2>&1)
    if [ "$macos" = 1 ]; then
        grep -q "cannot sync the directory of rb/file" "$mount_log" || fail "the directory sync of rb did not run: $out"
    else
        echo "$out" | grep -q "fsync failed" || fail "the directory sync of rb did not run: $out"
    fi
    echo "$out" | grep -q "second fsync ok" || fail "the second fsync failed: $out"
    expect_unmount 3

fi
if faults_armed; then
    faults=""
    step "scenario 35: a refused growth keeps the data and the next write succeeds"
    # Start with an existing file so only the larger write triggers the growth fault.
    printf 'start' > "$plain/grow.bin"
    quiet "$bin" encrypt --key "$key" "$plain/grow.bin" "$enc/grow.bin"
    cat > "$work/grow.py" <<'PY'
import os, sys, errno
p = sys.argv[1]
fd = os.open(p, os.O_RDWR)
assert os.pread(fd, 5, 0) == b"start"
big = b"g" * (70 * 1024)
failures = 0
for attempt in range(6):
    try:
        os.pwrite(fd, big, 0)
        os.fsync(fd)
        break
    except OSError as e:
        failures += 1
        print("write refused:", errno.errorcode.get(e.errno, e.errno))
print("failures", failures)
os.close(fd)
with open(p, "rb") as f:
    data = f.read()
print("len", len(data), "ok" if data == big else "bad")
PY
    faults=ciphertext_alloc,plaintext_realloc; mount_fs || fail "mount"
    out=$(py "$work/grow.py" "$mnt/grow.bin" 2>&1)
    # macOS retries failed NFS writes internally, hiding the first refusal.
    if [ "$macos" = 1 ]; then
        echo "$out" | grep -q "write refused" || fail "no refused write: $out"
    else
        echo "$out" | grep -q "failures 2" || fail "expected two refused writes: $out"
    fi
    echo "$out" | grep -q "ok" || fail "the data after the growth is wrong: $out"
    expect_unmount 0
    quiet "$bin" verify --key "$key" "$enc" || fail "verify"
else
    unmount_fs
    echo "   (faults are not armed in this build, scenarios 18, 25, 26, 27, 30 and 35 skipped)"
fi
faults=""

if [ "$macos" = 1 ]; then
    step "scenario 17: a full disk retains the node, and the rescue copy restores the data"
    # Keep hdiutil's stderr warning out of the device name.
    ramdev=$(hdiutil attach -nomount ram://4096 2>/dev/null | awk 'NR == 1 { print $1 }')
    if [ -n "$ramdev" ] && quiet diskutil erasevolume HFS+ tcram "$ramdev"; then
        small="/Volumes/tcram"
        rm -rf "$small/enc"; mkdir "$small/enc"
        enc_saved="$enc"; enc="$small/enc"; backing="$enc"
        # Fill the disk externally because failed write-backs remove their temporary files.
        # Leave less than one allocation block so the next write-back cannot allocate a file.
        fill_disk() { dd if=/dev/zero of="$small/filler" bs=4096 2>/dev/null; dd if=/dev/zero of="$small/filler2" bs=512 2>/dev/null; }
        mount_fs --rescue-dir "$work/rescue" || fail "mount on the RAM disk"
        sh -c "printf 'kept in memory' > '$mnt/retained.txt'"
        fill_disk
        sh -c "printf ' and retried' >> '$mnt/retained.txt'" 2>/dev/null
        grep -q "cannot write back retained.txt" "$mount_log" || fail "the write-back on the full disk did not fail"
        expect_content "$mnt/retained.txt" "kept in memory and retried"
        rm -f "$small/filler" "$small/filler2"
        cat > "$work/retry.py" <<'PY'
import os, sys
fd = os.open(sys.argv[1], os.O_RDWR)
os.fsync(fd)
os.close(fd)
print("retry ok")
PY
        py "$work/retry.py" "$mnt/retained.txt" 2>&1 | grep -q "retry ok" || fail "the retry after freeing space failed"
        expect_unmount 3
        quiet "$bin" decrypt --key "$key" "$enc/retained.txt" "$work/retained.txt" || fail "decrypt of the retried file"
        expect_content "$work/retained.txt" "kept in memory and retried"
        rm -rf "$small/enc"; mkdir "$small/enc"
        mount_fs --rescue-dir "$work/rescue" || fail "mount on the RAM disk"
        sh -c "printf 'rescued' > '$mnt/lost.txt'"
        fill_disk
        sh -c "printf ' at unmount' >> '$mnt/lost.txt'" 2>/dev/null
        expect_unmount 2
        rm -f "$small/filler" "$small/filler2"
        sidecar=$(grep -lx "lost.txt" "$work/rescue"/*.path 2>/dev/null | head -1)
        [ -n "$sidecar" ] || fail "no rescue copy for lost.txt"
        rescued="${sidecar%.path}.enc"
        expect_eq "$(mode "$rescued")" "600"
        expect_eq "$(mode "$work/rescue")" "700"
        quiet "$bin" decrypt --key "$key" "$rescued" "$work/rescued.txt" || fail "decrypt of the rescue copy"
        expect_content "$work/rescued.txt" "rescued at unmount"
        enc="$enc_saved"; backing="$enc"
        hdiutil detach "$ramdev" >/dev/null 2>&1
        ramdev=""
    else
        echo "   (no RAM disk, skipped)"
    fi
fi

step "scenario 20: SIGTERM while a writer holds the file open"
fresh_tree
mount_fs || fail "mount"
(
    exec 3>"$mnt/held.txt"
    printf 'held data' >&3
    kill -TERM "$mount_pid"
    n=0; while is_mounted; do nap; n=$((n + 1)); [ $n -gt 100 ] && break; done
    exec 3>&-
) 2>/dev/null
wait_exit
sigterm_status=$?
if quiet "$bin" decrypt --key "$key" "$enc/held.txt" "$work/held.txt"; then
    echo "   held.txt after SIGTERM: '$(cat "$work/held.txt")', status $sigterm_status"
else
    echo "   held.txt after SIGTERM: not written, status $sigterm_status"
fi

step "scenario 21: names that differ by Unicode normalization"
fresh_tree
nfc=$(printf 'caf\303\251')
nfd=$(printf 'cafe\314\201')
echo "composed" > "$plain/$nfc.txt"
echo "decomposed" > "$plain/$nfd.txt"
for names in "" "--encrypted-filenames"; do
    rm -rf "$enc"
    quiet "$bin" encrypt --key "$key" $names "$plain" "$enc" || fail "encrypt"
    if [ "$macos" = 1 ]; then nfc_variants='"" "-o nfc"'; else nfc_variants='""'; fi
    eval "set -- $nfc_variants"
    for nfcopt in "$@"; do
        mount_fs $names $nfcopt || fail "mount"
        listed=$(ls "$mnt" | grep -c "caf")
        seen_nfc=$(cat "$mnt/$nfc.txt" 2>/dev/null || echo "ENOENT")
        seen_nfd=$(cat "$mnt/$nfd.txt" 2>/dev/null || echo "ENOENT")
        echo "   names='$names' opt='$nfcopt': listed $listed, NFC reads '$seen_nfc', NFD reads '$seen_nfd'"
        expect_unmount 0
    done
done

##### Containers made by "turbocrypt init" #####

backing="$box"
descriptor=".turbocrypt-raf"
chunk=16384
record=16416

fresh_plain() {
    rm -rf "$plain"
    mkdir -p "$plain/sub/deeper"
    echo "hello world" > "$plain/hello.txt"
    head -c 100000 /dev/urandom > "$plain/sub/random.bin"
    echo "deep" > "$plain/sub/deeper/d.txt"
    : > "$plain/empty"
}

fresh_box() {
    rm -rf "$box" "$mnt"
    mkdir -p "$mnt"
    "$bin" init --key "$key" "$@" "$box" > "$work/init.log" 2>&1 || fail "init with '$*': $(cat "$work/init.log")"
}

# The AppleDouble sidecars that macOS writes next to copied files are not part of the test.
visible() { ls "$1" | grep -v '^\._' | tr '\n' ' '; }
descriptor_size=65

step "container 1: init, mount, and the hidden descriptor in the three name modes"
fresh_plain
for names in "" "--encrypted-filenames" "--enc-suffix" "--encrypted-filenames --enc-suffix"; do
    fresh_box $names
    expect_eq "$(size_of "$box/$descriptor")" "$descriptor_size"
    expect_eq "$(ls -a "$box" | grep -cxF "$descriptor")" "1"
    mount_fs || fail "mount of a container made with '$names'"
    cp -R "$plain/." "$mnt/" 2>/dev/null
    expect_eq "$(visible "$mnt")" "empty hello.txt sub "
    expect_eq "$(ls -a "$mnt" | grep -c turbocrypt-raf)" "0"
    cat "$mnt/$descriptor" 2>&1 | grep -qi "no such file" || fail "the descriptor is visible with '$names'"
    expect_content "$mnt/hello.txt" "hello world"
    expect_content "$mnt/sub/deeper/d.txt" "deep"
    cmp -s "$mnt/sub/random.bin" "$plain/sub/random.bin" || fail "random.bin differs"
    expect_eq "$(size_of "$mnt/empty")" "0"
    expect_unmount 0
    expect_eq "$(size_of "$box/$descriptor")" "$descriptor_size"
    # The settings live in the descriptor: a later mount needs no filename option.
    mount_fs || fail "second mount without options"
    expect_content "$mnt/sub/deeper/d.txt" "deep"
    expect_unmount 0
    if [ "$names" = "--encrypted-filenames --enc-suffix" ]; then
        expect_eq "$(ls "$box" | grep -c '\.enc$')" "0"
    fi
done

step "container 2: the reserved name cannot be created, replaced, renamed or removed"
fresh_box
mount_fs || fail "mount"
echo "x" > "$mnt/hello.txt"
cat > "$work/reserved.py" <<'PY'
import os, sys, errno
reserved, other = sys.argv[1], sys.argv[2]
def attempt(call):
    try:
        call()
        return "ok"
    except OSError as e:
        return errno.errorcode.get(e.errno, str(e.errno))
print("create", attempt(lambda: os.close(os.open(reserved, os.O_WRONLY | os.O_CREAT))))
print("mkdir", attempt(lambda: os.mkdir(reserved)))
print("rename", attempt(lambda: os.rename(other, reserved)))
print("unlink", attempt(lambda: os.unlink(reserved)))
print("open", attempt(lambda: os.close(os.open(reserved, os.O_RDONLY))))
PY
# Another spelling of the name reaches the same file on a case-insensitive filesystem.
for spelling in "$descriptor" ".TURBOCRYPT-RAF" ".Turbocrypt-Raf"; do
    out=$(py "$work/reserved.py" "$mnt/$spelling" "$mnt/hello.txt" 2>&1)
    echo "$out" | grep -q "^create EPERM" || fail "create of $spelling: $out"
    echo "$out" | grep -q "^mkdir EPERM" || fail "mkdir of $spelling: $out"
    echo "$out" | grep -q "^rename EPERM" || fail "rename onto $spelling: $out"
    echo "$out" | grep -q "^unlink ENOENT" || fail "unlink of $spelling: $out"
    echo "$out" | grep -q "^open ENOENT" || fail "open of $spelling: $out"
done
expect_content "$mnt/hello.txt" "x"
expect_unmount 0
expect_eq "$(size_of "$box/$descriptor")" "$descriptor_size"
mount_fs || fail "the descriptor did not survive the reserved-name attempts"
expect_content "$mnt/hello.txt" "x"
expect_unmount 0
expect_eq "$(size_of "$box/$descriptor")" "$descriptor_size"
# With encrypted names the plain name maps elsewhere, and the descriptor is untouched.
fresh_box --encrypted-filenames
mount_fs || fail "mount"
echo "mine" > "$mnt/$descriptor" || fail "a user file with the reserved plain name was refused with encrypted names"
expect_content "$mnt/$descriptor" "mine"
expect_unmount 0
expect_eq "$(size_of "$box/$descriptor")" "$descriptor_size"
# The user file has an encrypted name; macOS adds a sidecar next to it.
[ "$(ls -A "$box" | wc -l | tr -d ' ')" -ge 2 ] || fail "the user file did not land in the container"
mount_fs || fail "remount"
expect_content "$mnt/$descriptor" "mine"
expect_unmount 0

step "container 3: filename options must agree with the descriptor, and the saved default is ignored"
fresh_box
expect_refused "initialized with plain names" "a conflicting --encrypted-filenames" "$bin" mount --key "$key" --encrypted-filenames "$box" "$mnt"
expect_refused "initialized without the suffix" "a conflicting --enc-suffix" "$bin" mount --key "$key" --enc-suffix "$box" "$mnt"
is_mounted && fail "mounted despite the conflict"
quiet "$bin" config set-encrypted-filenames true || fail "config"
mount_fs || fail "mount with a saved default that differs from the descriptor"
echo "plain names" > "$mnt/named.txt"
expect_unmount 0
expect_file "$box/named.txt"
quiet "$bin" config set-encrypted-filenames false || fail "config"
fresh_box --enc-suffix
mount_fs --enc-suffix || fail "an agreeing --enc-suffix was refused"
echo "s" > "$mnt/s.txt"
expect_unmount 0
expect_file "$box/s.txt.enc"

step "container 4: create, append, write at offsets, truncate, sizes, and a remount"
fresh_box
mount_fs || fail "mount"
echo "line one" > "$mnt/new.txt"
echo "line two" >> "$mnt/new.txt"
printf 'XX' | dd of="$mnt/new.txt" bs=1 seek=5 conv=notrunc 2>/dev/null
expect_eq "$(cat "$mnt/new.txt" | tr '\n' '|')" "line XXe|line two|"
printf 'Z' | dd of="$mnt/new.txt" bs=1 seek=40 conv=notrunc 2>/dev/null
expect_eq "$(size_of "$mnt/new.txt")" "41"
truncate -s 4 "$mnt/new.txt"
expect_content "$mnt/new.txt" "line"
truncate -s 6 "$mnt/new.txt"
expect_eq "$(od -An -c "$mnt/new.txt" | tr -d ' \n')" 'line\0\0'
: > "$mnt/zero"
expect_eq "$(size_of "$box/zero")" "64"
expect_eq "$(size_of "$box/new.txt")" "$((64 + record))"
head -c $chunk /dev/urandom > "$work/one_chunk.bin"
head -c $((chunk + 1)) /dev/urandom > "$work/one_chunk_and_one.bin"
cp "$work/one_chunk.bin" "$mnt/one_chunk.bin"
cp "$work/one_chunk_and_one.bin" "$mnt/one_chunk_and_one.bin"
expect_eq "$(size_of "$box/one_chunk.bin")" "$((64 + record))"
expect_eq "$(size_of "$box/one_chunk_and_one.bin")" "$((64 + 2 * record))"
cat > "$work/straddle.py" <<'PY'
import os, sys
p = sys.argv[1]
chunk = 16384
fd = os.open(p, os.O_RDWR)
os.pwrite(fd, b"ABCDEFGH", chunk - 4)
assert os.pread(fd, 8, chunk - 4) == b"ABCDEFGH"
os.pwrite(fd, b"Q", 3 * chunk + 7)
os.fsync(fd)
os.close(fd)
with open(p, "rb") as f:
    data = f.read()
assert len(data) == 3 * chunk + 8, len(data)
assert data[chunk - 4:chunk + 4] == b"ABCDEFGH"
assert data[chunk + 4:3 * chunk + 7] == bytes(2 * chunk + 3), "the gap is not zero"
assert data[-1:] == b"Q"
print("straddle ok")
PY
py "$work/straddle.py" "$mnt/one_chunk_and_one.bin" 2>&1 | grep -q "straddle ok" || fail "the straddling write or the gap failed"
expect_eq "$(size_of "$box/one_chunk_and_one.bin")" "$((64 + 4 * record))"
truncate -s $((chunk + 1)) "$mnt/one_chunk_and_one.bin"
expect_eq "$(size_of "$box/one_chunk_and_one.bin")" "$((64 + 2 * record))"
expect_unmount 0
mount_fs || fail "remount"
expect_eq "$(od -An -c "$mnt/new.txt" | tr -d ' \n')" 'line\0\0'
cmp -s "$mnt/one_chunk.bin" "$work/one_chunk.bin" || fail "one_chunk.bin differs after the remount"
expect_eq "$(size_of "$mnt/one_chunk_and_one.bin")" "$((chunk + 1))"
expect_unmount 0

step "container 5: a 64 MiB file, mmap, and the hash after a remount"
mount_fs || fail "mount"
cp "$work/big.bin" "$mnt/big.bin"
expect_eq "$(sha "$mnt/big.bin")" "$(sha "$work/big.bin")"
expect_eq "$(size_of "$box/big.bin")" "$((64 + 4096 * record))"
echo "hello world" > "$mnt/hello.txt"
if command -v python3 >/dev/null 2>&1; then
    py "$work/mm.py" "$mnt/hello.txt" || fail "mmap"
    expect_content "$mnt/hello.txt" "HELLO world"
fi
expect_unmount 0
mount_fs || fail "remount"
expect_eq "$(sha "$mnt/big.bin")" "$(sha "$work/big.bin")"
expect_unmount 0

step "container 6: mv and rm, closed and open, a directory rename with an open descendant, and a rename over an open destination"
fresh_box
mount_fs || fail "mount"
echo "hello world" > "$mnt/hello.txt"
mv "$mnt/hello.txt" "$mnt/renamed.txt"
expect_no_file "$mnt/hello.txt"
expect_content "$mnt/renamed.txt" "hello world"
expect_eq "$( (exec 3<"$mnt/renamed.txt"; mv "$mnt/renamed.txt" "$mnt/open-moved.txt"; cat <&3) )" "hello world"
expect_content "$mnt/open-moved.txt" "hello world"
rm "$mnt/open-moved.txt"
expect_no_file "$mnt/open-moved.txt"
echo "to delete" > "$mnt/gone.txt"
( exec 3<"$mnt/gone.txt"; rm "$mnt/gone.txt"; expect_eq "$(cat <&3)" "to delete" )
expect_no_file "$mnt/gone.txt"
expect_eq "$(ls -a "$box" | grep -c '^\.tc-')" "0"
mkdir "$mnt/dir1"
(
    exec 3>"$mnt/dir1/live.txt"
    printf 'live data' >&3
    mv "$mnt/dir1" "$mnt/dir2"
    printf ' more' >&3
    exec 3>&-
)
expect_no_file "$mnt/dir1"
expect_content "$mnt/dir2/live.txt" "live data more"
echo "old" > "$mnt/dest.txt"
echo "new" > "$mnt/src.txt"
expect_eq "$( (exec 3<"$mnt/dest.txt"; mv "$mnt/src.txt" "$mnt/dest.txt"; cat <&3) )" "old"
expect_content "$mnt/dest.txt" "new"
expect_no_file "$mnt/src.txt"
mkdir "$mnt/d1"
echo x > "$mnt/d1/f"
rmdir "$mnt/d1" 2>/dev/null && fail "rmdir of a non-empty directory succeeded"
rm "$mnt/d1/f"
rmdir "$mnt/d1"
expect_no_file "$box/d1"
expect_unmount 0
mount_fs || fail "remount"
expect_content "$mnt/dir2/live.txt" "live data more"
expect_content "$mnt/dest.txt" "new"
expect_eq "$(ls "$box" | grep -c "src.txt")" "0"
expect_unmount 0

step "container 7: concurrent writers on two files, and two appenders on one file"
mount_fs || fail "mount"
( i=0; while [ $i -lt 200 ]; do echo "a$i" >> "$mnt/wa.txt"; i=$((i + 1)); done ) &
wa=$!
( i=0; while [ $i -lt 200 ]; do echo "b$i" >> "$mnt/wb.txt"; i=$((i + 1)); done ) &
wb=$!
wait $wa; wait $wb
expect_eq "$(wc -l < "$mnt/wa.txt" | tr -d ' ')" "200"
expect_eq "$(wc -l < "$mnt/wb.txt" | tr -d ' ')" "200"
expect_eq "$(tail -1 "$mnt/wb.txt")" "b199"
( i=0; while [ $i -lt 100 ]; do echo "x$i" >> "$mnt/shared.txt"; i=$((i + 1)); done ) &
xa=$!
( i=0; while [ $i -lt 100 ]; do echo "y$i" >> "$mnt/shared.txt"; i=$((i + 1)); done ) &
xb=$!
wait $xa; wait $xb
expect_eq "$(wc -l < "$mnt/shared.txt" | tr -d ' ')" "200"
expect_eq "$(sort "$mnt/shared.txt" | uniq -d | wc -l | tr -d ' ')" "0"
expect_unmount 0

step "container 8: --read-only refuses writes, and a write-only open still updates records"
mount_fs --read-only || fail "mount"
touch "$mnt/nope" 2>&1 | grep -qi "read-only" || fail "touch did not fail with EROFS"
expect_content "$mnt/dest.txt" "new"
expect_unmount 0
mount_fs || fail "mount"
cat > "$work/wronly.py" <<'PY'
import os, sys
p = sys.argv[1]
fd = os.open(p, os.O_WRONLY)
os.pwrite(fd, b"WO", 1)
os.close(fd)
fd = os.open(p, os.O_WRONLY | os.O_APPEND)
os.write(fd, b"+")
os.close(fd)
with open(p, "rb") as f:
    print(f.read().decode())
PY
expect_eq "$(py "$work/wronly.py" "$mnt/dest.txt" 2>&1 | tr -d '\n')" "nWO+"
# On a case-insensitive filesystem two spellings reach one inode; only one context may hold it.
: > "$mnt/CaseAlias"
if [ -e "$mnt/casealias" ]; then
    cat > "$work/alias.py" <<'PY'
import os, sys, errno
first, second = sys.argv[1], sys.argv[2]
a = os.open(first, os.O_RDWR)
os.pwrite(a, b"A", 0)
try:
    b = os.open(second, os.O_RDWR)
    os.close(b)
    print("second open ok")
except OSError as e:
    print("second open", errno.errorcode.get(e.errno, str(e.errno)))
os.close(a)
b = os.open(second, os.O_RDWR)
os.pwrite(b, b"B", 1)
os.close(b)
print("alias write done")
PY
    out=$(py "$work/alias.py" "$mnt/CaseAlias" "$mnt/casealias" 2>&1)
    echo "$out" | grep -q "second open ok" && fail "an alias of an open file got its own context: $out"
    echo "$out" | grep -q "alias write done" || fail "the write through the alias failed: $out"
    grep -q "already open under another name" "$mount_log" || fail "no alias message: $(cat "$mount_log")"
    # The client caches attributes per spelling, so the stored bytes are checked through a fresh mount.
    expect_unmount 0
    mount_fs || fail "remount"
    expect_eq "$(cat "$mnt/CaseAlias")" "AB"
    expect_eq "$(cat "$mnt/casealias")" "AB"
else
    echo "   (case-sensitive filesystem, the alias check is skipped)"
fi
expect_unmount 0

step "container 9: wrong key and context, refused options, duplicate mounts, and mounts inside"
expect_refused "wrong key, wrong context" "a mount with the wrong key" "$bin" mount --key "$work/wrong.key" "$box" "$mnt"
expect_refused "wrong key, wrong context" "a mount with another context" "$bin" mount --key "$key" --context other "$box" "$mnt"
expect_refused "wrong key, wrong context" "--force with the wrong key" "$bin" mount --key "$work/wrong.key" --force "$box" "$mnt"
expect_refused "does not apply to a container" "--force on a container" "$bin" mount --key "$key" --force "$box" "$mnt"
for opt in "--max-file-size 1073741824" "--memory-limit 4294967296" "--rescue-dir $work/r"; do
    expect_refused "not to a container" "$opt on a container" "$bin" mount --key "$key" $opt "$box" "$mnt"
done
is_mounted && fail "mounted after a refused option"
mount_fs || fail "mount"
mkdir -p "$work/mnt2"
expect_refused "already mounted" "a second mount of the same container" "$bin" mount --key "$key" "$box" "$work/mnt2"
expect_refused "already a container" "init of a mounted container" "$bin" init --key "$key" "$box"
mkdir -p "$mnt/inside"
expect_refused "inside the container" "a mount inside the container" "$bin" mount --key "$key" "$box/inside" "$work/mnt2"
expect_refused "inside the container" "init inside a container" "$bin" init --key "$key" "$box/inside/deeper"
expect_no_file "$box/inside/deeper"
expect_unmount 0
rmdir "$work/mnt2"
rm -rf "$work/empty"; mkdir "$work/empty"
backing="$work/empty"
mount_fs || fail "mount of an empty v1 tree"
expect_refused "in use by another turbocrypt process" "init of a mounted empty directory" "$bin" init --key "$key" "$work/empty"
expect_unmount 0
backing="$box"

step "container 10: the ordinary commands and a v1 mount refuse a container"
expect_refused "Mount it and copy" "list of a container" "$bin" list "$box"
expect_refused "Mount it and copy" "verify of a container" "$bin" verify --key "$key" "$box"
expect_refused "Mount it and copy" "decrypt of a container" "$bin" decrypt --key "$key" "$box" "$work/dec-box"
expect_no_file "$work/dec-box"
expect_refused "Mount it and copy" "encrypt into a container" "$bin" encrypt --key "$key" "$plain" "$box/into"
expect_no_file "$box/into"
# Resolve bare destinations against the container working directory.
in_box() { ( cd "$box" && "$@" ); }
quiet "$bin" encrypt --key "$key" "$plain/hello.txt" "$work/for-cwd.v1" || fail "encrypt"
expect_refused "inside the TurboCrypt container" "decrypt to a bare name inside the container" in_box "$bin" decrypt --key "$key" "$work/for-cwd.v1" leaked.txt
expect_no_file "$box/leaked.txt"
expect_refused "inside the TurboCrypt container" "encrypt to a bare name inside the container" in_box "$bin" encrypt --key "$key" "$plain/hello.txt" new.enc
expect_no_file "$box/new.enc"
expect_refused "inside the container" "init of a bare name inside the container" in_box "$bin" init --key "$key" nested
expect_no_file "$box/nested"
fresh_tree
mkdir -p "$enc/nested"
: > "$enc/nested/$descriptor"
expect_refused "is a TurboCrypt container" "list of a tree with a nested container" "$bin" list "$enc"
rm -rf "$enc/nested"
# A stray file under the reserved name refuses a v1 mount, and --force does not help.
echo "mine" > "$enc/$descriptor"
backing="$enc"
expect_refused "$descriptor is not a valid container descriptor" "a v1 mount with a stray descriptor" "$bin" mount --key "$key" "$enc" "$mnt"
grep -q "move or delete that file" "$work/refused.log" || fail "no advice in the message: $(cat "$work/refused.log")"
expect_refused "$descriptor" "--force on a v1 tree with a stray descriptor" "$bin" mount --key "$key" --force "$enc" "$mnt"
rm "$enc/$descriptor"
mount_fs || fail "the v1 tree does not mount once the stray file is gone"
expect_content "$mnt/hello.txt" "hello world"
expect_unmount 0
backing="$box"

step "container 11: damaged, stray, crafted and hard-linked files stay listable and removable"
fresh_box
mount_fs || fail "mount"
head -c 40000 /dev/urandom > "$work/dmg.bin"
cp "$work/dmg.bin" "$mnt/dmg"
cp "$work/dmg.bin" "$mnt/hdr"
echo "small" > "$mnt/small"
echo "linkme" > "$mnt/linkme"
expect_unmount 0
cat > "$work/damage.py" <<'PY'
import sys
path, offset = sys.argv[1], int(sys.argv[2])
with open(path, "r+b") as f:
    f.seek(offset)
    b = f.read(1)
    f.seek(offset)
    f.write(bytes([b[0] ^ 0x80]))
PY
py "$work/damage.py" "$box/dmg" $((64 + record + 16 + 5)) || fail "damage"
py "$work/damage.py" "$box/hdr" 50 || fail "damage"
# The ordinary command refuses to write into a container, so the stray file is moved in by hand.
quiet "$bin" encrypt --key "$key" "$plain/hello.txt" "$work/stray.v1" || fail "encrypt"
mv "$work/stray.v1" "$box/stray.v1"
cat > "$work/craft.py" <<'PY'
import sys, struct
src, dst = sys.argv[1], sys.argv[2]
with open(src, "rb") as f:
    hdr = bytearray(f.read(64))
hdr[16:24] = struct.pack("<Q", 2**64 - 1)
with open(dst, "wb") as f:
    f.write(hdr)
PY
py "$work/craft.py" "$box/small" "$box/crafted" || fail "craft"
ln "$box/linkme" "$box/linked"
mount_fs || fail "mount"
expect_eq "$(size_of "$mnt/dmg")" "40000"
expect_eq "$(size_of "$mnt/hdr")" "40000"
expect_eq "$(size_of "$mnt/stray.v1")" "60"
expect_eq "$(size_of "$mnt/crafted")" "64"
expect_eio "$mnt/dmg" "no EIO for the damaged record"
expect_eio "$mnt/hdr" "no EIO for the damaged header"
expect_eio "$mnt/stray.v1" "no EIO for the stray v1 file"
expect_eio "$mnt/crafted" "no EIO for the crafted header"
# The NFS client of fuse-t shows EOPNOTSUPP from open as a permission error.
cat "$mnt/linked" 2>&1 | grep -qi "not supported\|permission denied" || fail "a hard-linked file was opened"
cat "$mnt/linkme" 2>&1 | grep -qi "not supported\|permission denied" || fail "the other name of a hard-linked file was opened"
grep -q "linked has 2 links; a container file must have one" "$mount_log" || fail "no hard-link message: $(cat "$mount_log")"
expect_content "$mnt/small" "small"
grep -q "hdr does not authenticate; its size comes from the unauthenticated header" "$mount_log" || fail "no probe message: $(cat "$mount_log")"
grep -q "stray.v1 is not a container file" "$mount_log" || fail "no stray-file message: $(cat "$mount_log")"
rm "$mnt/dmg" "$mnt/hdr" "$mnt/stray.v1" "$mnt/crafted" "$mnt/linked" || fail "removal of damaged files failed"
expect_content "$mnt/linkme" "linkme"
expect_no_file "$box/dmg"
expect_no_file "$box/crafted"
expect_unmount 0
expect_eq "$(grep -c "internal error" "$mount_log")" "0"

step "container 12: symlinks in a recursive copy are reported, and the other files land"
fresh_plain
ln -s hello.txt "$plain/link"
mount_fs || fail "mount"
cp -R "$plain/." "$mnt/" > "$work/cp.log" 2>&1 && fail "cp -R with a symlink reported success"
# GNU cp says "symbolic link", BSD cp says "symlink", and the NFS client of fuse-t shows EOPNOTSUPP as EIO.
grep -qi "link.*not supported\|link.*input/output error" "$work/cp.log" || fail "no error for the symlink: $(cat "$work/cp.log")"
expect_content "$mnt/hello.txt" "hello world"
expect_content "$mnt/sub/deeper/d.txt" "deep"
expect_no_file "$mnt/link"
expect_unmount 0
rm "$plain/link"

step "container 13: chmod upgrades an open reader, and cp -p keeps the mtime"
mount_fs $fresh_attrs || fail "mount"
chmod 400 "$mnt/empty"
python3 - "$mnt/empty" <<'PY'
import os, sys
p = sys.argv[1]
reader = os.open(p, os.O_RDONLY)
try:
    os.chmod(p, 0o600)
    writer = os.open(p, os.O_WRONLY)
    try:
        os.write(writer, b"X")
    finally:
        os.close(writer)
finally:
    os.close(reader)
PY
expect_content "$mnt/empty" "X"
expect_eq "$(mode "$mnt/empty")" "600"
expect_eq "$(mode "$box/empty")" "600"
touch -t 202001010000 "$plain/hello.txt"
cp -p "$plain/hello.txt" "$mnt/copied.txt" 2>/dev/null
expect_eq "$(mtime "$mnt/copied.txt")" "$(mtime "$plain/hello.txt")"
# The fault scenarios below append to this file, so it must exist before a fault is armed.
head -c 20000 /dev/urandom > "$work/two.bin"
cp "$work/two.bin" "$mnt/two.bin"
expect_unmount 0
expect_eq "$(mtime "$box/copied.txt")" "$(mtime "$plain/hello.txt")"
expect_eq "$(mode "$box/empty")" "600"

faults=raf_writev_short; mount_fs || fail "mount"
if faults_armed; then
    step "container 14: a torn record poisons the open file, and a fresh open sees the damage"
    cat > "$work/torn.py" <<'PY'
import os, sys, errno
p = sys.argv[1]
fd = os.open(p, os.O_RDWR)
size = os.fstat(fd).st_size
seen = []
try:
    os.pwrite(fd, b"appended", size)
    os.fsync(fd)
except OSError as e:
    seen.append(errno.errorcode.get(e.errno, str(e.errno)))
try:
    os.pread(fd, 10, 0)
except OSError as e:
    seen.append(errno.errorcode.get(e.errno, str(e.errno)))
# A sync of the directory must not report success while the open file has a failed write.
d = os.open(os.path.dirname(p), os.O_RDONLY)
try:
    os.fsync(d)
    seen.append("dirsync-ok")
except OSError as e:
    seen.append("dirsync-" + errno.errorcode.get(e.errno, str(e.errno)))
os.close(d)
try:
    os.close(fd)
except OSError as e:
    seen.append(errno.errorcode.get(e.errno, str(e.errno)))
print("seen", " ".join(seen))
PY
    out=$(py "$work/torn.py" "$mnt/two.bin" 2>&1)
    grep -q "cannot write two.bin: InputOutput" "$mount_log" || fail "the torn write was not reported: $(cat "$mount_log") / $out"
    if [ "$macos" = 0 ]; then
        echo "$out" | grep -q "EIO" || fail "the application did not see the error: $out"
        echo "$out" | grep -q "dirsync-EIO" || fail "the directory sync hid the failed write: $out"
    fi
    expect_eq "$(size_of "$mnt/two.bin")" "20000"
    expect_eio "$mnt/two.bin" "the torn record still reads"
    rm "$mnt/two.bin"
    expect_unmount 0
    expect_eq "$(grep -c "internal error" "$mount_log")" "0"

    step "container 15: a refused length change fails a growth with ENOSPC and leaves the file readable"
    faults=raf_set_length; mount_fs || fail "mount"
    cat > "$work/grow_fail.py" <<'PY'
import os, sys, errno
p = sys.argv[1]
fd = os.open(p, os.O_RDWR)
seen = []
try:
    os.pwrite(fd, b"more", 16384 * 2)
    os.fsync(fd)
except OSError as e:
    seen.append(errno.errorcode.get(e.errno, str(e.errno)))
try:
    os.close(fd)
except OSError as e:
    seen.append(errno.errorcode.get(e.errno, str(e.errno)))
print("seen", " ".join(seen))
PY
    out=$(py "$work/grow_fail.py" "$mnt/small" 2>&1)
    grep -q "cannot write small: NoSpaceLeft" "$mount_log" || fail "the refused growth was not reported: $(cat "$mount_log") / $out"
    if [ "$macos" = 0 ]; then
        echo "$out" | grep -q "ENOSPC" || fail "the application did not see ENOSPC: $out"
    fi
    expect_content "$mnt/small" "small"
    expect_unmount 0

    step "container 16: a failed sync of a container file is reported"
    faults=file_sync; mount_fs || fail "mount"
    out=$(py "$work/fsync.py" "$mnt/synced.txt" 2>&1)
    if [ "$macos" = 1 ]; then
        grep -q "cannot sync synced.txt" "$mount_log" || fail "the sync fault did not fire: $out"
    else
        echo "$out" | grep -q "first fsync failed" || fail "the sync fault did not fire: $out"
    fi
    echo "$out" | grep -q "second fsync ok" || fail "the second fsync failed: $out"
    expect_content "$mnt/synced.txt" "synced data"
    expect_unmount 3
    faults=""
else
    unmount_fs
    echo "   (faults are not armed in this build, container scenarios 14 to 16 skipped)"
fi
faults=""

if [ -n "${TURBOCRYPT_E2E_BIG:-}" ]; then
    step "container 17: a file above the old 1 GiB limit, random access past 1 GiB, and flat memory"
    fresh_box
    mount_fs || fail "mount"
    rss() { ps -o rss= -p "$mount_pid" | tr -d ' '; }
    rss_before=$(rss)
    head -c $((1024 * 1024 * 1024 + 1024 * 1024)) /dev/urandom > "$work/huge.bin"
    cp "$work/huge.bin" "$mnt/huge.bin"
    rss_after=$(rss)
    echo "   mount RSS: $rss_before KiB before, $rss_after KiB after a 1 GiB + 1 MiB copy"
    [ $((rss_after - rss_before)) -lt 65536 ] || fail "the mount's memory grew with the file: $rss_before -> $rss_after KiB"
    expect_eq "$(sha "$mnt/huge.bin")" "$(sha "$work/huge.bin")"
    cat > "$work/far.py" <<'PY'
import os, sys, hashlib
p, ref = sys.argv[1], sys.argv[2]
fd = os.open(p, os.O_RDWR)
size = os.fstat(fd).st_size
for off in (size - 5, 1024 * 1024 * 1024 + 3, 1024 * 1024 * 1024 - 7, 12345678):
    os.pwrite(fd, b"MARK", off)
    assert os.pread(fd, 4, off) == b"MARK", off
os.close(fd)
with open(ref, "r+b") as f:
    for off in (size - 5, 1024 * 1024 * 1024 + 3, 1024 * 1024 * 1024 - 7, 12345678):
        f.seek(off)
        f.write(b"MARK")
print("far ok")
PY
    py "$work/far.py" "$mnt/huge.bin" "$work/huge.bin" 2>&1 | grep -q "far ok" || fail "random access past 1 GiB failed"
    expect_unmount 0
    mount_fs || fail "remount"
    expect_eq "$(sha "$mnt/huge.bin")" "$(sha "$work/huge.bin")"
    expect_unmount 0
    rm -f "$work/huge.bin"
fi

backing="$enc"

cleanup
echo "mount_e2e: all scenarios passed"
