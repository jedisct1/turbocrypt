# Mounting an encrypted directory

[Back to the main README](../README.md)

`turbocrypt mount` shows an encrypted directory as a normal one.
You read and write plain files in the mounted directory, and TurboCrypt keeps encrypted files in the original one.
`decrypt`, `verify` and `list` accept that directory afterwards, since the file format does not change.

```bash
turbocrypt mount encrypted/ ~/Volumes/plain
turbocrypt unmount ~/Volumes/plain
```

The first argument is the encrypted directory.
The second is an empty directory where the plain files appear.
The command stays in the foreground until the volume is unmounted.
`--daemon` returns once the volume is up.

## Starting from plain files

`mount` does not encrypt an existing directory.
It shows files that are already encrypted.
To start from plain files, encrypt them first, then mount the result:

```bash
turbocrypt encrypt documents/ encrypted/
mkdir ~/Volumes/documents
turbocrypt mount encrypted/ ~/Volumes/documents
```

From then on, every file written under `~/Volumes/documents` lands encrypted in `encrypted/`.
An empty encrypted directory mounts too, so a new store can also start empty and fill up through the mount.

## Requirements

On macOS, install [fuse-t](https://github.com/macos-fuse-t/fuse-t/releases).
It needs no kernel extension and no reboot.
The mount loads its library at run time, so a machine without it still runs every other command.

On Linux, install the `fuse3` package for its `fusermount3` helper.
The library itself is compiled into the binary, which stays a single static file.
That library is libfuse, under the LGPL-2.1, and its source is the tarball named in `build.zig.zon`.
Windows is not supported.

## How it works

TurboCrypt encrypts each file as one message with one authentication tag.
There is no way to read or change part of a file without processing the whole file.
The mount therefore keeps each open file decrypted in memory.
A read decrypts the whole file on the first access.
A write changes the copy in memory.
The file goes back to disk as a new encrypted file when it is flushed, synced or closed.

This has consequences:

- A file larger than `--max-file-size` cannot be opened. The default is 1 GiB.
- All open files together must fit in `--memory-limit`. The default is 4 GiB.
- Closing a large file takes the time of one encryption of that file.
- Every write-back replaces the encrypted file. Hard links to it break, and its inode changes.

Filenames map in both directions without any table.
The mount handles plain names, names with the `.enc` suffix, and encrypted names, with the same options as `encrypt`.

## Options

| Option                  | Effect                                                              |
| ----------------------- | ------------------------------------------------------------------- |
| `--key`, `--password`, `--context` | As for every other command. The config default for encrypted filenames applies too |
| `--encrypted-filenames` | The encrypted directory has encrypted names                         |
| `--enc-suffix`          | Files in the encrypted directory carry `.enc`, the view does not    |
| `--read-only`           | Every change is refused with EROFS                                  |
| `--daemon`              | Return once the volume is mounted                                   |
| `--single-thread`       | Serve one request at a time, for debugging                          |
| `--debug`               | Print libfuse traffic and the mount's own diagnostics               |
| `--volname <name>`      | The volume name, by default the name of the mountpoint              |
| `--allow-other`         | Serve other users, with POSIX permission checks done by the mount   |
| `--max-file-size <n>`   | Largest file that can be opened, in bytes                           |
| `--memory-limit <n>`    | Budget for all open files, in bytes. At least three times the file limit plus 1 MiB |
| `--rescue-dir <dir>`    | Where files that could not be written back go at unmount            |
| `--force`               | Skip the key check on the first file                                |
| `-o <option>`           | A libfuse or fuse-t option, may be repeated                         |

`--exclude` is not accepted. The view shows the whole directory.

## Permissions

The mount serves its own user only.
A request from another account gets EACCES.
`--allow-other` serves everyone, and the mount then applies the usual POSIX rules itself: the mode bits, the owner, the group and the sticky bit.
On macOS only the primary group of the caller counts, because fuse-t gives no list of supplementary groups.
A file or directory that another user creates gets that user as its owner.
Only a mount that runs as root can give it, so another user's create gets EPERM otherwise.

A file is writable through the mount only when a new file could get the same owner and group.
That holds for the files you own, with your group, with a group of yours, or with the group the directory hands out.
A file that belongs to someone else can be read but not written, and the mount prints why.

Creation modes follow the umask of the program that creates the file, once.

## Key check

At mount time, the mount reads the header of the first file it finds and checks it against the key.
A wrong key or context refuses the mount.
Every existing file would be unreadable, and every new file would be written with the wrong key.
`--force` skips the check.
An empty directory has nothing to check and mounts without it.
The search stops after 1024 entries.
A tree with no readable file among them, or whose files the mount cannot read, is refused unless `--force` is given, since the key cannot be checked.

## Caching

fuse-t serves the volume through the NFS client of macOS.
That client caches file data and attributes.
A `stat` from another process can show attributes that are up to 60 seconds old.
Opening the file gives the latest content.
Pass `-o noattrcache` when fresh attributes matter more than speed.

fuse-t moves data in requests of `rwsize` bytes.
The mount asks for 1 MiB.
On a 256 MiB file that gave about 345 MB/s of writes and 2 GB/s of first reads.
The default of 32 KiB gave 70 MB/s and 1 GB/s.
Pass your own `-o rwsize=<power of two>` to change it.

Two names that differ only by Unicode normalization collapse into one for the NFS client, in both name modes.
The listing shows one entry and only the decomposed file can be read.
With encrypted names the decomposed spelling of that name may give ENOENT unless `-o nfc` is given.
A name that is not valid UTF-8 is invisible.

macOS creates `.DS_Store` and `._*` files through the mount.
The `._*` files hold the extended attributes that the mount does not accept.
They are encrypted like everything else and stay in the encrypted directory.
Some programs notice them: a `git clone` into the mount works, but git then complains about the `._pack-*.idx` files next to its pack indexes.

## What is hidden

The view shows regular files and directories.
Symbolic links, FIFOs, sockets and devices in the encrypted directory are absent and answer ENOENT.
Names that do not decode in encrypted-name mode are absent too.
So are files without `.enc` in suffix mode, and temporary files of the form `.tc-<16 hex digits>.tmp`.
`list` still shows everything.

The temporary name is reserved.
In plain-name mode a file with that name cannot be created through the mount.
A temporary file left by a crash stays hidden.
Remove them with:

```bash
find encrypted/ -name '.tc-*.tmp' -delete
```

A directory that holds only hidden entries is not empty on disk, so `rmdir` refuses it.

## Unsupported operations

Hard links, symbolic links, device nodes and extended attributes answer ENOTSUP.
`cp -p` warns about extended attributes and copies the rest.

## Failures and the exit status

A write-back can fail, for example on a full disk.
The file stays in memory, the mount prints one line, and the next flush, sync or close retries.
On macOS the program that called `fsync` or `close` does not see the error: fuse-t answers it with success anyway.
The line on stderr and the exit status are the only signs of it there.
An `fsync` on a file with no pending writes does not reach the mount on macOS either.
The directory entry of a file is therefore made durable at unmount, not at that call.
A program that reopens the file sees its own data.
At unmount, what still cannot be written back is saved as ciphertext under `--rescue-dir`.
The default is `rescue/` in the application data directory.
A sidecar file next to each copy holds the path.
`turbocrypt decrypt` restores such a copy with the same key.

The exit status of a foreground mount:

| Status | Meaning                                                                    |
| ------ | -------------------------------------------------------------------------- |
| 0      | A requested unmount, with no failure during the session                    |
| 1      | A setup error, the mount never happened                                    |
| 2      | The volume is gone but at least one file could not be written back         |
| 3      | The session ended without an unmount request, or a failure was counted     |

A daemonized mount reports only through stderr and the rescue directory.

Stop a mount with `turbocrypt unmount`, `umount` or `diskutil unmount`.
Close the files first.
The unmount writes back what is still open, but a program that keeps a file open during the unmount may lose what it wrote last.
SIGTERM, SIGINT and SIGHUP end the session too, with the same write-back, and count as a requested stop.
A `kill -9` loses every change that was not written back yet.

## Things that must not touch a mounted directory

The encrypted directory belongs to the mount while it is mounted.
A second mount of the same directory is refused.
Do not run `encrypt --in-place` or `decrypt` on it, and do not edit its files by hand.
A change made behind the mount's back is invisible to open files and a write-back can overwrite it.

Do not mount the `.enc/` store of a git repository.
Its entries are bound to their paths, so they do not decrypt through the mount, and a file written there would not be bound.

The mountpoint must not be inside the encrypted directory.
The reverse works: an encrypted directory under the mountpoint is hidden while the volume is mounted and comes back after the unmount.

## Locks and logs

File locks never reach the mount on macOS. The NFS client handles them locally.

fuse-t writes `fuse-t.log` and `fuse-t.err` under `~/Library/Logs/fuse-t`.
The log names the mountpoint and is readable by everyone on the machine.
