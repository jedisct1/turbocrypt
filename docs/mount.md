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

Windows is not supported.

## Limitations

- A file larger than `--max-file-size` cannot be opened. The default is 1 GiB.
- All open files together must fit in `--memory-limit`. The default is 4 GiB.
- Closing a large file takes the time of one encryption of that file.
- Every write-back replaces the encrypted file. Hard links to it break, and its inode changes.

Filenames map in both directions without any table.

The mount handles plain names, names with the `.enc` suffix, and encrypted names, with the same options as `encrypt`.

## Options

| Option                             | Effect                                                                              |
| ---------------------------------- | ----------------------------------------------------------------------------------- |
| `--key`, `--password`, `--context` | As for every other command. The config default for encrypted filenames applies too  |
| `--encrypted-filenames`            | The encrypted directory has encrypted names                                         |
| `--enc-suffix`                     | Files in the encrypted directory carry `.enc`, the view does not                    |
| `--read-only`                      | Every change is refused with EROFS                                                  |
| `--daemon`                         | Return once the volume is mounted                                                   |
| `--single-thread`                  | Serve one request at a time, for debugging                                          |
| `--debug`                          | Print libfuse traffic and the mount's own diagnostics                               |
| `--volname <name>`                 | The volume name, by default the name of the mountpoint                              |
| `--allow-other`                    | Serve other users, with POSIX permission checks done by the mount                   |
| `--max-file-size <n>`              | Largest file that can be opened, in bytes                                           |
| `--memory-limit <n>`               | Budget for all open files, in bytes. At least three times the file limit plus 1 MiB |
| `--rescue-dir <dir>`               | Where files that could not be written back go at unmount                            |
| `--force`                          | Skip the key check on the first file                                                |
| `-o <option>`                      | A libfuse or fuse-t option, may be repeated                                         |

`--exclude` is not accepted. The view shows the whole directory.

## Permissions

The mount serves its own user only.

`--allow-other` serves everyone, and the mount then applies the usual POSIX rules itself: the mode bits, the owner, the group and the sticky bit.

On macOS only the primary group of the caller counts, because fuse-t gives no list of supplementary groups.

A file or directory that another user creates gets that user as its owner.

Only a mount that runs as root can give it, so another user's create gets EPERM otherwise.

A file is writable through the mount only when a new file could get the same owner and group.

A file that belongs to someone else can be read but not written, and the mount prints why.

Creation modes follow the umask of the program that creates the file, once.

## What is hidden

The view shows regular files and directories.

Symbolic links, FIFOs, sockets and devices in the encrypted directory are absent and answer ENOENT.

Names that do not decode in encrypted-name mode are absent too.

So are files without `.enc` in suffix mode, and temporary files of the form `.tc-<16 hex digits>.tmp`.
`list` still shows everything.

In plain-name mode a file with that name cannot be created through the mount.

A temporary file left by a crash stays hidden.

Remove them with:

```bash
find encrypted/ -name '.tc-*.tmp' -delete
```

A directory that holds only hidden entries is not empty on disk, so `rmdir` refuses it.

## Unsupported operations

Hard links, symbolic links, device nodes and extended attributes answer `ENOTSUP`.

`cp -p` warns about extended attributes and copies the rest.

## Failures and the exit status

The exit status of a foreground mount:

| Status | Meaning                                                                |
| ------ | ---------------------------------------------------------------------- |
| 0      | A requested unmount, with no failure during the session                |
| 1      | A setup error, the mount never happened                                |
| 2      | The volume is gone but at least one file could not be written back     |
| 3      | The session ended without an unmount request, or a failure was counted |

A daemonized mount reports only through stderr and the rescue directory.

Stop a mount with `turbocrypt unmount`, `umount` or `diskutil unmount`.

## Locks and logs

File locks never reach the mount on macOS. The NFS client handles them locally.

fuse-t writes `fuse-t.log` and `fuse-t.err` under `~/Library/Logs/fuse-t`.
The log names the mountpoint and is readable by everyone on the machine.
