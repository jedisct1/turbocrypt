# Troubleshooting

[Back to the main README](../README.md)

## Encryption and decryption

### "Wrong decryption key, wrong context, or corrupted file header"

TurboCrypt cannot distinguish a wrong key or context from a foreign or damaged header.

Check the key and use exactly the context supplied during encryption.

### "Authentication failed" during decryption

The header was accepted, but the encrypted contents did not authenticate.

Get another copy of the file if one is available, because TurboCrypt will not produce unauthenticated output.

### "Access denied" errors with large files

TurboCrypt memory-maps files larger than 1 MiB.

If only large files fail, check that the current user can read the source and write both the destination directory and its existing file, if any.

### Performance is slow

Try fewer threads for a tree of small files; `--threads 2` or `--threads 4` can beat a large worker count.

For large files, storage speed is usually the limit.

### Out of memory errors

Reduce the per-file buffer, for example with `--buffer-size 1048576`.

## Mount

### "fuse-t is not installed"

On macOS, `mount` loads fuse-t at run time.
Install it from [its releases](https://github.com/macos-fuse-t/fuse-t/releases).
Every other command works without it.
On Linux the library is part of the binary, and only the `fusermount3` helper of the `fuse3` package is needed.

### The command does not return

That is the normal foreground mode.
The volume stays mounted until you run `turbocrypt unmount <mountpoint>` in another terminal, or press Ctrl-C.
Pass `--daemon` to get the prompt back once the volume is up.

### The mounted directory is empty

The arguments are `<encrypted-dir> <mountpoint>`, in that order.
With the order reversed, the mount shows an empty encrypted directory and hides your files under the mountpoint until the unmount.
The mount warns when the mountpoint is not empty.

### "is already mounted by another turbocrypt process"

The encrypted directory belongs to one mount at a time.
Unmount the other one first.

### "is read-only through the mount"

The file belongs to another user, or to a group the mount could not give to a new file.
A write-back creates a new file, so the mount refuses to open the file for writing instead of failing at every close.
Change the owner or the group of the file, or copy it.

### "cannot write back"

The write of the new encrypted file failed, on a full disk for example.
The data stays in memory and the next flush, sync or close retries.
At unmount, what still fails is saved as ciphertext under the rescue directory, and the exit status is 2.
`turbocrypt decrypt` restores such a copy with the same key.

### "still in the mount table"

The fuse-t server died while the mount was up, so the mountpoint kept a stale entry.
Run `umount <mountpoint>`.

### Attributes look old

The NFS client of macOS caches attributes for up to 60 seconds.
Open the file to see the latest content, or mount with `-o noattrcache`.

## Git integration

### "nothing to commit" after editing a private file

Git decides whether there is something to commit before it runs the pre-commit hook, and the hook is what stages the encrypted file.

Update and stage the encrypted copies, then commit:

```bash
turbocrypt git encrypt
git commit -m "Update private files"
```

This also works with `git commit -a`, including when you've added new files inside a private directory.

### "commit refused, private files are tracked by git"

A file listed in `.gitprivate` is also tracked in clear.
Committing it would publish it.

Run `git rm --cached -- <path>` and commit.
Earlier commits still contain the file in clear.

### A merge conflict on a private file

Git cannot merge two encrypted versions.
It leaves the entry unmerged and keeps your version in the working tree.

Edit the plain file until it holds what you want, then run `turbocrypt git encrypt --force <path>` and commit.

To look at the other side first, run `git checkout --theirs -- .enc/<name>` followed by `turbocrypt git decrypt --force <path>`.

### "entry cannot be committed as it is"

A file in `.enc/` does not decrypt: it was altered, or it came from a different key.
Commits stop until it is fixed.

When the plain file is present and correct, `turbocrypt git encrypt --force <path>` writes a fresh entry from it.
Otherwise `turbocrypt git rm <path>` drops the entry.

### "this repository already has a different key"

`init` and `unlock` keep the key bound to the repository, whatever the default key or `TURBOCRYPT_KEY_FILE` says.

To replace it, run the same command again with `--force`.
`unlock` needs a key that already has files in the store.
`init` also takes a key that is new to the repository.

The `.gitprivate` list stays, so the files it names become that key's private files at the next commit.
Neither command rotates a key.

### "the store has no files for" a key

`unlock` only takes a key that already has files in the store, since a wrong key looks the same as a new one.

A key that is new to the repository joins with `turbocrypt git init --key <key-file>`.

### Hooks do not run from a GUI client

GUI clients run hooks with a minimal PATH.
The installed hooks use the absolute path of the `turbocrypt` binary recorded at `init` time.

When the binary moved, run `turbocrypt git init` again to refresh the hooks.
