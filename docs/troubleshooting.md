# Troubleshooting

[Back to the main README](../README.md)

## Encryption and decryption

### "Wrong decryption key, wrong context, or corrupted file header"

TurboCrypt cannot distinguish a wrong key or context from a foreign or damaged
header. Check the key and use exactly the context supplied during encryption.

### "Authentication failed" during decryption

The header was accepted, but the encrypted contents did not authenticate. Get
another copy of the file if one is available, because TurboCrypt will not
produce unauthenticated output.

### "Access denied" errors with large files

TurboCrypt memory-maps files larger than 1 MiB. If only large files fail, check
that the current user can read the source and write both the destination
directory and its existing file, if any.

### Performance is slow

Try fewer threads for a tree of small files; `--threads 2` or `--threads 4`
can beat a large worker count. For large files, storage speed is usually the
limit.

### Out of memory errors

Reduce the per-file buffer, for example with `--buffer-size 1048576`.

## Git integration

### "nothing to commit" after editing a private file

Git decides whether there is something to commit before it runs the pre-commit
hook, and the hook is what stages the encrypted file. Run `git commit` again.
With `git commit -a`, run `turbocrypt git encrypt` first.

### "commit refused, private files are tracked by git"

A file listed in `.gitprivate` is also tracked in clear. Committing it would
publish it. Run `git rm --cached -- <path>` and commit. Earlier commits still
contain the file in clear.

### A merge conflict on a private file

Git cannot merge two encrypted versions. It leaves the entry unmerged and
keeps your version in the working tree. Edit the plain file until it holds what
you want, then run `turbocrypt git encrypt --force <path>` and commit. To look
at the other side first, run `git checkout --theirs -- .enc/<name>` followed by
`turbocrypt git decrypt --force <path>`.

### "entry cannot be committed as it is"

A file in `.enc/` does not decrypt: it was altered, or it came from a different
key. Commits stop until it is fixed. When the plain file is present and
correct, `turbocrypt git encrypt --force <path>` writes a fresh entry from it.
Otherwise `turbocrypt git rm <path>` drops the entry.

### "this repository already has a different key"

`init` and `unlock` keep the key bound to the repository, whatever the default
key or `TURBOCRYPT_KEY_FILE` says. To replace it, run the same command again
with `--force`. `unlock` needs a key that already has files in the store.
`init` also takes a key that is new to the repository. The `.gitprivate` list
stays, so the files it names become that key's private files at the next
commit. Neither command rotates a key.

### "the store has no files for" a key

`unlock` only takes a key that already has files in the store, since a wrong
key looks the same as a new one. A key that is new to the repository joins with
`turbocrypt git init --key <key-file>`.

### Hooks do not run from a GUI client

GUI clients run hooks with a minimal PATH. The installed hooks use the absolute
path of the `turbocrypt` binary recorded at `init` time. When the binary moved,
run `turbocrypt git init` again to refresh the hooks.
