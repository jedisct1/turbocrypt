# Keep your files recoverable

[Back to the main README](../README.md)

A useful encrypted backup needs two things: a working copy of your files and the key that opens them. Check both before you depend on it.

## Keep a separate copy of your key

Create keys with `turbocrypt keygen`, then back them up somewhere separate from the encrypted files.

If your only key is on the same drive as the backup, losing that drive means losing both.

A saved default key is another copy on your computer. Keep a separate key file somewhere you can reach if that computer is lost.

If you protect the key with a password, keep a reliable way to recover that password, too.

## Try restoring before you need to

After making an encrypted backup, check it:

```bash
turbocrypt verify encrypted-documents/
```

Then restore it to a new folder:

```bash
turbocrypt decrypt encrypted-documents/ restored-documents/
```

Open some of the restored files and compare the folder with what you meant to save, including the files and subfolders you expected to include.

Keep your originals until you're satisfied with the result. Repeat this check after moving a backup to another drive or changing how you store it.

## Write down the settings needed to restore

Along with the backup, keep a note of which key to use and whether you used `--encrypted-filenames`, `--enc-suffix`, or a context. You'll need the same settings when restoring it.

A context has to match exactly. If you intend it to be secret, store it with your other secrets rather than in a public script or shell command history.

## Keep track of key copies

Changing a key file's password doesn't change the encryption key inside it. Update the saved default afterward with `turbocrypt config set-key`, and remember that older copies of the key still have their previous password protection.

Someone who already has the key can still read files protected by it. To protect future files from that person, use a new key.

## Take care with in-place jobs

`--in-place` replaces the originals, so make a separate backup first. Each file is replaced only after its new copy has been written, but the whole folder isn't changed in one operation.

An interrupted job can leave a mixture of readable and encrypted files.

Manage any older readable copies in snapshots and backups separately.

## Save your work before disconnecting storage

For a mounted folder, save and close your files, then unmount it before unplugging a drive or disconnecting remote storage.

If a save fails, keep the mount running while you fix the problem. The [mount guide](mount.md#recover-a-file-that-couldnt-be-saved) explains rescue copies.

For private files in Git, run `turbocrypt git encrypt` and commit before cleaning a checkout.

Avoid `git stash --all`, which saves readable private files in local Git storage. See [the Git recovery steps](git.md#recover-files-after-a-cleanup).
