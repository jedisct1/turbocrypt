# Fix a problem

[Back to the main README](../README.md)

Start with the message TurboCrypt printed. The sections below explain the common ones and what to try next.

## Encrypting and restoring files

### "Wrong decryption key, wrong context, or corrupted file header"

First, check that you're using the key that encrypted the file. If you have several keys, choose one explicitly:

```bash
turbocrypt verify --quick --key backup.key encrypted-documents/
```

If you used a context, add the exact same `--context` value. A key chosen through `TURBOCRYPT_KEY_FILE` takes priority over your saved default, which can be easy to overlook in an old terminal session.

If the key and context are right, the file may be damaged or may not be a TurboCrypt file. Try another copy. This error alone can't tell you which of those causes applies.

### "Authentication failed" during decryption

TurboCrypt accepted the beginning of the file, but the contents failed its check. It won't save them as a successfully restored file.

Keep your original and try another encrypted copy, if you have one. Passing `verify --quick` doesn't rule out this problem, because that command doesn't check the full contents.

### "Access denied" when processing a file

Check that you can read the source and write to the destination folder. If an output file already exists, check its permissions, too.

For files on an external or network drive, make sure the drive is connected and writable.

### Filenames still look encrypted

Use `--encrypted-filenames` when decrypting a folder whose names were encrypted:

```bash
turbocrypt decrypt --encrypted-filenames encrypted-documents/ restored-documents/
```

Use the same key and context as before. If you're working with ordinary names but have filename encryption saved as a default, turn it off with `turbocrypt config set-encrypted-filenames false`.

### Some files are missing from the result

Check your exclusions with `turbocrypt config show`, then try the job with `--dry-run` to see its file count and total size. If you've supplied `--exclude` on the command line, those patterns replace the saved list.

Also check whether you're using `--enc-suffix` during decryption. That option skips files whose names don't end in `.enc`.

### File processing is slow or runs out of memory

Try a smaller worker count on a representative folder and compare the time it takes:

```bash
turbocrypt encrypt --threads 2 documents/ encrypted-documents/
```

Reducing the worker count also means fewer files are processed at once, which can help with memory use. If necessary, try `--threads 1` and close other apps that use a lot of memory.

Storage speed and the mix of file sizes affect the result, so compare runs on the drive you'll actually use. `turbocrypt bench` runs performance measurements in the current directory if you want to investigate further.

For memory limits while using a mount, see [working with larger files](mount.md#work-with-larger-files).

## Mounting folders

### "fuse-t is not installed"

On macOS, install [fuse-t](https://github.com/macos-fuse-t/fuse-t/releases), then try mounting again. Other TurboCrypt commands work without it.

On Linux, install your distribution's `fuse3` package so the `fusermount3` helper is available.

### The mount command doesn't return to the prompt

By default, the command stays running while the folder is mounted. Leave that terminal open and use another one for your work.

To get the prompt back immediately on future mounts, add `--daemon`. To close the current mount, run this in another terminal:

```bash
turbocrypt unmount ~/Volumes/documents
```

### The mounted folder is empty

Check the argument order: the encrypted folder comes first, and the empty folder where you want to work comes second.

```bash
turbocrypt mount --daemon encrypted-documents/ ~/Volumes/documents
```

If you've reversed them, unmount first. Files that were already in the second folder are hidden while the mount is open; they should become visible again after unmounting.

### "is already mounted by another turbocrypt process"

An encrypted folder can only be opened by one TurboCrypt mount at a time. Close the other mount before starting a new one.

### "is read-only through the mount"

The file may belong to another user or to a group TurboCrypt can't preserve when saving a replacement. Check the ownership of the encrypted file.

If appropriate, change its owner or group, or copy it to a folder you own and work with that copy. Also check that you didn't start the mount with `--read-only`.

### "cannot write back"

The new encrypted copy couldn't be saved. Common causes are a full disk, a disconnected network drive, or changed permissions.

Keep the mount running while you fix the cause, then try saving or closing the file again. TurboCrypt keeps the pending contents in memory and retries when the file is flushed or closed.

At unmount, it tries to save any remaining files as encrypted rescue copies. Read the printed messages to find them, then decrypt a rescue file into a new destination:

```bash
turbocrypt decrypt --key secret.key /path/to/rescued-file.enc recovered-file
```

Replace the source path with the one TurboCrypt printed, and use the same context if you mounted with one. Check the recovered file before moving it back. See [rescue folders](mount.md#recover-a-file-that-couldnt-be-saved) for choosing where these copies go.

### "still in the mount table"

The mount stopped, but the system still thinks the folder is mounted. Close any apps using it, then run:

```bash
umount ~/Volumes/documents
```

### "is a TurboCrypt container" or "is inside the TurboCrypt container"

You ran `encrypt`, `decrypt`, `verify` or `list` on a container, or on a folder inside one. Those commands only handle ordinary encrypted files. Mount the container and copy the files through the mounted view:

```bash
mkdir -p ~/Volumes/container
turbocrypt mount --daemon encrypted-container/ ~/Volumes/container
cp -R ~/Volumes/container/. restored-documents/
turbocrypt unmount ~/Volumes/container
```

A recursive job stops at the first container it meets, so files before that point may already have been processed.

### "is not a valid container descriptor"

The folder holds a file named `.turbocrypt-raf` that isn't a container descriptor. If the folder is an ordinary encrypted folder, that name is reserved: move or delete the file, then mount again. If the folder is a container, its descriptor is damaged; restore that file from a backup of the container.

`--force` doesn't help here. It skips the key check of an ordinary folder, and a container has no such check to skip.

### "wrong key, wrong context, or damaged descriptor" on a container

A container needs the key and the context that were given to `turbocrypt init`. Check both, as for [an ordinary file](#wrong-decryption-key-wrong-context-or-corrupted-file-header). If they're right, the descriptor at the root of the container is damaged; restore it from a backup.

### "was initialized with plain names" or "without the suffix"

You passed `--encrypted-filenames` or `--enc-suffix` to a mount of a container that was created without it. The container remembers its own settings, so drop the option. Your saved filename default is ignored for containers.

### "does not apply to a container" or "not to a container"

`--max-file-size`, `--memory-limit`, `--rescue-dir` and `--force` belong to mounts of ordinary encrypted folders. A container mount keeps no file in memory, has no rescue copies, and checks the key through its descriptor. Leave those options out.

### "A container is mounted at its root"

You asked to mount a folder that lies inside a container. Mount the container itself, at the path the message shows, and find your folder inside the mounted view.

### "is not empty" from init

`init` needs a folder that doesn't exist yet or that is empty. It never converts existing files. If the message names a `.tc-` file, an earlier `init` was interrupted: look at the folder, remove that file yourself, and run `init` again.

### "cannot write" a file in a container

A write to a container file failed, for example because the disk is full or a drive disconnected. Unlike an ordinary mount, a container has no copy in memory to retry from: the chunk being written may be damaged, the open file keeps reporting the error, and a fresh open reads what survived. Free space or reconnect the drive, then check the file and restore it from a backup if part of it is unreadable.

### "is already open under another name"

On a case-insensitive filesystem, such as the default on macOS, `Report.pdf` and `report.pdf` are one file. A container file is open under one spelling at a time, because two open views of one file would write over each other. Close the file in the app that has it open, or use the same spelling.

### "does not authenticate" or "is not a container file" while listing

A file in the container can't be read with the mount's key. Either it's damaged, or it's a file that was copied into the stored folder directly, such as an ordinary encrypted file. The listing shows a size taken from the stored file so that you can still see and remove it, but opening it gives an input/output error. Restore the file from a backup, or remove it.

### File details look out of date on macOS

macOS may cache details such as sizes and modification times for up to a minute. Open the file to check its current contents.

If that gets in the way, unmount and start it again with caching disabled:

```bash
turbocrypt mount --daemon -o noattrcache encrypted-documents/ ~/Volumes/documents
```

For a mount problem you can't explain, try running without `--daemon` and add `--debug` to see its messages. On macOS, fuse-t also writes logs under `~/Library/Logs/fuse-t`. Those logs can include the mount path, so review them before sharing them.

## Git integration

### "nothing to commit" after editing a private file

Git can decide there's nothing to commit before the hook stages the encrypted copies. Update them first, then commit:

```bash
turbocrypt git encrypt
git commit -m "Update private files"
```

This works with `git commit -a`, too, including when you add new files inside a private folder.

### "commit refused, private files are tracked by git"

A file selected as private is also tracked in readable form. Stop tracking that readable copy, then update the encrypted copy:

```bash
git rm --cached -- docs/internal.md
turbocrypt git encrypt
git commit -m "Keep internal notes private from now on"
```

Replace `docs/internal.md` with the path in the error. `--cached` leaves your working file on disk. Earlier commits still contain the readable version.

### A merge conflict on a private file

Git can't combine two encrypted versions of a file. First, save a separate copy of any local edits you need to keep. Then open the readable private file and edit it until it contains the version you want.

To encrypt that version and resolve its entry, run:

```bash
turbocrypt git encrypt --force NOTES.md
```

Check `git status`, resolve any other conflicts, and finish the merge with `git commit`. If you're in a rebase, follow Git's instruction to run `git rebase --continue` instead.

If you want to inspect an encrypted version before deciding, `turbocrypt git show NOTES.md` tells you its path under `.enc/`. After selecting a version of that entry in Git, `turbocrypt git decrypt --force NOTES.md` replaces the readable file with it. Save your local edits first.

### "entry cannot be committed as it is"

An encrypted entry couldn't be read with this checkout's key. It may be damaged or may have been replaced with a file encrypted using another key.

If the readable file is present and correct, recreate its encrypted copy:

```bash
turbocrypt git encrypt --force NOTES.md
```

Otherwise, recover a known-good version from a backup or Git history before committing. If you intended to remove the file from private management, use `turbocrypt git rm NOTES.md`; its readable copy, if present, stays on disk.

### "this repository already has a different key"

The checkout keeps the key it was set up with, even if you've since changed your default or `TURBOCRYPT_KEY_FILE`.

Check that you've selected the intended key. To use a separate collection of private files, it's often easiest to make another clone and unlock it with that collection's key.

If you deliberately want to replace this checkout's key, repeat `init` or `unlock` with `--force`. `unlock` requires a key that already has a store in the repository; `init` also accepts a new key. Existing `.gitprivate` selections remain, so review them before the next commit. This doesn't change the keys used by earlier commits.

### "the store has no files for" a key

If you're restoring existing private files, check that you chose the right key. `unlock` refuses a key that doesn't already have a store in this repository.

If you're adding a new collection with a new key, use:

```bash
turbocrypt git init --key ~/.config/turbocrypt/my.key
```

Then select your files with `turbocrypt git add` as described in [the Git guide](git.md).

### Hooks don't run from a GUI client

The hooks remember the full path to the TurboCrypt program. If you moved or replaced it, run this from the checkout to update the hooks:

```bash
turbocrypt git init
```

This keeps the checkout's existing key and refreshes the paths the hooks use.
