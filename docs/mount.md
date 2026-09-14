# Work with an encrypted folder

[Back to the main README](../README.md)

A mount lets you open and edit encrypted files in your usual apps. TurboCrypt shows them in a normal folder while keeping the stored copies encrypted.

For example, you might keep encrypted documents on an external drive and open them through `~/Volumes/documents`. Files you save there are encrypted as they're written back to the drive.

## 1. Install the mount support

On macOS, install [fuse-t](https://github.com/macos-fuse-t/fuse-t/releases). It works without a kernel extension or a reboot. On Linux, install your distribution's `fuse3` package, which provides the mount helper TurboCrypt needs.

Once that's installed, you can mount folders you own without running TurboCrypt as root. Mounting is available on Linux and macOS. Ordinary encryption and decryption work without the mount support installed.

## 2. Prepare an encrypted folder

If your files are still readable, encrypt them first:

```bash
turbocrypt encrypt documents/ encrypted-documents/
```

This uses your default key and leaves `documents/` alone. You can choose a key explicitly with `--key secret.key`, just as you would for other file commands.

If you'd like to start with an empty encrypted folder, create one instead:

```bash
mkdir encrypted-documents
```

Choose one of these starting points. The `mount` command opens encrypted files; it doesn't encrypt an existing folder of readable files for you.

## 3. Mount it

Create an empty folder where you want to work, then mount the encrypted folder there:

```bash
mkdir -p ~/Volumes/documents
turbocrypt mount --daemon encrypted-documents/ ~/Volumes/documents
```

The encrypted folder comes first. The second path is where the readable files appear while the mount is open. Keep these folders separate, with neither inside the other.

`--daemon` gives you your terminal prompt back once the folder is mounted. Leave it out if you'd like the command to stay in the terminal so you can watch its messages.

## 4. Open and edit your files

Open `~/Volumes/documents` in your file manager or editor. You can read, change, create, and delete files there as you would in another folder.

Work through this mounted folder while it's open. TurboCrypt keeps open files in memory and writes encrypted versions back when they're saved or closed. Closing a large file can therefore take a little time.

The stored files use the same format as `turbocrypt encrypt`. After unmounting, you can also use `decrypt`, `verify`, or `list` on `encrypted-documents/`.

## 5. Unmount when you're done

Save your work, close any open files, then run:

```bash
turbocrypt unmount ~/Volumes/documents
```

The readable view disappears, and the encrypted files stay in `encrypted-documents/`. If TurboCrypt says a file is still open, close the app using it and try again.

## Open a folder with encrypted names

If you used `--encrypted-filenames` when creating the folder, use it again when mounting:

```bash
turbocrypt mount --daemon --encrypted-filenames encrypted-documents/ ~/Volumes/documents
```

Likewise, use `--enc-suffix` if your encrypted files were written with that option. If you used a context, pass the same `--context` value, too.

Your [saved filename setting](configuration.md#encrypt-filenames-by-default) applies to mounts. Exclusions don't: a mount shows the whole encrypted folder.

## Browse without changing anything

For a backup you only want to read, mount it with `--read-only`:

```bash
turbocrypt mount --daemon --read-only encrypted-documents/ ~/Volumes/documents
```

You can open files and copy them elsewhere, but apps won't be able to save changes to the mounted folder.

## Use remote storage

First, connect your remote storage so it appears as a folder on your computer. Then give TurboCrypt the path to the encrypted folder on it. For example, if a network drive appears at `/Volumes/backup`:

```bash
turbocrypt mount --daemon /Volumes/backup/encrypted-documents/ ~/Volumes/documents
```

TurboCrypt takes a folder path, so the connection to the server needs to be set up separately. Keep that connection available while you work, and unmount TurboCrypt before disconnecting the drive.

## Work with larger files

By default, a mount allows files up to 1 GiB and uses a memory budget of 4 GiB. Since open files are held in memory, opening several large files can reach that budget.

If your computer has enough memory, you can raise both limits. This example allows files up to 2 GiB with an 8 GiB budget:

```bash
turbocrypt mount --daemon \
  --max-file-size 2147483648 \
  --memory-limit 8589934592 \
  encrypted-documents/ ~/Volumes/documents
```

Values are in bytes. The memory budget must be at least three times the file-size limit plus 1 MiB. For files too large to work with comfortably this way, use ordinary `decrypt` and `encrypt` commands instead.

## Know which file operations are supported

The mount handles regular files and folders. Hard links, symbolic links, device files, and extended attributes aren't supported. A copy command such as `cp -p` may warn that it couldn't preserve extended attributes even though it copied the file's contents.

Saving changes replaces the encrypted file. If you've made hard links to that stored file outside the mount, they won't follow the replacement.

By default, only your user can access the mount. `--allow-other` lets other users access it according to the files' permissions. Files owned by another user may be readable but not writable, and creating files for another user requires the mount to run as root. On macOS, group checks only use the caller's primary group.

## Recover a file that couldn't be saved

If the disk fills up or remote storage disconnects, TurboCrypt reports that it "cannot write back" a file. Reconnect the drive or free up space while the mount is still running, then try saving or closing the file again.

If saving still fails at unmount, TurboCrypt tries to save an encrypted rescue copy and prints its location. You can choose a local rescue folder when mounting, which is useful when the encrypted folder is on a remote drive:

```bash
turbocrypt mount --rescue-dir ~/turbocrypt-rescue encrypted-documents/ ~/Volumes/documents
```

Use `turbocrypt decrypt` with the same key and context to recover the file from the printed path. Rescue copies also need free space, so check the messages before assuming the file was saved.

For other mount problems, see [Troubleshooting](troubleshooting.md#mounting-folders). To see the options your installed version accepts, run `turbocrypt mount --help`.
