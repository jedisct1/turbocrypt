# Everyday tasks

[Back to the main README](../README.md)

These examples walk through a few common jobs. If this is your first time using TurboCrypt, start with [the setup guide](getting-started.md).

## Send someone an encrypted file

Create a key for the files you want to share, then encrypt your document with it:

```bash
turbocrypt keygen --password shared.key
turbocrypt encrypt --key shared.key report.pdf report.pdf.enc
```

Send `report.pdf.enc` to the recipient, and share `shared.key` and its password through a separate trusted channel. Anyone with that key and password can open every file encrypted with the key, so use a separate key if you don't want to share access to your other files.

Once the recipient has TurboCrypt installed, they can restore the document with:

```bash
turbocrypt decrypt --key shared.key report.pdf.enc report.pdf
```

TurboCrypt will ask for the key's password. The recipient doesn't need to save this key as their default.

## Back up a project folder

Suppose your project is in `project/`, and you want a copy without its Git history or build logs. First, preview the job:

```bash
turbocrypt encrypt --dry-run \
  --exclude ".git/" \
  --exclude "*.log" \
  project/ encrypted-project/
```

Check the reported file count and size, then run the same command without `--dry-run`:

```bash
turbocrypt encrypt \
  --exclude ".git/" \
  --exclude "*.log" \
  project/ encrypted-project/
```

Verify the result before copying `encrypted-project/` to your backup drive:

```bash
turbocrypt verify encrypted-project/
```

Keep a copy of the key somewhere separate from that drive. If the filenames should also be private, see [how to encrypt names](usage.md#hide-file-and-folder-names).

## Restore a backup without replacing your current files

Choose a new destination for the restored files:

```bash
turbocrypt decrypt --key backup.key encrypted-project/ restored-project/
```

Now open the files in `restored-project/` and compare them with the ones you're working on. Copy back only what you need.

Use the same `--context`, `--encrypted-filenames`, or `--enc-suffix` options you used when creating the backup. If you aren't sure which key belongs to it, try a quick check first:

```bash
turbocrypt verify --quick --key backup.key encrypted-project/
```

A successful quick check confirms that the headers match the key. Run a full `verify` if you also want to check the stored contents.

## Move encrypted files to another computer

Install TurboCrypt on the new computer, then copy over your encrypted folder and transfer the key separately. Ordinary encrypted files can be moved between supported systems without converting them.

Save the key as your default on the new computer, then restore your files:

```bash
turbocrypt config set-key backup.key
turbocrypt decrypt encrypted-documents/ restored-documents/
```

If you used encrypted filenames or a context, use the same options here. For a Git repository, clone it normally and follow [the unlock steps](git.md#restore-private-files-in-another-clone).

## Use a different key for one job

You can keep your everyday default and choose a key just for a work folder:

```bash
turbocrypt encrypt --key work.key work-documents/ encrypted-work/
turbocrypt verify --key work.key encrypted-work/
```

Later, use `--key work.key` again when decrypting. This doesn't change your saved default or the keys used by existing Git checkouts.

## Start a container for a mounted folder

If you mostly work through a mounted folder, and your files are large or change often, a container suits that better than a folder of ordinary encrypted files. Create an empty one with the key you'll mount it with, then fill it through the mounted view:

```bash
turbocrypt init --key work.key encrypted-container/
mkdir -p ~/Volumes/work
turbocrypt mount --daemon --key work.key encrypted-container/ ~/Volumes/work
cp -R work-documents/. ~/Volumes/work/
turbocrypt unmount ~/Volumes/work
```

`init` needs a missing or empty folder; it never converts existing files. The ordinary `encrypt`, `decrypt`, `verify` and `list` commands don't read containers, so keep using the mount to get files in and out. The [mount guide](mount.md#use-a-container-for-random-access) explains the differences.

## Find help for your installed version

The built-in help lists the commands and options your copy supports:

```bash
turbocrypt --help
turbocrypt git help
turbocrypt mount --help
turbocrypt init --help
```

If you need to report a problem, include the output of `turbocrypt version` along with the command you ran and the error message. The [troubleshooting guide](troubleshooting.md) covers the most common problems.
