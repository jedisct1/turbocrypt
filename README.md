<p align="center">
  <img src=".media/logo.png" width="400" alt="TurboCrypt Logo" />
</p>

# TurboCrypt

A universal file encryption tool.

TurboCrypt encrypts anything from a single document to a whole directory of backups. You can also use it to open encrypted folders as local volumes or keep private files in a public Git repository.

- **Easy to use:** create a key, then encrypt and decrypt files with a single command.
- **Small and portable:** written in Zig and runs on Linux, macOS, Windows, and BSD.
- **Fast:** processes files in parallel, whether you're working with a few documents or a large directory tree.
- **Modern cryptography:** built on Argon2, AEGIS, HCTR2, and TurboSHAKE, with no insecure options.
- **Encrypted folders you can work in:** mount a folder and use your usual apps to read and edit its files. The encrypted folder can be on your own disk or on remote storage you've connected to your computer.
- **Private files in Git alongside public code:** commit encrypted notes, scripts, or unfinished work to Git, and optionally share the key with other maintainers who need access.

## Install TurboCrypt

Download the archive for your system from the [releases page](https://github.com/jedisct1/turbocrypt/releases), extract it, and put `turbocrypt` somewhere on your `PATH`.

If you'd rather build it yourself, install the master version of [Zig](https://ziglang.org/download/), then run:

```bash
git clone https://github.com/jedisct1/turbocrypt.git
cd turbocrypt
zig build -Doptimize=ReleaseFast
```

You'll find the program in `zig-out/bin/`. The [getting started guide](docs/getting-started.md) walks you through installation and your first encrypted files.

## Encrypt your first folder

First, create a key and save it as your default:

```bash
turbocrypt keygen secret.key
turbocrypt config set-key secret.key
```

Keep a backup of `secret.key` somewhere separate from your encrypted files. You'll need that key to get them back, and anyone who has it can read them.

Now encrypt a folder, check the encrypted copy, and restore it to a new folder:

```bash
turbocrypt encrypt my-documents/ encrypted-documents/
turbocrypt verify encrypted-documents/
turbocrypt decrypt encrypted-documents/ restored-documents/
```

Your original files stay where they are. The same commands work on individual files, too.

## Open an encrypted folder

On Linux and macOS, you can work with encrypted files through a normal folder:

```bash
mkdir -p ~/Volumes/documents
turbocrypt mount --daemon encrypted-documents/ ~/Volumes/documents
```

Open `~/Volumes/documents` in your editor or file manager. When you're done, close the files and unmount it:

```bash
turbocrypt unmount ~/Volumes/documents
```

This uses FUSE and needs a one-time installation of `fuse3` on Linux or [fuse-t](https://github.com/macos-fuse-t/fuse-t) on macOS. After setup, you can mount your files without running TurboCrypt as root. On macOS, no kernel extension is needed.

For large files that change often, `turbocrypt init` creates a container made for random access. Files in it are read and written in encrypted chunks, so the mount keeps nothing in memory and has no file-size limit:

```bash
turbocrypt init encrypted-container/
turbocrypt mount --daemon encrypted-container/ ~/Volumes/documents
```

See [Work with an encrypted folder](docs/mount.md) for setup, remote folders, file-size limits, and containers.

## Keep maintainer files in Git

From an existing checkout with a default key set, choose the files that should stay private:

```bash
turbocrypt git init
turbocrypt git add NOTES.md ops/
git commit -m "Add maintainer files"
```

You keep editing the files at their usual paths, while Git stores encrypted copies. Other maintainers can restore them with the key; everyone else sees the public project.

The [Git guide](docs/git.md) covers setup, everyday commits, and restoring private files in another clone.

## More things you can do

- [Encrypt files and folders](docs/usage.md): hide filenames, skip files, and check your backups.
- [Everyday tasks](docs/command-reference.md): send a file, restore a backup, or use a different key.
- [Save your preferences](docs/configuration.md): choose a default key and avoid repeating options.
- [Keep your files recoverable](docs/safety.md): back up keys and check that you can restore your data.
- [Understand what encryption protects](docs/cryptography.md): learn what stays private and what others can still see.
- [Fix a problem](docs/troubleshooting.md): get help with file errors, mounts, and Git.
