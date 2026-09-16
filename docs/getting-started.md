# Get started with TurboCrypt

[Back to the main README](../README.md)

This guide takes you from installing TurboCrypt to restoring your first encrypted folder. Start with a few files you can experiment with.

## 1. Install TurboCrypt

Download the archive for your system from the [releases page](https://github.com/jedisct1/turbocrypt/releases) and extract it.

Put `turbocrypt` in a directory on your `PATH` so you can run it from any folder. On Windows, the program is called `turbocrypt.exe`.

Then open a terminal and check that it runs:

```bash
turbocrypt version
```

If you haven't added it to your `PATH` yet, you can run `./turbocrypt` from the directory where you extracted it. In Windows PowerShell, use `.\turbocrypt.exe`.

### Build it yourself

To build from source, install the master version of [Zig](https://ziglang.org/download/), then run:

```bash
git clone https://github.com/jedisct1/turbocrypt.git
cd turbocrypt
zig build -Doptimize=ReleaseFast
```

The program is written to `zig-out/bin/`. Add that directory to your `PATH`, or use the full path to the program in the examples below.

## 2. Create a key

TurboCrypt uses a key file to encrypt and decrypt your files. Create one now:

```bash
turbocrypt keygen secret.key
```

Save this key outside the folder you're about to encrypt, and keep a backup somewhere separate. If you lose every copy, you won't be able to recover your encrypted files.

Anyone with the key can read files encrypted with it. If you'd like a password on the key file as well, use `turbocrypt keygen --password secret.key` when creating it.

TurboCrypt will ask for that password whenever it needs to open the key.

## 3. Save your default key

To avoid typing the key's path each time, run:

```bash
turbocrypt config set-key secret.key
```

TurboCrypt saves a copy in your settings. Moving the original key file later won't affect that copy. If you used a password, the saved copy keeps its password protection.

You can also choose a key for an individual command with `--key secret.key`. The [settings guide](configuration.md#choose-which-key-to-use) explains how this works when you have more than one key.

## 4. Encrypt a folder

Choose a folder with a few files in it. In this example, it's called `my-documents`:

```bash
turbocrypt encrypt my-documents/ encrypted-documents/
```

TurboCrypt creates the encrypted copies in `encrypted-documents/` and leaves the originals alone. Keep the output folder outside the source folder.

To encrypt just one file, give the command two filenames instead:

```bash
turbocrypt encrypt document.pdf document.pdf.enc
```

By default, folder and file names stay readable. You can [encrypt those too](usage.md#hide-file-and-folder-names).

## 5. Check the encrypted copy

Before relying on it, check that TurboCrypt can read and verify every encrypted file:

```bash
turbocrypt verify encrypted-documents/
```

This checks the full contents without saving decrypted copies. If anything is damaged or the key is wrong, TurboCrypt reports an error.

## 6. Restore your files

Decrypt into a new folder so you can compare the result with your originals:

```bash
turbocrypt decrypt encrypted-documents/ restored-documents/
```

Open a few files in `restored-documents/` and make sure they're what you expect. For the single file from earlier, use:

```bash
turbocrypt decrypt document.pdf.enc restored-document.pdf
```

Now you can [encrypt a larger collection](usage.md), [work in a mounted folder](mount.md), or [keep private files in Git](git.md).
