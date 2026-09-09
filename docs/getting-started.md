# Getting started

[Back to the main README](../README.md)

## Installation

Linux, macOS and Windows binaries are available from the
[releases page](https://github.com/jedisct1/turbocrypt/releases), so the
quickest installation is to download the archive for your system.

For the best performance, build locally instead. Zig can then optimize the
binary for the machine it will run on. You will need the master version of
[Zig](https://ziglang.org/download/):

```bash
git clone https://github.com/jedisct1/turbocrypt.git
cd turbocrypt
zig build -Doptimize=ReleaseFast
```

The binary is written to `zig-out/bin/turbocrypt`.

## Quick start

### Step 1: Generate a key

First, create the key that will encrypt and decrypt your files:

```bash
turbocrypt keygen secret.key
```

The file contains a random 128-bit key.

Keep a backup somewhere separate, because losing it also means losing access
to the encrypted files. Anyone who gets a copy of it can decrypt them.

### Step 2: Set the default key

Next, copy the key into the configuration so that you do not need to pass
`--key` to every command:

```bash
turbocrypt config set-key secret.key
```

From this point on, TurboCrypt will use the stored copy unless a command
selects another key explicitly.

Moving or deleting `secret.key` does not change that copy.

### Step 3: Encrypt files

Once the key is configured, the same command works on a file or a whole
directory:

```bash
# A single file
turbocrypt encrypt document.pdf document.pdf.enc

# A directory tree
turbocrypt encrypt my-documents/ encrypted-documents/
```

### Step 4: Verify the result

Before deleting the original, authenticate the encrypted copy from beginning
to end:

```bash
turbocrypt verify encrypted-documents/
```

For a faster key check, `verify --quick` authenticates only the header.

It does not detect damage elsewhere in the file.

```bash
turbocrypt verify --quick encrypted-documents/
```

### Step 5: Decrypt files

Finally, supply the encrypted source and the destination for the plaintext.
As with encryption, the source may be a file or a directory:

```bash
# A single file
turbocrypt decrypt document.pdf.enc document.pdf

# A directory tree
turbocrypt decrypt encrypted-documents/ my-documents/
```

Continue with the [usage guide](usage.md) for common workflows and options.
