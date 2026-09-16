# Understand what encryption protects

[Back to the main README](../README.md)

TurboCrypt chooses the encryption settings for you. Your main choices are which key to use, whether to hide filenames, and where to keep the copies you need for recovery.

## Protect the contents of a file

When you encrypt a file, someone without the key can't read its contents. TurboCrypt also checks for changes to the encrypted contents when you decrypt or verify it.

If that check fails, it reports an error instead of saving the damaged result as a restored file.

Keep a separate backup so you can recover from accidental changes, damaged storage, or deleted files.

## Decide whether names should be private

By default, TurboCrypt leaves filenames readable. That can be convenient for a backup, but a name like `acquisition-plans.pdf` may reveal more than you'd like.

Use `--encrypted-filenames` to hide file and folder names as well:

```bash
turbocrypt encrypt --encrypted-filenames documents/ encrypted-documents/
```

Filename encryption is deterministic: the same name produces the same encrypted name under the same key and context. File sizes and folder structure remain visible.

The [Git guide](git.md#what-stays-visible) describes what remains visible in a public repository.

## Put a password on a key you carry or share

A key file contains the secret needed to open your files. Adding a password protects that key file if someone gets a copy of it:

```bash
turbocrypt change-password secret.key
```

Use a long, unique password. TurboCrypt uses Argon2id to make password guesses more expensive.

Changing the password updates the key file's protection while keeping the underlying encryption key the same.

See [how to keep track of key copies](safety.md#keep-track-of-key-copies).

## Use a full check when the contents matter

A normal verification checks the complete encrypted files:

```bash
turbocrypt verify encrypted-documents/
```

`verify --quick` checks the file headers to confirm the key and context. Use the full check to verify the contents.

To check a backup against your originals, restore it to a separate folder and compare what you get.

These commands check ordinary encrypted files. For a container, mount it and read or copy all the files through the mounted view to check their contents.

The mount authenticates each chunk as it's read.

## Know when a context is useful

A context lets you use the same key file with a different label for a collection. Changing the label changes the encryption result, so you must remember the exact label to open those files later.

Use contexts to separate collections, and separate keys when different people should be able to read different files.

If you choose a context, keep a record of it. The [usage guide](usage.md#use-a-context-for-a-separate-collection) shows how to use it in commands.

## How a container encrypts files

A [container](mount.md#use-a-container-for-random-access) encrypts each file in chunks of 16 KiB, so a mount can read and write a small part of a large file.

Each file gets a random identifier used to derive its own keys. Each chunk is encrypted with AEGIS-128X2 and a fresh random nonce, with the file identifier and the chunk's position and size bound to it.

The container's key comes from your key file and context through a derivation separate from ordinary file encryption.

When mounting, TurboCrypt authenticates the marker file `.turbocrypt-raf` at the root to check the key, context, and filename settings.

The marker uses AEGISMAC-128X2 with a separate derived key and includes a random value that makes independently created markers different.

File headers record the exact plaintext sizes, and files and folders keep their normal permissions.

Keep backups of the container, including its marker, as described in the [mount guide](mount.md#use-a-container-for-random-access).

## Move encrypted files or share them

Files created with ordinary `encrypt` commands can be moved or renamed without encrypting them again.

Each encryption uses a fresh random nonce, so encrypting the same contents twice normally produces different encrypted files.

Private files in Git have an extra check that ties each encrypted copy to its original path.

Use `turbocrypt git` commands to manage those files instead of moving entries around inside `.enc/`.

Anyone you give the key to can decrypt the files protected by it. Before sharing a key, check which other files and older backups use it, too.
