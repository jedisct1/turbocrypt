# Understand what encryption protects

[Back to the main README](../README.md)

TurboCrypt chooses the encryption settings for you. Your main choices are which key to use, whether to hide filenames, and where to keep the copies you need for recovery.

## Protect the contents of a file

When you encrypt a file, someone without the key can't read its contents. TurboCrypt also checks for changes to the encrypted contents when you decrypt or verify it. If that check fails, it reports an error instead of saving the damaged result as a restored file.

That doesn't make an encrypted copy a substitute for a backup. Someone can still delete it, damage it, or replace it with an older encrypted version. Keep another copy when you need to recover from those situations.

## Decide whether names should be private

By default, TurboCrypt leaves filenames readable. That can be convenient for a backup, but a name like `acquisition-plans.pdf` may reveal more than you'd like.

Use `--encrypted-filenames` to hide file and folder names as well:

```bash
turbocrypt encrypt --encrypted-filenames documents/ encrypted-documents/
```

People can still see how many files there are, their sizes, and the folder structure. Repeated names also produce the same encrypted name under the same key and context, so those repetitions remain visible. Longer encrypted names reveal information about the original name's length.

Keep these limits in mind when deciding where to store or share a folder. The [Git guide](git.md#what-stays-visible) describes what remains visible in a public repository.

## Put a password on a key you carry or share

A key file contains the secret needed to open your files. Adding a password protects that key file if someone gets a copy of it:

```bash
turbocrypt change-password secret.key
```

Use a long, unique password. Someone with a protected key file can try guesses on their own computer, without TurboCrypt being able to limit their attempts. Password protection makes those guesses more expensive, but a short or reused password is still a weak point.

The password protects the key file; it doesn't replace the key. Changing it leaves the underlying encryption key unchanged, and other copies of that key remain usable. See [how to keep track of those copies](safety.md#keep-track-of-key-copies).

## Use a full check when the contents matter

A normal verification checks the complete encrypted files:

```bash
turbocrypt verify encrypted-documents/
```

`verify --quick` only checks the beginning of each file. That's useful for checking whether you selected the right key and context, but it doesn't check the rest of the contents.

Neither check compares the backup with your original files or proves that it's the newest copy. For that, restore to a separate folder and compare what you get.

## Know when a context is useful

A context lets you use the same key file with a different label for a collection. Changing the label changes the encryption result, so you must remember the exact label to open those files later.

It's an optional way to separate collections. It isn't a replacement for a password, and it doesn't give people with a shared key different access rights. Use separate keys when different people should be able to read different files.

If you choose a context, keep a record of it. The [usage guide](usage.md#use-a-context-for-a-separate-collection) shows how to use it in commands.

## Understand the limits of a container

A [container](mount.md#use-a-container-for-random-access) encrypts each file in chunks of 16 KiB, so a mount can read and write a small part of a large file. Each chunk is encrypted and checked on its own, with the file and the chunk's position bound to it. Someone without the key can't read the contents, and a changed or swapped chunk is detected when it's read. The container's key comes from the same key file and context as ordinary files, through a separate derivation, and a wrong key or context is refused when the container is mounted, even if it's empty. The check is the marker file `.turbocrypt-raf` at the root. It holds the filename settings and a random value, authenticated with AEGIS-128X2-MAC under a second derived key. Only the right key and context pass that check. The random value keeps two containers of one key from looking alike.

Some things an ordinary encrypted file gives you are different here:

- Chunks are checked one by one, not the file as a whole. Someone who can write to the stored files can put back an older version of one chunk, or of one whole file, without the mount noticing. A container doesn't protect against being rolled back to an earlier state; keep backups for that.
- A write updates the stored file in place. A write cut short by a full disk or a lost connection can leave that chunk unreadable, as [the mount guide explains](mount.md#know-what-happens-when-a-write-fails). An ordinary mount replaces the whole file at once and keeps the old copy until then.
- Like ordinary encrypted folders, a container reveals the number of files, their approximate sizes, and the folder structure. Sizes are rounded up to the chunk, and every change to a chunk shows as a change of the stored file.

Containers inside containers aren't supported. A mount of the outer one decrypts the files of the inner one too when both were created with the same key and context: the key is what protects the files, not the folder they're in. Files and folders inside a container keep their normal permissions.

## Move encrypted files or share them

Files created with ordinary `encrypt` commands can be moved or renamed without encrypting them again. Encrypting the same contents twice normally produces different encrypted files, so different results don't by themselves mean anything went wrong.

Private files in Git have an extra check that ties each encrypted copy to its original path. Use `turbocrypt git` commands to manage those files instead of moving entries around inside `.enc/`.

Anyone you give the key to can decrypt the files protected by it. Before sharing a key, check which other files and older backups use it, too.
