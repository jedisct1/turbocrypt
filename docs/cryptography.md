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

## Move encrypted files or share them

Files created with ordinary `encrypt` commands can be moved or renamed without encrypting them again. Encrypting the same contents twice normally produces different encrypted files, so different results don't by themselves mean anything went wrong.

Private files in Git have an extra check that ties each encrypted copy to its original path. Use `turbocrypt git` commands to manage those files instead of moving entries around inside `.enc/`.

Anyone you give the key to can decrypt the files protected by it. Before sharing a key, check which other files and older backups use it, too.
