# Encrypt files and folders

[Back to the main README](../README.md)

Once you've [created a key](getting-started.md), the same commands work on a single file or a whole folder. The examples here use your saved default key. Add `--key secret.key` if you'd like to choose a different one.

## Make an encrypted copy

Give TurboCrypt the source first, followed by the destination:

```bash
# Encrypt one document
turbocrypt encrypt report.pdf report.pdf.enc

# Encrypt a folder and everything inside it
turbocrypt encrypt documents/ encrypted-documents/
```

The originals stay in place. Choose a separate destination outside the source folder, and keep your key outside both folders.

To restore the folder later, reverse the direction and choose a new destination:

```bash
turbocrypt decrypt encrypted-documents/ restored-documents/
```

Files at the destination with matching names are replaced without a prompt. Use a new destination folder when you want to keep an earlier copy.

## Hide file and folder names

Encryption protects file contents by default. If names such as `tax-return.pdf` should also stay private, add `--encrypted-filenames`:

```bash
turbocrypt encrypt --encrypted-filenames documents/ encrypted-documents/
```

Use the same option when restoring them:

```bash
turbocrypt decrypt --encrypted-filenames encrypted-documents/ restored-documents/
```

The names in the encrypted folder will look like random text. People can still see the folder structure, the number of files, and their sizes. See [what encryption protects](cryptography.md) for more on that.

## Leave out files you don't need

For a project backup, you might want to skip logs and downloaded dependencies:

```bash
turbocrypt encrypt \
  --exclude "*.log" \
  --exclude "node_modules/" \
  project/ encrypted-project/
```

Repeat `--exclude` for each pattern, and keep the quotes so your shell doesn't expand it first. Add `--ignore-symlinks` if you want to skip symbolic links as well.

Before a large job, try the command with `--dry-run`. It counts the files and their total size without writing anything:

```bash
turbocrypt encrypt --dry-run \
  --exclude "*.log" \
  --exclude "node_modules/" \
  project/ encrypted-project/
```

Once the totals look right, run it again without `--dry-run`. You can use dry runs with `decrypt` and `verify`, too.

If you often skip the same files, [save the exclusions in your settings](configuration.md#skip-the-same-files-each-time). Any `--exclude` options on a command replace that saved list for the run, so include every pattern you need.

## Check a backup

Run a full check after encrypting files or copying them to another drive:

```bash
turbocrypt verify encrypted-documents/
```

This checks every file's contents with your key. It doesn't write readable copies, and it doesn't compare the backup with your original folder. To check that everything you meant to save is there, restore to a separate folder and compare it with the source.

If you only need to check whether you have the right key, use:

```bash
turbocrypt verify --quick encrypted-documents/
```

The quick check reads just the beginning of each file. It won't detect damage elsewhere in the file, so use the full check before relying on a backup.

## See what's in an encrypted folder

To list files without decrypting their contents, run:

```bash
turbocrypt list encrypted-documents/
```

If you encrypted the names, add the option to show their original names:

```bash
turbocrypt list --encrypted-filenames encrypted-documents/
```

The listing includes file sizes and a total. Those are the sizes of the encrypted files. Reading encrypted names requires the same key and context you used to create them.

## Add a password to your key

You can protect an existing key file with a password:

```bash
turbocrypt change-password secret.key
```

Run the same command to change an existing password. TurboCrypt asks for the current password first, then the new one. It detects protected keys automatically when you use them.

To remove the password later, run:

```bash
turbocrypt change-password --remove-password secret.key
```

These commands change the key file's password protection. Your encryption key stays the same, so you don't need to encrypt your files again.

If you've saved this key as your default, update that copy afterward:

```bash
turbocrypt config set-key secret.key
```

Other copies of the key still have their old protection. That includes an unlocked key saved by the [Git integration](git.md#the-checkouts-key).

## Use a context for a separate collection

A context is an extra label that changes how TurboCrypt uses your key. For example, you can use `work-archive` for one collection:

```bash
turbocrypt encrypt --context "work-archive" documents/ encrypted-documents/
```

You'll need that exact label whenever you decrypt, verify, or mount those files:

```bash
turbocrypt decrypt --context "work-archive" encrypted-documents/ restored-documents/
```

Keep a record of it with your backup instructions. The label isn't stored in the encrypted files, and a missing or mistyped context makes the key check fail.

For everyday use, it's fine to leave contexts out. They don't replace a strong password or give different people separate access to files encrypted with a shared key.

## Mark encrypted files with .enc

If you want to recognize encrypted files by their extension, use `--enc-suffix`:

```bash
turbocrypt encrypt --enc-suffix documents/ encrypted-documents/
turbocrypt decrypt --enc-suffix encrypted-documents/ restored-documents/
```

On encryption, this adds `.enc` to filenames. On decryption, it removes the suffix and skips files that don't have it.

## Replace files in place

If you want encrypted files to take the place of the originals, make a separate backup first, then use:

```bash
turbocrypt encrypt --in-place documents/
```

To replace them with readable files again:

```bash
turbocrypt decrypt --in-place documents/
```

TurboCrypt writes each replacement to a temporary file before putting it in place. A folder is still processed one file at a time, so an interrupted job can leave a mix of encrypted and readable files.

In-place processing can't be combined with encrypted filenames. It also doesn't securely erase older copies that may remain in backups, snapshots, or free disk space.
