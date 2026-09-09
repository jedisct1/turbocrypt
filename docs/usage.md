# Usage guide

[Back to the main README](../README.md)

## Password-protected keys

`--password` encrypts the key file itself. TurboCrypt detects protected keys
when it loads them and prompts for the password automatically:

```bash
# Create a protected key
turbocrypt keygen --password protected.key

# The protected key triggers a prompt when it is used
turbocrypt encrypt --key protected.key source/ dest/
```

You can still pass `--password` to force the prompt.

You can also add protection to a plain key, change an existing password, or
remove the password later. In each case, the underlying encryption key stays
the same.

```bash
# Add protection to a plain key
turbocrypt change-password secret.key

# Change the password of a protected key
turbocrypt change-password protected.key

# Remove password protection
turbocrypt change-password --remove-password protected.key
```

## Contexts

A context changes the key used for encryption. As a result, decryption
requires both the same key file and the exact same context. Omitting the
context or supplying another string fails authentication.

```bash
# Encrypt in the "my-secret-phrase" context
turbocrypt encrypt --key my-secret.key --context "my-secret-phrase" documents/ encrypted/

# Use that context again to decrypt
turbocrypt decrypt --key my-secret.key --context "my-secret-phrase" encrypted/ documents/
```

Contexts provide separate encryption domains while reusing a key file. If the
context is meant to remain secret, do not put it in shell history or scripts.

## In-place encryption

```bash
turbocrypt encrypt --key my-secret.key --in-place my-documents/
```

This replaces every source file. TurboCrypt first writes a temporary file and
then renames it over the original, but that does not substitute for a backup.

## Encrypted filenames

Pass `--encrypted-filenames` in both directions:

```bash
# Encrypt both contents and names
turbocrypt encrypt --key my-secret.key --encrypted-filenames source/ dest/

# The option is required again during decryption
turbocrypt decrypt --key my-secret.key --encrypted-filenames dest/ restored/
```

Each component of a path gets an opaque name. However, the directory
structure, file sizes and number of entries remain visible.

## Excluding files

`--exclude` may be repeated. For example, this skips logs and the repository
metadata:

```bash
turbocrypt encrypt --key my-secret.key \
  --exclude "*.log" \
  --exclude ".git/" \
  my-project/ encrypted-project/
```

## Dry runs

Use `--dry-run` to check paths and exclusions before starting the real job. It
prints the file count and total size without modifying anything:

```bash
turbocrypt encrypt --dry-run --key my-secret.key \
  --exclude "*.log" \
  --exclude "node_modules/" \
  large-project/ encrypted-project/
```

The same flag also works with `decrypt` and `verify`.

## Verification

By default, verification authenticates the header and contents without
writing the plaintext. In contrast, quick verification authenticates only the
header. That is enough to check the key and context, but it says nothing about
the integrity of the file contents.

```bash
# Check one file
turbocrypt verify --key my-secret.key encrypted-file.enc

# Check a directory tree
turbocrypt verify --key my-secret.key encrypted-documents/

# Check only the headers
turbocrypt verify --quick --key my-secret.key encrypted-documents/
```

## Listing a directory

`list` reports paths, encrypted sizes and a total without decrypting file
contents. When the names were encrypted, add the key and
`--encrypted-filenames` to make them readable in the listing.

```bash
# Show names as stored
turbocrypt list encrypted-documents/

# Decrypt encrypted names for the listing
turbocrypt list --key my-secret.key --encrypted-filenames encrypted-documents/
```

```text
Listing contents: encrypted-documents/

  report.pdf (2500 bytes)
  memo.doc (1248 bytes)
  photos/sunset.jpg (5347 bytes)
  photos/beach.jpg (4896 bytes)

Total: 4 files, 13.4 KB
```

## Defaults

Keys, thread counts, buffer sizes, exclusions, symlink handling and filename
encryption can be saved in the configuration:

```bash
# Choose the key and worker count
turbocrypt config set-key my-secret.key
turbocrypt config set-threads 8

# Keep these exclusions for later commands
turbocrypt config add-exclude "*.log"
turbocrypt config add-exclude ".git/"

# Review the result
turbocrypt config show
```

Command-line options still take precedence over saved values. See
[Configuration](configuration.md) for storage locations and the full
precedence rules.
