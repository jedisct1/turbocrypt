# Command reference

[Back to the main README](../README.md)

These examples cover the current command set. For the exact usage accepted by
the installed version, run `turbocrypt --help` or `turbocrypt git help`.

## Key management

```bash
# Write a new key
turbocrypt keygen output.key

# Protect a new key with a password
turbocrypt keygen --password output.key

# Add or change password protection
turbocrypt change-password my.key

# Turn a protected key back into a plain key
turbocrypt change-password --remove-password my.key
```

## Encryption

```bash
# Encrypt a file or directory
turbocrypt encrypt --key KEY source dest

# Force a password prompt (protected keys are normally detected)
turbocrypt encrypt --key KEY --password source dest

# Replace the source instead of writing a second copy
turbocrypt encrypt --key KEY --in-place source/

# Encrypt every component of the destination path
turbocrypt encrypt --key KEY --encrypted-filenames source/ dest/

# Skip matching paths; --exclude may be repeated
turbocrypt encrypt --key KEY --exclude "*.log" --exclude ".git/" source/ dest/

# Derive a key for this context
turbocrypt encrypt --key KEY --context "project-x" source/ dest/

# Add .enc to destination names
turbocrypt encrypt --key KEY --enc-suffix source/ dest/

# Override the configured worker count
turbocrypt encrypt --key KEY --threads 16 source/ dest/

# Check the paths and totals without writing files
turbocrypt encrypt --key KEY --dry-run source/ dest/
```

## Decryption

```bash
# Decrypt a file or directory
turbocrypt decrypt --key KEY source dest

# Replace encrypted files in place
turbocrypt decrypt --key KEY --in-place encrypted/

# Recover names that were encrypted too
turbocrypt decrypt --key KEY --encrypted-filenames encrypted/ decrypted/

# The context must match the one used for encryption
turbocrypt decrypt --key KEY --context "project-x" encrypted/ decrypted/

# Remove .enc and skip source files without that suffix
turbocrypt decrypt --key KEY --enc-suffix encrypted/ decrypted/

# Show what would be decrypted
turbocrypt decrypt --key KEY --dry-run encrypted/ decrypted/
```

## Verification and listing

```bash
# Authenticate the complete contents
turbocrypt verify --key KEY encrypted-file.enc
turbocrypt verify --key KEY encrypted-directory/

# Authenticate headers only
turbocrypt verify --quick --key KEY encrypted-directory/

# A context used for encryption is also needed here
turbocrypt verify --quick --key KEY --context "project-x" encrypted/

# Preview verification without reading and authenticating the contents
turbocrypt verify --key KEY --dry-run encrypted/

# List stored paths as they appear on disk
turbocrypt list encrypted-directory/

# Decrypt encrypted names in the listing
turbocrypt list --key KEY --encrypted-filenames encrypted-directory/
```

## Configuration commands

```bash
# Inspect the current values
turbocrypt config show

# Copy a key into the config, then set processing defaults
turbocrypt config set-key path/to/key
turbocrypt config set-threads 8
turbocrypt config set-buffer-size 8388608

# Add or remove a persistent exclusion
turbocrypt config add-exclude "*.tmp"
turbocrypt config remove-exclude "*.tmp"

# Choose how directory jobs handle links and names
turbocrypt config set-ignore-symlinks true
turbocrypt config set-encrypted-filenames true
```

## Git

```bash
# Set up this repository with the selected key
turbocrypt git init

# Set up a clone with a key already represented in .enc/
turbocrypt git unlock --key team.key

# Join with a key that has no files in the repository yet
turbocrypt git init --key my.key

# Write a password-protected copy of the repository key
turbocrypt git export-key --password team.key

# Make paths private or public again
turbocrypt git add INTERNAL-DOC.md ops/
turbocrypt git rm INTERNAL-DOC.md

# Compare the working files with the encrypted store
turbocrypt git status

# Refresh one side from the other
turbocrypt git encrypt
turbocrypt git decrypt

# Resolve a file changed on both sides
turbocrypt git decrypt --force docs/internal.md  # take the upstream version
turbocrypt git encrypt --force docs/internal.md  # keep the working version
```

## Benchmarks and version

```bash
# Measure encryption throughput
turbocrypt bench

# Print the installed version
turbocrypt version
```

## Processing options

The processing commands accept the following options where they apply:

| Option                  | Effect                                                                      |
| ----------------------- | --------------------------------------------------------------------------- |
| `--key <path>`          | Use this key instead of the environment or configuration                    |
| `--password`            | Force a password prompt; protected keys are normally detected               |
| `--context <string>`    | Derive a separate key namespace from the context                            |
| `--threads <n>`         | Override the default of one worker per CPU, capped at 16; the maximum is 64 |
| `--buffer-size <bytes>` | Change the 4 MiB I/O buffer                                                 |
| `--in-place`            | Replace the source during encryption or decryption                          |
| `--force`               | Replace an existing destination without prompting                           |
| `--enc-suffix`          | Add `.enc` when encrypting; remove it and skip other names when decrypting  |
| `--encrypted-filenames` | Encrypt each path component; incompatible with `--in-place`                 |
| `--exclude <pattern>`   | Skip matching paths; may be repeated                                        |
| `--ignore-symlinks`     | Skip symbolic links                                                         |
| `--quick`               | Authenticate only the header during verification                            |
| `--dry-run`             | Report what would be processed without changing files                       |
