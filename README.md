<p align="center">
  <img src=".media/logo.png" width="400" alt="TurboCrypt Logo" />
</p>

# TurboCrypt

A fast, easy-to-use, and secure command-line tool for encrypting and decrypting files or entire directory trees.

- [TurboCrypt](#turbocrypt)
  - [What Makes TurboCrypt Different](#what-makes-turbocrypt-different)
  - [Installation](#installation)
    - [Download Pre-Built Binaries](#download-pre-built-binaries)
    - [Build from Source](#build-from-source)
  - [Quick Start](#quick-start)
    - [Step 1: Generate an Encryption Key](#step-1-generate-an-encryption-key)
    - [Step 2: Set Your Default Key](#step-2-set-your-default-key)
    - [Step 3: Encrypt Files](#step-3-encrypt-files)
    - [Step 4: Verify Encrypted Files](#step-4-verify-encrypted-files)
    - [Step 5: Decrypt Files](#step-5-decrypt-files)
  - [Usage Examples](#usage-examples)
    - [Password-Protected Keys](#password-protected-keys)
    - [Managing Key Passwords](#managing-key-passwords)
    - [Adding an Extra Layer of Protection with Contexts](#adding-an-extra-layer-of-protection-with-contexts)
    - [Encrypting in Place](#encrypting-in-place)
    - [Hiding Filenames](#hiding-filenames)
    - [Skipping Certain Files](#skipping-certain-files)
    - [Previewing Operations with Dry Run](#previewing-operations-with-dry-run)
    - [Verifying File Integrity](#verifying-file-integrity)
    - [Listing Encrypted Directory Contents](#listing-encrypted-directory-contents)
    - [Setting Up Defaults](#setting-up-defaults)
    - [Private Files in a Git Repository](#private-files-in-a-git-repository)
  - [All Commands](#all-commands)
    - [Key Management](#key-management)
    - [Encryption](#encryption)
    - [Decryption](#decryption)
    - [Verification](#verification)
    - [Configuration](#configuration)
    - [Git](#git)
    - [Performance Testing](#performance-testing)
  - [Command-Line Options](#command-line-options)
  - [File Portability](#file-portability)
    - [Filename Encryption](#filename-encryption)
  - [Configuration File](#configuration-file)
    - [Priority Order](#priority-order)
  - [Best Practices](#best-practices)
    - [Key Management](#key-management-1)
    - [Safe Workflows](#safe-workflows)
    - [Performance Tips](#performance-tips)
  - [Troubleshooting](#troubleshooting)
    - ["Wrong decryption key, wrong context, or corrupted file header"](#wrong-decryption-key-wrong-context-or-corrupted-file-header)
    - ["Authentication failed" during decryption](#authentication-failed-during-decryption)
    - ["Access denied" errors with large files](#access-denied-errors-with-large-files)
    - [Performance is slow](#performance-is-slow)
    - [Out of memory errors](#out-of-memory-errors)
    - ["nothing to commit" after editing a private file](#nothing-to-commit-after-editing-a-private-file)
    - ["commit refused, private files are tracked by git"](#commit-refused-private-files-are-tracked-by-git)
    - [A merge conflict on a private file](#a-merge-conflict-on-a-private-file)
    - ["this repository already has a different key"](#this-repository-already-has-a-different-key)
    - [Hooks do not run from a GUI client](#hooks-do-not-run-from-a-gui-client)
  - [Environment Variables](#environment-variables)

## What Makes TurboCrypt Different

- Fast: Uses AEGIS-128X2 and multi-threaded processing for directories
- Secure: Every file is authenticated - tampering is detected automatically
- Simple: Clean command-line interface with sensible defaults
- Flexible: Works with single files or entire directory trees, with optional filename encryption

## Installation

### Download Pre-Built Binaries

Pre-built binaries for Linux, macOS, and Windows are available at:
https://github.com/jedisct1/turbocrypt/releases

### Build from Source

Note: Building from source is recommended for best performance. The compiled binary will be optimized for your specific platform, while pre-built binaries are built for the lowest common denominator.

Requirements: [Zig](https://ziglang.org/download/) (master)

```bash
git clone https://github.com/jedisct1/turbocrypt.git
cd turbocrypt
zig build -Doptimize=ReleaseFast
```

The compiled binary will be in `zig-out/bin/turbocrypt`. Move it elsewhere, add it to your PATH or use the full path.

## Quick Start

### Step 1: Generate an Encryption Key

First, create a key file. This is a random 128-bit key that you'll use to encrypt and decrypt your files.

```bash
turbocrypt keygen secret.key
```

Important: Keep this key file safe! Anyone with access to it can decrypt your files.

### Step 2: Set Your Default Key

Store the key in your configuration so you don't have to specify it every time:

```bash
turbocrypt config set-key secret.key
```

After this, you can encrypt and decrypt without specifying the key. The tool is now ready to use!

### Step 3: Encrypt Files

Encrypt a single file:

```bash
turbocrypt encrypt document.pdf document.pdf.enc
```

Encrypt an entire directory:

```bash
turbocrypt encrypt my-documents/ encrypted-documents/
```

### Step 4: Verify Encrypted Files

Check that your encrypted files are intact:

```bash
turbocrypt verify encrypted-documents/
```

This confirms all files were encrypted successfully and haven't been corrupted or tampered with.

For a faster check that just verifies you have the correct key:

```bash
turbocrypt verify --quick encrypted-documents/
```

### Step 5: Decrypt Files

Decrypt a file:

```bash
turbocrypt decrypt document.pdf.enc document.pdf
```

Decrypt the entire directory:

```bash
turbocrypt decrypt encrypted-documents/ my-documents/
```

That's it!

## Usage Examples

### Password-Protected Keys

If you want to protect your key file, you can encrypt it with a password:

```bash
# Generate a password-protected key
turbocrypt keygen --password protected.key
# Enter your password when prompted

# Use it (you'll be prompted for the password)
turbocrypt encrypt --key protected.key --password source/ dest/
```

### Managing Key Passwords

You can add, change, or remove password protection on existing keys:

```bash
# Add password protection to a plain key
turbocrypt change-password secret.key
# Enter your new password when prompted

# Change the password on a protected key
turbocrypt change-password protected.key
# Enter current password, then new password

# Remove password protection from a key
turbocrypt change-password --remove-password protected.key
# Enter current password to confirm
```

This is useful when you want to:
- Add password protection to an existing plain key without regenerating it
- Change a compromised or forgotten password while keeping the same encryption key
- Remove password protection when moving a key to secure storage

### Adding an Extra Layer of Protection with Contexts

When you encrypt a directory, you can optionally specify a context string. This adds an additional secret that's required to decrypt your files - think of it as a second password that works alongside your encryption key.

Here's why this matters: Even if someone gains access to your encryption key file and your password, they still won't be able to decrypt your files without knowing the context you used. The context acts as an extra safeguard that you keep in your head rather than written down.

```bash
# Encrypt with a context
turbocrypt encrypt --key my-secret.key --context "my-secret-phrase" documents/ encrypted/

# To decrypt, you MUST provide the exact same context
turbocrypt decrypt --key my-secret.key --context "my-secret-phrase" encrypted/ documents/

# Wrong context? Decryption will fail, even with the correct key
turbocrypt decrypt --key my-secret.key --context "wrong-phrase" encrypted/ documents/
# Error: Wrong decryption key, wrong context, or corrupted file header
```

Each context creates completely different encrypted files, even when using the same key. Files encrypted with context "project-a" cannot be decrypted with context "project-b", or without any context at all.

### Encrypting in Place

Sometimes you want to encrypt files directly without creating copies:

```bash
turbocrypt encrypt --key my-secret.key --in-place my-documents/
```

Warning: This overwrites the original files. For safety, TurboCrypt writes the encrypted data to a temporary file first and then atomically replaces the original. Make sure you have backups first!

### Hiding Filenames

If you want to conceal not just the contents but also the names of your files:

```bash
# Encrypt with encrypted filenames
turbocrypt encrypt --key my-secret.key --encrypted-filenames source/ dest/

# Decrypt - you MUST use --encrypted-filenames to decrypt
turbocrypt decrypt --key my-secret.key --encrypted-filenames dest/ restored/
```

This encrypts each filename component, making it impossible to tell what files are in the encrypted directory without the key. Note: You must use `--encrypted-filenames` for both encryption AND decryption.

### Skipping Certain Files

Use exclude patterns to skip files you don't want to encrypt:

```bash
# Skip log files and the .git directory
turbocrypt encrypt --key my-secret.key \
  --exclude "*.log" \
  --exclude ".git/" \
  my-project/ encrypted-project/
```

Common exclude patterns:
- `*.log` - skip all .log files
- `*.tmp` - skip temporary files
- `.git/` - skip git repository data
- `node_modules/` - skip Node.js dependencies
- `__pycache__/` - skip Python cache files

### Previewing Operations with Dry Run

Before encrypting or decrypting files, you can preview what will happen without actually processing them:

```bash
# See what files would be encrypted
turbocrypt encrypt --dry-run --key my-secret.key documents/ encrypted/

# Test exclude patterns before committing
turbocrypt encrypt --dry-run --key my-secret.key \
  --exclude "*.log" \
  --exclude "node_modules/" \
  large-project/ encrypted-project/

# Preview decryption
turbocrypt decrypt --dry-run --key my-secret.key encrypted/ restored/
```

This is particularly useful for:
- Testing exclude patterns before processing large directories
- Verifying source and destination paths are correct
- Estimating how many files will be processed
- Checking operations before committing to them

The `--dry-run` flag works with all operations (encrypt, decrypt, verify) and shows accurate file counts and sizes without modifying any files.

### Verifying File Integrity

Check if encrypted files are intact without decrypting them:

```bash
# Verify a single file
turbocrypt verify --key my-secret.key encrypted-file.enc

# Verify an entire directory
turbocrypt verify --key my-secret.key encrypted-documents/

# Quick verification (only checks if you have the correct key)
turbocrypt verify --quick --key my-secret.key encrypted-documents/
```

This is useful for checking backups or verifying files after transferring them.

Quick vs Full Verification:
- `--quick`: Only verifies the header MAC (checks if you have the correct key). Much faster but doesn't verify data integrity.
- Full verification (default): Checks both the header MAC and content, ensuring both key correctness and data integrity.

### Listing Encrypted Directory Contents

You can list the contents of an encrypted directory without fully decrypting the files:

```bash
# List encrypted directory (shows encrypted filenames as-is)
turbocrypt list encrypted-documents/

# List with decrypted filenames (requires the correct key)
turbocrypt list --key my-secret.key --encrypted-filenames encrypted-documents/
```

The list command displays:
- File paths (decrypted if `--encrypted-filenames` is used)
- File sizes (encrypted size, which includes 48-byte overhead per file)
- Total file count and combined size

This is useful for:
- Browsing encrypted backups without extracting them
- Verifying what files are in an encrypted archive
- Finding specific files before decrypting the entire directory
- Quick inventory of encrypted data

Example output:
```
Listing contents: encrypted-documents/

  report.pdf (2500 bytes)
  memo.doc (1248 bytes)
  photos/sunset.jpg (5347 bytes)
  photos/beach.jpg (4896 bytes)

Total: 4 files, 13.4 KB
```

### Setting Up Defaults

If you use the same key and settings frequently, save them:

```bash
# Set your default key (stores it in config)
turbocrypt config set-key my-secret.key

# Set default thread count
turbocrypt config set-threads 8

# Add permanent exclude patterns
turbocrypt config add-exclude "*.log"
turbocrypt config add-exclude ".git/"

# View your configuration
turbocrypt config show
```

Now you can run commands without repeating options:

```bash
# Uses the key and excludes from your config
turbocrypt encrypt source/ dest/
```

### Private Files in a Git Repository

A public repository shows every tracked file to everyone. Sometimes a few
files should stay readable by the maintainers only, such as an
`INTERNAL-DOC.md` with internal instructions or deployment notes in
`docs/`. TurboCrypt can keep those files encrypted in the repository
while you edit them in clear.

The encrypted copies live in a committed `.enc/` directory. Their names and
their contents look random. Git hooks refresh `.enc/` before every commit
and refresh the plain files after a checkout, a merge or a rebase. The
plain files are kept out of commits by a local exclude rule. The list of
private files is encrypted too.

Set it up once, in the repository. The key comes from `--key`, then
`TURBOCRYPT_KEY_FILE`, then the default key in your config, exactly like
`turbocrypt encrypt`. Nothing generates a key for you:

```bash
turbocrypt keygen secret.key         # once, when you have no key yet
turbocrypt config set-key secret.key
turbocrypt git init                  # binds the key, creates .enc/, .gitprivate and the hooks
turbocrypt git add INTERNAL-DOC.md   # one file
turbocrypt git add docs/internal.md
turbocrypt git add ops/              # a whole directory, including future files
git commit -m "Add private notes"    # the hook encrypts and stages .enc/
git push
```

The hooks run without a terminal, so `init` copies the key to
`.git/turbocrypt/key` in clear. The file has mode 0600 and its directory
has mode 0700. A password-protected key is asked for once, at that
moment. From then on the repository uses that copy. A new default key or
a new `TURBOCRYPT_KEY_FILE` does not change it, and the daily commands
refuse `--key`.

Share the key with the other maintainers, outside of git. When the key
came from a file, a copy of that file does the same job:

```bash
turbocrypt git export-key --password team.key
```

On another clone:

```bash
git clone git@github.com:acme/my-project
cd my-project
turbocrypt git unlock --key team.key # binds the key, installs the hooks and decrypts .enc/
```

`unlock` picks the key like `init` does. A maintainer whose default key
is the team key runs `turbocrypt git unlock` alone. A key that does not
open the store is refused, and the message says where it came from.

From then on, daily work is plain git. Edit a private file and commit. Pull
and switch branches. The hooks keep both sides in sync. A few things are
worth knowing:

- `git commit -a` decides "nothing to commit" before the hook runs. When only
  private files changed, run `turbocrypt git encrypt` first, or run
  `git commit` again. `turbocrypt git status` shows what is pending.
- A new file inside a private directory is encrypted at the next commit. Run
  `turbocrypt git encrypt` when you use `git commit -a`, because it cannot
  stage a new store entry on its own.
- `turbocrypt git rm docs/internal.md` makes a file public again. The plain
  file stays on disk as an ordinary untracked file.
- A private file that you edited is never overwritten by a pull. You get a
  `conflict` line instead. `turbocrypt git decrypt --force <path>` takes the
  upstream version, `turbocrypt git encrypt --force <path>` keeps yours.
- `git clean -x` deletes the plain files, including edits made since the
  last commit. `turbocrypt git decrypt` brings back the committed version.
- `git stash --all` writes the plain files into local git objects. Avoid
  it in a repository with private files.
- Do not keep a private file on one branch and a tracked public file at
  the same path on another. Switching to the branch that tracks it
  overwrites the plain file, and no hook can bring an edit back.
- The `.gitprivate` list accepts one path per line, `/path/to/file` for a
  file and `/path/to/dir/` for a directory. No wildcards, no negation.

What the public can see: how many private files exist, the shape of the
directory tree, the size of each file, which ones are executable, and when
they change. Two files with the same name in different directories get the
same encrypted name. An entry cannot be moved or swapped without detection,
but a whole commit can be reverted to an older one, which is why signed
commits still matter.

The feature works on macOS and Linux. Linked worktrees are not supported.
The hooks are a convenience: `git commit --no-verify` skips them, and
`git add -f` can stage a plain file on purpose.

## All Commands

### Key Management

```bash
# Generate a new key
turbocrypt keygen output.key

# Generate a password-protected key
turbocrypt keygen --password output.key

# Add password protection to existing key
turbocrypt change-password my.key

# Change password on protected key
turbocrypt change-password protected.key

# Remove password protection
turbocrypt change-password --remove-password protected.key

# Set default key in config
turbocrypt config set-key my.key
```

### Encryption

```bash
# Basic encryption
turbocrypt encrypt --key KEY source dest

# With password-protected key
turbocrypt encrypt --key KEY --password source dest

# Encrypt in place (overwrites source)
turbocrypt encrypt --key KEY --in-place source/

# Encrypt filenames too
turbocrypt encrypt --key KEY --encrypted-filenames source/ dest/

# Exclude certain files
turbocrypt encrypt --key KEY --exclude "*.log" --exclude ".git/" source/ dest/

# Use context for key derivation
turbocrypt encrypt --key KEY --context "project-x" source/ dest/

# Add .enc suffix automatically
turbocrypt encrypt --key KEY --enc-suffix source/ dest/

# Custom thread count
turbocrypt encrypt --key KEY --threads 16 source/ dest/

# Preview without actually encrypting
turbocrypt encrypt --key KEY --dry-run source/ dest/
```

### Decryption

```bash
# Basic decryption
turbocrypt decrypt --key KEY source dest

# Decrypt in place
turbocrypt decrypt --key KEY --in-place encrypted/

# Decrypt encrypted filenames (must use --encrypted-filenames if used during encryption)
turbocrypt decrypt --key KEY --encrypted-filenames encrypted/ decrypted/

# Decrypt with context (must match encryption context)
turbocrypt decrypt --key KEY --context "project-x" encrypted/ decrypted/

# Remove .enc suffix automatically
turbocrypt decrypt --key KEY --enc-suffix encrypted/ decrypted/

# Preview without actually decrypting
turbocrypt decrypt --key KEY --dry-run encrypted/ decrypted/
```

### Verification

```bash
# Verify file integrity (full verification)
turbocrypt verify --key KEY encrypted-file.enc

# Verify directory (full verification)
turbocrypt verify --key KEY encrypted-directory/

# Quick verification (only checks key correctness, not data integrity)
turbocrypt verify --quick --key KEY encrypted-directory/

# Quick verification with context
turbocrypt verify --quick --key KEY --context "project-x" encrypted/

# Preview verification without actually verifying
turbocrypt verify --key KEY --dry-run encrypted/
```

### Configuration

```bash
# View current settings
turbocrypt config show

# Set default key
turbocrypt config set-key path/to/key

# Set thread count
turbocrypt config set-threads 8

# Set buffer size (in bytes)
turbocrypt config set-buffer-size 8388608

# Manage exclude patterns
turbocrypt config add-exclude "*.tmp"
turbocrypt config remove-exclude "*.tmp"

# Set symlink behavior
turbocrypt config set-ignore-symlinks true

# Set filename encryption default
turbocrypt config set-encrypted-filenames true
```

### Git

```bash
# Set up the repository you are in, with --key, TURBOCRYPT_KEY_FILE or the default key
turbocrypt git init

# Set up a clone with the shared key
turbocrypt git unlock --key team.key

# Share the key
turbocrypt git export-key --password team.key

# Make files or directories private, or public again
turbocrypt git add INTERNAL-DOC.md ops/
turbocrypt git rm INTERNAL-DOC.md

# See what is private and what is out of sync
turbocrypt git status

# Refresh the store from the plain files, or the plain files from the store
turbocrypt git encrypt
turbocrypt git decrypt

# Resolve a file that changed on both sides
turbocrypt git decrypt --force docs/internal.md   # take the upstream version
turbocrypt git encrypt --force docs/internal.md   # keep yours
```

### Performance Testing

```bash
# Run benchmarks
turbocrypt bench
```

## Command-Line Options

Options available for most commands:

- `--key <path>` - Path to key file (required unless set in config)
- `--password` - Prompt for password (for password-protected keys)
- `--context <string>` - Context string for key derivation (creates independent key namespace)
- `--threads <n>` - Number of parallel threads (default: CPU count capped at 16, max 64)
- `--in-place` - Overwrite source files instead of creating new ones
- `--encrypted-filenames` - Encrypt/decrypt filenames (required for both encryption and decryption, cannot be used with --in-place)
- `--enc-suffix` - Add/remove .enc suffix automatically
- `--exclude <pattern>` - Skip files matching pattern (can use multiple times)
- `--ignore-symlinks` - Skip symbolic links
- `--quick` - (verify only) Only check header MAC, skip full verification - faster but doesn't verify data integrity
- `--dry-run` - Show what would be processed without actually encrypting/decrypting - useful for testing exclude patterns and verifying operations
- `--force` - Overwrite existing files without asking
- `--buffer-size <bytes>` - Set I/O buffer size (default: 4MB)

## File Portability

Encrypted files can be freely moved between directories and renamed. The encryption intentionally does not depend on the file's path, filename, or parent directories. This means you can reorganize and rename your encrypted files however you like without needing to re-encrypt them.

### Filename Encryption

When using `--encrypted-filenames`:

- Each path component (directory or filename) is encrypted separately
- Encoded with base91 to ensure filesystem compatibility
- Preserves directory structure (you still see folders, just with encrypted names)
- Must be used for both encryption and decryption operations

## Configuration File

TurboCrypt stores your settings in a JSON configuration file:

- macOS: `~/Library/Application Support/turbocrypt/config.json`
- Linux: `~/.local/share/turbocrypt/config.json`
- Windows: `%LOCALAPPDATA%\turbocrypt\config.json`

The config file is created with restricted permissions (owner read/write only) to protect your key if you choose to store it there.

### Priority Order

Settings are applied in this order (highest priority first):

1. Command-line flags (e.g., `--key`, `--threads`)
2. Environment variables (`TURBOCRYPT_KEY_FILE`)
3. Configuration file settings

## Best Practices

### Key Management

- Generate strong keys: Always use `turbocrypt keygen` - don't create keys manually
- Keep backups: Store a copy of your key in a safe, separate location
- Use password protection: For keys stored on your computer, consider using `turbocrypt keygen --password` or adding protection later with `turbocrypt change-password`
- Change passwords when needed: If you suspect your password may be compromised, use `turbocrypt change-password` to update it without regenerating the key
- Never share keys: Each person should have their own key, or use password-protected keys with different passwords for additional security

### Safe Workflows

- Preview first: Use `--dry-run` to see what will be processed before running the actual operation
- Test first: Try encrypting/decrypting a small test directory before processing important data
- Test exclude patterns: Use `--dry-run` with `--exclude` to verify your patterns work as expected
- Verify after transfer: Use `turbocrypt verify` to check files after copying or uploading them
- Keep originals: Don't delete unencrypted files until you've verified the encrypted versions
- Exclude unnecessary files: Use `--exclude` to skip cache, logs, and other regenerable files

### Performance Tips

- Adjust threads for directories: Use `--threads` based on your CPU core count and disk features
- Larger buffers for huge files: Try `--buffer-size 16777216` (16MB) for very large files
- Exclude unnecessary files: Using exclude patterns is faster than encrypting files and deleting them later

## Troubleshooting

### "Wrong decryption key, wrong context, or corrupted file header"

This error means either:
- You're using the wrong key file
- You're using the wrong context (or missing a required context)
- The file wasn't encrypted with TurboCrypt
- The file header is corrupted

Double-check you're using the same key and context that were used to encrypt the file.

### "Authentication failed" during decryption

The file has been modified or corrupted after encryption. TurboCrypt detected tampering and refused to decrypt. This is a security feature - the file may have been altered maliciously or damaged during storage/transfer.

### "Access denied" errors with large files

On some systems, memory-mapped I/O (used for files >1MB) requires specific permissions. Try running with sudo/administrator privileges, or check that your user has read/write access to both source and destination directories.

### Performance is slow

- Check if you're using too many threads (`--threads 4` is often faster than 32 for small files)
- Ensure your source/destination are on fast storage (SSD vs HDD makes a big difference)
- For many small files, threading overhead can reduce performance - try using `--threads 2`

### Out of memory errors

Reduce the buffer size: `--buffer-size 1048576` (1MB instead of default 4MB)

### "nothing to commit" after editing a private file

Git decides whether there is something to commit before it runs the
pre-commit hook, and the hook is what stages the encrypted file. Run
`git commit` again. With `git commit -a`, run `turbocrypt git encrypt`
first.

### "commit refused, private files are tracked by git"

A file listed in `.gitprivate` is also tracked in clear. Committing it
would publish it. Run `git rm --cached -- <path>` and commit. Earlier
commits still contain the file in clear.

### A merge conflict on a private file

Git cannot merge two encrypted versions. It leaves the entry unmerged and
keeps your version in the working tree. Edit the plain file until it holds
what you want, then run `turbocrypt git encrypt --force <path>` and commit.
To look at the other side first, run `git checkout --theirs -- .enc/<name>`
followed by `turbocrypt git decrypt --force <path>`.

### "entry cannot be committed as it is"

A file in `.enc/` does not decrypt: it was altered, or it came from a
different key. Commits stop until it is fixed. When the plain file is
present and correct, `turbocrypt git encrypt --force <path>` writes a fresh
entry from it. Otherwise `turbocrypt git rm <path>` drops the entry.

### "this repository already has a different key"

`init` and `unlock` keep the key bound to the repository, whatever the
default key or `TURBOCRYPT_KEY_FILE` says. To replace it, run
`turbocrypt git unlock --key <key-file> --force`. The new key must open
the store, so this is not a way to rotate keys.

### Hooks do not run from a GUI client

GUI clients run hooks with a minimal PATH. The installed hooks use the
absolute path of the `turbocrypt` binary recorded at `init` time. When the
binary moved, run `turbocrypt git init` again to refresh the hooks.

## Environment Variables

- `TURBOCRYPT_KEY_FILE`: Path to your key file (overridden by `--key` flag). `turbocrypt git init` and `unlock` read it once, when they bind a key to a repository.

Example:

```bash
export TURBOCRYPT_KEY_FILE=~/.ssh/turbocrypt.key
turbocrypt encrypt source/ dest/  # Uses key from environment
```
