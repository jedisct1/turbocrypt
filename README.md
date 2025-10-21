<p align="center">
  <img src=".media/logo.png" width="400" alt="TurboCrypt Logo" />
</p>

# TurboCrypt

A fast, simple, secure command-line tool for encrypting and decrypting files and directories.

## What Makes TurboCrypt Different

- Fast: Multi-threaded processing for directories
- Secure: Every file is authenticated - tampering is detected automatically
- Simple: Clean command-line interface with sensible defaults
- Flexible: Works with single files or entire directory trees, with optional filename encryption

## Installation

### Build from Source

Requirements: [Zig](https://ziglang.org/download/)

```bash
git clone https://github.com/jedisct1/turbocrypt.git
cd turbocrypt
zig build -Doptimize=ReleaseFast
```

The compiled binary will be in `zig-out/bin/turbocrypt`. Move it elsewhere, add it to your PATH or use the full path.

## Quick Start

### Generate an Encryption Key

First, create a key file. This is a random 128-bit key that you'll use to encrypt and decrypt your files.

```bash
turbocrypt keygen my-secret.key
```

Important: Keep this key file safe! Anyone with access to it can decrypt your files. Consider storing it on a USB drive or in a password manager.

### Encrypt Files

Encrypt a single file:

```bash
turbocrypt encrypt --key my-secret.key document.pdf document.pdf.enc
```

Encrypt an entire directory:

```bash
turbocrypt encrypt --key my-secret.key my-documents/ encrypted-documents/
```

### Decrypt Files

Decrypt a file:

```bash
turbocrypt decrypt --key my-secret.key document.pdf.enc document.pdf
```

Decrypt a directory:

```bash
turbocrypt decrypt --key my-secret.key encrypted-documents/ my-documents/
```

## Common Operations

### Password-Protected Keys

If you want to protect your key file, you can encrypt it with a password:

```bash
# Generate a password-protected key
turbocrypt keygen --password protected.key
# Enter your password when prompted

# Use it (you'll be prompted for the password)
turbocrypt encrypt --key protected.key --password source/ dest/
```

### Encrypting in Place

Sometimes you want to encrypt files directly without creating copies:

```bash
turbocrypt encrypt --key my-secret.key --in-place my-documents/
```

Warning: This overwrites the original files. Make sure you have backups first!

### Hiding Filenames

If you want to conceal not just the contents but also the names of your files:

```bash
turbocrypt encrypt --key my-secret.key --encrypt-filenames source/ dest/
```

This encrypts each filename component, making it impossible to tell what files are in the encrypted directory without the key.

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

### Verifying File Integrity

Check if encrypted files are intact without decrypting them:

```bash
# Verify a single file
turbocrypt verify --key my-secret.key encrypted-file.enc

# Verify an entire directory
turbocrypt verify --key my-secret.key encrypted-documents/
```

This is useful for checking backups or verifying files after transferring them.

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

## All Commands

### Key Management

```bash
# Generate a new key
turbocrypt keygen output.key

# Generate a password-protected key
turbocrypt keygen --password output.key

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
turbocrypt encrypt --key KEY --encrypt-filenames source/ dest/

# Exclude certain files
turbocrypt encrypt --key KEY --exclude "*.log" --exclude ".git/" source/ dest/

# Add .enc suffix automatically
turbocrypt encrypt --key KEY --enc-suffix source/ dest/

# Custom thread count
turbocrypt encrypt --key KEY --threads 16 source/ dest/
```

### Decryption

```bash
# Basic decryption
turbocrypt decrypt --key KEY source dest

# Decrypt in place
turbocrypt decrypt --key KEY --in-place encrypted/

# Remove .enc suffix automatically
turbocrypt decrypt --key KEY --enc-suffix encrypted/ decrypted/
```

### Verification

```bash
# Verify file integrity
turbocrypt verify --key KEY encrypted-file.enc

# Verify directory
turbocrypt verify --key KEY encrypted-directory/
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
- `--threads <n>` - Number of parallel threads (default: CPU count, max 64)
- `--in-place` - Overwrite source files instead of creating new ones
- `--encrypt-filenames` - Encrypt filenames (cannot be used with --in-place)
- `--enc-suffix` - Add/remove .enc suffix automatically
- `--exclude <pattern>` - Skip files matching pattern (can use multiple times)
- `--ignore-symlinks` - Skip symbolic links
- `--force` - Overwrite existing files without asking
- `--buffer-size <bytes>` - Set I/O buffer size (default: 4MB)

## How It Works

### Encryption Process

1. Each file gets a unique random 16-byte nonce
2. Header MAC: A message authentication code is generated for the nonce and version, providing fast verification of the key before attempting decryption
3. The file contents are encrypted using AEGIS-128X2, which simultaneously provides confidentiality and authenticity
4. Authentication Tag: A 16-byte tag is appended to verify the file hasn't been tampered with

Total overhead: 48 bytes per file (32-byte header + 16-byte authentication tag)

**File Portability**: Encrypted files can be freely moved between directories. The encryption is based only on the file contents and a random nonce - it does not depend on the file's path or parent directories. This means you can reorganize your encrypted files however you like without needing to re-encrypt them.

### Filename Encryption

When using `--encrypt-filenames`:

- Each path component (directory or filename) is encrypted separately
- Uses HCTR2, a wide-block cipher designed for encrypting data of varying lengths
- Encoded with base91 to ensure filesystem compatibility
- Preserves directory structure (you still see folders, just with encrypted names)
- Special entries (`.` and `..`) are never encrypted

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
- Use password protection: For keys stored on your computer, consider `--password`
- Never share keys: Each person should have their own key, or use password-protected keys with different passwords

### Safe Workflows

- Test first: Try encrypting/decrypting a small test directory before processing important data
- Verify after transfer: Use `turbocrypt verify` to check files after copying or uploading them
- Keep originals: Don't delete unencrypted files until you've verified the encrypted versions
- Exclude unnecessary files: Use `--exclude` to skip cache, logs, and other regenerable files

### Performance Tips

- More threads for directories: Use `--threads` based on your CPU core count (default is usually optimal)
- Larger buffers for huge files: Try `--buffer-size 16777216` (16MB) for very large files
- In-place for speed: `--in-place` is faster but overwrites files - use with caution
- Exclude patterns: Excluding files is faster than encrypting and deleting them later

## Troubleshooting

### "Wrong decryption key or corrupted file header"

This error means either:
- You're using the wrong key file
- The file wasn't encrypted with TurboCrypt
- The file header is corrupted

Double-check you're using the same key that encrypted the file.

### "Authentication failed" during decryption

The file has been modified or corrupted after encryption. TurboCrypt detected tampering and refused to decrypt. This is a security feature - the file may have been altered maliciously or damaged during storage/transfer.

### "Access denied" errors with large files

On some systems, memory-mapped I/O (used for files >1MB) requires specific permissions. Try running with sudo/admin privileges, or check that your user has read/write access to both source and destination directories.

### Performance is slow

- Check if you're using too many threads (`--threads 4` is often faster than 32 for small files)
- Ensure your source/destination are on fast storage (SSD vs HDD makes a big difference)
- For many small files, threading overhead can reduce performance - try `--threads 2`

### Out of memory errors

Reduce the buffer size: `--buffer-size 1048576` (1MB instead of default 4MB)

## Environment Variables

- `TURBOCRYPT_KEY_FILE`: Path to your key file (overridden by `--key` flag)

Example:

```bash
export TURBOCRYPT_KEY_FILE=~/.ssh/turbocrypt.key
turbocrypt encrypt source/ dest/  # Uses key from environment
```
