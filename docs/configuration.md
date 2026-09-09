# Configuration and portability

[Back to the main README](../README.md)

## Configuration

TurboCrypt stores its JSON configuration here:

- macOS: `~/Library/Application Support/turbocrypt/config.json`

- Linux: `~/.local/share/turbocrypt/config.json`

- Windows: `%LOCALAPPDATA%\turbocrypt\config.json`

The file is created for owner read/write access only.

Explicit command-line options win over `TURBOCRYPT_KEY_FILE`, which in turn
wins over values in this file.

`config set-key` copies the key into the configuration; it does not retain the
path to the original key file.

Also, if a command supplies one or more `--exclude` patterns, they replace the
configured exclusion list for that run.

See the [usage guide](usage.md#defaults) for examples of saving defaults and
the [command reference](command-reference.md#configuration-commands) for all
configuration commands.

## Environment variables

`TURBOCRYPT_KEY_FILE` supplies the key path when `--key` was not given. The Git
`init` and `unlock` commands read it only once, when they bind the key to the
repository.

```bash
export TURBOCRYPT_KEY_FILE=~/.ssh/turbocrypt.key
turbocrypt encrypt source/ dest/  # uses the key above
```

## File portability

Encrypted contents do not depend on a file's name or path.

An encrypted file can be moved or renamed without re-encrypting it.

With `--encrypted-filenames`, each path component is encrypted separately and
encoded with base84 so that it remains a valid name on Linux, macOS and
Windows.

The directory structure is preserved. Use the option again when decrypting.
