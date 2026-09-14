# Save your preferences

[Back to the main README](../README.md)

If you keep typing the same options, save them once with `turbocrypt config`. Start by looking at your current settings:

```bash
turbocrypt config show
```

## Choose which key to use

To save a default key, run:

```bash
turbocrypt config set-key secret.key
```

This copies the key into your settings. It doesn't save a link to the original file, so moving or deleting that file won't change the saved copy. Password protection is preserved.

For a single command, you can choose another key:

```bash
turbocrypt encrypt --key work.key documents/ encrypted-documents/
```

If you want several commands in the same terminal to use a key, set `TURBOCRYPT_KEY_FILE`. In a Unix shell:

```bash
export TURBOCRYPT_KEY_FILE="$HOME/.config/turbocrypt/work.key"
turbocrypt encrypt documents/ encrypted-documents/
```

TurboCrypt first looks for `--key`, then `TURBOCRYPT_KEY_FILE`, and finally your saved default. To return to the default in that shell, run `unset TURBOCRYPT_KEY_FILE`.

Git checkouts have their own saved key. Changing these settings won't change a checkout you've already set up; see [the checkout's key](git.md#the-checkouts-key).

## Skip the same files each time

For example, to leave logs and temporary files out of future folder jobs:

```bash
turbocrypt config add-exclude "*.log"
turbocrypt config add-exclude "*.tmp"
```

Remove a pattern when you no longer need it:

```bash
turbocrypt config remove-exclude "*.tmp"
```

When a command has its own `--exclude` options, those replace the saved exclusions for that run. They aren't added to the list.

To skip symbolic links by default, use:

```bash
turbocrypt config set-ignore-symlinks true
```

Use `false` to turn that setting off again.

## Encrypt filenames by default

If you want names to stay private for all your file jobs, enable:

```bash
turbocrypt config set-encrypted-filenames true
```

This also applies when decrypting, listing, or mounting folders. If you later work with files whose names weren't encrypted, turn it off first:

```bash
turbocrypt config set-encrypted-filenames false
```

This setting only changes future commands. It doesn't rename or encrypt files you already have.

## Adjust how many files run at once

TurboCrypt chooses a worker count automatically. You can usually leave it alone, but if you want to use fewer workers, try it on one job first:

```bash
turbocrypt encrypt --threads 4 documents/ encrypted-documents/
```

If that works well for your files and drive, save it:

```bash
turbocrypt config set-threads 4
```

`--threads` overrides the saved worker count for one command. For help with a slow job or memory errors, see [Troubleshooting](troubleshooting.md#file-processing-is-slow-or-runs-out-of-memory).

## Find your settings file

TurboCrypt stores your settings in `config.json`:

- On macOS: `~/Library/Application Support/turbocrypt/config.json`
- On Linux and BSD: `~/.local/share/turbocrypt/config.json`, or `$XDG_DATA_HOME/turbocrypt/config.json` if you've set `XDG_DATA_HOME`
- On Windows: `%LOCALAPPDATA%\turbocrypt\config.json`

Use the config commands to change it. If you've saved a default key, treat this file as another copy of that key when backing up or sharing your computer's settings.

After changing a key file's password, run `turbocrypt config set-key` again to update the saved copy. See [password-protected keys](usage.md#add-a-password-to-your-key) for the steps.
