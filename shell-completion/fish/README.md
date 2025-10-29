# Fish Completion for TurboCrypt

This file provides command-line completion for turbocrypt in Fish shells.

## Installation

Copy the completion file to Fish's completions directory:

```fish
cp turbocrypt.fish ~/.config/fish/completions/
```

Fish automatically loads completions from this directory, so no additional configuration is needed.

## Verification

After copying the file, completions are immediately available. Test by typing:

```fish
turbocrypt <TAB>
```

You should see available commands with descriptions like:
- `encrypt` — Encrypt files or directories
- `decrypt` — Decrypt files or directories
- `keygen` — Generate a new key
