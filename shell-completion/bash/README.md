# Bash Completion for TurboCrypt

This file provides command-line completion for turbocrypt in Bash shells.

## Installation

### System-wide (requires root)

Copy the completion file to your system's bash completion directory:

```bash
sudo cp turbocrypt /usr/share/bash-completion/completions/
```

### User-local

Copy to your user completion directory:

```bash
mkdir -p ~/.local/share/bash-completion/completions
cp turbocrypt ~/.local/share/bash-completion/completions/
```

### Manual loading

Source the file directly in your `~/.bashrc`:

```bash
source /path/to/shell-completions/bash/turbocrypt
```

## Verification

After installation, restart your shell or source your bashrc. Then test:

```bash
turbocrypt <TAB>
```

You should see available commands like `encrypt`, `decrypt`, `keygen`, etc.
