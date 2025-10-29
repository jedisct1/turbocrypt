# Zsh Completion for TurboCrypt

This file provides command-line completion for turbocrypt in Zsh shells.

## Installation

### Using fpath (recommended)

1. Create a directory for custom completions if you don't have one:

```zsh
mkdir -p ~/.zsh/completions
```

2. Copy the completion file:

```zsh
cp _turbocrypt ~/.zsh/completions/
```

3. Add the directory to your fpath in `~/.zshrc` (before `compinit`):

```zsh
fpath=(~/.zsh/completions $fpath)
autoload -Uz compinit
compinit
```

### System-wide (requires root)

Copy to a system completion directory:

```zsh
sudo cp _turbocrypt /usr/local/share/zsh/site-functions/
```

## Verification

After installation, restart your shell or run:

```zsh
exec zsh
```

Then test:

```zsh
turbocrypt <TAB>
```

You should see available commands like `encrypt`, `decrypt`, `keygen`, etc.
