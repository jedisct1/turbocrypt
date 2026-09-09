<p align="center">
  <img src=".media/logo.png" width="400" alt="TurboCrypt Logo" />
</p>

# TurboCrypt

A fast, easy-to-use, and secure command-line tool for encrypting and decrypting
files, Git repositories, and directory trees.

## Installation

Linux, macOS, and Windows binaries are available from the
[releases page](https://github.com/jedisct1/turbocrypt/releases).

To build an optimized binary locally, install the master version of
[Zig](https://ziglang.org/download/), then run:

```bash
git clone https://github.com/jedisct1/turbocrypt.git
cd turbocrypt
zig build -Doptimize=ReleaseFast
```

The binary is written to `zig-out/bin/turbocrypt`. See the
[getting started guide](docs/getting-started.md) for a detailed walkthrough.

## Quick start

Create a key and save it as the default:

```bash
turbocrypt keygen secret.key
turbocrypt config set-key secret.key
```

Keep a backup of the key somewhere separate. Losing it means losing access to
the encrypted files, and anyone with a copy can decrypt them.

Encrypt a directory, authenticate the encrypted copy, and decrypt it again:

```bash
turbocrypt encrypt my-documents/ encrypted-documents/
turbocrypt verify encrypted-documents/
turbocrypt decrypt encrypted-documents/ restored-documents/
```

The same commands work on individual files. Read
[Getting started](docs/getting-started.md) for the full tutorial or the
[command reference](docs/command-reference.md) for the complete command set.

## Documentation

- [Getting started](docs/getting-started.md) — installation and a first
  encrypted file or directory
- [Usage guide](docs/usage.md) — password-protected keys, contexts, filenames,
  exclusions, verification, and other common workflows
- [Private files in Git](docs/git.md) — encrypted files in public repositories,
  setup, collaboration, and conflict handling
- [Command reference](docs/command-reference.md) — commands and processing options at a glance
- [Configuration](docs/configuration.md) — saved settings, precedence,
  environment variables, and file portability
- [Safety](docs/safety.md) — key handling, backups, verification, and performance considerations
- [Troubleshooting](docs/troubleshooting.md) — common errors and Git integration problems
