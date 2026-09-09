<p align="center">
  <img src=".media/logo.png" width="400" alt="TurboCrypt Logo" />
</p>

# TurboCrypt

A fast, easy-to-use, and secure command-line tool for encrypting and decrypting files or entire directory trees.

- [TurboCrypt](#turbocrypt)
  - [Installation](#installation)
  - [Quick start](#quick-start)
    - [Step 1: Generate a key](#step-1-generate-a-key)
    - [Step 2: Set the default key](#step-2-set-the-default-key)
    - [Step 3: Encrypt files](#step-3-encrypt-files)
    - [Step 4: Verify the result](#step-4-verify-the-result)
    - [Step 5: Decrypt files](#step-5-decrypt-files)
  - [Examples](#examples)
    - [Password-protected keys](#password-protected-keys)
    - [Contexts](#contexts)
    - [In-place encryption](#in-place-encryption)
    - [Encrypted filenames](#encrypted-filenames)
    - [Excluding files](#excluding-files)
    - [Dry runs](#dry-runs)
    - [Verification](#verification)
    - [Listing a directory](#listing-a-directory)
    - [Defaults](#defaults)
    - [Private Files in a Git Repository](#private-files-in-a-git-repository)
  - [All commands](#all-commands)
    - [Key management](#key-management)
    - [Encryption](#encryption)
    - [Decryption](#decryption)
    - [Verification and listing](#verification-and-listing)
    - [Configuration commands](#configuration-commands)
    - [Git](#git)
    - [Benchmarks and version](#benchmarks-and-version)
    - [Options](#options)
  - [File portability](#file-portability)
  - [Configuration](#configuration)
  - [A few cautions](#a-few-cautions)
  - [Troubleshooting](#troubleshooting)
    - ["Wrong decryption key, wrong context, or corrupted file header"](#wrong-decryption-key-wrong-context-or-corrupted-file-header)
    - ["Authentication failed" during decryption](#authentication-failed-during-decryption)
    - ["Access denied" errors with large files](#access-denied-errors-with-large-files)
    - [Performance is slow](#performance-is-slow)
    - [Out of memory errors](#out-of-memory-errors)
    - ["nothing to commit" after editing a private file](#nothing-to-commit-after-editing-a-private-file)
    - ["commit refused, private files are tracked by git"](#commit-refused-private-files-are-tracked-by-git)
    - [A merge conflict on a private file](#a-merge-conflict-on-a-private-file)
    - ["entry cannot be committed as it is"](#entry-cannot-be-committed-as-it-is)
    - ["this repository already has a different key"](#this-repository-already-has-a-different-key)
    - ["the store has no files for" a key](#the-store-has-no-files-for-a-key)
    - [Hooks do not run from a GUI client](#hooks-do-not-run-from-a-gui-client)
  - [Environment variables](#environment-variables)

## Installation

Linux, macOS and Windows binaries are available from the
[releases page](https://github.com/jedisct1/turbocrypt/releases), so the
quickest installation is to download the archive for your system.

For the best performance, build locally instead. Zig can then optimize the
binary for the machine it will run on. You will need the master version of
[Zig](https://ziglang.org/download/):

```bash
git clone https://github.com/jedisct1/turbocrypt.git
cd turbocrypt
zig build -Doptimize=ReleaseFast
```

The binary is written to `zig-out/bin/turbocrypt`.

## Quick start

### Step 1: Generate a key

First, create the key that will encrypt and decrypt your files:

```bash
turbocrypt keygen secret.key
```

The file contains a random 128-bit key. Keep a backup somewhere separate,
because losing it also means losing access to the encrypted files. Anyone who
gets a copy of it can decrypt them.

### Step 2: Set the default key

Next, copy the key into the configuration so that you do not need to pass
`--key` to every command:

```bash
turbocrypt config set-key secret.key
```

From this point on, TurboCrypt will use the stored copy unless a command
selects another key explicitly. Moving or deleting `secret.key` does not
change that copy.

### Step 3: Encrypt files

Once the key is configured, the same command works on a file or a whole
directory:

```bash
# A single file
turbocrypt encrypt document.pdf document.pdf.enc

# A directory tree
turbocrypt encrypt my-documents/ encrypted-documents/
```

### Step 4: Verify the result

Before deleting the original, authenticate the encrypted copy from beginning
to end:

```bash
turbocrypt verify encrypted-documents/
```

For a faster key check, `verify --quick` authenticates only the header. It does
not detect damage elsewhere in the file.

```bash
turbocrypt verify --quick encrypted-documents/
```

### Step 5: Decrypt files

Finally, supply the encrypted source and the destination for the plaintext.
As with encryption, the source may be a file or a directory:

```bash
# A single file
turbocrypt decrypt document.pdf.enc document.pdf

# A directory tree
turbocrypt decrypt encrypted-documents/ my-documents/
```

## Examples

### Password-protected keys

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

### Contexts

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

### In-place encryption

```bash
turbocrypt encrypt --key my-secret.key --in-place my-documents/
```

This replaces every source file. TurboCrypt first writes a temporary file and
then renames it over the original, but that does not substitute for a backup.

### Encrypted filenames

Pass `--encrypted-filenames` in both directions:

```bash
# Encrypt both contents and names
turbocrypt encrypt --key my-secret.key --encrypted-filenames source/ dest/

# The option is required again during decryption
turbocrypt decrypt --key my-secret.key --encrypted-filenames dest/ restored/
```

Each component of a path gets an opaque name. However, the directory
structure, file sizes and number of entries remain visible.

### Excluding files

`--exclude` may be repeated. For example, this skips logs and the repository
metadata:

```bash
turbocrypt encrypt --key my-secret.key \
  --exclude "*.log" \
  --exclude ".git/" \
  my-project/ encrypted-project/
```

### Dry runs

Use `--dry-run` to check paths and exclusions before starting the real job. It
prints the file count and total size without modifying anything:

```bash
turbocrypt encrypt --dry-run --key my-secret.key \
  --exclude "*.log" \
  --exclude "node_modules/" \
  large-project/ encrypted-project/
```

The same flag also works with `decrypt` and `verify`.

### Verification

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

### Listing a directory

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

### Defaults

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

Command-line options still take precedence over saved values.

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
is the team key runs `turbocrypt git unlock` alone. A key that has no
files in the store is refused, and the message says where it came from.

Several keys can share one repository. Each key keeps its files in a
directory of its own under `.enc/`, and a key holder sees only those.
A maintainer whose key is new to the repository joins with `init`
instead of `unlock`:

```bash
turbocrypt git init --key my.key     # joins the repository with a key of its own
```

The files of the other keys stay encrypted and are never touched. Keys
do not see each other's file lists, so a path that is private for one
key is an ordinary file for the others.

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

What the public can see: how many keys there are, how many private files
each one has, the shape of the directory tree, the size of each file,
which ones are executable, and when they change. Two files with the same name in different directories get the
same encrypted name. An entry cannot be moved or swapped without detection,
but a whole commit can be reverted to an older one, which is why signed
commits still matter.

Linked worktrees are not supported. On Windows, the hooks run through
the `sh` that comes with Git for Windows. The hooks are a convenience: `git commit --no-verify` skips them, and
`git add -f` can stage a plain file on purpose.

## All commands

These examples cover the current command set. For the exact usage accepted by
the installed version, run `turbocrypt --help` or `turbocrypt git help`.

### Key management

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

### Encryption

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

### Decryption

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

### Verification and listing

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

### Configuration commands

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

### Git

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

### Benchmarks and version

```bash
# Measure encryption throughput
turbocrypt bench

# Print the installed version
turbocrypt version
```

### Options

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

## File portability

Encrypted contents do not depend on a file's name or path. An encrypted file
can be moved or renamed without re-encrypting it.

With `--encrypted-filenames`, each path component is encrypted separately and
encoded with base84 so that it remains a valid name on Linux, macOS and
Windows. The directory structure is preserved. Use the option again when
decrypting.

## Configuration

TurboCrypt stores its JSON configuration here:

- macOS: `~/Library/Application Support/turbocrypt/config.json`
- Linux: `~/.local/share/turbocrypt/config.json`
- Windows: `%LOCALAPPDATA%\turbocrypt\config.json`

The file is created for owner read/write access only. Explicit command-line
options win over `TURBOCRYPT_KEY_FILE`, which in turn wins over values in this
file.

`config set-key` copies the key into the configuration; it does not retain the
path to the original key file. Also, if a command supplies one or more
`--exclude` patterns, they replace the configured exclusion list for that run.

## A few cautions

Generate keys with `turbocrypt keygen` and keep a backup away from the data it
protects. Password protection limits access to a key file at rest; changing
that password does not change the encryption key.

`keygen`, `change-password` and the configuration commands write a new file
and rename it into place. If the destination is a symbolic link, the link is
replaced by a regular file rather than followed.

Keep the plaintext until a full `verify` succeeds on the encrypted copy.
`--dry-run` is useful before a large directory job, particularly when exclude
patterns are involved.

More threads are not always faster. A small worker count often suits trees of
small files, while a larger buffer can help with very large files. Measure on
the storage you actually use; `turbocrypt bench` is available for that.

## Troubleshooting

### "Wrong decryption key, wrong context, or corrupted file header"

TurboCrypt cannot distinguish a wrong key or context from a foreign or damaged
header. Check the key and use exactly the context supplied during encryption.

### "Authentication failed" during decryption

The header was accepted, but the encrypted contents did not authenticate. Get
another copy of the file if one is available, because TurboCrypt will not
produce unauthenticated output.

### "Access denied" errors with large files

TurboCrypt memory-maps files larger than 1 MiB. If only large files fail,
check that the current user can read the source and write both the destination
directory and its existing file, if any.

### Performance is slow

Try fewer threads for a tree of small files; `--threads 2` or `--threads 4`
can beat a large worker count. For large files, storage speed is usually the
limit.

### Out of memory errors

Reduce the per-file buffer, for example with `--buffer-size 1048576`.

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
default key or `TURBOCRYPT_KEY_FILE` says. To replace it, run the same
command again with `--force`. `unlock` needs a key that already has
files in the store. `init` also takes a key that is new to the
repository. The `.gitprivate` list stays, so the files it names become
that key's private files at the next commit. Neither command rotates a
key.

### "the store has no files for" a key

`unlock` only takes a key that already has files in the store, since a
wrong key looks the same as a new one. A key that is new to the
repository joins with `turbocrypt git init --key <key-file>`.

### Hooks do not run from a GUI client

GUI clients run hooks with a minimal PATH. The installed hooks use the
absolute path of the `turbocrypt` binary recorded at `init` time. When the
binary moved, run `turbocrypt git init` again to refresh the hooks.

## Environment variables

`TURBOCRYPT_KEY_FILE` supplies the key path when `--key` was not given. The
Git `init` and `unlock` commands read it only once, when they bind the key to
the repository.

```bash
export TURBOCRYPT_KEY_FILE=~/.ssh/turbocrypt.key
turbocrypt encrypt source/ dest/  # uses the key above
```
