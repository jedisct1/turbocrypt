# Private files in a Git repository

[Back to the main README](../README.md)

A public repository shows every tracked file to everyone.

Sometimes a few files should stay readable by the maintainers only, such as an
`INTERNAL-DOC.md` with internal instructions or deployment notes in `docs/`.
TurboCrypt can keep those files encrypted in the repository while you edit them
in clear.

The encrypted copies live in a committed `.enc/` directory. Their names and
their contents look random.

Git hooks refresh `.enc/` before every commit and refresh the plain files after
a checkout, a merge or a rebase. The plain files are kept out of commits by a
local exclude rule.

The list of private files is encrypted too.

## Set up a repository

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
`.git/turbocrypt/key` in clear. The file has mode 0600 and its directory has
mode 0700.

A password-protected key is asked for once, at that moment. From then on the
repository uses that copy.

A new default key or a new `TURBOCRYPT_KEY_FILE` does not change it, and the
daily commands refuse `--key`.

## Share access with maintainers

Share the key with the other maintainers, outside of Git. When the key came
from a file, a copy of that file does the same job:

```bash
turbocrypt git export-key --password team.key
```

On another clone:

```bash
git clone git@github.com:acme/my-project
cd my-project
turbocrypt git unlock --key team.key # binds the key, installs the hooks and decrypts .enc/
```

`unlock` picks the key like `init` does. A maintainer whose default key is the
team key runs `turbocrypt git unlock` alone.

A key that has no files in the store is refused, and the message says where it
came from.

Several keys can share one repository. Each key keeps its files in a directory
of its own under `.enc/`, and a key holder sees only those. A maintainer whose
key is new to the repository joins with `init` instead of `unlock`:

```bash
turbocrypt git init --key my.key     # joins the repository with a key of its own
```

The files of the other keys stay encrypted and are never touched.

Keys do not see each other's file lists, so a path that is private for one key
is an ordinary file for the others.

## Daily use and recovery

From then on, daily work is plain Git. Edit a private file and commit. Pull and
switch branches. The hooks keep both sides in sync. A few things are worth
knowing:

- `git commit -a` decides "nothing to commit" before the hook runs. When only
  private files changed, run `turbocrypt git encrypt` first, or run
  `git commit` again. `turbocrypt git status` shows what is pending.

- A new file inside a private directory is encrypted at the next commit. Run
  `turbocrypt git encrypt` when you use `git commit -a`, because it cannot
  stage a new store entry on its own.

- `turbocrypt git rm docs/internal.md` makes a file public again. The plain
  file stays on disk as an ordinary untracked file.

- `turbocrypt git show docs/internal.md` prints the path of its entry under
  `.enc/`. It also tells whether git tracks the entry and which commit
  changed it last. The last line is a `git log` command ready to paste.
  Encrypted names contain characters that a shell and git would otherwise
  interpret. A removed entry keeps its store path as long as git has its
  history.

- A private file that you edited is never overwritten by a pull. You get a
  `conflict` line instead. `turbocrypt git decrypt --force <path>` takes the
  upstream version, `turbocrypt git encrypt --force <path>` keeps yours.

- `git clean -x` deletes the plain files, including edits made since the last
  commit. `turbocrypt git decrypt` brings back the committed version.

- `git stash --all` writes the plain files into local Git objects. Avoid it in
  a repository with private files.

- Do not keep a private file on one branch and a tracked public file at the
  same path on another. Switching to the branch that tracks it overwrites the
  plain file, and no hook can bring an edit back.

- The `.gitprivate` list accepts one path per line, `/path/to/file` for a file
  and `/path/to/dir/` for a directory. No wildcards, no negation.

## Metadata and limitations

The public can see how many keys there are, how many private files each one
has, the shape of the directory tree, the size of each file, which ones are
executable, and when they change.

Two files with the same name in different directories get the same encrypted
name.

An entry cannot be moved or swapped without detection, but a whole commit can
be reverted to an older one, which is why signed commits still matter.

Linked worktrees are not supported. On Windows, the hooks run through the `sh`
that comes with Git for Windows.

The hooks are a convenience: `git commit --no-verify` skips them, and
`git add -f` can stage a plain file on purpose.

See [Troubleshooting](troubleshooting.md#git-integration) for common Git
integration errors and recovery steps.
