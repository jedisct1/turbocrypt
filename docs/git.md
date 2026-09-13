# Private files in a Git repository

[Back to the main README](../README.md)

Maintainer notes, deployment scripts, and unfinished experiments belong with the project, even when they aren't ready to publish.

Leaving them untracked means they stay behind when you clone the repository on another machine.
Adding them to `.git/info/exclude` quiets `git status`, but doesn't give them a history or a backup.

TurboCrypt lets you commit encrypted copies of those files alongside the public code.
Their contents, names, and the list of private paths are encrypted.

Anyone with the key can restore them in a fresh clone through the same remote and history as the rest of the project.

The readable files stay at their original paths.
Notes open in an editor, scripts run as usual, and private source files can sit next to public ones.

There's no filesystem to mount or separate private directory to work in.

## Add your first private files

Start from an existing checkout with an untracked `NOTES.md` and an `ops/` directory containing your deployment scripts.

First, generate a key outside the repository and save it as your default:

```bash
mkdir -p ~/.config/turbocrypt
turbocrypt keygen --password ~/.config/turbocrypt/secret.key
turbocrypt config set-key ~/.config/turbocrypt/secret.key
```

If you already have a key, use it instead.
Keep a backup somewhere separate; losing the key means losing access to the encrypted files.

Then set up the checkout and select the paths that should stay private:

```bash
turbocrypt git init                  # use the default key and install hooks
turbocrypt git add NOTES.md ops/     # encrypt and stage a file and a directory
git commit -m "Add maintainer files"
git push
```

`init` asks for the key's password once and keeps an unlocked copy in `.git/turbocrypt/key`, so the hooks can run without prompting.

The original key file stays password-protected.
See [The checkout's key](#the-checkouts-key) for how that copy is used.

After the push, `NOTES.md` and `ops/deploy.sh` are still on disk.
Git tracks their encrypted copies under `.enc/`, with encrypted file and directory names.

TurboCrypt also creates a local `.gitprivate` file listing the paths you selected, and stores an encrypted copy of that list in `.enc/`.

Local rules in `.git/info/exclude` keep the readable files and `.gitprivate` out of ordinary `git add` operations.
Their names don't have to appear in a public `.gitignore` file.

The commit hook also refuses private paths that are tracked in clear.

## Work with private files

Edit the files where they are.
The hooks update and stage their encrypted copies before ordinary commits, and refresh the readable files after checkouts, merges, and rebases.

When only private files have changed, explicitly update the store before committing:

```bash
turbocrypt git status               # see which private files changed
turbocrypt git encrypt              # update and stage their encrypted copies
git commit -m "Update maintainer files"
git push
```

Git can decide there's "nothing to commit" before the pre-commit hook stages anything.
Running `turbocrypt git encrypt` first also handles new private files with `git commit -a`.

For partial commits such as `git commit <path>`, the hook leaves pending private changes out and reports them.

### Choose files and directories

Privacy applies to individual paths.
You can keep a private `AGENTS.md` at the repository root or add a single document inside an otherwise public directory:

```bash
turbocrypt git add AGENTS.md docs/internal.md
```

A directory rule such as `ops/` covers its subdirectories and future files, so new helpers are picked up at the next sync.

Existing Git ignore rules still apply: an ignored build log inside `ops/` isn't encrypted or backed up.
`turbocrypt git status` reports those files as `ignored`.

The selection lives in `.gitprivate`, which you can also edit directly:

```text
/NOTES.md
/ops/
/AGENTS.md
/docs/internal.md
```

Paths are relative to the repository root, one per line.
A trailing `/` selects a directory tree.
Wildcards and negation aren't supported.

Keep Git's control files, including `.gitignore`, `.gitattributes`, and `.gitmodules`, public; they can't be made private.

If Git already tracks a file in clear, remove it from the index before adding it to private management:

```bash
git rm --cached -- docs/internal.md # leave the readable copy on disk
turbocrypt git add docs/internal.md
git commit -m "Keep internal notes private from now on"
```

Earlier commits still contain the readable file.
This changes future commits and doesn't erase anything already published.

### Find a file's history

```bash
turbocrypt git show NOTES.md
```

This prints the file's path under `.enc/`, whether Git tracks that entry, and the last commit that changed it.
It ends with a `git log` command you can paste.

Use that command's quoting: encrypted names can contain characters that the shell or Git would otherwise interpret.

A removed entry can still be found while Git retains its history.

## Restore files in another clone

Clone normally, and copy your key to the other machine separately.
With the key saved at the path used above, run:

```bash
git clone git@github.com:acme/my-project.git
cd my-project
turbocrypt git unlock --key ~/.config/turbocrypt/secret.key
```

`unlock` binds the key to this checkout, installs the hooks, and restores `NOTES.md`, `ops/`, and the other private files at their original paths.

If this machine already has the right default key configured, just run `turbocrypt git unlock`.

Someone cloning without the key gets the public project and the encrypted store.
The private files don't appear at their readable paths.

They can work on the public code without installing TurboCrypt, as long as that code doesn't depend on private files.

## Share access or keep separate maintainer files

To work on the same private files, share the key outside of Git.
You can copy the original key file or export a password-protected copy of the key bound to this checkout:

```bash
turbocrypt git export-key --password ~/.config/turbocrypt/team.key
```

The other maintainer saves it outside their checkout and runs `turbocrypt git unlock --key <key-file>`.

Everyone with that key can decrypt the files protected by it, including their earlier versions in Git history.

Maintainers can also keep their own notes and scripts with separate keys.
Each key gets its own directory under `.enc/` and its own encrypted path list.

TurboCrypt syncs the files belonging to the checkout's key and leaves the other stores encrypted and untouched.

From a fresh clone, generate your own key outside the repository and create the notes and scripts you want to keep.
A key that's new to the repository starts with `init`:

```bash
turbocrypt keygen --password ~/.config/turbocrypt/my.key
turbocrypt git init --key ~/.config/turbocrypt/my.key
turbocrypt git add NOTES.md ops/
git commit -m "Add personal maintainer files"
git push
```

On later clones, use `unlock` with that key to get the files back.
`unlock` refuses a key with no store of its own, since that could mean the wrong key was selected.

Each checkout uses one key.
Separate keys don't share their path lists, so a path marked private by one maintainer isn't automatically private for another.

Agree separately on any paths that everyone should keep out of public commits.

## Develop a feature before publishing it

A branch can carry private source files and documentation for an unfinished feature.
Select those paths with `turbocrypt git add`, then commit and push as usual.

Teammates with the key can work on the feature while it depends on an unreleased API or is still an experiment.

When a file is ready to publish, take it out of private management and add the readable copy to Git:

```bash
turbocrypt git rm NOTES.md          # keep the readable file on disk
git add NOTES.md                    # explicitly stage it for publication
git commit -m "Publish maintainer notes"
git push
```

`turbocrypt git rm` stages removal of the encrypted entry and updates the private path list.
The file stays on disk as an ordinary untracked file until you add it.
Earlier encrypted versions remain in Git history.

A file covered by a directory rule stays private until you remove that rule or move the file outside the directory.

For example, `turbocrypt git rm ops/` stops managing the directory's files privately, while `turbocrypt git rm ops/deploy.sh` alone can't override the `ops/` rule.

Avoid keeping a private file on one branch and a tracked public file at the same path on another.
Switching to the branch that tracks it can overwrite the readable file before a hook runs, losing private edits.

Take particular care when returning to an older private branch after publishing its files.

## Conflicts and recovery

When both a private file and its encrypted copy have changed, TurboCrypt reports a `conflict` and keeps the local edits.
Choose which version to use:

```bash
turbocrypt git decrypt --force NOTES.md  # replace local edits with the store version
```

Or keep your working copy, editing it first if needed:

```bash
turbocrypt git encrypt --force NOTES.md  # replace and stage the encrypted version
git commit -m "Resolve private notes conflict"
```

Git can't merge encrypted contents itself.
If it leaves an entry under `.enc/` unmerged, follow the [merge conflict steps](troubleshooting.md#a-merge-conflict-on-a-private-file).

Commands that include ignored files also include the readable private files:

- `git clean -xfd` deletes them, including edits that haven't been encrypted.
  `turbocrypt git decrypt` restores files from the current `.enc/` store, but can't recover edits that never reached it.

- `git stash --all` writes readable private files into local Git objects.
  Avoid it in a checkout with private files.

See [Troubleshooting](troubleshooting.md#git-integration) for damaged entries, key errors, and other recovery steps.

## The checkout's key

On initial setup, `init` and `unlock` choose the key from `--key`, then `TURBOCRYPT_KEY_FILE`, then your saved default.

## Limitations

Encryption doesn't hide the repository's activity.

Branch names, commit messages, authors, and timestamps stay public, so choose them with that in mind when pushing unfinished work.
