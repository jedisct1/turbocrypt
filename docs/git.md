# Keep private files in a Git repository

[Back to the main README](../README.md)

You may want maintainer notes, deployment scripts, or unfinished code to travel with a project without publishing them. TurboCrypt lets you commit encrypted copies of those files alongside your public code.

You still open and edit the files at their normal paths. When another maintainer clones the repository, they can restore the private files with the key. Someone without it gets the public project and the encrypted copies.

## 1. Choose a key

Start in an existing Git checkout. For this example, we'll keep an untracked `NOTES.md` file and an `ops/` directory private. If you use `git worktree`, make a separate clone for this setup; linked worktrees aren't supported.

If you don't already have a key, create one outside the repository:

```bash
mkdir -p ~/.config/turbocrypt
turbocrypt keygen --password ~/.config/turbocrypt/secret.key
```

Keep a backup of the key somewhere separate. You'll need it when you move to another computer or restore the repository from a clone.

## 2. Set up the checkout

From the repository, run:

```bash
turbocrypt git init --key ~/.config/turbocrypt/secret.key
```

If you've already saved the right key as your default, `turbocrypt git init` is enough.

TurboCrypt installs Git hooks, which are small scripts Git runs during commits and branch changes. It also saves an unlocked copy of the key inside `.git/` so those scripts don't need to ask for a password every time. Your original key file keeps its password protection.

## 3. Add your private files

Choose the files and folders to encrypt, then commit:

```bash
turbocrypt git add NOTES.md ops/
git commit -m "Add maintainer files"
git push
```

The readable files stay in place. Git tracks encrypted copies under `.enc/`, including encrypted filenames and an encrypted list of private paths.

TurboCrypt keeps a readable version of that list in `.gitprivate` for you. It adds local Git ignore rules for the private files and the list, so their names don't need to appear in a public `.gitignore`.

You can keep using your editor and scripts as usual. Other people can work on the public project without installing TurboCrypt, as long as the public code doesn't need the private files to build or run.

## Commit your next changes

After editing private files, run:

```bash
turbocrypt git status
turbocrypt git encrypt
git commit -m "Update maintainer files"
git push
```

`status` shows what's changed. `encrypt` updates the encrypted copies and stages them for the commit.

The commit hook also updates private files during ordinary commits. Still, running `turbocrypt git encrypt` first is a useful habit: if only private files changed, Git may otherwise report "nothing to commit" before the hook gets a chance to run. This also handles new private files when you use `git commit -a`.

If you commit only named paths, as in `git commit README.md`, the hook leaves pending private changes out and tells you about them.

After a checkout, merge, or rebase, the hooks update your readable files from the encrypted copies. If both versions changed, TurboCrypt keeps your local edits and reports a conflict.

## Add more files over time

You can select an individual file anywhere in the project:

```bash
turbocrypt git add AGENTS.md docs/internal.md
```

A folder selection such as `ops/` includes its subfolders and files you add later. Existing Git ignore rules still apply, though. For example, an ignored build log under `ops/` won't be encrypted or backed up. `turbocrypt git status` marks it as `ignored`.

You can also edit `.gitprivate` directly. It has one path per line, relative to the repository root:

```text
/NOTES.md
/ops/
/AGENTS.md
/docs/internal.md
```

A trailing `/` selects a whole folder. Use exact paths; wildcards and rules that undo another selection aren't supported. Git's own control files, such as `.gitignore`, `.gitattributes`, and `.gitmodules`, must stay public.

### Make an already tracked file private

First, stop tracking its readable copy without deleting it from disk:

```bash
git rm --cached -- docs/internal.md
turbocrypt git add docs/internal.md
git commit -m "Keep internal notes private from now on"
```

Earlier commits still contain the readable file. This protects future versions; it doesn't remove anything you've already published.

## Restore private files in another clone

Clone the project normally, and transfer your key to the other computer separately:

```bash
git clone git@github.com:acme/my-project.git
cd my-project
turbocrypt git unlock --key ~/.config/turbocrypt/secret.key
```

`unlock` saves the key for this checkout, installs the hooks, and restores your private files at their original paths. If the right key is already your default, you can leave out `--key`.

Use `unlock` when the repository already has files encrypted with your key. Use `init` when you're adding a new key to the project for the first time.

## Give another maintainer access

Share a copy of the key outside Git. You can use your original key file or export a password-protected copy from this checkout:

```bash
turbocrypt git export-key --password ~/.config/turbocrypt/team.key
```

The other maintainer then runs:

```bash
turbocrypt git unlock --key ~/.config/turbocrypt/team.key
```

Everyone with that key can read and update the files it protects, including older versions in Git history.

### Keep your own maintainer files

Different maintainers can use different keys in the same repository. Each key gets its own encrypted files and private path list under `.enc/`.

To add your own collection, start from a fresh clone, create the files you want to keep, and run:

```bash
turbocrypt keygen --password ~/.config/turbocrypt/my.key
turbocrypt git init --key ~/.config/turbocrypt/my.key
turbocrypt git add NOTES.md ops/
git commit -m "Add personal maintainer files"
git push
```

On later clones, use `unlock` with `my.key` to restore them. TurboCrypt leaves other keys' encrypted files alone.

Each checkout uses one key. Because the private path lists are separate, a path you mark private isn't automatically private for everyone else. Agree with the other maintainers about any paths that should never be committed publicly.

## Publish a private file

When an experiment or document is ready to share, remove it from private management and explicitly add the readable copy:

```bash
turbocrypt git rm NOTES.md          # leave the readable file on disk
git add NOTES.md                    # stage it for publication
git commit -m "Publish maintainer notes"
git push
```

`turbocrypt git rm` stages removal of the encrypted copy and updates the private path list. Earlier encrypted versions remain in Git history.

If a file is covered by a folder rule, remove that rule or move the file out of the folder first. For example, `turbocrypt git rm ops/deploy.sh` can't make an exception to an `ops/` rule; `turbocrypt git rm ops/` removes the rule for the whole folder.

Be careful when the same path is private on one branch and public on another. Switching to a branch that tracks the readable file can overwrite your private edits before a hook runs. Save those edits separately before switching, especially when returning to an older branch after publishing a feature.

## Find an older version

Start by asking TurboCrypt where the file is stored:

```bash
turbocrypt git show NOTES.md
```

It prints the encrypted path, the last commit that changed it, and a `git log` command you can copy. Use the quoting in that command, since encrypted names can contain characters your shell would otherwise interpret.

You can find removed entries this way, too, as long as Git still has their history.

## Resolve a conflict

When both your readable file and its encrypted copy have changed, decide which version you want to keep.

To use the encrypted version from the repository, first save any local edits you want to keep, then run:

```bash
turbocrypt git decrypt --force NOTES.md
```

To keep your working file instead, edit it until it's right, then run:

```bash
turbocrypt git encrypt --force NOTES.md
git commit -m "Resolve private notes conflict"
```

Git can't merge encrypted contents itself. If Git reports an unmerged entry under `.enc/`, follow the [merge conflict walkthrough](troubleshooting.md#a-merge-conflict-on-a-private-file).

## Recover files after a cleanup

Private files are ignored by Git, so `git clean -xfd` deletes them along with other ignored files. You can restore the last encrypted versions with:

```bash
turbocrypt git decrypt
```

Edits that never reached `.enc/` can't be restored this way. Run `turbocrypt git encrypt` and commit before cleaning the checkout.

Also avoid `git stash --all` here: it puts readable private files into local Git storage. Commit their encrypted copies before switching tasks instead.

## The checkout's key

During setup, `init` and `unlock` choose a key from `--key`, then `TURBOCRYPT_KEY_FILE`, then your saved default. After that, this checkout uses its copy in `.git/turbocrypt/key`.

Changing your default key or the original key file's password doesn't change that copy. It is stored without password protection so hooks can use it, so treat access to the checkout as access to its private files.

If you intentionally need to replace the checkout's key, `init` and `unlock` accept `--force`. This doesn't re-encrypt Git history, and the existing `.gitprivate` selections stay in place. For separate collections, a separate clone is easier to keep track of.

## What stays visible

File contents, names, and the private path list are encrypted. People can still see the number and sizes of encrypted files, their folder structure, and when they change.

Branch names, commit messages, authors, and timestamps also remain public. Keep that in mind when writing commit messages for private work.

Git integration currently handles regular files up to 256 MiB each. Use ordinary file encryption for larger files. Symbolic links aren't supported as private files.

For key errors, damaged encrypted copies, or hooks that stopped working, see [Troubleshooting](troubleshooting.md#git-integration).
