#! /bin/sh

set -u

root=$(cd "$(dirname "$0")/.." && pwd)
if [ $# -ge 1 ]; then
    bin_dir=$(cd "$(dirname "$1")" && pwd)
else
    bin_dir="$root/zig-out/bin"
fi
work="$root/tmp/git_e2e"
A="$work/a"
B="$work/b"

export PATH="$bin_dir:$PATH"
export HOME="$work/home"
export GIT_CONFIG_GLOBAL="$work/home/gitconfig"
export GIT_CONFIG_NOSYSTEM=1
export GIT_AUTHOR_NAME=Test GIT_AUTHOR_EMAIL=test@example.invalid
export GIT_COMMITTER_NAME=Test GIT_COMMITTER_EMAIL=test@example.invalid
export XDG_DATA_HOME="$work/home/data"
unset TURBOCRYPT_KEY_FILE

current=""
step() { current="$*"; printf '== %s\n' "$*"; }
fail() { printf 'FAILED at "%s": %s\n' "$current" "$*" >&2; exit 1; }
expect_eq() { [ "$1" = "$2" ] || fail "expected '$2', got '$1'"; }
expect_file() { [ -f "$1" ] || fail "missing file $1"; }
expect_no_file() { [ ! -e "$1" ] || fail "unexpected file $1"; }
expect_content() { expect_file "$1"; expect_eq "$(cat "$1")" "$2"; }
expect_clean() { [ -z "$(git status --short)" ] || fail "working tree not clean: $(git status --short)"; }
mode() { stat -c %a "$1" 2>/dev/null || stat -f %Lp "$1"; }
# git commit -a decides "nothing to commit" before the hook stages private changes.
# It cannot stage a new store entry on a retry either, so the store is refreshed first.
commit_all() { quiet turbocrypt git encrypt && git commit -qam "$1"; }
quiet() { "$@" >/dev/null 2>&1; }

rm -rf "$work"
mkdir -p "$work/home"
git config --global init.defaultBranch main

step "init needs an existing key"
git init -q "$A" && cd "$A" || fail "git init"
echo "# public" > README.md
printf '*.log\n' > .gitignore
git add README.md .gitignore && git commit -qm "public" || fail "first commit"
quiet turbocrypt git init && fail "init without a key succeeded"
turbocrypt git init 2>&1 | grep -q 'turbocrypt keygen' || fail "no keygen hint"
expect_no_file .git/turbocrypt/key
expect_no_file .enc

step "init binds the default key"
quiet turbocrypt keygen "$work/secret.key" || fail "keygen"
quiet turbocrypt config set-key "$work/secret.key" || fail "set-key"
quiet turbocrypt git init || fail "init"
expect_file .enc/.turbocrypt
expect_file .enc/.gitattributes
expect_file .gitprivate
expect_file .git/turbocrypt/key
cmp -s .git/turbocrypt/key "$work/secret.key" || fail "the bound key is not the default key"
expect_eq "$(mode .git/turbocrypt)" "700"
expect_eq "$(mode .git/turbocrypt/key)" "600"
expect_file .git/hooks/pre-commit
grep -q '^/.gitprivate$' .git/info/exclude || fail "exclude block missing"
quiet turbocrypt git init || fail "init twice"

step "a changed default does not touch the bound key"
quiet turbocrypt keygen "$work/other.key" || fail "keygen"
quiet turbocrypt config set-key "$work/other.key" || fail "set-key"
quiet turbocrypt git init || fail "init with another default key"
cmp -s .git/turbocrypt/key "$work/secret.key" || fail "the default key replaced the bound key"
(export TURBOCRYPT_KEY_FILE="$work/other.key"; quiet turbocrypt git init) || fail "init with another environment key"
cmp -s .git/turbocrypt/key "$work/secret.key" || fail "the environment replaced the bound key"
turbocrypt git init --key "$work/other.key" 2>&1 | grep -q 'different key' || fail "a different --key was not refused"
cmp -s .git/turbocrypt/key "$work/secret.key" || fail "init --key replaced the bound key"
quiet turbocrypt git init --key "$work/secret.key" || fail "init --key with the bound key"
turbocrypt git status --key "$work/secret.key" 2>&1 | grep -q 'init and unlock' || fail "status accepted --key"
quiet turbocrypt git status extra && fail "status accepted an argument"

step "add files and a directory"
echo "secret agent notes" > AGENT.md
mkdir -p docs ops
echo "internal" > docs/internal.md
printf '#!/bin/sh\necho hi\n' > ops/deploy.sh && chmod +x ops/deploy.sh
echo "junk" > ops/build.log
quiet turbocrypt git add AGENT.md docs/internal.md ops/ || fail "add"
grep -q '^/ops/$' .gitprivate || fail "manifest line"
expect_eq "$(git status --short | grep -c '^??')" "0"
git commit -qm "private" || fail "commit"
expect_clean
git ls-files -z | tr '\0' '\n' | while IFS= read -r f; do
    case "$f" in
        .enc/*|.gitignore|README.md) ;;
        *) fail "plain path tracked: $f" ;;
    esac
done || exit 1
expect_eq "$(git ls-files -s | grep -c '^100755')" "1"
quiet turbocrypt git status || fail "status"
expect_eq "$(turbocrypt git status 2>&1 | grep -c '  ignored    ops/build.log')" "1"

step "no-op encrypt leaves no diff"
quiet turbocrypt git encrypt || fail "encrypt"
expect_clean

step "clone and unlock"
git clone -q "$A" "$B" || fail "clone"
quiet turbocrypt git export-key "$work/team.key" || fail "export-key"
cmp -s "$work/team.key" "$work/secret.key" || fail "export-key wrote another key"
cd "$B" || fail "cd b"
expect_no_file AGENT.md
turbocrypt git unlock 2>&1 | grep -q 'the default key in' || fail "a wrong default key was not named"
(export TURBOCRYPT_KEY_FILE="$work/other.key"; turbocrypt git unlock 2>&1) | grep -q 'other.key (TURBOCRYPT_KEY_FILE)' || fail "a wrong environment key was not named"
turbocrypt git unlock --key "$work/other.key" 2>&1 | grep -q 'other.key (--key)' || fail "a wrong --key was not named"
expect_no_file .git/turbocrypt/key
(export TURBOCRYPT_KEY_FILE="$work/team.key"; quiet turbocrypt git unlock) || fail "unlock"
cmp -s .git/turbocrypt/key "$work/team.key" || fail "the environment key was not bound"
expect_content AGENT.md "secret agent notes"
expect_content docs/internal.md "internal"
[ -x ops/deploy.sh ] || fail "exec bit lost"
expect_no_file ops/build.log
expect_file .git/hooks/post-checkout
expect_clean
quiet turbocrypt git unlock --key "$work/other.key" && fail "unlock with a different key succeeded"
quiet turbocrypt git unlock --key "$work/other.key" --force && fail "unlock --force with a wrong key succeeded"
cmp -s .git/turbocrypt/key "$work/team.key" || fail "a wrong key was bound"

step "a damaged repository key fails and is not replaced"
printf 'damaged' > .git/turbocrypt/key
turbocrypt git status 2>&1 | grep -q 'cannot read the repository key' || fail "the damaged key was not reported"
quiet turbocrypt git unlock --key "$work/team.key" --force && fail "unlock replaced a damaged key"
(export TURBOCRYPT_KEY_FILE="$work/team.key"; quiet turbocrypt git init) && fail "init replaced a damaged key"
expect_content .git/turbocrypt/key "damaged"
cp "$work/team.key" .git/turbocrypt/key

step "git add -A stages nothing private"
git add -A && expect_eq "$(git diff --cached --name-only | wc -l | tr -d ' ')" "0"

step "edit, commit through the hook, pull"
cd "$A" && echo "more notes" >> AGENT.md
commit_all "edit" || fail "commit -a"
expect_clean
cd "$B" && git pull -q || fail "pull"
expect_eq "$(cat AGENT.md)" "$(printf 'secret agent notes\nmore notes')"

step "a local edit survives a pull as a conflict"
echo "b local" >> docs/internal.md
cd "$A" && echo "a upstream" >> docs/internal.md && commit_all "a edits" || fail "commit"
cd "$B" && git pull -q || fail "pull"
expect_eq "$(cat docs/internal.md)" "$(printf 'internal\nb local')"
turbocrypt git status >/dev/null 2>&1 && fail "status should exit 1 on a conflict"
quiet turbocrypt git decrypt --force docs/internal.md || fail "decrypt --force"
expect_eq "$(cat docs/internal.md)" "$(printf 'internal\na upstream')"

step "a private file added on another clone is ignored before it appears"
cd "$B" && echo "later" > later.md && quiet turbocrypt git add later.md && git commit -qm "later" || fail "add on b"
cd "$A" && git pull -q "$B" main || fail "pull from b"
expect_content later.md "later"
git check-ignore -q later.md || fail "later.md is not ignored"
git add -A && expect_eq "$(git diff --cached --name-only | wc -l | tr -d ' ')" "0"
cd "$B"

step "a tracked file cannot become private"
echo "leak" > leak.md && git add -f leak.md
quiet turbocrypt git add leak.md && fail "add of a tracked file succeeded"
git reset -q leak.md && rm leak.md

step "clean -xfd, then decrypt restores"
git clean -xfdq
expect_no_file AGENT.md
quiet turbocrypt git decrypt || fail "decrypt"
expect_content docs/internal.md "$(printf 'internal\na upstream')"

step "partial commit stays out"
echo "x" >> AGENT.md
echo "pub" >> README.md
git commit -qm "partial" README.md || fail "partial commit"
git show --name-only --format= HEAD | grep -q '\.enc/' && fail "partial commit took private changes"
commit_all "rest" || fail "commit rest"
git show --name-only --format= HEAD | grep -q '\.enc/' || fail "second commit missed the private change"

step "rm makes a file public again"
quiet turbocrypt git rm docs/internal.md || fail "rm"
grep -q internal .gitprivate && fail "manifest still lists the file"
expect_file docs/internal.md
expect_eq "$(git status --short docs)" "?? docs/"
git commit -qm "internal removed from the store" || fail "commit"
rm -r docs

step "rm of a file under a directory line keeps its entry"
turbocrypt git rm ops/deploy.sh > "$work/rm.log" 2>&1 || fail "rm failed"
grep -q "stays private" "$work/rm.log" || fail "rm did not explain the directory line"
expect_eq "$(turbocrypt git status 2>&1 | grep -c '  ok         ops/deploy.sh')" "1"

step "a replayed manifest cannot expose a newer entry"
cd "$A" && echo "extra" > extra.md && quiet turbocrypt git add extra.md && git commit -qm "extra" || fail "add extra"
replayed=$(git diff --name-only -z --diff-filter=M HEAD~1 HEAD -- .enc | tr '\0' '\n')
expect_eq "$(printf '%s\n' "$replayed" | wc -l | tr -d ' ')" "1"
git clone -q "$A" "$work/replay" && cd "$work/replay" || fail "clone"
git --literal-pathspecs checkout -q HEAD~1 -- "$replayed" && git commit -qm "replayed manifest" || fail "replay commit"
git clone -q "$work/replay" "$work/victim" && cd "$work/victim" || fail "clone victim"
quiet turbocrypt git unlock --key "$work/team.key" || fail "unlock victim"
expect_content extra.md "extra"
git check-ignore -q extra.md || fail "extra.md is not ignored after a replayed manifest"
git add -A && expect_eq "$(git diff --cached --name-only | wc -l | tr -d ' ')" "0"
git add -f extra.md && turbocrypt git encrypt >/dev/null 2>&1 && fail "a tracked store path was accepted"
git reset -q extra.md
cd "$B"

step "rm of a directory unignores its files"
mkdir -p ops2 && echo "two" > ops2/file.md && quiet turbocrypt git add ops2/ && git commit -qm "ops2" || fail "add ops2"
quiet turbocrypt git rm ops2/ || fail "rm ops2"
git check-ignore -q ops2/file.md && fail "ops2/file.md is still ignored"
expect_eq "$(git status --short ops2)" "?? ops2/"
rm -r ops2 && git commit -qm "ops2 gone" || fail "commit"

if [ "$(uname)" = Darwin ]; then
step "core.precomposeunicode=yes composes a decomposed name"
git config core.precomposeunicode yes
nfd=$(printf 're\314\201sume\314\201.md')
echo "unicode secret" > "$nfd"
quiet turbocrypt git add "$nfd" || fail "add decomposed name"
git add -A
expect_eq "$(git diff --cached --name-only -z | tr '\0' '\n' | grep -v '^\.enc/' | grep -c .)" "0"
git commit -qm "unicode" || fail "commit unicode"
git ls-files -z | tr '\0' '\n' | grep -v '^\.enc/' | grep -q 'sum' && fail "plain unicode name tracked"
git config core.precomposeunicode true
fi

step "branch switch mirrors git"
git switch -qc feature || fail "switch"
echo "feature only" > ops/feature.txt
commit_all "feature file" || fail "commit"
git switch -q main || fail "switch main"
expect_no_file ops/feature.txt
git switch -q feature || fail "switch feature"
expect_content ops/feature.txt "feature only"
git switch -q main

step "squash merge, then commit"
git merge -q --squash feature >/dev/null 2>&1 || fail "squash"
git commit -qm "squashed" || fail "squash commit"
expect_content ops/feature.txt "feature only"

step "rebase keeps the plain files in sync"
git switch -qc topic main
echo "topic" > ops/topic.txt && commit_all "topic file" || fail "commit"
git switch -q main && echo "again" >> README.md && git commit -qam "main moves" || fail "commit"
git switch -q topic && git rebase -q main || fail "rebase"
expect_content ops/topic.txt "topic"
git switch -q main

step "cherry-pick syncs through post-commit"
git cherry-pick topic >/dev/null || fail "cherry-pick"
expect_content ops/topic.txt "topic"

step "merge conflict resolved with encrypt --force"
git switch -qc left && echo "left" > ops/hosts.txt && commit_all "left" || fail "commit"
git switch -q main && echo "right" > ops/hosts.txt && commit_all "right" || fail "commit"
git merge -q left >/dev/null 2>&1 && fail "merge should conflict"
expect_eq "$(git ls-files -u | cut -f2 | sort -u | wc -l | tr -d ' ')" "1"
echo "merged" > ops/hosts.txt
quiet turbocrypt git encrypt --force ops/hosts.txt || fail "encrypt --force"
expect_eq "$(git ls-files -u | wc -l | tr -d ' ')" "0"
git commit -qm "merged" || fail "merge commit"
expect_content ops/hosts.txt "merged"

step "swapped entries are refused"
cd "$B" && cp -R .enc "$work/enc-good"
files=$(find .enc -type f ! -name '.*' | head -2)
f1=$(printf '%s\n' "$files" | sed -n 1p); f2=$(printf '%s\n' "$files" | sed -n 2p)
mv "$f1" "$work/tmpswap" && mv "$f2" "$f1" && mv "$work/tmpswap" "$f2"
turbocrypt git decrypt 2>&1 | grep -q 'bad\|corrupted' || fail "swap not reported"
rm -rf .enc && cp -R "$work/enc-good" .enc

step "a flipped byte is refused"
entry=$(find .enc -type f ! -name '.*' | head -1)
printf '\000' | dd of="$entry" bs=1 seek=40 conv=notrunc 2>/dev/null
turbocrypt git decrypt 2>&1 | grep -q 'bad\|corrupted' || fail "corruption not reported"
rm -rf .enc && cp -R "$work/enc-good" .enc
git status --short | grep -q '.enc' && fail "store not restored"

step "renaming the checkout and the remote changes nothing"
cd "$work" && mv b renamed && cd renamed || fail "mv"
git remote set-url origin "$work/somewhere-else"
before=$(git ls-files -s .enc | awk '{print $2}' | sort | tr '\n' ' ')
quiet turbocrypt git encrypt || fail "encrypt after rename"
after=$(git ls-files -s .enc | awk '{print $2}' | sort | tr '\n' ' ')
expect_eq "$after" "$before"
cd "$work" && mv renamed b

step "archive, git init, unlock"
cd "$A" && git archive --format=tar -o "$work/archive.tar" HEAD || fail "archive"
mkdir -p "$work/c" && cd "$work/c" && tar xf "$work/archive.tar" || fail "untar"
git init -q || fail "git init"
(export TURBOCRYPT_KEY_FILE="$work/other.key"; quiet turbocrypt git unlock --key "$work/team.key") || fail "unlock from archive"
cmp -s .git/turbocrypt/key "$work/team.key" || fail "--key did not win over the environment"
expect_content AGENT.md "$(printf 'secret agent notes\nmore notes')"

cd "$A"
step "plain git commit picks private changes up on the second try"
echo "quirk" >> AGENT.md
git commit -qm "quirk" >/dev/null 2>&1 && fail "first commit should report nothing to commit"
git commit -qm "quirk" || fail "second commit"
expect_clean
git show --name-only --format= HEAD | grep -q '\.enc/' || fail "the private change is not in the commit"

step "a second key joins the repository"
git clone -q "$A" "$work/d" && cd "$work/d" || fail "clone"
turbocrypt git unlock --key "$work/other.key" 2>&1 | grep -q 'other.key (--key).*new to this repository' || fail "unlock did not explain a key without files"
expect_no_file .git/turbocrypt/key
quiet turbocrypt git init --key "$work/other.key" || fail "init with a second key"
cmp -s .git/turbocrypt/key "$work/other.key" || fail "the second key was not bound"
expect_no_file AGENT.md
expect_file .gitprivate
expect_eq "$(find .enc -mindepth 1 -maxdepth 1 -type d | wc -l | tr -d ' ')" "2"
turbocrypt git status 2>&1 | grep -q 'Other keys : 1' || fail "status does not count the other key"
echo "second" > second.md
echo "d agent" > AGENT.md
quiet turbocrypt git add second.md AGENT.md && git commit -qm "second key" || fail "add with the second key"
expect_eq "$(git status --short | grep -c '^??')" "0"
quiet turbocrypt git encrypt || fail "encrypt with the second key"
expect_clean
cd "$A" || fail "cd a"
agent_before=$(cat AGENT.md)
git pull -q "$work/d" main || fail "pull from d"
expect_no_file second.md
expect_eq "$(cat AGENT.md)" "$agent_before"
turbocrypt git status 2>&1 | grep -q 'Other keys : 1' || fail "status does not count the second key"
turbocrypt git status 2>&1 | grep -q 'second.md' && fail "the second key's file shows in status"
quiet turbocrypt git encrypt || fail "encrypt after the pull"
expect_clean
quiet turbocrypt git unlock --key "$work/other.key" && fail "a different key was bound without --force"
cmp -s .git/turbocrypt/key "$work/secret.key" || fail "the bound key changed"

step "init --force rebinds to a key that is new to the store"
git clone -q "$A" "$work/e" && cd "$work/e" || fail "clone"
quiet turbocrypt git unlock --key "$work/team.key" || fail "unlock"
expect_content AGENT.md "$agent_before"
quiet turbocrypt keygen "$work/third.key" || fail "keygen"
quiet turbocrypt git init --key "$work/third.key" && fail "init rebound without --force"
quiet turbocrypt git init --key "$work/third.key" --force || fail "init --force"
cmp -s .git/turbocrypt/key "$work/third.key" || fail "the third key was not bound"
expect_content AGENT.md "$agent_before"
git commit -qm "third key" || fail "commit"
expect_eq "$(find .enc -mindepth 1 -maxdepth 1 -type d | wc -l | tr -d ' ')" "3"
turbocrypt git status 2>&1 | grep -q 'Other keys : 2' || fail "status does not count both other keys"
expect_eq "$(turbocrypt git status 2>&1 | grep -c '  ok         AGENT.md')" "1"

step "unlock --force adopts a store rebuilt with another key"
git init -q "$work/r" && cd "$work/r" || fail "git init"
echo "note" > note.md
(export TURBOCRYPT_KEY_FILE="$work/other.key"; quiet turbocrypt git init) || fail "init from the environment"
cmp -s .git/turbocrypt/key "$work/other.key" || fail "the environment key was not bound"
quiet turbocrypt git add note.md && git commit -qm "note" || fail "commit"
git clone -q "$work/r" "$work/r2" && cd "$work/r2" || fail "clone"
quiet turbocrypt git unlock || fail "unlock from the default key"
cmp -s .git/turbocrypt/key "$work/other.key" || fail "the default key was not bound"
expect_content note.md "note"
cd "$work/r" && rm -f .git/turbocrypt/key .git/turbocrypt/state && rm -r .enc
quiet turbocrypt git init --key "$work/secret.key" || fail "init --key on a rebuilt store"
cmp -s .git/turbocrypt/key "$work/secret.key" || fail "init --key did not bind the key"
git add -A && git commit -qm "store rebuilt with another key" || fail "commit"
cd "$work/r2" && git pull -q || fail "pull"
quiet turbocrypt git unlock --key "$work/secret.key" && fail "a different key was bound without --force"
quiet turbocrypt git unlock --key "$work/secret.key" --force || fail "unlock --force with the new key"
cmp -s .git/turbocrypt/key "$work/secret.key" || fail "the new key was not bound"
expect_content note.md "note"

printf 'All git integration steps passed\n'
