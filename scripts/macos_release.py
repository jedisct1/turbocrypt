#!/usr/bin/env python3
"""Build signed macOS archives and maintain the separate Homebrew tap locally."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parent.parent
TAP_REPO = "jedisct1/homebrew-turbocrypt"
FUSE_COMMIT = "6a245daa2b914e6c05fafe687c0aaef7cb3deb20"
SIGNING_REQUIREMENT = (
    '=anchor apple generic and identifier "org.pureftpd.turbocrypt" '
    'and certificate leaf[subject.OU] = "888H8YF752" '
    'and certificate leaf[field.1.2.840.113635.100.6.1.13] exists'
)


def run(*args, cwd=ROOT):
    subprocess.run([str(arg) for arg in args], cwd=cwd, check=True)


def output(*args, cwd=ROOT):
    return subprocess.check_output(
        [str(arg) for arg in args], cwd=cwd, text=True, stderr=subprocess.STDOUT
    ).rstrip()


def version():
    match = re.search(r'\.version\s*=\s*"(\d+\.\d+\.\d+)"',
                      (ROOT / "build.zig.zon").read_text())
    if not match:
        raise ValueError("build.zig.zon must contain a stable x.y.z version")
    return match[1]


def archive_path(ver):
    return ROOT / "dist" / f"turbocrypt_{ver}_macos_universal.tar.gz"


def sha256(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def verify_binary(binary, ver):
    run("codesign", "--verify", "--strict", "--all-architectures",
        "-R", SIGNING_REQUIREMENT, binary)
    if set(output("lipo", "-archs", binary).split()) != {"arm64", "x86_64"}:
        raise ValueError("The executable must contain ARM64 and Intel slices")
    if "libfuse" in output("otool", "-L", binary):
        raise ValueError("The release executable must link fuse-t statically")
    if output(binary, "version") != f"turbocrypt {ver}":
        raise ValueError("The executable's version doesn't match build.zig.zon")


def inspect_archive(archive, ver):
    # Read only these regular files; don't extract archive paths or symlinks.
    with tempfile.TemporaryDirectory(prefix="turbocrypt-verify-") as tmp:
        with tarfile.open(archive) as bundle:
            for name in ("turbocrypt", "BUILD-INFO.json"):
                matches = [entry for entry in bundle.getmembers() if entry.name == name]
                if len(matches) != 1 or not matches[0].isfile():
                    raise ValueError(f"Archive must contain exactly one regular {name}")
                with bundle.extractfile(matches[0]) as src:
                    with (Path(tmp) / name).open("wb") as dst:
                        shutil.copyfileobj(src, dst)
        binary = Path(tmp) / "turbocrypt"
        binary.chmod(0o755)
        verify_binary(binary, ver)
        info = json.loads((Path(tmp) / "BUILD-INFO.json").read_text())
        if info["version"] != ver:
            raise ValueError("Archive metadata has the wrong version")
        with tarfile.open(archive) as bundle:
            for name in ("source/turbocrypt/build.zig", "source/libfuse3/LGPL2.txt",
                         "source/libfuse3/lib/fuse.c", "source/README.md"):
                if name not in bundle.getnames() or not bundle.getmember(name).isfile():
                    raise ValueError(f"Archive is missing rebuild sources: {name}")
        return info


def render_formula(ver, digest):
    clauses = SIGNING_REQUIREMENT.split(" and ")
    ruby_clauses = []
    for index, clause in enumerate(clauses):
        if index < len(clauses) - 1:
            clause += " and "
        ruby_clauses.append(f"'{clause}'" if '"' in clause else json.dumps(clause))
    requirement = " \\\n                 ".join(ruby_clauses)
    return f'''class Turbocrypt < Formula
  desc "Fast file, directory, and Git encryption"
  homepage "https://github.com/jedisct1/turbocrypt"
  url "https://github.com/{TAP_REPO}/releases/download/{ver}/turbocrypt_{ver}_macos_universal.tar.gz"
  version "{ver}"
  sha256 "{digest}"
  license all_of: ["MIT", "LGPL-2.1-only"]

  depends_on :macos

  on_macos do
    depends_on macos: :ventura
  end

  # Preserve the upstream Developer ID signature.
  skip_clean "bin/turbocrypt"

  def install
    bin.install "turbocrypt"
    bash_completion.install "shell-completion/bash/turbocrypt"
    zsh_completion.install "shell-completion/zsh/_turbocrypt"
    fish_completion.install "shell-completion/fish/turbocrypt.fish"
    pkgshare.install "source", "BUILD-INFO.json"
    system "/usr/bin/codesign", "--verify", "--strict", "--all-architectures",
           "-R", {requirement}, bin/"turbocrypt"
  end

  def caveats
    <<~EOS
      To use `turbocrypt mount`, install fuse-t:
        brew install --cask fuse-t
    EOS
  end

  test do
    assert_match version.to_s, shell_output("#{{bin}}/turbocrypt version 2>&1")
    system "/usr/bin/codesign", "--verify", "--strict", "--all-architectures",
           "-R", {requirement}, bin/"turbocrypt"
    (testpath/"plain.txt").write "Homebrew encryption test\\n"
    system bin/"turbocrypt", "keygen", "test.key"
    system bin/"turbocrypt", "encrypt", "--key", "test.key", "plain.txt", "encrypted"
    system bin/"turbocrypt", "decrypt", "--key", "test.key", "encrypted", "restored.txt"
    assert_equal (testpath/"plain.txt").read, (testpath/"restored.txt").read
  end
end
'''


def formula(tap, ver):
    archive = archive_path(ver)
    inspect_archive(archive, ver)
    path = tap / "Formula" / "turbocrypt.rb"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_formula(ver, sha256(archive)))
    print(f"Updated {path}")


def build_fuse(dist):
    source = dist / "libfuse3-source"
    if not source.exists():
        run("git", "clone", "https://github.com/macos-fuse-t/libfuse3.git", source)
        run("git", "checkout", "--detach", FUSE_COMMIT, cwd=source)
    if output("git", "rev-parse", "HEAD", cwd=source) != FUSE_COMMIT or output(
            "git", "status", "--porcelain", cwd=source):
        raise ValueError(f"{source} must be a clean checkout of {FUSE_COMMIT}")
    for arch in ("arm64", "x86_64"):
        build_dir = dist / f"libfuse3-{arch}"
        run("uvx", "--from", "meson==1.12.0", "meson", "setup", "--reconfigure",
            build_dir, source, "-Ddefault_library=static", "-Dbuildtype=release",
            "-Dutils=false", "-Dexamples=false", "-Dtests=false",
            "-Ddisable-libc-symbol-version=true",
            f"-Dc_args=-arch {arch} -mmacosx-version-min=13.0",
            f"-Dc_link_args=-arch {arch} -mmacosx-version-min=13.0")
        run("ninja", "-C", build_dir)
    library = dist / "libfuse3.a"
    run("lipo", "-create", dist / "libfuse3-arm64/lib/libfuse3.a",
        dist / "libfuse3-x86_64/lib/libfuse3.a", "-output", library)
    return source, library


def bundle_sources(stage, fuse_source):
    destination = stage / "source"
    # Ship the actual build inputs, including local edits, so the LGPL library
    # can be modified and the executable rebuilt without the signing key.
    paths = output("git", "ls-files", "-z", "--", "src", "build.zig", "build.zig.zon", "LICENSE")
    for name in paths.split("\0"):
        if not name:
            continue
        target = destination / "turbocrypt" / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / name, target)
    for package in re.findall(r'\.hash\s*=\s*"([^"]+)"', (ROOT / "build.zig.zon").read_text()):
        if (ROOT / "zig-pkg" / package).is_dir():
            shutil.copytree(ROOT / "zig-pkg" / package,
                            destination / "turbocrypt/zig-pkg" / package)
    shutil.copytree(fuse_source, destination / "libfuse3", ignore=shutil.ignore_patterns(".git"))
    shutil.copy2(ROOT / "scripts/rebuild-macos.md", destination / "README.md")


def build(tap, ver):
    dist = ROOT / "dist"
    dist.mkdir(exist_ok=True)
    zig = os.environ.get("ZIG", "zig")
    fuse_source, fuse_library = build_fuse(dist)
    if set(output("lipo", "-archs", fuse_library).split()) != {"arm64", "x86_64"}:
        raise ValueError("libfuse3.a must contain ARM64 and Intel slices")
    sdk = output("xcrun", "--show-sdk-path")
    with tempfile.TemporaryDirectory(prefix="macos-", dir=dist) as tmp:
        work = Path(tmp)
        for arch, cpu in (("aarch64", "apple_m1"),
                          ("x86_64", "baseline+aes+avx+pclmul")):
            run(zig, "build", "-Doptimize=ReleaseFast", "-Dfuse=true",
                f"-Dtarget={arch}-macos.13.0", f"-Dcpu={cpu}",
                f"-Dfuse-t-static={fuse_library}", f"-Dmacos-sdk={sdk}", "--sysroot", sdk,
                "--prefix", work / arch)
        stage = work / "stage"
        stage.mkdir()
        binary = stage / "turbocrypt"
        run("lipo", "-create", work / "aarch64/bin/turbocrypt",
            work / "x86_64/bin/turbocrypt", "-output", binary)
        run("sh", ROOT / "scripts/sign-macos.sh", binary)
        verify_binary(binary, ver)

        notarized = False
        if profile := os.environ.get("NOTARY_PROFILE"):
            submission = work / "notarization.zip"
            run("ditto", "-c", "-k", binary, submission)
            result = json.loads(output("xcrun", "notarytool", "submit", submission,
                                       "--keychain-profile", profile, "--wait",
                                       "--output-format", "json"))
            if result.get("status") != "Accepted":
                raise ValueError(f"Notarization failed: {result}")
            notarized = True

        info = {
            "version": ver,
            "source_commit": output("git", "rev-parse", "HEAD"),
            "source_dirty": bool(output("git", "status", "--porcelain", "--",
                                        "src", "build.zig", "build.zig.zon",
                                        "shell-completion")),
            "zig_version": output(zig, "version"),
            "libfuse3_sha256": sha256(fuse_library),
            "libfuse3_commit": FUSE_COMMIT,
            "notarized": notarized,
        }
        (stage / "BUILD-INFO.json").write_text(json.dumps(info, indent=2) + "\n")
        for name in ("README.md", "LICENSE"):
            shutil.copy2(ROOT / name, stage / name)
        shutil.copytree(ROOT / "shell-completion", stage / "shell-completion")
        bundle_sources(stage, fuse_source)
        archive = archive_path(ver)
        pending = work / archive.name
        with tarfile.open(pending, "w:gz") as bundle:
            for path in sorted(stage.iterdir()):
                bundle.add(path, arcname=path.name)
        pending.replace(archive)
    digest = sha256(archive)
    archive.with_suffix(archive.suffix + ".sha256").write_text(f"{digest}  {archive.name}\n")
    formula(tap, ver)
    print(f"Built {archive}")


def publish(tap, ver):
    archive = archive_path(ver)
    info = inspect_archive(archive, ver)
    expected = render_formula(ver, sha256(archive))
    if (tap / "Formula/turbocrypt.rb").read_text() != expected:
        raise ValueError("Formula doesn't match the archive; run make formula")
    remote = output("git", "remote", "get-url", "origin", cwd=tap)
    if remote not in (f"git@github.com:{TAP_REPO}.git", f"https://github.com/{TAP_REPO}.git"):
        raise ValueError(f"Unexpected tap origin: {remote}")
    if output("git", "branch", "--show-current", cwd=tap) != "main":
        raise ValueError("The tap must be on its main branch")
    run("git", "fetch", "origin", "main", cwd=tap)
    run("git", "merge-base", "--is-ancestor", "origin/main", "HEAD", cwd=tap)
    ahead = output("git", "diff", "--name-only", "origin/main", "HEAD", cwd=tap)
    if any(path != "Formula/turbocrypt.rb" for path in ahead.splitlines()):
        raise ValueError("Push the tap's unrelated commits before publishing")
    changes = output("git", "status", "--porcelain", "--untracked-files=all", cwd=tap)
    if any(line[3:] != "Formula/turbocrypt.rb" for line in changes.splitlines()):
        raise ValueError("The tap has unrelated changes; commit or stash them first")
    previous = subprocess.run(
        ["git", "show", "origin/main:Formula/turbocrypt.rb"], cwd=tap,
        capture_output=True, text=True,
    )
    if previous.returncode == 0:
        old_version = re.search(r'^  version "(\d+\.\d+\.\d+)"$', previous.stdout, re.M)
        if not old_version:
            raise ValueError("Couldn't read the published formula's version")
        if tuple(map(int, ver.split('.'))) < tuple(map(int, old_version[1].split('.'))):
            raise ValueError("Refusing to downgrade the published formula")

    # Listing releases distinguishes an absent tag from network/authentication failures.
    releases = json.loads(output("gh", "api", "--paginate", "--slurp",
                                f"repos/{TAP_REPO}/releases?per_page=100"))
    release = next((r for page in releases for r in page if r["tag_name"] == ver), None)
    if release is None:
        notes = (f"Universal macOS binary signed with Frank Denis's Developer ID.\n\n"
                 f"Source: https://github.com/jedisct1/turbocrypt/commit/{info['source_commit']}\n\n"
                 "Complete build sources, including any local changes, are included in the archive.\n\n"
                 f"Zig: {info['zig_version']}\n\n"
                 f"Apple notarization: {'accepted' if info['notarized'] else 'not requested'}.\n")
        with tempfile.TemporaryDirectory(prefix="turbocrypt-notes-") as tmp:
            notes_path = Path(tmp) / "notes.md"
            notes_path.write_text(notes)
            run("gh", "release", "create", ver, "--repo", TAP_REPO, "--draft",
                "--target", "main", "--title", f"TurboCrypt {ver}", "--notes-file", notes_path)
    details = json.loads(output("gh", "release", "view", ver, "--repo", TAP_REPO,
                                "--json", "assets,isDraft"))
    # A retry can finish an interrupted upload, but can never replace released bytes.
    asset_names = {asset["name"] for asset in details["assets"]}
    checksum = archive.with_suffix(archive.suffix + ".sha256")
    checksum.write_text(f"{sha256(archive)}  {archive.name}\n")
    for asset in (archive, checksum):
        if asset.name in asset_names:
            with tempfile.TemporaryDirectory(prefix="turbocrypt-download-") as tmp:
                run("gh", "release", "download", ver, "--repo", TAP_REPO,
                    "--pattern", asset.name, "--dir", tmp)
                if sha256(Path(tmp) / asset.name) != sha256(asset):
                    raise ValueError(f"Released {asset.name} differs; bump the version")
        else:
            run("gh", "release", "upload", ver, asset, "--repo", TAP_REPO)
    if details["isDraft"]:
        run("gh", "release", "edit", ver, "--repo", TAP_REPO, "--draft=false")
    run("git", "add", "Formula/turbocrypt.rb", cwd=tap)
    if subprocess.run(["git", "diff", "--cached", "--quiet"], cwd=tap).returncode:
        run("git", "commit", "-m", f"Update TurboCrypt to {ver}", cwd=tap)
    run("git", "push", "origin", "main", cwd=tap)
    print(f"Published {ver}. To install:\n"
          "brew trust jedisct1/turbocrypt\n"
          "brew install jedisct1/turbocrypt/turbocrypt")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tap-dir", type=Path, default=ROOT.parent / "homebrew-turbocrypt")
    parser.add_argument("command", choices=("build", "formula", "publish"))
    args = parser.parse_args()
    if platform.system() != "Darwin":
        parser.error("Building and verifying Developer ID signatures requires macOS")
    try:
        {"build": build, "formula": formula, "publish": publish}[args.command](
            args.tap_dir.resolve(), version())
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"Error: {error}\n")


if __name__ == "__main__":
    main()
