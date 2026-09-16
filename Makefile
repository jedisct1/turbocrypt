ZIG ?= zig
PYTHON ?= python3
TAP_DIR ?= ../homebrew-turbocrypt

.PHONY: all build clean test check dist formula publish release

all: build

build:
	$(ZIG) build -Doptimize=ReleaseFast

clean:
	rm -rf .zig-cache zig-out dist

test:
	$(ZIG) build test
	$(ZIG) build test -Doptimize=ReleaseFast
	$(ZIG) build test-git

check:
	$(ZIG) fmt --check build.zig src
	$(PYTHON) -m unittest discover -s tests -p 'test_release.py'
	shellcheck scripts/sign-macos.sh

# Build and sign on this Mac, then update the local tap's formula.
dist:
	ZIG="$(ZIG)" $(PYTHON) scripts/macos_release.py --tap-dir "$(TAP_DIR)" build

formula:
	$(PYTHON) scripts/macos_release.py --tap-dir "$(TAP_DIR)" formula

# Publish an already built archive. Existing release assets aren't replaced.
publish:
	$(PYTHON) scripts/macos_release.py --tap-dir "$(TAP_DIR)" publish

release:
	$(MAKE) dist
	$(MAKE) publish
