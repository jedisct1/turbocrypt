# Rebuild with a modified libfuse3

The executable includes fuse-t's libfuse3 under LGPL 2.1. Its source and license are in `libfuse3/`; the exact TurboCrypt source used for this build is in `turbocrypt/`. The source may include changes made locally after the commit recorded in `../BUILD-INFO.json`. TurboCrypt itself is MIT licensed.

You may modify the library and rebuild the executable for your own use. Install Xcode Command Line Tools, uv, Ninja, and the Zig version recorded in `../BUILD-INFO.json`. From this directory, build your modified library for your Mac:

```sh
uvx --from meson==1.12.0 meson setup fuse-build libfuse3 -Ddefault_library=static -Dbuildtype=release -Dutils=false -Dexamples=false -Dtests=false -Ddisable-libc-symbol-version=true
ninja -C fuse-build
```

Then build TurboCrypt against it:

```sh
cd turbocrypt
zig build -Doptimize=ReleaseFast -Dfuse-t-static="$PWD/../fuse-build/lib/libfuse3.a" -Dmacos-sdk="$(xcrun --show-sdk-path)" --sysroot "$(xcrun --show-sdk-path)"
./zig-out/bin/turbocrypt version
```

Zig creates a locally runnable executable; you don't need the maintainer's Developer ID certificate. Mounting still needs the separately installed fuse-t server. Other commands don't require it.
