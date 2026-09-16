#!/bin/sh
set -eu

if [ "$#" -ne 1 ]; then
    echo "Usage: sh scripts/sign-macos.sh BINARY" >&2
    exit 1
fi

identity=${CODESIGN_IDENTITY:-Developer ID Application: Frank Denis (888H8YF752)}

codesign --force --sign "$identity" --timestamp --options runtime \
    --identifier org.pureftpd.turbocrypt "$1"
codesign --verify --strict --all-architectures --verbose=2 "$1"
