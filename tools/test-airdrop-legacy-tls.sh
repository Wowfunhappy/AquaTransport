#!/bin/bash
set -euo pipefail
DIR="$(cd "$(dirname "$0")/.." && pwd)"
clang -mmacosx-version-min=10.9 -fobjc-arc -fblocks -Wall -Wextra -Wno-deprecated-declarations \
    -I"$DIR/build/openssl/include" "$DIR/tools/airdrop-legacy-tls-test.m" \
    "$DIR/build/openssl/lib/libcrypto.a" -framework Foundation -o "$DIR/build/airdrop-legacy-tls-test"
"$DIR/build/airdrop-legacy-tls-test"
