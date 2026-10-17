#!/bin/bash
set -euo pipefail
DIR="$(cd "$(dirname "$0")/.." && pwd)"
mkdir -p "$DIR/build"
clang -mmacosx-version-min=10.9 -fobjc-arc -fblocks -Wall -Wextra \
    "$DIR/tools/airdrop-power-test.m" -framework Foundation -o "$DIR/build/airdrop-power-test"
"$DIR/build/airdrop-power-test"
clang -mmacosx-version-min=10.9 -Wall -Wextra -I "$DIR/deps/owl/src" \
    "$DIR/tools/airdrop-radio-start-test.c" "$DIR/deps/owl/daemon/io.c" "$DIR/deps/owl/src/log.c" \
    -lpcap -o "$DIR/build/airdrop-radio-start-test"
"$DIR/build/airdrop-radio-start-test"
