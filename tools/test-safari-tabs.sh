#!/bin/bash
set -eu
DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$DIR"
clang -Wall -Wextra -Wno-deprecated-declarations -arch x86_64 -arch i386 -mmacosx-version-min=10.7 \
    tools/safari-tabs-test.m src/mac/aquatransport_config.c -framework AppKit -o build/safari-tabs-test
arch -x86_64 build/safari-tabs-test
arch -i386 build/safari-tabs-test
bash tools/build-cloudtabs-test-runtime.sh
PYTHONDONTWRITEBYTECODE=1 /usr/bin/python2.7 -E -S -B tools/cloudtabs-crypto-test.py
