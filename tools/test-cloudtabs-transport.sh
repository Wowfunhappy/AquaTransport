#!/bin/bash
set -eu
DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$DIR"
clang -arch x86_64 -arch i386 -mmacosx-version-min=10.7 -Wall -Wno-deprecated-declarations \
    -Ibuild/openssl/include tools/cloudtabs-transport-fixture.m src/mac/aquatransport_gsa_crypto.c \
    src/mac/aquatransport_config.c build/openssl/lib/libcrypto.a \
    -framework AppKit -framework IOKit -lz -o build/cloudtabs-transport-fixture
bash tools/build-cloudtabs-test-runtime.sh
/usr/bin/python2.7 -E -S -B tools/cloudtabs-transport-test.py
