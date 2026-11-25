#!/bin/bash
set -eu
DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$DIR"
OUT="$DIR/build/cloudtabs-system"
mkdir -p "$OUT"
find "$OUT" -name '*.pyc' -delete
printf '_AQCloudTabsNativeCall\n_AQCloudTabsNativeFree\n' > build/cloudtabs-native.exp
clang -arch x86_64 -arch i386 -mmacosx-version-min=10.7 -O2 -Wall -Wno-deprecated-declarations -fvisibility=hidden \
    -Ibuild/openssl/include -dynamiclib src/mac/cloudtabs/native.m build/openssl/lib/libcrypto.a \
    -framework Foundation -Wl,-exported_symbols_list,build/cloudtabs-native.exp \
    -install_name /usr/share/aquatransport/cloudtabs/aquatransport_cloudtabs_native.dylib \
    -o "$OUT/aquatransport_cloudtabs_native.dylib"
cp src/mac/cloudtabs/*.py "$OUT/"
