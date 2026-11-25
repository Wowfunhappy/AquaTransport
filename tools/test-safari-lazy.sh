#!/bin/bash
set -eu
DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$DIR"
TEST="$DIR/build/safari-lazy"
mkdir -p "$TEST/Safari.framework"
clang -arch x86_64 -arch i386 -mmacosx-version-min=10.7 -framework Foundation -dynamiclib tools/safari-lazy-fixture.m -o "$TEST/Safari.framework/Safari"
clang -arch x86_64 -arch i386 -mmacosx-version-min=10.7 -framework Foundation tools/safari-lazy-test.m -o "$TEST/Safari"
for architecture in x86_64 i386; do
    DYLD_INSERT_LIBRARIES="$DIR/build/stage/usr/share/aquatransport/aquatransport.dylib" arch -"$architecture" "$TEST/Safari" "$TEST/Safari.framework/Safari"
done
