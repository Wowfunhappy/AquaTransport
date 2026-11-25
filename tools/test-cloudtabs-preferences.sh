#!/bin/bash
set -eu
DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$DIR"
clang -Wall -Wextra -Wno-deprecated-declarations -arch x86_64 -arch i386 -mmacosx-version-min=10.7 \
    tools/cloudtabs-preferences-test.m -framework AppKit -o build/cloudtabs-preferences-test
arch -x86_64 build/cloudtabs-preferences-test
arch -i386 build/cloudtabs-preferences-test
TEST="$DIR/build/cloudtabs-preferences-lazy"
mkdir -p "$TEST/AOSUI.framework"
clang -arch x86_64 -arch i386 -mmacosx-version-min=10.7 -framework Foundation -dynamiclib \
    tools/cloudtabs-preferences-fixture.m -o "$TEST/AOSUI.framework/AOSUI"
clang -arch x86_64 -arch i386 -mmacosx-version-min=10.7 -framework Foundation \
    tools/cloudtabs-preferences-lazy-test.m -o "$TEST/System Preferences"
cp "$TEST/System Preferences" "$TEST/com.apple.preferences.icloud.remoteservice"
for architecture in x86_64 i386; do
    DYLD_INSERT_LIBRARIES="$DIR/build/stage/usr/share/aquatransport/aquatransport.dylib" arch -"$architecture" "$TEST/System Preferences" "$TEST/AOSUI.framework/AOSUI"
    DYLD_INSERT_LIBRARIES="$DIR/build/stage/usr/share/aquatransport/aquatransport.dylib" arch -"$architecture" "$TEST/com.apple.preferences.icloud.remoteservice" "$TEST/AOSUI.framework/AOSUI"
done
