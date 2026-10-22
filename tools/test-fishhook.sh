#!/bin/bash
# Local dylibs only. Optional argument: exact engine to exercise alongside the
# namespace fixtures. Does not install anything or contact external services.
set -euo pipefail
DIR="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$DIR/build/fishhook-test"
SRC="$DIR/tools/fishhook"
mkdir -p "$OUT/startup" "$OUT/runtime"
printf 'fishhook-probe\n' > "$OUT/startup/disabled.txt"
printf 'disable-maps-fixes\ndisable-modern-airdrop\n' > "$OUT/runtime/flags.txt"
printf 'fishhook-probe\nhttps://namespace.invalid/\nX-Namespace-Test: active\n' > "$OUT/runtime/headers.txt"
for arch in x86_64 i386; do
    dest="$OUT/$arch"
    mkdir -p "$dest/a" "$dest/b"
    flags=(-arch "$arch" -mmacosx-version-min=10.6 -Wall -Wextra -Werror)
    for pair in a:11 b:22; do
        which="${pair%:*}"; value="${pair#*:}"
        clang "${flags[@]}" -dynamiclib -DVALUE="$value" "$SRC/provider.c" \
            -install_name "$dest/$which/libcollision.dylib" -o "$dest/$which/libcollision.dylib"
        for kind in bound unbound late engine-late; do
            clang "${flags[@]}" -dynamiclib "$SRC/client.c" "$dest/$which/libcollision.dylib" \
                -o "$dest/$kind-$which.dylib"
        done
    done
    clang "${flags[@]}" -dynamiclib -DVALUE=44 "$SRC/provider.c" -o "$dest/not-loaded.dylib"
    clang "${flags[@]}" -dynamiclib -DWEAK_IMPORT "$SRC/client.c" \
        -Wl,-weak_library,"$dest/a/libcollision.dylib" -o "$dest/weak.dylib"
    for name in umbrella unapproved; do
        clang "${flags[@]}" -dynamiclib -Wl,-reexport_library,"$dest/a/libcollision.dylib" \
            -install_name "$dest/$name.dylib" -o "$dest/$name.dylib"
        clang "${flags[@]}" -dynamiclib "$SRC/client.c" "$dest/$name.dylib" \
            -Wl,-no_implicit_dylibs -o "$dest/$name-client.dylib"
    done
    clang "${flags[@]}" -dynamiclib "$SRC/client.c" "$dest/a/libcollision.dylib" \
        -Wl,-flat_namespace -o "$dest/flat.dylib"
    clang "${flags[@]}" -dynamiclib "$SRC/client.c" \
        -Wl,-undefined,dynamic_lookup -o "$dest/lookup.dylib"
    clang "${flags[@]}" -Wno-deprecated-declarations -dynamiclib "$SRC/system-client.c" \
        -framework Security -framework CFNetwork -framework CoreFoundation -o "$dest/system-client.dylib"
    clang "${flags[@]}" "$SRC/probe.c" "$DIR/deps/fishhook/fishhook.c" \
        -framework Security -framework CFNetwork -o "$dest/fishhook-probe"
    echo "== fishhook $arch =="
    args=("$dest")
    if [ "$#" -gt 0 ]; then args+=("$1" "$OUT/runtime"); fi
    AQUATRANSPORT_DIR="$OUT/startup" "$dest/fishhook-probe" "${args[@]}"
done
