#!/bin/bash
# No installation, public network, or keychain changes. socketpair peers require
# TLS 1.3; a per-trust test anchor retains actual native signature/hostname checks.
set -euo pipefail
DIR="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$DIR/build/trust-transport-test"
ENGINE="${1:-$DIR/build/stage/usr/share/aquatransport/aquatransport_engine.dylib}"
mkdir -p "$OUT/startup" "$OUT/runtime" "$OUT/disabled"
printf 'trust-transport-test\n' > "$OUT/startup/disabled.txt"
printf 'ocspd\n' > "$OUT/disabled/disabled.txt"
printf 'disable-modern-airdrop\ndisable-maps-fixes\n' > "$OUT/runtime/flags.txt"
: > "$OUT/exports.txt"
clang -arch x86_64 -arch i386 -mmacosx-version-min=10.6 \
    -Wall -Wextra -Wno-deprecated-declarations -I"$DIR/build/openssl/include" \
    "$DIR/tools/trust-transport-test.c" "$DIR/deps/fishhook/fishhook.c" \
    "$DIR/build/openssl/lib/libssl.a" "$DIR/build/openssl/lib/libcrypto.a" \
    -framework Security -framework CoreFoundation \
    -Wl,-exported_symbols_list,"$OUT/exports.txt" -o "$OUT/trust-transport-test"
for arch in x86_64 i386; do
    for process in ocspd securityd securityd_service trustd trust-transport-app; do
        echo "== $arch $process =="
        AQUATRANSPORT_DIR="$OUT/startup" /usr/bin/arch -"$arch" \
            "$OUT/trust-transport-test" "$ENGINE" "$OUT/runtime" "$process"
    done
    AQUATRANSPORT_DIR="$OUT/startup" /usr/bin/arch -"$arch" \
        "$OUT/trust-transport-test" "$ENGINE" "$OUT/disabled" ocspd disabled
done
