#!/bin/bash
set -eu
DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$DIR"
clang -arch x86_64 -arch i386 -mmacosx-version-min=10.7 -fblocks -Wall -Wextra tools/cloudtabs-bootstrap-test.m -framework Foundation -o build/cloudtabs-bootstrap-test
arch -x86_64 build/cloudtabs-bootstrap-test
arch -i386 build/cloudtabs-bootstrap-test
