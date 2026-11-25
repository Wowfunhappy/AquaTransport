#!/bin/bash
set -eu
BASE=/usr/share/aquatransport/cloudtabs
# Only an explicitly configured account starts network work at login.
STATE="$HOME/Library/Application Support/AquaTransport/CloudTabs"
mode=sync.py
if [ "${1:-}" = --prepare ] || [ "${1:-}" = --disable ]; then
    mode=setup.py
else
    [ -f "$STATE/session.plist" ] && [ -f "$STATE/safari-service-keys.plist" ] || exit 0
fi
if [ -f /usr/share/aquatransport/config/flags.txt ] &&
   grep -qx 'disable-safari-cloudtabs' /usr/share/aquatransport/config/flags.txt; then exit 0; fi
export PYTHONDONTWRITEBYTECODE=1
# This feature is Mavericks-specific; use only its stock interpreter.
case "$(uname -r)" in 13.*) ;; *) exit 0 ;; esac
exec /usr/bin/python2.7 -E -S -B "$BASE/$mode" "$@"
