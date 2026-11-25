#!/bin/bash

clear
printf "You are about to remove AquaTransport from your computer. Your computer will restart automatically once the process is complete. Continue? (yes/no) "
read -r confirmation
if [ "$confirmation" != "y" ] && [ "$confirmation" != "yes" ]
then
	echo "Exiting. No changes have been made."
	exit 1
fi

echo "Please type in your password and press return. No characters will appear as you type."
sudo true || exit 1

# We need to unload the current user's cloud tabs job before deleting the Application Support directory,
# or the job might recreate that directory before we reboot.
sudo launchctl unload /usr/share/aquatransport/cloudtabs/org.aquatransport.cloudtabs.plist  >/dev/null 2>&1 || true
dscl . -list /Users UniqueID | while read -r username uid
do
    [ "$uid" -ge 500 ] || continue
    user_home="$(dscl . -read "/Users/$username" NFSHomeDirectory 2>/dev/null | sed 's/^NFSHomeDirectory: //')"
	case "$user_home" in ""|"/"|"/Users"|"/Library"|"/System"|"/private"|"/var")
            continue
            ;;
    esac
    sudo rm -rf -- "$user_home/Library/Application Support/AquaTransport"
done

sudo rm -f /Library/LaunchDaemons/org.aquatransport.bootstrap.plist
# No need to manually unload jobs; we're deleting their definitions, then rebooting.

SECURITY_BIN="/System/Library/Frameworks/Security.framework/Versions/A/Security"
sudo mv -f "$SECURITY_BIN.original" "$SECURITY_BIN"
sudo rm -rf "/usr/share/aquatransport"

sudo pkgutil --forget Wowfunhappy.AquaTransport

# Tap Kext
sudo rm -f /Library/LaunchDaemons/net.sf.tuntaposx.tap.plist
sudo rm -rf /Library/Extensions/tap.kext
sudo pkgutil --forget net.sf.tuntaposx.tap

sudo update_dyld_shared_cache
sudo shutdown -r now
