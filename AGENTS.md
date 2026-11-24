# AquaTransport development workflow

- After changes, build, run the relevant checks, and install the changes on the
  local system. Installation is part of the work, not an optional follow-up.
- Use the local development installation workflow (`install-macos.sh install`).
  If macOS administrator access is unavailable, report the exact blocker and
  finish installation and verification once access is available.
- Keep the staged binaries and source resources referenced by the Packages GUI
  project up to date, so the user can rebuild their installer easily.
- Do not build, overwrite, or modify the user's official distribution installer
  package. The user builds it manually in Packages. Leave release-version choices
  to the user unless explicitly requested.
- Keep AquaTransport-owned runtime state under `/usr/share/aquatransport`.
- Do not reboot the local system automatically; leave rebooting to the user.
