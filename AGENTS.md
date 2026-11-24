# AquaTransport development workflow

- After changes, build, run the relevant checks, and install the changes on the
  local system. Installation is part of the work, not an optional follow-up.
- The user should grant you sudo access for work on this project. If the user forgot or it timed out, please remind them.
- Use the local development installation workflow (`install-macos.sh install`).
  If macOS administrator access is unavailable, report the exact blocker and
  finish installation and verification once access is available.
- Keep the staged binaries and source resources referenced by the Packages GUI
  project up to date, so the user can rebuild their installer easily.
- Do not make ANY changes inside the packaging/ directory without clear and explicit authorization by the user. If the user authorizes changes to this directory, interpret those instructions literally and do not make ANY changes beyond what was very specifically requested. If you believe more changes should be made, let the user know.
- Keep AquaTransport-owned runtime state under `/usr/share/aquatransport`.
- Do not reboot the local system automatically; leave rebooting to the user.
