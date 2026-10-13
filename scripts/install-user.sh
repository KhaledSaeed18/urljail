#!/usr/bin/env bash
# Install the operator's side of urljail, without root: the CLI in ~/.local/bin and the
# retention timer as a systemd user unit (runs even when logged out if lingering is on).
#
#   scripts/install-user.sh        # after `make build`
set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
[ "$(id -u)" -ne 0 ] || { echo "run as the operator, not root" >&2; exit 1; }
[ -x "$REPO/bin/urljail" ] || { echo "build first: make build" >&2; exit 1; }

install -d -m 0755 "$HOME/.local/bin" "$HOME/.config/systemd/user"
install -m 0755 "$REPO/bin/urljail" "$HOME/.local/bin/urljail"
install -m 0644 "$REPO/deploy/urljail-gc.service" "$REPO/deploy/urljail-gc.timer" "$HOME/.config/systemd/user/"
systemctl --user daemon-reload
systemctl --user enable --now urljail-gc.timer
echo "installed: ~/.local/bin/urljail, urljail-gc.timer ($(systemctl --user show urljail-gc.timer -p NextElapseUSecRealtime --value))"
