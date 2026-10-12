#!/usr/bin/env bash
# Install urljaild as a system service, from a built checkout (make build, make selinux).
#
#   sudo scripts/install-daemon.sh            # install or update binaries, policy and unit
#   sudo systemctl enable --now urljaild      # then start it
#
# Copies the daemon, jailer and firecracker to root-owned paths: as a service (and in live
# mode), root must not execute binaries the operator can replace. Re-run after rebuilding.
set -euo pipefail

[ "$(id -u)" = 0 ] || { echo "run with sudo" >&2; exit 1; }
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OP="${SUDO_USER:?run with sudo from the operator account}"
OP_HOME="$(getent passwd "$OP" | cut -d: -f6)"

fc="$(readlink -f "$OP_HOME/.local/bin/firecracker")"
jl="$(readlink -f "$OP_HOME/.local/bin/jailer")"
for f in "$REPO/bin/urljaild" "$REPO/selinux/urljail.pp" "$fc" "$jl"; do
    [ -f "$f" ] || { echo "missing $f (build first)" >&2; exit 1; }
done

install -d -m 0755 /usr/local/libexec/urljail /usr/local/share/urljail
install -m 0755 -o root -g root "$REPO/bin/urljaild" /usr/local/sbin/urljaild
# The jailer names jail directories after the exec file: keep a name containing "firecracker".
install -m 0755 -o root -g root "$fc" /usr/local/libexec/urljail/firecracker
install -m 0755 -o root -g root "$jl" /usr/local/libexec/urljail/jailer
install -m 0644 -o root -g root "$REPO/selinux/urljail.pp" "$REPO/selinux/urljail.te" /usr/local/share/urljail/
install -m 0644 -o root -g root "$REPO/README.md" /usr/local/share/urljail/README.md
restorecon -R /usr/local/sbin/urljaild /usr/local/libexec/urljail /usr/local/share/urljail 2>/dev/null || true

install -d -m 0700 /etc/urljail
if [ ! -e /etc/urljail/urljaild.env ]; then
    sed "s/^URLJAIL_OPERATOR=.*/URLJAIL_OPERATOR=$OP/" "$REPO/deploy/urljaild.env.example" > /etc/urljail/urljaild.env
    chmod 0600 /etc/urljail/urljaild.env
    echo "wrote /etc/urljail/urljaild.env (edit it to change the egress mode)"
fi
install -m 0644 -o root -g root "$REPO/deploy/urljaild.service" /etc/systemd/system/urljaild.service
systemctl daemon-reload
echo "installed. Start with: sudo systemctl enable --now urljaild"
if systemctl is-active -q urljaild; then
    echo "urljaild is running: restart it to use the new binaries (sudo systemctl restart urljaild)"
fi
