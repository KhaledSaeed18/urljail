#!/usr/bin/env bash
# Set up the urljail control plane for the operator, without root (ADR 0019):
# secrets, Postgres and Redis as rootless podman Quadlet units, the API and the dashboard as
# systemd user services, all on 127.0.0.1. Re-running rotates the API token and keeps data.
#
#   control-plane/scripts/setup.sh          # after building api/ and web/ (see README)
set -euo pipefail
CP="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO="$(dirname "$CP")"
[ "$(id -u)" -ne 0 ] || { echo "run as the operator, not root" >&2; exit 1; }
POSTGRES_IMAGE="${POSTGRES_IMAGE:-docker.io/library/postgres:17-alpine}"
REDIS_IMAGE="${REDIS_IMAGE:-docker.io/library/redis:7-alpine}"
NODE="$(command -v node)"
for img in "$POSTGRES_IMAGE" "$REDIS_IMAGE"; do
    podman image exists "$img" || podman pull "$img"
done
# Pin what was pulled: the units name the digest, not the moving tag.
pin() { podman image inspect "$1" --format '{{index .RepoDigests 0}}'; }
POSTGRES_IMAGE="$(pin "$POSTGRES_IMAGE")"; REDIS_IMAGE="$(pin "$REDIS_IMAGE")"

rand() { head -c 32 /dev/urandom | base64 | tr -d '/+=' | head -c 40; }
install -d -m 0700 "$HOME/.config/urljail"
ENV="$HOME/.config/urljail/control-plane.env"
# Database and Redis passwords are created once (the data volumes keep them); the token rotates.
PG_PASS="$(podman secret inspect urljail-pg-password >/dev/null 2>&1 && sed -n 's/^PG_PASSWORD=//p' "$ENV" 2>/dev/null || true)"
REDIS_PASS="$(sed -n 's/^REDIS_PASSWORD=//p' "$ENV" 2>/dev/null || true)"
[ -n "$PG_PASS" ] || { PG_PASS="$(rand)"; podman secret rm urljail-pg-password >/dev/null 2>&1 || true; printf %s "$PG_PASS" | podman secret create urljail-pg-password - >/dev/null; }
[ -n "$REDIS_PASS" ] || REDIS_PASS="$(rand)"
podman secret rm urljail-redis-conf >/dev/null 2>&1 || true
printf 'bind 0.0.0.0\nprotected-mode yes\nrequirepass %s\nappendonly yes\n' "$REDIS_PASS" | podman secret create urljail-redis-conf - >/dev/null
TOKEN="$(rand)"
umask 077
cat > "$ENV" <<ENVEOF
# urljail control plane (control-plane/scripts/setup.sh). Keep private: 0600.
PG_PASSWORD=$PG_PASS
REDIS_PASSWORD=$REDIS_PASS
DATABASE_URL=postgres://urljail:$PG_PASS@127.0.0.1:55432/urljail
REDIS_URL=redis://:$REDIS_PASS@127.0.0.1:56379
URLJAIL_API_TOKEN=$TOKEN
URLJAIL_API_URL=http://127.0.0.1:7801
URLJAIL_SOCKET=/run/urljail/urljaild.sock
URLJAIL_RUNS_DIR=$HOME/.local/share/urljail/runs
URLJAIL_PROTO_DIR=$REPO/api/proto
ENVEOF
chmod 600 "$ENV"

install -d -m 0755 "$HOME/.config/containers/systemd" "$HOME/.config/systemd/user"
sed "s#@POSTGRES_IMAGE@#$POSTGRES_IMAGE#" "$CP/deploy/urljail-postgres.container" > "$HOME/.config/containers/systemd/urljail-postgres.container"
sed "s#@REDIS_IMAGE@#$REDIS_IMAGE#" "$CP/deploy/urljail-redis.container" > "$HOME/.config/containers/systemd/urljail-redis.container"
for u in urljail-api urljail-web; do
    sed "s#@REPO@#$REPO#; s#@NODE@#$NODE#" "$CP/deploy/$u.service" > "$HOME/.config/systemd/user/$u.service"
done
systemctl --user daemon-reload
systemctl --user restart urljail-postgres.service urljail-redis.service
systemctl --user enable urljail-api.service urljail-web.service >/dev/null
systemctl --user restart urljail-api.service urljail-web.service
echo "control plane: http://127.0.0.1:7800 (API http://127.0.0.1:7801; token in $ENV)"
