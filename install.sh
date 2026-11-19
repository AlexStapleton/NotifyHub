#!/usr/bin/env bash
# NotifyHub installer / updater. Run from a checkout of the repo:
#   sudo ./install.sh                 install or update the hub (keeps settings, history and login)
#   sudo ./install.sh --diun DIR      also set up Diun (container update checks) in DIR, e.g. /opt/diun
# Layout: code in /home/notify/hub, ntfy settings in /home/notify/notify.conf, data in /var/lib/notify-hub,
# site settings in /etc/default/notify-hub, the `notify` command in /home/notify/notify (+ /usr/local/bin/notify).
set -uo pipefail
[ "$(id -u)" -eq 0 ] || { echo "Run with sudo"; exit 1; }
SRC=$(cd "$(dirname "$0")" && pwd)
BASE=/home/notify; HUB=$BASE/hub; DATA=/var/lib/notify-hub; ENVF=/etc/default/notify-hub
OLD=$BASE/update-approver           # older version of this project (policies are imported)
DIUN_DIR=""
[ "${1:-}" = "--diun" ] && { DIUN_DIR=${2:-}; [ -n "$DIUN_DIR" ] || { echo "usage: $0 --diun DIR"; exit 1; }; }
TS=$(date +%Y%m%d-%H%M%S); BK=$DATA/backups/$TS
mkdir -p "$BK" && chmod 700 "$DATA"

echo "== 1. checks"
command -v python3 >/dev/null || { echo "!! python3 is required"; exit 1; }
command -v docker >/dev/null || echo "   (docker not found - update features stay idle)"
python3 -m py_compile "$SRC/hub.py" "$SRC"/reports/*.py || { echo "!! source doesn't compile - nothing changed"; exit 1; }
find "$SRC" -name __pycache__ -prune -exec rm -rf {} +
sh -n "$SRC/notify" || { echo "!! notify script has a syntax error - nothing changed"; exit 1; }
echo "   ok"

echo; echo "== 2. files -> $HUB"
mkdir -p "$HUB/reports" "$HUB/web" "$HUB/checks"
if [ ! -s "$HUB/diun.secret" ]; then
  if [ -s "$OLD/diun.secret" ]; then install -m 600 "$OLD/diun.secret" "$HUB/diun.secret"
  else (umask 077; python3 -c 'import secrets; print(secrets.token_hex(32))' > "$HUB/diun.secret"); fi
fi
chmod 600 "$HUB/diun.secret"
install -m 755 "$SRC/hub.py" "$HUB/hub.py"
for f in "$SRC"/reports/*.py; do install -m 644 "$f" "$HUB/reports/"; done
for f in "$SRC"/web/*; do install -m 644 "$f" "$HUB/web/"; done
for f in "$SRC"/checks/*; do [ -e "$HUB/checks/$(basename "$f")" ] || install -m 644 "$f" "$HUB/checks/"; done
chown -R root:root "$HUB"; chmod 755 "$BASE" "$HUB" "$HUB/reports" "$HUB/web" "$HUB/checks"
printf '#!/bin/sh\n# NotifyHub admin: set-password | totp-on | totp-off | logout-all | send "Title" "Message"\n[ "$(id -u)" -eq 0 ] || exec sudo "$0" "$@"\nexec /usr/bin/python3 /home/notify/hub/hub.py "$@"\n' > /usr/local/bin/notify-hub
chmod 755 /usr/local/bin/notify-hub
if [ ! -f "$BASE/notify.conf" ]; then
  printf '# ntfy settings (also used by the notify command). Change them in the hub'"'"'s Settings page.\nNTFY_URL=http://127.0.0.1:2586\nNTFY_TOPIC=change-me-%s\n# NTFY_TOKEN=\n' "$(python3 -c 'import secrets;print(secrets.token_hex(6))')" > "$BASE/notify.conf"
  chmod 644 "$BASE/notify.conf"
  echo "   created $BASE/notify.conf - set your ntfy server/topic in Settings"
fi
echo "   installed; admin command: notify-hub"

echo; echo "== 3. site settings ($ENVF)"
LAN_IP=$(python3 -c 'import socket;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.connect(("192.0.2.1",9));print(s.getsockname()[0])' 2>/dev/null || echo 127.0.0.1)
DIUN_YML=""
if [ -n "$DIUN_DIR" ]; then DIUN_YML="$DIUN_DIR/diun.yml"
elif command -v docker >/dev/null; then
  DIUN_YML=$(docker inspect -f '{{range .Mounts}}{{if eq .Destination "/diun.yml"}}{{.Source}}{{end}}{{end}}' diun 2>/dev/null || true)
fi
if [ ! -f "$ENVF" ]; then
  printf '# NotifyHub site settings (read by notify-hub.service; restart the service after editing)\nHUB_LAN_URL=http://%s:8099\nHUB_DIUN_YML=%s\n# HUB_PORT=8099\n' "$LAN_IP" "$DIUN_YML" > "$ENVF"
  echo "   created: LAN address http://$LAN_IP:8099, Diun config ${DIUN_YML:-(none found)}"
elif [ -n "$DIUN_YML" ] && ! grep -q '^HUB_DIUN_YML=.' "$ENVF"; then
  sed -i '/^HUB_DIUN_YML=/d' "$ENVF"; echo "HUB_DIUN_YML=$DIUN_YML" >> "$ENVF"; echo "   added Diun config $DIUN_YML"
else
  echo "   kept existing file"
fi

echo; echo "== 4. service"
if [ -e /etc/systemd/system/update-approver.service ]; then
  systemctl disable --now update-approver.service >/dev/null 2>&1
  mv /etc/systemd/system/update-approver.service "$BK/"
  echo "   old update-approver service replaced"
fi
install -m 644 "$SRC/notify-hub.service" /etc/systemd/system/notify-hub.service
systemctl daemon-reload; systemctl enable notify-hub.service >/dev/null 2>&1; systemctl restart notify-hub.service
PORT=$(sed -n 's/^HUB_PORT=//p' "$ENVF"); PORT=${PORT:-8099}
for i in $(seq 1 15); do [ "$(curl -s -m 2 "http://127.0.0.1:$PORT/health")" = ok ] && break; sleep 1; done
echo "   notify-hub: $(systemctl is-active notify-hub) health=$(curl -s -m 2 "http://127.0.0.1:$PORT/health" || echo FAIL)"
if [ -d "$OLD" ] && python3 -c 'import json,sys; c=json.load(open("/home/notify/hub/config.json")); sys.exit(0 if len(c.get("policies",{}))>1 else 1)' 2>/dev/null; then
  tar -czf "$BK/update-approver-folder.tgz" -C "$BASE" update-approver && rm -rf "$OLD" && echo "   imported policies from the old update-approver (folder archived)"
fi

echo; echo "== 5. notify command"
if ! cmp -s "$SRC/notify" "$BASE/notify"; then
  [ -f "$BASE/notify" ] && cp -a "$BASE/notify" "$BK/notify.orig"
  install -m 755 -o root -g root "$SRC/notify" "$BASE/notify"
  echo "   $BASE/notify updated"
fi
[ -e /usr/local/bin/notify ] || ln -s "$BASE/notify" /usr/local/bin/notify

if [ -n "$DIUN_DIR" ]; then
  echo; echo "== 6. Diun in $DIUN_DIR"
  mkdir -p "$DIUN_DIR/data"
  [ -f "$DIUN_DIR/docker-compose.yml" ] || install -m 644 "$SRC/diun/docker-compose.yml" "$DIUN_DIR/docker-compose.yml"
  if [ ! -f "$DIUN_DIR/diun.yml" ]; then
    sed -e "s#__HUB_URL__#http://$LAN_IP:$PORT#" -e "s/__SECRET__/$(cat "$HUB/diun.secret")/" "$SRC/diun/diun.yml.template" > "$DIUN_DIR/diun.yml"
    chmod 600 "$DIUN_DIR/diun.yml"
  fi
  [ -f "$DIUN_DIR/.env" ] || echo "TZ=$(timedatectl show -p Timezone --value 2>/dev/null || echo UTC)" > "$DIUN_DIR/.env"
  (cd "$DIUN_DIR" && docker compose up -d) && sleep 8
  systemctl restart notify-hub.service
fi
if docker inspect diun >/dev/null 2>&1; then
  docker exec diun diun notif test >/dev/null 2>&1 && echo "   Diun test sent (look for 'Diun test OK')" || echo "   !! 'diun notif test' failed - check docker logs diun"
fi

NOTIFY_SOURCE=install "$BASE/notify" -p low -g tada "NotifyHub installed" "Open it at http://$LAN_IP:$PORT" || true
echo; echo "== Next"
[ -f "$DATA/auth.json" ] && echo "   Login exists (change: sudo notify-hub set-password)" || echo "   Set the login:      sudo notify-hub set-password"
echo "   2-factor (recommended if reachable from the internet): sudo notify-hub totp-on"
echo "   Open: http://$LAN_IP:$PORT     Backups of replaced files: $BK"
