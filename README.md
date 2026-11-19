# NotifyHub

A small, self-hosted notification hub for a Linux home server. It sends everything to your phone through [ntfy](https://ntfy.sh), keeps a history, and gives you a web page to manage it all.

- **One place for notifications.** Scripts, cron jobs, RAID/SMART hooks and the hub's own reports all go through it. It keeps a searchable history, can hold low-priority messages during quiet hours, and retries if ntfy is down.
- **Container updates with approval.** [Diun](https://crazymax.dev/diun/) spots new images. For each container you choose what happens next:
  - **Auto-update**
  - **Ask me**: a notification with an **Update** button
  - **Just tell me**
  - **Ignore**

  Every update checks the container comes back healthy, rolls back to the old image if it doesn't, and recreates containers that share its network (e.g. a torrent client behind a VPN container).
- **Scheduled reports and checks.** Built in:
  - **Weekly downloads** (Radarr/Sonarr)
  - **Server health** (RAID, SMART, temperatures, free space, containers, OS updates)
  - **Disk space alert**
  - **Container watch** (unhealthy, restart loops, crashes)

  To add your own, drop in a Python plug-in or any shell script.
- **Web UI:**
  - **Overview**
  - **Updates**
  - **Reports & checks:** turn on/off, change schedules and settings, preview, run now
  - **History**
  - **Settings**

  Login with optional 2-factor (TOTP). Safe to put behind a reverse proxy on the internet.

It uses only the Python standard library, has no build step, and runs as one systemd service.

## Requirements

- Linux with systemd, Python 3.8+, `curl`
- An ntfy server (self-hosted or ntfy.sh) and the ntfy phone app
- Optional: Docker + Docker Compose v2 (for container updates and container reports), `smartctl` (drive health), Diun

## Install

```bash
git clone https://github.com/AlexStapleton/NotifyHub.git
cd NotifyHub
sudo ./install.sh                     # add --diun /opt/diun to also set up Diun
sudo notify-hub set-password
sudo notify-hub totp-on               # recommended, especially if the hub is reachable from the internet
```

Then open `http://<server>:8099`. Set your ntfy server and topic under **Settings**, and press **Send test**.

To update, `git pull` and run `sudo ./install.sh` again. Settings, history and the login are kept.

### Where things live

| Path | What |
|---|---|
| `/home/notify/hub/` | the code; `config.json` holds settings edited in the UI |
| `/home/notify/notify.conf` | ntfy server, topic, optional token (shared with the `notify` command) |
| `/var/lib/notify-hub/` | `hub.db` (history, sessions), `auth.json` (login), backups of replaced files |
| `/etc/default/notify-hub` | site settings: `HUB_LAN_URL`, `HUB_DIUN_YML`, `HUB_PORT`, `HUB_TRUSTED_PROXIES` |
| `/usr/local/bin/notify-hub` | admin command |
| `/usr/local/bin/notify` | send a notification from any script |

## Sending notifications

```bash
notify "Backup" "Nightly backup finished"
notify -p high -g warning,floppy_disk "RAID" "md0 is degraded"
```

The `notify` command hands the message to the hub (`POST /api/notify`, localhost only). If the hub isn't running, for example early at boot, it sends straight to ntfy and keeps retrying for 15 minutes.

## Container updates with Diun

`sudo ./install.sh --diun /opt/diun` writes `diun.yml` with the hub's address and a shared secret, then starts Diun from `diun/docker-compose.yml`. Diun checks every running container daily and calls the hub's `/diun` webhook. You then set a policy per container on the **Updates** page.

Updates only work for containers started with Docker Compose. The hub refuses to update a container whose compose file names a different image than the one running, to avoid surprise downgrades.

## Your own reports and checks

**Shell checks:** put an executable script in `/home/notify/hub/checks/`. Exit code `0` is silent, `1` sends an alert, `2` or higher sends at high priority. The output becomes the message, and a first line `title: …` becomes the title. See `checks/README.md` and the sample.

**Python plug-ins:** put a file in `/home/notify/hub/reports/`. It appears on the **Reports & checks** page automatically:

```python
NAME = "my_report"                     # unique id
TITLE = "My report"
DESCRIPTION = "What it does"
DEFAULT_ENABLED = False
DEFAULT_SCHEDULE = "daily 09:00"       # or "every 30" (minutes) or "weekly sun 18:00"
SETTINGS = [                           # rendered as a form in the UI
    {"key": "limit", "label": "Limit", "type": "number", "default": 5},   # types: number, text, bool
]

def run(ctx, settings):
    # ctx.run(cmd) -> (rc, stdout, stderr)   ctx.http_json(url, headers)   ctx.containers(all_=False)
    # ctx.mounts(setting)   ctx.get(key, default) / ctx.set(key, value)  (small persistent memory)
    return {"title": "Hello", "message": "...", "priority": 3, "tags": ["wave"]}   # or None = send nothing
```

## Putting it on the internet

Put it behind a reverse proxy with HTTPS, e.g. Nginx Proxy Manager or Caddy, pointing at `http://<server>:8099`. Then set **Settings → Public hub address**, so the **Update** buttons work from anywhere. The proxy must send `X-Real-IP` and `X-Forwarded-Proto`; NPM and Caddy do this by default.

The hub only believes `X-Real-IP` from a proxy running on the same server (e.g. NPM with `network_mode: host`). If your proxy runs elsewhere, or in a Docker bridge network, add its address or subnet to `HUB_TRUSTED_PROXIES` in `/etc/default/notify-hub`, e.g. `HUB_TRUSTED_PROXIES=172.18.0.0/16`. A proxy in a Docker bridge network also hides IPv6 visitors' real addresses; running it on the host network avoids that.

How it protects itself:

- **Login:**
  - no default password
  - scrypt password hashing
  - optional TOTP
  - 5 failed logins from one IP within 15 minutes block that IP. 25 failures from internet addresses block internet logins only, so bots can't lock you out at home.
  - at most 2 password checks run at once, so a burst of logins can't exhaust memory or CPU
  - a notification on every login from outside your home network (your own IPv6 range counts as home)
- **Sessions:** HttpOnly, SameSite=Lax (so links from other pages keep you signed in), and Secure behind HTTPS cookies. They expire after 7 days idle or 30 days at most.
- **Requests:**
  - Every change needs a custom request header, so other sites can't trigger actions.
  - A strict Content-Security-Policy is set, and nothing is loaded from other sites.
  - `/diun` and `/api/notify` refuse anything that arrives through the proxy.
- **Update links:** one-time use, and they expire after 14 days by default.

The service runs as root because it manages Docker (which is root-equivalent anyway) and reads SMART data. Treat the login accordingly.

## Admin command

```
sudo notify-hub set-password     # create or change the login (signs everyone out)
sudo notify-hub totp-on          # turn on 2-factor (shows a key for your authenticator app)
sudo notify-hub totp-off
sudo notify-hub logout-all
sudo notify-hub send "Title" "Message"
journalctl -u notify-hub -f      # logs
```

## Uninstall

```bash
sudo systemctl disable --now notify-hub
sudo rm -rf /home/notify/hub /var/lib/notify-hub /etc/systemd/system/notify-hub.service /etc/default/notify-hub /usr/local/bin/notify-hub
```

## License

GPL-3.0 - see [LICENSE](LICENSE).
