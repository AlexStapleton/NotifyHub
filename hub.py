#!/usr/bin/env python3
"""NotifyHub - a self-hosted notification hub for a home server.

One small web app (Python standard library only) that:
  * sends every notification to ntfy, keeps a history, and can hold low-priority ones during quiet hours
  * receives Diun's "new image" webhooks and, per container, updates automatically / asks with an
    "Update" button / just tells you / ignores (with health check + automatic rollback)
  * runs scheduled reports and checks (plug-ins in reports/*.py, shell scripts in checks/)
  * serves a web UI (login + optional 2-factor code) to manage all of it

Endpoints that change things are only reachable after login, except:
  POST /diun        Diun webhook (Bearer secret; refused when it arrives through the reverse proxy)
  POST /api/notify  local senders on the server itself (127.0.0.1 only; used by the `notify` command)
  /update/<token>   one-time "Update" links from ntfy messages

CLI (run as root):  hub.py set-password | totp-on | totp-off | logout-all | send "Title" "Message"

Site-specific settings come from the environment (the systemd unit reads /etc/default/notify-hub).
"""
import base64
import getpass
import hashlib
import hmac
import importlib.util
import ipaddress
import json
import os
import re
import secrets
import sqlite3
import struct
import subprocess
import sys
import threading
import time
import traceback
import urllib.parse
import urllib.request
from datetime import datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HUB_DIR = os.environ.get("HUB_DIR", "/home/notify/hub")
DATA_DIR = os.environ.get("HUB_DATA", "/var/lib/notify-hub")
PORT = int(os.environ.get("HUB_PORT", "8099"))
NOTIFY_CONF = os.environ.get("NOTIFY_CONF", "/home/notify/notify.conf")
DIUN_YML = os.environ.get("HUB_DIUN_YML", "")          # Diun's config file, so the UI can change its schedule
LAN_URL = os.environ.get("HUB_LAN_URL", "")            # used in Update buttons when no public URL is set
OLD_POLICY = os.environ.get("HUB_OLD_POLICY", "/home/notify/update-approver/policy.conf")  # legacy import
TITLE_PREFIX = os.environ.get("HUB_TITLE_PREFIX", "")
HEALTH_WAIT = int(os.environ.get("HUB_HEALTH_WAIT", "300"))
STABLE_FOR = int(os.environ.get("HUB_STABLE_FOR", "30"))
NTFY_RETRIES = int(os.environ.get("HUB_NTFY_RETRIES", "20"))
TICK = int(os.environ.get("HUB_TICK", "30"))

CONFIG_FILE = os.path.join(HUB_DIR, "config.json")
SECRET_FILE = os.path.join(HUB_DIR, "diun.secret")
WEB_DIR = os.path.join(HUB_DIR, "web")
REPORTS_DIR = os.path.join(HUB_DIR, "reports")
CHECKS_DIR = os.path.join(HUB_DIR, "checks")
AUTH_FILE = os.path.join(DATA_DIR, "auth.json")
DB_FILE = os.path.join(DATA_DIR, "hub.db")

POLICIES = ("auto", "ask", "notify", "ignore")
PRIO = {"min": 1, "low": 2, "default": 3, "high": 4, "urgent": 5, "max": 5}
DAYS = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")
SESSION_IDLE = 7 * 86400
SESSION_MAX = 30 * 86400
DEFAULT_CONFIG = {
    "public_url": "",
    "quiet": {"enabled": False, "start": "22:00", "end": "07:00", "bypass_priority": 4},
    "policies": {"*": "ask"},
    "reports": {},
    "checks": {},
    "pending_ttl_days": 14,
    "history_days": 90,
}


def log(*a):
    print(*a, flush=True)


# ============================================================ storage
_db_lock = threading.RLock()
_db = None
SCHEMA = """
create table if not exists notifications(id integer primary key, ts real, source text, title text,
    message text, priority integer, tags text, status text);
create table if not exists held(nid integer primary key, body text);
create table if not exists updates(id integer primary key, ts real, container text, old text, new text,
    ok integer, mode text, detail text);
create table if not exists pending(token text primary key, containers text, image text, ts real);
create table if not exists sessions(id text primary key, created real, last real, ip text, agent text);
create table if not exists kv(k text primary key, v text);
"""


def db():
    global _db
    if _db is None:
        os.makedirs(DATA_DIR, mode=0o700, exist_ok=True)
        _db = sqlite3.connect(DB_FILE, check_same_thread=False, isolation_level=None)
        _db.row_factory = sqlite3.Row
        _db.execute("pragma journal_mode=wal")
        _db.executescript(SCHEMA)
        os.chmod(DB_FILE, 0o600)
    return _db


def q(sql, args=()):
    with _db_lock:
        return [dict(r) for r in db().execute(sql, args).fetchall()]


def x(sql, args=()):
    with _db_lock:
        return db().execute(sql, args).lastrowid


def kv_get(k, default=None):
    r = q("select v from kv where k=?", (k,))
    return json.loads(r[0]["v"]) if r else default


def kv_set(k, v):
    x("insert into kv(k,v) values(?,?) on conflict(k) do update set v=excluded.v", (k, json.dumps(v)))


_cfg_lock = threading.RLock()


def load_config():
    with _cfg_lock:
        try:
            with open(CONFIG_FILE) as f:
                cfg = json.load(f)
        except (OSError, ValueError):
            cfg = {}
        out = json.loads(json.dumps(DEFAULT_CONFIG))
        for k, v in cfg.items():
            if isinstance(v, dict) and isinstance(out.get(k), dict):
                out[k].update(v)
            else:
                out[k] = v
        return out


def save_config(cfg):
    with _cfg_lock:
        tmp = CONFIG_FILE + ".tmp"
        with open(tmp, "w") as f:
            json.dump(cfg, f, indent=2, sort_keys=True)
        os.chmod(tmp, 0o600)
        os.replace(tmp, CONFIG_FILE)


def migrate_old_policy():
    """One-time import of update-approver's policy.conf."""
    cfg = load_config()
    if kv_get("migrated_policy") or not os.path.isfile(OLD_POLICY):
        return
    with open(OLD_POLICY) as f:
        for line in f:
            parts = line.split("#", 1)[0].split()
            if len(parts) >= 2 and parts[1] in POLICIES:
                cfg["policies"][parts[0]] = parts[1]
    save_config(cfg)
    kv_set("migrated_policy", True)
    log("imported policies from", OLD_POLICY)


# ============================================================ helpers
def run(cmd, cwd=None, timeout=1200, input=None):
    try:
        p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout, input=input)
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return 124, "", f"timed out after {timeout}s"
    except OSError as e:
        return 127, "", str(e)


def tail(text, n=300):
    text = (text or "").strip()
    return text[-n:] if len(text) > n else text


def read_kv(path):
    d = {}
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            d[k.strip()] = v.strip().strip('"').strip("'")
    return d


def prio(p):
    if isinstance(p, int):
        return max(1, min(5, p))
    p = str(p or "default").strip().lower()
    return int(p) if p.isdigit() and 1 <= int(p) <= 5 else PRIO.get(p, 3)


def primary_ip():
    """The server's LAN address (no traffic is sent; this only asks the kernel which source IP it would use)."""
    import socket
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("192.0.2.1", 9))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except OSError:
        return "127.0.0.1"


def public_base():
    cfg = load_config()
    return (cfg.get("public_url") or LAN_URL or f"http://{primary_ip()}:{PORT}").rstrip("/")


# ============================================================ notifications
def quiet_now(cfg=None):
    qc = (cfg or load_config())["quiet"]
    if not qc.get("enabled"):
        return False
    try:
        now = datetime.now().strftime("%H:%M")
        s, e = qc["start"], qc["end"]
        return (s <= now < e) if s < e else (now >= s or now < e)
    except (KeyError, TypeError):
        return False


def notify(title, message, priority=3, tags=None, actions=None, source="hub", topic=None):
    """Record + deliver (or hold during quiet hours). Returns the history id."""
    cfg = load_config()
    priority = prio(priority)
    tags = [t for t in (tags or []) if t]
    body = {"title": TITLE_PREFIX + title, "message": message, "priority": priority}
    if tags:
        body["tags"] = tags
    if actions:
        body["actions"] = actions
    if topic:
        body["topic"] = topic
    nid = x("insert into notifications(ts,source,title,message,priority,tags,status) values(?,?,?,?,?,?,?)",
            (time.time(), source, title, message, priority, ",".join(tags), "queued"))
    if quiet_now(cfg) and priority < int(cfg["quiet"].get("bypass_priority", 4)):
        x("update notifications set status='held' where id=?", (nid,))
        x("insert or replace into held(nid, body) values(?,?)", (nid, json.dumps(body)))
        return nid
    threading.Thread(target=deliver, args=(nid, body), daemon=True).start()
    return nid


def deliver(nid, body):
    try:
        conf = read_kv(NOTIFY_CONF)
        url = conf["NTFY_URL"].rstrip("/")
        body.setdefault("topic", conf["NTFY_TOPIC"])
    except (OSError, KeyError) as e:
        x("update notifications set status=? where id=?", (f"failed: notify.conf {e}", nid))
        return False
    headers = {"Content-Type": "application/json"}
    if conf.get("NTFY_TOKEN"):
        headers["Authorization"] = "Bearer " + conf["NTFY_TOKEN"]
    data = json.dumps(body).encode()
    err = None
    for attempt in range(max(1, NTFY_RETRIES)):
        try:
            req = urllib.request.Request(url, data=data, headers=headers, method="POST")
            with urllib.request.urlopen(req, timeout=10) as r:
                if r.status == 200:
                    x("update notifications set status='sent' where id=?", (nid,))
                    return True
                err = f"HTTP {r.status}"
        except Exception as e:  # ntfy may be restarting
            err = e
        if attempt + 1 < NTFY_RETRIES:
            time.sleep(15)
    x("update notifications set status=? where id=?", (f"failed: {err}"[:200], nid))
    log("ntfy: giving up:", err, "|", body.get("title"))
    return False


def flush_held():
    if quiet_now():
        return
    for r in q("select nid, body from held order by nid"):
        x("delete from held where nid=?", (r["nid"],))
        x("update notifications set status='queued' where id=?", (r["nid"],))
        threading.Thread(target=deliver, args=(r["nid"], json.loads(r["body"])), daemon=True).start()


# ============================================================ docker / updates
def norm(ref):
    ref = (ref or "").split("@", 1)[0]
    if not ref:
        return ""
    if ":" not in ref.rsplit("/", 1)[-1]:
        ref += ":latest"
    first = ref.split("/", 1)[0]
    if "/" not in ref or ("." not in first and ":" not in first and first != "localhost"):
        ref = "docker.io/" + ref
    if ref.startswith("docker.io/") and ref.count("/") == 1:
        ref = "docker.io/library/" + ref[len("docker.io/"):]
    return ref


def inspect(obj, kind="container"):
    rc, out, _ = run(["docker", kind, "inspect", obj], timeout=60)
    if rc:
        return None
    try:
        return json.loads(out)[0]
    except (ValueError, IndexError):
        return None


def containers(all_=False):
    rc, out, _ = run(["docker", "ps", "-q", "--no-trunc"] + (["-a"] if all_ else []), timeout=60)
    ids = out.split()
    if rc or not ids:
        return []
    rc, out, _ = run(["docker", "container", "inspect"] + ids, timeout=120)
    try:
        return json.loads(out) if not rc else []
    except ValueError:
        return []


def cname(c):
    return c["Name"].lstrip("/")


def image_versions(ids):
    ids = sorted(set(i for i in ids if i))
    if not ids:
        return {}
    rc, out, _ = run(["docker", "image", "inspect"] + ids, timeout=60)
    res = {}
    try:
        for img in json.loads(out) if not rc else []:
            labels = (img.get("Config") or {}).get("Labels") or {}
            res[img["Id"]] = labels.get("org.opencontainers.image.version") or img["Id"].replace("sha256:", "")[:12]
    except ValueError:
        pass
    return res


def image_version(image_id):
    return image_versions([image_id]).get(image_id) or (image_id or "").replace("sha256:", "")[:12]


def compose_info(c):
    L = c["Config"].get("Labels") or {}
    proj, svc = L.get("com.docker.compose.project"), L.get("com.docker.compose.service")
    wd, cf = L.get("com.docker.compose.project.working_dir"), L.get("com.docker.compose.project.config_files")
    if not (proj and svc and wd and cf):
        return None
    files = [f if f.startswith("/") else os.path.join(wd, f) for f in cf.split(",")]
    if not all(os.path.isfile(f) for f in files):
        return None
    base = ["docker", "compose", "-p", proj]
    for f in files:
        base += ["-f", f]
    env = L.get("com.docker.compose.project.environment_file")
    if env and os.path.isfile(env):
        base += ["--env-file", env]
    return {"project": proj, "service": svc, "wd": wd, "base": base}


def wait_up(name, need_health, timeout=None):
    timeout = timeout or HEALTH_WAIT
    end = time.time() + timeout
    started, since, last = None, None, "?"
    time.sleep(3)
    while time.time() < end:
        c = inspect(name)
        if c is None:
            last = "container missing"
        else:
            st = c["State"]
            health = (st.get("Health") or {}).get("Status")
            last = health or st.get("Status")
            if st.get("Status") == "running" and not st.get("Restarting"):
                if health and need_health:
                    if health == "healthy":
                        return True, "healthy"
                else:
                    if st.get("StartedAt") != started:
                        started, since = st.get("StartedAt"), time.time()
                    elif time.time() - since >= STABLE_FOR:
                        return True, "running"
            else:
                started = None
        time.sleep(3)
    return False, f"not up after {timeout}s (last state: {last})"


def recreate(c):
    ci = compose_info(c)
    if not ci:
        rc, _, _ = run(["docker", "restart", cname(c)])
        return rc == 0
    rc, _, err = run(ci["base"] + ["up", "-d", "--no-deps", "--force-recreate", ci["service"]], cwd=ci["wd"])
    if rc:
        log("recreate failed:", cname(c), tail(err))
    return rc == 0


def update_one(name):
    c = inspect(name)
    if not c:
        return False, f"{name}: container not found", "", ""
    ci = compose_info(c)
    if not ci:
        return False, f"{name}: no compose file found for it - update it by hand", "", ""
    ref = c["Config"]["Image"]
    rc, out, err = run(ci["base"] + ["config", "--format", "json"], cwd=ci["wd"], timeout=60)
    if rc:
        return False, f"{name}: compose file is invalid: {tail(err)}", "", ""
    want = (json.loads(out).get("services", {}).get(ci["service"]) or {}).get("image", "")
    if norm(want) != norm(ref):
        return False, f"{name}: compose file says '{want}' but it runs '{ref}' - not touching it", "", ""
    old_id = c["Image"]
    old_ver = image_version(old_id)
    was_unhealthy = (c["State"].get("Health") or {}).get("Status") == "unhealthy"
    log(f"updating {name} ({old_ver})")
    rc, _, err = run(ci["base"] + ["pull", ci["service"]], cwd=ci["wd"])
    if rc:
        return False, f"{name}: pull failed: {tail(err)}", old_ver, ""
    img = inspect(want, "image")
    if not img:
        return False, f"{name}: pulled, but can't find image {want}", old_ver, ""
    new_id = img["Id"]
    if new_id == old_id:
        return True, f"{name}: already on the newest image ({old_ver})", old_ver, old_ver
    new_ver = image_version(new_id)
    deps = [d for d in containers() if d["HostConfig"].get("NetworkMode") in (f"container:{c['Id']}", f"container:{name}")]
    rc, _, err = run(ci["base"] + ["up", "-d", "--no-deps", ci["service"]], cwd=ci["wd"])
    ok, why = (True, "") if rc == 0 else (False, f"start failed: {tail(err)}")
    if ok:
        ok, why = wait_up(name, need_health=not was_unhealthy)
    if not ok:
        log(f"{name}: {why} -> rolling back to {old_ver}")
        run(["docker", "image", "tag", old_id, want])
        back = inspect(name)
        if back:
            recreate(back)
        ok2, _ = wait_up(name, need_health=False, timeout=120)
        for d in deps:
            recreate(d)
        state = "it is running again" if ok2 else "BUT IT IS NOT RUNNING - check it"
        return False, f"{name}: {new_ver} failed ({why}); rolled back to {old_ver}, {state}", old_ver, new_ver
    for d in deps:
        log(f"recreating {cname(d)} (shares {name}'s network)")
        recreate(d)
    rc, _, _ = run(["docker", "image", "rm", old_id], timeout=120)
    return True, f"{name}: {old_ver} -> {new_ver}" + (" (old image removed)" if rc == 0 else ""), old_ver, new_ver


_update_lock = threading.Lock()


def do_updates(names, mode):
    with _update_lock:
        results = []
        for n in names:
            try:
                ok, msg, old, new = update_one(n)
            except Exception as e:
                traceback.print_exc()
                ok, msg, old, new = False, f"{n}: internal error: {e}", "", ""
            x("insert into updates(ts,container,old,new,ok,mode,detail) values(?,?,?,?,?,?,?)",
              (time.time(), n, old, new, int(ok), mode, msg))
            results.append((ok, msg))
        good = all(ok for ok, _ in results)
        title = ("Updated" if good else "Update FAILED") + ": " + ", ".join(names)
        msg = "\n".join(m for _, m in results) + {"auto": "\n(automatic update)", "manual": "\n(started from the hub)"}.get(mode, "")
        notify(title, msg, priority=3 if good else 4, tags=["white_check_mark" if good else "warning"], source="updates")


def handle_diun(p):
    image = p.get("image", "")
    link = p.get("hub_link") or ""
    log(f"diun: status={p.get('status')} image={image}")
    view = [{"action": "view", "label": "Release info", "url": link}] if link.startswith("http") else []
    if "diun/testnotif" in image:
        notify("Diun test OK", "Diun -> hub -> ntfy is working.", 2, ["white_check_mark"], source="updates")
        return
    names = {cname(d) for d in containers() if norm(d["Config"]["Image"]) == norm(image)}
    for n in str((p.get("metadata") or {}).get("ctn_names") or "").split(","):
        n = n.strip().lstrip("/")
        if n and inspect(n):
            names.add(n)
    if not names:
        notify("Update seen, nothing to do", f"Diun reports a new image for {image}, but no running container uses it.",
               2, ["information_source"], view, source="updates")
        return
    pol = load_config()["policies"]
    groups = {k: [] for k in POLICIES}
    for n in sorted(names):
        p = pol.get(n) or pol.get("*", "ask")
        groups[p if p in POLICIES else "ask"].append(n)
    if groups["auto"]:
        threading.Thread(target=guard(do_updates), args=(groups["auto"], "auto"), daemon=True).start()

    def desc(ns):
        out = []
        for n in ns:
            c = inspect(n)
            out.append(f"{n} ({image_version(c['Image']) if c else '?'})")
        return ", ".join(out)

    hub_view = [{"action": "view", "label": "Open hub", "url": public_base() + "/#updates"}]
    if groups["ask"]:
        token = secrets.token_urlsafe(24)
        for r in q("select token, containers from pending"):
            if set(json.loads(r["containers"])) & set(groups["ask"]):
                x("delete from pending where token=?", (r["token"],))
        x("insert into pending(token,containers,image,ts) values(?,?,?,?)",
          (token, json.dumps(groups["ask"]), image, time.time()))
        days = load_config().get("pending_ttl_days", 14)
        notify("Update available: " + ", ".join(groups["ask"]),
               f"New image: {image}\nRunning now: {desc(groups['ask'])}\nTap Update to install it (link works once, for {days} days).",
               3, ["package"],
               [{"action": "http", "label": "Update", "url": f"{public_base()}/update/{token}", "method": "POST", "clear": True}] + (view or hub_view),
               source="updates")
    if groups["notify"]:
        notify("Update available: " + ", ".join(groups["notify"]),
               f"New image: {image}\nRunning now: {desc(groups['notify'])}\nSet to manual updates - update by hand when ready.",
               3, ["package"], view or hub_view, source="updates")


def guard(fn):
    def wrapped(*a):
        try:
            return fn(*a)
        except Exception as e:
            traceback.print_exc()
            notify("Hub error", f"{getattr(fn, '__name__', 'task')}: {e}", 4, ["warning"])
    return wrapped


def diun_schedule(new=None):
    """Read (or set) Diun's check schedule in diun.yml."""
    try:
        with open(DIUN_YML) as f:
            text = f.read()
    except OSError:
        if new is not None:
            raise ValueError("Diun's config file isn't known - set HUB_DIUN_YML in /etc/default/notify-hub")
        return None
    m = re.search(r'^(\s*schedule:\s*)"([^"]*)"', text, re.M)
    if not m:
        if new is not None:
            raise ValueError(f'no quoted schedule: line found in {DIUN_YML}')
        return None
    if new is None:
        return m.group(2)
    if not re.fullmatch(r"[0-9*/,\-]+( [0-9*/,\-]+){4}", new):
        raise ValueError("schedule must be 5 cron fields, e.g. 0 9 * * *")
    text = text[:m.start(2)] + new + text[m.end(2):]
    tmp = DIUN_YML + ".tmp"
    with open(tmp, "w") as f:
        f.write(text)
    os.chmod(tmp, 0o600)
    os.replace(tmp, DIUN_YML)
    run(["docker", "restart", "diun"], timeout=60)
    return new


# ============================================================ reports & checks
def parse_schedule(s):
    p = (s or "").lower().split()
    try:
        if len(p) == 2 and p[0] == "every" and 1 <= int(p[1]) <= 100000:
            return ("every", int(p[1]))
        if len(p) == 2 and p[0] == "daily":
            h, m = map(int, p[1].split(":"))
            if 0 <= h < 24 and 0 <= m < 60:
                return ("daily", h, m)
        if len(p) == 3 and p[0] == "weekly" and p[1][:3] in DAYS:
            h, m = map(int, p[2].split(":"))
            if 0 <= h < 24 and 0 <= m < 60:
                return ("weekly", DAYS.index(p[1][:3]), h, m)
    except ValueError:
        pass
    raise ValueError("schedule must look like 'every 30', 'daily 09:00' or 'weekly sun 18:00'")


def due(schedule, last, now):
    k = parse_schedule(schedule)
    if k[0] == "every":
        return now - last >= k[1] * 60
    dt = datetime.fromtimestamp(now)
    if k[0] == "daily":
        t = dt.replace(hour=k[1], minute=k[2], second=0, microsecond=0)
        if t > dt:
            t -= timedelta(days=1)
    else:
        t = dt.replace(hour=k[2], minute=k[3], second=0, microsecond=0) - timedelta(days=(dt.weekday() - k[1]) % 7)
        if t > dt:
            t -= timedelta(days=7)
    return last < t.timestamp() <= now


class Ctx:
    """What a report plug-in gets: helpers + its own small key/value memory."""

    def __init__(self, name):
        self.name = name

    def run(self, cmd, timeout=120):
        return run(cmd, timeout=timeout)

    def get(self, key, default=None):
        return kv_get(f"plugin:{self.name}:{key}", default)

    def set(self, key, value):
        kv_set(f"plugin:{self.name}:{key}", value)

    def http_json(self, url, headers=None, timeout=20):
        req = urllib.request.Request(url, headers=headers or {})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode())

    def containers(self, all_=False):
        return containers(all_)

    def mounts(self, setting=""):
        """Mount points from a comma-separated setting, or (blank/'auto') every real disk filesystem."""
        wanted = [m.strip() for m in str(setting or "").split(",") if m.strip() and m.strip().lower() != "auto"]
        if wanted:
            return wanted
        out, devs = [], set()
        try:
            with open("/proc/mounts") as f:
                for line in f:
                    dev, mnt, fstype = line.split()[:3]
                    mnt = mnt.replace("\\040", " ")
                    if fstype not in ("ext2", "ext3", "ext4", "xfs", "btrfs", "zfs", "f2fs", "jfs", "reiserfs"):
                        continue
                    if mnt.startswith(("/boot", "/snap", "/var/lib/docker", "/var/snap")) or dev in devs:
                        continue
                    devs.add(dev)
                    out.append(mnt)
        except OSError:
            out = ["/"]
        return out

    def log(self, *a):
        log(f"[{self.name}]", *a)


_plugins, _plugin_mtimes = {}, {}


def plugins():
    """Load/reload reports/*.py when they change."""
    seen = set()
    if os.path.isdir(REPORTS_DIR):
        for fn in sorted(os.listdir(REPORTS_DIR)):
            if not fn.endswith(".py") or fn.startswith("_"):
                continue
            path = os.path.join(REPORTS_DIR, fn)
            seen.add(path)
            mt = os.path.getmtime(path)
            if _plugin_mtimes.get(path) == mt:
                continue
            try:
                spec = importlib.util.spec_from_file_location("hubreport_" + fn[:-3], path)
                mod = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(mod)
                for attr in ("NAME", "TITLE", "run"):
                    if not hasattr(mod, attr):
                        raise ValueError(f"missing {attr}")
                for k, v in list(_plugins.items()):
                    if v["path"] == path:
                        del _plugins[k]
                _plugins[mod.NAME] = {"mod": mod, "path": path, "error": None}
            except Exception as e:
                _plugins["!" + fn] = {"mod": None, "path": path, "error": f"{fn}: {e}"}
                log("plugin load failed:", fn, e)
            _plugin_mtimes[path] = mt
    for k, v in list(_plugins.items()):
        if v["path"] not in seen:
            del _plugins[k]
            _plugin_mtimes.pop(v["path"], None)
    return _plugins


def check_scripts():
    if not os.path.isdir(CHECKS_DIR):
        return []
    return sorted(fn for fn in os.listdir(CHECKS_DIR)
                  if os.path.isfile(os.path.join(CHECKS_DIR, fn)) and os.access(os.path.join(CHECKS_DIR, fn), os.X_OK)
                  and not fn.startswith(".") and not fn.endswith((".sample", ".md", ".txt")))


def items(cfg=None):
    """Every report and check with its effective settings."""
    cfg = cfg or load_config()
    out = []
    for name, p in sorted(plugins().items()):
        if p["mod"] is None:
            out.append({"kind": "report", "name": name, "title": name.lstrip("!"), "error": p["error"],
                        "enabled": False, "schedule": "", "settings": {}, "fields": [], "description": ""})
            continue
        m = p["mod"]
        fields = list(getattr(m, "SETTINGS", []))
        saved = cfg["reports"].get(name, {})
        settings = {f["key"]: f.get("default") for f in fields}
        settings.update(saved.get("settings", {}))
        out.append({"kind": "report", "name": name, "title": m.TITLE, "description": getattr(m, "DESCRIPTION", ""),
                    "enabled": saved.get("enabled", getattr(m, "DEFAULT_ENABLED", False)),
                    "schedule": saved.get("schedule", getattr(m, "DEFAULT_SCHEDULE", "daily 09:00")),
                    "settings": settings, "fields": fields, "error": None})
    for fn in check_scripts():
        saved = cfg["checks"].get(fn, {})
        out.append({"kind": "check", "name": fn, "title": fn, "error": None,
                    "description": f"Script {CHECKS_DIR}/{fn}: exit 0 = all good (silent), other exit = alert with its output.",
                    "enabled": saved.get("enabled", False), "schedule": saved.get("schedule", "every 60"),
                    "settings": {"always_send": saved.get("settings", {}).get("always_send", False)},
                    "fields": [{"key": "always_send", "label": "Send the output even when it exits 0", "type": "bool", "default": False}]})
    for it in out:
        it["last_run"] = kv_get(f"last:{it['kind']}:{it['name']}")
        it["last_result"] = kv_get(f"result:{it['kind']}:{it['name']}")
    return out


def run_item(kind, name, send=True):
    """Run one report/check now. Returns {'title','message','priority','tags'} or None, plus an error text."""
    res, err = None, None
    try:
        it = next((i for i in items() if i["kind"] == kind and i["name"] == name), None)
        if not it:
            raise ValueError(f"no {kind} named {name}")
        if kind == "report":
            res = plugins()[name]["mod"].run(Ctx(name), it["settings"])
        else:
            rc, out, er = run([os.path.join(CHECKS_DIR, name)], timeout=300)
            text = (out or "").strip() or (er or "").strip()
            if rc != 0 or it["settings"].get("always_send"):
                lines = text.splitlines() or ["(no output)"]
                title = lines[0][6:].strip() if lines[0].lower().startswith("title:") else name
                body = "\n".join(lines[1:] if lines[0].lower().startswith("title:") else lines) or f"exit code {rc}"
                res = {"title": title, "message": body[:3500], "priority": 4 if rc >= 2 else 3,
                       "tags": ["warning"] if rc else ["information_source"]}
    except Exception as e:
        traceback.print_exc()
        err = f"{type(e).__name__}: {e}"
    kv_set(f"result:{kind}:{name}", {"ts": time.time(), "error": err,
                                      "title": (res or {}).get("title"), "message": (res or {}).get("message")})
    if send and res:
        notify(res.get("title", name), res.get("message", ""), res.get("priority", 3), res.get("tags"),
               res.get("actions"), source=name)
    elif send and err:
        notify(f"{name} failed", err, 3, ["warning"], source=name)
    return res, err


def scheduler():
    while True:
        try:
            flush_held()
            cfg = load_config()
            now = time.time()
            x("delete from notifications where ts < ?", (now - cfg.get("history_days", 90) * 86400,))
            x("delete from pending where ts < ?", (now - cfg.get("pending_ttl_days", 14) * 86400,))
            x("delete from sessions where last < ? or created < ?", (now - SESSION_IDLE, now - SESSION_MAX))
            for it in items(cfg):
                if not it["enabled"] or it.get("error"):
                    continue
                key = f"last:{it['kind']}:{it['name']}"
                last = kv_get(key)
                if last is None:          # newly enabled: start counting from now (don't fire at once)
                    kv_set(key, now)
                    continue
                try:
                    if due(it["schedule"], last, now):
                        kv_set(key, now)
                        threading.Thread(target=run_item, args=(it["kind"], it["name"]), daemon=True).start()
                except ValueError as e:
                    log("bad schedule:", it["name"], e)
        except Exception:
            traceback.print_exc()
        time.sleep(TICK)


# ============================================================ authentication
def load_auth():
    try:
        with open(AUTH_FILE) as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def save_auth(a):
    os.makedirs(DATA_DIR, mode=0o700, exist_ok=True)
    tmp = AUTH_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(a, f)
    os.chmod(tmp, 0o600)
    os.replace(tmp, AUTH_FILE)


def pw_hash(pw, salt):
    return hashlib.scrypt(pw.encode(), salt=salt, n=2 ** 15, r=8, p=1, maxmem=64 * 1024 * 1024, dklen=32).hex()


def pw_check(a, pw):
    return bool(a) and hmac.compare_digest(pw_hash(pw, bytes.fromhex(a["salt"])), a["hash"])


def totp_code(secret_b32, counter):
    key = base64.b32decode(secret_b32 + "=" * (-len(secret_b32) % 8), casefold=True)
    h = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    o = h[-1] & 0x0F
    return "%06d" % ((struct.unpack(">I", h[o:o + 4])[0] & 0x7FFFFFFF) % 1000000)


def totp_check(secret_b32, code):
    code = re.sub(r"\D", "", code or "")
    if len(code) != 6:
        return False
    now = int(time.time() // 30)
    last = kv_get("totp_last", 0)
    for c in (now - 1, now, now + 1):
        if c > last and hmac.compare_digest(totp_code(secret_b32, c), code):
            kv_set("totp_last", c)   # each code works once
            return True
    return False


_fail_lock = threading.Lock()
_fails = {}   # ip -> [timestamps]


def too_many_fails(ip):
    now = time.time()
    with _fail_lock:
        for k in list(_fails):
            _fails[k] = [t for t in _fails[k] if now - t < 900]
            if not _fails[k]:
                del _fails[k]
        return len(_fails.get(ip, [])) >= 5 or sum(len(v) for v in _fails.values()) >= 25


def add_fail(ip):
    with _fail_lock:
        _fails.setdefault(ip, []).append(time.time())
        n = len(_fails[ip])
    if n == 5:
        notify("Hub: repeated failed logins", f"5 failed logins from {ip} in 15 minutes; that address is now blocked for a while.",
               4, ["warning", "lock"], source="security")


def new_session(ip, agent):
    tok = secrets.token_urlsafe(32)
    now = time.time()
    x("insert into sessions(id,created,last,ip,agent) values(?,?,?,?,?)",
      (hashlib.sha256(tok.encode()).hexdigest(), now, now, ip, (agent or "")[:200]))
    return tok


def session_ok(tok):
    if not tok:
        return False
    sid = hashlib.sha256(tok.encode()).hexdigest()
    r = q("select created,last from sessions where id=?", (sid,))
    now = time.time()
    if not r or now - r[0]["last"] > SESSION_IDLE or now - r[0]["created"] > SESSION_MAX:
        return False
    if now - r[0]["last"] > 300:
        x("update sessions set last=? where id=?", (now, sid))
    return True


def is_private(ip):
    try:
        a = ipaddress.ip_address(ip)
        return a.is_private or a.is_loopback
    except ValueError:
        return False


# ============================================================ HTTP
STATIC = {"/app.js": ("app.js", "text/javascript"), "/app.css": ("app.css", "text/css"),
          "/login": ("login.html", "text/html"), "/favicon.svg": ("favicon.svg", "image/svg+xml")}
CSP = ("default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; "
       "form-action 'self'; frame-ancestors 'none'; base-uri 'none'")


class Handler(BaseHTTPRequestHandler):
    server_version = "notify-hub"
    sys_version = ""

    # ---- plumbing
    @property
    def proxied(self):
        return "X-Forwarded-For" in self.headers or "X-Real-IP" in self.headers

    @property
    def ip(self):
        peer = self.client_address[0]
        if self.proxied and is_private(peer):
            return (self.headers.get("X-Real-IP") or self.headers.get("X-Forwarded-For", "").split(",")[0]).strip() or peer
        return peer

    @property
    def https(self):
        return self.headers.get("X-Forwarded-Proto", "") == "https"

    def cookie(self, name):
        for part in self.headers.get("Cookie", "").split(";"):
            k, _, v = part.strip().partition("=")
            if k == name:
                return v
        return None

    @property
    def authed(self):
        return session_ok(self.cookie("hub_session"))

    def _headers(self, code, ctype, length, extra=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(length))
        self.send_header("Content-Security-Policy", CSP)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()

    def send_json(self, code, obj, extra=None):
        b = json.dumps(obj).encode()
        self._headers(code, "application/json", len(b), extra)
        self.wfile.write(b)

    def send_text(self, code, text, ctype="text/plain; charset=utf-8", extra=None):
        b = text.encode()
        self._headers(code, ctype, len(b), extra)
        self.wfile.write(b)

    def redirect(self, to, extra=None):
        h = {"Location": to}
        h.update(extra or {})
        self._headers(303, "text/plain", 0, h)

    def send_file(self, fn, ctype):
        try:
            with open(os.path.join(WEB_DIR, fn), "rb") as f:
                b = f.read()
        except OSError:
            return self.send_text(404, "not found")
        self._headers(200, ctype + ("; charset=utf-8" if ctype.startswith("text") else ""), len(b))
        self.wfile.write(b)

    def body(self):
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            n = -1
        if n < 0 or n > 65536:
            raise ValueError("bad length")
        return self.rfile.read(n) if n else b""

    def json_body(self):
        d = json.loads(self.body() or b"{}")
        if not isinstance(d, dict):
            raise ValueError("expected an object")
        return d

    def log_message(self, fmt, *args):
        msg = re.sub(r"/update/\S+", "/update/<token>", fmt % args)
        if "/api/" in msg and '" 200' in msg and "GET" in msg:
            return   # don't flood the journal with UI polling
        log("http", self.ip, msg)

    # ---- routes
    def do_GET(self):
        path = urllib.parse.urlsplit(self.path).path
        if path == "/health":
            return self.send_text(200, "ok")
        if path in STATIC:
            return self.send_file(*STATIC[path])
        m = re.fullmatch(r"/update/([A-Za-z0-9_-]{20,64})", path)
        if m:
            return self.send_file("update.html", "text/html")
        if path == "/":
            if not load_auth():
                return self.send_file("setup.html", "text/html")
            return self.send_file("index.html", "text/html") if self.authed else self.redirect("/login")
        if path.startswith("/api/"):
            if not self.authed:
                return self.send_json(401, {"error": "login required"})
            try:
                return self.api_get(path, urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query))
            except Exception as e:
                traceback.print_exc()
                return self.send_json(500, {"error": str(e)})
        self.send_text(404, "not found")

    def do_POST(self):
        path = urllib.parse.urlsplit(self.path).path
        try:
            if path == "/diun":
                if self.proxied:
                    return self.send_text(403, "forbidden")
                if not hmac.compare_digest(self.headers.get("Authorization", "").encode(), ("Bearer " + SECRET).encode()):
                    return self.send_text(403, "forbidden")
                threading.Thread(target=guard(handle_diun), args=(self.json_body(),), daemon=True).start()
                return self.send_text(200, "ok")
            if path == "/api/notify":
                if self.proxied or self.client_address[0] not in ("127.0.0.1", "::1"):
                    return self.send_text(403, "local senders only")
                def hv(name):   # http.server decodes headers as latin-1; senders (curl) send UTF-8
                    v = self.headers.get(name) or ""
                    try:
                        return v.encode("latin-1").decode("utf-8")
                    except UnicodeError:
                        return v
                msg = self.body().decode("utf-8", "replace") or "(no message)"
                nid = notify(hv("Title") or os.uname().nodename, msg, hv("Priority") or None, [t.strip() for t in hv("Tags").split(",")],
                             source=hv("X-Source") or "notify", topic=hv("X-Topic") or None)
                return self.send_text(200, f"queued {nid}")
            m = re.fullmatch(r"/update/([A-Za-z0-9_-]{20,64})", path)
            if m:
                rows = q("select containers from pending where token=?", (m.group(1),))
                x("delete from pending where token=?", (m.group(1),))
                if not rows:
                    return self.send_text(404, "This update link has expired or was already used.")
                names = json.loads(rows[0]["containers"])
                threading.Thread(target=guard(do_updates), args=(names, "approved"), daemon=True).start()
                return self.send_text(202, "Updating " + ", ".join(names) + " - a notification follows when done.")
            if path == "/api/login":
                return self.login()
            if path == "/api/logout":
                tok = self.cookie("hub_session")
                if tok:
                    x("delete from sessions where id=?", (hashlib.sha256(tok.encode()).hexdigest(),))
                return self.redirect("/login", {"Set-Cookie": "hub_session=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict"})
            if path.startswith("/api/"):
                if not self.authed:
                    return self.send_json(401, {"error": "login required"})
                if self.headers.get("X-Hub") != "1":      # blocks cross-site form posts
                    return self.send_json(403, {"error": "missing X-Hub header"})
                return self.api_post(path, self.json_body())
        except ValueError as e:
            return self.send_json(400, {"error": str(e)})
        except Exception as e:
            traceback.print_exc()
            return self.send_json(500, {"error": str(e)})
        self.send_text(404, "not found")

    def login(self):
        ip = self.ip
        if too_many_fails(ip):
            time.sleep(1)
            return self.redirect("/login?e=locked")
        form = urllib.parse.parse_qs(self.body().decode("utf-8", "replace"))
        user = (form.get("user") or [""])[0]
        pw = (form.get("password") or [""])[0]
        code = (form.get("code") or [""])[0]
        a = load_auth()
        ok = bool(a) and hmac.compare_digest(user.encode(), a["user"].encode()) and pw_check(a, pw)
        if ok and a.get("totp"):
            ok = totp_check(a["totp"], code)
        if not ok:
            add_fail(ip)
            time.sleep(1)
            return self.redirect("/login?e=1")
        tok = new_session(ip, self.headers.get("User-Agent"))
        if not is_private(ip):
            notify("Hub login", f"New login to the hub from {ip}.", 2, ["key"], source="security")
        cookie = f"hub_session={tok}; Path=/; Max-Age={SESSION_MAX}; HttpOnly; SameSite=Strict" + ("; Secure" if self.https else "")
        return self.redirect("/", {"Set-Cookie": cookie})

    # ---- API: reads
    def api_get(self, path, qs):
        if path == "/api/overview":
            cfg = load_config()
            run_c = containers()
            unhealthy = [cname(c) for c in run_c if ((c["State"].get("Health") or {}).get("Status")) == "unhealthy"]
            try:
                conf = read_kv(NOTIFY_CONF)
                with urllib.request.urlopen(conf["NTFY_URL"].rstrip("/") + "/v1/health", timeout=3) as r:
                    ntfy_ok = r.status == 200
            except Exception:
                ntfy_ok = False
            diun = inspect("diun")
            with open("/proc/uptime") as f:
                up = float(f.read().split()[0])
            return self.send_json(200, {
                "host": os.uname().nodename, "uptime": up, "ntfy_ok": ntfy_ok,
                "diun": (diun or {}).get("State", {}).get("Status", "missing"), "diun_schedule": diun_schedule(),
                "containers": len(run_c), "unhealthy": unhealthy,
                "pending": len(q("select token from pending")), "held": len(q("select nid from held")),
                "quiet": cfg["quiet"], "quiet_now": quiet_now(cfg),
                "recent": q("select * from notifications order by id desc limit 15"),
                "updates": q("select * from updates order by id desc limit 5"),
                "items": [{"kind": i["kind"], "name": i["name"], "title": i["title"], "enabled": i["enabled"],
                           "schedule": i["schedule"], "last_run": i["last_run"], "last_result": i["last_result"],
                           "error": i["error"]} for i in items(cfg)],
            })
        if path == "/api/containers":
            cfg = load_config()
            pol = cfg["policies"]
            cs = containers(all_=True)
            vers = image_versions([c["Image"] for c in cs])
            last = {r["container"]: r for r in q("select * from updates where id in (select max(id) from updates group by container)")}
            pend = {}
            for r in q("select * from pending"):
                for n in json.loads(r["containers"]):
                    pend[n] = r["ts"]
            out = []
            for c in cs:
                n = cname(c)
                out.append({"name": n, "image": c["Config"]["Image"], "version": vers.get(c["Image"], ""),
                            "state": c["State"].get("Status"), "health": (c["State"].get("Health") or {}).get("Status"),
                            "policy": pol.get(n), "default_policy": pol.get("*", "ask"),
                            "compose": compose_info(c) is not None, "last_update": last.get(n), "pending": pend.get(n)})
            out.sort(key=lambda r: (r["state"] != "running", r["name"]))
            return self.send_json(200, {"containers": out, "default_policy": pol.get("*", "ask")})
        if path == "/api/pending":
            return self.send_json(200, [{"token": r["token"], "containers": json.loads(r["containers"]), "image": r["image"], "ts": r["ts"]}
                                        for r in q("select * from pending order by ts desc")])
        if path == "/api/history":
            limit = min(int((qs.get("limit") or ["200"])[0]), 1000)
            src = (qs.get("source") or [""])[0]
            if src:
                rows = q("select * from notifications where source=? order by id desc limit ?", (src, limit))
            else:
                rows = q("select * from notifications order by id desc limit ?", (limit,))
            return self.send_json(200, {"rows": rows, "sources": [r["source"] for r in q("select distinct source from notifications order by source")]})
        if path == "/api/updates":
            return self.send_json(200, q("select * from updates order by id desc limit 200"))
        if path == "/api/items":
            return self.send_json(200, items())
        if path == "/api/settings":
            cfg = load_config()
            try:
                conf = read_kv(NOTIFY_CONF)
            except OSError:
                conf = {}
            a = load_auth() or {}
            return self.send_json(200, {
                "public_url": cfg.get("public_url", ""), "quiet": cfg["quiet"], "history_days": cfg["history_days"],
                "pending_ttl_days": cfg["pending_ttl_days"], "default_policy": cfg["policies"].get("*", "ask"),
                "ntfy_url": conf.get("NTFY_URL", ""), "ntfy_topic": conf.get("NTFY_TOPIC", ""),
                "ntfy_token_set": bool(conf.get("NTFY_TOKEN")), "diun_schedule": diun_schedule(),
                "user": a.get("user"), "totp": bool(a.get("totp")),
                "sessions": q("select created,last,ip,agent from sessions order by last desc"),
            })
        return self.send_json(404, {"error": "unknown"})

    # ---- API: changes
    def api_post(self, path, d):
        cfg = load_config()
        if path == "/api/policy":
            n, p = str(d.get("container", "")), d.get("policy")
            if not n or (p not in POLICIES and p is not None):
                raise ValueError("bad policy")
            if p is None and n != "*":
                cfg["policies"].pop(n, None)
            else:
                cfg["policies"][n] = p or "ask"
            save_config(cfg)
            return self.send_json(200, {"ok": True})
        if path == "/api/update-now":
            n = str(d.get("container", ""))
            if not inspect(n):
                raise ValueError("no such container")
            threading.Thread(target=guard(do_updates), args=([n], "manual"), daemon=True).start()
            return self.send_json(202, {"ok": True, "message": f"Updating {n} - watch for the notification."})
        if path in ("/api/pending/approve", "/api/pending/dismiss"):
            tok = str(d.get("token", ""))
            rows = q("select containers from pending where token=?", (tok,))
            x("delete from pending where token=?", (tok,))
            if not rows:
                raise ValueError("already handled or expired")
            if path.endswith("approve"):
                threading.Thread(target=guard(do_updates), args=(json.loads(rows[0]["containers"]), "approved"), daemon=True).start()
            return self.send_json(200, {"ok": True})
        if path == "/api/check-updates":
            rc, _, err = run(["docker", "restart", "diun"], timeout=60)
            if rc:
                raise ValueError("couldn't restart Diun: " + tail(err))
            return self.send_json(200, {"ok": True, "message": "Diun is checking all images now; anything new arrives as a notification."})
        if path == "/api/items/save":
            kind, name = d.get("kind"), str(d.get("name", ""))
            it = next((i for i in items(cfg) if i["kind"] == kind and i["name"] == name), None)
            if not it or it.get("error"):
                raise ValueError("unknown item")
            sched = str(d.get("schedule", it["schedule"])).strip()
            parse_schedule(sched)
            settings = dict(it["settings"])
            for f in it["fields"]:
                if f["key"] in (d.get("settings") or {}):
                    v = d["settings"][f["key"]]
                    if f.get("type") == "number":
                        v = float(v) if "." in str(v) else int(v)
                    elif f.get("type") == "bool":
                        v = bool(v)
                    else:
                        v = str(v)[:500]
                    settings[f["key"]] = v
            section = "reports" if kind == "report" else "checks"
            enabled = bool(d.get("enabled", it["enabled"]))
            if enabled and not it["enabled"]:
                kv_set(f"last:{kind}:{name}", time.time())
            cfg[section][name] = {"enabled": enabled, "schedule": sched, "settings": settings}
            save_config(cfg)
            return self.send_json(200, {"ok": True})
        if path == "/api/items/run":
            res, err = run_item(d.get("kind"), str(d.get("name", "")), send=bool(d.get("send")))
            return self.send_json(200, {"result": res, "error": err})
        if path == "/api/test":
            notify("Test from the hub", "If you can read this, the hub can reach your phone.", 3, ["wave"], source="hub")
            return self.send_json(200, {"ok": True})
        if path == "/api/settings":
            if "public_url" in d:
                u = str(d["public_url"]).strip().rstrip("/")
                if u and not re.fullmatch(r"https?://[A-Za-z0-9.\-]+(:\d+)?", u):
                    raise ValueError("public URL must look like https://hub.example.com")
                cfg["public_url"] = u
            if "quiet" in d:
                qd = d["quiet"]
                for k in ("start", "end"):
                    if not re.fullmatch(r"([01]\d|2[0-3]):[0-5]\d", str(qd.get(k, ""))):
                        raise ValueError("quiet hours must be HH:MM")
                cfg["quiet"] = {"enabled": bool(qd.get("enabled")), "start": qd["start"], "end": qd["end"],
                                "bypass_priority": max(1, min(6, int(qd.get("bypass_priority", 4))))}
            for k in ("history_days", "pending_ttl_days"):
                if k in d:
                    cfg[k] = max(1, min(3650, int(d[k])))
            if "default_policy" in d:
                if d["default_policy"] not in POLICIES:
                    raise ValueError("bad policy")
                cfg["policies"]["*"] = d["default_policy"]
            if any(k in d for k in ("ntfy_url", "ntfy_topic", "ntfy_token")):
                write_notify_conf(d)
            if d.get("diun_schedule"):
                diun_schedule(str(d["diun_schedule"]).strip())
            save_config(cfg)
            return self.send_json(200, {"ok": True})
        if path == "/api/password":
            a = load_auth()
            if not pw_check(a, str(d.get("current", ""))):
                raise ValueError("current password is wrong")
            new = str(d.get("new", ""))
            if len(new) < 12:
                raise ValueError("use at least 12 characters")
            salt = secrets.token_bytes(16)
            a.update({"salt": salt.hex(), "hash": pw_hash(new, salt)})
            save_auth(a)
            return self.send_json(200, {"ok": True})
        if path == "/api/logout-all":
            x("delete from sessions")
            return self.send_json(200, {"ok": True})
        return self.send_json(404, {"error": "unknown"})


def write_notify_conf(d):
    conf = read_kv(NOTIFY_CONF)
    url = str(d.get("ntfy_url", conf.get("NTFY_URL", ""))).strip().rstrip("/")
    topic = str(d.get("ntfy_topic", conf.get("NTFY_TOPIC", ""))).strip()
    token = conf.get("NTFY_TOKEN", "")
    if "ntfy_token" in d and d["ntfy_token"] is not None:
        token = str(d["ntfy_token"]).strip()
    if not re.fullmatch(r"https?://[A-Za-z0-9.\-]+(:\d+)?(/[A-Za-z0-9._\-/]*)?", url):
        raise ValueError("ntfy URL looks wrong")
    if not re.fullmatch(r"[A-Za-z0-9_\-]{1,64}", topic):
        raise ValueError("topic may only contain letters, digits, - and _")
    if not re.fullmatch(r"[A-Za-z0-9_.\-]*", token):
        raise ValueError("token has unexpected characters")
    lines = ["# Central ntfy settings (also used by the notify command).",
             "# Managed by notify-hub - change them in the hub's Settings page or here (sudo).",
             f"NTFY_URL={url}", f"NTFY_TOPIC={topic}"]
    lines.append(f"NTFY_TOKEN={token}" if token else "# NTFY_TOKEN=")
    tmp = NOTIFY_CONF + ".tmp"
    with open(tmp, "w") as f:
        f.write("\n".join(lines) + "\n")
    os.chmod(tmp, 0o644)
    os.replace(tmp, NOTIFY_CONF)


# ============================================================ CLI
def cli(argv):
    cmd = argv[0] if argv else ""
    if cmd == "set-password":
        a = load_auth() or {}
        user = input(f"Username [{a.get('user', 'admin')}]: ").strip() or a.get("user", "admin")
        while True:
            pw = getpass.getpass("New password (12+ characters): ")
            if len(pw) < 12:
                print("Too short.")
                continue
            if pw != getpass.getpass("Again: "):
                print("They don't match.")
                continue
            break
        salt = secrets.token_bytes(16)
        a.update({"user": user, "salt": salt.hex(), "hash": pw_hash(pw, salt)})
        save_auth(a)
        x("delete from sessions")
        print(f"Saved. User '{user}'. All existing logins were signed out.")
    elif cmd == "totp-on":
        a = load_auth()
        if not a:
            sys.exit("Set a password first: set-password")
        secret = base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")
        label = urllib.parse.quote(f"NotifyHub {os.uname().nodename}:{a['user']}")
        print("Add this to your authenticator app (scan as text/QR, or type the key):")
        print(f"  key: {secret}")
        print(f"  otpauth://totp/{label}?secret={secret}&issuer=NotifyHub")
        code = input("Enter the 6-digit code it shows to confirm: ")
        if not totp_check(secret, code):
            sys.exit("That code didn't match - nothing changed. Check the phone's clock and try again.")
        a["totp"] = secret
        save_auth(a)
        x("delete from sessions")
        print("Two-factor login is ON. All existing logins were signed out.")
    elif cmd == "totp-off":
        a = load_auth()
        if a:
            a.pop("totp", None)
            save_auth(a)
        print("Two-factor login is OFF.")
    elif cmd == "logout-all":
        x("delete from sessions")
        print("All sessions signed out.")
    elif cmd == "send" and len(argv) >= 3:
        nid = notify(argv[1], argv[2], argv[3] if len(argv) > 3 else 3, source="cli")
        time.sleep(3)
        print("status:", q("select status from notifications where id=?", (nid,))[0]["status"])
    else:
        print(__doc__)


if __name__ == "__main__":
    if len(sys.argv) > 1:
        cli(sys.argv[1:])
        sys.exit(0)
    with open(SECRET_FILE) as f:
        SECRET = f.read().strip()
    if len(SECRET) < 16:
        raise SystemExit(f"secret in {SECRET_FILE} is missing/too short")
    db()
    migrate_old_policy()
    threading.Thread(target=scheduler, daemon=True).start()
    log(f"notify-hub listening on :{PORT}, public url {public_base()}")
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
