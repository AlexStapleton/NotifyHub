"""Server health summary: RAID, drives, space, containers, updates."""
import json
import os
import re

NAME = "server_health"
TITLE = "Server health summary"
DESCRIPTION = "RAID state, drive SMART health and temperatures, free space, containers, pending OS updates."
DEFAULT_ENABLED = True
DEFAULT_SCHEDULE = "weekly sun 18:05"
SETTINGS = [
    {"key": "mounts", "label": "Mount points to report (comma separated; auto = all disks)", "type": "text", "default": "auto"},
    {"key": "temp_warn", "label": "Drive temperature warning (°C)", "type": "number", "default": 50},
    {"key": "only_problems", "label": "Only send when something needs attention", "type": "bool", "default": False},
]


def human(n):
    for unit in ("B", "KB", "MB", "GB", "TB", "PB"):
        if n < 1024 or unit == "PB":
            return f"{n:.0f} {unit}" if unit in ("B", "KB", "MB") else f"{n:.1f} {unit}"
        n /= 1024


def run(ctx, s):
    lines, problems = [], []

    # RAID
    try:
        with open("/proc/mdstat") as f:
            md = f.read()
        for m in re.finditer(r"^(md\d+) : (\w+) (\w+) .*?\n.*?\[(\d+)/(\d+)\] \[([U_]+)\](.*?)(?=^md|\Z)", md, re.M | re.S):
            name, state, level, total, up, flags, rest = m.groups()
            act = ""
            try:
                with open(f"/sys/block/{name}/md/sync_action") as f2:
                    a = f2.read().strip()
                act = "" if a == "idle" else f", {a} running"
                with open(f"/sys/block/{name}/md/mismatch_cnt") as f2:
                    mm = int(f2.read().strip())
                if mm:
                    act += f", mismatch_cnt {mm}"
            except OSError:
                pass
            ok = state == "active" and "_" not in flags
            lines.append(f"RAID {name} ({level}): {'OK' if ok else 'DEGRADED'} [{flags}]{act}")
            if not ok:
                problems.append(f"{name} is degraded")
    except OSError:
        lines.append("RAID: /proc/mdstat not readable")

    # drives
    rc, out, _ = ctx.run(["lsblk", "-dno", "NAME,TYPE,TRAN"])
    disks = [l.split()[0] for l in out.splitlines() if len(l.split()) >= 2 and l.split()[1] == "disk" and not l.startswith(("loop", "zram"))]
    for d in disks:
        rc, out, _ = ctx.run(["smartctl", "-j", "-H", "-A", "-i", f"/dev/{d}"], timeout=60)
        try:
            j = json.loads(out)
        except ValueError:
            continue
        passed = (j.get("smart_status") or {}).get("passed")
        temp = (j.get("temperature") or {}).get("current")
        hours = (j.get("power_on_time") or {}).get("hours")
        attrs = {a["id"]: a["raw"]["value"] for a in (j.get("ata_smart_attributes") or {}).get("table", [])}
        realloc, pend, unc = attrs.get(5, 0), attrs.get(197, 0), attrs.get(198, 0)
        nvme = j.get("nvme_smart_health_information_log") or {}
        if nvme:
            temp = temp or nvme.get("temperature")
            hours = hours or nvme.get("power_on_hours")
        model = j.get("model_name") or ""
        bad = []
        if passed is None and not attrs and not nvme:
            lines.append(f"/dev/{d}: SMART data not readable (needs root)")
            continue
        if passed is False:
            bad.append("SMART FAILED")
        if realloc or pend or unc:
            bad.append(f"reallocated {realloc}, pending {pend}, uncorrectable {unc}")
        if temp and temp >= int(s.get("temp_warn") or 50):
            bad.append(f"hot ({temp}°C)")
        if bad:
            problems.append(f"/dev/{d}: " + ", ".join(bad))
        lines.append(f"/dev/{d} {model}: {'OK' if not bad else '; '.join(bad)}"
                     + (f", {temp}°C" if temp else "") + (f", {hours // 24 // 365:.0f}y {hours // 24 % 365}d on" if hours else ""))

    # space
    for mnt in ctx.mounts(s.get("mounts")):
        try:
            st = os.statvfs(mnt)
            total, free = st.f_blocks * st.f_frsize, st.f_bavail * st.f_frsize
            pct = 100 - free * 100 / total if total else 0
            lines.append(f"{mnt}: {pct:.0f}% used, {human(free)} free")
            if pct >= 85:
                problems.append(f"{mnt} is {pct:.0f}% full")
        except OSError:
            lines.append(f"{mnt}: not mounted")
            problems.append(f"{mnt} not mounted")

    # containers
    cs = ctx.containers(all_=False)
    unhealthy = [c["Name"].lstrip("/") for c in cs if ((c["State"].get("Health") or {}).get("Status")) == "unhealthy"]
    lines.append(f"Containers: {len(cs)} running" + (f", unhealthy: {', '.join(unhealthy)}" if unhealthy else ", all healthy"))
    if unhealthy:
        problems.append("unhealthy: " + ", ".join(unhealthy))

    # OS
    with open("/proc/uptime") as f:
        up = float(f.read().split()[0])
    rc, out, _ = ctx.run(["apt-get", "-s", "-o", "Debug::NoLocking=1", "upgrade"], timeout=120)
    upd = len(re.findall(r"^Inst ", out, re.M))
    sec = len(re.findall(r"^Inst .*-security", out, re.M))
    reboot = os.path.exists("/var/run/reboot-required")
    lines.append(f"Up {up // 86400:.0f} days; {upd} package update(s) waiting ({sec} security)" + ("; REBOOT NEEDED" if reboot else ""))

    if s.get("only_problems") and not problems:
        return None
    host = os.uname().nodename
    title = f"{host} health: all good" if not problems else f"{host} health: {len(problems)} thing(s) need attention"
    msg = ("Needs attention:\n  - " + "\n  - ".join(problems) + "\n\n" if problems else "") + "\n".join(lines)
    return {"title": title, "message": msg, "priority": 4 if problems else 2,
            "tags": ["warning"] if problems else ["white_check_mark"]}
