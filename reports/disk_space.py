"""Disk space alert: tells you once when a drive gets too full, and once when it's back to normal."""
import os

NAME = "disk_space"
TITLE = "Disk space alert"
DESCRIPTION = "Alerts once when a drive passes the limit, and once when it drops back below it."
DEFAULT_ENABLED = True
DEFAULT_SCHEDULE = "every 30"
SETTINGS = [
    {"key": "mounts", "label": "Mount points to watch (comma separated; auto = all disks)", "type": "text", "default": "auto"},
    {"key": "threshold", "label": "Alert above (% used)", "type": "number", "default": 85},
]


def run(ctx, s):
    limit = float(s.get("threshold") or 85)
    alerted = ctx.get("alerted", {})
    over, back = [], []
    for mnt in ctx.mounts(s.get("mounts")):
        try:
            st = os.statvfs(mnt)
        except OSError:
            continue
        if not st.f_blocks:
            continue
        pct = 100 - st.f_bavail * 100 / st.f_blocks
        free_gb = st.f_bavail * st.f_frsize / 1024 ** 3
        if pct >= limit and not alerted.get(mnt):
            alerted[mnt] = True
            over.append(f"{mnt} is {pct:.0f}% full ({free_gb:.0f} GB free)")
        elif pct < limit - 2 and alerted.get(mnt):
            alerted.pop(mnt)
            back.append(f"{mnt} is back to {pct:.0f}% ({free_gb:.0f} GB free)")
    ctx.set("alerted", alerted)
    if over:
        return {"title": "Disk space low", "message": "\n".join(over + back), "priority": 4, "tags": ["warning", "floppy_disk"]}
    if back:
        return {"title": "Disk space OK again", "message": "\n".join(back), "priority": 2, "tags": ["white_check_mark"]}
    return None
