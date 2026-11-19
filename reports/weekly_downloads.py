"""Weekly downloads: what Radarr and Sonarr imported recently."""
import re
from datetime import datetime, timedelta, timezone

NAME = "weekly_downloads"
TITLE = "Weekly downloads"
DESCRIPTION = "Movies and TV episodes that Radarr and Sonarr imported in the last few days."
DEFAULT_ENABLED = True
DEFAULT_SCHEDULE = "weekly sun 18:00"
SETTINGS = [
    {"key": "days", "label": "Look back (days)", "type": "number", "default": 7},
    {"key": "send_when_empty", "label": "Send even when nothing was downloaded", "type": "bool", "default": False},
    {"key": "radarr_url", "label": "Radarr address", "type": "text", "default": "http://127.0.0.1:7878"},
    {"key": "radarr_config", "label": "Radarr config.xml (blank = find it from the radarr container)", "type": "text", "default": ""},
    {"key": "sonarr_url", "label": "Sonarr address", "type": "text", "default": "http://127.0.0.1:8989"},
    {"key": "sonarr_config", "label": "Sonarr config.xml (blank = find it from the sonarr container)", "type": "text", "default": ""},
]
IMPORTED = ("downloadFolderImported", 3, "3")


def find_config(ctx, app):
    """config.xml in the host folder mounted at /config of the running container whose image mentions the app."""
    for c in ctx.containers():
        if app in (c["Config"].get("Image") or "").lower():
            for m in c.get("Mounts", []):
                if m.get("Destination") == "/config" and m.get("Source"):
                    return m["Source"].rstrip("/") + "/config.xml"
    raise ValueError(f"no running {app} container with a /config folder - set the config.xml path")


def api_key(path):
    with open(path) as f:
        m = re.search(r"<ApiKey>([^<]+)</ApiKey>", f.read())
    if not m:
        raise ValueError(f"no ApiKey in {path}")
    return m.group(1)


def ranges(nums):
    nums = sorted(set(nums))
    out, start, prev = [], None, None
    for n in nums:
        if start is None:
            start = prev = n
        elif n == prev + 1:
            prev = n
        else:
            out.append((start, prev))
            start = prev = n
    if start is not None:
        out.append((start, prev))
    return ", ".join(f"E{a:02d}" if a == b else f"E{a:02d}-E{b:02d}" for a, b in out)


def run(ctx, s):
    days = int(s.get("days") or 7)
    since = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")
    errors, movies, shows = [], [], {}

    try:
        key = api_key(s.get("radarr_config") or find_config(ctx, "radarr"))
        data = ctx.http_json(f"{s['radarr_url'].rstrip('/')}/api/v3/history/since?date={since}&eventType=3&includeMovie=true",
                             {"X-Api-Key": key})
        seen = set()
        for r in data:
            if r.get("eventType") not in IMPORTED:
                continue
            m = r.get("movie") or {}
            mid = m.get("id") or r.get("movieId")
            if mid in seen:
                continue
            seen.add(mid)
            movies.append(f"{m.get('title', r.get('sourceTitle', '?'))} ({m.get('year', '?')})")
    except Exception as e:
        errors.append(f"Radarr: {e}")

    episodes = 0
    try:
        key = api_key(s.get("sonarr_config") or find_config(ctx, "sonarr"))
        data = ctx.http_json(f"{s['sonarr_url'].rstrip('/')}/api/v3/history/since?date={since}&eventType=3"
                             "&includeSeries=true&includeEpisode=true", {"X-Api-Key": key})
        seen = set()
        for r in data:
            if r.get("eventType") not in IMPORTED:
                continue
            ep = r.get("episode") or {}
            eid = ep.get("id") or r.get("episodeId")
            if eid in seen:
                continue
            seen.add(eid)
            episodes += 1
            title = (r.get("series") or {}).get("title", "?")
            shows.setdefault(title, {}).setdefault(ep.get("seasonNumber", 0), []).append(ep.get("episodeNumber", 0))
    except Exception as e:
        errors.append(f"Sonarr: {e}")

    if not movies and not episodes and not errors and not s.get("send_when_empty"):
        return None
    lines = []
    if movies:
        lines.append(f"Movies ({len(movies)}):")
        lines += [f"  - {m}" for m in sorted(movies)]
    if shows:
        if lines:
            lines.append("")
        lines.append(f"TV ({episodes} episode{'s' if episodes != 1 else ''} of {len(shows)} show{'s' if len(shows) != 1 else ''}):")
        for title in sorted(shows):
            parts = [f"S{season:02d} {ranges(eps)}" for season, eps in sorted(shows[title].items())]
            lines.append(f"  - {title}: " + "; ".join(parts))
    if not movies and not shows:
        lines.append(f"Nothing new in the last {days} days.")
    if errors:
        lines += ["", "Problems: " + "; ".join(errors)]
    summary = []
    if movies:
        summary.append(f"{len(movies)} movie{'s' if len(movies) != 1 else ''}")
    if episodes:
        summary.append(f"{episodes} episode{'s' if episodes != 1 else ''}")
    return {"title": "This week: " + (", ".join(summary) if summary else "nothing new"),
            "message": "\n".join(lines), "priority": 3 if not errors else 4, "tags": ["clapper"]}
