"""Container watch: unhealthy containers, restart loops, and containers that crash and stay down."""
import time

NAME = "container_watch"
TITLE = "Container watch"
DESCRIPTION = "Alerts when a container stays unhealthy, keeps restarting, or crashes and stays down - and when it recovers."
DEFAULT_ENABLED = True
DEFAULT_SCHEDULE = "every 5"
SETTINGS = [
    {"key": "unhealthy_minutes", "label": "Alert after unhealthy for (minutes)", "type": "number", "default": 10},
    {"key": "restarts", "label": "Alert after this many restarts between checks", "type": "number", "default": 3},
    {"key": "ignore", "label": "Ignore these containers (comma separated)", "type": "text", "default": ""},
]


def run(ctx, s):
    ignore = {n.strip() for n in str(s.get("ignore", "")).split(",") if n.strip()}
    st = ctx.get("state", {})          # name -> {"bad_since", "alerted", "restarts", "running"}
    first_run = not st
    now = time.time()
    alerts, recovered = [], []
    seen = set()
    for c in ctx.containers(all_=True):
        n = c["Name"].lstrip("/")
        if n in ignore:
            continue
        seen.add(n)
        state = c["State"]
        health = (state.get("Health") or {}).get("Status")
        rec = st.get(n, {"bad_since": None, "alerted": False, "restarts": c.get("RestartCount", 0), "running": False})
        problem = None
        restarted = c.get("RestartCount", 0) - rec.get("restarts", 0)   # restarts since the last check (<0 = recreated)
        code = state.get("ExitCode", 0)
        stopped_on_purpose = code in (0, 137, 143)   # clean exit, or docker stop (SIGTERM=143 / SIGKILL=137)
        if state.get("Status") == "running" and health == "unhealthy":
            rec["bad_since"] = rec["bad_since"] or now
            if now - rec["bad_since"] >= float(s.get("unhealthy_minutes") or 10) * 60:
                problem = f"{n} has been unhealthy for {int((now - rec['bad_since']) / 60)} min"
        elif state.get("Restarting") or restarted >= int(s.get("restarts") or 3):
            rec["bad_since"] = rec["bad_since"] or now
            problem = f"{n} keeps restarting (exit code {code})"
        elif state.get("Status") == "exited" and rec.get("running") and not stopped_on_purpose:
            rec["bad_since"] = rec["bad_since"] or now
            problem = f"{n} crashed (exit code {code}) and is down"
        elif state.get("Status") == "running" and health in (None, "healthy") and restarted <= 0:
            # only "recovered" once it went a whole check without restarting
            if rec.get("alerted"):
                recovered.append(f"{n} is running{' and healthy' if health else ''} again")
            rec["bad_since"], rec["alerted"] = None, False
        elif state.get("Status") == "exited" and rec.get("alerted") and stopped_on_purpose:
            rec["bad_since"], rec["alerted"] = None, False
        if problem and not rec["alerted"] and not first_run:
            alerts.append(problem)
            rec["alerted"] = True
        rec["restarts"] = c.get("RestartCount", 0)
        rec["running"] = state.get("Status") == "running"
        st[n] = rec
    for n in list(st):
        if n not in seen:
            del st[n]
    ctx.set("state", st)
    if alerts:
        return {"title": "Container problem", "message": "\n".join(alerts + recovered) +
                "\n\nLogs: docker logs --tail 50 <name>", "priority": 4, "tags": ["warning", "whale"]}
    if recovered:
        return {"title": "Container recovered", "message": "\n".join(recovered), "priority": 2, "tags": ["white_check_mark"]}
    return None
