"use strict";
// NotifyHub UI - plain JS, no libraries. All text goes through textContent (no HTML injection).

const $ = (s, r = document) => r.querySelector(s);
function el(tag, attrs = {}, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k === "class") e.className = v;
    else if (k.startsWith("on")) e.addEventListener(k.slice(2), v);
    else if (k === "value") e.value = v;
    else if (k === "checked") e.checked = !!v;
    else e.setAttribute(k, v === true ? "" : v);
  }
  for (const k of kids.flat()) if (k !== null && k !== undefined && k !== false) e.append(k instanceof Node ? k : String(k));
  return e;
}
function show(...kids) { $("#view").replaceChildren(...kids.flat(Infinity).filter(k => k !== null && k !== undefined && k !== false)); }
const ranAt = (i) => i.last_result ? i.last_result.ts : null;   // last real run (not the scheduler's start mark)
function toast(msg) {
  const t = $("#toast"); if (!t) return alert(msg);
  t.textContent = msg; t.classList.add("show"); clearTimeout(toast._t);
  toast._t = setTimeout(() => t.classList.remove("show"), 3500);
}
async function api(path, body) {
  const opt = { credentials: "same-origin", headers: {} };
  if (body !== undefined) { opt.method = "POST"; opt.headers["Content-Type"] = "application/json"; opt.headers["X-Hub"] = "1"; opt.body = JSON.stringify(body); }
  const r = await fetch(path, opt);
  if (r.status === 401) { location.href = "/login"; throw new Error("login required"); }
  const d = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(d.error || ("HTTP " + r.status));
  return d;
}
const ago = (ts) => {
  if (!ts) return "never";
  const s = Date.now() / 1000 - ts;
  if (s < 60) return "just now";
  if (s < 3600) return Math.round(s / 60) + " min ago";
  if (s < 86400) return Math.round(s / 3600) + " h ago";
  return Math.round(s / 86400) + " d ago";
};
const when = (ts) => ts ? new Date(ts * 1000).toLocaleString([], { dateStyle: "medium", timeStyle: "short" }) : "";
const SCHED_HELP = "every 30 · daily 09:00 · weekly sun 18:00";
const POLICY_TEXT = { auto: "Auto-update", ask: "Ask me (button)", notify: "Just tell me", ignore: "Ignore" };

// ---------------------------------------------------------------- login + one-time update pages
if ($("form.login")) {
  const e = new URLSearchParams(location.search).get("e");
  if (e) { const p = $("#err"); p.hidden = false; p.textContent = e === "locked" ? "Too many failed attempts. Try again in 15 minutes."
    : e === "busy" ? "Too many sign-ins at once. Try again in a moment." : "Wrong username, password or code."; }
}
if ($("#upd")) {
  $("#go").addEventListener("click", async () => {
    $("#go").disabled = true;
    const r = await fetch(location.pathname, { method: "POST" });
    $("#out").textContent = await r.text();
  });
}

// ---------------------------------------------------------------- app
const view = $("#view");
const pages = { overview, updates, reports, history, settings };
let refreshTimer = null;
async function route() {
  if (!view) return;
  const page = (location.hash || "#overview").slice(1).split("?")[0];
  document.querySelectorAll("#tabs a").forEach(a => a.classList.toggle("on", a.getAttribute("href") === "#" + page));
  clearInterval(refreshTimer);
  refreshTimer = null;
  const fn = pages[page] || overview;
  try { await fn(); }
  catch (e) { show(el("p", { class: "err" }, e.message)); }
  // Only the overview auto-refreshes: exactly one timer, and only while the tab is visible.
  if (fn === overview) refreshTimer = setInterval(() => { if (!document.hidden) overview().catch(() => {}); }, 30000);
}
window.addEventListener("hashchange", route);
route();

function feed(rows) {
  if (!rows.length) return el("p", { class: "muted" }, "Nothing yet.");
  return el("ul", { class: "feed" }, rows.map(r => el("li", {},
    el("span", { class: "p p" + r.priority, title: "priority " + r.priority }),
    el("div", {},
      el("div", { class: "row spread" }, el("span", { class: "t" }, r.title),
        el("span", { class: "muted small" }, `${r.source} · ${when(r.ts)}`,
          r.status !== "sent" ? el("span", { class: "chip " + (r.status.startsWith("failed") ? "bad" : "warn") }, " " + r.status) : null)),
      el("div", { class: "m" }, r.message)))));
}

async function overview() {
  const d = await api("/api/overview");
  const stat = (k, v, cls) => el("div", { class: "card stat" }, el("div", { class: "k" }, k), el("div", { class: "v" }, cls ? el("span", { class: "dot " + cls }) : null, v));
  const days = Math.floor(d.uptime / 86400), hrs = Math.floor(d.uptime % 86400 / 3600);
  show(
    el("div", { class: "row spread" }, el("h2", {}, d.host),
      el("div", { class: "row" },
        el("button", { class: "ghost", onclick: async () => { await api("/api/test", {}); toast("Test notification sent."); } }, "Send test notification"),
        el("button", { class: "ghost", onclick: async () => { const r = await api("/api/check-updates", {}); toast(r.message); } }, "Check for updates now"))),
    el("div", { class: "grid" },
      stat("ntfy", d.ntfy_ok ? "reachable" : "DOWN", d.ntfy_ok ? "ok" : "bad"),
      stat("Diun (update checks)", d.diun, d.diun === "running" ? "ok" : "bad"),
      stat("Containers running", d.containers + (d.unhealthy.length ? ` · ${d.unhealthy.length} unhealthy` : ""), d.unhealthy.length ? "warn" : "ok"),
      stat("Updates available", String(d.available), d.available ? "warn" : "ok"),
      stat("Waiting for approval", String(d.pending), d.pending ? "warn" : null),
      stat("Quiet hours", d.quiet.enabled ? `${d.quiet.start}–${d.quiet.end}${d.quiet_now ? " (now)" : ""}` : "off", d.quiet_now ? "warn" : null),
      stat("Uptime", `${days} d ${hrs} h`)),
    d.unhealthy.length ? el("p", { class: "err" }, "Unhealthy: " + d.unhealthy.join(", ")) : null,
    d.held ? el("p", { class: "muted" }, `${d.held} notification(s) held for the end of quiet hours.`) : null,
    el("h2", {}, "Scheduled"),
    el("div", { class: "card scroll" }, el("table", { class: "table" },
      el("tr", {}, el("th", {}, "Name"), el("th", {}, "Schedule"), el("th", {}, "Last run")),
      d.items.map(i => el("tr", {}, el("td", {}, i.title, i.kind === "check" ? el("span", { class: "chip" }, " check") : null),
        el("td", {}, i.error ? el("span", { class: "err" }, i.error) : i.enabled ? i.schedule : el("span", { class: "muted" }, "off")),
        el("td", { class: "muted" }, ago(ranAt(i))))),
      el("tr", {}, el("td", {}, "Diun image check"), el("td", {}, d.diun_schedule ? "cron " + d.diun_schedule : "?"), el("td", {})))),
    el("h2", {}, "Recent notifications"), el("div", { class: "card" }, feed(d.recent)),
    el("h2", {}, "Recent updates"), el("div", { class: "card" }, updatesTable(d.updates)));
}

function updatesTable(rows) {
  if (!rows.length) return el("p", { class: "muted" }, "No updates yet.");
  return el("div", { class: "scroll" }, el("table", { class: "table" },
    el("tr", {}, el("th", {}, "When"), el("th", {}, "Container"), el("th", {}, "Result"), el("th", { class: "hide-sm" }, "How")),
    rows.map(r => el("tr", {}, el("td", { class: "muted small" }, when(r.ts)), el("td", {}, r.container),
      el("td", {}, el("span", { class: "chip " + (r.ok ? "ok" : "bad") }, r.ok ? "OK" : "failed"), " ", el("span", { class: "small" }, r.detail.replace(r.container + ": ", ""))),
      el("td", { class: "muted small hide-sm" }, r.mode)))));
}

async function updates() {
  const [c, pend, hist] = await Promise.all([api("/api/containers"), api("/api/pending"), api("/api/updates")]);
  const policySel = (cur, onchange, withDefault) => el("select", { onchange },
    withDefault ? el("option", { value: "", selected: !cur }, `Default: ${POLICY_TEXT[c.default_policy]}`) : null,
    Object.entries(POLICY_TEXT).map(([k, v]) => el("option", { value: k, selected: cur === k }, v)));
  const updateNow = async (name, btn) => {
    if (!confirm(`Update ${name} now? It restarts if a newer image exists.`)) return;
    if (btn) btn.disabled = true;
    const x = await api("/api/update-now", { container: name }); toast(x.message);
  };
  show(
    el("div", { class: "row spread" }, el("h2", {}, "Out of date"),
      el("div", { class: "row" }, el("span", { class: "muted small" }, "Last checked " + ago(c.checked)),
        el("button", { class: "ghost sm", onclick: async (e) => { e.target.disabled = true; const r = await api("/api/check-updates", {}); toast(r.message); } }, "Check now"))),
    el("div", { class: "card" }, c.available.length ? el("ul", { class: "feed" }, c.available.map(a => el("li", {}, el("span", { class: "p p4" }),
      el("div", { class: "row spread" },
        el("div", {}, el("div", { class: "t" }, a.name),
          el("div", { class: "m" }, a.image + (a.running_version ? ` · running ${a.running_version}` : "")),
          a.change ? el("div", { class: "m" }, a.change) : null),
        a.compose ? el("button", { onclick: (e) => updateNow(a.name, e.target) }, "Update now")
                  : el("span", { class: "muted small" }, "not from a compose file - update by hand")))))
      : el("p", { class: "muted" }, c.checked ? "Everything is up to date." : "Not checked yet - press Check now.")),
    el("h2", {}, "Waiting for your approval"),
    el("div", { class: "card" }, pend.length ? el("ul", { class: "feed" }, pend.map(p => el("li", {}, el("span", { class: "p p4" }),
      el("div", { class: "row spread" },
        el("div", {}, el("div", { class: "t" }, p.containers.join(", ")), el("div", { class: "m" }, `${p.image} · ${ago(p.ts)}`)),
        el("div", { class: "row" },
          el("button", { onclick: async () => { await api("/api/pending/approve", { token: p.token }); toast("Updating " + p.containers.join(", ")); updates(); } }, "Update"),
          el("button", { class: "ghost", onclick: async () => { await api("/api/pending/dismiss", { token: p.token }); updates(); } }, "Dismiss"))))))
      : el("p", { class: "muted" }, "Nothing waiting.")),
    el("div", { class: "row spread" }, el("h2", {}, "Containers"),
      el("label", { class: "inline" }, "Default for unlisted containers:",
        policySel(c.default_policy, async (e) => { await api("/api/policy", { container: "*", policy: e.target.value }); toast("Saved"); updates(); }, false))),
    el("p", { class: "muted small" }, "Auto-update: installs new images by itself (with health check and rollback). Ask me: notification with an Update button. Just tell me: notification only."),
    el("div", { class: "card scroll" }, el("table", { class: "table" },
      el("tr", {}, el("th", {}, "Container"), el("th", {}, "Version"), el("th", {}, "State"), el("th", {}, "When a new image appears"), el("th", {}, "")),
      c.containers.map(r => el("tr", {},
        el("td", {}, el("div", {}, r.name), el("div", { class: "muted small" }, r.image)),
        el("td", { class: "small" }, r.version),
        el("td", {}, el("span", { class: "chip " + (r.state !== "running" ? "" : r.health === "unhealthy" ? "bad" : "ok") }, r.state === "running" ? (r.health || "running") : r.state),
          r.update_available ? el("span", { class: "chip warn" }, " update available") : null,
          r.pending ? el("span", { class: "chip warn" }, " waiting for approval") : null),
        el("td", {}, policySel(r.policy, async (e) => { await api("/api/policy", { container: r.name, policy: e.target.value || null }); toast("Saved"); }, true),
          r.last_update ? el("div", { class: "muted small" }, `last: ${r.last_update.ok ? "updated" : "failed"} ${ago(r.last_update.ts)}`) : null),
        el("td", {}, el("button", { class: "ghost sm", disabled: !r.compose || r.state !== "running", title: r.compose ? "Pull the newest image and recreate" : "Not started from a compose file",
          onclick: (e) => updateNow(r.name, e.target) }, "Update now")))))),
    el("h2", {}, "Update history"), el("div", { class: "card" }, updatesTable(hist)));
}

function fieldInput(f, value, onchange) {
  if (f.type === "bool") return el("label", { class: "inline" }, el("input", { type: "checkbox", checked: value, onchange: e => onchange(e.target.checked) }), f.label);
  return el("label", {}, f.label, el("input", { type: f.type === "number" ? "number" : "text", value: value ?? "", oninput: e => onchange(e.target.value) }));
}

async function reports() {
  const list = await api("/api/items");
  show(
    el("h2", {}, "Reports & checks"),
    el("p", { class: "muted small" }, "Turn things on, change when they run, preview what they would send. ",
      "Add your own: drop a Python plug-in in /home/notify/hub/reports/ or an executable script in /home/notify/hub/checks/ (see the README there) and reload this page."),
    list.map(it => {
      const st = { enabled: it.enabled, schedule: it.schedule, settings: { ...it.settings } };
      const out = el("div", { class: "result" });
      const show = (r) => {
        if (r.error) out.replaceChildren(el("p", { class: "err" }, r.error));
        else if (!r.result) out.replaceChildren(el("p", { class: "muted" }, "Nothing to report right now (it would stay silent)."));
        else out.replaceChildren(el("div", { class: "t" }, r.result.title), el("pre", {}, r.result.message));
      };
      const lr = it.last_result;
      return el("div", { class: "card item" },
        el("div", { class: "head" },
          el("div", {}, el("h3", {}, it.title, it.kind === "check" ? el("span", { class: "chip" }, " script") : null),
            el("div", { class: "muted small" }, it.error || it.description),
            el("div", { class: "muted small" }, "Last run: " + ago(ranAt(it)) + (lr && lr.error ? " · error: " + lr.error : lr && lr.title ? " · sent: " + lr.title : ""))),
          el("label", { class: "inline" }, el("input", { type: "checkbox", checked: it.enabled, disabled: !!it.error, onchange: e => st.enabled = e.target.checked }), "On")),
        it.error ? null : el("div", { class: "fields" },
          el("label", {}, "Schedule (" + SCHED_HELP + ")", el("input", { value: it.schedule, oninput: e => st.schedule = e.target.value })),
          it.fields.map(f => fieldInput(f, it.settings[f.key], v => st.settings[f.key] = v))),
        it.error ? null : el("div", { class: "row" },
          el("button", { onclick: async () => { await api("/api/items/save", { kind: it.kind, name: it.name, ...st }); toast("Saved"); } }, "Save"),
          el("button", { class: "ghost", onclick: async () => { out.replaceChildren(el("p", { class: "muted" }, "Running…")); show(await api("/api/items/run", { kind: it.kind, name: it.name, send: false })); } }, "Preview"),
          el("button", { class: "ghost", onclick: async () => { const r = await api("/api/items/run", { kind: it.kind, name: it.name, send: true }); show(r); toast(r.result ? "Sent." : "Nothing to send."); } }, "Run & send now")),
        out);
    }));
}

async function history() {
  const src = new URLSearchParams(location.hash.split("?")[1] || "").get("source") || "";
  const d = await api("/api/history?limit=300" + (src ? "&source=" + encodeURIComponent(src) : ""));
  show(
    el("div", { class: "row spread" }, el("h2", {}, "History"),
      el("select", { onchange: e => { location.hash = "history" + (e.target.value ? "?source=" + e.target.value : ""); } },
        el("option", { value: "" }, "All sources"), d.sources.map(s => el("option", { value: s, selected: s === src }, s)))),
    el("div", { class: "card" }, feed(d.rows)));
}

async function settings() {
  const s = await api("/api/settings");
  const v = { ...s, quiet: { ...s.quiet }, ntfy_token: null };
  const save = async (part) => { await api("/api/settings", part); toast("Saved"); settings(); };
  const inp = (label, key, attrs = {}) => el("label", {}, label, el("input", { value: v[key] ?? "", oninput: e => v[key] = e.target.value, ...attrs }));
  show(
    el("h2", {}, "Notifications"),
    el("div", { class: "card" },
      el("div", { class: "fields" },
        inp("ntfy server", "ntfy_url"),
        inp("Topic", "ntfy_topic"),
        el("label", {}, "Access token " + (s.ntfy_token_set ? "(set - leave empty to keep)" : "(not set)"),
          el("input", { type: "password", autocomplete: "off", oninput: e => v.ntfy_token = e.target.value }))),
      el("div", { class: "row" }, el("button", { onclick: () => save({ ntfy_url: v.ntfy_url, ntfy_topic: v.ntfy_topic, ntfy_token: v.ntfy_token || undefined }) }, "Save"),
        el("button", { class: "ghost", onclick: async () => { await api("/api/test", {}); toast("Test sent"); } }, "Send test"))),
    el("h2", {}, "Quiet hours"),
    el("div", { class: "card" },
      el("p", { class: "muted small" }, "During quiet hours, notifications below the chosen priority are held and delivered when quiet hours end."),
      el("div", { class: "fields" },
        el("label", { class: "inline" }, el("input", { type: "checkbox", checked: v.quiet.enabled, onchange: e => v.quiet.enabled = e.target.checked }), "Quiet hours on"),
        el("label", {}, "From", el("input", { type: "time", value: v.quiet.start, oninput: e => v.quiet.start = e.target.value })),
        el("label", {}, "Until", el("input", { type: "time", value: v.quiet.end, oninput: e => v.quiet.end = e.target.value })),
        el("label", {}, "Still deliver at once if priority is at least",
          el("select", { onchange: e => v.quiet.bypass_priority = +e.target.value },
            [[3, "default"], [4, "high"], [5, "urgent only"], [6, "never (hold everything)"]].map(([n, t]) => el("option", { value: n, selected: v.quiet.bypass_priority === n }, t))))),
      el("button", { onclick: () => save({ quiet: v.quiet }) }, "Save")),
    el("h2", {}, "Updates"),
    el("div", { class: "card" },
      el("div", { class: "fields" },
        inp("Diun check schedule (cron, e.g. 0 9 * * *)", "diun_schedule"),
        inp("Public hub address (used in Update buttons)", "public_url", { placeholder: "https://hub.example.com" }),
        inp("Update links expire after (days)", "pending_ttl_days", { type: "number" }),
        inp("Keep history for (days)", "history_days", { type: "number" })),
      el("button", { onclick: () => save({ diun_schedule: v.diun_schedule !== s.diun_schedule ? v.diun_schedule : undefined, public_url: v.public_url, pending_ttl_days: +v.pending_ttl_days, history_days: +v.history_days }) }, "Save")),
    el("h2", {}, "Security"),
    el("div", { class: "card" },
      el("p", {}, "Signed in as ", el("b", {}, s.user), ". Two-factor login is ", el("b", {}, s.totp ? "on" : "off"), "."),
      s.totp ? null : el("p", { class: "muted small" }, "Recommended because the hub is reachable from the internet. Turn it on from the server: ", el("code", {}, "sudo notify-hub totp-on")),
      el("div", { class: "fields" },
        el("label", {}, "Current password", el("input", { type: "password", id: "pw0", autocomplete: "current-password" })),
        el("label", {}, "New password (12+ characters)", el("input", { type: "password", id: "pw1", autocomplete: "new-password" }))),
      el("button", { onclick: async () => { await api("/api/password", { current: $("#pw0").value, new: $("#pw1").value }); $("#pw0").value = $("#pw1").value = ""; toast("Password changed"); } }, "Change password"),
      el("h3", { class: "small muted" }, "Signed-in devices"),
      el("div", { class: "scroll" }, el("table", { class: "table" },
        el("tr", {}, el("th", {}, "Signed-in device"), el("th", {}, "From"), el("th", {}, "Last active")),
        s.sessions.map(x => el("tr", {}, el("td", { class: "small" }, (x.agent || "").slice(0, 70)), el("td", {}, x.ip), el("td", { class: "muted" }, ago(x.last)))))),
      el("button", { class: "danger", onclick: async () => { if (confirm("Sign out every device, including this one?")) { await api("/api/logout-all", {}); location.href = "/login"; } } }, "Sign out everywhere")));
}
