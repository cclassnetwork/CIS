"use strict";
/* CCLASS Intelligence Suite dashboard. All external text goes through esc() before reaching innerHTML. */
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));
const esc = v => String(v ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const SEV = ["info", "low", "medium", "high", "critical"];
const SEV_COLOR = { info: "#64748b", low: "#3b82f6", medium: "#f59e0b", high: "#ef4444", critical: "#b91c1c" };
const TYPE_COLOR = { domain: "#3b82f6", ip: "#22d3ee", email: "#a78bfa", username: "#f472b6", profile: "#fb7185", hostname: "#60a5fa",
  asn: "#34d399", network: "#10b981", organization: "#fbbf24", place: "#f97316", country: "#fb923c", cve: "#ef4444", file: "#94a3b8",
  person: "#e879f9", event: "#f43f5e", software: "#2dd4bf", device: "#a3e635", mac: "#818cf8", hash: "#cbd5e1" };

const state = { view: "overview", inv: null, charts: [], map: null, cy: null, user: null, authEnabled: true };
try { state.inv = JSON.parse(localStorage.getItem("cclass.inv")); } catch (e) { state.inv = null; }

// ------------------------------------------------------------------ helpers
async function api(path, opts = {}) {
  const o = { headers: { "X-Requested-With": "cclass" }, credentials: "same-origin", ...opts };
  o.headers = { "X-Requested-With": "cclass", ...(opts.headers || {}) };
  if (o.body && !(o.body instanceof FormData)) { o.headers["Content-Type"] = "application/json"; o.body = JSON.stringify(o.body); }
  let res;
  try { res = await fetch("/api" + path, o); } catch (e) { throw new Error("Cannot reach the CCLASS server"); }
  if (!res.ok) {
    let msg = res.statusText, j = null;
    try { j = await res.json(); msg = typeof j.detail === "string" ? j.detail : JSON.stringify(j.detail); } catch (e) { /* keep status text */ }
    if (res.status === 401 && !path.startsWith("/auth/login") && !path.startsWith("/auth/setup")) { state.user = null; showAuth(); throw new Error("Please sign in"); }
    if (res.status === 403 && j && j.password_change_required) { showForcedPasswordChange(); throw new Error("Please choose a new password"); }
    throw new Error(msg || `HTTP ${res.status}`);
  }
  return res.status === 204 ? null : res.json();
}
function toast(msg, kind = "primary") {
  const el = document.createElement("div");
  el.className = `alert alert-${kind} shadow py-2 px-3 mb-2`;
  el.textContent = msg;
  $("#toast-area").appendChild(el);
  setTimeout(() => el.remove(), kind === "danger" ? 7000 : 3800);
}
const fail = e => toast(e.message || String(e), "danger");
const TLP_LEVELS = ["CLEAR", "GREEN", "AMBER", "AMBER+STRICT", "RED"];
const TLP_COLOR = { "CLEAR": "#ffffff", "GREEN": "#33ff00", "AMBER": "#ffc000", "AMBER+STRICT": "#ffc000", "RED": "#ff2b2b" };
const tlpBadge = t => `<span class="tlp-badge" style="color:${TLP_COLOR[t] || "#fff"}">TLP:${esc(t)}</span>`;
const dueBadge = i => { if (!i.due_date) return ""; const late = i.status === "open" && i.due_date < new Date().toISOString().slice(0, 10); return `<span class="${late ? "text-danger fw-bold" : ""}">${esc(i.due_date)}${late ? " (overdue)" : ""}</span>`; };
const tagChips = t => (t ? String(t).split(",") : []).map(x => `<span class="badge text-bg-secondary me-1">${esc(x)}</span>`).join("");
const sevBadge = s => `<span class="sev sev-${esc(s)}">${esc(s)}</span>`;
const confBar = c => `<span class="conf" title="${Math.round(c * 100)}%"><i style="width:${Math.round(c * 100)}%"></i></span> <small class="muted">${Math.round(c * 100)}%</small>`;
const fmtTime = t => t ? esc(String(t).replace("T", " ").replace(/\+00:00$/, "Z").slice(0, 19)) : "";
function busy(btn, on) { btn.disabled = on; btn.dataset.t = btn.dataset.t || btn.innerHTML; btn.innerHTML = on ? '<span class="spinner-inline"></span> Working...' : btn.dataset.t; }
function destroyViz() {
  state.charts.forEach(c => c.destroy()); state.charts = [];
  if (state.map) { state.map.remove(); state.map = null; }
  if (state.cy) { state.cy.destroy(); state.cy = null; }
}
function libMissing(name) { return `<div class="alert alert-warning">The ${esc(name)} library did not load (no Internet access and no local copy in <code>cclass_suite/web/static/vendor</code>). Run <code>./install.sh --vendor</code> while online to store it locally.</div>`; }
function setInv(inv) { state.inv = inv ? { id: inv.id, name: inv.name } : null; try { localStorage.setItem("cclass.inv", JSON.stringify(state.inv)); } catch (e) { /* storage unavailable */ } }

async function refreshInvSelect() {
  const list = await api("/investigations");
  const sel = $("#active-inv");
  sel.innerHTML = `<option value="">No active investigation</option>` + list.map(i => `<option value="${i.id}">#${i.id} ${esc(i.name)}</option>`).join("");
  if (state.inv && list.some(i => i.id === state.inv.id)) sel.value = state.inv.id; else { state.inv = null; sel.value = ""; }
  return list;
}
async function refreshBadge() {
  try {
    const s = await api("/overview");
    const b = $("#alert-badge"), n = s.totals.unacknowledged_alerts;
    b.textContent = n; b.classList.toggle("d-none", !n);
    const pill = $("#mode-pill"); pill.textContent = s.offline_mode ? "OFFLINE MODE" : "ONLINE MODE";
    pill.className = "badge " + (s.offline_mode ? "text-bg-warning" : "text-bg-success");
  } catch (e) { /* non-critical */ }
}

// ------------------------------------------------------------------ navigation
function go(view) { location.hash = "#" + view; }
async function render() {
  const view = (location.hash || "#overview").slice(1).split("/")[0];
  const known = Object.keys(views);
  state.view = known.includes(view) ? view : "overview";
  $$("#nav .nav-link").forEach(a => a.classList.toggle("active", a.dataset.view === state.view));
  $("#sidebar").classList.remove("open");
  destroyViz();
  const root = $("#view");
  root.innerHTML = '<div class="p-4 muted"><span class="spinner-inline"></span> Loading...</div>';
  try { await views[state.view](root); } catch (e) { root.innerHTML = `<div class="alert alert-danger">${esc(e.message)}</div>`; }
  refreshBadge();
}
window.addEventListener("hashchange", render);

// ------------------------------------------------------------------ views
const views = {};

views.overview = async root => {
  const s = await api("/overview");
  const t = s.totals;
  const tile = (n, l) => `<div class="col-6 col-md-4 col-xl"><div class="card stat"><div class="n">${n}</div><div class="l">${l}</div></div></div>`;
  root.innerHTML = `
  <div class="d-flex flex-wrap justify-content-between align-items-center mb-3"><h4 class="m-0">Overview</h4>
    <button class="btn btn-sm btn-outline-primary" id="load-demo">Load offline demo data</button></div>
  <div class="row g-3 mb-3">${tile(t.open_investigations, "Open investigations")}${tile(t.entities, "Entities")}${tile(t.findings, "Findings")}
    ${tile(t.unacknowledged_alerts, "Open threat alerts")}${tile(t.watchlist_hits, "Watchlist hits")}${tile(t.evidence, "Evidence items")}</div>
  <div class="row g-3 mb-3">
    <div class="col-lg-6"><div class="card"><div class="card-header">Findings by severity</div><div class="card-body"><canvas id="c-sev" height="160"></canvas></div></div></div>
    <div class="col-lg-6"><div class="card"><div class="card-header">Findings per day (14 days)</div><div class="card-body"><canvas id="c-day" height="160"></canvas></div></div></div>
    <div class="col-lg-6"><div class="card"><div class="card-header">Entities by type</div><div class="card-body"><canvas id="c-type" height="160"></canvas></div></div></div>
    <div class="col-lg-6"><div class="card"><div class="card-header">Threat alerts by severity</div><div class="card-body"><canvas id="c-alert" height="160"></canvas></div></div></div>
  </div>
  <div class="row g-3">
    <div class="col-lg-6"><div class="card"><div class="card-header">Recent threat alerts</div><ul class="list-group list-group-flush">
      ${s.recent_alerts.map(a => `<li class="list-group-item bg-transparent">${sevBadge(a.severity)} <b>${esc(a.title)}</b><div class="small muted">${esc(a.feed)} &middot; ${fmtTime(a.published_at)}</div></li>`).join("") || '<li class="list-group-item bg-transparent muted">No alerts yet. Refresh feeds under Threat Alerts.</li>'}</ul></div></div>
    <div class="col-lg-6"><div class="card"><div class="card-header">Recent activity</div><ul class="list-group list-group-flush">
      ${s.recent_activity.map(a => `<li class="list-group-item bg-transparent small"><span class="muted">${fmtTime(a.created_at)}</span> <b>${esc(a.action.replace(/_/g, " "))}</b> ${esc(a.detail)}</li>`).join("") || '<li class="list-group-item bg-transparent muted">No activity yet.</li>'}</ul></div></div>
  </div>
  ${s.overlaps.length ? `<div class="card mt-3"><div class="card-header">Entities shared across investigations</div><div class="card-body small">${s.overlaps.map(o => `<span class="me-3"><code>${esc(o.type)}:${esc(o.value)}</code> &times;${o.n}</span>`).join("")}</div></div>` : ""}`;
  $("#load-demo").onclick = async e => { busy(e.target, true); try { const r = await api("/demo", { method: "POST" }); setInv({ id: r.investigation_id, name: "Demo" }); toast("Demo data loaded"); await refreshInvSelect(); render(); } catch (x) { fail(x); } busy(e.target, false); };
  if (typeof Chart === "undefined") { root.insertAdjacentHTML("beforeend", libMissing("Chart.js")); return; }
  Chart.defaults.color = "#8aa4cf"; Chart.defaults.borderColor = "#1d3a6b";
  const mk = (id, cfg) => state.charts.push(new Chart($(id), cfg));
  const opts = { plugins: { legend: { display: false } }, scales: { y: { beginAtZero: true, ticks: { precision: 0 } } } };
  mk("#c-sev", { type: "bar", data: { labels: SEV, datasets: [{ data: SEV.map(k => s.findings_by_severity[k] || 0), backgroundColor: SEV.map(k => SEV_COLOR[k]) }] }, options: opts });
  mk("#c-alert", { type: "bar", data: { labels: SEV, datasets: [{ data: SEV.map(k => s.alerts_by_severity[k] || 0), backgroundColor: SEV.map(k => SEV_COLOR[k]) }] }, options: opts });
  mk("#c-day", { type: "line", data: { labels: s.findings_per_day.map(d => d.day.slice(5)), datasets: [{ data: s.findings_per_day.map(d => d.count), borderColor: "#60a5fa", backgroundColor: "rgba(59,130,246,.2)", fill: true, tension: .3 }] }, options: opts });
  const types = Object.keys(s.entities_by_type);
  mk("#c-type", { type: "doughnut", data: { labels: types, datasets: [{ data: types.map(k => s.entities_by_type[k]), backgroundColor: types.map(k => TYPE_COLOR[k] || "#64748b"), borderWidth: 0 }] }, options: { plugins: { legend: { position: "right" } } } });
};

function resultsTable(rows) {
  return `<div class="table-responsive"><table class="table table-sm table-hover align-middle"><thead><tr><th>Severity</th><th>Finding</th><th>Entity</th><th>Source</th><th>Confidence</th></tr></thead><tbody>` +
    (rows.map(f => `<tr><td>${sevBadge(f.severity)}</td><td><b>${esc(f.title)}</b><div class="small muted">${esc(f.summary)}</div></td>
      <td>${f.entity_value ? `<small class="muted">${esc(f.entity_type)}</small><br><code>${esc(f.entity_value)}</code>` : ""}</td>
      <td class="small">${esc(f.source_name || "")} <span class="rel" title="Source reliability">${esc(f.source_reliability || "-")}</span><div class="muted">${esc(f.module)}</div></td>
      <td>${confBar(f.confidence)}</td></tr>`).join("") || '<tr><td colspan="5" class="muted">No findings.</td></tr>') + `</tbody></table></div>`;
}

views.search = async root => {
  root.innerHTML = `<h4>Intelligence Search <small class="muted fs-6">XKEYSEARCH</small></h4>
  <div class="card mb-3"><div class="card-body"><form id="sf" class="row g-2">
    <div class="col-lg"><input id="sq" class="form-control form-control-lg" maxlength="500" placeholder="e-mail, IP, domain, URL, username, CVE-ID, lat,lon, place or keyword" required></div>
    <div class="col-lg-auto d-flex gap-2"><button class="btn btn-outline-primary" data-act="search">Search stored data</button><button class="btn btn-primary" data-act="investigate">Investigate</button></div>
    <div class="col-12 small muted"><span id="det"></span> &middot; <b>Investigate</b> runs the matching public-source modules, pivots to related entities and correlates. It adds results to the active investigation (or creates one).</div>
  </form></div></div><div id="sr"></div>`;
  const q = $("#sq"); let mode = "search";
  $$("#sf button").forEach(b => b.onclick = () => { mode = b.dataset.act; });
  q.oninput = async () => { if (q.value.length > 1) { try { $("#det").textContent = "Detected type: " + (await api("/detect?q=" + encodeURIComponent(q.value))).type; } catch (e) { /* ignore */ } } };
  $("#sf").onsubmit = async ev => { ev.preventDefault(); await runSearch(q.value.trim(), mode, $("#sr")); };
  if (state.pendingQuery) { q.value = state.pendingQuery.q; const m = state.pendingQuery.mode; state.pendingQuery = null; await runSearch(q.value, m, $("#sr")); }
};

async function runSearch(q, mode, out) {
  if (!q) return;
  out.innerHTML = '<div class="muted"><span class="spinner-inline"></span> Working...</div>';
  try {
    if (mode === "investigate") {
      const r = await api("/investigate", { method: "POST", body: { query: q, investigation_id: state.inv ? state.inv.id : null } });
      if (r.created_investigation) { await refreshInvSelect(); setInv({ id: r.investigation_id, name: "Auto" }); await refreshInvSelect(); }
      const f = await api(`/investigations/${r.investigation_id}/findings?limit=200`);
      out.innerHTML = `<div class="card mb-3"><div class="card-body"><b>Investigation #${r.investigation_id}</b> &middot; detected <code>${esc(r.detected_type)}</code>${r.offline ? ' &middot; <span class="badge text-bg-warning">offline sample data</span>' : ""}
        <ul class="mb-0 mt-2">${r.modules.map(m => `<li>${m.ok ? "&#10003;" : "&#10007;"} <b>${esc(m.module)}</b> <code>${esc(m.query)}</code>${m.pivot ? " (pivot)" : ""} &mdash; ${m.ok ? `+${m.stats.findings_new} findings, +${m.stats.entities_new} entities${m.stats.findings_duplicate ? `, ${m.stats.findings_duplicate} duplicates skipped` : ""}` : esc(m.error)}${m.warnings.length ? `<div class="small text-warning">${m.warnings.map(esc).join("; ")}</div>` : ""}</li>`).join("")}</ul>
        ${r.notes.map(n => `<div class="small text-info mt-1">${esc(n)}</div>`).join("")}
        ${r.insights.length ? `<hr><b>Correlation insights</b><ul class="mb-0">${r.insights.map(i => `<li>${sevBadge(i.severity)} ${esc(i.title)}<div class="small muted">${esc(i.detail)}</div></li>`).join("")}</ul>` : ""}</div></div>
        <div class="card"><div class="card-header">Findings (<a href="#investigations" class="pointer" id="open-inv">open investigation</a>)</div><div class="card-body p-2">${resultsTable(f)}</div></div>`;
      $("#open-inv").onclick = e => { e.preventDefault(); state.openInv = r.investigation_id; go("investigations"); };
      refreshBadge();
    } else {
      const r = await api("/search?q=" + encodeURIComponent(q));
      const sect = (title, rows, fn) => rows.length ? `<div class="card mb-3"><div class="card-header">${title} (${rows.length})</div><ul class="list-group list-group-flush">${rows.map(fn).join("")}</ul></div>` : "";
      out.innerHTML = (r.total ? "" : `<div class="alert alert-secondary">No stored matches for <code>${esc(q)}</code>. Use <b>Investigate</b> to collect public-source intelligence.</div>`) +
        sect("Entities", r.results.entities, e => `<li class="list-group-item bg-transparent"><small class="muted">${esc(e.type)}</small> <code>${esc(e.value)}</code> ${confBar(e.confidence)} <span class="muted small">in #${e.investigation_id} ${esc(e.investigation_name)}</span></li>`) +
        sect("Findings", r.results.findings, f => `<li class="list-group-item bg-transparent">${sevBadge(f.severity)} <b>${esc(f.title)}</b> <span class="muted small">#${f.investigation_id} &middot; ${esc(f.module)}</span><div class="small muted">${esc(f.summary)}</div></li>`) +
        sect("Threat alerts", r.results.alerts, a => `<li class="list-group-item bg-transparent">${sevBadge(a.severity)} <b>${esc(a.title)}</b> <span class="muted small">${esc(a.vendor || "")} ${esc(a.product || "")}</span></li>`) +
        sect("Investigations", r.results.investigations, i => `<li class="list-group-item bg-transparent">#${i.id} <b>${esc(i.name)}</b> <span class="muted small">${esc(i.status)}</span></li>`) +
        sect("Evidence", r.results.evidence, v => `<li class="list-group-item bg-transparent">${esc(v.filename)} <code>${esc(v.sha256.slice(0, 16))}</code></li>`);
    }
  } catch (e) { out.innerHTML = `<div class="alert alert-danger">${esc(e.message)}</div>`; }
}

views.modules = async root => {
  const mods = await api("/modules");
  const hints = { EMAILINTEL: "admin@example.com", IPINTEL: "8.8.8.8", DOMAININTEL: "example.com", SOCIALINTEL: "username", GEOINT: "Lagos  |  Lagos | London  |  6.52,3.37", THREATMONITOR: "CVE-2021-44228 or keyword", NETWORKINTEL: "192.168.1.0/24 or local", GLOBALWATCH: "Nigeria | Kano   or   global" };
  root.innerHTML = `<h4>Modules</h4><div class="row g-3" id="mods">${mods.map(m => `
    <div class="col-md-6 col-xl-4"><div class="card h-100"><div class="card-body d-flex flex-column">
      <h6 class="text-primary">${esc(m.name)} ${m.requires_authorization ? '<span class="badge text-bg-warning">authorised use only</span>' : ""}</h6>
      <p class="small muted flex-grow-1">${esc(m.description)}</p>
      ${m.runnable && !m.cli_only ? `<form data-mod="${esc(m.name)}"><div class="input-group input-group-sm"><input class="form-control" placeholder="${esc(hints[m.name] || "")}" required maxlength="500">
        <button class="btn btn-primary">Run</button></div>
        ${m.requires_authorization ? '<div class="form-check mt-2 small"><input class="form-check-input" type="checkbox" id="auth-chk"><label class="form-check-label" for="auth-chk">I own this network or have written permission to inventory it.</label></div>' : ""}</form>`
        : m.cli_only ? '<div class="small muted">Runs on evidence: open an investigation and attach a file (or use <code>cclass.py metadata FILE</code>).</div>'
        : `<a class="btn btn-sm btn-outline-primary" href="#${esc(m.view)}">Open ${esc(m.view)}</a>`}
    </div></div></div>`).join("")}</div><div id="mr" class="mt-3"></div>`;
  $$("#mods form").forEach(f => f.onsubmit = async ev => {
    ev.preventDefault(); const btn = $("button", f); busy(btn, true);
    const body = { query: $("input", f).value.trim(), investigation_id: state.inv ? state.inv.id : null };
    if (f.dataset.mod === "NETWORKINTEL") body.authorized = !!$("#auth-chk").checked;
    try {
      const r = await api(`/modules/${f.dataset.mod}/run`, { method: "POST", body });
      if (r.created_investigation) { setInv({ id: r.investigation_id, name: "Auto" }); await refreshInvSelect(); }
      const res = r.result, fl = await api(`/investigations/${r.investigation_id}/findings?module=${res.module}&limit=100`);
      $("#mr").innerHTML = `<div class="card"><div class="card-header">${esc(res.module)} &middot; <code>${esc(res.query)}</code> &middot; investigation #${r.investigation_id}</div><div class="card-body">
        ${res.ok ? "" : `<div class="alert alert-danger">${esc(res.error)}</div>`}${res.warnings.map(w => `<div class="alert alert-warning py-1 small">${esc(w)}</div>`).join("")}
        <div class="small muted mb-2">+${r.stats.findings_new} new findings, +${r.stats.entities_new} new entities, ${r.stats.findings_duplicate} duplicates.</div>${resultsTable(fl)}</div></div>`;
    } catch (e) { $("#mr").innerHTML = `<div class="alert alert-danger">${esc(e.message)}</div>`; }
    busy(btn, false);
  });
};

views.threats = async root => {
  root.innerHTML = `<div class="d-flex flex-wrap gap-2 justify-content-between mb-3"><h4 class="m-0">Threat Alerts</h4><div class="d-flex gap-2">
    <button class="btn btn-sm btn-primary" id="refresh">Refresh public feeds</button><button class="btn btn-sm btn-outline-secondary" id="refresh-s">Load sample feed</button></div></div>
  <div class="card mb-3"><div class="card-body row g-2"><div class="col-md"><input class="form-control form-control-sm" id="aq" placeholder="Filter by CVE, vendor, product or keyword"></div>
    <div class="col-auto"><select class="form-select form-select-sm" id="as"><option value="">All severities</option>${SEV.slice().reverse().map(s => `<option>${s}</option>`).join("")}</select></div>
    <div class="col-auto form-check pt-1 ms-2"><input type="checkbox" class="form-check-input" id="am"><label class="form-check-label small" for="am">Watchlist matches only</label></div></div></div>
  <div id="al"></div>
  <div class="row g-3 mt-1"><div class="col-lg-6"><div class="card"><div class="card-header">Watchlists</div><div class="card-body"><form id="wf" class="input-group input-group-sm mb-2">
    <select class="form-select" id="wk" style="max-width:120px">${["keyword", "product", "vendor", "cve", "domain", "ip", "email", "username"].map(k => `<option>${k}</option>`).join("")}</select>
    <input class="form-control" id="wv" placeholder="value" required minlength="2" maxlength="200"><button class="btn btn-primary">Add</button></form><div id="wl"></div></div></div></div>
  <div class="col-lg-6"><div class="card"><div class="card-header">Scheduled monitoring</div><div class="card-body"><form id="tf" class="row g-2 mb-2">
    <div class="col-12 col-sm"><input class="form-control form-control-sm" id="tn" placeholder="Task name" required maxlength="120"></div>
    <div class="col-6 col-sm-auto"><select class="form-select form-select-sm" id="tt"><option value="feed_refresh">Refresh feeds</option><option value="watchlist_scan">Re-check watchlist selectors</option>${state.user && state.user.role === "admin" ? '<option value="backup">Create backup</option><option value="retention">Apply retention policy</option>' : ""}</select></div>
    <div class="col-6 col-sm-auto"><input type="number" class="form-control form-control-sm" id="ti" value="60" min="1" max="10080" style="width:90px" title="minutes"></div>
    <div class="col-12 col-sm-auto"><button class="btn btn-sm btn-primary w-100">Schedule</button></div></form><div id="tl"></div></div></div></div></div>`;
  const loadAlerts = async () => {
    const p = new URLSearchParams(); if ($("#aq").value) p.set("q", $("#aq").value); if ($("#as").value) p.set("severity", $("#as").value); if ($("#am").checked) p.set("matched_only", "true");
    const rows = await api("/alerts?" + p);
    $("#al").innerHTML = `<div class="card"><div class="table-responsive"><table class="table table-sm table-hover align-middle mb-0"><thead><tr><th>Severity</th><th>Alert</th><th>Product</th><th>Published</th><th>Watchlist</th><th></th></tr></thead><tbody>${rows.map(a => `
      <tr class="${a.acknowledged ? "opacity-50" : ""}"><td>${sevBadge(a.severity)}</td><td><b>${esc(a.title)}</b><div class="small muted">${esc(a.description.slice(0, 220))}</div>${a.url ? `<a class="small" href="${esc(a.url)}" target="_blank" rel="noopener noreferrer">reference</a>` : ""}</td>
      <td class="small">${esc(a.vendor || "")}<br>${esc(a.product || "")}</td><td class="small">${fmtTime(a.published_at)}</td>
      <td>${a.matched_watchlists.map(m => `<span class="badge text-bg-info me-1">${esc(m)}</span>`).join("")}</td>
      <td><button class="btn btn-sm btn-outline-secondary" data-ack="${a.id}" data-v="${a.acknowledged ? 0 : 1}">${a.acknowledged ? "Reopen" : "Ack"}</button></td></tr>`).join("") || '<tr><td colspan="6" class="muted p-3">No alerts. Use Refresh public feeds (needs Internet) or Load sample feed.</td></tr>'}</tbody></table></div></div>`;
    $$("[data-ack]").forEach(b => b.onclick = async () => { try { await api(`/alerts/${b.dataset.ack}/ack`, { method: "POST", body: { enabled: b.dataset.v === "1" } }); loadAlerts(); refreshBadge(); } catch (e) { fail(e); } });
  };
  const loadWatch = async () => {
    const w = await api("/watchlists");
    $("#wl").innerHTML = w.map(x => `<div class="d-flex justify-content-between align-items-center border-bottom py-1 small ${x.active ? "" : "opacity-50"}"><span><span class="badge text-bg-secondary">${esc(x.kind)}</span> ${esc(x.value)}</span>
      <span><button class="btn btn-sm btn-link" data-wt="${x.id}" data-a="${x.active ? 0 : 1}">${x.active ? "pause" : "resume"}</button><button class="btn btn-sm btn-link text-danger" data-wd="${x.id}">delete</button></span></div>`).join("") || '<div class="muted small">No watchlist entries.</div>';
    $$("[data-wt]").forEach(b => b.onclick = async () => { try { await api(`/watchlists/${b.dataset.wt}/active`, { method: "POST", body: { enabled: b.dataset.a === "1" } }); loadWatch(); loadAlerts(); } catch (e) { fail(e); } });
    $$("[data-wd]").forEach(b => b.onclick = async () => { try { await api(`/watchlists/${b.dataset.wd}`, { method: "DELETE" }); loadWatch(); loadAlerts(); } catch (e) { fail(e); } });
  };
  const loadTasks = async () => {
    const t = await api("/tasks");
    $("#tl").innerHTML = (t.scheduler_running ? "" : '<div class="small text-warning mb-1">Scheduler is not running (enable it in Settings).</div>') + (t.tasks.map(x => `<div class="border-bottom py-1 small ${x.enabled ? "" : "opacity-50"}"><b>${esc(x.name)}</b> <span class="muted">${esc(x.task_type)} every ${x.interval_minutes} min</span>
      <div class="muted">last: ${fmtTime(x.last_run) || "never"} ${x.last_status ? `(${esc(x.last_status)}: ${esc(x.last_message)})` : ""}</div>
      <button class="btn btn-sm btn-link p-0 me-2" data-tr="${x.id}">run now</button><button class="btn btn-sm btn-link p-0 me-2" data-te="${x.id}" data-a="${x.enabled ? 0 : 1}">${x.enabled ? "disable" : "enable"}</button><button class="btn btn-sm btn-link text-danger p-0" data-td="${x.id}">delete</button></div>`).join("") || '<div class="muted small">No scheduled tasks.</div>');
    $$("[data-tr]").forEach(b => b.onclick = async () => { busy(b, true); try { const r = await api(`/tasks/${b.dataset.tr}/run`, { method: "POST" }); toast(`${r.status}: ${r.message}`); } catch (e) { fail(e); } loadTasks(); loadAlerts(); });
    $$("[data-te]").forEach(b => b.onclick = async () => { try { await api(`/tasks/${b.dataset.te}/enabled`, { method: "POST", body: { enabled: b.dataset.a === "1" } }); loadTasks(); } catch (e) { fail(e); } });
    $$("[data-td]").forEach(b => b.onclick = async () => { try { await api(`/tasks/${b.dataset.td}`, { method: "DELETE" }); loadTasks(); } catch (e) { fail(e); } });
  };
  const doRefresh = (sample) => async e => {
    busy(e.target, true);
    try {
      const r = await api("/feeds/refresh?sample=" + sample, { method: "POST" });
      const bad = Object.entries(r.feeds).filter(([, f]) => !f.ok);
      toast(`${r.new_alerts} new alert(s), ${r.matched} watchlist match(es)` + (bad.length ? `. Unavailable: ${bad.map(([n, f]) => n + " (" + f.error + ")").join(", ")}` : ""), bad.length ? "warning" : "success");
    } catch (x) { fail(x); }
    busy(e.target, false); loadAlerts(); refreshBadge();
  };
  $("#refresh").onclick = doRefresh(false); $("#refresh-s").onclick = doRefresh(true);
  ["#aq", "#as", "#am"].forEach(s => $(s).addEventListener("input", loadAlerts));
  $("#wf").onsubmit = async e => { e.preventDefault(); try { await api("/watchlists", { method: "POST", body: { kind: $("#wk").value, value: $("#wv").value } }); $("#wv").value = ""; loadWatch(); loadAlerts(); } catch (x) { fail(x); } };
  $("#tf").onsubmit = async e => { e.preventDefault(); try { await api("/tasks", { method: "POST", body: { name: $("#tn").value, task_type: $("#tt").value, interval_minutes: +$("#ti").value } }); $("#tn").value = ""; loadTasks(); } catch (x) { fail(x); } };
  await Promise.all([loadAlerts(), loadWatch(), loadTasks()]);
};

views.investigations = async root => {
  if (state.openInv) { const id = state.openInv; state.openInv = null; await refreshInvSelect(); return showInvestigation(root, id); }
  const f = state.invFilter || (state.invFilter = { mine: false, overdue: false, tag: "", tlp: "" });
  const qs = new URLSearchParams(); if (f.mine) qs.set("mine", "true"); if (f.overdue) qs.set("overdue", "true"); if (f.tag) qs.set("tag", f.tag); if (f.tlp) qs.set("tlp", f.tlp);
  const [list, people] = await Promise.all([api("/investigations" + (qs.toString() ? "?" + qs : "")), api("/people")]);
  await refreshInvSelect();
  const peopleOpts = sel => `<option value="">Unassigned</option>` + people.map(p => `<option value="${p.id}" ${String(p.id) === String(sel) ? "selected" : ""}>${esc(p.display_name || p.username)}</option>`).join("");
  root.innerHTML = `<div class="d-flex justify-content-between mb-3"><h4 class="m-0">Investigations</h4></div>
  <div class="card mb-3"><div class="card-body"><form id="nf" class="row g-2"><div class="col-md-4"><input class="form-control" id="nn" placeholder="Investigation name" required maxlength="200"></div>
    <div class="col-md"><input class="form-control" id="nd" placeholder="Description (optional)" maxlength="5000"></div>
    <div class="col-auto"><select class="form-select" id="np" title="Priority">${["low", "medium", "high", "critical"].map(p => `<option ${p === "medium" ? "selected" : ""}>${p}</option>`).join("")}</select></div>
    <div class="col-auto"><select class="form-select" id="nt" title="Traffic Light Protocol - who may see the results">${TLP_LEVELS.map(t => `<option ${t === "AMBER" ? "selected" : ""}>${t}</option>`).join("")}</select></div>
    <div class="col-md-3"><select class="form-select" id="na" title="Assignee">${peopleOpts("")}</select></div>
    <div class="col-auto"><input type="date" class="form-control" id="ndue" title="Due date"></div>
    <div class="col-md"><input class="form-control" id="ntags" placeholder="Tags (comma separated)" maxlength="200"></div>
    <div class="col-auto"><button class="btn btn-primary">Create</button></div></form></div></div>
  <form id="ff" class="row g-2 mb-2 align-items-center"><div class="col-auto"><div class="form-check"><input class="form-check-input" type="checkbox" id="f-mine" ${f.mine ? "checked" : ""}><label class="form-check-label small" for="f-mine">Assigned to me</label></div></div>
    <div class="col-auto"><div class="form-check"><input class="form-check-input" type="checkbox" id="f-over" ${f.overdue ? "checked" : ""}><label class="form-check-label small" for="f-over">Overdue</label></div></div>
    <div class="col-auto"><select class="form-select form-select-sm" id="f-tlp"><option value="">Any TLP</option>${TLP_LEVELS.map(t => `<option ${t === f.tlp ? "selected" : ""}>${t}</option>`).join("")}</select></div>
    <div class="col-auto"><input class="form-control form-control-sm" id="f-tag" placeholder="Tag" value="${esc(f.tag)}" maxlength="40"></div></form>
  <div class="card"><div class="table-responsive"><table class="table table-hover align-middle mb-0"><thead><tr><th>#</th><th>Name</th><th>TLP</th><th>Status</th><th>Priority</th><th>Assignee</th><th>Due</th><th>Findings</th><th>Updated</th></tr></thead><tbody>
  ${list.map(i => `<tr class="pointer" data-id="${i.id}"><td>${i.id}</td><td><b>${esc(i.name)}</b><div>${tagChips(i.tags)}</div></td><td>${tlpBadge(i.tlp)}</td><td>${esc(i.status)}</td><td>${esc(i.priority)}</td><td>${esc(i.assignee || "")}</td><td class="small">${dueBadge(i)}</td><td>${i.finding_count}</td><td class="small">${fmtTime(i.updated_at)}</td></tr>`).join("") || '<tr><td colspan="9" class="muted p-3">No investigations match.</td></tr>'}</tbody></table></div></div>`;
  $("#nf").onsubmit = async e => { e.preventDefault(); try { const body = { name: $("#nn").value, description: $("#nd").value, priority: $("#np").value, tlp: $("#nt").value, tags: $("#ntags").value.split(",").map(x => x.trim()).filter(Boolean), due_date: $("#ndue").value || null, assignee_id: $("#na").value ? +$("#na").value : null }; const i = await api("/investigations", { method: "POST", body }); setInv(i); showInvestigation(root, i.id); } catch (x) { fail(x); } };
  const refilter = () => { state.invFilter = { mine: $("#f-mine").checked, overdue: $("#f-over").checked, tlp: $("#f-tlp").value, tag: $("#f-tag").value.trim() }; render(); };
  ["#f-mine", "#f-over", "#f-tlp"].forEach(sel => $(sel).onchange = refilter);
  $("#ff").onsubmit = e => { e.preventDefault(); refilter(); };
  $$("tr[data-id]").forEach(r => r.onclick = () => showInvestigation(root, +r.dataset.id));
};

async function showInvestigation(root, id) {
  destroyViz();
  const [inv, findings, entities, evidence, comments, people] = await Promise.all([api(`/investigations/${id}`), api(`/investigations/${id}/findings?limit=500`), api(`/investigations/${id}/entities`), api(`/investigations/${id}/evidence`), api(`/investigations/${id}/comments`), api("/people")]);
  setInv(inv); await refreshInvSelect();
  root.innerHTML = `<a href="#investigations" class="small" id="back">&larr; All investigations</a>
  <div class="d-flex flex-wrap justify-content-between align-items-start my-2"><div><h4 class="mb-0">#${inv.id} ${esc(inv.name)} ${tlpBadge(inv.tlp)}</h4><div class="muted small">${esc(inv.description)}</div></div>
    <div class="d-flex gap-2 align-items-center"><select class="form-select form-select-sm" id="st">${["open", "closed", "archived"].map(s => `<option ${s === inv.status ? "selected" : ""}>${s}</option>`).join("")}</select>
    <select class="form-select form-select-sm" id="pr">${["low", "medium", "high", "critical"].map(s => `<option ${s === inv.priority ? "selected" : ""}>${s}</option>`).join("")}</select>
    <button class="btn btn-sm btn-outline-primary" id="cor">Correlate</button><button class="btn btn-sm btn-outline-danger" id="del">Delete</button></div></div>
  <div class="card mb-3"><div class="card-body py-2"><form id="cf" class="row g-2 align-items-end">
    <div class="col-6 col-md-2"><label class="form-label small mb-0" for="c-tlp">TLP</label><select class="form-select form-select-sm" id="c-tlp">${TLP_LEVELS.map(t => `<option ${t === inv.tlp ? "selected" : ""}>${t}</option>`).join("")}</select></div>
    <div class="col-6 col-md-3"><label class="form-label small mb-0" for="c-as">Assignee</label><select class="form-select form-select-sm" id="c-as"><option value="">Unassigned</option>${people.map(p => `<option value="${p.id}" ${p.id === inv.assignee_id ? "selected" : ""}>${esc(p.display_name || p.username)}</option>`).join("")}</select></div>
    <div class="col-6 col-md-2"><label class="form-label small mb-0" for="c-due">Due date</label><input type="date" class="form-control form-control-sm" id="c-due" value="${esc(inv.due_date || "")}"></div>
    <div class="col-12 col-md"><label class="form-label small mb-0" for="c-tags">Tags</label><input class="form-control form-control-sm" id="c-tags" value="${esc(inv.tags)}" maxlength="200" placeholder="comma separated"></div>
    <div class="col-auto"><button class="btn btn-sm btn-primary">Save case details</button></div></form>
    <div class="small mt-1">${dueBadge(inv) ? "Due: " + dueBadge(inv) + " &middot; " : ""}TLP tells readers how widely the results may be shared; it is printed on every report.</div></div></div>
  <ul class="nav nav-tabs mb-3" id="tabs"><li class="nav-item"><a class="nav-link active" data-tab="f">Findings (${findings.length})</a></li><li class="nav-item"><a class="nav-link" data-tab="e">Entities (${entities.length})</a></li><li class="nav-item"><a class="nav-link" data-tab="v">Evidence (${evidence.length})</a></li><li class="nav-item"><a class="nav-link" data-tab="c">Discussion (${comments.length})</a></li><li class="nav-item"><a class="nav-link" data-tab="g">Graph / map / timeline</a></li></ul>
  <div id="tab"></div>`;
  $("#back").onclick = e => { e.preventDefault(); go("investigations"); render(); };
  $("#st").onchange = () => api(`/investigations/${id}`, { method: "PATCH", body: { status: $("#st").value } }).then(() => toast("Updated")).catch(fail);
  $("#pr").onchange = () => api(`/investigations/${id}`, { method: "PATCH", body: { priority: $("#pr").value } }).then(() => toast("Updated")).catch(fail);
  $("#cf").onsubmit = async e => { e.preventDefault(); try { await api(`/investigations/${id}`, { method: "PATCH", body: { tlp: $("#c-tlp").value, assignee_id: $("#c-as").value ? +$("#c-as").value : null, due_date: $("#c-due").value || null, tags: $("#c-tags").value.split(",").map(x => x.trim()).filter(Boolean) } }); toast("Case details saved", "success"); showInvestigation(root, id); } catch (x) { fail(x); } };
  $("#cor").onclick = async () => { try { const r = await api(`/investigations/${id}/correlate`, { method: "POST" }); toast(`${r.insights.length} correlation insight(s)`); showInvestigation(root, id); } catch (e) { fail(e); } };
  $("#del").onclick = async () => { if (!confirm("Delete this investigation, its findings and evidence files permanently?")) return; try { await api(`/investigations/${id}`, { method: "DELETE" }); setInv(null); go("investigations"); render(); } catch (e) { fail(e); } };
  const tabs = {
    f: () => resultsTable(findings),
    e: () => `<div class="table-responsive"><table class="table table-sm table-hover"><thead><tr><th>Type</th><th>Value</th><th>Confidence</th><th>Seen</th><th>Location</th></tr></thead><tbody>${entities.map(e => `<tr><td><span class="badge" style="background:${TYPE_COLOR[e.type] || "#64748b"}">${esc(e.type)}</span></td><td><code>${esc(e.value)}</code>${e.label && e.label !== e.value ? `<div class="small muted">${esc(e.label)}</div>` : ""}</td><td>${confBar(e.confidence)}</td><td>${e.sightings}</td><td class="small">${e.lat != null ? `${e.lat.toFixed(3)}, ${e.lon.toFixed(3)}` : ""}</td></tr>`).join("")}</tbody></table></div>`,
    v: () => `<div class="card mb-3"><div class="card-body"><form id="uf" class="row g-2"><div class="col-md"><input type="file" class="form-control" id="uff" required></div><div class="col-md"><input class="form-control" id="un" placeholder="Notes (chain of custody, origin...)" maxlength="2000"></div>
      <div class="col-auto"><button class="btn btn-primary">Upload &amp; analyse</button></div></form><div class="small muted mt-1">Files are hashed (SHA-256), stored read-only on this machine and their metadata is extracted. Nothing is executed or opened remotely.</div></div></div>
      <div class="table-responsive"><table class="table table-sm"><thead><tr><th>File</th><th>SHA-256</th><th>Size</th><th>Collected</th><th>Notes</th><th></th></tr></thead><tbody>${evidence.map(v => `<tr><td>${esc(v.filename)}</td><td><code>${esc(v.sha256)}</code></td><td>${v.size_bytes}</td><td class="small">${fmtTime(v.collected_at)}</td><td class="small">${esc(v.notes)}</td>
      <td class="text-nowrap"><a class="btn btn-sm btn-outline-secondary" href="/api/evidence/${v.id}/download">Download</a> <button class="btn btn-sm btn-outline-primary" data-an="${v.id}">Re-analyse</button> <button class="btn btn-sm btn-outline-danger" data-dv="${v.id}">Delete</button></td></tr>`).join("") || '<tr><td colspan="6" class="muted">No evidence attached.</td></tr>'}</tbody></table></div>`,
    c: () => `<form id="cmf" class="mb-3"><textarea class="form-control mb-2" id="cm" rows="3" maxlength="5000" placeholder="Add a note for the team: what you checked, what to look at next..." required></textarea><button class="btn btn-primary btn-sm">Post note</button></form>
      ${comments.slice().reverse().map(c => `<div class="card mb-2"><div class="card-body py-2"><div class="small muted d-flex justify-content-between"><span><b>${esc(c.author)}</b> &middot; ${fmtTime(c.created_at)}</span><a href="#" class="text-danger" data-dc="${c.id}">delete</a></div><div style="white-space:pre-wrap">${esc(c.body)}</div></div></div>`).join("") || '<div class="muted">No notes yet.</div>'}`,
    g: () => `<div class="d-flex gap-2"><a class="btn btn-outline-primary" href="#graph">Entity graph</a><a class="btn btn-outline-primary" href="#map">Map</a><a class="btn btn-outline-primary" href="#timeline">Timeline</a><a class="btn btn-outline-primary" href="#reports">Reports</a></div>`,
  };
  const show = k => {
    $$("#tabs .nav-link").forEach(a => a.classList.toggle("active", a.dataset.tab === k));
    $("#tab").innerHTML = tabs[k]();
    const uf = $("#uf");
    if (uf) uf.onsubmit = async e => {
      e.preventDefault(); const fd = new FormData(); fd.append("file", $("#uff").files[0]); fd.append("notes", $("#un").value);
      try { const r = await api(`/investigations/${id}/evidence`, { method: "POST", body: fd }); toast(r.duplicate ? "Duplicate file (same SHA-256) - not stored again" : "Evidence stored and analysed", r.duplicate ? "warning" : "success"); showInvestigation(root, id); } catch (x) { fail(x); }
    };
    const cmf = $("#cmf");
    if (cmf) cmf.onsubmit = async e => { e.preventDefault(); try { await api(`/investigations/${id}/comments`, { method: "POST", body: { body: $("#cm").value } }); await showInvestigation(root, id); $$("#tabs .nav-link").find(a => a.dataset.tab === "c").click(); } catch (x) { fail(x); } };
    $$("[data-dc]").forEach(a => a.onclick = async ev => { ev.preventDefault(); if (!confirm("Delete this note?")) return; try { await api(`/comments/${a.dataset.dc}`, { method: "DELETE" }); await showInvestigation(root, id); $$("#tabs .nav-link").find(x => x.dataset.tab === "c").click(); } catch (x) { fail(x); } });
    $$("[data-an]").forEach(b => b.onclick = async () => { try { await api(`/evidence/${b.dataset.an}/analyze`, { method: "POST" }); toast("Analysed"); showInvestigation(root, id); } catch (x) { fail(x); } });
    $$("[data-dv]").forEach(b => b.onclick = async () => { if (!confirm("Delete this evidence file?")) return; try { await api(`/evidence/${b.dataset.dv}`, { method: "DELETE" }); showInvestigation(root, id); } catch (x) { fail(x); } });
  };
  $$("#tabs .nav-link").forEach(a => a.onclick = () => show(a.dataset.tab));
  show("f");
}

function needInv(root, title) {
  if (state.inv) return true;
  root.innerHTML = `<h4>${title}</h4><div class="alert alert-secondary">Select an active investigation in the top bar (or load the demo from Overview).</div>`;
  return false;
}

views.map = async root => {
  root.innerHTML = `<div class="d-flex justify-content-between mb-2"><h4 class="m-0">Geographic Map</h4><div class="form-check form-switch"><input class="form-check-input" type="checkbox" id="allinv"><label class="form-check-label small" for="allinv">All investigations</label></div></div>
  <div class="legend mb-2"></div><div id="map"></div><div class="small muted mt-2">IP-based locations are approximate (city / region level) and never identify a person or a precise site.</div>`;
  if (typeof L === "undefined") { root.insertAdjacentHTML("beforeend", libMissing("Leaflet")); return; }
  const draw = async () => {
    if (state.map) { state.map.remove(); state.map = null; }
    const all = $("#allinv").checked, invId = state.inv && !all ? state.inv.id : null;
    const pts = await api("/map" + (invId ? `?investigation_id=${invId}` : ""));
    state.map = L.map("map", { worldCopyJump: true }).setView([15, 10], 2);
    L.tileLayer("https://tile.openstreetmap.org/{z}/{x}/{y}.png", { maxZoom: 18, referrerPolicy: "origin", attribution: "&copy; OpenStreetMap contributors" }).addTo(state.map);
    const group = [];
    pts.forEach(p => {
      const color = p.kind === "finding" ? (SEV_COLOR[p.type] || "#3b82f6") : (TYPE_COLOR[p.type] || "#60a5fa");
      const m = L.circleMarker([p.lat, p.lon], { radius: 6 + 6 * p.confidence, color, fillColor: color, fillOpacity: .55, weight: 2 }).addTo(state.map);
      const pop = document.createElement("div"); pop.innerHTML = `<b></b><br><small></small>`;
      $("b", pop).textContent = p.title; $("small", pop).textContent = `${p.kind} (${p.type}) - confidence ${Math.round(p.confidence * 100)}% - investigation #${p.investigation_id}`;
      m.bindPopup(pop); group.push([p.lat, p.lon]);
    });
    if (group.length) state.map.fitBounds(group, { padding: [40, 40], maxZoom: 6 });
    $(".legend").innerHTML = `${pts.length} located item(s)` + (pts.length ? "" : " - none yet; run IPINTEL, GEOINT or analyse a geotagged image.");
  };
  $("#allinv").onchange = draw; await draw();
};

views.graph = async root => {
  if (!needInv(root, "Entity Relationship Graph")) return;
  const g = await api(`/investigations/${state.inv.id}/graph`);
  root.innerHTML = `<div class="d-flex justify-content-between mb-2"><h4 class="m-0">Entity Relationship Graph <small class="muted fs-6">${g.nodes.length} nodes &middot; ${g.edges.length} edges</small></h4>
    <div class="d-flex gap-2"><select id="lay" class="form-select form-select-sm"><option value="cose">Force layout</option><option value="concentric">Concentric</option><option value="breadthfirst">Hierarchy</option><option value="circle">Circle</option></select><div class="btn-group d-flex"><button class="btn btn-sm btn-outline-secondary" id="zout" title="Zoom out" aria-label="Zoom out">&minus;</button><button class="btn btn-sm btn-outline-secondary" id="zlvl" title="Reset zoom to 100%" style="min-width:58px">100%</button><button class="btn btn-sm btn-outline-secondary" id="zin" title="Zoom in" aria-label="Zoom in">+</button></div><button class="btn btn-sm btn-outline-secondary" id="fit" title="Fit whole graph on screen">Fit</button></div></div>
    <div class="legend mb-2">${Object.entries(TYPE_COLOR).map(([k, c]) => `<span><i style="background:${c}"></i>${k}</span>`).join("")}</div><div id="cy"></div><div id="sel" class="card card-body mt-2 small muted">Click a node or edge for details.</div>`;
  if (typeof cytoscape === "undefined") { root.insertAdjacentHTML("beforeend", libMissing("Cytoscape.js")); return; }
  const layout = n => ({ name: n, animate: false, padding: 30, nodeRepulsion: 9000, idealEdgeLength: 90, fit: true });
  state.cy = cytoscape({ container: $("#cy"), elements: [...g.nodes, ...g.edges], wheelSensitivity: .8, minZoom: .1, maxZoom: 6,
    style: [{ selector: "node", style: { "background-color": e => TYPE_COLOR[e.data("type")] || "#64748b", label: "data(label)", color: "#dce8ff", "font-size": 9, "text-wrap": "ellipsis", "text-max-width": 110, "text-valign": "bottom", "text-margin-y": 3, width: e => 16 + 22 * (e.data("confidence") || .3), height: e => 16 + 22 * (e.data("confidence") || .3) } },
      { selector: "edge", style: { width: 1.5, "line-color": "#2c4f8f", "target-arrow-color": "#2c4f8f", "target-arrow-shape": "triangle", "curve-style": "bezier", label: "data(label)", "font-size": 7, color: "#8aa4cf", "text-rotation": "autorotate" } },
      { selector: ":selected", style: { "border-width": 3, "border-color": "#fff", "line-color": "#60a5fa" } }] });
  state.cy.layout(layout("cose")).run();
  state.cy.on("tap", "node", ev => { const d = ev.target.data(); $("#sel").innerHTML = `<b>${esc(d.type)}</b> <code>${esc(d.value)}</code> &middot; confidence ${Math.round((d.confidence || 0) * 100)}% &middot; ${ev.target.degree()} connection(s)`; });
  state.cy.on("tap", "edge", ev => { const d = ev.target.data(); $("#sel").innerHTML = `Relationship <b>${esc(d.label)}</b> &middot; confidence ${Math.round((d.confidence || 0) * 100)}%`; });
  const cy = state.cy, lvl = $("#zlvl");
  const showZoom = () => { lvl.textContent = Math.round(cy.zoom() * 100) + "%"; };
  const zoomBy = f => { const z = Math.min(cy.maxZoom(), Math.max(cy.minZoom(), cy.zoom() * f));
    cy.animate({ zoom: { level: z, renderedPosition: { x: cy.width() / 2, y: cy.height() / 2 } } }, { duration: 150 }); };
  cy.on("zoom", showZoom); showZoom();
  $("#zin").onclick = () => zoomBy(1.4); $("#zout").onclick = () => zoomBy(1 / 1.4);
  lvl.onclick = () => cy.animate({ zoom: { level: 1, renderedPosition: { x: cy.width() / 2, y: cy.height() / 2 } } }, { duration: 150 });
  $("#lay").onchange = e => { cy.layout(layout(e.target.value)).run(); showZoom(); };
  $("#fit").onclick = () => { cy.fit(undefined, 30); showZoom(); };
};

views.timeline = async root => {
  if (!needInv(root, "Investigation Timeline")) return;
  const ev = await api(`/investigations/${state.inv.id}/timeline`);
  root.innerHTML = `<h4>Investigation Timeline <small class="muted fs-6">#${state.inv.id} &middot; ${ev.length} event(s)</small></h4>
  <div class="mb-3"><select class="form-select form-select-sm w-auto d-inline" id="tk"><option value="">All events</option><option value="finding">Findings</option><option value="evidence">Evidence</option><option value="activity">Activity</option></select></div>
  <div class="timeline" id="tlw"></div>`;
  const draw = () => { const k = $("#tk").value; $("#tlw").innerHTML = ev.filter(e => !k || e.kind === k).map(e => `<div class="tl-item sev-${esc(e.severity)} k-${esc(e.kind)}"><div class="small muted">${fmtTime(e.time)} &middot; ${esc(e.kind)} &middot; ${esc(e.module)}</div><div>${e.kind === "finding" ? sevBadge(e.severity) + " " : ""}<b>${esc(e.title)}</b></div>${e.detail ? `<div class="small muted">${esc(String(e.detail).slice(0, 300))}</div>` : ""}</div>`).join("") || '<div class="muted">Nothing to show.</div>'; };
  $("#tk").onchange = draw; draw();
};

views.reports = async root => {
  const [invs, reps] = await Promise.all([api("/investigations"), api("/reports")]);
  root.innerHTML = `<h4>Reports</h4><div class="card mb-3"><div class="card-body"><form id="rf" class="row g-2">
    <div class="col-md"><select class="form-select" id="ri" required>${invs.map(i => `<option value="${i.id}" ${state.inv && state.inv.id === i.id ? "selected" : ""}>#${i.id} ${esc(i.name)}</option>`).join("")}</select></div>
    <div class="col-auto"><select class="form-select" id="rfmt">${["html", "pdf", "csv", "json", "txt"].map(f => `<option>${f}</option>`).join("")}</select></div>
    <div class="col-auto"><button class="btn btn-primary">Generate report</button></div></form></div></div>
  <div class="card"><div class="table-responsive"><table class="table table-sm table-hover mb-0"><thead><tr><th>#</th><th>Investigation</th><th>Format</th><th>Created</th><th></th></tr></thead><tbody>
  ${reps.map(r => `<tr><td>${r.id}</td><td>#${r.investigation_id} ${esc(r.title)}</td><td>${esc(r.format).toUpperCase()}</td><td class="small">${fmtTime(r.created_at)}</td><td><a class="btn btn-sm btn-outline-primary" href="/api/reports/${r.id}/download">Download</a>${r.format === "html" ? ` <a class="btn btn-sm btn-outline-secondary" target="_blank" rel="noopener" href="/api/reports/${r.id}/download?inline=true">View</a>` : ""}</td></tr>`).join("") || '<tr><td colspan="5" class="muted p-3">No reports yet.</td></tr>'}</tbody></table></div></div>`;
  $("#rf").onsubmit = async e => { e.preventDefault(); const b = $("button", e.target); busy(b, true); try { await api("/reports", { method: "POST", body: { investigation_id: +$("#ri").value, format: $("#rfmt").value } }); toast("Report generated", "success"); render(); } catch (x) { fail(x); busy(b, false); } };
};

views.settings = async root => {
  const s = await api("/settings"), src = await api("/sources");
  const chk = (k, l) => `<div class="form-check form-switch mb-2"><input class="form-check-input" type="checkbox" id="s-${k}" ${s[k] ? "checked" : ""}><label class="form-check-label" for="s-${k}">${l}</label></div>`;
  const num = (k, l, step = 1) => `<div class="col-6 col-lg-3"><label class="form-label small" for="s-${k}">${l}</label><input type="number" step="${step}" class="form-control form-control-sm" id="s-${k}" value="${esc(s[k])}"></div>`;
  root.innerHTML = `<h4>Settings</h4><div class="row g-3"><div class="col-lg-8"><div class="card"><div class="card-header">Platform</div><div class="card-body"><form id="sf">
    ${chk("offline_mode", "Offline mode - use bundled sample datasets, make no network requests")}${chk("scheduler_enabled", "Run scheduled monitoring in the background")}
    ${chk("allow_public_network_targets", "Allow NETWORKINTEL on public ranges <span class='text-warning small'>(only for networks you own or are contracted to test)</span>")}
    <div class="row g-2 mb-3">${num("http_timeout", "HTTP timeout (s)")}${num("dns_timeout", "DNS timeout (s)")}${num("scan_timeout", "Scan timeout (s)", .1)}${num("scan_workers", "Scan workers")}
    ${num("backup_keep", "Backups kept")}${num("retention_alert_days", "Delete acknowledged alerts after (days, 0=never)")}${num("retention_activity_days", "Delete activity rows after (days, 0=never)")}${num("max_scan_hosts", "Max hosts per inventory")}${num("max_upload_mb", "Max upload (MB)")}${num("subdomain_resolve_limit", "Sub-domains resolved")}${num("scheduler_poll_seconds", "Scheduler poll (s)")}</div>
    <div class="mb-3"><label class="form-label small" for="s-scan_ports">Inventory ports (comma separated)</label><input class="form-control form-control-sm" id="s-scan_ports" value="${esc(s.scan_ports.join(", "))}"></div>
    <div class="mb-3"><label class="form-label small" for="s-user_agent">HTTP user agent</label><input class="form-control form-control-sm" id="s-user_agent" value="${esc(s.user_agent)}"></div>
    <div class="mb-3"><label class="form-label small" for="s-log_level">Log level</label><select class="form-select form-select-sm w-auto" id="s-log_level">${["DEBUG", "INFO", "WARNING", "ERROR"].map(l => `<option ${l === s.log_level ? "selected" : ""}>${l}</option>`).join("")}</select></div>
    <div class="small muted mb-3">Data directory: <code>${esc(s.data_dir)}</code> &middot; NVD API key: ${s.nvd_api_key_configured ? "configured via CCLASS_NVD_API_KEY" : "not set (optional; set CCLASS_NVD_API_KEY in the environment)"}. Host/port changes apply after restart.</div>
    <button class="btn btn-primary">Save settings</button></form></div></div></div>
    <div class="col-lg-4"><div class="card"><div class="card-header">Source reliability</div><div class="card-body small"><div class="muted mb-2">Reliability scales every finding's confidence. Adjust to your own assessment.</div>
    ${src.sources.map(x => `<div class="d-flex justify-content-between align-items-center mb-1"><span>${esc(x.name)}</span><select class="form-select form-select-sm w-auto" data-src="${x.id}">${Object.keys(src.scale).map(k => `<option value="${k}" ${k === x.reliability ? "selected" : ""} title="${esc(src.scale[k])}">${k}</option>`).join("")}</select></div>`).join("") || '<div class="muted">Sources appear after the first module runs.</div>'}</div></div></div></div>`;
  $$("[data-src]").forEach(sel => sel.onchange = () => api(`/sources/${sel.dataset.src}`, { method: "PATCH", body: { reliability: sel.value } }).then(() => toast("Reliability updated")).catch(fail));
  $("#sf").onsubmit = async e => {
    e.preventDefault();
    const n = k => Number($("#s-" + k).value), b = k => $("#s-" + k).checked;
    const ports = $("#s-scan_ports").value.split(",").map(x => x.trim()).filter(Boolean).map(Number);
    const body = { offline_mode: b("offline_mode"), scheduler_enabled: b("scheduler_enabled"), allow_public_network_targets: b("allow_public_network_targets"),
      http_timeout: n("http_timeout"), dns_timeout: n("dns_timeout"), scan_timeout: n("scan_timeout"), scan_workers: n("scan_workers"), max_scan_hosts: n("max_scan_hosts"),
      max_upload_mb: n("max_upload_mb"), subdomain_resolve_limit: n("subdomain_resolve_limit"), scheduler_poll_seconds: n("scheduler_poll_seconds"), backup_keep: n("backup_keep"), retention_alert_days: n("retention_alert_days"), retention_activity_days: n("retention_activity_days"),
      scan_ports: ports, user_agent: $("#s-user_agent").value, log_level: $("#s-log_level").value };
    try { await api("/settings", { method: "PUT", body }); toast("Settings saved", "success"); refreshBadge(); } catch (x) { fail(x); }
  };
};


// ------------------------------------------------------------------ authentication UI
const ROLE_LABEL = { viewer: "Viewer", analyst: "Analyst", admin: "Administrator" };
function authShell(inner) {
  document.body.classList.add("authing");
  const el = $("#auth-screen"); el.classList.remove("d-none");
  el.innerHTML = `<div class="auth-card card"><div class="card-body p-4"><div class="brand mb-3"><span class="brand-mark">C</span><div><b>CCLASS</b><small>Intelligence Suite</small></div></div>${inner}</div></div>`;
  return el;
}
function hideAuth() { document.body.classList.remove("authing"); $("#auth-screen").classList.add("d-none"); $("#auth-screen").innerHTML = ""; }
async function authCall(path, body) {
  const res = await fetch("/api" + path, { method: "POST", credentials: "same-origin", headers: { "Content-Type": "application/json", "X-Requested-With": "cclass" }, body: JSON.stringify(body || {}) });
  let j = {}; try { j = await res.json(); } catch (e) { /* empty body */ }
  return { ok: res.ok, status: res.status, j };
}
function showAuth(setupRequired = false) {
  const note = m => `<div class="alert alert-danger py-2 small d-none" id="auth-err">${esc(m || "")}</div>`;
  if (setupRequired) {
    const el = authShell(`<h5>Create the first administrator</h5><p class="small muted">This account manages users and the audit log. Passwords need 12+ characters mixing three of: lower, upper, digits, symbols.</p>${note()}
      <form id="auth-form"><input class="form-control mb-2" id="a-user" placeholder="Username" autocomplete="username" required maxlength="40">
      <input class="form-control mb-2" id="a-name" placeholder="Display name (optional)" maxlength="80">
      <input class="form-control mb-2" id="a-pass" type="password" placeholder="Password" autocomplete="new-password" required maxlength="256">
      <input class="form-control mb-2" id="a-tok" placeholder="Setup token (only if you are not on the server itself)" maxlength="100">
      <button class="btn btn-primary w-100">Create administrator</button></form>`);
    $("#auth-form", el).onsubmit = async e => {
      e.preventDefault();
      const r = await authCall("/auth/setup", { username: $("#a-user").value, display_name: $("#a-name").value, password: $("#a-pass").value, setup_token: $("#a-tok").value });
      if (r.ok) { startSession(r.j.user); } else { const b = $("#auth-err"); b.textContent = r.j.detail || "Setup failed"; b.classList.remove("d-none"); }
    };
    return;
  }
  const el = authShell(`<h5>Sign in</h5>${note()}<form id="auth-form"><input class="form-control mb-2" id="a-user" placeholder="Username" autocomplete="username" required maxlength="40">
    <input class="form-control mb-2" id="a-pass" type="password" placeholder="Password" autocomplete="current-password" required maxlength="256">
    <input class="form-control mb-2 d-none" id="a-totp" placeholder="6-digit authenticator code" inputmode="numeric" autocomplete="one-time-code" maxlength="12">
    <button class="btn btn-primary w-100">Sign in</button></form>`);
  $("#a-user", el).focus();
  $("#auth-form", el).onsubmit = async e => {
    e.preventDefault();
    const r = await authCall("/auth/login", { username: $("#a-user").value, password: $("#a-pass").value, totp: $("#a-totp").value });
    if (r.ok && r.j.totp_required) { $("#a-totp").classList.remove("d-none"); $("#a-totp").focus(); return; }
    if (r.ok) { startSession(r.j.user); return; }
    const b = $("#auth-err"); b.textContent = r.j.detail || "Sign-in failed"; b.classList.remove("d-none"); $("#a-pass").value = "";
  };
}
function showForcedPasswordChange() {
  const el = authShell(`<h5>Choose a new password</h5><p class="small muted">An administrator set a temporary password for you.</p><div class="alert alert-danger py-2 small d-none" id="auth-err"></div>
    <form id="auth-form"><input class="form-control mb-2" id="a-cur" type="password" placeholder="Temporary password" autocomplete="current-password" required>
    <input class="form-control mb-2" id="a-new" type="password" placeholder="New password" autocomplete="new-password" required>
    <button class="btn btn-primary w-100">Change password</button></form>`);
  $("#auth-form", el).onsubmit = async e => {
    e.preventDefault();
    const r = await authCall("/auth/password", { current: $("#a-cur").value, new: $("#a-new").value });
    if (r.ok) { location.reload(); } else { const b = $("#auth-err"); b.textContent = r.j.detail || "Could not change password"; b.classList.remove("d-none"); }
  };
}
function renderUserBox() {
  const u = state.user, box = $("#user-box");
  const admin = !!u && u.role === "admin";
  $$(".admin-only").forEach(x => x.classList.toggle("d-none", !admin));
  document.body.dataset.userRole = u ? u.role : "";
  if (!state.authEnabled) { box.innerHTML = '<span class="badge text-bg-danger" title="Anyone who can reach this page has full access">AUTH DISABLED</span>'; return; }
  box.innerHTML = u ? `<div><b>${esc(u.display_name || u.username)}</b> <span class="badge text-bg-secondary">${esc(ROLE_LABEL[u.role] || u.role)}</span></div>
    <a href="#account" class="me-2">My account</a><a href="#" id="signout">Sign out</a>` : "";
  const so = $("#signout"); if (so) so.onclick = async e => { e.preventDefault(); await authCall("/auth/logout"); location.reload(); };
}
let appStarted = false;
function startSession(user) {
  if (new URLSearchParams(location.search).get("next") === "/graphlab") { location.replace("/graphlab"); return; }
  state.user = user; hideAuth(); renderUserBox();
  if (!appStarted) { appStarted = true; wireChrome(); }
  refreshInvSelect().catch(() => { }).finally(render);
}

views.account = async root => {
  const me = (await api("/auth/me")).user;
  root.innerHTML = `<h4>My account</h4><div class="row g-3"><div class="col-lg-5"><div class="card"><div class="card-header">Change password</div><div class="card-body">
    <form id="pw"><input class="form-control mb-2" id="p-cur" type="password" placeholder="Current password" autocomplete="current-password" required>
    <input class="form-control mb-2" id="p-new" type="password" placeholder="New password (12+ characters)" autocomplete="new-password" required>
    <button class="btn btn-primary">Change password</button></form><div class="small muted mt-2">Other sessions are signed out when you change it.</div></div></div></div>
    <div class="col-lg-7"><div class="card"><div class="card-header">Two-factor authentication (authenticator app)</div><div class="card-body" id="tf">
    <p>Status: ${me.totp_enabled ? '<span class="badge text-bg-success">enabled</span>' : '<span class="badge text-bg-secondary">not enabled</span>'}</p>
    ${me.totp_enabled ? `<form id="tf-off" class="row g-2"><div class="col"><input class="form-control" id="tf-pw" type="password" placeholder="Password to confirm" required></div><div class="col-auto"><button class="btn btn-outline-danger">Disable</button></div></form>`
      : '<button class="btn btn-primary" id="tf-on">Set up two-factor</button><div id="tf-setup" class="mt-3"></div>'}</div></div></div></div>`;
  $("#pw").onsubmit = async e => { e.preventDefault(); try { await api("/auth/password", { method: "POST", body: { current: $("#p-cur").value, new: $("#p-new").value } }); toast("Password changed", "success"); e.target.reset(); } catch (x) { fail(x); } };
  const on = $("#tf-on");
  if (on) on.onclick = async () => {
    try {
      const r = await api("/auth/totp/begin", { method: "POST" });
      $("#tf-setup").innerHTML = `<p class="small">Add this account to an authenticator app (Google Authenticator, Aegis, 1Password, Authy...) using <b>manual entry</b>, then enter the 6-digit code below.</p>
        <div class="mb-2">Secret key: <code class="user-select-all fs-6">${esc(r.secret)}</code></div>
        <div class="small muted mb-2">Or open this link on a device with an authenticator: <code class="user-select-all text-break">${esc(r.uri)}</code></div>
        <form id="tf-conf" class="row g-2"><div class="col"><input class="form-control" id="tf-code" placeholder="6-digit code" inputmode="numeric" maxlength="6" required></div><div class="col-auto"><button class="btn btn-success">Confirm and enable</button></div></form>`;
      $("#tf-conf").onsubmit = async e => { e.preventDefault(); try { await api("/auth/totp/confirm", { method: "POST", body: { code: $("#tf-code").value } }); toast("Two-factor enabled", "success"); render(); } catch (x) { fail(x); } };
    } catch (x) { fail(x); }
  };
  const off = $("#tf-off");
  if (off) off.onsubmit = async e => { e.preventDefault(); try { await api("/auth/totp/disable", { method: "POST", body: { password: $("#tf-pw").value } }); toast("Two-factor disabled"); render(); } catch (x) { fail(x); } };
};

views.users = async root => {
  const users = await api("/users");
  root.innerHTML = `<h4>Users</h4><div class="card mb-3"><div class="card-header">Add a user</div><div class="card-body"><form id="nu" class="row g-2">
    <div class="col-md-3"><input class="form-control" id="nu-u" placeholder="Username" required maxlength="40"></div>
    <div class="col-md-3"><input class="form-control" id="nu-n" placeholder="Display name" maxlength="80"></div>
    <div class="col-md-3"><input class="form-control" id="nu-p" type="password" placeholder="Temporary password" autocomplete="new-password" required></div>
    <div class="col-md-2"><select class="form-select" id="nu-r"><option value="viewer">Viewer</option><option value="analyst" selected>Analyst</option><option value="admin">Administrator</option></select></div>
    <div class="col-md-1"><button class="btn btn-primary w-100">Add</button></div></form>
    <div class="small muted mt-2">The user must choose their own password at first sign-in. <b>Viewer</b>: read only. <b>Analyst</b>: run investigations, upload evidence, build reports. <b>Administrator</b>: also users, settings, audit log, backups.</div></div></div>
  <div class="card"><div class="table-responsive"><table class="table table-sm align-middle mb-0"><thead><tr><th>User</th><th>Role</th><th>2FA</th><th>Last sign-in</th><th>Status</th><th></th></tr></thead><tbody>
  ${users.map(u => `<tr><td><b>${esc(u.username)}</b><div class="small muted">${esc(u.display_name)}</div></td>
    <td><select class="form-select form-select-sm w-auto" data-urole="${u.id}">${["viewer", "analyst", "admin"].map(r => `<option value="${r}" ${r === u.role ? "selected" : ""}>${ROLE_LABEL[r]}</option>`).join("")}</select></td>
    <td>${u.totp_enabled ? "on" : '<span class="muted">off</span>'}</td><td class="small">${fmtTime(u.last_login) || '<span class="muted">never</span>'}</td>
    <td>${u.disabled ? '<span class="badge text-bg-secondary">disabled</span>' : u.locked_until && new Date(u.locked_until) > new Date() ? '<span class="badge text-bg-warning">locked</span>' : '<span class="badge text-bg-success">active</span>'}</td>
    <td class="text-end text-nowrap"><button class="btn btn-sm btn-outline-secondary" data-act="unlock" data-id="${u.id}">Unlock</button>
      <button class="btn btn-sm btn-outline-secondary" data-act="pw" data-id="${u.id}">Reset password</button>
      ${u.totp_enabled ? `<button class="btn btn-sm btn-outline-secondary" data-act="2fa" data-id="${u.id}">Reset 2FA</button>` : ""}
      <button class="btn btn-sm btn-outline-warning" data-act="toggle" data-dis="${u.disabled ? 1 : 0}" data-id="${u.id}">${u.disabled ? "Enable" : "Disable"}</button>
      <button class="btn btn-sm btn-outline-danger" data-act="del" data-id="${u.id}">Delete</button></td></tr>`).join("")}</tbody></table></div></div>`;
  $("#nu").onsubmit = async e => { e.preventDefault(); try { await api("/users", { method: "POST", body: { username: $("#nu-u").value, display_name: $("#nu-n").value, password: $("#nu-p").value, role: $("#nu-r").value } }); toast("User created", "success"); render(); } catch (x) { fail(x); } };
  $$("[data-urole]").forEach(s => s.onchange = () => api(`/users/${s.dataset.urole}`, { method: "PATCH", body: { role: s.value } }).then(() => toast("Role updated")).catch(x => { fail(x); render(); }));
  $$("[data-act]").forEach(b => b.onclick = async () => {
    const id = b.dataset.id, act = b.dataset.act;
    try {
      if (act === "unlock") await api(`/users/${id}/unlock`, { method: "POST" });
      else if (act === "2fa") { if (!confirm("Remove two-factor authentication for this user?")) return; await api(`/users/${id}/reset-2fa`, { method: "POST" }); }
      else if (act === "pw") { const p = prompt("Temporary password for this user (they must change it at next sign-in):"); if (!p) return; await api(`/users/${id}/password`, { method: "POST", body: { password: p } }); }
      else if (act === "toggle") await api(`/users/${id}`, { method: "PATCH", body: { disabled: b.dataset.dis !== "1" } });
      else if (act === "del") { if (!confirm("Delete this user permanently? Their audit-log entries are kept.")) return; await api(`/users/${id}`, { method: "DELETE" }); }
      toast("Done", "success"); render();
    } catch (x) { fail(x); }
  });
};

views.backups = async root => {
  const d = await api("/backups");
  const size = n => n > 1048576 ? (n / 1048576).toFixed(1) + " MB" : Math.max(1, Math.round(n / 1024)) + " KB";
  root.innerHTML = `<div class="d-flex flex-wrap justify-content-between align-items-center mb-3"><h4 class="m-0">Backups &amp; retention</h4><button class="btn btn-primary btn-sm" id="bk-new">Create backup now</button></div>
  <div class="alert alert-warning small py-2">Backups contain case data, password hashes and 2FA secrets. Copy them off this server and store them <b>encrypted</b> (for example <code>gpg -c file.zip</code> or an encrypted volume). Restore is a command-line action with the dashboard stopped: <code>python3 cclass.py restore &lt;file&gt;</code>. Directory: <code>${esc(d.directory)}</code>; newest ${d.keep} kept.</div>
  <div class="card mb-3"><div class="table-responsive"><table class="table table-sm align-middle mb-0"><thead><tr><th>File</th><th>Created</th><th>Size</th><th></th></tr></thead><tbody>
  ${d.backups.map(b => `<tr><td><code>${esc(b.name)}</code></td><td class="small">${fmtTime(b.created_at)}</td><td>${size(b.size)}</td><td class="text-end text-nowrap">
    <button class="btn btn-sm btn-outline-success" data-v="${esc(b.name)}">Verify</button> <a class="btn btn-sm btn-outline-secondary" href="/api/backups/${encodeURIComponent(b.name)}/download">Download</a>
    <button class="btn btn-sm btn-outline-danger" data-d="${esc(b.name)}">Delete</button></td></tr>`).join("") || '<tr><td colspan="4" class="muted p-3">No backups yet.</td></tr>'}</tbody></table></div></div>
  <div class="card"><div class="card-header">Data retention</div><div class="card-body small">Removes <b>acknowledged</b> threat alerts and activity-log rows older than the limits set under Settings, plus expired sessions. The audit log, investigations, findings, evidence and reports are never deleted by retention.
    <div class="mt-2"><button class="btn btn-sm btn-outline-secondary" id="rt-prev">Preview</button> <button class="btn btn-sm btn-outline-danger" id="rt-run">Run now</button> <span id="rt-out" class="ms-2"></span></div></div></div>`;
  $("#bk-new").onclick = async e => { busy(e.target, true); try { await api("/backups", { method: "POST" }); toast("Backup created", "success"); render(); } catch (x) { fail(x); busy(e.target, false); } };
  $$("[data-v]").forEach(b => b.onclick = async () => { try { const r = await api(`/backups/${encodeURIComponent(b.dataset.v)}/verify`); toast(r.ok ? `Verified: ${r.files} files, all checksums match` : "FAILED: " + r.problems.join("; "), r.ok ? "success" : "danger"); } catch (x) { fail(x); } });
  $$("[data-d]").forEach(b => b.onclick = async () => { if (!confirm("Delete this backup file?")) return; try { await api(`/backups/${encodeURIComponent(b.dataset.d)}`, { method: "DELETE" }); render(); } catch (x) { fail(x); } });
  const rt = async dry => { try { const r = await api("/retention/run", { method: "POST", body: { dry_run: dry } }); const o = r.removed || r.would_remove; $("#rt-out").textContent = `${dry ? "Would remove" : "Removed"}: ${o.alerts} alert(s), ${o.activity} activity row(s), ${o.sessions} expired session(s)`; } catch (x) { fail(x); } };
  $("#rt-prev").onclick = () => rt(true);
  $("#rt-run").onclick = () => { if (confirm("Permanently delete the aged records?")) rt(false); };
};

views.audit = async root => {
  const q = state.auditFilter || { actor: "", action: "" };
  const qs = new URLSearchParams({ limit: 200 }); if (q.actor) qs.set("actor", q.actor); if (q.action) qs.set("action", q.action);
  const d = await api("/audit?" + qs);
  root.innerHTML = `<div class="d-flex flex-wrap justify-content-between align-items-center mb-3"><h4 class="m-0">Audit log <small class="muted">${d.total} entries</small></h4>
    <div><button class="btn btn-sm btn-outline-success" id="av">Verify integrity</button>
    <a class="btn btn-sm btn-outline-secondary" href="/api/audit/export?format=csv">Export CSV</a> <a class="btn btn-sm btn-outline-secondary" href="/api/audit/export?format=json">Export JSON</a></div></div>
  <div id="av-out"></div>
  <form id="af" class="row g-2 mb-3"><div class="col-md-3"><input class="form-control form-control-sm" id="af-a" placeholder="Actor (exact username)" value="${esc(q.actor)}"></div>
    <div class="col-md-3"><input class="form-control form-control-sm" id="af-c" placeholder="Action starts with (e.g. login, user.)" value="${esc(q.action)}"></div><div class="col-auto"><button class="btn btn-sm btn-primary">Filter</button></div></form>
  <div class="card"><div class="table-responsive"><table class="table table-sm table-hover mb-0 small"><thead><tr><th>#</th><th>Time (UTC)</th><th>Actor</th><th>Action</th><th>Target</th><th>Detail</th><th>IP</th></tr></thead><tbody>
  ${d.entries.map(e => `<tr><td>${e.seq}</td><td class="text-nowrap">${fmtTime(e.ts)}</td><td>${esc(e.actor)}</td><td><code>${esc(e.action)}</code></td><td class="text-break">${esc(e.target)}</td><td class="text-break">${esc(e.detail)}</td><td>${esc(e.ip)}</td></tr>`).join("") || '<tr><td colspan="7" class="muted p-3">No entries.</td></tr>'}</tbody></table></div></div>`;
  $("#af").onsubmit = e => { e.preventDefault(); state.auditFilter = { actor: $("#af-a").value.trim(), action: $("#af-c").value.trim() }; render(); };
  $("#av").onclick = async () => {
    try {
      const r = await api("/audit/verify");
      $("#av-out").innerHTML = r.ok ? `<div class="alert alert-success py-2">Chain intact: ${r.entries} entries verified. Head hash <code class="text-break">${esc(r.head)}</code><div class="small">Record this value somewhere outside this server to detect removal of the newest entries.</div></div>`
        : `<div class="alert alert-danger py-2"><b>Tampering detected</b> at entry #${esc(r.first_bad_seq)}: ${esc(r.problem)}. Restore from a trusted backup and investigate.</div>`;
    } catch (x) { fail(x); }
  };
};

function wireChrome() {
  $("#quick-search").onsubmit = e => { e.preventDefault(); const q = $("#quick-q").value.trim(); if (!q) return; state.pendingQuery = { q, mode: "search" }; $("#quick-q").value = ""; if (location.hash === "#search") render(); else go("search"); };
  $("#active-inv").onchange = e => { const o = e.target.selectedOptions[0]; setInv(e.target.value ? { id: +e.target.value, name: o.textContent } : null); if (["graph", "timeline", "map"].includes(state.view)) render(); };
  $("#menu-btn").onclick = () => $("#sidebar").classList.toggle("open");
  $$("#nav .nav-link[data-view]").forEach(a => a.onclick = () => go(a.dataset.view));
}

(async function start() {
  let st;
  try { const res = await fetch("/api/auth/status", { credentials: "same-origin" }); st = await res.json(); } catch (e) { authShell('<div class="alert alert-danger">Cannot reach the CCLASS server.</div>'); return; }
  state.authEnabled = st.auth_enabled;
  if (!st.auth_enabled || st.authenticated) { startSession(st.user); return; }
  showAuth(st.setup_required);
})();
