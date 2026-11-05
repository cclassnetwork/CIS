"use strict";
/* CCLASS Graph Lab - Maltego-style link analysis. Every value that came from a user or a data source goes through esc()
   before it reaches innerHTML; Cytoscape renders labels as canvas text, never as HTML. */
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));
const esc = v => String(v ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const SHAPES = { domain: "round-rectangle", hostname: "round-rectangle", url: "round-rectangle", ip: "diamond", network: "diamond", asn: "hexagon",
  organization: "hexagon", person: "ellipse", email: "ellipse", username: "ellipse", profile: "round-tag", phone: "pentagon", place: "triangle", country: "triangle", cve: "octagon",
  hash: "rectangle", event: "star", text: "rectangle" };

const S = { meta: null, graphs: [], gid: null, cy: null, user: null, tab: "entity", linkMode: false, linkFrom: null, busy: 0, nodes: new Map() };

async function api(path, opts = {}) {
  const o = { credentials: "same-origin", ...opts, headers: { "X-Requested-With": "cclass", ...(opts.headers || {}) } };
  if (o.body && typeof o.body !== "string") { o.headers["Content-Type"] = "application/json"; o.body = JSON.stringify(o.body); }
  let res;
  try { res = await fetch("/api" + path, o); } catch (e) { throw new Error("Cannot reach the CCLASS server"); }
  if (res.status === 401) { location.href = "/?next=/graphlab"; throw new Error("Please sign in"); }
  if (!res.ok) {
    let msg = res.statusText;
    try { const j = await res.json(); msg = typeof j.detail === "string" ? j.detail : JSON.stringify(j.detail); } catch (e) { /* keep status text */ }
    throw new Error(msg || `HTTP ${res.status}`);
  }
  return res.json();
}
function toast(msg, kind = "primary") {
  const el = document.createElement("div");
  el.className = `alert alert-${kind} shadow py-2 px-3 mb-2`;
  el.textContent = msg;
  $("#toast-area").appendChild(el);
  setTimeout(() => el.remove(), kind === "danger" ? 7000 : 3800);
}
const fail = e => toast(e.message || String(e), "danger");
const canEdit = () => !S.user || S.user.role !== "viewer";
const need = () => { if (!canEdit()) { toast("Your account is read-only (viewer).", "warning"); return false; } return true; };
const typeInfo = t => (S.meta.types[t] || { label: t, color: "#64748b" });

/* ------------------------------------------------------------------ dialog */
function ask(title, fields, ok = "OK") {
  return new Promise(resolve => {
    const m = $("#gl-modal"), f = $("#gl-modal-form");
    f.innerHTML = `<h6>${esc(title)}</h6>` + fields.map(x => `<div class="mb-2"><label class="form-label small mb-1" for="m-${x.id}">${esc(x.label)}</label>` +
      (x.options ? `<select class="form-select form-select-sm" id="m-${x.id}">${x.options.map(o => `<option value="${esc(o[0])}" ${o[0] === x.value ? "selected" : ""}>${esc(o[1])}</option>`).join("")}</select>`
        : x.area ? `<textarea class="form-control form-control-sm" id="m-${x.id}" rows="3">${esc(x.value || "")}</textarea>`
          : `<input class="form-control form-control-sm" id="m-${x.id}" value="${esc(x.value || "")}" maxlength="${x.max || 500}" ${x.required ? "required" : ""}>`) + `</div>`).join("") +
      `<div class="d-flex gap-2 justify-content-end mt-3"><button type="button" class="btn btn-sm btn-outline-secondary" id="m-cancel">Cancel</button><button class="btn btn-sm btn-primary">${esc(ok)}</button></div>`;
    m.classList.remove("d-none");
    const first = f.querySelector("input,select,textarea"); if (first) first.focus();
    const close = v => { m.classList.add("d-none"); f.onsubmit = null; resolve(v); };
    $("#m-cancel").onclick = () => close(null);
    f.onsubmit = e => { e.preventDefault(); const out = {}; fields.forEach(x => out[x.id] = $("#m-" + x.id).value); close(out); };
    m.onkeydown = e => { if (e.key === "Escape") close(null); };
  });
}

/* ------------------------------------------------------------------ graph (Cytoscape) */
function nodeData(n) { return { id: "n" + n.id, nid: n.id, type: n.type, value: n.value, nlabel: n.label || "", label: n.label || n.value, notes: n.notes || "", source: n.source, attrs: n.attrs || {} }; }
function edgeData(e) { return { id: "e" + e.id, eid: e.id, source: "n" + e.src, target: "n" + e.dst, label: e.label, origin: e.source }; }

function initCy() {
  S.cy = cytoscape({
    container: $("#gl-cy"), wheelSensitivity: .7, minZoom: .05, maxZoom: 5, boxSelectionEnabled: true,
    style: [
      { selector: "node", style: { "background-color": n => typeInfo(n.data("type")).color, shape: n => SHAPES[n.data("type")] || "ellipse",
        label: "data(label)", color: "#dce8ff", "font-size": 10, "text-wrap": "ellipsis", "text-max-width": 130, "text-valign": "bottom", "text-margin-y": 4,
        width: 34, height: 34, "border-width": 2, "border-color": "#0a1628", "text-outline-width": 2, "text-outline-color": "#060f1e" } },
      { selector: "edge", style: { width: 1.6, "line-color": "#2c4f8f", "target-arrow-color": "#2c4f8f", "target-arrow-shape": "triangle", "curve-style": "bezier",
        label: "data(label)", "font-size": 8, color: "#8aa4cf", "text-rotation": "autorotate", "text-background-color": "#060f1e", "text-background-opacity": .85, "text-background-padding": 2 } },
      { selector: ":selected", style: { "border-width": 4, "border-color": "#fff", "line-color": "#60a5fa", "target-arrow-color": "#60a5fa" } },
      { selector: ".fresh", style: { "border-width": 4, "border-color": "#fde047" } },
      { selector: ".linksrc", style: { "border-width": 4, "border-color": "#22d3ee", "border-style": "dashed" } },
      { selector: ".dim", style: { opacity: .12 } },
      { selector: ".hit", style: { "border-width": 4, "border-color": "#f59e0b" } },
    ],
  });
  const cy = S.cy;
  let raf = 0; const refresh = () => { cancelAnimationFrame(raf); raf = requestAnimationFrame(() => { renderPane(); renderStatus(); }); };
  cy.on("select unselect", refresh);
  cy.on("add remove", () => { renderStatus(); $("#gl-empty").classList.toggle("d-none", cy.nodes().length > 0); });
  cy.on("zoom", () => { $("#gl-zlvl").textContent = Math.round(cy.zoom() * 100) + "%"; });
  cy.on("tap", "node", ev => { if (S.linkMode) handleLinkClick(ev.target); });
  cy.on("tap", ev => { if (ev.target === cy) hideCtx(); });
  cy.on("cxttap", ev => { ev.originalEvent && ev.originalEvent.preventDefault(); showCtx(ev); });
  cy.on("dragfree", "node", ev => { const t = ev.target; const set = t.selected() ? cy.nodes(":selected") : t; scheduleSave(set); });
  cy.on("dbltap", "node", ev => { const ids = [ev.target.data("nid")]; const tr = (S.meta.transforms.filter(x => x.accepts.includes(ev.target.data("type")) && x.kind === "module")[0]); if (tr && canEdit()) runTransform(tr.id, ids); });

  const el = $("#gl-cy");
  el.addEventListener("contextmenu", e => e.preventDefault());
  el.addEventListener("dragover", e => e.preventDefault());
  el.addEventListener("drop", async e => {
    e.preventDefault(); const t = e.dataTransfer.getData("text/plain"); if (!S.meta.types[t]) return;
    const r = el.getBoundingClientRect(), p = cy.pan(), z = cy.zoom();
    addEntityDialog(t, { x: (e.clientX - r.left - p.x) / z, y: (e.clientY - r.top - p.y) / z });
  });
  el.addEventListener("keydown", e => {
    if (e.key === "Delete" || e.key === "Backspace") { e.preventDefault(); deleteSelection(); }
    else if (e.key === "Escape") { cy.elements().unselect(); hideCtx(); cancelLink(); }
    else if (e.key === "f") { cy.fit(undefined, 50); }
    else if ((e.ctrlKey || e.metaKey) && e.key === "a") { e.preventDefault(); cy.nodes().select(); }
  });
  document.addEventListener("click", e => { if (!e.target.closest("#gl-ctx")) hideCtx(); });
}

let saveTimer = 0, saveSet = new Set();
function scheduleSave(nodes) {
  if (!canEdit()) return;
  nodes.forEach(n => saveSet.add(n));
  clearTimeout(saveTimer);
  saveTimer = setTimeout(async () => {
    const items = [...saveSet].filter(n => n.inside()).map(n => ({ id: n.data("nid"), x: n.position("x"), y: n.position("y") })); saveSet = new Set();
    try { await api(`/graphlab/graphs/${S.gid}/positions`, { method: "POST", body: { nodes: items } }); } catch (e) { fail(e); }
  }, 500);
}

function layoutOpts(name) {
  const base = { name, animate: true, animationDuration: 350, padding: 50, fit: true };
  if (name === "cose") return { ...base, nodeRepulsion: () => 12000, idealEdgeLength: () => 110, nodeOverlap: 20, gravity: 0.4 };
  if (name === "breadthfirst") return { ...base, directed: true, spacingFactor: 1.2 };
  if (name === "concentric") return { ...base, minNodeSpacing: 40, concentric: n => n.degree(), levelWidth: () => 2 };
  return base;
}
function arrange(name) {
  const lay = S.cy.layout(layoutOpts(name));
  lay.on("layoutstop", () => scheduleSave(S.cy.nodes()));
  lay.run();
}

/* ------------------------------------------------------------------ load / graphs */
async function loadGraphs(selectId) {
  S.graphs = await api("/graphlab/graphs");
  if (!S.graphs.length && canEdit()) { const id = (await api("/graphlab/graphs", { method: "POST", body: { name: "My first graph" } })).id; S.graphs = await api("/graphlab/graphs"); selectId = id; }
  let id = selectId || +localStorage.getItem("cclass.gl.graph");
  if (!S.graphs.some(g => g.id === id)) id = S.graphs.length ? S.graphs[0].id : null;
  renderGraphSelect(id);
  if (id) await openGraph(id); else { S.cy.elements().remove(); S.gid = null; renderPane(); }
}
function renderGraphSelect(id) {
  $("#gl-graph").innerHTML = S.graphs.map(g => `<option value="${g.id}" ${g.id === id ? "selected" : ""}>${esc(g.name)} (${g.node_count})</option>`).join("");
}
async function openGraph(id) {
  const snap = await api(`/graphlab/graphs/${id}`);
  S.gid = id; try { localStorage.setItem("cclass.gl.graph", String(id)); } catch (e) { /* private mode */ }
  S.graph = snap.graph; cancelLink();
  const cy = S.cy; cy.elements().remove();
  cy.add([...snap.nodes.map(n => ({ group: "nodes", data: nodeData(n), position: { x: n.x, y: n.y } })), ...snap.edges.map(e => ({ group: "edges", data: edgeData(e) }))]);
  const allZero = snap.nodes.length > 1 && snap.nodes.every(n => n.x === 0 && n.y === 0);
  if (allZero) arrange("cose"); else if (snap.nodes.length) cy.fit(undefined, 60);
  $("#gl-empty").classList.toggle("d-none", snap.nodes.length > 0);
  renderPane(); renderStatus();
}

/* ------------------------------------------------------------------ entities */
function viewCentre() { const c = S.cy, p = c.pan(), z = c.zoom(); return { x: (c.width() / 2 - p.x) / z + (Math.random() - .5) * 60, y: (c.height() / 2 - p.y) / z + (Math.random() - .5) * 60 }; }
async function addEntity(type, value, pos) {
  if (!need() || !S.gid) return null;
  try {
    const p = pos || viewCentre();
    const r = await api(`/graphlab/graphs/${S.gid}/nodes`, { method: "POST", body: { type, value, x: p.x, y: p.y } });
    const n = r.node; let ele = S.cy.getElementById("n" + n.id);
    if (!ele.length) ele = S.cy.add({ group: "nodes", data: nodeData(n), position: { x: n.x, y: n.y } });
    else toast("That entity is already in the graph.", "info");
    S.cy.elements().unselect(); ele.select(); flash(ele);
    return ele;
  } catch (e) { fail(e); return null; }
}
function flash(eles) { eles.addClass("fresh"); setTimeout(() => eles.removeClass("fresh"), 2500); }
async function addEntityDialog(type, pos) {
  if (!need()) return;
  const v = await ask(`Add ${typeInfo(type).label}`, [{ id: "value", label: typeInfo(type).label, required: true, max: type === "text" ? 4000 : 500, area: type === "text" }], "Add");
  if (v && v.value.trim()) addEntity(type, v.value.trim(), pos);
}
async function deleteSelection() {
  if (!need()) return;
  const sel = S.cy.$(":selected"); if (!sel.length) return;
  if (!confirm(`Delete ${sel.nodes().length} entit(y/ies) and ${sel.edges().length} link(s)?`)) return;
  try {
    for (const e of sel.edges()) await api(`/graphlab/edges/${e.data("eid")}`, { method: "DELETE" });
    for (const n of sel.nodes()) await api(`/graphlab/nodes/${n.data("nid")}`, { method: "DELETE" });
    sel.remove(); hideCtx();
  } catch (e) { fail(e); }
}

/* ------------------------------------------------------------------ links */
function cancelLink() { S.linkMode = false; S.linkFrom = null; S.cy && S.cy.nodes().removeClass("linksrc"); $("#gl-linkmode").textContent = "Link mode: off"; }
function toggleLink() { if (S.linkMode) { cancelLink(); return; } if (!need()) return; S.linkMode = true; $("#gl-linkmode").textContent = "Link mode: click two entities"; toast("Click the source entity, then the target.", "info"); }
async function handleLinkClick(n) {
  if (!S.linkFrom) { S.linkFrom = n; n.addClass("linksrc"); return; }
  const a = S.linkFrom; cancelLink(); if (a.id() === n.id()) return;
  await createLink(a, n);
}
async function createLink(a, b) {
  const v = await ask("Link entities", [{ id: "label", label: `${a.data("label")}  →  ${b.data("label")}`, value: "related_to", required: true, max: 80 }], "Link");
  if (!v) return;
  try {
    const r = await api(`/graphlab/graphs/${S.gid}/edges`, { method: "POST", body: { src: a.data("nid"), dst: b.data("nid"), label: v.label } });
    if (!S.cy.getElementById("e" + r.edge.id).length) S.cy.add({ group: "edges", data: edgeData(r.edge) });
  } catch (e) { fail(e); }
}

/* ------------------------------------------------------------------ transforms */
function transformsFor(types) { return S.meta.transforms.filter(t => types.every(x => t.accepts.includes(x))); }
async function runTransform(tid, ids) {
  if (!need()) return;
  const t = S.meta.transforms.find(x => x.id === tid);
  S.busy++; renderStatus(`Running "${t.name}"...`);
  try {
    const r = await api(`/graphlab/graphs/${S.gid}/transform`, { method: "POST", body: { transform: tid, node_ids: ids } });
    const cy = S.cy, fresh = cy.collection();
    r.added_nodes.forEach(n => { if (!cy.getElementById("n" + n.id).length) fresh.merge(cy.add({ group: "nodes", data: nodeData(n), position: { x: n.x, y: n.y } })); });
    r.added_edges.forEach(e => { if (!cy.getElementById("e" + e.id).length && cy.getElementById("n" + e.src).length && cy.getElementById("n" + e.dst).length) cy.add({ group: "edges", data: edgeData(e) }); });
    r.updated_nodes.forEach(n => { const el = cy.getElementById("n" + n.id); if (el.length) el.data("notes", n.notes); });
    flash(fresh);
    const errs = r.results.filter(x => x.status === "error");
    if (fresh.length || r.added_edges.length) toast(`${t.name}: +${fresh.length} entities, +${r.added_edges.length} links`, "success");
    else if (!errs.length) toast(`${t.name}: nothing new to add.`, "info");
    errs.slice(0, 3).forEach(x => toast(x.message, "warning"));
    r.results.forEach(x => (x.warnings || []).slice(0, 2).forEach(w => toast(w, "info")));
    if (fresh.length) { const src = ids.map(i => cy.getElementById("n" + i)).reduce((a, b) => a.union(b), cy.collection()); cy.animate({ fit: { eles: fresh.union(src), padding: 80 } }, { duration: 350 }); }
    refreshGraphCounts();
  } catch (e) { fail(e); } finally { S.busy--; renderStatus(); renderPane(); }
}
async function refreshGraphCounts() { try { S.graphs = await api("/graphlab/graphs"); renderGraphSelect(S.gid); } catch (e) { /* cosmetic */ } }

/* ------------------------------------------------------------------ context menu */
function hideCtx() { $("#gl-ctx").classList.add("d-none"); }
function showCtx(ev) {
  const cy = S.cy, tgt = ev.target, m = $("#gl-ctx"); let html = "";
  if (tgt !== cy && tgt.isNode()) {
    if (!tgt.selected()) { cy.elements().unselect(); tgt.select(); }
    const sel = cy.nodes(":selected"), types = [...new Set(sel.map(n => n.data("type")))];
    const list = transformsFor(types), groups = {};
    list.forEach(t => (groups[t.group || "Other"] = groups[t.group || "Other"] || []).push(t));
    html += `<div class="grp">${sel.length > 1 ? sel.length + " entities" : esc(typeInfo(types[0]).label)}</div>`;
    if (!list.length) html += `<div class="px-2 py-1 small text-secondary">No transforms for this selection.</div>`;
    Object.keys(groups).forEach(g => { html += `<div class="grp">${esc(g)}</div>` + groups[g].map(t => `<button data-tr="${esc(t.id)}">${esc(t.name)}<small>${esc(t.description)}</small></button>`).join(""); });
    html += `<hr><button data-act="link">Link from here...</button><button data-act="copy">Copy value</button><button data-act="del">Delete</button>`;
  } else if (tgt !== cy && tgt.isEdge()) {
    cy.elements().unselect(); tgt.select();
    html += `<button data-act="rename-edge">Rename link</button><button data-act="del">Delete link</button>`;
  } else {
    html += `<div class="grp">Canvas</div>` + Object.keys(S.meta.types).slice(0, 8).map(t => `<button data-add="${esc(t)}">Add ${esc(typeInfo(t).label)}...</button>`).join("") + `<hr><button data-act="all">Select all</button><button data-act="fit">Fit to window</button>`;
    m.dataset.x = ev.position.x; m.dataset.y = ev.position.y;
  }
  m.innerHTML = html; m.classList.remove("d-none");
  const r = $("#gl-cy").getBoundingClientRect(), rp = ev.renderedPosition || { x: 20, y: 20 };
  m.style.left = Math.min(rp.x, Math.max(0, r.width - 270)) + "px"; m.style.top = Math.min(rp.y, Math.max(0, r.height - m.offsetHeight - 10)) + "px";
  m.onclick = async e => {
    const b = e.target.closest("button"); if (!b) return; hideCtx();
    if (b.dataset.tr) runTransform(b.dataset.tr, cy.nodes(":selected").map(n => n.data("nid")));
    else if (b.dataset.add) addEntityDialog(b.dataset.add, { x: +m.dataset.x, y: +m.dataset.y });
    else if (b.dataset.act === "del") deleteSelection();
    else if (b.dataset.act === "copy") { const n = cy.nodes(":selected")[0]; try { await navigator.clipboard.writeText(n.data("value")); toast("Copied", "success"); } catch (x) { toast("Copy is blocked by the browser", "warning"); } }
    else if (b.dataset.act === "link") { if (!need()) return; S.linkMode = true; S.linkFrom = cy.nodes(":selected")[0]; S.linkFrom.addClass("linksrc"); $("#gl-linkmode").textContent = "Link mode: click the target"; }
    else if (b.dataset.act === "rename-edge") renameEdge(cy.edges(":selected")[0]);
    else if (b.dataset.act === "all") cy.nodes().select();
    else if (b.dataset.act === "fit") cy.fit(undefined, 50);
  };
}
async function renameEdge(e) {
  if (!need() || !e) return;
  const v = await ask("Rename link", [{ id: "label", label: "Label", value: e.data("label"), required: true, max: 80 }], "Save");
  if (!v) return;
  try { const r = await api(`/graphlab/edges/${e.data("eid")}`, { method: "PATCH", body: { label: v.label } }); e.data("label", r.label); renderPane(); } catch (x) { fail(x); }
}

/* ------------------------------------------------------------------ inspector */
function renderStatus(busy) {
  const cy = S.cy; if (!cy) return;
  $("#gl-st-counts").textContent = `${cy.nodes().length} entities · ${cy.edges().length} links`;
  const n = cy.$(":selected").length; $("#gl-st-sel").textContent = n ? `${n} selected` : "";
  $("#gl-st-busy").textContent = S.busy ? (busy || "Working...") : "";
}
function renderPane() {
  const pane = $("#gl-pane"); if (!S.cy || !S.meta) return;
  $$("#gl-tabs li").forEach(li => li.classList.toggle("on", li.dataset.tab === S.tab));
  if (S.tab === "runs") return renderRuns(pane);
  if (S.tab === "graph") return renderGraphTab(pane);
  const cy = S.cy, nodes = cy.nodes(":selected"), edges = cy.edges(":selected");
  if (!nodes.length && !edges.length) {
    pane.innerHTML = `<p class="small text-secondary">Select an entity to see its details and available transforms.</p>
      <ul class="small text-secondary ps-3"><li><b>Right-click</b> an entity to run a transform</li><li><b>Double-click</b> runs its main lookup</li>
      <li><b>Drag</b> to move, <b>Shift+drag</b> to box-select</li><li><b>Link mode</b> draws your own links</li><li><b>Delete</b> removes the selection</li></ul>`; return;
  }
  if (edges.length && !nodes.length) {
    const e = edges[0];
    pane.innerHTML = `<div class="gl-badge">Link</div><div class="gl-val">${esc(e.source().data("label"))} → ${esc(e.target().data("label"))}</div>
      <div class="small mb-2">Label: <b>${esc(e.data("label"))}</b><br><span class="text-secondary">Origin: ${esc(e.data("origin"))}</span></div>
      <button class="btn btn-sm btn-outline-secondary" id="p-ren">Rename</button> <button class="btn btn-sm btn-outline-danger" id="p-del">Delete</button>`;
    $("#p-ren").onclick = () => renameEdge(e); $("#p-del").onclick = deleteSelection; return;
  }
  const types = [...new Set(nodes.map(n => n.data("type")))], trs = transformsFor(types);
  const groups = {}; trs.forEach(t => (groups[t.group || "Other"] = groups[t.group || "Other"] || []).push(t));
  let h = "";
  if (nodes.length === 1) {
    const n = nodes[0], d = n.data(), ti = typeInfo(d.type);
    h += `<span class="gl-badge"><i class="gl-dot" style="background:${esc(ti.color)}"></i>${esc(ti.label)}</span>
      <div class="gl-val">${esc(d.value)}</div>
      <label class="form-label small mb-0" for="p-label">Label (optional)</label><input class="form-control form-control-sm mb-2" id="p-label" value="${esc(d.nlabel)}" maxlength="200">
      <label class="form-label small mb-0" for="p-notes">Notes</label><textarea class="form-control form-control-sm mb-2" id="p-notes" rows="4" maxlength="5000">${esc(d.notes)}</textarea>
      <div class="d-flex gap-2 mb-2"><button class="btn btn-sm btn-primary" id="p-save">Save</button><button class="btn btn-sm btn-outline-danger" id="p-del">Delete</button></div>
      <div class="small text-secondary mb-2">Added by: ${esc(d.source)} · ${n.degree()} link(s)</div>`;
    const at = Object.entries(d.attrs || {});
    if (at.length) h += `<table class="table table-sm small mb-2"><tbody>${at.map(([k, v]) => `<tr><td class="text-secondary">${esc(k)}</td><td>${esc(typeof v === "object" ? JSON.stringify(v) : v)}</td></tr>`).join("")}</tbody></table>`;
  } else {
    h += `<span class="gl-badge">${nodes.length} entities selected</span>`;
    if (nodes.length === 2) h += ` <button class="btn btn-sm btn-outline-secondary ms-1" id="p-link">Link them...</button>`;
    h += ` <button class="btn btn-sm btn-outline-danger ms-1" id="p-del">Delete</button><div class="mb-2"></div>`;
  }
  h += `<div class="gl-h mt-2">Transforms</div>`;
  if (!trs.length) h += `<div class="small text-secondary">No transform accepts this selection.</div>`;
  Object.keys(groups).forEach(g => { h += `<div class="gl-hint mb-1">${esc(g)}</div>` + groups[g].map(t => `<button class="gl-tr ${esc(t.kind)}" data-tr="${esc(t.id)}">${esc(t.name)}<small>${esc(t.description)}</small></button>`).join(""); });
  pane.innerHTML = h;
  $$("[data-tr]", pane).forEach(b => b.onclick = () => runTransform(b.dataset.tr, nodes.map(n => n.data("nid"))));
  const del = $("#p-del"); if (del) del.onclick = deleteSelection;
  const lk = $("#p-link"); if (lk) lk.onclick = () => createLink(nodes[0], nodes[1]);
  const sv = $("#p-save"); if (sv) sv.onclick = async () => {
    if (!need()) return; const n = nodes[0];
    try { const r = await api(`/graphlab/nodes/${n.data("nid")}`, { method: "PATCH", body: { label: $("#p-label").value, notes: $("#p-notes").value } });
      n.data({ nlabel: r.label, label: r.label || r.value, notes: r.notes }); toast("Saved", "success"); } catch (e) { fail(e); }
  };
}
async function renderRuns(pane) {
  pane.innerHTML = `<div class="small text-secondary">Loading...</div>`;
  try {
    const runs = await api(`/graphlab/graphs/${S.gid}/runs`), name = id => (S.meta.transforms.find(t => t.id === id) || { name: id }).name;
    pane.innerHTML = runs.length ? runs.map(r => `<div class="gl-run"><b>${esc(name(r.transform))}</b><br><span class="mono">${esc(r.node_value || "(deleted)")}</span><br>
      ${r.status === "ok" ? `+${r.added_nodes} entities, +${r.added_edges} links` : `<span class="err">${esc(r.message || "failed")}</span>`}
      <span class="text-secondary"> · ${esc(r.actor)} · ${esc((r.created_at || "").replace("T", " ").slice(0, 19))}</span></div>`).join("") : `<p class="small text-secondary">No transforms have been run on this graph yet.</p>`;
  } catch (e) { pane.innerHTML = `<div class="alert alert-danger">${esc(e.message)}</div>`; }
}
function renderGraphTab(pane) {
  const cy = S.cy, counts = {}; cy.nodes().forEach(n => counts[n.data("type")] = (counts[n.data("type")] || 0) + 1);
  const top = cy.nodes().sort((a, b) => b.degree() - a.degree()).slice(0, 8);
  pane.innerHTML = `<div class="gl-h">${esc(S.graph ? S.graph.name : "")}</div><div class="small text-secondary mb-2">${esc(S.graph ? S.graph.description : "")}</div>
    <div class="gl-h">By type</div>` + (Object.keys(counts).map(t => `<div class="small mb-1"><i class="gl-dot d-inline-block me-2" style="background:${esc(typeInfo(t).color)}"></i>${esc(typeInfo(t).label)} <b class="float-end">${counts[t]}</b></div>`).join("") || `<div class="small text-secondary">Empty graph.</div>`) +
    `<div class="gl-h mt-3">Most connected</div>` + top.map(n => `<button class="gl-tr" data-focus="${esc(n.id())}">${esc(n.data("label"))}<small>${esc(typeInfo(n.data("type")).label)} · ${n.degree()} links</small></button>`).join("");
  $$("[data-focus]", pane).forEach(b => b.onclick = () => { const n = cy.getElementById(b.dataset.focus); cy.elements().unselect(); n.select(); cy.animate({ center: { eles: n }, zoom: Math.max(cy.zoom(), 1) }, { duration: 300 }); S.tab = "entity"; renderPane(); });
}

/* ------------------------------------------------------------------ chrome */
function buildPalette() {
  $("#gl-palette").innerHTML = Object.entries(S.meta.types).map(([k, v]) => `<div class="gl-pal" draggable="true" data-type="${esc(k)}"><i class="gl-dot" style="background:${esc(v.color)}"></i>${esc(v.label)}</div>`).join("");
  $$(".gl-pal").forEach(p => {
    p.addEventListener("dragstart", e => { e.dataTransfer.setData("text/plain", p.dataset.type); e.dataTransfer.effectAllowed = "copy"; });
    p.onclick = () => addEntityDialog(p.dataset.type);
  });
}
function wire() {
  $("#gl-graph").onchange = e => openGraph(+e.target.value).catch(fail);
  $("#gl-new").onclick = async () => { if (!need()) return; const v = await ask("New graph", [{ id: "name", label: "Name", required: true, max: 120 }], "Create"); if (!v) return;
    try { const g = await api("/graphlab/graphs", { method: "POST", body: { name: v.name } }); await loadGraphs(g.id); } catch (e) { fail(e); } };
  $("#gl-rename").onclick = async () => { if (!need() || !S.gid) return; const v = await ask("Rename graph", [{ id: "name", label: "Name", value: S.graph.name, required: true, max: 120 }, { id: "description", label: "Description", value: S.graph.description, area: true, max: 2000 }], "Save"); if (!v) return;
    try { await api(`/graphlab/graphs/${S.gid}`, { method: "PATCH", body: v }); await loadGraphs(S.gid); } catch (e) { fail(e); } };
  $("#gl-delgraph").onclick = async () => { if (!need() || !S.gid) return; if (!confirm(`Delete the graph "${S.graph.name}" and everything in it?`)) return;
    try { await api(`/graphlab/graphs/${S.gid}`, { method: "DELETE" }); localStorage.removeItem("cclass.gl.graph"); await loadGraphs(); } catch (e) { fail(e); } };
  $("#gl-quick").onsubmit = async e => { e.preventDefault(); const v = $("#gl-quick-q").value.trim(); if (!v) return; $("#gl-quick-q").value = ""; await addEntity("auto", v); };
  $("#gl-layout").onchange = e => { if (e.target.value) arrange(e.target.value); e.target.value = ""; };
  $("#gl-export").onchange = e => {
    const v = e.target.value; e.target.value = ""; if (!v || !S.gid) return;
    if (v === "png") { const a = document.createElement("a"); a.href = S.cy.png({ full: true, bg: "#060f1e", scale: 2 }); a.download = `graph_${S.gid}.png`; a.click(); return; }
    const [fmt, part] = v.split("-"); location.href = `/api/graphlab/graphs/${S.gid}/export?format=${fmt}${part ? "&part=" + part : ""}`;
  };
  $("#gl-import").onclick = () => { if (need()) $("#gl-import-file").click(); };
  $("#gl-import-file").onchange = async e => {
    const f = e.target.files[0]; e.target.value = ""; if (!f || !S.gid) return;
    try { const r = await api(`/graphlab/graphs/${S.gid}/import`, { method: "POST", body: await f.text() });
      toast(`Imported ${r.nodes} entities and ${r.edges} links` + (r.skipped ? ` (${r.skipped} skipped)` : ""), "success"); await openGraph(S.gid); await refreshGraphCounts(); } catch (x) { fail(x); }
  };
  $("#gl-linkmode").onclick = toggleLink;
  $("#gl-selall").onclick = () => S.cy.nodes().select();
  const cy = S.cy, zoomBy = f => { const z = Math.min(cy.maxZoom(), Math.max(cy.minZoom(), cy.zoom() * f)); cy.animate({ zoom: { level: z, renderedPosition: { x: cy.width() / 2, y: cy.height() / 2 } } }, { duration: 150 }); };
  $("#gl-zin").onclick = () => zoomBy(1.4); $("#gl-zout").onclick = () => zoomBy(1 / 1.4);
  $("#gl-zlvl").onclick = () => cy.animate({ zoom: 1 }, { duration: 150 });
  $("#gl-fit").onclick = () => cy.fit(undefined, 50);
  $("#gl-search").oninput = e => {
    const q = e.target.value.trim().toLowerCase(); cy.elements().removeClass("dim hit");
    if (!q) return;
    const hit = cy.nodes().filter(n => (n.data("value") + " " + n.data("label") + " " + n.data("notes")).toLowerCase().includes(q));
    cy.elements().addClass("dim"); hit.removeClass("dim").addClass("hit"); hit.connectedEdges().removeClass("dim");
    if (hit.length) cy.animate({ fit: { eles: hit, padding: 120 } }, { duration: 250 });
  };
  $$("#gl-tabs li").forEach(li => li.onclick = () => { S.tab = li.dataset.tab; renderPane(); });
}

(async function boot() {
  let st;
  try { st = await (await fetch("/api/auth/status", { credentials: "same-origin" })).json(); } catch (e) { document.body.innerHTML = '<div class="p-4">Cannot reach the CCLASS server.</div>'; return; }
  if (st.auth_enabled && !st.authenticated) { location.href = "/?next=/graphlab"; return; }
  S.user = st.user;
  $("#gl-user").innerHTML = st.user ? `${esc(st.user.display_name || st.user.username)} <span class="badge text-bg-secondary">${esc(st.user.role)}</span> <a href="/">Dashboard</a>` : "";
  try {
    S.meta = await api("/graphlab/meta");
    const m = $("#gl-mode"); m.classList.remove("d-none"); m.className = "badge " + (S.meta.offline_mode ? "text-bg-warning" : "text-bg-success"); m.textContent = S.meta.offline_mode ? "OFFLINE MODE" : "ONLINE";
    if (!canEdit()) { const b = document.createElement("span"); b.className = "badge text-bg-secondary"; b.textContent = "READ-ONLY"; $("#gl-mode").after(b); }
    if (typeof cytoscape === "undefined") { document.body.insertAdjacentHTML("beforeend", '<div class="alert alert-danger m-3">Cytoscape.js could not be loaded (no internet and no local copy). Run install.sh --vendor to store the libraries locally.</div>'); return; }
    initCy(); buildPalette(); wire(); await loadGraphs();
  } catch (e) { fail(e); }
})();
