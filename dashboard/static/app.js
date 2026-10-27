/* ERIS analyst console */
"use strict";

const CLASSES = ["BENIGN", "DoS", "GAS", "RPM", "SPEED", "STEERING_WHEEL"];
const ATTACKS = CLASSES.slice(1);
const PRETTY = { BENIGN: "Benign", DoS: "DoS flooding", GAS: "GAS spoofing", RPM: "RPM spoofing",
  SPEED: "SPEED spoofing", STEERING_WHEEL: "Steering spoofing" };
const SEVS = ["Critical", "High", "Medium", "Low"];
const STATUSES = ["new", "acknowledged", "investigating", "resolved", "false_positive"];
const STATUS_LABEL = { new: "New", acknowledged: "Acknowledged", investigating: "Investigating",
  resolved: "Resolved", false_positive: "False positive" };
const FIELDS = ["CAN_ID", "D0", "D1", "D2", "D3", "D4", "D5", "D6", "D7"];
const PRESETS = [ // Table 6.1
  ["BENIGN", "CAN_ID 167 D0 00 D1 80 D2 00 D3 00 D4 00 D5 01 D6 E3 D7 00"],
  ["DoS", "CAN_ID 123 D0 03 D1 02 D2 0D D3 0D D4 0A D5 0F D6 02 D7 04"],
  ["GAS", "CAN_ID 201 D0 00 D1 00 D2 00 D3 00 D4 00 D5 00 D6 40 D7 9C"],
  ["RPM", "CAN_ID 1DC D0 02 D1 1E D2 F5 D3 03 D4 00 D5 00 D6 00 D7 00"],
  ["RPM (error case)", "CAN_ID 201 D0 06 D1 1C D2 06 D3 3F D4 06 D5 2A D6 02 D7 29"],
  ["SPEED", "CAN_ID 158 D0 06 D1 1C D2 06 D3 3F D4 06 D5 2A D6 02 D7 29"],
  ["STEERING_WHEEL", "CAN_ID 080 D0 84 D1 03 D2 02 D3 23 D4 18 D5 05 D6 8A D7 22"],
];

const $ = (s, el = document) => el.querySelector(s);
const $$ = (s, el = document) => [...el.querySelectorAll(s)];
const cssv = n => getComputedStyle(document.documentElement).getPropertyValue(n).trim();
const clsColor = c => cssv("--c-" + c) || "#888";
const sevColor = s => cssv("--s-" + s) || "#888";
const esc = s => String(s ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const pct = (x, d = 1) => x == null ? "–" : (100 * x).toFixed(d) + "%";
const fix = (x, d = 4) => x == null ? "–" : Number(x).toFixed(d);
const pad = n => String(n).padStart(2, "0");
const fmtTime = ts => { const d = new Date(ts * 1000); return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`; };
const fmtDur = s => s == null ? "–" : s < 60 ? `${Math.round(s)}s` : s < 3600 ? `${Math.floor(s / 60)}m ${Math.round(s % 60)}s` : `${Math.floor(s / 3600)}h ${Math.floor(s % 3600 / 60)}m`;
const ago = ts => fmtDur(Date.now() / 1000 - ts) + " ago";
const hexA = (hex, a) => { const h = hex.replace("#", ""); const n = parseInt(h, 16); return `rgba(${n >> 16 & 255},${n >> 8 & 255},${n & 255},${a})`; };

const clsBadge = c => `<span class="cls" style="color:${clsColor(c)};border-color:${hexA(clsColor(c), .45)};background:${hexA(clsColor(c), .1)}">${esc(c)}</span>`;
const sevBadge = s => `<span class="sev" style="color:${sevColor(s)};background:${hexA(sevColor(s), .13)}">${esc(s)}</span>`;
const stBadge = s => `<span class="st st-${s}">${STATUS_LABEL[s] || esc(s)}</span>`;
const bytesHTML = utr => { const t = utr.split(" "); return `<span class="bytes">${[3, 5, 7, 9, 11, 13, 15, 17].map(i => `<span>${t[i]}</span>`).join("")}</span>`; };
const canId = utr => utr.split(" ")[1];

async function api(path, opts = {}) {
  const o = { headers: { "Content-Type": "application/json" }, ...opts };
  if (o.body && typeof o.body !== "string") o.body = JSON.stringify(o.body);
  const r = await fetch(path, o);
  const j = r.headers.get("content-type")?.includes("json") ? await r.json() : await r.text();
  if (!r.ok) throw new Error(j?.detail || r.statusText);
  return j;
}

// ------------------------------------------------------------------ state
const S = {
  status: null, stats: null, stream: null, ws: null,
  frames: [], traffic: [], charts: {}, page: null, seenInc: new Set(),
  aq: { status: ["new", "acknowledged", "investigating"], severity: [], label: [], q: "", sort: "ts", desc: true, offset: 0, limit: 25 },
  selected: new Set(), incFilter: "open", run: "reported", metrics: {}, lastAlertRefresh: 0,
  predQ: { q: "", cls: "", errors: false, page: 0 },
};

// ------------------------------------------------------------------ router
const PAGES = {
  overview: ["Live Monitor", "Real-time CAN-bus classification of replayed held-out traffic"],
  alerts: ["Alerts", "Triage, assign and resolve detections"],
  incidents: ["Incidents", "Alerts grouped by attack class and CAN ID"],
  inspector: ["Frame Inspector", "Classify and explain any CAN frame"],
  explain: ["Explainability", "Why ERIS makes each decision"],
  stats: ["Model Stats", "Evaluation of the T5 detector on held-out frame patterns"],
  system: ["System & Tests", "Architecture, evaluation protocol and live self-checks"],
};

function route() {
  const [p, qs] = (location.hash.replace(/^#\/?/, "") || "overview").split("?");
  const page = PAGES[p] ? p : "overview";
  $$("#drawer-root canvas").forEach(c => Chart.getChart(c)?.destroy());
  $("#drawer-root").innerHTML = "";
  Object.values(S.charts).forEach(c => c.destroy()); S.charts = {};
  S.page = page;
  $$("#nav a").forEach(a => a.classList.toggle("active", a.dataset.page === page));
  $("#page-title").textContent = PAGES[page][0];
  $("#page-sub").textContent = PAGES[page][1];
  const params = new URLSearchParams(qs || "");
  ({ overview, alerts, incidents, inspector, explain, stats, system })[page](params);
  window.scrollTo(0, 0);
}
window.addEventListener("hashchange", route);

// ------------------------------------------------------------------ chrome
async function pollStatus() {
  try {
    const s = await api("/api/status");
    S.status = s;
    const pm = $("#pill-model");
    pm.classList.toggle("live", !s.loading && s.mode === "live model");
    pm.lastElementChild.textContent = s.loading ? "loading model…" :
      s.mode === "live model" ? `T5 · ${s.params_m}M params · ${s.model_dir}` : "recorded predictions";
    $("#pill-dev").classList.toggle("hidden", !s.dev_model);
    setStream(s.stream);
  } catch (e) { /* server restarting */ }
}
function setStream(st) {
  if (!st) return;
  S.stream = st;
  const p = $("#pill-stream");
  p.classList.toggle("live", st.running);
  p.lastElementChild.textContent = st.running ? `LIVE · ${st.fps} fps` : "PAUSED";
}
function setStats(st) {
  if (!st) return;
  S.stats = st;
  const a = $("#nb-alerts"), i = $("#nb-inc");
  a.textContent = st.alerts_open; a.classList.toggle("hidden", !st.alerts_open);
  i.textContent = st.incidents_open; i.classList.toggle("hidden", !st.incidents_open);
}
setInterval(() => { const d = new Date(); $("#clock").textContent = `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`; }, 1000);

function toast(title, sub, sev, onclick) {
  const t = document.createElement("div");
  t.className = "toast";
  t.style.borderLeftColor = sevColor(sev);
  t.innerHTML = `<b>${esc(title)}</b><span>${esc(sub)}</span>`;
  t.onclick = () => { t.remove(); onclick && onclick(); };
  $("#toasts").prepend(t);
  while ($("#toasts").children.length > 4) $("#toasts").lastChild.remove();
  setTimeout(() => t.remove(), 7000);
}

// ------------------------------------------------------------------ websocket
function connect() {
  const ws = new WebSocket(`${location.protocol === "https:" ? "wss" : "ws"}://${location.host}/ws/stream`);
  S.ws = ws;
  ws.onmessage = ev => {
    const m = JSON.parse(ev.data);
    setStream(m.stream); setStats(m.stats);
    if (m.frames && m.frames.length) onFrames(m.frames);
    if (S.page === "overview") updateOverview(m);
    if (S.page === "alerts" && m.frames?.some(f => f.alert_id) && Date.now() - S.lastAlertRefresh > 2500
        && !S.selected.size && S.aq.offset === 0 && !$(".drawer") && !$("#a-tbl:hover")) loadAlerts();
    if (S.page === "incidents" && m.frames?.some(f => f.new_incident) && !$(".drawer")) loadIncidents();
  };
  ws.onclose = () => setTimeout(connect, 1500);
}
function onFrames(frames) {
  for (const f of frames) {
    S.frames.unshift(f);
    const sec = Math.floor(f.ts);
    let b = S.traffic[S.traffic.length - 1];
    if (!b || b.t !== sec) { b = { t: sec, c: {} }; S.traffic.push(b); }
    b.c[f.label] = (b.c[f.label] || 0) + 1;
    if (f.new_incident && !S.seenInc.has(f.incident_id)) {
      S.seenInc.add(f.incident_id);
      if (f.rank >= 3) toast(`New ${f.severity} incident`, f.title, f.severity, () => openIncident(f.incident_id));
    }
  }
  S.frames.length = Math.min(S.frames.length, 80);
  const cut = Math.floor(Date.now() / 1000) - 60;
  S.traffic = S.traffic.filter(b => b.t > cut);
}
function control(cmd) { return api("/api/stream", { method: "POST", body: cmd }).then(setStream); }

// ------------------------------------------------------------------ chart helpers
Chart.defaults.color = "#8d99b6";
Chart.defaults.borderColor = "rgba(34,48,82,.7)";
Chart.defaults.font.family = cssv("--sans") || "sans-serif";
function chart(id, cfg) { const el = document.getElementById(id); if (!el) return; S.charts[id] = new Chart(el, cfg); return S.charts[id]; }

// ================================================================== OVERVIEW
function overview() {
  $("#view").innerHTML = `
  <div class="kpis">
    <div class="kpi accent"><div class="l">Frames analysed</div><div class="v" id="k-frames">0</div><div class="s" id="k-fps">– fps</div></div>
    <div class="kpi"><div class="l">Open alerts</div><div class="v" id="k-open">0</div><div class="s" id="k-total">0 total</div></div>
    <div class="kpi"><div class="l">Open incidents</div><div class="v" id="k-inc">0</div><div class="s" id="k-inc-t">0 total</div></div>
    <div class="kpi bad"><div class="l">Critical incidents</div><div class="v" id="k-crit">0</div><div class="s">open, safety-relevant</div></div>
    <div class="kpi"><div class="l">Mean time to acknowledge</div><div class="v" id="k-mtta">–</div><div class="s">analyst response</div></div>
  </div>
  <div class="grid g21 mb">
    <div class="card"><h3>CAN traffic by predicted class <span class="grow"></span><span class="small dim">frames / second, last 60 s</span></h3>
      <div class="chart-box"><canvas id="ch-traffic"></canvas></div></div>
    <div class="card"><h3>Stream control</h3>
      <div class="btns mb"><button class="btn primary" id="b-run"></button>
        <label class="toggle"><input type="checkbox" id="b-auto"> scheduled attacks</label></div>
      <div class="mb"><div class="small muted">Replay rate: <b id="rate-v"></b> frames/s</div><input type="range" min="2" max="50" id="b-rate" style="width:100%"></div>
      <div class="small muted" style="margin-bottom:8px">Inject an attack burst (held-out test frames)</div>
      <div class="btns" id="b-inject">${ATTACKS.map(c => `<button class="btn sm" data-c="${c}" style="border-color:${hexA(clsColor(c), .6)}">${PRETTY[c]}</button>`).join("")}</div>
      <div class="small" id="burst" style="margin-top:12px;min-height:20px"></div>
      <div class="callout blue small" style="margin-top:10px">Traffic is replayed from the <b>held-out test patterns</b> of CICIoV2024, so every frame is unseen by the model. Each frame passes through classification → explanation → risk assessment.</div>
    </div>
  </div>
  <div class="grid g21 mb">
    <div class="card"><h3>Live CAN bus <span class="grow"></span><a href="#/alerts" class="small">open alert queue →</a></h3>
      <div class="ticker"><div class="row head"><span>time</span><span>ID</span><span>payload D0–D7</span><span>prediction</span><span class="right">conf.</span></div><div id="ticker"></div></div></div>
    <div class="card"><h3>Active incidents <span class="grow"></span><a href="#/incidents" class="small">all →</a></h3><div id="ov-inc"><div class="empty">No incidents yet</div></div></div>
  </div>
  <div class="grid g2">
    <div class="card"><h3>Open alerts by severity</h3><div class="chart-box short"><canvas id="ch-sev"></canvas></div></div>
    <div class="card"><h3>Alerts by attack class</h3><div class="chart-box short"><canvas id="ch-cls"></canvas></div></div>
  </div>`;
  $("#b-run").onclick = () => control({ cmd: S.stream?.running ? "pause" : "start" });
  $("#b-auto").onchange = e => control({ cmd: "auto", value: e.target.checked });
  $("#b-rate").oninput = e => { $("#rate-v").textContent = e.target.value; };
  $("#b-rate").onchange = e => control({ cmd: "rate", value: +e.target.value });
  $$("#b-inject button").forEach(b => b.onclick = () => control({ cmd: "inject", cls: b.dataset.c, n: 60 }));
  chart("ch-traffic", { type: "bar", data: { labels: [], datasets: CLASSES.map(c => ({ label: c, data: [], backgroundColor: clsColor(c), stack: "s", borderWidth: 0 })) },
    options: { animation: false, maintainAspectRatio: false, scales: { x: { stacked: true, ticks: { maxTicksLimit: 7 } }, y: { stacked: true, beginAtZero: true } }, plugins: { legend: { position: "bottom", labels: { boxWidth: 10 } } } } });
  chart("ch-sev", { type: "doughnut", data: { labels: SEVS, datasets: [{ data: [0, 0, 0, 0], backgroundColor: SEVS.map(sevColor), borderWidth: 0 }] },
    options: { maintainAspectRatio: false, cutout: "65%", plugins: { legend: { position: "right" } } } });
  chart("ch-cls", { type: "bar", data: { labels: ATTACKS, datasets: [{ data: [0, 0, 0, 0, 0], backgroundColor: ATTACKS.map(clsColor) }] },
    options: { maintainAspectRatio: false, indexAxis: "y", plugins: { legend: { display: false } }, scales: { x: { beginAtZero: true } } } });
  updateOverview({ stream: S.stream, stats: S.stats });
  refreshOvIncidents();
}
let lastOvInc = 0;
function updateOverview(m) {
  const st = S.stream, s = S.stats;
  if (st) {
    $("#k-frames").textContent = st.processed.toLocaleString();
    $("#k-fps").textContent = `${st.fps} frames/s`;
    $("#b-run").textContent = st.running ? "❚❚ Pause stream" : "▶ Start stream";
    $("#b-auto").checked = st.auto;
    if (document.activeElement !== $("#b-rate")) { $("#b-rate").value = st.rate; $("#rate-v").textContent = st.rate; }
    $("#burst").innerHTML = st.burst ? `<span class="spin"></span> Injecting ${clsBadge(st.burst[0])} burst · ${st.burst[1]} frames left` : `<span class="dim">No burst active</span>`;
  }
  if (s) {
    $("#k-open").textContent = s.alerts_open.toLocaleString();
    $("#k-total").textContent = `${s.alerts_total.toLocaleString()} total`;
    $("#k-inc").textContent = s.incidents_open; $("#k-inc-t").textContent = `${s.incidents_total} total`;
    $("#k-crit").textContent = s.critical_open; $("#k-mtta").textContent = fmtDur(s.mtta_s);
    const cs = S.charts["ch-sev"], cc = S.charts["ch-cls"];
    if (cs) { cs.data.datasets[0].data = SEVS.map(x => s.open_by_severity[x] || 0); cs.update("none"); }
    if (cc) { cc.data.datasets[0].data = ATTACKS.map(x => s.by_label[x] || 0); cc.update("none"); }
  }
  $("#ticker").innerHTML = S.frames.slice(0, 14).map(f => `<div class="row ${f.label !== "BENIGN" ? "attack" : ""}">
    <span class="dim">${fmtTime(f.ts)}</span><span>${f.can_id}</span>${bytesHTML(f.utr)}<span>${clsBadge(f.label)}</span><span class="right">${pct(f.confidence)}</span></div>`).join("");
  const ct = S.charts["ch-traffic"];
  if (ct) {
    const now = Math.floor(Date.now() / 1000), secs = [...Array(60).keys()].map(i => now - 59 + i);
    const by = Object.fromEntries(S.traffic.map(b => [b.t, b.c]));
    ct.data.labels = secs.map(t => t === now ? "now" : `-${now - t}s`);
    ct.data.datasets.forEach(ds => ds.data = secs.map(t => (by[t] || {})[ds.label] || 0));
    ct.update("none");
  }
  if (m.frames?.some(f => f.alert_id) && Date.now() - lastOvInc > 2000) refreshOvIncidents();
}
async function refreshOvIncidents() {
  lastOvInc = Date.now();
  const r = await api("/api/incidents?status=new,acknowledged,investigating");
  const el = $("#ov-inc"); if (!el) return;
  el.innerHTML = r.rows.slice(0, 6).map(incItem).join("") || `<div class="empty">No open incidents</div>`;
  $$(".inc-item", el).forEach(x => x.onclick = () => openIncident(+x.dataset.id));
}
const incItem = i => `<div class="inc-item" data-id="${i.id}"><div class="bar" style="background:${sevColor(i.severity)}"></div>
  <div><div class="t">${esc(i.title)}</div><div class="small muted">${i.count} alerts · first ${fmtTime(i.first_ts)} · last ${ago(i.last_ts)}</div></div>
  <div class="right">${sevBadge(i.severity)}<div style="margin-top:4px">${stBadge(i.status)}</div></div></div>`;

// ================================================================== ALERTS
function alerts() {
  const q = S.aq;
  $("#view").innerHTML = `
  <div class="card mb">
    <div class="btns" style="margin-bottom:10px">
      <input id="a-q" placeholder="Search CAN ID, class, payload, assignee…" style="min-width:280px" value="${esc(q.q)}">
      <span class="small muted" style="margin-left:6px">Status</span>${STATUSES.map(s => `<span class="chip ${q.status.includes(s) ? "on" : ""}" data-f="status" data-v="${s}">${STATUS_LABEL[s]}</span>`).join("")}
    </div>
    <div class="btns">
      <span class="small muted">Severity</span>${SEVS.map(s => `<span class="chip ${q.severity.includes(s) ? "on" : ""}" data-f="severity" data-v="${s}" style="color:${sevColor(s)}">${s}</span>`).join("")}
      <span class="small muted" style="margin-left:8px">Class</span>${ATTACKS.map(c => `<span class="chip ${q.label.includes(c) ? "on" : ""}" data-f="label" data-v="${c}">${c}</span>`).join("")}
      <span class="grow" style="flex:1"></span><button class="btn sm ghost" id="a-clear">Reset filters</button>
    </div>
  </div>
  <div class="card">
    <div class="btns" style="margin-bottom:10px">
      <b id="a-count" class="small"></b><span class="small muted" id="a-selc"></span><span style="flex:1"></span>
      <button class="btn sm" data-bulk="acknowledged">Acknowledge</button>
      <button class="btn sm" data-bulk="investigating">Investigate</button>
      <button class="btn sm ok" data-bulk="resolved">Resolve</button>
      <button class="btn sm" data-bulk="false_positive">False positive</button>
      <input id="a-assign" placeholder="Assign to…" style="width:130px;padding:4px 8px"><button class="btn sm" id="a-assign-b">Assign</button>
    </div>
    <div class="scroll"><table class="tbl" id="a-tbl"><thead><tr>
      <th style="width:28px"><input type="checkbox" id="a-all"></th>
      <th class="sortable" data-s="id">#</th><th class="sortable" data-s="ts">Time</th><th class="sortable" data-s="rank">Severity</th>
      <th class="sortable" data-s="label">Detection</th><th class="sortable" data-s="can_id">CAN ID</th><th>Payload</th>
      <th class="sortable num" data-s="confidence">Conf.</th><th class="sortable" data-s="status">Status</th><th>Assignee</th><th>Incident</th></tr></thead>
      <tbody id="a-body"><tr><td colspan="11" class="loading"><span class="spin"></span></td></tr></tbody></table></div>
    <div class="pager"><span id="a-range"></span><button class="btn sm" id="a-prev">‹ Prev</button><button class="btn sm" id="a-next">Next ›</button></div>
  </div>`;
  let t;
  $("#a-q").oninput = e => { clearTimeout(t); t = setTimeout(() => { q.q = e.target.value; q.offset = 0; loadAlerts(); }, 250); };
  $$(".chip[data-f]").forEach(c => c.onclick = () => {
    const arr = q[c.dataset.f], v = c.dataset.v, i = arr.indexOf(v);
    i >= 0 ? arr.splice(i, 1) : arr.push(v); c.classList.toggle("on"); q.offset = 0; loadAlerts();
  });
  $("#a-clear").onclick = () => { Object.assign(q, { status: ["new", "acknowledged", "investigating"], severity: [], label: [], q: "", offset: 0 }); alerts(); };
  $$("th[data-s]").forEach(th => th.onclick = () => { q.desc = q.sort === th.dataset.s ? !q.desc : true; q.sort = th.dataset.s; loadAlerts(); });
  $("#a-prev").onclick = () => { q.offset = Math.max(0, q.offset - q.limit); loadAlerts(); };
  $("#a-next").onclick = () => { q.offset += q.limit; loadAlerts(); };
  $("#a-all").onchange = e => { $$("#a-body input[type=checkbox]").forEach(cb => { cb.checked = e.target.checked; toggleSel(+cb.dataset.id, cb.checked); }); };
  $$("[data-bulk]").forEach(b => b.onclick = () => bulk({ status: b.dataset.bulk }));
  $("#a-assign-b").onclick = () => bulk({ assignee: $("#a-assign").value.trim() });
  S.selected.clear();
  loadAlerts();
}
function toggleSel(id, on) {
  on ? S.selected.add(id) : S.selected.delete(id);
  const tr = $(`#a-body tr[data-id="${id}"]`); tr && tr.classList.toggle("sel", on);
  $("#a-selc").textContent = S.selected.size ? `· ${S.selected.size} selected` : "";
}
async function bulk(body) {
  if (!S.selected.size) return toast("Nothing selected", "Tick one or more alerts first", "Low");
  await api("/api/alerts", { method: "PATCH", body: { ids: [...S.selected], ...body } });
  toast("Alerts updated", `${S.selected.size} alert(s) ${body.status ? "→ " + STATUS_LABEL[body.status] : "assigned to " + (body.assignee || "nobody")}`, "Low");
  S.selected.clear(); $("#a-all").checked = false; $("#a-selc").textContent = ""; loadAlerts();
}
async function loadAlerts() {
  S.lastAlertRefresh = Date.now();
  const q = S.aq;
  const p = new URLSearchParams({ status: q.status.join(","), severity: q.severity.join(","), label: q.label.join(","), q: q.q, sort: q.sort, desc: q.desc, limit: q.limit, offset: q.offset });
  const r = await api("/api/alerts?" + p);
  const body = $("#a-body"); if (!body) return;
  $("#a-count").textContent = `${r.total.toLocaleString()} alerts`;
  $("#a-range").textContent = r.total ? `${q.offset + 1}–${Math.min(q.offset + q.limit, r.total)} of ${r.total}` : "";
  $("#a-prev").disabled = q.offset === 0; $("#a-next").disabled = q.offset + q.limit >= r.total;
  $$("th[data-s]").forEach(th => th.textContent = th.textContent.replace(/ [▲▼]$/, "") + (th.dataset.s === q.sort ? (q.desc ? " ▼" : " ▲") : ""));
  body.innerHTML = r.rows.map(a => `<tr class="click ${S.selected.has(a.id) ? "sel" : ""}" data-id="${a.id}">
    <td><input type="checkbox" data-id="${a.id}" ${S.selected.has(a.id) ? "checked" : ""}></td>
    <td class="dim mono">${a.id}</td><td class="mono nowrap">${fmtTime(a.ts)}</td><td>${sevBadge(a.severity)}</td>
    <td>${clsBadge(a.label)}</td><td class="mono">0x${a.can_id}</td><td class="mono small">${bytesHTML(a.utr)}</td>
    <td class="num">${pct(a.confidence)}</td><td>${stBadge(a.status)}</td><td>${esc(a.assignee || "—")}</td>
    <td><a href="#" data-inc="${a.incident_id}">#${a.incident_id}</a></td></tr>`).join("")
    || `<tr><td colspan="11"><div class="empty">No alerts match the filters. Inject an attack from the Live Monitor.</div></td></tr>`;
  $$("#a-body tr.click").forEach(tr => tr.onclick = e => {
    if (e.target.matches("input")) return toggleSel(+e.target.dataset.id, e.target.checked);
    if (e.target.dataset.inc) { e.preventDefault(); return openIncident(+e.target.dataset.inc); }
    openAlert(+tr.dataset.id);
  });
}

// ------------------------------------------------------------------ drawer
function drawer(html) {
  closeDrawer();
  $("#drawer-root").innerHTML = `<div class="drawer-bg"></div><div class="drawer">${html}</div>`;
  $(".drawer-bg").onclick = closeDrawer;
  $$(".drawer .x").forEach(x => x.onclick = closeDrawer);
}
function closeDrawer() {
  $$("#drawer-root canvas").forEach(c => { const ch = Chart.getChart(c); ch && ch.destroy(); delete S.charts[c.id]; });
  $("#drawer-root").innerHTML = "";
  if (S.page === "alerts") loadAlerts();
  if (S.page === "incidents") loadIncidents();
}
document.addEventListener("keydown", e => { if (e.key === "Escape" && $(".drawer")) closeDrawer(); });

function workflowHTML(status, assignee) {
  return `<div class="btns">${STATUSES.filter(s => s !== "new").map(s => `<button class="btn sm ${s === "resolved" ? "ok" : ""} ${s === status ? "primary" : ""}" data-st="${s}">${STATUS_LABEL[s]}</button>`).join("")}
    <span style="flex:1"></span><input id="d-assign" placeholder="Assignee" value="${esc(assignee || "")}" style="width:130px;padding:4px 8px"><button class="btn sm" id="d-assign-b">Assign</button></div>`;
}
function notesHTML(events) {
  return `<div class="card"><h3>Analyst notes &amp; activity</h3>
    <div class="btns mb"><input id="d-note" placeholder="Add a note for the investigation…" style="flex:1"><button class="btn sm primary" id="d-note-b">Add note</button></div>
    <ul class="timeline">${events.slice().reverse().map(e => `<li class="k-${e.kind}"><span class="dim mono small">${fmtTime(e.ts)}</span> · <b>${esc(e.actor)}</b> — ${esc(e.detail)}</li>`).join("") || `<li class="dim">No activity yet</li>`}</ul></div>`;
}

async function openAlert(id) {
  drawer(`<div class="dh"><div><h2>Alert #${id}</h2></div><span style="flex:1"></span><button class="x">×</button></div><div class="db"><div class="loading"><span class="spin"></span> Computing explanation…</div></div>`);
  const a = await api(`/api/alerts/${id}`);
  const html = `<div class="dh"><div>
      <div class="btns" style="margin-bottom:6px">${sevBadge(a.severity)}${clsBadge(a.label)}${stBadge(a.status)}<span class="small dim">Alert #${a.id} · ${new Date(a.ts * 1000).toLocaleString()}</span></div>
      <h2>${esc(PRETTY[a.label])} on CAN ID 0x${a.can_id}</h2>
      <div class="small muted" style="margin-top:4px">Incident <a href="#" id="d-inc">#${a.incident_id}</a> · ${a.incident?.count ?? "?"} related alerts · confidence ${pct(a.confidence)}
        ${a.true_label ? ` · replay ground truth ${clsBadge(a.true_label)}` : ""}</div></div>
      <span style="flex:1"></span><button class="x">×</button></div>
    <div class="db">
      <div class="card">${workflowHTML(a.status, a.assignee)}</div>
      ${a.explanation ? explanationHTML(a.explanation) : `<div class="card"><div class="empty">Explanation unavailable: the model is not loaded (recorded mode).</div></div>`}
      ${riskHTML(a.risk)}
      ${notesHTML(a.events)}
    </div>`;
  if (!$(".drawer")) return;
  $(".drawer").innerHTML = html;
  $$(".drawer .x").forEach(x => x.onclick = closeDrawer);
  $("#d-inc").onclick = e => { e.preventDefault(); openIncident(a.incident_id); };
  const upd = body => api("/api/alerts", { method: "PATCH", body: { ids: [a.id], ...body } }).then(() => openAlert(a.id));
  $$("[data-st]").forEach(b => b.onclick = () => upd({ status: b.dataset.st }));
  $("#d-assign-b").onclick = () => upd({ assignee: $("#d-assign").value.trim() });
  $("#d-note-b").onclick = () => $("#d-note").value.trim() && upd({ note: $("#d-note").value });
  $("#d-note").onkeydown = e => e.key === "Enter" && $("#d-note-b").click();
  if (a.explanation) drawProbChart("d-probs", a.explanation.probs);
}

// ------------------------------------------------------------------ explanation + risk components
const heatBg = (v, rgb = "255,181,71") => `background:rgba(${rgb},${Math.min(.9, .06 + v * 1.4)});color:${v > .35 ? "#111" : "#e7ecf6"}`;
function frameHTML(values, shares, changed = []) {
  const top = shares ? [...shares.keys()].sort((a, b) => shares[b] - shares[a]).slice(0, 3) : [];
  return `<div class="frame">${FIELDS.map((f, i) => `<div class="f ${top.includes(i) ? "hot" : ""} ${changed.includes(f) ? "changed" : ""}"
    style="${shares ? `background:rgba(255,181,71,${(shares[i] * 0.9).toFixed(3)})` : ""}">
    <div class="n">${f === "CAN_ID" ? "CAN ID" : f}</div><div class="v">${esc(values[i])}</div>${shares ? `<div class="p">${pct(shares[i], 0)}</div>` : ""}</div>`).join("")}</div>`;
}
function explanationHTML(ex, pid = "d-probs") {
  const rows = [["Combined", ex.combined, "Average of occlusion and IG shares"],
    ["Occlusion", ex.occlusion_share, "Drop in class probability when the field is masked"],
    ["Integrated Gradients", ex.ig_share, "Gradient path integral from a masked frame"],
    ["Cross-attention", ex.attention_share, "Decoder attention while generating the label"]];
  const cf = ex.counterfactual, pr = ex.prototype;
  const cfHTML = !cf.applicable ? `<div class="small muted">Frame is benign: no counterfactual needed.</div>` : !cf.found ?
    `<div class="small muted">No small change towards known benign traffic (${esc(cf.scope)}) makes ERIS call this frame benign: a strong attack signature.</div>` :
    `<div class="small muted mb">${esc(cf.method)} · searched ${esc(cf.scope)}</div>
     <div class="small" style="margin-bottom:4px">Observed frame → ${clsBadge(ex.label)}</div>${frameHTML(ex.values, null)}
     <div style="text-align:center;color:var(--accent2);margin:6px 0">▼ change ${cf.changes.map(c => `<b class="mono">${c.field}</b> ${c.from}→${c.to}`).join(", ")}</div>
     <div class="small" style="margin-bottom:4px">Counterfactual frame → ${clsBadge("BENIGN")} ${pct(cf.new_confidence)}</div>${frameHTML(cf.frame.split(" ").filter((_, i) => i % 2), null, cf.changes.map(c => c.field))}`;
  return `<div class="card"><h3>Explanation <span class="grow"></span><span class="small dim">consistency ρ = ${fix(ex.consistency, 2)}</span></h3>
    <div class="mb">${frameHTML(ex.values, ex.combined)}</div>
    <ul class="rationale">${ex.rationale.map(s => `<li>${esc(s)}</li>`).join("")}</ul></div>
  <div class="card"><h3>Field attribution by method</h3>
    <div class="scroll"><table class="heat"><tr><th></th>${FIELDS.map(f => `<th>${f === "CAN_ID" ? "ID" : f}</th>`).join("")}</tr>
    ${rows.map(([n, v, d]) => `<tr><th class="rl" title="${esc(d)}">${n}</th>${v.map(x => `<td style="${heatBg(x)}">${(100 * x).toFixed(0)}</td>`).join("")}</tr>`).join("")}
    <tr><th class="rl dim">value</th>${ex.values.map(v => `<td class="dim">${esc(v)}</td>`).join("")}</tr></table></div>
    <div class="grid g3" style="margin-top:12px">
      <div><div class="small muted">Payload vs identifier</div><div class="meter" style="margin-top:6px"><div style="width:${100 * ex.payload_share}%;background:var(--accent)"></div></div><div class="small" style="margin-top:4px">payload ${pct(ex.payload_share, 0)} · ID ${pct(ex.id_share, 0)}</div></div>
      <div><div class="small muted">Method agreement (Spearman ρ)</div><div class="meter" style="margin-top:6px"><div style="width:${Math.max(0, 100 * ex.consistency)}%;background:${ex.consistency >= .6 ? "var(--ok)" : "var(--warn)"}"></div></div><div class="small" style="margin-top:4px">${fix(ex.consistency, 2)} ${ex.consistency >= .6 ? "· consistent" : "· partial"}</div></div>
      <div><div class="small muted">IG completeness check</div><div class="small" style="margin-top:6px">Σ attributions ${fix(ex.ig_check.sum_attr, 3)} vs Δlog p ${fix(ex.ig_check.target_delta, 3)}<br><span class="dim">error ${fix(ex.ig_check.completeness_error, 3)}</span></div></div>
    </div></div>
  <div class="grid g2" style="gap:14px">
    <div class="card"><h3>Counterfactual: what would make it benign?</h3>${cfHTML}</div>
    <div class="card"><h3>Class probabilities</h3><div class="chart-box short"><canvas id="${pid}"></canvas></div>
      <div class="small muted" style="margin-top:8px">Nearest known frame (${esc(pr.source)}): ${clsBadge(pr.class)} · ${pr.distance}/9 fields differ${pr.diff_fields.length && pr.distance <= 3 ? ` (${pr.diff_fields.join(", ")})` : ""}<div class="mono" style="margin-top:4px">${esc(pr.frame)}</div></div></div>
  </div>`;
}
function drawProbChart(id, probs) {
  chart(id, { type: "bar", data: { labels: CLASSES, datasets: [{ data: CLASSES.map(c => probs[c]), backgroundColor: CLASSES.map(clsColor) }] },
    options: { maintainAspectRatio: false, indexAxis: "y", plugins: { legend: { display: false }, tooltip: { callbacks: { label: c => pct(c.raw, 3) } } },
      scales: { x: { min: 0, max: 1, ticks: { callback: v => (v * 100) + "%" } } } } });
}
function riskHTML(r) {
  if (!r || r.level === "None") return `<div class="card"><h3>Risk assessment <span class="tag">preview</span></h3><div class="small muted">No attack: no vehicle function at risk.</div></div>`;
  const c = sevColor(r.level);
  return `<div class="card"><h3>Risk assessment <span class="tag">preview</span><span class="grow"></span><span class="small dim">ISO/SAE 21434-style impact × feasibility</span></h3>
    <div class="risk-head mb"><div class="risk-score" style="border-color:${c};color:${c}">${r.score}</div>
      <div><div>${sevBadge(r.level)} ${r.sustained ? `<span class="tag" style="color:var(--bad);background:rgba(255,84,104,.14)">sustained</span>` : ""}</div>
      <div style="font-size:15px;font-weight:600;margin-top:4px">${esc(r.function)}</div>
      <div class="small muted">${esc(r.domain)} · impact ${r.impact}/4 · feasibility ${r.feasibility}/4</div></div></div>
    <div class="small mb">${esc(r.impact_note)}</div>
    <div class="grid g2"><div><div class="small muted">Recommended actions</div><ol class="actions small">${r.actions.map(a => `<li>${esc(a)}</li>`).join("")}</ol></div>
    <div><div class="small muted">Scoring factors</div><ul class="actions small">${r.factors.map(a => `<li>${esc(a)}</li>`).join("")}</ul></div></div></div>`;
}

// ================================================================== INCIDENTS
function incidents() {
  $("#view").innerHTML = `<div class="card">
    <div class="btns mb"><div class="seg" id="i-seg">${[["open", "Open"], ["closed", "Closed"], ["all", "All"]].map(([k, l]) => `<button data-k="${k}" class="${S.incFilter === k ? "on" : ""}">${l}</button>`).join("")}</div>
      <span style="flex:1"></span><a class="btn sm" href="/api/export?format=csv">⤓ Export CSV</a><a class="btn sm" href="/api/export?format=json">⤓ Full report (JSON)</a></div>
    <div class="scroll"><table class="tbl"><thead><tr><th>#</th><th>Severity</th><th>Incident</th><th>Class</th><th class="num">Alerts</th><th>First seen</th><th>Last seen</th><th>Duration</th><th>Status</th><th>Assignee</th></tr></thead>
    <tbody id="i-body"><tr><td colspan="10" class="loading"><span class="spin"></span></td></tr></tbody></table></div></div>`;
  $$("#i-seg button").forEach(b => b.onclick = () => { S.incFilter = b.dataset.k; incidents(); });
  loadIncidents();
}
async function loadIncidents() {
  const f = { open: "new,acknowledged,investigating", closed: "resolved,false_positive", all: "" }[S.incFilter];
  const r = await api("/api/incidents?status=" + f);
  const body = $("#i-body"); if (!body) return;
  body.innerHTML = r.rows.map(i => `<tr class="click" data-id="${i.id}"><td class="dim mono">${i.id}</td><td>${sevBadge(i.severity)}</td>
    <td><b>${esc(i.title)}</b></td><td>${clsBadge(i.label)}</td><td class="num">${i.count}</td><td class="mono">${fmtTime(i.first_ts)}</td>
    <td class="mono">${fmtTime(i.last_ts)}</td><td>${fmtDur(i.last_ts - i.first_ts)}</td><td>${stBadge(i.status)}</td><td>${esc(i.assignee || "—")}</td></tr>`).join("")
    || `<tr><td colspan="10"><div class="empty">No incidents in this view</div></td></tr>`;
  $$("#i-body tr.click").forEach(tr => tr.onclick = () => openIncident(+tr.dataset.id));
}
async function openIncident(id) {
  drawer(`<div class="dh"><h2>Incident #${id}</h2><span style="flex:1"></span><button class="x">×</button></div><div class="db"><div class="loading"><span class="spin"></span></div></div>`);
  const i = await api(`/api/incidents/${id}`);
  if (!$(".drawer")) return;
  $(".drawer").innerHTML = `<div class="dh"><div>
      <div class="btns" style="margin-bottom:6px">${sevBadge(i.severity)}${clsBadge(i.label)}${stBadge(i.status)}<span class="small dim">Incident #${i.id}</span></div>
      <h2>${esc(i.title)}</h2></div><span style="flex:1"></span><button class="x">×</button></div>
    <div class="db">
      <div class="kpis"><div class="kpi"><div class="l">Alerts</div><div class="v">${i.count}</div></div>
        <div class="kpi"><div class="l">Duration</div><div class="v">${fmtDur(i.last_ts - i.first_ts)}</div><div class="s">${fmtTime(i.first_ts)} → ${fmtTime(i.last_ts)}</div></div>
        <div class="kpi"><div class="l">Time to acknowledge</div><div class="v">${i.ack_ts ? fmtDur(i.ack_ts - i.first_ts) : "pending"}</div></div>
        <div class="kpi"><div class="l">Alert status</div><div class="s" style="margin-top:8px">${Object.entries(i.by_status).map(([k, v]) => `${stBadge(k)} ${v}`).join("<br>")}</div></div></div>
      <div class="card">${workflowHTML(i.status, i.assignee)}<div class="small dim" style="margin-top:8px">Status changes apply to every open alert in this incident.</div></div>
      ${riskHTML(i.risk)}
      <div class="card"><h3>Alerts in this incident <span class="grow"></span><span class="small dim">latest ${i.alerts.length}</span></h3>
        <div class="scroll" style="max-height:280px"><table class="tbl"><tbody>${i.alerts.map(a => `<tr class="click" data-id="${a.id}"><td class="dim mono">#${a.id}</td><td class="mono">${fmtTime(a.ts)}</td><td class="mono small">${bytesHTML(a.utr)}</td><td class="num">${pct(a.confidence)}</td><td>${stBadge(a.status)}</td></tr>`).join("")}</tbody></table></div></div>
      ${notesHTML(i.events)}
    </div>`;
  $$(".drawer .x").forEach(x => x.onclick = closeDrawer);
  const upd = body => api(`/api/incidents/${id}`, { method: "PATCH", body }).then(() => openIncident(id));
  $$("[data-st]").forEach(b => b.onclick = () => upd({ status: b.dataset.st }));
  $("#d-assign-b").onclick = () => upd({ assignee: $("#d-assign").value.trim() });
  $("#d-note-b").onclick = () => $("#d-note").value.trim() && upd({ note: $("#d-note").value });
  $("#d-note").onkeydown = e => e.key === "Enter" && $("#d-note-b").click();
  $$(".drawer tr.click").forEach(tr => tr.onclick = () => openAlert(+tr.dataset.id));
}

// ================================================================== INSPECTOR
function inspector(params) {
  $("#view").innerHTML = `
  <div class="card mb"><h3>Frame input</h3>
    <div class="desc">Enter raw CSV values exactly as they appear in CICIoV2024 (e.g. <span class="mono">000001DC</span>, <span class="mono">2.0</span>, <span class="mono">3</span>). ERIS normalises them before classification.</div>
    <div class="btns mb"><span class="small muted">Table 6.1 samples:</span>${PRESETS.map(([n, u], i) => `<button class="btn sm" data-p="${i}">${n}</button>`).join("")}</div>
    <div class="grid" style="grid-template-columns:1.3fr repeat(8,1fr) auto;gap:6px;align-items:end">
      <div><div class="small muted">CAN ID</div><input class="byte-in" id="in-id" value="000001DC"></div>
      ${[0, 1, 2, 3, 4, 5, 6, 7].map(i => `<div><div class="small muted">DATA_${i}</div><input class="byte-in" id="in-b${i}" value="${["2.0", "1E", "F5", "3", "0", "0", "0", "0"][i]}"></div>`).join("")}
      <button class="btn primary" id="in-go">Analyse ▸</button>
    </div>
    <div class="btns" style="margin-top:10px"><span class="small muted">or paste a UTR:</span><input id="in-utr" class="mono" style="flex:1" placeholder="CAN_ID 1DC D0 02 D1 1E D2 F5 D3 03 D4 00 D5 00 D6 00 D7 00"><button class="btn" id="in-go2">Analyse UTR</button></div>
  </div>
  <div id="in-out"></div>`;
  const fill = utr => { const t = utr.split(" "); $("#in-id").value = t[1]; [0, 1, 2, 3, 4, 5, 6, 7].forEach(i => $(`#in-b${i}`).value = t[3 + 2 * i]); };
  $$("[data-p]").forEach(b => b.onclick = () => { fill(PRESETS[b.dataset.p][1]); analyse({ utr: PRESETS[b.dataset.p][1] }, PRESETS[b.dataset.p][0]); });
  $("#in-go").onclick = () => analyse({ can_id: $("#in-id").value, data: [0, 1, 2, 3, 4, 5, 6, 7].map(i => $(`#in-b${i}`).value) });
  $("#in-go2").onclick = () => analyse({ utr: $("#in-utr").value });
  $$("#view input.byte-in").forEach(i => i.onkeydown = e => e.key === "Enter" && $("#in-go").click());
  const u = params.get("utr");
  if (u) { fill(u); analyse({ utr: u }); }
}
async function analyse(body, expected) {
  const out = $("#in-out");
  out.innerHTML = `<div class="card loading"><span class="spin"></span> Classifying and explaining…</div>`;
  let r;
  try { r = await api("/api/classify", { method: "POST", body }); }
  catch (e) { out.innerHTML = `<div class="card"><div class="banner" style="margin:0">${esc(e.message)}</div></div>`; return; }
  const ex = r.explanation, exp = expected && expected.split(" ")[0];
  out.innerHTML = `
  <div class="grid g12 mb">
    <div class="card"><h3>Prediction</h3>
      <div style="font-size:26px;font-weight:800;color:${clsColor(ex.label)}">${esc(PRETTY[ex.label])}</div>
      <div class="muted">confidence ${pct(ex.confidence, 2)} · generated text “<span class="mono">${esc(r.generated)}</span>”</div>
      ${exp ? `<div style="margin-top:8px" class="small">Report label: ${clsBadge(exp)} ${exp === ex.label ? `<span class="test-pass">✓ matches</span>` : `<span class="test-fail">✗ differs (see error analysis, Section 7.4)</span>`}</div>` : ""}
      <div class="chart-box short" style="margin-top:12px"><canvas id="in-probs"></canvas></div></div>
    <div class="card"><h3>Pre-processing: normalisation &amp; tokens</h3>
      <div class="scroll"><table class="tbl"><tr><th>Field</th>${r.steps.map(s => `<th class="mono">${s.field}</th>`).join("")}</tr>
        <tr><td class="muted">raw</td>${r.steps.map(s => `<td class="mono">${esc(s.raw)}</td>`).join("")}</tr>
        <tr><td class="muted">normalised</td>${r.steps.map(s => `<td class="mono" style="${s.raw !== s.normalised ? "color:var(--ok);font-weight:700" : ""}">${esc(s.normalised)}</td>`).join("")}</tr></table></div>
      <div class="small muted" style="margin:12px 0 6px">UTR (model input)</div><div class="mono mb" style="font-size:13px">${esc(r.utr)}</div>
      <div class="small muted" style="margin-bottom:6px">Tokens → IDs (word-level hex vocabulary)</div>
      <div>${r.tokens.map((t, i) => `<span class="tok">${esc(t)}<i>${r.token_ids[i] ?? ""}</i></span>`).join("")}</div></div>
  </div>
  ${explanationHTML(ex, "in-probs2")}
  ${riskHTML(r.risk)}`;
  drawProbChart("in-probs", ex.probs);
  drawProbChart("in-probs2", ex.probs);
}

// ================================================================== EXPLAINABILITY
async function explain() {
  $("#view").innerHTML = `
  <div class="card mb"><h3>How ERIS explains a decision</h3>
    <div class="desc">Every alert carries an explanation built from five complementary views, combined into a plain-language rationale for the analyst.</div>
    <div class="grid" style="grid-template-columns:repeat(auto-fit,minmax(210px,1fr))">
      <div class="method"><b><span class="num">1</span>Occlusion</b><span class="small muted">Each field (CAN ID, D0–D7) is masked in turn; the drop in the predicted class probability measures how much the decision depends on it.</span></div>
      <div class="method"><b><span class="num">2</span>Integrated Gradients</b><span class="small muted">Gradients integrated along a path from a fully masked frame to the real one on the T5 input embeddings. Attributions sum to the change in log-probability (completeness).</span></div>
      <div class="method"><b><span class="num">3</span>Cross-attention</b><span class="small muted">Where the T5 decoder looks in the encoded frame while it generates the class label.</span></div>
      <div class="method"><b><span class="num">4</span>Counterfactual</b><span class="small muted">The smallest change, drawn from real benign traffic on the same CAN ID, that makes ERIS call the frame benign.</span></div>
      <div class="method"><b><span class="num">5</span>Prototype</b><span class="small muted">The nearest known frame and its class: an example-based justification analysts can verify.</span></div>
    </div></div>
  <div id="ex-body"><div class="card loading"><span class="spin"></span> Computing explanations for all held-out test frames…</div></div>`;
  let g;
  for (let i = 0; i < 60; i++) {
    const r = await fetch("/api/explain/global");
    if (r.status === 200) { g = await r.json(); break; }
    if (S.page !== "explain") return;
    await new Promise(res => setTimeout(res, 1000));
  }
  if (!g || S.page !== "explain") return;
  const body = $("#ex-body");
  const wrong = g.frames.filter(f => f.true !== f.pred);
  const top = c => [...c.keys()].sort((a, b) => c[b] - c[a]).slice(0, 3).map(k => FIELDS[k]).join(", ");
  body.innerHTML = `
  <div class="kpis">
    <div class="kpi accent"><div class="l">Frames explained</div><div class="v">${g.frames.length}</div><div class="s">unique held-out test patterns</div></div>
    <div class="kpi"><div class="l">Method agreement · attacks</div><div class="v">${fix(g.mean_consistency_attacks ?? g.mean_consistency, 2)}</div><div class="s">mean Spearman ρ, occlusion vs IG (all frames ${fix(g.mean_consistency, 2)})</div></div>
    <div class="kpi"><div class="l">Attack decisions driven by payload</div><div class="v">${pct(avg(g.classes.filter(c => c !== "BENIGN").map(c => 1 - g.heatmap[c][0])), 0)}</div><div class="s">mean share of D0–D7</div></div>
    <div class="kpi ${wrong.length ? "bad" : "ok"}"><div class="l">Misclassified frames</div><div class="v">${wrong.length}</div><div class="s">explained below</div></div>
  </div>
  <div class="grid g21 mb">
    <div class="card"><h3>Global attribution: what each class decision relies on</h3><div class="desc">Mean combined attribution share per field, grouped by predicted class.</div>
      <div class="scroll"><table class="heat"><tr><th></th>${FIELDS.map(f => `<th>${f === "CAN_ID" ? "CAN ID" : f}</th>`).join("")}</tr>
      ${g.classes.map(c => `<tr><th class="rl">${clsBadge(c)}</th>${g.heatmap[c].map(v => `<td style="${heatBg(v)}">${(100 * v).toFixed(0)}%</td>`).join("")}</tr>`).join("")}</table></div></div>
    <div class="card"><h3>Identifier vs payload</h3><div class="chart-box"><canvas id="ex-idp"></canvas></div></div>
  </div>
  ${wrong.length ? `<div class="card mb callout"><h3>Explaining the errors</h3>${wrong.map(f => `<div class="mb"><div class="mono">${esc(f.utr)}</div>
    <div class="small" style="margin:4px 0">true ${clsBadge(f.true)} → predicted ${clsBadge(f.pred)} · top fields: <b>${top(f.combined)}</b> · CAN ID share ${pct(f.combined[0], 0)}</div>
    <a class="btn sm" href="#/inspector?utr=${encodeURIComponent(f.utr)}">Open full explanation ›</a></div>`).join("")}
    <div class="small muted">The payload of this frame is byte-for-byte identical to a SPEED frame while its identifier belongs to GAS. The attribution shows the decision follows the payload, matching the error analysis in Section 7.4.</div></div>` : ""}
  <div class="card"><h3>Per-frame explanations <span class="grow"></span><span class="small dim">click a row to inspect</span></h3>
    <div class="scroll"><table class="tbl"><thead><tr><th>Frame (UTR)</th><th>True</th><th>Predicted</th><th>Top fields</th><th class="num">ID share</th><th class="num">ρ</th></tr></thead>
    <tbody>${g.frames.map(f => `<tr class="click ${f.true !== f.pred ? "bad" : ""}" data-u="${esc(f.utr)}"><td class="mono small">${esc(f.utr)}</td><td>${clsBadge(f.true)}</td><td>${clsBadge(f.pred)}</td>
      <td class="mono small">${top(f.combined)}</td><td class="num">${pct(f.combined[0], 0)}</td><td class="num">${fix(f.consistency, 2)}</td></tr>`).join("")}</tbody></table></div></div>`;
  $$("#ex-body tr.click").forEach(tr => tr.onclick = () => location.hash = "#/inspector?utr=" + encodeURIComponent(tr.dataset.u));
  chart("ex-idp", { type: "bar", data: { labels: g.classes, datasets: [
      { label: "CAN ID", data: g.classes.map(c => g.heatmap[c][0]), backgroundColor: "#4f8cff" },
      { label: "Payload D0–D7", data: g.classes.map(c => 1 - g.heatmap[c][0]), backgroundColor: "#ffb547" }] },
    options: { maintainAspectRatio: false, scales: { x: { stacked: true }, y: { stacked: true, max: 1, ticks: { callback: v => v * 100 + "%" } } }, plugins: { legend: { position: "bottom" } } } });
}
const avg = a => a.length ? a.reduce((x, y) => x + y, 0) / a.length : 0;

// ================================================================== MODEL STATS
async function stats() {
  if (!S.status) await pollStatus();
  const live = S.status?.runs?.live;
  $("#view").innerHTML = `<div class="btns mb"><div class="seg" id="run-seg">
      <button data-r="reported" class="${S.run === "reported" ? "on" : ""}">Reported run (report Ch. 7)</button>
      <button data-r="live" class="${S.run === "live" ? "on" : ""}" ${live ? "" : "disabled title='Run eris_t5.py --out results_live first'"}>Live re-run</button></div>
      <span class="small muted" id="run-info"></span></div><div id="st-body"><div class="loading"><span class="spin"></span></div></div>`;
  $$("#run-seg button").forEach(b => b.onclick = () => { if (b.disabled) return; S.run = b.dataset.r; stats(); });
  let m;
  try { m = S.metrics[S.run] || (S.metrics[S.run] = await api("/api/metrics?run=" + S.run)); }
  catch (e) { $("#st-body").innerHTML = `<div class="banner">${esc(e.message)}</div>`; return; }
  const s = m.summary, pc = m.per_class, bestEpoch = m.loss.eval.reduce((a, b) => b.loss < a.loss ? b : a, m.loss.eval[0] || {});
  $("#run-info").textContent = `mode: ${m.mode} · best checkpoint ${m.best_checkpoint}`;
  $("#st-body").innerHTML = `
  <div class="kpis">
    <div class="kpi accent"><div class="l">Row accuracy</div><div class="v">${pct(s.row_accuracy, 2)}</div><div class="s">${m.rows.test.toLocaleString()} test rows</div></div>
    <div class="kpi accent"><div class="l">Macro F1</div><div class="v">${fix(s.macro_f1)}</div><div class="s">P ${fix(s.macro_precision)} · R ${fix(s.macro_recall)}</div></div>
    <div class="kpi accent"><div class="l">Pattern-level accuracy</div><div class="v">${pct(s.pattern_accuracy, 2)}</div><div class="s">${s.pattern_correct} / ${s.pattern_total} unique frames</div></div>
    <div class="kpi"><div class="l">Weighted F1</div><div class="v">${fix(s.weighted_f1)}</div><div class="s">equal support per class</div></div>
    <div class="kpi ${s.reload_identical ? "ok" : "bad"}"><div class="l">Reload check</div><div class="v">${s.reload_identical ? "Identical" : "Differs"}</div><div class="s">saved model re-predicts</div></div>
    <div class="kpi"><div class="l">Training</div><div class="v">${m.train_runtime ? Math.round(m.train_runtime) + "s" : "–"}</div><div class="s">${m.rows.train.toLocaleString()} train · ${m.rows.val.toLocaleString()} val rows</div></div>
  </div>
  <div class="grid g2 mb">
    <div class="card"><h3>Training &amp; validation loss <span class="grow"></span><span class="small dim">Fig. 7.1 · log scale</span></h3><div class="chart-box tall"><canvas id="st-loss"></canvas></div>
      <div class="small muted" style="margin-top:6px">Best checkpoint: epoch ${bestEpoch.epoch} (val loss ${fix(bestEpoch.loss)}), chosen on validation loss only; the test set is never used for selection.</div></div>
    <div class="card"><h3>Confusion matrix <span class="grow"></span><span class="small dim">Fig. 7.2 · rows true, cols predicted</span></h3>${confusionHTML(m.confusion)}</div>
  </div>
  <div class="grid g21 mb">
    <div class="card"><h3>Per-class precision, recall, F1 <span class="grow"></span><span class="small dim">Fig. 7.3</span></h3><div class="chart-box"><canvas id="st-prf"></canvas></div></div>
    <div class="card"><h3>Per-class results <span class="grow"></span><span class="small dim">Table 7.2</span></h3><table class="tbl compact"><tr><th>Class</th><th class="num">P</th><th class="num">R</th><th class="num">F1</th><th class="num">n</th></tr>
      ${CLASSES.map(c => pc[c] ? `<tr><td>${clsBadge(c)}</td><td class="num">${fix(pc[c].precision)}</td><td class="num">${fix(pc[c].recall)}</td><td class="num" style="${pc[c].f1 < 1 ? "color:var(--warn)" : ""}">${fix(pc[c].f1)}</td><td class="num">${pc[c].support}</td></tr>` : "").join("")}
      ${pc["macro avg"] ? `<tr><td><b>Macro avg</b></td><td class="num"><b>${fix(pc["macro avg"].precision)}</b></td><td class="num"><b>${fix(pc["macro avg"].recall)}</b></td><td class="num"><b>${fix(pc["macro avg"].f1)}</b></td><td class="num">${pc["macro avg"].support}</td></tr>` : ""}</table></div>
  </div>
  <div class="grid g2 mb">
    <div class="card"><h3>Pattern-level analysis <span class="grow"></span><span class="small dim">Table 7.3</span></h3><table class="tbl"><tr><th>Class</th><th class="num">Unique test frames</th><th>CAN ID(s)</th><th class="num">Correct</th></tr>
      ${m.pattern_by_class.map(r => `<tr><td>${clsBadge(r.class)}</td><td class="num">${r.frames}</td><td class="mono small">${r.ids.length > 4 ? r.ids.length + " different IDs" : r.ids.join(", ")}</td><td class="num" style="${r.correct < r.frames ? "color:var(--bad);font-weight:700" : ""}">${r.correct} / ${r.frames}</td></tr>`).join("")}
      <tr><td><b>Total</b></td><td class="num"><b>${s.pattern_total}</b></td><td></td><td class="num"><b>${s.pattern_correct} / ${s.pattern_total}</b></td></tr></table></div>
    <div class="card callout"><h3>Error analysis <span class="grow"></span><span class="small dim">Section 7.4</span></h3>
      ${m.patterns.filter(p => !p.correct).map(p => `<div class="mono mb">${esc(p.utr)}</div><div class="mb">True ${clsBadge(p.true)} predicted ${clsBadge(p.pred)} on <b>${p.rows}</b> test rows.</div>`).join("") || "<div>No misclassified frames.</div>"}
      <div class="small">Its eight payload bytes <span class="mono">06 1C 06 3F 06 2A 02 29</span> are identical to the SPEED frame on CAN ID 158, and its CAN ID 201 is the GAS identifier. A frame with an RPM label, a SPEED payload and a GAS identifier points to a labelling artefact in the dataset. The model followed the payload.</div>
      <div class="btns" style="margin-top:10px"><a class="btn sm" href="#/inspector?utr=${encodeURIComponent("CAN_ID 201 D0 06 D1 1C D2 06 D3 3F D4 06 D5 2A D6 02 D7 29")}">Explain this frame ›</a></div></div>
  </div>
  <div class="grid g3 mb">
    <div class="card"><h3>Dataset <span class="grow"></span><span class="small dim">Table 5.1</span></h3><table class="tbl compact"><tr><th>Class</th><th class="num">Raw rows</th><th class="num">Patterns</th></tr>
      ${m.dataset.map(d => `<tr><td>${clsBadge(d.class)}</td><td class="num">${d.rows.toLocaleString()}</td><td class="num">${d.patterns.toLocaleString()}</td></tr>`).join("")}
      <tr><td><b>Total</b></td><td class="num"><b>${m.dataset.reduce((a, d) => a + d.rows, 0).toLocaleString()}</b></td><td class="num"><b>${m.dataset.reduce((a, d) => a + d.patterns, 0).toLocaleString()}</b></td></tr></table>
      <div class="small muted" style="margin-top:8px">99.7% of rows are duplicates, so splits are made on unique frames.</div></div>
    <div class="card"><h3>Pattern-level split <span class="grow"></span><span class="small dim">Table 5.3</span></h3><table class="tbl compact"><tr><th>Class</th><th class="num">Patterns</th><th class="num">Train</th><th class="num">Val</th><th class="num">Test</th></tr>
      ${m.pattern_split.map(r => `<tr><td>${clsBadge(r.class)}</td><td class="num">${r.patterns}</td><td class="num">${r.train}</td><td class="num">${r.val}</td><td class="num">${r.test}</td></tr>`).join("")}</table>
      <div class="small muted" style="margin-top:8px">No frame appears in more than one split. Rows: ${m.rows.train} / ${m.rows.val} / ${m.rows.test}.</div></div>
    <div class="card"><h3>Model configuration <span class="grow"></span><span class="small dim">Table 5.4</span></h3>${m.config.map(([k, v]) => `<div class="stat-line"><span class="muted">${k}</span><span class="right">${v}</span></div>`).join("")}</div>
  </div>
  <div class="card mb"><h3>Comparison with related work <span class="grow"></span><span class="small dim">Table 7.4</span></h3><table class="tbl"><tr><th>Study</th><th>Evaluation protocol</th><th>Model</th><th class="num">Macro F1</th></tr>
    ${m.comparison.map(c => `<tr ${c.study.startsWith("ERIS") ? 'style="background:rgba(79,140,255,.08)"' : ""}><td><b>${esc(c.study)}</b></td><td>${esc(c.protocol)}</td><td>${esc(c.model)}</td><td class="num">${fix(c.f1, 2)}</td></tr>`).join("")}</table>
    <div class="small muted" style="margin-top:8px">Random splits of duplicated rows give perfect but leaked scores; removing duplicates drops them sharply. ERIS reports 0.91 under a strict pattern-level split.</div></div>
  <div class="card"><h3>Test predictions browser <span class="grow"></span><span class="small dim">test_predictions.csv · ${m.predictions.length.toLocaleString()} rows</span></h3>
    <div class="btns mb"><input id="pb-q" placeholder="Search UTR / CAN ID…" style="min-width:240px" value="${esc(S.predQ.q)}">
      <select id="pb-c"><option value="">All classes</option>${CLASSES.map(c => `<option ${S.predQ.cls === c ? "selected" : ""}>${c}</option>`).join("")}</select>
      <label class="toggle"><input type="checkbox" id="pb-e" ${S.predQ.errors ? "checked" : ""}> errors only</label><span class="small muted" id="pb-n"></span></div>
    <div class="scroll"><table class="tbl"><thead><tr><th>#</th><th>Input text (UTR)</th><th>True</th><th>Predicted</th><th></th></tr></thead><tbody id="pb-body"></tbody></table></div>
    <div class="pager"><button class="btn sm" id="pb-prev">‹ Prev</button><span id="pb-range"></span><button class="btn sm" id="pb-next">Next ›</button></div></div>`;
  const tr = m.loss.train, ev = m.loss.eval;
  chart("st-loss", { type: "line", data: { datasets: [
      { label: "Training loss (every 50 steps)", data: tr.map(p => ({ x: p.epoch, y: p.loss })), borderColor: "#4f8cff", pointRadius: 0, borderWidth: 2, tension: .2 },
      { label: "Validation loss (per epoch)", data: ev.map(p => ({ x: p.epoch, y: p.loss })), borderColor: "#ff9f43", backgroundColor: "#ff9f43", borderDash: [5, 4],
        pointRadius: ev.map(p => p === bestEpoch ? 8 : 4), pointStyle: ev.map(p => p === bestEpoch ? "star" : "circle"), borderWidth: 2 }] },
    options: { maintainAspectRatio: false, parsing: false, scales: { x: { type: "linear", min: 0, max: Math.ceil(Math.max(...tr.map(p => p.epoch), 1)), title: { display: true, text: "Epoch" } },
      y: { type: "logarithmic", title: { display: true, text: "Cross-entropy loss (log)" }, ticks: { callback: v => { const l = Math.log10(v); return Math.abs(l - Math.round(l)) < 1e-9 ? "10" + String(Math.round(l)).split("").map(ch => "⁻⁰¹²³⁴⁵⁶⁷⁸⁹"["-0123456789".indexOf(ch)]).join("") : ""; } } } }, plugins: { legend: { position: "bottom" } } } });
  chart("st-prf", { type: "bar", data: { labels: CLASSES, datasets: [["precision", "#4f8cff", "Precision"], ["recall", "#ff9f43", "Recall"], ["f1", "#3ecf8e", "F1-score"]].map(([k, c, l]) => ({ label: l, data: CLASSES.map(x => pc[x]?.[k]), backgroundColor: c })) },
    options: { maintainAspectRatio: false, scales: { y: { min: 0, max: 1.05 } }, plugins: { legend: { position: "bottom" } } } });
  const pb = () => {
    const q = S.predQ, needle = q.q.trim().toUpperCase();
    const rows = m.predictions.map((p, i) => ({ ...p, i: i + 1 })).filter(p => (!needle || p.utr.includes(needle)) && (!q.cls || p.true_class === q.cls) && (!q.errors || p.true_class !== p.predicted_class));
    const per = 15, pages = Math.max(1, Math.ceil(rows.length / per)); q.page = Math.min(q.page, pages - 1);
    $("#pb-n").textContent = `${rows.length.toLocaleString()} rows`;
    $("#pb-range").textContent = `page ${q.page + 1} / ${pages}`;
    $("#pb-body").innerHTML = rows.slice(q.page * per, q.page * per + per).map(p => `<tr class="${p.true_class !== p.predicted_class ? "bad" : ""}"><td class="dim mono">${p.i}</td><td class="mono small">${esc(p.utr)}</td><td>${clsBadge(p.true_class)}</td><td>${clsBadge(p.predicted_class)}</td>
      <td><a class="small" href="#/inspector?utr=${encodeURIComponent(p.utr)}">explain ›</a></td></tr>`).join("");
  };
  $("#pb-q").oninput = e => { S.predQ.q = e.target.value; S.predQ.page = 0; pb(); };
  $("#pb-c").onchange = e => { S.predQ.cls = e.target.value; S.predQ.page = 0; pb(); };
  $("#pb-e").onchange = e => { S.predQ.errors = e.target.checked; S.predQ.page = 0; pb(); };
  $("#pb-prev").onclick = () => { S.predQ.page = Math.max(0, S.predQ.page - 1); pb(); };
  $("#pb-next").onclick = () => { S.predQ.page++; pb(); };
  pb();
}
function confusionHTML(c) {
  const max = Math.max(...c.matrix.flat());
  return `<div class="scroll"><table class="heat"><tr><th></th>${c.labels.map(l => `<th style="font-size:10px">${l.replace("_", " ")}</th>`).join("")}</tr>
    ${c.matrix.map((row, i) => `<tr><th class="rl">${clsBadge(c.labels[i])}</th>${row.map((v, j) => {
      const bg = i === j ? `rgba(79,140,255,${.12 + .8 * v / max})` : v ? `rgba(255,84,104,${.25 + .6 * v / max})` : "rgba(34,48,82,.35)";
      return `<td style="background:${bg};color:${v / max > .5 || (i !== j && v) ? "#fff" : "#8d99b6"};font-size:14px;padding:12px 4px;font-weight:${v ? 700 : 400}">${v}</td>`;
    }).join("")}</tr>`).join("")}</table></div>`;
}

// ================================================================== SYSTEM & TESTS
async function system() {
  if (!S.status) await pollStatus();
  const st = S.status || {};
  $("#view").innerHTML = `
  <div class="card mb"><h3>ERIS architecture</h3>
    <div class="arch">
      <div class="stage"><h4>CICIoV2024 CAN traffic</h4><ul><li>6 hexadecimal CSV files</li><li>1.41 M rows, 3,588 unique frames</li><li>2019 Ford, DoS + 4 spoofing attacks</li></ul></div><div class="to">→</div>
      <div class="stage"><span class="ok">● ACTIVE</span><h4>Stage 1 · Classification</h4><ul><li>Hex normalisation, drop DLC / Interface</li><li>Frame → text (UTR)</li><li>Pattern-level split · hex tokenizer</li><li>T5 encoder-decoder generates the label</li></ul></div><div class="to">→</div>
      <div class="stage"><span class="ok">● ACTIVE</span><h4>Stage 2 · Explainability</h4><ul><li>Occlusion &amp; Integrated Gradients</li><li>Cross-attention</li><li>Counterfactual &amp; prototype</li><li>Plain-language rationale</li></ul></div><div class="to">→</div>
      <div class="stage"><span class="ok" style="color:var(--warn)">● PREVIEW</span><h4>Stage 3 · Risk assessment</h4><ul><li>Affected vehicle function</li><li>Impact × feasibility (ISO/SAE 21434)</li><li>Confidence &amp; burst escalation</li></ul></div><div class="to">→</div>
      <div class="stage"><span class="ok">● ACTIVE</span><h4>Analyst console</h4><ul><li>Live alerts &amp; incidents</li><li>Triage workflow &amp; audit trail</li><li>Label + explanation + severity</li></ul></div>
    </div></div>
  <div class="card mb"><h3>Leak-free evaluation protocol</h3>
    <div class="grid" style="grid-template-columns:repeat(auto-fit,minmax(220px,1fr))">
      <div class="method"><b><span class="num">1</span>Formatting leaks removed</b><span class="small muted">The DoS file has no DLC column and spoofing files write unpadded bytes. All IDs and bytes become fixed-width hex; constant fields are dropped.</span></div>
      <div class="method"><b><span class="num">2</span>Split by unique frame</b><span class="small muted">Train, validation and test are drawn from disjoint sets of frame patterns, so every test frame is new to the model.</span></div>
      <div class="method"><b><span class="num">3</span>Validation-only selection</b><span class="small muted">The checkpoint with the lowest validation loss is kept; the test set is touched only once, at the end.</span></div>
      <div class="method"><b><span class="num">4</span>Row + pattern metrics, reload check</b><span class="small muted">Pattern-level accuracy counts each independent decision once; the saved model must reproduce its predictions.</span></div>
    </div></div>
  <div class="card mb"><h3>Test cases <span class="grow"></span><span class="small dim">Table 5.5</span><button class="btn primary sm" id="run-tests">▶ Run checks</button></h3>
    <div class="desc">“Live” checks execute now against the running system; the others are verified from the saved training run.</div>
    <div class="scroll"><table class="tbl"><thead><tr><th>ID</th><th>Test</th><th>Expected</th><th>Actual</th><th>Source</th><th>Status</th></tr></thead><tbody id="t-body"><tr><td colspan="6"><div class="empty">Press “Run checks”</div></td></tr></tbody></table></div>
    <div class="small" id="t-sum" style="margin-top:8px"></div></div>
  <div class="grid g2">
    <div class="card"><h3>Runtime</h3>
      ${[["Mode", st.mode], ["Model", st.model_dir || "–"], ["Parameters", st.params_m ? st.params_m + " M" : "–"], ["Vocabulary", st.vocab ? st.vocab.toLocaleString() + " tokens" : "–"],
        ["Explanation reference set", st.reference || "–"], ["Reported run available", st.runs?.reported ? "yes (results/)" : "no"], ["Live re-run available", st.runs?.live ? "yes (results_live/)" : "no"]]
        .map(([k, v]) => `<div class="stat-line"><span class="muted">${k}</span><span class="mono small">${esc(v)}</span></div>`).join("")}
      ${st.error ? `<div class="banner" style="margin-top:10px">${esc(st.error)}</div>` : ""}</div>
    <div class="card"><h3>Demo controls</h3>
      <div class="desc">Reset clears all alerts, incidents and notes (for a fresh demonstration).</div>
      <div class="btns"><button class="btn danger" id="reset">Reset alert database</button><a class="btn" href="/api/export?format=json">⤓ Export report</a></div></div>
  </div>`;
  $("#run-tests").onclick = runTests;
  $("#reset").onclick = async () => { if (!confirm("Delete all alerts, incidents and notes?")) return; await api("/api/reset", { method: "POST" }); S.seenInc.clear(); toast("Alert database reset", "All alerts and incidents cleared", "Low"); };
}
async function runTests() {
  const b = $("#run-tests"); b.disabled = true; b.innerHTML = `<span class="spin"></span> Running…`;
  try {
    const r = await api("/api/selftest", { method: "POST" });
    $("#t-body").innerHTML = r.tests.map(t => `<tr><td class="mono"><b>${t.id}</b></td><td>${esc(t.name)}</td><td class="small">${esc(t.expected)}</td><td class="mono small">${esc(t.actual)}</td>
      <td>${t.live ? `<span class="tag" style="color:var(--ok);background:rgba(62,207,142,.14)">live</span>` : `<span class="tag" style="color:var(--muted);background:rgba(141,153,182,.14)">saved run</span>`}</td>
      <td class="test-${t.status}">${t.status === "pass" ? "✓ Pass" : t.status === "fail" ? "✗ Fail" : "See Ch. 7"}</td></tr>`).join("");
    $("#t-sum").innerHTML = `<b class="test-pass">${r.passed} passed</b> · ${r.tests.filter(t => t.status === "fail").length} failed · ${r.tests.filter(t => t.status === "info").length} informational`;
  } finally { b.disabled = false; b.innerHTML = "▶ Run checks"; }
}

// ------------------------------------------------------------------ boot
pollStatus(); setInterval(pollStatus, 4000);
api("/api/stats").then(setStats);
connect();
route();
