"use strict";
/* TRACE console.
 *
 * Talks only to the local FastAPI server — no network access, no CDN.
 * Chart colours come from a validated palette (see docs/decisions.md): series
 * slots are fixed and never cycled, and every status colour ships beside a
 * text label so nothing is carried by hue alone.
 */

const $ = (id) => document.getElementById(id);
const REFRESH_MS = 1000;          // live poll; the server answers with a delta
const HEALTH_MS = 4000;
const EXPLAIN_DEBOUNCE = 140;

const S = {
  meta: null, A: null, aid: null, host: null, cursor: 0,
  mode: "analyst", ex: null, exKey: null, exTimer: null, exAbort: null,
  charts: {}, bench: null, enforce: null,
  replaying: false, replayTimer: null,
  liveTimer: null, liveBusy: false, needFull: true, healthTimer: null,
  online: true, action: null, coneCache: {},
};

const STAGES = {
  1: { name: "Reconnaissance", short: "Recon", tac: "TA0043", tech: "T1595 Active Scanning · T1046 Network Service Discovery", v: "--st1" },
  2: { name: "Initial Access", short: "Access", tac: "TA0001", tech: "T1110 Brute Force · T1190 Exploit Public-Facing App · T1566 Phishing", v: "--st2" },
  3: { name: "Lateral Movement", short: "Lateral", tac: "TA0008", tech: "T1021 Remote Services — SMB, RDP, SSH, WinRM", v: "--st3" },
  4: { name: "Command & Control", short: "C2", tac: "TA0011", tech: "T1071 Application Layer Protocol · T1573 Encrypted Channel", v: "--st4" },
  5: { name: "Exfiltration", short: "Exfil", tac: "TA0010", tech: "T1048 Exfiltration Over Alternative Protocol · T1041", v: "--st5" },
  6: { name: "Impact", short: "Impact", tac: "TA0040", tech: "T1498 / T1499 Denial of Service", v: "--st6" },
};

/* ── small helpers ─────────────────────────────────────────────────── */

const css = (v) => getComputedStyle(document.documentElement).getPropertyValue(v).trim();
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const pct = (p) => (p == null || Number.isNaN(p) ? "–" : `${Math.round(p * 100)}%`);
const clamp = (v, lo, hi) => Math.max(lo, Math.min(hi, v));

function alpha(color, a) {
  const h = String(color).trim().replace("#", "");
  if (!/^[0-9a-f]{3,8}$/i.test(h)) return color;
  const n = parseInt(h.length === 3 ? h.split("").map((c) => c + c).join("") : h.slice(0, 6), 16);
  return `rgba(${(n >> 16) & 255},${(n >> 8) & 255},${n & 255},${a})`;
}

function fmtBytes(b) {
  if (b == null) return "–";
  if (b >= 1e9) return `${(b / 1e9).toFixed(1)} GB`;
  if (b >= 1e6) return `${(b / 1e6).toFixed(1)} MB`;
  if (b >= 1e3) return `${(b / 1e3).toFixed(1)} kB`;
  return `${b} B`;
}
const fmtMin = (m) => (m == null ? "–" : m >= 1 ? `${(+m.toFixed(1))} min` : `${Math.round(m * 60)} s`);
const minutes = (w) => (w * (S.A ? S.A.window_s : 30)) / 60;

function clock(i) {
  if (!S.A) return "";
  const ms = S.A.t0 + i * S.A.window_s * 1000;
  const utc = /CIC/.test(S.A.dataset || "");
  return new Date(ms).toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit", timeZone: utc ? "UTC" : undefined });
}

// Risk bands start at the model's own alarm threshold: the forecast is a
// calibrated probability, so the threshold is where "act" begins.
function band(p) {
  const thr = S.A ? S.A.threshold : 0.4;
  if (p == null) return { key: "low", label: "–", v: "--muted" };
  if (p < thr) return { key: "low", label: "Low", v: "--good" };
  if (p < 0.5) return { key: "medium", label: "Medium", v: "--warning" };
  if (p < 0.85) return { key: "high", label: "High", v: "--serious" };
  return { key: "critical", label: "Critical", v: "--critical" };
}
const statusChip = (p) => { const b = band(p); return `<span class="status ${b.key}"><i class="ico"></i>${b.label}</span>`; };

/* ── networking ────────────────────────────────────────────────────── */

async function api(path, opts = {}, timeoutMs = 120000) {
  const ac = new AbortController();
  const timer = setTimeout(() => ac.abort(), timeoutMs);
  try {
    const r = await fetch(path, { ...opts, signal: ac.signal });
    if (!r.ok) {
      const body = await r.text().catch(() => "");
      throw new Error(`${r.status} ${r.statusText}${body ? `: ${body.slice(0, 200)}` : ""}`);
    }
    setOnline(true);
    return await r.json();
  } catch (e) {
    if (e.name === "AbortError") throw new Error("the server took too long to answer");
    if (e instanceof TypeError) setOnline(false);   // network-level failure
    throw e;
  } finally {
    clearTimeout(timer);
  }
}

function setOnline(ok) {
  if (S.online === ok) return;
  S.online = ok;
  const el = $("conn");
  el.classList.toggle("off", !ok);
  $("connText").textContent = ok ? "connected" : "server unreachable";
  if (!ok) toast("Lost contact with the TRACE server — retrying.", true);
}

function toast(msg, bad = false) {
  const t = $("toast");
  t.textContent = msg;
  t.className = `toast${bad ? " bad" : ""}`;
  clearTimeout(toast.h);
  toast.h = setTimeout(() => t.classList.add("hidden"), bad ? 6000 : 3600);
}
function loading(on, text) {
  $("loading").classList.toggle("hidden", !on);
  if (text) $("loadingText").textContent = text;
}

/* ── charts ────────────────────────────────────────────────────────── */

function chart(id) {
  const el = $(id);
  if (!el) return null;
  if (!S.charts[id] || S.charts[id].isDisposed()) S.charts[id] = echarts.init(el, null, { renderer: "canvas" });
  return S.charts[id];
}
function paint(id, option) {
  const ch = chart(id);
  if (!ch) return;
  ch.setOption(option, { replaceMerge: ["series", "xAxis", "yAxis", "legend", "grid"] });
}
function disposeCharts(prefix) {
  for (const k of Object.keys(S.charts)) {
    if (k.startsWith(prefix)) { S.charts[k].dispose(); delete S.charts[k]; }
  }
}
window.addEventListener("resize", () => Object.values(S.charts).forEach((c) => !c.isDisposed() && c.resize()));

// Shared chart chrome, so every plot reads as one system.
function axisBase() {
  return {
    axisLine: { lineStyle: { color: css("--rule") } },
    axisTick: { show: false },
    axisLabel: { color: css("--muted"), fontSize: 11 },
    splitLine: { lineStyle: { color: css("--grid"), type: "solid" } },
  };
}
function tooltipBase(extra = {}) {
  return {
    backgroundColor: css("--surface"),
    borderColor: css("--border"),
    borderWidth: 1,
    padding: [7, 10],
    textStyle: { color: css("--ink"), fontSize: 12 },
    extraCssText: "box-shadow:0 4px 14px rgba(0,0,0,.12); border-radius:8px;",
    ...extra,
  };
}

/* ── selection helpers ─────────────────────────────────────────────── */

const hostObj = () => (S.A && S.A.hosts.find((h) => h.host === S.host)) || (S.A && S.A.hosts[0]) || null;

// Local window index for a host at the global cursor, or null when that host
// had no window then. Returning null (rather than clamping) is what stops a
// host that stopped reporting from showing a stale value as if it were current.
function localT(h, c = S.cursor) {
  if (!h) return null;
  const t = c - h.off;
  return t < 0 || t >= h.T ? null : t;
}
function lastT(h) { return h && h.T ? h.T - 1 : null; }

function argmax(a) { let k = 0; for (let i = 1; i < a.length; i++) if (a[i] > a[k]) k = i; return k; }
function nowStage(h, t) {
  const row = h.now && h.now[t];
  if (!row) return 0;
  const s = argmax(row);
  return s > 0 && row[s] >= 0.5 ? s : 0;
}
function nextStage(h, t) {
  const now = nowStage(h, t), row = h.stage_max && h.stage_max[t];
  if (!row) return 0;
  let best = 0;
  for (let s = 1; s <= 6; s++) if (s !== now && (best === 0 || row[s] > row[best])) best = s;
  return best;
}

/* ── boot ──────────────────────────────────────────────────────────── */

async function init() {
  const saved = (() => { try { return localStorage.getItem("trace-theme"); } catch { return null; } })();
  if (saved) document.documentElement.setAttribute("data-theme", saved);

  bind();
  try {
    S.meta = await api("/api/meta", {}, 30000);
  } catch (e) {
    loading(false);
    return toast(`Cannot reach the TRACE server: ${e.message}`, true);
  }
  fillScenarios();
  renderEnforce(S.meta.enforcement);
  refreshLedgerBadge();
  renderHow();
  await load(S.meta.scenarios[0] ? S.meta.scenarios[0].id : "live");
  S.healthTimer = setInterval(health, HEALTH_MS);
}

async function health() {
  try { await api("/api/health", {}, 8000); } catch { /* setOnline already handled it */ }
}

function fillScenarios(select) {
  const opts = [`<option value="live">● Live capture (sensor)</option>`]
    .concat(S.meta.scenarios.map((s) => `<option value="${esc(s.id)}">${esc(s.name)}</option>`));
  $("scenario").innerHTML = opts.join("");
  if (select) $("scenario").value = select;
}

/* ── loading a capture ─────────────────────────────────────────────── */

async function load(aid) {
  stopReplay();
  stopLive();
  S.ex = null; S.exKey = null; S.action = null; S.coneCache = {};
  if (aid === "live") return startLive();

  const sc = (S.meta.scenarios || []).find((s) => s.id === aid);
  loading(true, sc && sc.kind === "csv"
    ? "Analysing a full day of real traffic — the first run takes about half a minute…"
    : "Extracting features and rolling the world model forward…");
  let d;
  try {
    d = await api(`/api/analysis/${encodeURIComponent(aid)}`);
  } catch (e) {
    loading(false);
    return toast(`Could not load that capture: ${e.message}`, true);
  }
  loading(false);
  S.aid = aid;
  S.A = d;
  $("scenario").value = aid;
  if (d.detail && d.hosts.length) S.coneCache[d.detail] = d.hosts.find((h) => h.host === d.detail).cone;

  // Open where the story is: the host that alarmed first, just after it alarmed.
  const first = d.hosts.filter((h) => h.first_alarm != null)
    .sort((a, b) => (a.off + a.first_alarm) - (b.off + b.first_alarm))[0];
  S.host = first ? first.host : d.hosts.length ? d.hosts[0].host : null;
  S.cursor = first ? clamp(first.off + first.first_alarm + 2, 0, d.T - 1) : d.T - 1;

  $("scrub").max = Math.max(0, d.T - 1);
  $("scrub").value = S.cursor;
  $("playBtn").disabled = false;
  await ensureCone(S.host);
  renderAll();
  scheduleExplain(0);
}

// The forecast cone is the biggest field in the payload, so the server sends
// one host's and the rest are fetched when the analyst selects them.
async function ensureCone(host) {
  if (!host || !S.A) return;
  const h = S.A.hosts.find((x) => x.host === host);
  if (!h || (h.cone && h.cone.length)) return;
  if (S.coneCache[host]) { h.cone = S.coneCache[host]; return; }
  try {
    const r = await api(`/api/cone/${encodeURIComponent(S.aid)}/${encodeURIComponent(host)}`, {}, 30000);
    S.coneCache[host] = r.cone;
    h.cone = r.cone;
  } catch { /* the cone is an embellishment; the forecast line still renders */ }
}

/* ── live mode ─────────────────────────────────────────────────────── */

function stopLive() {
  clearInterval(S.liveTimer);
  S.liveTimer = null;
  S.needFull = true;
  $("liveStatus").classList.add("hidden");
}

async function startLive() {
  S.aid = "live";
  S.A = null;            // drop the batch view so the first poll lands on the live edge
  $("scenario").value = "live";
  $("playBtn").disabled = true;
  loading(true, "Connecting to the live sensor…");
  await pollLive();
  loading(false);
  S.liveTimer = setInterval(pollLive, REFRESH_MS);
}

async function pollLive() {
  if (S.liveBusy) return;                 // never let polls pile up
  S.liveBusy = true;
  try {
    const atEdge = !S.A || S.A.T === 0 || S.cursor >= S.A.T - 1;
    const since = S.needFull || !S.A ? null : S.A.T;
    const q = new URLSearchParams();
    if (since != null) q.set("since", String(since));
    if (S.host) q.set("detail", S.host);
    const d = await api(`/api/live/state?${q}`, {}, 25000);
    const ok = mergeLive(d);
    S.needFull = !ok;
    if (!S.A || !S.A.hosts.length) { renderEmptyLive(); return; }
    if (!S.A.hosts.some((h) => h.host === S.host)) S.host = S.A.hosts[0].host;
    if (atEdge) S.cursor = S.A.T - 1;     // follow the edge unless scrubbed back
    S.cursor = clamp(S.cursor, 0, S.A.T - 1);
    $("scrub").max = Math.max(0, S.A.T - 1);
    $("scrub").value = S.cursor;
    renderAll();
    renderLiveStatus();
    scheduleExplain(atEdge ? 250 : EXPLAIN_DEBOUNCE);
  } catch (e) {
    S.needFull = true;
    renderLiveStatus();
  } finally {
    S.liveBusy = false;
  }
}

// Append a delta onto what we already hold. Anything that does not line up
// exactly (a host's history rotated out, a host appeared or vanished) asks for
// a full refresh next tick rather than silently stitching wrong data together.
function mergeLive(d) {
  if (d.full || !S.A || S.A.id !== "live") {
    S.A = d;
    for (const h of d.hosts) h.from = h.off;
    return true;
  }
  const byName = new Map(S.A.hosts.map((h) => [h.host, h]));
  for (const inc of d.hosts) {
    const cur = byName.get(inc.host);
    if (!cur || cur.off !== inc.off) return false;
    const at = inc.from - inc.off;
    if (at > cur.p.length) return false;              // a gap: refuse to guess
    for (const key of ["p", "stage_max", "eta", "now", "surprise", "present"]) {
      if (!Array.isArray(inc[key])) continue;
      cur[key].length = at;
      for (const v of inc[key]) cur[key].push(v);
    }
    if (inc.cone && inc.cone.length) { cur.cone = cur.cone || []; cur.cone.length = at; for (const v of inc.cone) cur.cone.push(v); }
    cur.T = inc.T; cur.peak = inc.peak; cur.first_alarm = inc.first_alarm; cur.role = inc.role;
  }
  if (d.hosts.length !== S.A.hosts.length) return false;
  S.A.hosts.sort((a, b) => (b.p[b.p.length - 1] ?? 0) - (a.p[a.p.length - 1] ?? 0));
  Object.assign(S.A, {
    T: d.T, network: d.network, events: d.events, sensors: d.sensors, batches: d.batches,
    lag_rows: d.lag_rows, windows_done: d.windows_done, threshold: d.threshold, t0: d.t0,
  });
  return true;
}

function renderEmptyLive() {
  $("hostList").innerHTML = `<div class="empty">No windows yet.<br><span class="small">Start a sensor:<br><code class="mono">trace-sensor -iface eth0 -server http://127.0.0.1:8000</code></span></div>`;
  $("tlSub").textContent = "Waiting for a sensor to report its first window.";
  $("kpiSrcK").textContent = "Sensor";
  $("kpiSrc").textContent = "waiting";
  renderLiveStatus();
}

function renderLiveStatus() {
  const el = $("liveStatus");
  if (S.aid !== "live") return el.classList.add("hidden");
  el.classList.remove("hidden");
  const s = (S.A && S.A.sensors || [])[0];
  const age = s ? Date.now() / 1000 - s.last_seen : Infinity;
  const stale = !S.online || age > 12;
  el.className = `conn${stale ? " off" : ""}`;
  $("liveText").textContent = !S.online ? "disconnected"
    : stale ? `sensor quiet ${Number.isFinite(age) ? Math.round(age) + "s" : ""}`
    : `live${S.A.lag_rows ? ` · ${S.A.lag_rows} queued` : ""}`;
}

/* ── rendering ─────────────────────────────────────────────────────── */

function renderAll() {
  if (!S.A || !S.A.hosts.length) return;
  renderKpis();
  renderHosts();
  renderTimeline();
  renderKillchain();
  renderScrubOut();
}

function renderScrubOut() {
  const h = hostObj(), t = localT(h);
  $("scrubOut").textContent = `${clock(S.cursor)}  ·  ${S.cursor + 1}/${S.A.T}${t == null ? "  (no data)" : ""}`;
}

function renderKpis() {
  const A = S.A;
  const p = A.network.p[clamp(S.cursor, 0, A.T - 1)] ?? 0;
  const b = band(p);
  $("kpiRisk").textContent = pct(p);
  $("kpiRisk").style.color = css(b.v);
  $("kpiRiskBand").innerHTML = `${statusChip(p)} <span class="muted">— highest of any host, next 5 min</span>`;

  const above = A.hosts.filter((h) => { const t = localT(h); return t != null && h.p[t] >= A.threshold; });
  $("kpiHosts").textContent = String(above.length);
  $("kpiHosts").style.color = above.length ? css("--serious") : css("--ink");
  $("kpiHostsSub").textContent = `of ${A.hosts.length} internal hosts · alarm at ${pct(A.threshold)}`;

  const ev = A.events || {};
  if (ev.lead_min != null) {
    $("kpiLead").textContent = fmtMin(ev.lead_min);
    $("kpiLead").style.color = css("--good");
    $("kpiLeadSub").textContent = "warning before the first compromise";
  } else if (ev.alarm != null) {
    $("kpiLead").textContent = clock(ev.alarm);
    $("kpiLead").style.color = css("--ink");
    $("kpiLeadSub").textContent = A.truth_known ? "first alarm — no compromise recorded" : "first alarm raised";
  } else {
    $("kpiLead").textContent = "none";
    $("kpiLead").style.color = css("--good");
    $("kpiLeadSub").textContent = "no host crossed the threshold";
  }

  const ex = A.extraction || {};
  if (S.aid === "live") {
    const s = (A.sensors || [])[0] || {};
    $("kpiSrcK").textContent = "Sensor";
    $("kpiSrc").textContent = s.name ? String(s.name).split(":").pop() : "—";
    $("kpiSrcSub").textContent = `${(s.packets || 0).toLocaleString()} packets · ${s.active_flows || 0} active flows · ${A.windows_done || 0} windows`;
  } else {
    $("kpiSrcK").textContent = "Capture";
    $("kpiSrc").textContent = ex.packets_processed ? `${(ex.packets_processed / 1000).toFixed(0)}k packets` : ex.flows ? `${(ex.flows / 1000).toFixed(0)}k flows` : "—";
    $("kpiSrcSub").textContent = ex.packets_per_second
      ? `extracted at ${Math.round(ex.packets_per_second).toLocaleString()} packets/s`
      : A.packet_level ? "both feature levels" : "flow-level features only";
  }
  $("tlSub").textContent = [A.description, A.dataset].filter(Boolean).join(" · ");
  $("hostCount").textContent = `${A.hosts.length} shown`;
  $("otherAddr").textContent = (A.other_addresses || []).length
    ? `${A.other_addresses.length} further addresses appeared only briefly (scan targets, broadcast).` : "";
  $("legLR").classList.toggle("hidden", !(hostObj() && hostObj().lr));
  $("legTruth").classList.toggle("hidden", !A.truth_known);
}

function sparkline(p, upto) {
  const n = clamp(upto + 1, 1, p.length);
  const step = Math.max(1, Math.floor(n / 48));
  const pts = [];
  for (let i = 0; i < n; i += step) pts.push(p[i]);
  if (pts.length < 2) pts.push(pts[0] ?? 0);
  const w = 232, hh = 14;
  const d = pts.map((v, i) => `${i ? "L" : "M"}${((i / (pts.length - 1)) * w).toFixed(1)},${(hh - clamp(v, 0, 1) * hh).toFixed(1)}`).join(" ");
  return `<svg class="spark" width="100%" height="${hh}" viewBox="0 0 ${w} ${hh}" preserveAspectRatio="none" aria-hidden="true">
    <path d="${d}" fill="none" stroke="${css("--s1")}" stroke-width="1.4" vector-effect="non-scaling-stroke"/></svg>`;
}

function renderHosts() {
  const html = S.A.hosts.map((h) => {
    const t = localT(h);
    const p = t == null ? null : h.p[t];
    const b = band(p);
    const stage = t == null ? 0 : (h.truth ? h.truth[t] : 0) || nowStage(h, t);
    const chip = stage ? `<span class="chip${h.truth && h.truth[t] ? "" : " ghost"}" style="${h.truth && h.truth[t] ? `background:${css(STAGES[stage].v)}` : `color:${css(STAGES[stage].v)}`}">${STAGES[stage].short}</span>` : "";
    return `<div class="host" role="option" tabindex="0" data-host="${esc(h.host)}" aria-selected="${h.host === S.host}">
      <span class="ico" style="background:${css(b.v)}"></span>
      <span class="ip">${esc(h.host)}</span>
      <span class="pct" style="color:${p != null && p >= S.A.threshold ? css(b.v) : "inherit"}">${pct(p)}</span>
      <span class="meta"><span class="role">${esc(h.role)}</span>${chip}</span>
      ${t == null ? "" : sparkline(h.p, t)}</div>`;
  }).join("");
  const list = $("hostList");
  // Rebuilding wholesale on every live tick would drop scroll position; only
  // touch the DOM when the markup actually changed.
  if (list.dataset.sig !== html) { list.innerHTML = html; list.dataset.sig = html; }
}

function runs(arr) {
  const out = [];
  let a = null;
  for (let i = 0; i <= arr.length; i++) {
    const v = i < arr.length ? arr[i] : 0;
    if (a !== null && (v !== arr[a] || i === arr.length)) { if (arr[a] > 0) out.push([a, i - 1, arr[a]]); a = null; }
    if (a === null && i < arr.length && v > 0) a = i;
  }
  return out;
}

function renderTimeline() {
  const A = S.A, h = hostObj(), c = S.cursor, K = A.k;
  if (!h) return;
  const n = A.T + K;
  const cats = Array.from({ length: n }, (_, i) => i);
  const visible = (i) => !S.replaying || i <= c;
  const series = (arr) => cats.map((i) => {
    const t = i - h.off;
    return t >= 0 && t < h.T && arr && arr[t] != null && visible(i) ? arr[t] : null;
  });
  const t = localT(h);
  const s1 = css("--s1"), s2 = css("--s2"), ink = css("--ink"), muted = css("--muted");

  // forecast cone, anchored at the cursor
  const low = new Array(n).fill(null), bandv = new Array(n).fill(null), med = new Array(n).fill(null);
  if (t != null && h.cone && h.cone[t]) {
    low[c] = h.p[t]; bandv[c] = 0; med[c] = h.p[t];
    for (let j = 0; j < K && c + 1 + j < n; j++) {
      const q = h.cone[t][j];
      if (!q) break;
      low[c + 1 + j] = q[0];
      bandv[c + 1 + j] = Math.max(0, q[2] - q[0]);
      med[c + 1 + j] = q[1];
    }
  }

  // Ground-truth stage bands are a neutral wash with the stage named on them:
  // the series colours already own blue and orange on this plot.
  const areas = [];
  if (h.truth) {
    for (const [a, b, st] of runs(h.truth)) {
      if (S.replaying && a + h.off > c) continue;
      areas.push([
        { xAxis: a + h.off, name: STAGES[st].short, itemStyle: { color: alpha(css("--ink"), 0.055) },
          label: { color: css("--ink-2"), fontWeight: 600, fontSize: 10, position: "insideTop" } },
        { xAxis: Math.min(b + h.off, S.replaying ? c : b + h.off) },
      ]);
    }
  }

  const marks = [];
  if (h.first_alarm != null && visible(h.off + h.first_alarm)) {
    marks.push({ coord: [h.off + h.first_alarm, h.p[h.first_alarm]], value: "alarm",
      itemStyle: { color: css("--critical"), borderColor: css("--surface"), borderWidth: 2 } });
  }
  if (h.first_inf != null && visible(h.off + h.first_inf)) {
    marks.push({ coord: [h.off + h.first_inf, 1], value: "compromise",
      itemStyle: { color: ink, borderColor: css("--surface"), borderWidth: 2 } });
  }

  paint("timeline", {
    animation: false,
    grid: { left: 52, right: 20, top: 18, bottom: 34 },
    tooltip: {
      ...tooltipBase(), trigger: "axis",
      axisPointer: { type: "line", lineStyle: { color: css("--rule"), width: 1 } },
      formatter: (ps) => {
        if (!ps.length) return "";
        const i = +ps[0].axisValue;
        const rows = ps.filter((r) => r.value != null && r.seriesName && !r.seriesName.startsWith("_"))
          .map((r) => `<div style="display:flex;gap:8px;justify-content:space-between"><span>${r.marker} ${esc(r.seriesName)}</span><b>${pct(r.value)}</b></div>`);
        return `<b>${clock(i)}</b>${rows.join("")}`;
      },
    },
    xAxis: { ...axisBase(), type: "category", data: cats, boundaryGap: false,
      axisLabel: { ...axisBase().axisLabel, formatter: (i) => clock(+i), hideOverlap: true }, splitLine: { show: false } },
    yAxis: { ...axisBase(), type: "value", min: 0, max: 1, axisLabel: { ...axisBase().axisLabel, formatter: (v) => `${Math.round(v * 100)}%` } },
    series: [
      { name: "TRACE", type: "line", data: series(h.p), showSymbol: false, smooth: 0.12, z: 6,
        lineStyle: { width: 2, color: s1 }, itemStyle: { color: s1 },
        areaStyle: { color: alpha(s1, 0.07) },
        markLine: { symbol: "none", silent: true, animation: false, data: [
          { yAxis: A.threshold, lineStyle: { color: css("--critical"), width: 1, type: [5, 4] },
            label: { formatter: "alarm threshold", color: css("--critical"), fontSize: 10, position: "insideEndTop" } },
          ...(S.cursor < A.T - 1 || S.replaying || S.aid === "live"
            ? [{ xAxis: c, lineStyle: { color: ink, width: 1 }, label: { formatter: "now", color: ink, fontSize: 10 } }] : []),
        ] },
        markArea: { silent: true, animation: false, data: areas },
        markPoint: { symbol: "circle", symbolSize: 9, animation: false,
          label: { show: true, position: "top", fontSize: 10, fontWeight: 600, color: ink, formatter: (d) => d.value }, data: marks } },
      ...(h.lr ? [{ name: "Logistic regression", type: "line", data: series(h.lr), showSymbol: false,
        lineStyle: { width: 1.5, type: [5, 4], color: s2 }, itemStyle: { color: s2 } }] : []),
      { name: "_conelow", type: "line", data: low, stack: "cone", showSymbol: false, lineStyle: { opacity: 0 }, silent: true, tooltip: { show: false } },
      { name: "_coneband", type: "line", data: bandv, stack: "cone", showSymbol: false, lineStyle: { opacity: 0 },
        areaStyle: { color: alpha(s1, 0.20) }, silent: true, tooltip: { show: false } },
      { name: "Forecast (median)", type: "line", data: med, showSymbol: false,
        lineStyle: { type: "dotted", width: 2, color: s1 }, itemStyle: { color: s1 } },
    ],
  });

  $("tlTitle").textContent = `${h.host} — ${h.role}`;
  renderLead(h);
}

function renderLead(h) {
  const el = $("leadBanner"), c = S.cursor;
  const seen = (i) => !S.replaying || c >= h.off + i;
  if (h.first_inf != null && seen(h.first_inf)) {
    const lrFirst = h.lr ? h.lr.findIndex((v) => v >= S.A.lr_threshold) : -1;
    let lrTxt = "";
    if (h.lr) {
      lrTxt = lrFirst < 0 ? " Logistic regression never crossed its own threshold."
        : lrFirst < h.first_inf ? ` Logistic regression warned ${fmtMin(minutes(h.first_inf - lrFirst))} early.`
        : ` Logistic regression only crossed ${fmtMin(minutes(lrFirst - h.first_inf))} after the compromise.`;
    }
    if (h.first_alarm != null && h.first_alarm < h.first_inf) {
      el.className = "callout win";
      el.innerHTML = `TRACE warned <b>${fmtMin(minutes(h.first_inf - h.first_alarm))}</b> before this host was compromised — alarm at <b>${clock(h.off + h.first_alarm)}</b>, compromise at <b>${clock(h.off + h.first_inf)}</b>.${esc(lrTxt)}`;
    } else {
      el.className = "callout warn";
      el.innerHTML = `No early warning on this host: the compromise arrived with no precursor the model could see.${esc(lrTxt)}`;
    }
  } else if (h.first_alarm != null && seen(h.first_alarm)) {
    el.className = "callout info";
    el.innerHTML = `Alarm at <b>${clock(h.off + h.first_alarm)}</b> — the forecast crossed the ${pct(S.A.threshold)} threshold.`;
  } else {
    el.className = "callout hidden";
  }
}

function renderKillchain() {
  const h = hostObj(), t = localT(h);
  const box = $("killchain");
  if (t == null) {
    box.innerHTML = `<div class="empty" style="grid-column:1/-1">This host had no traffic in the selected window.</div>`;
    $("nextStage").textContent = "";
    $("surpriseRow").innerHTML = "";
    return;
  }
  const now = nowStage(h, t), nxt = nextStage(h, t);
  box.innerHTML = [1, 2, 3, 4, 5, 6].map((s) => {
    const st = STAGES[s], col = css(st.v), p = h.stage_max[t][s], eta = h.eta[t][s];
    const state = s === now ? "now" : s === nxt ? "next" : "";
    return `<div class="stage" data-state="${state}" style="--stc:${col}">
      ${state === "now" ? `<span class="tag">NOW</span>` : state === "next" ? `<span class="tag">NEXT</span>` : ""}
      <div class="name"><i></i>${st.name}</div>
      <div class="tac">${st.tac}</div>
      <div class="prob">${pct(p)}</div>
      <div class="eta">${eta ? `first likely in ~${fmtMin(minutes(eta))}` : "not likely within 5 min"}</div>
      <div class="bar"><i style="width:${clamp(Math.round(p * 100), 0, 100)}%"></i></div>
      <div class="tech">${st.tech}</div></div>`;
  }).join("");

  $("nextStage").innerHTML = `Now: <b>${now ? esc(STAGES[now].name) : "no attack stage"}</b> · most likely next: <b>${esc(STAGES[nxt].name)}</b> at ${pct(h.stage_max[t][nxt])}`;

  const sp = h.surprise[t] ?? 0;
  const novel = sp >= 95;
  $("surpriseRow").innerHTML = `<span class="muted small">Surprise</span>
    <span class="meter"><i style="width:${clamp(Math.round(sp), 0, 100)}%"></i></span>
    <b class="num">${Math.round(sp)}th percentile</b>
    <span class="muted">${novel
      ? "— unlike anything in normal traffic: possibly an attack the model was never trained on"
      : "— the dynamics look like normal traffic"}</span>`;
}

/* ── explanation ───────────────────────────────────────────────────── */

function scheduleExplain(delay = EXPLAIN_DEBOUNCE) {
  clearTimeout(S.exTimer);
  S.exTimer = setTimeout(fetchExplain, delay);
}

async function fetchExplain() {
  const h = hostObj(), t = localT(h);
  if (!h || t == null) return clearExplain();
  const key = `${S.aid}|${h.host}|${t}`;
  if (key === S.exKey && S.ex) return;
  S.exKey = key;
  if (S.exAbort) S.exAbort.abort();
  const ac = new AbortController();
  S.exAbort = ac;
  // A live tick asks for the cheap recommendation; a deliberate pause rehearses
  // every response inside the world model.
  const rehearse = S.aid !== "live" || !S.liveTimer;
  try {
    const ex = await api(`/api/explain/${encodeURIComponent(S.aid)}/${encodeURIComponent(h.host)}/${t}?rehearse_actions=${rehearse}`,
      { signal: ac.signal }, 60000);
    if (S.exKey !== key) return;
    S.ex = ex;
    renderWhy(); renderActions(); renderImagined(); renderFlows(); renderBlockBox();
  } catch (e) {
    if (e.name !== "AbortError" && S.exKey === key) S.exKey = null;
  }
}

function clearExplain() {
  S.ex = null;
  $("whySentences").innerHTML = `<li class="muted">Select a window where this host was active.</li>`;
  $("whyP").textContent = "";
  $("whyFaith").textContent = "";
  $("actions").innerHTML = "";
  $("recommend").innerHTML = `<span class="muted">No forecast to act on in this window.</span>`;
  $("whatifResult").innerHTML = "";
  $("imagined").innerHTML = "";
  $("flows").querySelector("tbody").innerHTML = `<tr><td colspan="9" class="empty">Nothing to show.</td></tr>`;
  $("blockBox").classList.add("hidden");
  disposeCharts("img");
  if (S.charts.whyBars) S.charts.whyBars.clear();
  if (S.charts.whyTime) S.charts.whyTime.clear();
  if (S.charts.whatifChart) S.charts.whatifChart.clear();
}

function renderWhy() {
  const ex = S.ex, h = hostObj();
  $("whyP").textContent = `${pct(ex.p)} at ${clock(h.off + ex.t)}`;
  $("whySentences").innerHTML = ex.sentences.length
    ? ex.sentences.map((s) => `<li>${esc(s)}</li>`).join("")
    : `<li class="muted">No single signal moves this forecast by more than a point — the traffic looks ordinary.</li>`;

  const top = ex.features.filter((f) => f.delta > 0.002).slice(0, 8).reverse();
  if (!top.length) {
    if (S.charts.whyBars) S.charts.whyBars.clear();
  } else {
    paint("whyBars", {
      animation: false,
      grid: { left: 8, right: 44, top: 4, bottom: 24, containLabel: true },
      tooltip: { ...tooltipBase(), trigger: "item", formatter: (pr) => {
        const f = top[pr.dataIndex];
        return `<b>${esc(f.label)}</b> <span style="color:${css("--muted")}">${f.level}-level</span><br>
          ${esc(f.description)}<br>now <b>${(+f.value.toFixed(2))}</b> · this host's normal <b>${(+f.typical.toFixed(2))}</b><br>
          forecast without it: <b>${pct(f.without)}</b>`;
      } },
      xAxis: { ...axisBase(), type: "value", name: "risk points", nameLocation: "middle", nameGap: 22,
        nameTextStyle: { color: css("--muted"), fontSize: 11 } },
      yAxis: { ...axisBase(), type: "category", data: top.map((f) => f.label),
        axisLabel: { color: css("--ink"), fontSize: 11.5, width: 168, overflow: "truncate" }, splitLine: { show: false } },
      series: [{ type: "bar", barMaxWidth: 13, data: top.map((f) => ({
        value: +(f.delta * 100).toFixed(1),
        itemStyle: { color: f.level === "packet" ? css("--s3") : css("--s1"), borderRadius: [0, 4, 4, 0] },
      })), label: { show: true, position: "right", color: css("--ink-2"), fontSize: 11, formatter: (v) => `+${v.value}` } }],
    });
  }

  const wins = ex.windows || [];
  paint("whyTime", {
    animation: false,
    grid: { left: 40, right: 16, top: 6, bottom: 20 },
    tooltip: { ...tooltipBase(), trigger: "axis", valueFormatter: (v) => `${v} risk points` },
    xAxis: { ...axisBase(), type: "category", data: wins.map((w) => clock(h.off + w.t)),
      axisLabel: { ...axisBase().axisLabel, hideOverlap: true }, splitLine: { show: false } },
    yAxis: { ...axisBase(), type: "value" },
    series: [{ type: "bar", data: wins.map((w) => +(Math.max(0, w.delta) * 100).toFixed(1)),
      itemStyle: { color: css("--s2"), borderRadius: [3, 3, 0, 0] }, barMaxWidth: 16 }],
  });

  const groups = (ex.groups || []).filter((g) => g.delta > 0.01).slice(0, 3)
    .map((g) => `${g.group} (${Math.round(g.delta * 100)})`).join(" · ");
  $("whyFaith").innerHTML = (ex.without_top != null
    ? `Deletion test: removing the top signals together drops the forecast from <b>${pct(ex.p)}</b> to <b>${pct(ex.without_top)}</b>, so the explanation is faithful to the model. ` : "")
    + (groups ? `Strongest groups: ${esc(groups)}.` : "");
}

function renderActions() {
  const rec = S.ex.recommendation || {};
  const b = band(S.ex.p);
  $("recommend").innerHTML = `${statusChip(S.ex.p)}<span class="muted">risk band →</span> <b style="color:${css(b.v)}">${esc(rec.label || "Keep monitoring")}</b>`;
  $("actions").innerHTML = Object.entries(S.meta.actions).map(([k, label]) => {
    const rehearsed = (rec.ranking || []).find((r) => r.action === k);
    const drop = rehearsed ? ` <span class="muted num">→ ${pct(rehearsed.after)}</span>` : "";
    return `<button class="btn" data-action="${k}" aria-pressed="${S.action === k}">${k === rec.action ? '<span class="tickmark">✓</span> ' : ""}${esc(label)}${drop}</button>`;
  }).join("");
  $("whatifResult").innerHTML = "";
  if (S.charts.whatifChart) S.charts.whatifChart.clear();
}

async function runWhatif(action) {
  const h = hostObj(), t = localT(h);
  if (t == null) return;
  S.action = action;
  $("actions").querySelectorAll("[data-action]").forEach((b) => b.setAttribute("aria-pressed", String(b.dataset.action === action)));
  $("whatifResult").innerHTML = `<span class="muted small">rehearsing…</span>`;
  let r;
  try {
    r = await api(`/api/whatif/${encodeURIComponent(S.aid)}/${encodeURIComponent(h.host)}/${t}/${encodeURIComponent(action)}`, {}, 60000);
  } catch (e) { return toast(`Could not rehearse that action: ${e.message}`, true); }
  const before = r.before[r.before.length - 1], after = r.after[r.after.length - 1];
  const good = after < before - 0.01;
  $("whatifResult").innerHTML = `<span class="num">${pct(before)}</span><span class="arrow">→</span>
    <span class="num" style="color:${css(good ? "--good" : "--muted")}">${pct(after)}</span>
    <span class="muted small">${esc(r.label)}</span>
    <button class="btn primary sm" id="approveBtn">Approve &amp; record</button>`;
  $("approveBtn").onclick = () => approve(action, before);

  const steps = r.before.map((_, j) => `+${fmtMin(minutes(j + 1))}`);
  paint("whatifChart", {
    animation: false,
    grid: { left: 46, right: 14, top: 26, bottom: 24 },
    tooltip: { ...tooltipBase(), trigger: "axis", valueFormatter: (v) => pct(v) },
    legend: { data: ["No action", "With this action"], textStyle: { color: css("--ink-2"), fontSize: 11 }, right: 0, top: 0, icon: "roundRect", itemWidth: 14, itemHeight: 3 },
    xAxis: { ...axisBase(), type: "category", data: steps, splitLine: { show: false } },
    yAxis: { ...axisBase(), type: "value", min: 0, max: 1, axisLabel: { ...axisBase().axisLabel, formatter: (v) => `${Math.round(v * 100)}%` } },
    series: [
      { name: "No action", type: "line", data: r.before, showSymbol: false, lineStyle: { width: 2, color: css("--critical") }, itemStyle: { color: css("--critical") } },
      { name: "With this action", type: "line", data: r.after, showSymbol: false, lineStyle: { width: 2, color: css("--good") }, itemStyle: { color: css("--good") } },
    ],
  });
}

async function approve(action, p) {
  const h = hostObj(), t = localT(h);
  try {
    const r = await api("/api/ledger/approve", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ aid: S.aid, host: h.host, window: S.A.t0 + (h.off + t) * S.A.window_s * 1000, action, p }),
    }, 30000);
    toast(`Approved “${S.meta.actions[action]}” for ${h.host} — ledger #${r.record.seq}, chain ${r.verify.ok ? "verified ✓" : "BROKEN ✗"}`);
    refreshLedgerBadge();
  } catch (e) { toast(`Could not record the approval: ${e.message}`, true); }
}

function renderImagined() {
  disposeCharts("img");
  const entries = Object.entries(S.ex.imagined || {});
  const box = $("imagined");
  if (!entries.length) { box.innerHTML = `<div class="empty" style="grid-column:1/-1">No imagined states for this window.</div>`; return; }
  box.innerHTML = entries.map(([f, v], i) => `<div><div class="t">${esc(v.label)}</div><div id="img${i}" class="c"></div></div>`).join("");
  entries.forEach(([f, v], i) => {
    const n = v.history.length, K = v.q50.length;
    const x = Array.from({ length: n + K }, (_, j) => j);
    const hist = x.map((j) => (j < n ? v.history[j] : null));
    const low = x.map((j) => (j === n - 1 ? v.history[n - 1] : j >= n ? v.q10[j - n] : null));
    const bnd = x.map((j) => (j === n - 1 ? 0 : j >= n ? Math.max(0, v.q90[j - n] - v.q10[j - n]) : null));
    const med = x.map((j) => (j === n - 1 ? v.history[n - 1] : j >= n ? v.q50[j - n] : null));
    paint(`img${i}`, {
      animation: false,
      grid: { left: 4, right: 4, top: 6, bottom: 4, containLabel: true },
      tooltip: { ...tooltipBase(), trigger: "axis", formatter: (ps) => {
        const j = +ps[0].axisValue;
        const val = j < n ? v.history[j] : v.q50[j - n];
        return `${j < n ? "observed" : `imagined +${fmtMin(minutes(j - n + 1))}`}<br><b>${val == null ? "–" : (+val.toFixed(2))}</b>`;
      } },
      xAxis: { ...axisBase(), type: "category", data: x, axisLabel: { show: false }, splitLine: { show: false } },
      yAxis: { ...axisBase(), type: "value", axisLabel: { color: css("--muted"), fontSize: 10 }, splitLine: { show: false } },
      series: [
        { name: "observed", type: "line", data: hist, showSymbol: false, lineStyle: { color: css("--ink-2"), width: 1.5 } },
        { name: "_lo", type: "line", data: low, stack: "b", showSymbol: false, lineStyle: { opacity: 0 }, silent: true, tooltip: { show: false } },
        { name: "_bd", type: "line", data: bnd, stack: "b", showSymbol: false, lineStyle: { opacity: 0 }, areaStyle: { color: alpha(css("--s1"), 0.22) }, silent: true, tooltip: { show: false } },
        { name: "imagined", type: "line", data: med, showSymbol: false, lineStyle: { color: css("--s1"), type: "dashed", width: 1.8 } },
      ],
    });
  });
}

function renderFlows() {
  const rows = S.ex.flows || [];
  const utc = /CIC/.test(S.A.dataset || "");
  $("flows").querySelector("tbody").innerHTML = rows.length
    ? rows.map((r) => `<tr>
        <td>${new Date(r.time).toLocaleTimeString("en-GB", { timeZone: utc ? "UTC" : undefined })}</td>
        <td class="mono">${esc(r.src)}</td><td class="mono">${esc(r.dst)}</td><td>${esc(r.proto)}</td>
        <td>${r.pkts}</td><td>${fmtBytes(r.bytes)}</td><td>${esc(r.state || "–")}</td><td>${r.ttl ?? "–"}</td>
        <td class="wrap">${esc(r.why)}</td></tr>`).join("")
    : `<tr><td colspan="9" class="empty">No flows sit behind a strong signal in this period.</td></tr>`;
}

/* ── enforcement ───────────────────────────────────────────────────── */

function renderEnforce(st) {
  if (!st) return;
  S.enforce = st;
  const armed = st.mode === "enforcing";
  const b = $("enforceBadge");
  b.innerHTML = `${armed ? "Enforcing" : "Dry run"}${st.blocks.length ? ` · ${st.blocks.length}` : ""}`;
  b.className = `badge ${armed ? "armed" : "dry"}`;
  b.title = `${st.status}\nBackend: ${st.backend}. ${st.never_block.length} addresses can never be blocked.`;
}

// The external address behind the strongest flagged flows — what an analyst
// would actually block. Internal hosts are never offered.
function attackerIP() {
  const flows = (S.ex && S.ex.flows) || [];
  const h = hostObj();
  if (!h) return null;
  const internal = /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|::1|fe80:)/;
  const count = {};
  for (const f of flows) {
    for (const side of [f.src, f.dst]) {
      const ip = String(side).split(":").slice(0, -1).join(":") || String(side);
      if (!ip || ip === h.host || internal.test(ip)) continue;
      count[ip] = (count[ip] || 0) + 1;
    }
  }
  const best = Object.entries(count).sort((a, b) => b[1] - a[1])[0];
  return best ? best[0] : null;
}

function renderBlockBox() {
  const box = $("blockBox"), ip = attackerIP(), st = S.enforce;
  if (!ip || !st) return box.classList.add("hidden");
  box.classList.remove("hidden");
  const blocked = st.blocks.some((b) => b.ip === ip);
  box.innerHTML = `<b>Source behind the flagged flows:</b> <code>${esc(ip)}</code>
    <div class="muted small" style="margin-top:3px">${st.mode === "enforcing"
      ? `A block installs an ${esc(st.backend)} rule for ${Math.round(st.ttl_s / 60)} minutes and can be undone.`
      : "Dry run — the decision goes in the ledger, no firewall rule is applied."}</div>
    <div class="row">${blocked
      ? `<button class="btn" id="unblockBtn">Undo block on ${esc(ip)}</button><span class="status critical"><i class="ico"></i>blocked</span>`
      : `<button class="btn primary" id="blockBtn">Block ${esc(ip)}</button><span class="muted small">analyst decision, recorded in the ledger</span>`}</div>`;
  const bb = $("blockBtn"); if (bb) bb.onclick = () => doBlock(ip);
  const ub = $("unblockBtn"); if (ub) ub.onclick = () => doUnblock(ip);
}

async function doBlock(ip) {
  const h = hostObj();
  try {
    const r = await api("/api/enforce/block", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ip, host: h.host, reason: `analyst approved from a ${pct(S.ex.p)} forecast on ${h.host}` }),
    }, 30000);
    if (!r.ok) return toast(`Refused: ${r.refused}`, true);
    toast(r.applied ? `Blocked ${ip} via ${S.enforce.backend} — ledger #${r.ledger_seq}` : `Recorded a block of ${ip} (dry run) — ledger #${r.ledger_seq}`);
    renderEnforce(await api("/api/enforce/state", {}, 20000));
    renderBlockBox(); refreshLedgerBadge();
  } catch (e) { toast(`Block failed: ${e.message}`, true); }
}

async function doUnblock(ip) {
  try {
    await api("/api/enforce/unblock", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ ip }) }, 30000);
    toast(`Removed the block on ${ip}`);
    renderEnforce(await api("/api/enforce/state", {}, 20000));
    renderBlockBox(); refreshLedgerBadge();
  } catch (e) { toast(`Could not remove the block: ${e.message}`, true); }
}

/* ── replay ────────────────────────────────────────────────────────── */

function toggleReplay() {
  if (S.aid === "live") return toast("Already live — the timeline advances as the sensor reports each window.");
  if (S.replayTimer) return stopReplay();
  if (S.cursor >= S.A.T - 1) S.cursor = 0;
  S.replaying = true;
  $("playBtn").innerHTML = "❚❚&nbsp; Pause";
  S.replayTimer = setInterval(stepReplay, +$("speed").value);
}
function stopReplay() {
  clearInterval(S.replayTimer);
  S.replayTimer = null;
  S.replaying = false;
  $("playBtn").innerHTML = "▶&nbsp; Replay";
  if (S.A) renderAll();
  scheduleExplain(0);
}
function stepReplay() {
  const h = hostObj();
  S.cursor++;
  if (S.cursor >= S.A.T - 1) { S.cursor = S.A.T - 1; stopReplay(); return; }
  $("scrub").value = S.cursor;
  renderAll();
  const t = localT(h);
  if (t != null && h.first_alarm === t) scheduleExplain(0);  // pause-worthy moment
}

/* ── benchmark ─────────────────────────────────────────────────────── */

async function renderBench() {
  const box = $("bench");
  if (!S.bench) {
    box.innerHTML = `<div class="card"><div class="empty">Loading benchmark…</div></div>`;
    try { S.bench = await api("/api/benchmark", {}, 40000); }
    catch (e) { return void (box.innerHTML = `<div class="card"><div class="empty">Could not load the benchmark: ${esc(e.message)}</div></div>`); }
  }
  disposeCharts("slow-");
  const names = { trace: "TRACE world model", lr_state: "Logistic regression (current window)", lr_stacked: "Logistic regression (last 20 windows)" };
  const order = ["trace", "lr_state", "lr_stacked"];
  const parts = [];

  for (const [key, b] of Object.entries(S.bench)) {
    const title = key === "sim"
      ? "Simulated kill chains — both feature levels, test episodes never seen in training"
      : "CIC-IDS2017 — real traffic, flow-only, tested on Thursday's infiltration chain";
    const all = b.tasks.all, early = b.tasks.early;
    const ew = b.early_warning, ewm = b.early_warning_matched || b.early_warning;
    const tiles = [
      [all.trace.f1.toFixed(3), `F1 — against ${all.lr_state.f1.toFixed(3)} and ${all.lr_stacked.f1.toFixed(3)} for the baselines`],
      [all.trace.pr_auc.toFixed(3), `PR-AUC — against ${all.lr_state.pr_auc.toFixed(3)} and ${all.lr_stacked.pr_auc.toFixed(3)}`],
      [`${ewm.trace.warned_before_compromise}/${ewm.trace.attack_episodes}`, `attacks warned before compromise, median ${fmtMin(ewm.trace.median_lead_min)} early — baselines ${ewm.lr_state.warned_before_compromise}/${ewm.lr_state.attack_episodes} and ${ewm.lr_stacked.warned_before_compromise}/${ewm.lr_stacked.attack_episodes} at the same false-alarm rate`],
      [`${ew.trace.false_alarm_episodes}/${ew.trace.benign_episodes || 0}`, `benign episodes raising any alarm — baselines ${ew.lr_state.false_alarm_episodes}/${ew.lr_state.benign_episodes || 0} and ${ew.lr_stacked.false_alarm_episodes}/${ew.lr_stacked.benign_episodes || 0}`],
    ];
    const table = (task, label) => `<h3 class="sub-h">${esc(label)}</h3><div class="tablewrap"><table>
      <thead><tr><th>Model</th><th>F1</th><th>Precision</th><th>Recall</th><th>False-positive rate</th><th>PR-AUC</th><th>Brier</th></tr></thead>
      <tbody>${order.map((m) => { const r = task[m]; return `<tr class="${m === "trace" ? "lead" : ""}">
        <td style="white-space:normal">${esc(names[m])}</td><td>${r.f1.toFixed(3)}</td><td>${r.precision.toFixed(3)}</td>
        <td>${r.recall.toFixed(3)}</td><td>${(r.fpr * 100).toFixed(2)}%</td><td>${r.pr_auc.toFixed(3)}</td><td>${r.brier.toFixed(3)}</td></tr>`; }).join("")}</tbody></table></div>`;

    const u = b.unseen;
    parts.push(`<section class="card">
      <header><h2>${esc(title)}</h2><span class="sub">${b.window_s} s windows · horizon K=${b.horizon_k} · thresholds fixed on validation</span></header>
      <div class="kpis">${tiles.map(([v, d]) => `<div class="tile"><div class="v num sm">${esc(v)}</div><div class="d">${esc(d)}</div></div>`).join("")}</div>
      ${table(all, "Infiltration within the next K windows — every window")}
      ${table(early, "Only windows before the host is compromised — pure forecasting")}
      ${b.slow_scan ? `<h3 class="sub-h">Slow-scan sweep — share of attack chains warned before compromise, as the scan slows down</h3><div id="slow-${esc(key)}" class="chart" style="height:280px"></div>` : ""}
      ${u ? `<h3 class="sub-h">Unseen attack family — DNS-tunnel exfiltration, never in training</h3>
        <p>Exfiltration windows flagged: <b>TRACE ${Math.round(u.exfil_windows_flagged.trace * 100)}%</b> · logistic regression ${Math.round(u.exfil_windows_flagged.lr_state * 100)}% · stacked ${Math.round(u.exfil_windows_flagged.lr_stacked * 100)}%. The world model's surprise sits at the <b>${Math.round(u.surprise_pct_exfil_median)}th percentile</b> on those windows, against ${Math.round(u.surprise_pct_benign_median)}th for benign traffic.</p>` : ""}
      <p class="small muted">Attack-stage macro-F1 ${b.stage_macro_f1.toFixed(3)} · next-state NLL ${b.next_state_nll.world_model.toFixed(2)} for the world model against ${b.next_state_nll.persistence_baseline.toFixed(2)} for a persistence baseline (lower is better) · split: ${esc(Object.entries(b.split).map(([k, v]) => `${k} ${Array.isArray(v) ? v.length : v}`).join(", "))}.</p>
    </section>`);
  }
  box.innerHTML = parts.join("") || `<div class="card"><div class="empty">No benchmark yet — run <code class="mono">make bench</code>.</div></div>`;

  for (const [key, b] of Object.entries(S.bench)) {
    if (!b.slow_scan) continue;
    const line = (k, label, color, dashed) => ({
      name: label, type: "line", symbolSize: 8, data: b.slow_scan.map((r) => Math.round(r[k] * 100)),
      lineStyle: { color, width: 2, type: dashed ? [5, 4] : "solid" },
      itemStyle: { color, borderColor: css("--surface"), borderWidth: 2 },
      endLabel: { show: true, formatter: "{a}", color, fontSize: 11, fontWeight: 600, distance: 6 },
    });
    paint(`slow-${key}`, {
      animation: false,
      grid: { left: 52, right: 130, top: 30, bottom: 44 },
      tooltip: { ...tooltipBase(), trigger: "axis", valueFormatter: (v) => `${v}%` },
      legend: { top: 0, left: 0, textStyle: { color: css("--ink-2"), fontSize: 11 }, icon: "roundRect", itemWidth: 14, itemHeight: 3 },
      xAxis: { ...axisBase(), type: "category", data: b.slow_scan.map((r) => `${r.probe_gap_s}s`),
        name: "seconds between probes", nameLocation: "middle", nameGap: 26, nameTextStyle: { color: css("--muted"), fontSize: 11 }, splitLine: { show: false } },
      yAxis: { ...axisBase(), type: "value", min: 0, max: 100, axisLabel: { ...axisBase().axisLabel, formatter: "{value}%" } },
      series: [
        line("trace", "TRACE", css("--s1")),
        line("lr_state", "LR (current window)", css("--s2"), true),
        line("lr_stacked", "LR (stacked)", css("--s3"), true),
        line("threshold_detector", "Per-window threshold", css("--s4"), true),
      ],
    });
  }
}

/* ── ledger ────────────────────────────────────────────────────────── */

async function refreshLedgerBadge() {
  try {
    const l = await api("/api/ledger", {}, 20000);
    const b = $("ledgerBadge");
    b.textContent = `Ledger ${l.verify.ok ? "✓" : "✗"} ${l.verify.count}`;
    b.className = `badge ${l.verify.ok ? "ok" : "bad"}`;
    return l;
  } catch { return null; }
}

async function renderLedger(tamper) {
  const l = await refreshLedgerBadge();
  const v = $("verifyResult");
  if (!l) { v.className = "verify bad"; v.textContent = "Could not read the ledger."; return; }
  if (tamper) {
    try {
      const r = await api("/api/ledger/tamper-test", { method: "POST" }, 20000);
      v.className = `verify ${r.ok ? "ok" : "bad"}`;
      v.textContent = r.ok ? "Not enough records to run the test yet."
        : `✗ Record #${r.edited_seq} was altered in a copy of the chain. Verification fails from #${r.broken_at} onward — its hash no longer matches, and neither does anything after it. The real ledger is untouched.`;
    } catch (e) { v.className = "verify bad"; v.textContent = `Tamper test failed: ${e.message}`; }
  } else {
    v.className = `verify ${l.verify.ok ? "ok" : "bad"}`;
    v.textContent = l.verify.ok
      ? `✓ Chain verified — ${l.verify.count} records, head ${String(l.verify.head || "").slice(0, 16)}…`
      : `✗ Chain broken at record #${l.verify.broken_at}`;
  }
  const kinds = { forecast: "Forecast alarm", approval: "Analyst approval", block: "Block applied", unblock: "Block removed", block_refused: "Block refused" };
  $("ledgerTable").querySelector("tbody").innerHTML = l.records.length ? l.records.map((r) => {
    let detail = "";
    if (r.kind === "forecast") detail = `${pct(r.p)} → ${esc(r.predicted_stage)} <span class="muted">(${esc(r.analysis)})</span>`;
    else if (r.kind === "approval") detail = `${esc((S.meta && S.meta.actions[r.action]) || r.action)} at ${pct(r.p)}`;
    else if (r.kind === "block") detail = `${r.applied ? `applied via ${esc(r.backend)}` : "recorded (dry run)"} · ${Math.round((r.ttl_s || 0) / 60)} min`;
    else if (r.kind === "unblock") detail = "removed";
    else if (r.kind === "block_refused") detail = esc(r.reason);
    return `<tr><td>${r.seq}</td><td>${esc(r.time)}</td><td>${esc(kinds[r.kind] || r.kind)}</td>
      <td class="mono">${esc(r.host || r.ip || "")}</td><td class="wrap">${detail}</td>
      <td class="mono">${esc(String(r.hash).slice(0, 12))}…</td><td class="mono">${esc(String(r.prev).slice(0, 12))}…</td></tr>`;
  }).join("") : `<tr><td colspan="7" class="empty">No records yet — an alarm or an approval writes the first one.</td></tr>`;
}

/* ── how it works ──────────────────────────────────────────────────── */

function renderHow() {
  const reqs = [
    ["Represent network state as feature vectors", "One state vector per internal host per 30 s window: 43 flow-level and 32 packet-level features, built by the Go extractor"],
    ["Learn P(S_t+1 | S_≤t) with a sequence model", "MDN-RNN world model: a GRU core with a five-component Gaussian mixture over the next state"],
    ["Forward simulation, K steps ahead", "100 Monte Carlo rollouts, 10 windows (5 minutes) — the forecast cone on the timeline"],
    ["Time-series probability of infiltration", "The forecast line per host, and for the network as the maximum over hosts"],
    ["Map predicted behaviour to MITRE ATT&CK", "A stage head on every real and imagined state; the kill-chain panel with tactic IDs"],
    ["Driving features — attention, SHAP or equivalent", "Occlusion attribution per feature, per group and per past window, with a deletion test for faithfulness"],
    ["Both flow- and packet-level features", "The f_* and p_* blocks; flow-only CSV inputs run with the packet block masked"],
    ["Accepts PCAP or CSV, offline interface", "Upload a pcap/pcapng or a CIC-IDS2017 CSV; FastAPI with vendored charts, no cloud calls"],
    ["Benchmark against logistic regression", "The Benchmark tab: F1, precision, recall, FPR, PR-AUC, lead time and false alarms per host-hour"],
    ["Generalise to unseen attack patterns", "DNS-tunnel exfiltration held out of training, the surprise meter, and CIC Thursday never trained on"],
    ["Reproducible training, weights and config", "make reproduce — a seeded simulator, with config.json saved beside model.pt"],
    ["Live operation (beyond the statement)", "trace-sensor captures on an interface — pure-Go AF_PACKET on Linux — and streams each closed window"],
    ["Prevention with safety limits (beyond the statement)", "Analyst-approved nftables/pf block with a TTL, an undo, and a never-block list covering this host, its gateway and its DNS"],
  ];
  const m = (S.meta && S.meta.models) || {};
  $("how").innerHTML = `
    <section class="card">
      <header><h2>Pipeline</h2></header>
      <div class="pipeline">
        <div><b>1 · Capture</b>A pcap/pcapng file, a CSV of flow records, or a live interface</div>
        <div><b>2 · Extractor (Go)</b>Flows plus per-host 30 s windows — 75 flow and packet features at ~780k packets/s</div>
        <div><b>3 · World model</b>An MDN-RNN learns P(S<sub>t+1</sub> | S<sub>≤t</sub>) over host states</div>
        <div><b>4 · Forward simulation</b>100 imagined futures × 10 windows → risk, ATT&amp;CK stage, confidence cone</div>
        <div><b>5 · Decision support</b>Explanations, what-if rehearsal, analyst approval, firewall enforcement, hash-chained ledger</div>
      </div>
      <p class="small muted">Live: <code class="mono">trace-sensor -iface eth0 -server http://127.0.0.1:8000</code> — rehearse without touching a network: <code class="mono">trace-sensor -replay data/demo/demo-killchain.pcap -speed 60</code></p>
      <p class="small muted">Models loaded: ${Object.entries(m).map(([k, v]) => `<b>${esc(k)}</b> — ${v.features} features, K=${v.horizon_k}, ${v.window_s} s windows${v.flow_only ? ", flow-only" : ""}`).join(" · ") || "none"}</p>
    </section>
    <section class="card">
      <header><h2>Problem statement SIH26153 — requirement checklist</h2></header>
      <div class="tablewrap"><table class="checklist">
        <thead><tr><th>Requirement</th><th></th><th>Where it is in TRACE</th></tr></thead>
        <tbody>${reqs.map(([a, b]) => `<tr><td>${esc(a)}</td><td class="tick">✓</td><td class="wrap">${esc(b)}</td></tr>`).join("")}</tbody>
      </table></div>
    </section>
    <section class="card">
      <header><h2>Keyboard</h2></header>
      <p class="small"><kbd>Space</kbd> play / pause replay · <kbd>←</kbd> <kbd>→</kbd> step one window · <kbd>Shift</kbd>+<kbd>←</kbd>/<kbd>→</kbd> ten windows · <kbd>↑</kbd> <kbd>↓</kbd> change host · <kbd>Home</kbd> / <kbd>End</kbd> jump to start or live edge.</p>
    </section>`;
}

/* ── wiring ────────────────────────────────────────────────────────── */

function moveCursor(to) {
  if (!S.A) return;
  S.cursor = clamp(to, 0, S.A.T - 1);
  $("scrub").value = S.cursor;
  renderAll();
  scheduleExplain();
}

function selectHost(name) {
  if (!name || name === S.host) return;
  S.host = name;
  S.exKey = null;
  ensureCone(name).then(() => { renderAll(); });
  renderAll();
  scheduleExplain(0);
}

function bind() {
  $("scenario").onchange = (e) => load(e.target.value);
  $("uploadBtn").onclick = () => $("file").click();
  $("file").onchange = async (e) => {
    const f = e.target.files[0];
    if (!f) return;
    e.target.value = "";
    loading(true, `Uploading and analysing ${f.name}…`);
    try {
      const fd = new FormData();
      fd.append("file", f);
      const r = await api("/api/upload", { method: "POST", body: fd }, 600000);
      S.meta = await api("/api/meta");
      fillScenarios(r.id);
      await load(r.id);
      toast(`Analysed ${f.name}`);
    } catch (err) {
      loading(false);
      toast(`Upload failed: ${err.message}`, true);
    }
  };

  $("hostList").onclick = (e) => { const row = e.target.closest(".host"); if (row) selectHost(row.dataset.host); };
  $("hostList").onkeydown = (e) => {
    const row = e.target.closest(".host");
    if (row && (e.key === "Enter" || e.key === " ")) { e.preventDefault(); selectHost(row.dataset.host); }
  };

  $("playBtn").onclick = toggleReplay;
  $("speed").onchange = () => { if (S.replayTimer) { stopReplay(); toggleReplay(); } };
  $("scrub").oninput = (e) => { stopReplay(); moveCursor(+e.target.value); };

  $("actions").onclick = (e) => { const b = e.target.closest("[data-action]"); if (b) runWhatif(b.dataset.action); };
  $("modeAnalyst").onclick = () => setMode("analyst");
  $("modeExec").onclick = () => setMode("exec");
  $("ledgerBadge").onclick = () => showTab("ledger");
  $("enforceBadge").onclick = () => showTab("ledger");
  $("verifyBtn").onclick = () => renderLedger(false);
  $("tamperBtn").onclick = () => renderLedger(true);

  $("themeBtn").onclick = () => {
    const cur = document.documentElement.getAttribute("data-theme")
      || (matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
    const next = cur === "dark" ? "light" : "dark";
    document.documentElement.setAttribute("data-theme", next);
    try { localStorage.setItem("trace-theme", next); } catch { /* private mode */ }
    // Every chart bakes in token colours, so they all have to be repainted.
    if (S.A) renderAll();
    if (S.ex) { renderWhy(); renderActions(); renderImagined(); }
    if (!$("tab-bench").hidden) { disposeCharts("slow-"); renderBench(); }
  };

  document.querySelectorAll('.tabs button[data-tab]').forEach((b) => (b.onclick = () => showTab(b.dataset.tab)));

  document.addEventListener("keydown", (e) => {
    const tag = (e.target.tagName || "").toLowerCase();
    if (tag === "input" || tag === "select" || tag === "textarea") return;
    if (!S.A) return;
    const jump = e.shiftKey ? 10 : 1;
    switch (e.key) {
      case " ": e.preventDefault(); toggleReplay(); break;
      case "ArrowRight": e.preventDefault(); stopReplay(); moveCursor(S.cursor + jump); break;
      case "ArrowLeft": e.preventDefault(); stopReplay(); moveCursor(S.cursor - jump); break;
      case "Home": e.preventDefault(); stopReplay(); moveCursor(0); break;
      case "End": e.preventDefault(); stopReplay(); moveCursor(S.A.T - 1); break;
      case "ArrowUp": case "ArrowDown": {
        e.preventDefault();
        const i = S.A.hosts.findIndex((h) => h.host === S.host);
        const nxt = S.A.hosts[clamp(i + (e.key === "ArrowDown" ? 1 : -1), 0, S.A.hosts.length - 1)];
        if (nxt) selectHost(nxt.host);
        break;
      }
    }
  });

  // Click the timeline to move the cursor there.
  const tl = chart("timeline");
  if (tl) tl.getZr().on("click", (ev) => {
    const pt = tl.convertFromPixel({ seriesIndex: 0 }, [ev.offsetX, ev.offsetY]);
    if (!pt) return;
    stopReplay();
    moveCursor(Math.round(pt[0]));
  });
}

function setMode(m) {
  S.mode = m;
  $("modeAnalyst").setAttribute("aria-pressed", String(m === "analyst"));
  $("modeExec").setAttribute("aria-pressed", String(m === "exec"));
  document.querySelectorAll(".detail").forEach((el) => el.classList.toggle("hidden", m === "exec"));
  setTimeout(() => Object.values(S.charts).forEach((c) => !c.isDisposed() && c.resize()), 0);
}

function showTab(name) {
  document.querySelectorAll(".tabs button[data-tab]").forEach((b) => b.setAttribute("aria-selected", String(b.dataset.tab === name)));
  document.querySelectorAll(".tab").forEach((t) => (t.hidden = t.id !== `tab-${name}`));
  if (name === "bench") renderBench();
  if (name === "ledger") renderLedger(false);
  setTimeout(() => Object.values(S.charts).forEach((c) => !c.isDisposed() && c.resize()), 0);
}

init().catch((e) => { loading(false); toast(`Start-up failed: ${e.message}`, true); });
