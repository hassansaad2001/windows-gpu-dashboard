"use strict";

// ------------------------------------------------------------ helpers
const $ = (id) => document.getElementById(id);
const css = (v) => getComputedStyle(document.documentElement).getPropertyValue(v).trim();
const GB = 1024 ** 3;
let ME = { user: "", is_admin: false };

function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}
function pct(v) { return v == null ? "–" : `${Math.round(v)}<small>%</small>`; }
function gb(b, d = 1) { return b == null ? "–" : `${(b / GB).toFixed(d)} GB`; }
function compact(n) { return n == null ? "–" : n >= 1e6 ? (n / 1e6).toFixed(1) + "M" : n >= 1e3 ? (n / 1e3).toFixed(1) + "K" : String(n); }
function dt(ts, withYear = false) {
  if (!ts) return "–";
  const d = new Date(ts * 1000);
  return d.toLocaleString(undefined, { year: withYear ? "numeric" : undefined, month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
}
function dur(sec) {
  if (sec == null) return "–";
  const d = Math.floor(sec / 86400), h = Math.floor((sec % 86400) / 3600), m = Math.floor((sec % 3600) / 60);
  return d ? `${d}d ${h}h` : h ? `${h}h ${m}m` : `${m}m`;
}
function meterClass(v) { return v >= 90 ? "meter crit" : v >= 75 ? "meter warn" : "meter"; }
function setMeter(id, v) {
  const el = $(id);
  el.style.width = `${Math.min(100, v || 0)}%`;
  el.parentElement.className = meterClass(v || 0);
}
function badge(kind, label) { return `<span class="badge ${kind}">${esc(label)}</span>`; }
function emptyRow(cols, text) { return `<tr><td colspan="${cols}" class="empty">${esc(text)}</td></tr>`; }

async function api(path, opts = {}) {
  const r = await fetch(path, {
    credentials: "same-origin",
    ...opts,
    headers: { "X-Requested-With": "aidash", ...(opts.body ? { "Content-Type": "application/json" } : {}), ...(opts.headers || {}) },
  });
  if (r.status === 401) { location.href = "/login"; throw new Error("login required"); }
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(j.detail || `HTTP ${r.status}`);
  return j;
}

function toast(msg, err = false) {
  const t = document.createElement("div");
  t.className = "toast" + (err ? " err" : "");
  t.textContent = msg;
  document.body.appendChild(t);
  setTimeout(() => t.remove(), err ? 8000 : 4500);
}

function confirmDlg(title, html, okLabel = "Confirm") {
  return new Promise((resolve) => {
    const d = $("confirmDlg");
    $("dlgTitle").textContent = title;
    $("dlgBody").innerHTML = html;
    $("dlgOk").textContent = okLabel;
    const done = (v) => { d.close(); $("dlgOk").onclick = $("dlgCancel").onclick = null; resolve(v); };
    $("dlgOk").onclick = () => done(true);
    $("dlgCancel").onclick = () => done(false);
    d.oncancel = () => done(false);
    d.showModal();
  });
}

// Shared hover tooltip for HTML marks.
const tip = $("tip");
function showTip(e, html) {
  tip.innerHTML = html;
  tip.classList.remove("hidden");
  const w = tip.offsetWidth, h = tip.offsetHeight;
  let x = e.clientX + 14, y = e.clientY + 14;
  if (x + w > innerWidth - 8) x = e.clientX - w - 14;
  if (y + h > innerHeight - 8) y = e.clientY - h - 14;
  tip.style.left = `${x}px`; tip.style.top = `${y}px`;
}
function hideTip() { tip.classList.add("hidden"); }

// ------------------------------------------------------------ overview
let lastOverview = null;
let flaggedCount = null;

async function loadOverview() {
  const o = await api("/api/overview");
  lastOverview = o;
  const L = o.live || {};
  $("host").textContent = o.host;
  document.title = `${o.host} · AI Server Dashboard`;

  $("kCpu").innerHTML = pct(L.cpu); setMeter("mCpu", L.cpu);
  $("fCpu").textContent = `${o.cpu_count} logical cores`;
  $("kRam").innerHTML = pct(L.ram); setMeter("mRam", L.ram);
  $("fRam").textContent = `${gb(o.ram_used, 0)} of ${gb(o.ram_total, 0)}`;
  $("kGpu").innerHTML = pct(L.gpu); setMeter("mGpu", L.gpu);
  const busy = (L.gpus || []).filter((g) => (g.util || 0) >= 10).length;
  $("fGpu").textContent = `${busy} of ${(L.gpus || []).length} GPUs busy · VRAM ${L.gpu_mem == null ? "–" : Math.round(L.gpu_mem) + "%"}`;

  const U = o.users;
  $("kUsers").textContent = U.registered;
  $("fUsers").textContent = `${U.admins} administrators · ${U.disabled} disabled`;
  $("fUsers").title = "Administrators: " + U.admin_names.join(", ");
  $("kSess").textContent = U.sessions_active + U.sessions_disconnected;
  $("fSess").textContent = `${U.sessions_active} active · ${U.sessions_disconnected} disconnected · ${U.users_logged_on} users`;
  $("kUp").textContent = dur(o.now - o.boot_ts);
  $("fUp").textContent = `since ${dt(o.boot_ts)}`;

  const stale = !L.ts || o.now - L.ts > 180;
  $("liveDot").classList.toggle("stale", stale);
  $("meta").textContent = L.ts ? `Updated ${new Date(L.ts * 1000).toLocaleTimeString()}` : "Waiting for first sample…";

  $("diskSub").textContent = o.disks.map((d) => `${d.mount.replace("\\", "")} ${gb(d.free, 0)} free of ${(d.total / 1024 ** 4).toFixed(1)} TB`).join(" · ");
  renderGpus(L.gpus || []);
  renderSessions(U.sessions);
}

let gpuOwners = {};
function renderGpus(gpus) {
  $("gpus").innerHTML = gpus.map((g) => {
    const memPct = g.mem_total_mb ? (g.mem_used_mb / g.mem_total_mb) * 100 : 0;
    const owners = gpuOwners[g.index] || [];
    return `<div class="gpu">
      <div class="row"><span>GPU ${g.index}</span><span>${g.temp ?? "–"}°C · ${g.power_w == null ? "–" : Math.round(g.power_w) + " W"}</span></div>
      <div class="row" style="margin-top:6px"><span class="big">${g.util ?? "–"}%</span><span>util</span></div>
      <div class="${meterClass(g.util || 0)}"><span style="width:${g.util || 0}%"></span></div>
      <div class="row" style="margin-top:8px"><span>VRAM</span><span>${(g.mem_used_mb / 1024).toFixed(1)} / ${(g.mem_total_mb / 1024).toFixed(0)} GB</span></div>
      <div class="${meterClass(memPct)}"><span style="width:${memPct}%"></span></div>
      <span class="who" title="${esc(owners.join(", "))}">${owners.length ? "Used by " + esc(owners.join(", ")) : "Idle"}</span>
    </div>`;
  }).join("") || `<div class="empty">nvidia-smi returned no GPUs</div>`;
}

function renderSessions(sessions) {
  const rows = [...sessions].sort((a, b) => a.state.localeCompare(b.state) || a.username.localeCompare(b.username));
  $("sessRows").innerHTML = rows.map((s) => {
    const kind = s.state === "Active" ? "good" : s.idle_seconds > 86400 ? "warning" : "";
    return `<tr><td>${esc(s.username)}</td><td class="num">${s.session_id}</td><td>${badge(kind, s.state)}</td>
      <td class="num">${dur(s.idle_seconds)}</td><td>${dt(s.logon_ts)}</td>
      <td class="admin-only"><button class="btn sm danger" data-logoff="${s.session_id}" data-user="${esc(s.username)}">Log off</button></td></tr>`;
  }).join("") || emptyRow(6, "No user sessions");
  applyRole();
}

// ------------------------------------------------------------ trends
let trendChart = null;
let range = "24h";

function labelFor(row, kind) {
  if (row.label) return kind === "monthly"
    ? new Date(row.label + "-01T00:00").toLocaleDateString(undefined, { month: "short", year: "numeric" })
    : new Date(row.label + "T00:00").toLocaleDateString(undefined, { month: "short", day: "numeric" });
  const d = new Date(row.ts * 1000);
  if (kind === "raw") return d.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" });
  return range === "24h" ? d.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" })
    : d.toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit" });
}

async function loadTrends() {
  const t = await api(`/api/trends?range=${range}`);
  const labels = t.rows.map((r) => labelFor(r, t.kind));
  const series = [
    ["CPU", "cpu", "--series-1"], ["RAM", "ram", "--series-2"], ["GPU", "gpu", "--series-3"],
  ];
  const sub = { raw: "Per-minute samples, %", hourly: "Hourly averages, %", daily: "Daily averages, %", monthly: "Monthly averages, %" };
  $("trendSub").textContent = `${sub[t.kind]} · ${t.rows.length} points`;

  const datasets = series.map(([name, key, color]) => ({
    label: name, data: t.rows.map((r) => (r[key] == null ? null : Math.round(r[key] * 10) / 10)),
    borderColor: css(color), backgroundColor: css(color), borderWidth: 2, pointRadius: t.rows.length < 40 ? 3 : 0,
    pointHoverRadius: 5, pointHoverBorderWidth: 2, pointHoverBorderColor: css("--surface"),
    tension: 0.25, spanGaps: true, borderCapStyle: "round", borderJoinStyle: "round",
  }));

  if (!trendChart) {
    Chart.defaults.font.family = css("--font");
    Chart.defaults.color = css("--muted");
    trendChart = new Chart($("trendChart"), {
      type: "line",
      data: { labels, datasets },
      options: {
        responsive: true, maintainAspectRatio: false, animation: false,
        interaction: { mode: "index", intersect: false },
        plugins: {
          legend: { display: false },
          tooltip: {
            backgroundColor: "#262624", borderColor: "rgba(255,255,255,.1)", borderWidth: 1,
            titleColor: css("--text"), bodyColor: css("--text-2"), padding: 10, boxWidth: 10, boxHeight: 3,
            callbacks: { label: (c) => ` ${c.dataset.label}: ${c.parsed.y == null ? "–" : c.parsed.y.toFixed(1) + "%"}` },
          },
        },
        scales: {
          x: { grid: { display: false }, border: { color: css("--axis") }, ticks: { maxRotation: 0, autoSkipPadding: 18 } },
          y: { min: 0, max: 100, grid: { color: css("--grid") }, border: { display: false },
               ticks: { stepSize: 25, callback: (v) => v + "%" } },
        },
      },
      plugins: [crosshair],
    });
  } else {
    trendChart.data.labels = labels;
    trendChart.data.datasets = datasets;
    trendChart.update();
  }
  renderHeat(t);
  renderTrendTable(t, labels);
}

// Vertical crosshair at the hovered index.
const crosshair = {
  id: "crosshair",
  afterDatasetsDraw(chart) {
    const a = chart.tooltip?.getActiveElements?.();
    if (!a || !a.length) return;
    const x = a[0].element.x, { top, bottom } = chart.chartArea, ctx = chart.ctx;
    ctx.save(); ctx.strokeStyle = css("--axis"); ctx.lineWidth = 1;
    ctx.beginPath(); ctx.moveTo(x, top); ctx.lineTo(x, bottom); ctx.stroke(); ctx.restore();
  },
};

const SEQ = ["--seq-1", "--seq-2", "--seq-3", "--seq-4", "--seq-5", "--seq-6", "--seq-7", "--seq-8"];
function heatColor(v) {
  if (v == null) return css("--surface-3");
  if (v < 1) return css("--surface-2");
  return css(SEQ[Math.min(SEQ.length - 1, Math.floor((v / 100) * SEQ.length))]);
}

function renderHeat(t) {
  $("heatRamp").innerHTML = SEQ.map((s) => `<i style="background:var(${s})"></i>`).join("");
  const keyOf = (r) => r.label || r.ts;
  const cols = [...new Set(t.gpus.map(keyOf))];
  const idx = [...new Set(t.gpus.map((g) => g.gpu_index))].sort((a, b) => a - b);
  const map = new Map(t.gpus.map((g) => [`${g.gpu_index}|${keyOf(g)}`, g.util]));
  const colLabels = cols.map((c) => labelFor(typeof c === "number" ? { ts: c } : { label: c }, t.kind));
  $("heat").innerHTML = idx.map((i) => `<div class="heat-row"><span class="lab">GPU ${i}</span>
    <div class="heat-cells" style="grid-template-columns:repeat(${cols.length},1fr)">${cols.map((c, j) => {
      const v = map.get(`${i}|${c}`);
      return `<i data-g="${i}" data-l="${esc(colLabels[j])}" data-v="${v == null ? "" : v.toFixed(1)}" style="background:${heatColor(v)}"></i>`;
    }).join("")}</div></div>`).join("") || `<div class="empty">No GPU history yet</div>`;
}
$("heat").addEventListener("mousemove", (e) => {
  const c = e.target.closest("i[data-g]");
  if (!c) return hideTip();
  showTip(e, `<b>GPU ${c.dataset.g}</b>${esc(c.dataset.l)}<br>${c.dataset.v === "" ? "no data" : c.dataset.v + "% avg utilization"}`);
});
$("heat").addEventListener("mouseleave", hideTip);

function renderTrendTable(t, labels) {
  const f = (v) => (v == null ? "–" : v.toFixed(1));
  $("trendTable").innerHTML = `<thead><tr><th>Period</th><th class="num">CPU %</th><th class="num">RAM %</th><th class="num">GPU %</th><th class="num">GPU VRAM %</th></tr></thead><tbody>` +
    t.rows.map((r, i) => `<tr><td>${esc(labels[i])}</td><td class="num">${f(r.cpu)}</td><td class="num">${f(r.ram)}</td><td class="num">${f(r.gpu)}</td><td class="num">${f(r.gpu_mem)}</td></tr>`).reverse().join("") + "</tbody>";
}

$("rangeSeg").addEventListener("click", (e) => {
  const b = e.target.closest("button[data-r]");
  if (!b) return;
  range = b.dataset.r;
  for (const x of $("rangeSeg").children) x.classList.toggle("on", x === b);
  loadTrends().catch((err) => toast(err.message, true));
});

// ------------------------------------------------------------ processes & alerts
let procCache = {};

async function loadProcesses(refresh = false) {
  const p = await api(`/api/processes${refresh ? "?refresh=1" : ""}`);
  procCache = {};
  for (const r of [...(p.gpu_procs || []), ...(p.flagged || [])]) procCache[r.pid] = r;

  gpuOwners = {};
  for (const r of p.gpu_procs || []) for (const [i, g] of Object.entries(r.gpus)) if (g.mem_mb >= 256) {
    (gpuOwners[i] ||= []).includes(r.username) || gpuOwners[i].push(r.username);
  }
  if (lastOverview) renderGpus(lastOverview.live.gpus || []);

  // VM workers can't be killed safely (see processes.VM_WORKERS); offer session log-off instead.
  const killBtn = (r) => r.vm
    ? `<span class="muted" title="GPU work inside WSL. Killing the VM can corrupt the user's Linux disk: ask them to run 'wsl --shutdown', or log off their session.">WSL VM</span>`
    : `<button class="btn sm danger" data-kill="${r.pid}">Terminate</button>`;

  // GPU processes table
  $("procRows").innerHTML = (p.gpu_procs || []).map((r) => {
    const gl = Object.entries(r.gpus).filter(([, g]) => g.mem_mb >= 1)
      .map(([i, g]) => `${i} <span class="muted">(${(g.mem_mb / 1024).toFixed(1)}G${g.util ? ", " + g.util + "%" : ""})</span>`).join(", ");
    return `<tr><td><b>${esc(r.username)}</b></td>
      <td>${esc(r.name)}${r.children ? ` <span class="muted">+${r.children} workers</span>` : ""}<span class="cmd" title="${esc(r.cmdline)}">${esc(r.cmdline)}</span></td>
      <td class="num">${r.pid}</td><td>${gl || "–"}</td><td class="num">${(r.gpu_mem_mb / 1024).toFixed(1)} GB</td>
      <td class="num">${Math.round(r.cpu_pct)}%</td><td class="num">${(r.rss_mb / 1024).toFixed(1)} GB</td>
      <td class="num">${dur(r.runtime_h * 3600)}</td><td>${esc(r.session_state)} <span class="muted">#${r.session_id}</span></td>
      <td class="admin-only">${killBtn(r)}</td></tr>`;
  }).join("") || emptyRow(10, "No processes are using GPU memory");

  // Alerts grouped by user
  const flagged = p.flagged || [];
  flaggedCount = flagged.length;
  const high = flagged.filter((f) => f.severity === "high").length, med = flagged.filter((f) => f.severity === "medium").length;
  $("kFlag").textContent = flagged.length;
  $("fFlag").innerHTML = flagged.length ? `${high} high · ${med} medium · ${flagged.length - high - med} low` : "Nothing flagged";
  $("alertSub").textContent = `Last scan ${p.ts ? new Date(p.ts * 1000).toLocaleTimeString() : "–"} · orphaned, detached, idle or resource-heavy compute jobs`;

  const byUser = {};
  for (const f of flagged) (byUser[f.username] ||= []).push(f);
  const sevRank = { high: 3, medium: 2, low: 1 };
  const users = Object.entries(byUser).sort((a, b) =>
    Math.max(...b[1].map((f) => sevRank[f.severity])) - Math.max(...a[1].map((f) => sevRank[f.severity])));
  $("alertList").innerHTML = users.map(([u, items]) => {
    const top = items.reduce((m, f) => (sevRank[f.severity] > sevRank[m] ? f.severity : m), "low");
    const vram = items.reduce((s, f) => s + f.gpu_mem_mb, 0);
    return `<div class="alert-user"><header>${badge(top, top)}<b>${esc(u)}</b>
        <span class="muted">${items.length} process${items.length > 1 ? "es" : ""}${vram ? ` · ${(vram / 1024).toFixed(1)} GB VRAM` : ""}</span></header>
      ${items.map((f) => `<div class="alert-item">
        <div><b>${esc(f.name)}</b> <span class="muted">PID ${f.pid} · ${dur(f.runtime_h * 3600)} · ${Math.round(f.cpu_pct)}% CPU · ${(f.rss_mb / 1024).toFixed(1)} GB RAM</span>
          <div class="reasons">${f.reasons.map(esc).join(" · ")}</div>
          <span class="cmd" title="${esc(f.cmdline)}">${esc(f.cmdline)}</span></div>
        <div class="admin-only">${killBtn(f)}</div>
      </div>`).join("")}</div>`;
  }).join("") || `<div class="empty">${badge("good", "All clear")} No rogue or orphaned compute processes detected.</div>`;
  applyRole();
}

document.addEventListener("click", async (e) => {
  const k = e.target.closest("[data-kill]");
  if (k) {
    const r = procCache[k.dataset.kill];
    if (!r) return;
    const ok = await confirmDlg("Terminate process?",
      `<p><b>${esc(r.name)}</b> (PID ${r.pid}) owned by <b>${esc(r.username)}</b>${r.children ? ` and its ${r.children} worker processes` : ""} will be stopped. Unsaved work in that job is lost.</p>
       <p class="muted" style="word-break:break-all">${esc(r.cmdline)}</p>`, "Terminate");
    if (!ok) return;
    try {
      const res = await api(`/api/processes/${r.pid}/terminate`, { method: "POST", body: JSON.stringify({ create_time: r.create_time, tree: true }) });
      toast(res.message);
      setTimeout(() => loadProcesses(true).catch(() => {}), 1500);
    } catch (err) { toast(err.message, true); }
    return;
  }
  const l = e.target.closest("[data-logoff]");
  if (l) {
    const ok = await confirmDlg("Log off session?",
      `<p>Session ${esc(l.dataset.logoff)} of <b>${esc(l.dataset.user)}</b> will be logged off. <b>Every program in that session closes</b>, including running training jobs.</p>`, "Log off");
    if (!ok) return;
    try {
      const res = await api(`/api/sessions/${l.dataset.logoff}/logoff`, { method: "POST" });
      toast(res.message);
      setTimeout(() => loadOverview().catch(() => {}), 2000);
    } catch (err) { toast(err.message, true); }
    return;
  }
  const d = e.target.closest("[data-delpolicy]");
  if (d) {
    const ok = await confirmDlg("Remove quota policy?", `<p>${esc(d.dataset.desc)}</p><p class="muted">Limits set by this policy are lifted right away.</p>`, "Remove");
    if (!ok) return;
    try { await api(`/api/quota/policies/${d.dataset.delpolicy}`, { method: "DELETE" }); toast("Policy removed"); loadQuota(); }
    catch (err) { toast(err.message, true); }
  }
});

$("refreshProcs").addEventListener("click", () => loadProcesses(true).catch((e) => toast(e.message, true)));

// ------------------------------------------------------------ restarts
async function loadRestarts() {
  const rows = await api("/api/restarts");
  $("restartRows").innerHTML = rows.map((r) => {
    const kind = r.kind === "Unexpected" ? (r.cause.startsWith("System crash") ? "critical" : "serious") : r.kind.startsWith("Planned") ? "good" : "";
    const down = r.shutdown_ts ? `${dt(r.shutdown_ts)} <span class="muted">(${dur(r.boot_ts - r.shutdown_ts)} down)</span>` : "–";
    const detail = [r.cause, r.reason, r.process, r.comment && `“${r.comment}”`].filter(Boolean).map(esc).join("<br><span class='muted'>") ;
    return `<tr><td>${dt(r.boot_ts, true)}</td><td>${down}</td><td>${badge(kind, r.kind)}</td><td>${detail}</td><td>${esc(r.username || "–")}</td></tr>`;
  }).join("") || emptyRow(5, "No restarts recorded yet");
}

// ------------------------------------------------------------ storage
const qKind = { ok: "good", warning: "warning", grace: "serious", blocked: "critical", "over-hard": "critical",
                "vm-protected": "warning", "not-enforced": "critical" };

async function loadStorage() {
  const s = await api("/api/storage");
  const max = Math.max(1, ...s.homes.map((h) => h.size_bytes));
  const ntfsBy = {};
  for (const n of s.ntfs) (ntfsBy[n.username.toLowerCase()] ||= []).push(n);
  const qBy = {};
  for (const q of s.quota) (qBy[q.username.toLowerCase()] ||= []).push(q);
  const total = s.homes.reduce((a, h) => a + h.size_bytes, 0);
  const ts = s.homes[0]?.ts;
  $("storageSub").textContent = ts
    ? `Scanned ${dt(ts)} · ${s.homes.length} profile folders · ${(total / 1024 ** 4).toFixed(2)} TB total${s.scan.running ? " · scan running…" : ""}`
    : (s.scan.running ? "First scan running…" : "No scan yet");

  $("storageRows").innerHTML = s.homes.map((h) => {
    const key = h.username.replace(/ \(no account\)$/, "").toLowerCase();
    const n = (ntfsBy[key] || []).map((x) => `${x.volume} ${gb(x.used_bytes)}`).join("<br>") || "<span class='muted'>–</span>";
    const q = (qBy[key] || []).map((x) => `${badge(qKind[x.status] || "", x.status)} <span class="muted">${x.volume}${x.soft_bytes ? " · soft " + gb(x.soft_bytes, 0) : ""}${x.enforced_limit ? " · limit " + gb(x.enforced_limit, 0) : ""}</span>`).join("<br>") || "<span class='muted'>no policy</span>";
    const w = (h.size_bytes / max) * 100;
    return `<tr><td>${esc(h.username)}${h.error ? ` <span class="muted" title="${esc(h.error)}">⚠</span>` : ""}</td>
      <td class="num">${gb(h.size_bytes)}</td>
      <td class="bar-cell"><div class="meter" style="margin-top:6px"><span style="width:${w}%"></span></div></td>
      <td class="num">${compact(h.file_count)}</td><td class="num">${n}</td><td>${q}</td></tr>`;
  }).join("") || emptyRow(6, s.scan.running ? "Scanning home folders…" : "No storage data yet");
}

$("rescanStorage").addEventListener("click", async () => {
  try { await api("/api/jobs/storage/run", { method: "POST" }); toast("Storage scan started; takes about a minute."); }
  catch (e) { toast(e.message, true); }
});

// ------------------------------------------------------------ quota admin
async function loadQuota() {
  if (!ME.is_admin) return;
  const q = await api("/api/quota");
  const tSel = $("qTarget"), cur = tSel.value;
  tSel.innerHTML = `<option value="*">All non-admin users</option>` + q.users.map((u) => `<option>${esc(u)}</option>`).join("");
  tSel.value = cur || "*";
  const vSel = $("qVolume"), vcur = vSel.value;
  vSel.innerHTML = Object.keys(q.volumes).map((v) => `<option>${esc(v)}</option>`).join("");
  if (vcur) vSel.value = vcur;
  $("volStatus").innerHTML = Object.entries(q.volumes).map(([v, st]) =>
    `${esc(v)} ${st.enforced ? badge("warning", "enforcing") : st.enabled ? badge("good", "tracking") : badge("", "quotas off")}` +
    (st.enabled && !st.defaults_ok ? ` ${badge("critical", "default limit is not 'No limit'")}` : "")).join(" &nbsp; ");

  const modeLabel = { soft: "Soft (warn)", hard: "Hard", grace: "Soft + grace" };
  $("policyRows").innerHTML = q.policies.map((p) => `<tr><td><b>${p.target === "*" ? "All non-admin users" : esc(p.target)}</b></td>
    <td>${esc(p.volume)}</td><td>${modeLabel[p.mode] || esc(p.mode)}</td>
    <td class="num">${p.soft_gb ? p.soft_gb + " GB" : "–"}</td><td class="num">${p.hard_gb ? p.hard_gb + " GB" : "–"}</td>
    <td class="num">${p.mode === "grace" ? p.grace_days + " d" : "–"}</td><td>${esc(p.created_by)} <span class="muted">${dt(p.created_ts)}</span></td>
    <td><button class="btn sm danger" data-delpolicy="${p.id}" data-desc="${esc((p.target === "*" ? "All users" : p.target) + " on " + p.volume)}">Remove</button></td></tr>`).join("")
    || emptyRow(8, "No quota policies. Nothing is limited.");

  $("qStateRows").innerHTML = q.status.map((s) => `<tr><td>${esc(s.username)}</td><td>${esc(s.volume)}</td>
    <td>${badge(qKind[s.status] || "", s.status)}</td><td class="num">${gb(s.usage_bytes)}</td>
    <td class="num">${s.soft_bytes ? gb(s.soft_bytes, 0) : "–"}</td><td class="num">${s.enforced_limit ? gb(s.enforced_limit, 0) : "none"}</td>
    <td>${s.over_since ? dt(s.over_since) : "–"}</td><td class="muted">${esc(s.note || "")}</td></tr>`).join("") || emptyRow(8, "No users under a policy yet");
}

// What saving a policy would do right now, from /api/quota/preview.
function previewHtml(body, p) {
  const who = body.target === "*" ? "all non-admin users" : body.target;
  const names = (rows, extra = () => "") => rows.map((r) => `${esc(r.user)} (${r.usage_gb} GB${extra(r)})`).join(", ");
  const section = (title, text) => `<p><b>${title}</b><br><span class="muted">${text}</span></p>`;
  let html = `<p>Apply to <b>${esc(who)}</b> on <b>${esc(body.volume)}</b>: ${p.total} account${p.total === 1 ? "" : "s"}.</p>`;
  if (p.volume_problem) html += `<p>${badge("critical", "Not enforced")} ${esc(p.volume_problem)}</p>`;
  if (p.blocked_now.length) html += section(`${badge("critical", "Blocked as soon as you save")}`,
    `${names(p.blocked_now)}. They are already at or over the limit and will be unable to write new data on ${esc(body.volume)}; a job writing at that moment can fail.`);
  if (p.grace.length) html += section(`${badge("serious", "Grace period")}`, names(p.grace, (r) => `, blocked from ${dt(r.until)}`));
  if (p.warned.length) html += section(`${badge("warning", "Warned only")}`, names(p.warned));
  if (p.vm_protected.length) html += section(`${badge("warning", "WSL/Docker disk on this drive")}`,
    `${names(p.vm_protected)}. Warned, never blocked, so their Linux disk is not damaged.`);
  if (p.exempt.length) html += section("Not covered", `${p.exempt.map(esc).join(", ")} (administrators, service accounts, exempt list).`);
  if (p.overridden.length) html += section("Own policy", `${p.overridden.map(esc).join(", ")} keep their user-specific policy.`);
  if (body.mode !== "soft" && !p.blocked_now.length)
    html += `<p class="muted">Nobody is blocked right now. Users who reach the limit later will be unable to write new data on ${esc(body.volume)}.</p>`;
  return html;
}

$("qMode").addEventListener("change", () => {
  $("quotaForm").grace_days.disabled = $("qMode").value !== "grace";
});

$("quotaForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  const f = new FormData(e.target);
  const num = (k) => (f.get(k) === "" || f.get(k) == null ? null : Number(f.get(k)));
  const body = { target: f.get("target"), volume: f.get("volume"), mode: f.get("mode"),
                 soft_gb: num("soft_gb"), hard_gb: num("hard_gb"), grace_days: num("grace_days") };
  let p;
  try { p = await api("/api/quota/preview", { method: "POST", body: JSON.stringify(body) }); }
  catch (err) { toast(err.message, true); return; }
  const n = p.blocked_now.length;
  const ok = await confirmDlg("Save quota policy?", previewHtml(body, p), n ? `Save and block ${n}` : "Save");
  if (!ok) return;
  try {
    await api("/api/quota/policies", { method: "POST", body: JSON.stringify(body) });
    toast("Policy saved; evaluating now.");
    setTimeout(() => { loadQuota(); loadStorage(); }, 4000);
  } catch (err) { toast(err.message, true); }
});

$("evalQuota").addEventListener("click", async () => {
  try { await api("/api/jobs/quota/run", { method: "POST" }); toast("Quota evaluation started."); setTimeout(loadQuota, 4000); }
  catch (e) { toast(e.message, true); }
});

// ------------------------------------------------------------ audit
async function loadAudit() {
  if (!ME.is_admin) return;
  const rows = await api("/api/audit");
  $("auditRows").innerHTML = rows.map((r) => `<tr><td>${dt(r.ts)}</td><td>${esc(r.actor)}</td><td>${esc(r.ip)}</td>
    <td>${r.ok ? "" : badge("critical", "failed") + " "}${esc(r.action)}</td><td>${esc(r.target)}</td><td class="sec">${esc(r.detail)}</td></tr>`).join("")
    || emptyRow(6, "No entries");
}

// ------------------------------------------------------------ boot
function applyRole() {
  for (const el of document.querySelectorAll(".admin-only")) el.classList.toggle("hidden", !ME.is_admin);
}

$("logout").addEventListener("click", async () => {
  await api("/api/logout", { method: "POST" }).catch(() => {});
  location.href = "/login";
});

function every(ms, fn) { const run = () => fn().catch((e) => console.warn(e)); run(); return setInterval(run, ms); }

(async function init() {
  ME = await api("/api/me");
  $("whoName").textContent = ME.user;
  $("whoRole").textContent = ME.is_admin ? "Administrator" : "Viewer";
  $("whoRole").classList.toggle("admin", ME.is_admin);
  if (ME.user === "anonymous") $("logout").textContent = "Sign in";
  applyRole();
  every(15000, loadOverview);
  every(60000, () => loadProcesses(false));
  every(300000, loadTrends);
  every(300000, loadStorage);
  every(600000, loadRestarts);
  every(300000, loadQuota);
  every(120000, loadAudit);
})();
