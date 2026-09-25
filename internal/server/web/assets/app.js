/* SysPulse dashboard — vanilla JS, no external dependencies (CSP: script-src 'self'). */
(() => {
  "use strict";
  const TOKEN = document.querySelector('meta[name="syspulse-token"]').content;
  const $ = (id) => document.getElementById(id);
  const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

  // ---------- formatting ----------
  const fmtBytes = (b) => {
    if (!b) return "0 B";
    const u = ["B", "KB", "MB", "GB", "TB"];
    let i = 0;
    while (b >= 1024 && i < u.length - 1) { b /= 1024; i++; }
    return (b >= 100 || i === 0 ? b.toFixed(0) : b.toFixed(1)) + " " + u[i];
  };
  const fmtPct = (v) => (v ?? 0).toFixed(1) + "%";
  const fmtUptime = (s) => {
    const d = Math.floor(s / 86400), h = Math.floor((s % 86400) / 3600), m = Math.floor((s % 3600) / 60);
    return d ? `${d}d ${h}h` : h ? `${h}h ${m}m` : `${m}m`;
  };
  const fmtTime = (ms) => (ms ? new Date(ms).toLocaleTimeString() : "");
  const fmtDateTime = (t) => { const d = new Date(t); return isNaN(d) ? "" : d.toLocaleString(); };
  const ago = (t) => {
    const s = Math.max(0, (Date.now() - new Date(t).getTime()) / 1000);
    if (s < 60) return Math.floor(s) + "s ago";
    if (s < 3600) return Math.floor(s / 60) + "m ago";
    if (s < 86400) return Math.floor(s / 3600) + "h ago";
    return Math.floor(s / 86400) + "d ago";
  };
  const CATS = {
    "service-crash": "Service crashes", "app-fault": "Application faults", "unexpected-shutdown": "Unexpected shutdowns",
    driver: "Driver issues", disk: "Disk / storage", "windows-update": "Windows Update", power: "Power",
  };

  // ---------- state ----------
  const S = {
    metrics: null, history: [], procs: [], conns: new Map(), netstats: null,
    events: [], evsum: null, evErr: "", netErr: "", software: null, newKeys: new Set(),
  };
  const connKey = (c) => [c.proto, c.localAddr, c.localPort, c.remoteAddr || "", c.remotePort || 0, c.pid].join("|");

  // ---------- tabs ----------
  let active = "overview";
  document.querySelectorAll(".tab").forEach((b) => b.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach((x) => x.classList.toggle("active", x === b));
    active = b.dataset.tab;
    document.querySelectorAll(".panel").forEach((p) => p.classList.toggle("active", p.id === "tab-" + active));
    if (active === "software" && !S.software) loadSoftware();
    renderAll();
  }));

  // ---------- sortable tables ----------
  const sorters = {};
  function sortable(tableId, defKey, defDir, onChange) {
    const st = (sorters[tableId] = { key: defKey, dir: defDir });
    const ths = document.querySelectorAll(`#${tableId} th[data-k]`);
    const mark = () => ths.forEach((th) => {
      th.classList.toggle("sorted-asc", th.dataset.k === st.key && st.dir > 0);
      th.classList.toggle("sorted-desc", th.dataset.k === st.key && st.dir < 0);
    });
    ths.forEach((th) => th.addEventListener("click", () => {
      if (st.key === th.dataset.k) st.dir = -st.dir; else { st.key = th.dataset.k; st.dir = th.classList.contains("num") ? -1 : 1; }
      mark(); onChange();
    }));
    mark();
    return st;
  }
  const cmp = (st) => (a, b) => {
    const x = a[st.key] ?? "", y = b[st.key] ?? "";
    if (typeof x === "number" && typeof y === "number") return (x - y) * st.dir;
    return String(x).localeCompare(String(y), undefined, { numeric: true, sensitivity: "base" }) * st.dir;
  };

  // ---------- canvas charts ----------
  function setupCanvas(c) {
    const dpr = window.devicePixelRatio || 1;
    const w = c.clientWidth, h = c.getAttribute("height") | 0;
    if (c.width !== w * dpr) { c.width = w * dpr; c.height = h * dpr; c.style.height = h + "px"; }
    const g = c.getContext("2d");
    g.setTransform(dpr, 0, 0, dpr, 0, 0);
    g.clearRect(0, 0, w, h);
    return { g, w, h };
  }
  function grid(g, x0, y0, w, h, max, suffix) {
    g.strokeStyle = "#1a2442"; g.fillStyle = "#6b7899"; g.font = "11px Segoe UI, sans-serif"; g.lineWidth = 1;
    for (let i = 0; i <= 4; i++) {
      const y = y0 + h - (h * i) / 4;
      g.beginPath(); g.moveTo(x0, y + 0.5); g.lineTo(x0 + w, y + 0.5); g.stroke();
      g.fillText(Math.round((max * i) / 4) + suffix, 2, y + 4);
    }
  }
  function drawSysChart() {
    const c = $("ch-sys"); if (!c.clientWidth) return;
    const { g, w, h } = setupCanvas(c);
    const x0 = 36, y0 = 8, cw = w - x0 - 6, chh = h - 20;
    grid(g, x0, y0, cw, chh, 100, "%");
    const pts = S.history.slice(-300);
    const line = (key, color) => {
      if (pts.length < 2) return;
      const grad = g.createLinearGradient(0, y0, 0, y0 + chh);
      grad.addColorStop(0, color + "55"); grad.addColorStop(1, color + "00");
      g.beginPath();
      pts.forEach((p, i) => {
        const x = x0 + (cw * i) / (300 - 1) + (cw * (300 - pts.length)) / (300 - 1);
        const y = y0 + chh - (chh * Math.min(100, p[key] || 0)) / 100;
        i ? g.lineTo(x, y) : g.moveTo(x, y);
      });
      g.strokeStyle = color; g.lineWidth = 2; g.stroke();
      const lastX = x0 + cw, firstX = x0 + (cw * (300 - pts.length)) / (300 - 1);
      g.lineTo(lastX, y0 + chh); g.lineTo(firstX, y0 + chh); g.closePath(); g.fillStyle = grad; g.fill();
    };
    line("memPercent", "#a78bfa");
    line("cpu", "#22d3ee");
  }
  function drawEventChart() {
    const c = $("ch-ev"); if (!c.clientWidth || !S.evsum) return;
    const { g, w, h } = setupCanvas(c);
    const tl = S.evsum.timeline || [];
    const max = Math.max(4, ...tl.map((b) => b.critical + b.error + b.warning + b.info));
    const x0 = 36, y0 = 8, cw = w - x0 - 6, chh = h - 26;
    grid(g, x0, y0, cw, chh, max, "");
    const bw = cw / Math.max(1, tl.length);
    tl.forEach((b, i) => {
      let y = y0 + chh;
      [["info", "#3b4a75"], ["warning", "#fbbf24"], ["error", "#f87171"], ["critical", "#e11d48"]].forEach(([k, col]) => {
        const v = b[k]; if (!v) return;
        const hh = (chh * v) / max;
        g.fillStyle = col; g.fillRect(x0 + i * bw + 1, y - hh, Math.max(1, bw - 2), hh); y -= hh;
      });
    });
    g.fillStyle = "#6b7899"; g.font = "11px Segoe UI, sans-serif";
    for (let i = 0; i < tl.length; i += 8) {
      const d = new Date(tl[i].start);
      g.fillText(d.toLocaleDateString(undefined, { weekday: "short", day: "numeric" }), x0 + i * bw, h - 6);
    }
  }
  window.addEventListener("resize", () => { drawSysChart(); drawEventChart(); });

  // ---------- renderers ----------
  function renderOverview() {
    const m = S.metrics; if (!m) return;
    $("host-line").textContent = `${m.hostname} · ${m.os}`;
    $("c-cpu").textContent = fmtPct(m.cpu);
    $("c-cores").textContent = `${m.cores} logical processors`;
    $("c-mem").textContent = fmtPct(m.memPercent);
    $("c-mem2").textContent = `${fmtBytes(m.memUsed)} / ${fmtBytes(m.memTotal)}`;
    $("c-commit").textContent = m.commitTotal ? fmtPct((m.commitUsed / m.commitTotal) * 100) : "–";
    $("c-commit2").textContent = `${fmtBytes(m.commitUsed)} / ${fmtBytes(m.commitTotal)}`;
    $("c-procs").textContent = m.processes;
    $("c-threads").textContent = `${m.threads.toLocaleString()} threads`;
    $("c-up").textContent = fmtUptime(m.uptime);
    if (S.netstats) {
      $("c-socks").textContent = S.netstats.total;
      $("c-rate").textContent = `${S.netstats.newPerSec.toFixed(1)} new/s · ${S.netstats.byState.ESTABLISHED || 0} established`;
    }
    $("disks").innerHTML = (m.disks || []).map((d) => `
      <div class="disk"><div class="row"><span><b>${esc(d.mount)}</b> <span class="muted">${esc(d.type)}</span></span>
      <span class="muted">${fmtBytes(d.free)} free of ${fmtBytes(d.total)}</span></div>
      <div class="meter ${d.percent > 90 ? "hot" : ""}"><i data-w="${d.percent.toFixed(1)}"></i></div></div>`).join("") || '<div class="muted">No volumes</div>';
    applyWidths($("disks"));
    $("top-procs").innerHTML = S.procs.slice(0, 10).map((p) => `
      <tr><td>${esc(p.name)}</td><td class="muted num">${p.pid}</td><td class="num">${fmtPct(p.cpu)}</td><td class="num muted">${fmtBytes(p.workingSet)}</td></tr>`).join("");
    const bad = S.events.filter((e) => e.level >= 1 && e.level <= 3).slice(0, 25);
    $("ov-feed").innerHTML = bad.map((e) => `
      <li><span class="lvl ${e.levelStr}">${e.levelStr}</span> <b>${esc(e.provider)}</b> <span class="muted">#${e.eventId}</span>
      <div class="meta">${ago(e.time)} · ${esc(CATS[e.category] || e.channel)}</div>
      <div>${esc(e.message.slice(0, 180))}</div></li>`).join("") || '<li class="muted">No recent errors or warnings 🎉</li>';
    drawSysChart();
  }

  // CSP forbids inline style attributes; set meter widths through the CSSOM.
  function applyWidths(root) {
    root.querySelectorAll("i[data-w]").forEach((i) => { i.style.width = `${Math.min(100, Math.max(0, +i.dataset.w || 0))}%`; });
  }

  function bars(el, items, total) {
    const max = Math.max(1, ...items.map((i) => i.count));
    el.innerHTML = items.map((i) => `
      <div class="bar"><div class="lbl" title="${esc(i.name)}">${esc(i.name)}<div class="meter"><i data-w="${((100 * i.count) / max).toFixed(1)}"></i></div></div><div class="n">${i.count}</div></div>`).join("")
      || '<div class="muted">—</div>';
    applyWidths(el);
  }

  const netSort = sortable("net-table", "processName", 1, () => renderNetwork());
  const isLoop = (a) => !a || a === "127.0.0.1" || a === "::1";
  function renderNetwork() {
    if (S.netstats) {
      const states = Object.entries(S.netstats.byState).map(([name, count]) => ({ name, count })).sort((a, b) => b.count - a.count);
      bars($("net-states"), states);
      bars($("net-procs"), S.netstats.topProcs || []);
      bars($("net-remotes"), S.netstats.topRemotes || []);
    }
    $("b-net").textContent = S.conns.size;
    if (active !== "network") return;
    const q = $("net-q").value.trim().toLowerCase(), pr = $("net-proto").value, stt = $("net-state").value, hide = $("net-hide-local").checked;
    let rows = [...S.conns.values()].filter((c) =>
      (!pr || c.proto === pr) && (!stt || c.state === stt) &&
      (!hide || !(isLoop(c.localAddr) && isLoop(c.remoteAddr))) &&
      (!q || `${c.processName} ${c.pid} ${c.localAddr}:${c.localPort} ${c.remoteAddr}:${c.remotePort} ${c.state} ${c.proto}`.toLowerCase().includes(q)));
    rows.sort(cmp(netSort));
    const shown = rows.slice(0, 2000);
    $("net-table").tBodies[0].innerHTML = shown.map((c) => `
      <tr class="${S.newKeys.has(connKey(c)) ? "new" : ""}"><td class="mono">${c.proto}</td><td title="${esc(c.processPath)}">${esc(c.processName)}</td><td class="num mono">${c.pid}</td>
      <td class="mono">${esc(c.localAddr)}</td><td class="num mono">${c.localPort}</td><td class="mono">${esc(c.remoteAddr || "")}</td>
      <td class="num mono">${c.remotePort || ""}</td><td>${c.state === "-" ? "" : `<span class="state ${c.state}">${c.state}</span>`}</td><td class="muted">${fmtTime(c.firstSeen)}</td></tr>`).join("");
    $("net-foot").textContent = `${rows.length} of ${S.conns.size} sockets${rows.length > shown.length ? " (first 2000 shown)" : ""}` + (S.netErr ? ` · error: ${S.netErr}` : "");
  }

  const procSort = sortable("proc-table", "cpu", -1, () => renderProcesses());
  function renderProcesses() {
    $("b-proc").textContent = S.procs.length;
    if (active !== "processes") return;
    const q = $("proc-q").value.trim().toLowerCase();
    const rows = S.procs.filter((p) => !q || `${p.name} ${p.pid} ${p.path || ""}`.toLowerCase().includes(q)).sort(cmp(procSort));
    $("proc-table").tBodies[0].innerHTML = rows.map((p) => `
      <tr><td>${esc(p.name)}</td><td class="num mono">${p.pid}</td><td class="num mono muted">${p.ppid}</td>
      <td class="num">${p.access ? fmtPct(p.cpu) : '<span class="muted">n/a</span>'}</td><td class="num">${p.access ? fmtBytes(p.workingSet) : ""}</td>
      <td class="num muted">${p.access ? fmtBytes(p.private) : ""}</td><td class="num muted">${p.threads}</td>
      <td class="muted">${p.started ? new Date(p.started).toLocaleString() : ""}</td><td class="path mono" title="${esc(p.path)}">${esc(p.path || (p.access ? "" : "access denied (protected process)"))}</td></tr>`).join("");
    $("proc-foot").textContent = `${rows.length} of ${S.procs.length} processes · processes marked n/a are protected and require elevation to inspect`;
  }

  function renderEvents() {
    const sum = S.evsum;
    const errs = (sum?.byLevel?.critical || 0) + (sum?.byLevel?.error || 0);
    $("b-ev").textContent = errs;
    if (active !== "events") return;
    const catSel = $("ev-cat");
    if (catSel.options.length === 1) Object.entries(CATS).forEach(([k, v]) => catSel.add(new Option(v, k)));
    $("ev-cats").innerHTML = Object.entries(CATS).map(([k, v]) => `
      <div class="c ${catSel.value === k ? "sel" : ""}" data-cat="${k}"><div class="n">${sum?.byCategory?.[k] || 0}</div><div class="t">${v}</div></div>`).join("");
    const errBox = $("ev-err");
    errBox.hidden = !S.evErr; errBox.textContent = S.evErr ? "Event log: " + S.evErr : "";
    const q = $("ev-q").value.trim().toLowerCase(), lv = $("ev-level").value, cat = catSel.value;
    const rows = S.events.filter((e) => (!lv || e.levelStr === lv) && (!cat || e.category === cat) &&
      (!q || `${e.provider} ${e.message} ${e.eventId}`.toLowerCase().includes(q)));
    const shown = rows.slice(0, 1500);
    $("ev-table").tBodies[0].innerHTML = shown.map((e) => `
      <tr><td class="muted" title="${esc(e.time)}">${fmtDateTime(e.time)}</td><td><span class="lvl ${e.levelStr}">${e.levelStr}</span></td>
      <td class="cat">${e.category === "other" ? "" : esc(CATS[e.category] || e.category)}</td><td>${esc(e.provider)}</td>
      <td class="num mono">${e.eventId}</td><td class="muted">${esc(e.channel)}</td><td class="msg">${esc(e.message)}</td></tr>`).join("");
    $("ev-foot").textContent = `${rows.length} of ${S.events.length} events${rows.length > shown.length ? " (first 1500 shown)" : ""}`;
    drawEventChart();
  }
  $("ev-cats").addEventListener("click", (ev) => {
    const c = ev.target.closest(".c"); if (!c) return;
    $("ev-cat").value = $("ev-cat").value === c.dataset.cat ? "" : c.dataset.cat;
    renderEvents();
  });

  const appSort = sortable("app-table", "name", 1, () => renderSoftware());
  function renderSoftware() {
    const sw = S.software;
    const n = sw?.upgrades?.length;
    $("b-sw").textContent = n == null ? "–" : n;
    if (active !== "software" || !sw) return;
    const checking = sw.checking;
    $("sw-refresh").disabled = checking;
    $("sw-refresh").innerHTML = checking ? '<span class="spin"></span> Checking…' : "Check for updates";
    $("sw-when").textContent = sw.upgradesAt && !sw.upgradesAt.startsWith("0001") ? `· checked ${ago(sw.upgradesAt)}` : "· not checked yet";
    const e = $("sw-err");
    const msg = [sw.upgradesError, sw.appsError].filter(Boolean).join(" · ");
    e.hidden = !msg; e.textContent = msg;
    const busy = new Set(sw.upgrading || []);
    $("up-table").tBodies[0].innerHTML = (sw.upgrades || []).map((u) => `
      <tr><td>${esc(u.name)}</td><td class="mono">${esc(u.id)}</td><td class="mono">${esc(u.version)}</td><td class="mono upd">${esc(u.available)}</td>
      <td class="muted">${esc(u.source)}</td><td class="cmd" title="Click to copy" data-copy="${esc(u.command)}">${esc(u.command)}</td>
      <td>${busy.has(u.id) ? '<span class="spin"></span> upgrading…' : `<button class="btn small" data-upgrade="${esc(u.id)}">Upgrade</button>`}</td></tr>`).join("")
      || `<tr><td colspan="7" class="muted">${checking ? "Running winget…" : sw.upgradesAt && !sw.upgradesAt.startsWith("0001") ? "Everything is up to date." : 'Press “Check for updates” to query winget.'}</td></tr>`;
    $("sw-results").innerHTML = (sw.results || []).slice(0, 5).map((r) => `
      <details class="result"><summary><span class="${r.ok ? "ok-t" : "bad-t"}">${r.ok ? "✔" : "✖"}</span> ${esc(r.id)} <span class="muted">${fmtDateTime(r.finished)}</span></summary><pre>${esc(r.output)}</pre></details>`).join("");
    const q = $("app-q").value.trim().toLowerCase(), onlyUpd = $("app-upd").checked;
    const apps = (sw.apps || []).filter((a) => (!onlyUpd || a.available) && (!q || `${a.name} ${a.publisher}`.toLowerCase().includes(q))).sort(cmp(appSort));
    $("app-count").textContent = `(${apps.length} of ${(sw.apps || []).length})`;
    $("app-table").tBodies[0].innerHTML = apps.map((a) => `
      <tr><td>${esc(a.name)}</td><td class="mono">${esc(a.version)}</td><td class="mono upd">${esc(a.available || "")}</td><td class="muted">${esc(a.publisher)}</td>
      <td class="muted">${esc(a.installDate)}</td><td class="num muted">${a.sizeKB ? fmtBytes(a.sizeKB * 1024) : ""}</td><td class="muted">${esc(a.scope)}</td></tr>`).join("");
  }

  let raf = 0;
  function renderAll() {
    if (raf) return;
    raf = requestAnimationFrame(() => {
      raf = 0;
      renderOverview(); renderNetwork(); renderProcesses(); renderEvents(); renderSoftware();
    });
  }
  ["net-q", "net-proto", "net-state", "net-hide-local", "proc-q", "ev-q", "ev-level", "ev-cat", "app-q", "app-upd"].forEach((id) =>
    $(id).addEventListener("input", renderAll));

  // ---------- API ----------
  async function api(path, opts = {}) {
    const r = await fetch(path, { ...opts, headers: { "Content-Type": "application/json", "X-SysPulse-Token": TOKEN, ...(opts.headers || {}) } });
    const body = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(body.error || r.statusText);
    return body;
  }
  function toast(msg) {
    const t = $("toast"); t.textContent = msg; t.hidden = false;
    clearTimeout(toast.t); toast.t = setTimeout(() => (t.hidden = true), 3500);
  }
  async function loadSoftware() {
    try { S.software = await api("/api/software"); renderAll(); } catch (e) { toast("Software inventory failed: " + e.message); }
  }
  $("sw-refresh").addEventListener("click", async () => {
    try {
      await api("/api/software/refresh", { method: "POST", body: "{}" });
      if (S.software) S.software.checking = true;
      renderAll(); toast("Checking for updates with winget…");
    } catch (e) { toast("Refresh failed: " + e.message); }
  });
  document.addEventListener("click", async (ev) => {
    const up = ev.target.closest("[data-upgrade]");
    if (up) {
      const id = up.dataset.upgrade;
      if (!confirm(`Upgrade ${id} silently with winget?`)) return;
      try {
        await api("/api/software/upgrade", { method: "POST", body: JSON.stringify({ id }) });
        toast(`Upgrading ${id}…`);
      } catch (e) { toast(`Upgrade failed: ${e.message}`); }
      return;
    }
    const cp = ev.target.closest("[data-copy]");
    if (cp) {
      navigator.clipboard?.writeText(cp.dataset.copy).then(() => toast("Command copied to clipboard"));
    }
  });

  // ---------- WebSocket ----------
  let ws, retry = 500;
  function setConn(state, text) {
    $("conn-dot").className = "dot " + state; $("conn-text").textContent = text;
  }
  function connect() {
    ws = new WebSocket(`${location.protocol === "https:" ? "wss" : "ws"}://${location.host}/ws?token=${encodeURIComponent(TOKEN)}`);
    ws.onopen = () => { retry = 500; setConn("on", "live"); };
    ws.onclose = () => {
      setConn("off", "disconnected — retrying");
      setTimeout(connect, retry); retry = Math.min(retry * 2, 10000);
    };
    ws.onmessage = (m) => {
      const msg = JSON.parse(m.data);
      const d = msg.data;
      switch (msg.type) {
        case "snapshot":
          S.metrics = d.metrics; S.history = d.history || []; S.procs = d.processes || [];
          S.conns = new Map((d.connections || []).map((c) => [connKey(c), c]));
          S.netstats = d.netstats; S.events = d.events || []; S.evsum = d.eventsummary;
          S.evErr = d.eventError || ""; S.netErr = d.netError || "";
          break;
        case "metrics":
          S.metrics = d; S.history.push(d); if (S.history.length > 300) S.history.shift();
          break;
        case "processes": S.procs = d || []; break;
        case "netstats": S.netstats = d; break;
        case "netdiff":
          S.newKeys = new Set();
          (d.removed || []).forEach((k) => S.conns.delete(k));
          (d.added || []).forEach((c) => { const k = connKey(c); S.conns.set(k, c); S.newKeys.add(k); });
          (d.changed || []).forEach((c) => S.conns.set(connKey(c), c));
          break;
        case "events":
          S.events = (d || []).concat(S.events).slice(0, 5000);
          break;
        case "eventsummary": S.evsum = d; break;
        case "software": S.software = d; break;
      }
      renderAll();
    };
  }
  connect();
})();
