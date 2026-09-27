/* SysPulse 3.0 dashboard — vanilla JS, no external dependencies (CSP: script-src 'self'). */
(() => {
  "use strict";
  const TOKEN = document.querySelector('meta[name="syspulse-token"]').content;
  const MODE = (document.querySelector('meta[name="syspulse-mode"]') || {}).content || "live";
  const $ = (id) => document.getElementById(id);
  const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const { t, tx } = window.I18N;
  const L = () => window.I18N.locale();

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
  const fmtTime = (ms) => (ms ? new Date(ms).toLocaleTimeString(L()) : "");
  const fmtDateTime = (v) => { const d = new Date(v); return isNaN(d) || d.getFullYear() < 1971 ? "" : d.toLocaleString(L()); };
  const fmtStamp = (v) => { const d = new Date(v); return isNaN(d) ? "" : d.toLocaleString(L(), { hour12: false }) + "." + String(d.getMilliseconds()).padStart(3, "0"); };
  const ago = (v) => {
    const s = Math.max(0, (Date.now() - new Date(v).getTime()) / 1000);
    if (s < 60) return t("ago.s", { n: Math.floor(s) });
    if (s < 3600) return t("ago.m", { n: Math.floor(s / 60) });
    if (s < 86400) return t("ago.h", { n: Math.floor(s / 3600) });
    return t("ago.d", { n: Math.floor(s / 86400) });
  };
  // Wrap LTR tokens (IPs, MACs, ports, paths) so they render correctly inside RTL text.
  const ltr = (s) => `<bdi dir="ltr">${esc(s)}</bdi>`;
  const CAT_KEYS = ["service-crash", "app-fault", "unexpected-shutdown", "driver", "disk", "windows-update", "power"];
  const ACATS = ["network-sweep", "authentication", "reliability", "resource", "system"];
  const catName = (k) => t("cat." + k);
  const sevName = (s) => t("sev." + s);
  // Event levels arrive as "error", "Error" or "ERROR" depending on the
  // source; normalise once so filters, badges and translations always match.
  const LVLS = ["critical", "error", "warning", "info", "verbose"];
  const lvlKey = (e) => {
    const s = String(e.levelStr || "").toLowerCase();
    if (LVLS.includes(s)) return s;
    return ({ 1: "critical", 2: "error", 3: "warning", 5: "verbose" })[e.level] || "info";
  };
  const lvlName = (l) => t("lvl." + String(l || "info").toLowerCase());
  const normEvent = (e) => { e.levelStr = lvlKey(e); if (!e.category) e.category = "other"; e._t = new Date(e.time).getTime() || 0; return e; };
  const dtLocalMs = (id) => { const v = $(id).value; if (!v) return 0; const ms = new Date(v).getTime(); return isNaN(ms) ? 0 : ms; };
  const copyText = (txt, okKey) => {
    const done = () => toast(t(okKey || "act.copied"));
    if (navigator.clipboard && window.isSecureContext) { navigator.clipboard.writeText(txt).then(done, () => fallbackCopy(txt, done)); } else fallbackCopy(txt, done);
  };
  function fallbackCopy(txt, done) {
    const ta = document.createElement("textarea");
    ta.value = txt; ta.setAttribute("readonly", ""); ta.className = "offscreen";
    document.body.appendChild(ta); ta.select();
    try { document.execCommand("copy"); done(); } catch (_) { toast(t("act.copyFailed")); }
    ta.remove();
  }

  // ---------- state ----------
  const S = {
    metrics: null, history: [], procs: [], conns: new Map(), netstats: null,
    events: [], evsum: null, evErr: "", netErr: "", software: null, newKeys: new Set(),
    radar: null, alerts: [], acounts: null, audit: { available: false, running: [], reports: {} },
    banner: [], // active sweep incidents shown in the banner (newest first)
    devices: [], selfTest: false,
  };
  const connKey = (c) => [c.proto, c.localAddr, c.localPort, c.remoteAddr || "", c.remotePort || 0, c.pid].join("|");

  // ---------- tabs ----------
  let active = "overview";
  function showTab(name) {
    active = name;
    document.querySelectorAll(".tab").forEach((x) => x.classList.toggle("active", x.dataset.tab === name));
    document.querySelectorAll(".panel").forEach((p) => p.classList.toggle("active", p.id === "tab-" + name));
    if (name === "software" && !S.software) loadSoftware();
    if (name === "guide") renderGuide();
    renderAll();
  }
  document.querySelectorAll(".tab").forEach((b) => b.addEventListener("click", () => showTab(b.dataset.tab)));
  document.querySelectorAll("[data-goto]").forEach((c) => c.addEventListener("click", () => showTab(c.dataset.goto)));

  // ---------- sortable tables ----------
  function sortable(tableId, defKey, defDir, onChange) {
    const st = { key: defKey, dir: defDir };
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
  const rtl = () => document.documentElement.dir === "rtl";
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
    g.strokeStyle = "#1a2442"; g.fillStyle = "#6b7899"; g.font = "11px Segoe UI, Tahoma, sans-serif"; g.lineWidth = 1;
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
        const x = x0 + (cw * i) / 299 + (cw * (300 - pts.length)) / 299;
        const y = y0 + chh - (chh * Math.min(100, p[key] || 0)) / 100;
        i ? g.lineTo(x, y) : g.moveTo(x, y);
      });
      g.strokeStyle = color; g.lineWidth = 2; g.stroke();
      g.lineTo(x0 + cw, y0 + chh); g.lineTo(x0 + (cw * (300 - pts.length)) / 299, y0 + chh); g.closePath(); g.fillStyle = grad; g.fill();
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
    g.fillStyle = "#6b7899"; g.font = "11px Segoe UI, Tahoma, sans-serif";
    for (let i = 0; i < tl.length; i += 8) {
      g.fillText(new Date(tl[i].start).toLocaleDateString(L(), { weekday: "short", day: "numeric" }), x0 + i * bw, h - 6);
    }
  }
  function drawRadarChart() {
    const c = $("ch-radar"); if (!c.clientWidth || !S.radar) return;
    const { g, w, h } = setupCanvas(c);
    const series = S.radar.series || [];
    const max = Math.max(5, ...series);
    const x0 = 36, y0 = 8, cw = w - x0 - 6, chh = h - 22;
    grid(g, x0, y0, cw, chh, max, "");
    const bw = cw / 60;
    series.forEach((v, i) => {
      if (!v) return;
      const hh = (chh * v) / max;
      g.fillStyle = v > S.radar.threshold ? "#f43f5e" : "#22d3ee";
      g.fillRect(x0 + i * bw + 1, y0 + chh - hh, Math.max(1, bw - 2), hh);
    });
    g.fillStyle = "#6b7899";
    g.fillText("-60s", x0, h - 6); g.fillText("0s", x0 + cw - 14, h - 6);
  }
  window.addEventListener("resize", () => { drawSysChart(); drawEventChart(); drawRadarChart(); });

  // CSP forbids inline style attributes; set meter widths through the CSSOM.
  function applyWidths(root) {
    root.querySelectorAll("i[data-w]").forEach((i) => { i.style.width = `${Math.min(100, Math.max(0, +i.dataset.w || 0))}%`; });
  }
  function bars(el, items) {
    const max = Math.max(1, ...items.map((i) => i.count));
    el.innerHTML = items.map((i) => `
      <div class="bar"><div class="lbl" title="${esc(i.name)}">${esc(i.name)}<div class="meter"><i data-w="${((100 * i.count) / max).toFixed(1)}"></i></div></div><div class="n">${i.count}</div></div>`).join("")
      || '<div class="muted">—</div>';
    applyWidths(el);
  }

  // ---------- overview ----------
  function renderOverview() {
    const m = S.metrics;
    const r = S.radar, ac = S.acounts;
    if (r) {
      $("c-radar").textContent = r.active ? t("ov.radarActive", { n: r.active }) : t("ov.radarClear");
      $("c-radar").classList.toggle("crit-t", r.active > 0);
      $("c-radar2").textContent = t("ov.radarSub", { t: r.tracked });
    }
    if (ac) {
      $("c-alerts").textContent = ac.unacked;
      $("c-alerts2").textContent = t("ov.alertsSub", { c: ac.bySeverity.critical || 0, w: ac.bySeverity.warning || 0 });
    }
    if (!m) return;
    $("host-line").textContent = `${m.hostname} · ${m.os}`;
    $("c-cpu").textContent = fmtPct(m.cpu);
    $("c-cores").textContent = t("ov.cores", { n: m.cores });
    $("c-mem").textContent = fmtPct(m.memPercent);
    $("c-mem2").textContent = `${fmtBytes(m.memUsed)} / ${fmtBytes(m.memTotal)}`;
    $("c-commit").textContent = m.commitTotal ? fmtPct((m.commitUsed / m.commitTotal) * 100) : "–";
    $("c-commit2").textContent = `${fmtBytes(m.commitUsed)} / ${fmtBytes(m.commitTotal)}`;
    $("c-procs").textContent = m.processes;
    $("c-threads").textContent = t("ov.threads", { n: m.threads.toLocaleString(L()) });
    $("c-up").textContent = fmtUptime(m.uptime);
    if (S.netstats) {
      $("c-socks").textContent = S.netstats.total;
      $("c-rate").textContent = t("ov.rate", { r: S.netstats.newPerSec.toFixed(1), e: S.netstats.byState.ESTABLISHED || 0 });
    }
    if (active !== "overview") return;
    $("disks").innerHTML = (m.disks || []).map((d) => `
      <div class="disk"><div class="row"><span><b>${ltr(d.mount)}</b> <span class="muted">${esc(d.type)}</span></span>
      <span class="muted">${esc(t("ov.free", { f: fmtBytes(d.free), t: fmtBytes(d.total) }))}</span></div>
      <div class="meter ${d.percent > 90 ? "hot" : ""}"><i data-w="${d.percent.toFixed(1)}"></i></div></div>`).join("") || `<div class="muted">${esc(t("ov.noVolumes"))}</div>`;
    applyWidths($("disks"));
    $("top-procs").innerHTML = S.procs.slice(0, 10).map((p) => `
      <tr><td>${esc(p.name)}</td><td class="muted num">${p.pid}</td><td class="num">${fmtPct(p.cpu)}</td><td class="num muted">${fmtBytes(p.workingSet)}</td></tr>`).join("");
    const bad = S.events.filter((e) => e.level >= 1 && e.level <= 3).slice(0, 25);
    $("ov-feed").innerHTML = bad.map((e) => `
      <li><span class="lvl ${e.levelStr}">${esc(lvlName(e.levelStr))}</span> <b>${esc(e.provider)}</b> <span class="muted">#${e.eventId}</span>
      <div class="meta">${esc(ago(e.time))} · ${esc(CAT_KEYS.includes(e.category) ? catName(e.category) : e.channel)}</div>
      <div class="msg-ltr" dir="auto">${esc(e.message.slice(0, 180))}</div></li>`).join("") || `<li class="muted">${esc(t("ov.noErrors"))}</li>`;
    drawSysChart();
  }

  // ---------- network ----------
  const netSort = sortable("net-table", "processName", 1, () => renderNetwork());
  const isLoop = (a) => !a || a === "127.0.0.1" || a === "::1";
  function renderNetwork() {
    $("b-net").textContent = S.conns.size;
    if (active !== "network") return;
    if (S.netstats) {
      const states = Object.entries(S.netstats.byState).map(([name, count]) => ({ name, count })).sort((a, b) => b.count - a.count);
      bars($("net-states"), states);
      bars($("net-procs"), S.netstats.topProcs || []);
      bars($("net-remotes"), S.netstats.topRemotes || []);
    }
    const q = $("net-q").value.trim().toLowerCase(), pr = $("net-proto").value, stt = $("net-state").value, hide = $("net-hide-local").checked;
    const rows = [...S.conns.values()].filter((c) =>
      (!pr || c.proto === pr) && (!stt || c.state === stt) &&
      (!hide || !(isLoop(c.localAddr) && isLoop(c.remoteAddr))) &&
      (!q || `${c.processName} ${c.pid} ${c.localAddr}:${c.localPort} ${c.remoteAddr}:${c.remotePort} ${c.state} ${c.proto}`.toLowerCase().includes(q)));
    rows.sort(cmp(netSort));
    const shown = rows.slice(0, 2000);
    $("net-table").tBodies[0].innerHTML = shown.map((c) => `
      <tr class="${S.newKeys.has(connKey(c)) ? "new" : ""}"><td class="mono">${c.proto}</td><td title="${esc(c.processPath)}">${esc(c.processName)}</td><td class="num mono">${c.pid}</td>
      <td class="mono">${ltr(c.localAddr)}</td><td class="num mono">${c.localPort}</td><td class="mono">${ltr(c.remoteAddr || "")}</td>
      <td class="num mono">${c.remotePort || ""}</td><td>${c.state === "-" ? "" : `<span class="state ${c.state}">${c.state}</span>`}</td><td class="muted">${fmtTime(c.firstSeen)}</td></tr>`).join("");
    $("net-foot").textContent = t("net.foot", { n: rows.length, total: S.conns.size }) + (rows.length > shown.length ? t("net.first2000") : "") + (S.netErr ? t("net.error", { e: S.netErr }) : "");
    renderDevices();
  }

  // ---------- local network devices ----------
  const DEV_CLASSES = ["pc", "mobile", "network", "printer", "iot", "tv", "console", "vm", "sbc", "unknown"];
  const DEV_ICON = { pc: "💻", mobile: "📱", network: "📡", printer: "🖨", iot: "💡", tv: "📺", console: "🎮", vm: "🧊", sbc: "🍓", unknown: "❔" };
  const devSort = sortable("dev-table", "ip", 1, () => renderDevices());
  const devClass = (d) => d.class || "unknown";
  const ipNum = (ip) => { const p = String(ip).split("."); return p.length === 4 ? p.reduce((a, x) => a * 256 + (+x || 0), 0) : 0; };
  function renderDevices() {
    if (active !== "network") return;
    const sel = $("dev-class");
    if (sel.options.length === 1) DEV_CLASSES.forEach((k) => sel.add(new Option(t("dclass." + k), k)));
    const q = $("dev-q").value.trim().toLowerCase(), cls = sel.value;
    const all = S.devices || [];
    const rows = all.filter((d) => (!cls || devClass(d) === cls) &&
      (!q || `${d.hostname || ""} ${d.ip} ${d.mac} ${d.vendor || ""} ${d.vendorFull || ""} ${d.workgroup || ""} ${d.interface || ""}`.toLowerCase().includes(q)));
    rows.sort((a, b) => devSort.key === "ip" ? (ipNum(a.ip) - ipNum(b.ip)) * devSort.dir : cmp(devSort)(a, b));
    const counts = {};
    all.forEach((d) => { const k = devClass(d); counts[k] = (counts[k] || 0) + 1; });
    const named = all.filter((d) => d.hostname).length, vend = all.filter((d) => d.vendor).length;
    $("dev-count").textContent = t("dev.count", { n: rows.length, total: all.length });
    $("dev-sum").innerHTML = DEV_CLASSES.filter((k) => counts[k]).map((k) => `<button class="dchip ${cls === k ? "sel" : ""}" data-dclass="${k}"><span>${DEV_ICON[k]}</span> ${esc(t("dclass." + k))} <b>${counts[k]}</b></button>`).join("")
      + `<span class="muted small dev-stats">${esc(t("dev.stats", { v: vend, n: named, total: all.length }))}</span>`;
    $("dev-table").tBodies[0].innerHTML = rows.map((d) => {
      const k = devClass(d);
      const name = d.hostname ? `<b dir="ltr">${esc(d.hostname)}</b>` : `<span class="muted">${esc(d.resolving ? t("dev.resolving") : t("dev.noName"))}</span>`;
      const vendor = d.vendor ? `<span title="${esc(d.vendorFull || "")}${d.oui ? " — " + esc(d.oui) + " (" + esc(d.registry || "") + ")" : ""}">${esc(d.vendor === "private address" ? t("dev.private") : d.vendor)}</span>`
        : d.randomMac ? `<span class="pill test" title="${esc(t("dev.randomTip"))}">${esc(t("dev.private"))}</span>` : `<span class="muted">${esc(t("dev.unknownVendor"))}</span>`;
      return `<tr data-dev="${esc(d.ip)}"><td><span class="dicon">${DEV_ICON[k]}</span> ${name}${d.gateway ? ` <span class="pill gw">${esc(t("dev.gateway"))}</span>` : ""}${d.workgroup ? ` <span class="muted small">· ${esc(d.workgroup)}</span>` : ""}</td>
        <td class="mono">${ltr(d.ip)}</td><td class="mono">${ltr(d.mac)}</td><td>${vendor}</td><td>${esc(t("dclass." + k))}</td>
        <td class="muted small">${d.nameSource ? esc(t("nsrc." + d.nameSource)) : "—"}</td><td class="muted">${esc(d.interface || "")}</td><td class="muted">${fmtTime(d.lastSeen)}</td></tr>`;
    }).join("") || `<tr><td colspan="8" class="muted">${esc(t("dev.none"))}</td></tr>`;
    $("dev-foot").textContent = t("dev.foot");
  }
  $("dev-sum").addEventListener("click", (ev) => {
    const b = ev.target.closest("[data-dclass]"); if (!b) return;
    $("dev-class").value = $("dev-class").value === b.dataset.dclass ? "" : b.dataset.dclass;
    renderDevices();
  });
  $("dev-table").addEventListener("click", (ev) => {
    const row = ev.target.closest("[data-dev]"); if (!row) return;
    const d = (S.devices || []).find((x) => x.ip === row.dataset.dev); if (!d) return;
    const names = Object.entries(d.names || {}).map(([k, v]) => `<dt>${esc(t("nsrc." + k))}</dt><dd class="mono">${ltr(v)}</dd>`).join("");
    const kv = [["col.ip", ltr(d.ip)], ["col.mac", ltr(d.mac)], ["dev.col.vendor", esc(d.vendor || "—")], ["dev.vendorFull", esc(d.vendorFull || (d.randomMac ? t("dev.randomTip") : "—"))],
      ["dev.oui", d.oui ? `${ltr(d.oui)} <span class="muted">${esc(d.registry || "")}</span>` : "—"], ["dev.col.type", esc(t("dclass." + devClass(d)))],
      ["dev.workgroup", esc(d.workgroup || "—")], ["col.iface", esc(d.interface || "—")], ["col.type", esc(d.type || "—")],
      ["col.firstSeen", esc(fmtDateTime(d.firstSeen))], ["col.lastSeen", esc(fmtDateTime(d.lastSeen))], ["dev.resolvedAt", esc(d.resolved ? fmtDateTime(d.resolved) : "—")]];
    modal(`${DEV_ICON[devClass(d)]} ${d.hostname || d.ip}`, `<dl class="kv">${kv.map(([k, v]) => `<dt>${esc(t(k))}</dt><dd>${v}</dd>`).join("")}</dl>
      ${names ? `<h4 class="mh">${esc(t("dev.allNames"))}</h4><dl class="kv">${names}</dl>` : ""}`,
      [{ label: t("act.copyIp"), value: "ip", ghost: true }, { label: t("act.copyMac"), value: "mac", ghost: true }, { label: t("btn.close"), value: false }])
      .then((v) => { if (v === "ip") copyText(d.ip); if (v === "mac") copyText(d.mac); });
  });
  $("dev-resolve").addEventListener("click", async () => {
    try { const r = await api("/api/devices/resolve", { method: "POST", body: "{}" }); toast(t("dev.resolvingToast", { n: r.resolving })); } catch (e) { toast(t("err.generic", { e: e.message })); }
  });

  // ---------- processes ----------
  const procSort = sortable("proc-table", "cpu", -1, () => renderProcesses());
  let procFilter = "";
  function procRows() {
    const q = $("proc-q").value.trim().toLowerCase();
    const cpuMin = +$("proc-cpu-min").value, memMin = +$("proc-mem-min").value;
    let rows = S.procs.filter((p) => !q || `${p.name} ${p.pid} ${p.path || ""}`.toLowerCase().includes(q));
    switch (procFilter) {
      case "cpu": rows = rows.filter((p) => p.access && p.cpu >= cpuMin); break;
      case "mem": rows = rows.filter((p) => p.access && p.workingSet >= memMin); break;
      case "denied": rows = rows.filter((p) => !p.access); break;
      case "top": {
        const score = (p) => p.cpu / 100 + p.workingSet / Math.max(1, S.metrics?.memTotal || 1);
        rows = rows.filter((p) => p.access).sort((a, b) => score(b) - score(a)).slice(0, 10);
        break;
      }
    }
    return rows;
  }
  function renderProcesses() {
    $("b-proc").textContent = S.procs.length;
    if (active !== "processes") return;
    const cpuMin = +$("proc-cpu-min").value, memMin = +$("proc-mem-min").value;
    document.querySelectorAll("#proc-chips .chip").forEach((c) => c.classList.toggle("active", c.dataset.pf === procFilter));
    const rows = procRows();
    if (procFilter !== "top") rows.sort(cmp(procSort));
    $("proc-table").tBodies[0].innerHTML = rows.map((p) => {
      const hotC = p.access && p.cpu >= cpuMin, hotM = p.access && p.workingSet >= memMin;
      return `<tr data-pid="${p.pid}" class="${hotC || hotM ? "hotrow" : ""}"><td>${esc(p.name)}</td><td class="num mono">${p.pid}</td><td class="num mono muted">${p.ppid}</td>
      <td class="num ${hotC ? "hot-t" : ""}">${p.access ? fmtPct(p.cpu) : `<span class="muted">${esc(t("proc.na"))}</span>`}</td><td class="num ${hotM ? "hot-t" : ""}">${p.access ? fmtBytes(p.workingSet) : ""}</td>
      <td class="num muted">${p.access ? fmtBytes(p.private) : ""}</td><td class="num muted">${p.threads}</td>
      <td class="muted">${p.started ? new Date(p.started).toLocaleString(L()) : ""}</td><td class="path mono" title="${esc(p.path)}">${p.path ? ltr(p.path) : esc(p.access ? "" : t("proc.denied"))}</td>
      <td class="acts"><button class="iconbtn sm" data-pact="copy" title="${esc(t("act.copyPath"))}" aria-label="${esc(t("act.copyPath"))}">⧉</button><button class="iconbtn sm" data-pact="inspect" title="${esc(t("act.inspect"))}" aria-label="${esc(t("act.inspect"))}">🔍</button></td></tr>`;
    }).join("") || `<tr><td colspan="10" class="muted">${esc(t("proc.none"))}</td></tr>`;
    $("proc-foot").textContent = t("proc.foot", { n: rows.length, total: S.procs.length });
  }
  $("proc-chips").addEventListener("click", (ev) => { const c = ev.target.closest(".chip"); if (!c) return; procFilter = procFilter === c.dataset.pf ? "" : c.dataset.pf; renderProcesses(); });
  // Diagnostic path: a paste-ready block with the image path, PID, parent and command line.
  function procDiagText(p, d) {
    const lines = [`${p.name} (PID ${p.pid}, parent ${p.ppid}${d?.parentName ? " " + d.parentName : ""})`, `Path: ${p.path || "(restricted)"}`];
    if (d?.commandLine) lines.push(`Command line: ${d.commandLine}`);
    if (d?.user) lines.push(`User: ${d.user}`);
    lines.push(`CPU ${fmtPct(p.cpu)} · Working set ${fmtBytes(p.workingSet)} · Private ${fmtBytes(p.private)} · Threads ${p.threads}`);
    return lines.join("\n");
  }
  async function inspectProcess(pid) {
    let d;
    try { d = await api(`/api/processes/${pid}`); } catch (e) { toast(t("err.generic", { e: e.message })); return; }
    const kv = [["col.name", esc(d.name)], ["col.pid", d.pid], ["col.parent", `${d.ppid}${d.parentName ? ` <span class="muted">(${esc(d.parentName)})</span>` : ""}`],
      ["col.path", d.path ? `<span class="mono">${ltr(d.path)}</span>` : esc(t("proc.denied"))], ["proc.cmdline", d.commandLine ? `<code class="wrap">${esc(d.commandLine)}</code>` : "—"],
      ["proc.user", esc(d.user || "—")], ["col.cpu", fmtPct(d.cpu)], ["col.ws", fmtBytes(d.workingSet)], ["col.private", fmtBytes(d.private)], ["col.threads", d.threads],
      ["proc.handles", d.handles || "—"], ["proc.priority", esc(d.priority || "—")], ["proc.cwd", d.cwd ? `<span class="mono">${ltr(d.cwd)}</span>` : "—"],
      ["col.started", d.started ? esc(new Date(d.started).toLocaleString(L())) : "—"]];
    const ex = d.extra || {};
    if (ex.ioReadBytes) kv.push(["proc.ioRead", fmtBytes(+ex.ioReadBytes)]);
    if (ex.ioWriteBytes) kv.push(["proc.ioWrite", fmtBytes(+ex.ioWriteBytes)]);
    if (ex.elevated) kv.push(["proc.elevated", esc(t("proc.yes"))]);
    const socks = (d.sockets || []).slice(0, 50).map((c) => `<tr><td class="mono">${c.proto}</td><td class="mono">${ltr(c.localAddr + ":" + c.localPort)}</td><td class="mono">${ltr(c.remoteAddr ? c.remoteAddr + ":" + c.remotePort : "")}</td><td>${c.state === "-" ? "" : `<span class="state ${c.state}">${c.state}</span>`}</td></tr>`).join("");
    const kids = (d.children || []).map((c) => `<li><b>${esc(c.name)}</b> <span class="muted mono">#${c.pid}</span> · ${fmtPct(c.cpu)} · ${fmtBytes(c.workingSet)}</li>`).join("");
    const v = await modal(`${d.name} — PID ${d.pid}`, `<dl class="kv">${kv.map(([k, x]) => `<dt>${esc(t(k))}</dt><dd>${x}</dd>`).join("")}</dl>
      ${kids ? `<h4 class="mh">${esc(t("proc.children", { n: d.children.length }))}</h4><ul class="kids">${kids}</ul>` : ""}
      ${socks ? `<h4 class="mh">${esc(t("proc.sockets", { n: d.sockets.length }))}</h4><div class="tablewrap"><table class="grid"><thead><tr><th>${esc(t("col.proto"))}</th><th>${esc(t("col.localAddr"))}</th><th>${esc(t("col.remoteAddr"))}</th><th>${esc(t("col.state"))}</th></tr></thead><tbody>${socks}</tbody></table></div>` : ""}
      ${(d.errors || []).length ? `<div class="note">${esc(t("proc.partial"))}: ${esc(d.errors.join(" · "))}</div>` : ""}`,
      [{ label: t("act.copyPath"), value: "path", ghost: true }, { label: t("act.copyDiag"), value: "diag", ghost: true }, { label: t("btn.close"), value: false }]);
    if (v === "path") copyText(d.path || d.name, "act.pathCopied");
    if (v === "diag") copyText(procDiagText(d, d), "act.diagCopied");
  }
  $("proc-table").addEventListener("click", (ev) => {
    const row = ev.target.closest("[data-pid]"); if (!row) return;
    const pid = +row.dataset.pid;
    const p = S.procs.find((x) => x.pid === pid);
    const act = ev.target.closest("[data-pact]")?.dataset.pact;
    if (act === "copy") { if (p) copyText(p.path || p.name, "act.pathCopied"); return; }
    inspectProcess(pid);
  });

  // ---------- events ----------
  // Event filters are evaluated client-side on every keystroke / click: no
  // reloads, no server round trips. Level chips are multi-select and stay in
  // sync with the level dropdown.
  const evLevels = new Set();
  let evRangeH = 0;
  function evRange() {
    let from = dtLocalMs("ev-from"), to = dtLocalMs("ev-to");
    if (evRangeH && !from) from = Date.now() - evRangeH * 3600e3;
    return [from, to];
  }
  function eventMatches(e, skipLevel) {
    const q = $("ev-q").value.trim().toLowerCase(), cat = $("ev-cat").value, ch = $("ev-chan").value;
    const [from, to] = evRange();
    if (!skipLevel && evLevels.size && !evLevels.has(e.levelStr)) return false;
    if (cat && e.category !== cat) return false;
    if (ch && e.channel !== ch) return false;
    if (from && e._t < from) return false;
    if (to && e._t > to) return false;
    if (q && !`${e.provider} ${e.message} ${e.eventId} ${e.channel}`.toLowerCase().includes(q)) return false;
    return true;
  }
  function renderEvents() {
    const sum = S.evsum;
    const bl = sum?.byLevel || {};
    const lv = (k) => Object.entries(bl).reduce((n, [x, v]) => (x.toLowerCase() === k ? n + v : n), 0);
    $("b-ev").textContent = lv("critical") + lv("error");
    if (active !== "events") return;
    const catSel = $("ev-cat");
    if (catSel.options.length === 1) CAT_KEYS.forEach((k) => catSel.add(new Option(catName(k), k)));
    const base = S.events.filter((e) => eventMatches(e, true));
    const cnt = { critical: 0, error: 0, warning: 0, info: 0 };
    base.forEach((e) => { cnt[e.levelStr === "verbose" ? "info" : e.levelStr] = (cnt[e.levelStr === "verbose" ? "info" : e.levelStr] || 0) + 1; });
    Object.keys(cnt).forEach((k) => { $("evc-" + k).textContent = cnt[k]; });
    document.querySelectorAll("#ev-lvl-chips .chip").forEach((c) => c.classList.toggle("active", evLevels.has(c.dataset.lv)));
    document.querySelectorAll("#ev-range-chips .chip").forEach((c) => c.classList.toggle("active", String(evRangeH || "") === c.dataset.range && !$("ev-from").value && !$("ev-to").value));
    const byCat = {};
    // Category card counts honour every other active filter (not the category itself).
    const catSave = catSel.value; catSel.value = "";
    S.events.forEach((e) => { if (eventMatches(e, false)) byCat[e.category] = (byCat[e.category] || 0) + 1; });
    catSel.value = catSave;
    const filtered = $("ev-q").value || evLevels.size || evRangeH || $("ev-from").value || $("ev-to").value || $("ev-chan").value;
    $("ev-cats").innerHTML = CAT_KEYS.map((k) => `
      <div class="c ${catSel.value === k ? "sel" : ""}" data-cat="${k}"><div class="n">${filtered ? byCat[k] || 0 : sum?.byCategory?.[k] || 0}</div><div class="t">${esc(catName(k))}</div></div>`).join("");
    const errBox = $("ev-err");
    errBox.hidden = !S.evErr; errBox.textContent = S.evErr ? t("ev.err", { e: S.evErr }) : "";
    const rows = base.filter((e) => !evLevels.size || evLevels.has(e.levelStr));
    const shown = rows.slice(0, 1500);
    $("ev-table").tBodies[0].innerHTML = shown.map((e) => `
      <tr><td class="muted" title="${esc(e.time)}">${fmtDateTime(e.time)}</td><td><span class="lvl ${e.levelStr}">${esc(lvlName(e.levelStr))}</span></td>
      <td class="cat">${e.category === "other" ? "" : esc(catName(e.category))}</td><td>${esc(e.provider)}</td>
      <td class="num mono">${e.eventId}</td><td class="muted">${esc(e.channel)}</td><td class="msg" dir="auto">${esc(e.message)}</td></tr>`).join("")
      || `<tr><td colspan="7" class="muted">${esc(t("ev.none"))}</td></tr>`;
    $("ev-foot").textContent = t("ev.foot", { n: rows.length, total: S.events.length }) + (rows.length > shown.length ? t("ev.first1500") : "");
    drawEventChart();
  }
  $("ev-cats").addEventListener("click", (ev) => {
    const c = ev.target.closest(".c"); if (!c) return;
    $("ev-cat").value = $("ev-cat").value === c.dataset.cat ? "" : c.dataset.cat;
    renderEvents();
  });
  $("ev-lvl-chips").addEventListener("click", (ev) => {
    const c = ev.target.closest(".chip"); if (!c) return;
    const k = c.dataset.lv;
    if (evLevels.has(k)) evLevels.delete(k); else evLevels.add(k);
    $("ev-level").value = evLevels.size === 1 ? [...evLevels][0] : "";
    renderEvents();
  });
  const evLevelSel = () => { evLevels.clear(); if ($("ev-level").value) evLevels.add($("ev-level").value); renderEvents(); };
  $("ev-level").addEventListener("change", evLevelSel);
  $("ev-level").addEventListener("input", evLevelSel);
  $("ev-range-chips").addEventListener("click", (ev) => {
    const c = ev.target.closest(".chip"); if (!c) return;
    evRangeH = +c.dataset.range || 0; $("ev-from").value = ""; $("ev-to").value = "";
    renderEvents();
  });
  $("ev-reset").addEventListener("click", () => {
    evLevels.clear(); evRangeH = 0;
    ["ev-q", "ev-level", "ev-cat", "ev-chan", "ev-from", "ev-to"].forEach((id) => { $(id).value = ""; });
    renderEvents();
  });

  // ---------- modal ----------
  function modal(title, bodyHtml, buttons) {
    $("modal-title").textContent = title;
    $("modal-body").innerHTML = bodyHtml;
    const foot = $("modal-foot");
    foot.innerHTML = "";
    return new Promise((resolve) => {
      const close = (v) => { $("modal").hidden = true; document.removeEventListener("keydown", onKey); resolve(v); };
      const onKey = (e) => { if (e.key === "Escape") close(false); };
      (buttons || [{ label: t("btn.close"), value: false }]).forEach((b) => {
        const el = document.createElement("button");
        el.className = "btn" + (b.ghost ? " ghost" : "") + (b.danger ? " danger" : "");
        el.textContent = b.label;
        el.addEventListener("click", () => close(b.value));
        foot.appendChild(el);
      });
      $("modal-x").onclick = () => close(false);
      $("modal").onclick = (e) => { if (e.target.id === "modal") close(false); };
      document.addEventListener("keydown", onKey);
      $("modal").hidden = false;
      foot.lastChild?.focus();
    });
  }
  const confirmBox = (title, text) => modal(title, `<p>${esc(text)}</p>`,
    [{ label: t("btn.cancel"), value: false, ghost: true }, { label: t("btn.confirm"), value: true }]);

  // ---------- audio chime (WebAudio, generated — no media files) ----------
  let soundOn = true;
  try { soundOn = localStorage.getItem("syspulse.sound") !== "off"; } catch (_) { /* ignore */ }
  let actx = null;
  const unlockAudio = () => {
    if (!actx) { const AC = window.AudioContext || window.webkitAudioContext; if (AC) actx = new AC(); }
    if (actx && actx.state === "suspended") actx.resume();
  };
  document.addEventListener("pointerdown", unlockAudio, { once: false, passive: true });
  function chime() {
    if (!soundOn) return;
    unlockAudio();
    if (!actx) return;
    const now = actx.currentTime;
    // Three descending alert tones (two-tone alarm), ~0.9 s total.
    [[880, 0], [660, 0.22], [880, 0.44], [660, 0.66]].forEach(([f, dt]) => {
      const o = actx.createOscillator(), g = actx.createGain();
      o.type = "triangle"; o.frequency.value = f;
      g.gain.setValueAtTime(0.0001, now + dt);
      g.gain.exponentialRampToValueAtTime(0.25, now + dt + 0.02);
      g.gain.exponentialRampToValueAtTime(0.0001, now + dt + 0.2);
      o.connect(g).connect(actx.destination);
      o.start(now + dt); o.stop(now + dt + 0.21);
    });
  }
  function renderSound() { $("sound-toggle").textContent = soundOn ? "🔔" : "🔕"; $("sound-toggle").classList.toggle("off", !soundOn); }
  $("sound-toggle").addEventListener("click", () => {
    soundOn = !soundOn;
    try { localStorage.setItem("syspulse.sound", soundOn ? "on" : "off"); } catch (_) { /* ignore */ }
    renderSound(); toast(t(soundOn ? "sound.on" : "sound.off"));
    if (soundOn) chime();
  });

  // ---------- sweep banner ----------
  const macText = (inc) => {
    if (inc.mac) return inc.mac + (!inc.onLink && inc.gateway ? " (" + t("radar.via", { g: inc.gateway }) + ")" : "");
    return inc.attrError ? t("radar.unknownMac") : t("radar.resolving");
  };
  function onSweep(inc, fresh) {
    const i = S.banner.findIndex((b) => b.id === inc.id);
    if (i >= 0) S.banner[i] = inc; else if (fresh) S.banner.unshift(inc);
    S.banner = S.banner.slice(0, 20);
    if (fresh) { chime(); flashTitle(); }
    renderBanner();
  }
  function renderBanner() {
    const b = $("sweep-banner");
    const inc = S.banner[0];
    if (!inc) { b.hidden = true; document.body.classList.remove("has-banner"); return; }
    b.hidden = false; document.body.classList.add("has-banner");
    b.classList.remove("pulse"); void b.offsetWidth; b.classList.add("pulse");
    $("sb-title").textContent = t(inc.test ? "sweep.titleTest" : "sweep.title");
    $("sb-ip").textContent = inc.remoteIp;
    $("sb-mac").textContent = macText(inc) + (inc.vendor ? ` · ${inc.vendor}` : "");
    $("sb-if").textContent = inc.interface || "—";
    $("sb-ports").textContent = inc.portRange + (inc.portMin ? `  [${inc.portMin}–${inc.portMax}]` : "");
    $("sb-count").textContent = `${inc.distinctPorts} (${t("radar.incAttempts", { n: inc.attempts })})`;
    $("sb-time").textContent = fmtStamp(inc.detected);
    $("sb-more").textContent = S.banner.length > 1 ? t("sweep.more", { n: S.banner.length - 1 }) : "";
  }
  $("sb-dismiss").addEventListener("click", () => { S.banner.shift(); renderBanner(); });
  $("sb-view").addEventListener("click", () => showTab("radar"));
  let titleTimer = 0;
  function flashTitle() {
    if (!document.hidden) return;
    const orig = document.title; let n = 0;
    clearInterval(titleTimer);
    titleTimer = setInterval(() => {
      document.title = n++ % 2 ? orig : "⚠ " + t("sweep.title");
      if (!document.hidden || n > 40) { clearInterval(titleTimer); document.title = orig; }
    }, 800);
  }

  // ---------- radar ----------
  function renderRadar() {
    const r = S.radar; if (!r) return;
    $("b-radar").textContent = r.active;
    $("b-radar").classList.toggle("zero", !r.active);
    if (active !== "radar") return;
    $("radar-rule").textContent = t("radar.ruleText", { thr: r.threshold, win: r.windowSec });
    $("radar-sensors").innerHTML = (r.sensors || []).map((s) => `<span class="sensor ${s.active ? "on" : "off"}" title="${esc(s.detail + (s.error ? " — " + s.error : "") + (s.adapters ? " — " + s.adapters.join(", ") : ""))}">
      <i></i>${esc(t("radar.sensor." + s.name))}: ${esc(t(s.active ? "radar.sensorOn" : "radar.sensorOff"))}${s.error ? ` <span class="muted">(${esc(s.error)})</span>` : ""}</span>`).join("");
    $("r-active").textContent = r.active;
    $("r-tracked").textContent = r.tracked;
    $("r-rate").textContent = r.obsPerSec.toFixed(1);
    $("r-arp").textContent = r.neighbors;
    $("radar-incidents").innerHTML = (r.incidents || []).slice(0, 20).map((inc) => `
      <div class="inc ${inc.active ? "active" : ""}" data-inc="${esc(inc.id)}">
        <div class="inc-h"><span class="mono">${esc(inc.id)}</span>
          <span class="pill ${inc.active ? "crit" : ""}">${esc(t(inc.active ? "radar.activeBadge" : "radar.closedBadge"))}</span>
          ${inc.test ? `<span class="pill test">${esc(t("radar.testBadge"))}</span>` : ""}
          <span class="muted inc-t">${esc(fmtDateTime(inc.detected))}</span></div>
        <div class="inc-b">${ltr(inc.remoteIp)} → <span class="mono">${ltr(macText(inc))}</span>${inc.vendor ? ` <span class="muted">(${esc(inc.vendor)})</span>` : ""} · ${esc(inc.interface || "—")}</div>
        <div class="inc-p mono">${ltr(inc.portRange)}</div>
        <div class="muted small">${esc(t("radar.incPorts", { n: inc.distinctPorts }))} · ${esc(t("radar.incAttempts", { n: inc.attempts }))} · ${esc(t("radar.sensor." + inc.sensor))}</div>
      </div>`).join("") || `<div class="muted empty">${esc(t("radar.noIncidents"))}</div>`;
    const q = $("radar-q").value.trim().toLowerCase();
    const hosts = (r.hosts || []).filter((h) => !q || `${h.ip} ${h.mac || ""} ${h.vendor || ""} ${h.interface || ""}`.toLowerCase().includes(q));
    $("radar-test").hidden = !S.selfTest;
    $("radar-table").tBodies[0].innerHTML = hosts.map((h) => {
      const p = Math.min(1.5, h.pressure);
      const cls = h.flagged || h.pressure > 1 ? "hot" : h.pressure > 0.6 ? "warm" : "";
      return `<tr class="${h.flagged ? "flagged" : ""}"><td class="mono">${ltr(h.ip)} ${h.flagged ? `<span class="pill crit">${esc(t("radar.flagged"))}</span>` : ""}</td>
        <td class="mono">${ltr(h.mac || "—")}</td><td>${h.vendor ? esc(h.vendor === "private address" ? t("dev.private") : h.vendor) : `<span class="muted">—</span>`}</td><td>${esc(h.interface || "—")}</td>
        <td class="num mono">${h.portsWindow} / ${r.threshold}</td>
        <td><div class="meter pressure ${cls}"><i data-w="${((p / 1.5) * 100).toFixed(1)}"></i></div><span class="muted small">${Math.round(h.pressure * 100)}%</span></td>
        <td class="num mono">${h.connsWindow}</td><td class="num mono">${h.rate.toFixed(2)}/s</td><td class="num mono">${h.distinctPorts}</td><td class="num mono">${h.total}</td>
        <td class="muted">${fmtTime(h.lastSeen)}</td><td class="muted small">${esc((h.sensors || []).map((s) => t("radar.sensor." + s)).join(", "))}</td></tr>`;
    }).join("") || `<tr><td colspan="12" class="muted">${esc(t("radar.noHosts"))}</td></tr>`;
    applyWidths($("radar-table"));
    $("radar-foot").textContent = t("radar.foot", { n: hosts.length, t: r.tracked, a: r.allowCount });
    drawRadarChart();
  }
  $("radar-test").addEventListener("click", async () => {
    if (!(await confirmBox(t("radar.selftest"), t("radar.testConfirm", { ip: "198.51.100.77" })))) return;
    unlockAudio();
    try {
      const res = await api("/api/radar/selftest", { method: "POST", body: JSON.stringify({ ports: 24 }) });
      toast(t("radar.testDone", { id: res.incident?.id || "" }));
    } catch (e) { toast(t("err.generic", { e: e.message })); }
  });
  $("radar-arp-btn").addEventListener("click", async () => {
    try {
      const { neighbors } = await api("/api/radar/neighbors");
      const rows = (neighbors || []).map((n) => `<tr><td class="mono">${ltr(n.ip)}</td><td class="mono">${ltr(n.mac)}</td><td>${esc(n.interface)}</td><td class="num">${n.ifIndex}</td><td class="muted">${esc(n.type)}</td></tr>`).join("");
      modal(t("radar.arpTitle"), rows ? `<div class="tablewrap"><table class="grid"><thead><tr><th>${esc(t("col.remoteIp"))}</th><th>${esc(t("col.mac"))}</th><th>${esc(t("col.iface"))}</th><th class="num">#</th><th>${esc(t("col.type"))}</th></tr></thead><tbody>${rows}</tbody></table></div>` : `<p class="muted">${esc(t("radar.arpEmpty"))}</p>`);
    } catch (e) { toast(t("err.generic", { e: e.message })); }
  });
  $("radar-incidents").addEventListener("click", (ev) => {
    const el = ev.target.closest("[data-inc]"); if (!el) return;
    const inc = (S.radar?.incidents || []).find((i) => i.id === el.dataset.inc); if (!inc) return;
    const kv = [["sweep.remoteIp", ltr(inc.remoteIp)], ["sweep.mac", ltr(macText(inc))], ["dev.col.vendor", esc(inc.vendor || "—")], ["sweep.iface", esc(inc.interface || "—")],
      ["sweep.ports", `<span class="mono">${ltr(inc.portRange)}</span>`], ["sweep.distinct", inc.distinctPorts], ["sweep.time", esc(fmtStamp(inc.detected))],
      ["col.lastSeen", esc(fmtStamp(inc.lastSeen))], ["col.sensor", esc(t("radar.sensor." + inc.sensor))]];
    modal(`${inc.id} — ${t(inc.test ? "sweep.titleTest" : "sweep.title")}`,
      `<dl class="kv">${kv.map(([k, v]) => `<dt>${esc(t(k))}</dt><dd>${v}</dd>`).join("")}</dl>
       <div class="portcloud mono">${(inc.ports || []).map((p) => `<span>${p}</span>`).join("")}</div>`);
  });

  // ---------- diagnostics ----------
  const fmtDur = (ms) => (ms < 1000 ? `${ms} ms` : `${(ms / 1000).toFixed(1)} s`);
  const FKINDS = ["failed-logon", "password-spray", "account-lockout", "privileged-logon", "service-crash", "app-fault", "app-hang", "bugcheck", "unexpected-shutdown"];
  const diagSev = new Set();
  let diagRangeH = 0;
  function findingMatches(f, skipSev) {
    const q = $("diag-q").value.trim().toLowerCase(), kind = $("diag-kind").value;
    let from = dtLocalMs("diag-from"); const to = dtLocalMs("diag-to");
    if (diagRangeH && !from) from = Date.now() - diagRangeH * 3600e3;
    if (!skipSev && diagSev.size && !diagSev.has(f.severity)) return false;
    if (kind && f.kind !== kind) return false;
    const first = new Date(f.first).getTime() || 0, last = new Date(f.last).getTime() || first;
    // A finding matches a date range when any of its occurrences fall inside it.
    if (from && last < from) return false;
    if (to && first > to) return false;
    if (q) {
      const hay = [f.id, f.subject, f.kind, f.title?.en, f.title?.ar, f.diagnosis?.en, f.diagnosis?.ar, f.fix?.en, f.fix?.ar, (f.eventIds || []).join(" "), ...Object.values(f.details || {})].join(" ").toLowerCase();
      if (!hay.includes(q)) return false;
    }
    return true;
  }
  function renderDiagnostics() {
    const a = S.audit || {};
    const running = new Set(a.running || []);
    document.querySelectorAll("[data-audit]").forEach((b) => {
      const k = b.dataset.audit;
      b.disabled = running.has(k) || !a.available;
      b.innerHTML = running.has(k) ? `<span class="spin"></span> ${esc(t("diag.running"))}` : esc(t(k === "auth" ? "diag.authBtn" : "diag.relBtn"));
    });
    $("diag-unavail").hidden = !!a.available;
    if (active !== "diagnostics") return;
    const reports = ["auth", "reliability"].map((k) => a.reports?.[k]).filter(Boolean);
    const ks = $("diag-kind");
    if (ks.options.length === 1) FKINDS.forEach((k) => ks.add(new Option(t("kind." + k), k)));
    $("diag-filter").hidden = !reports.length;
    const allF = reports.flatMap((r) => r.findings || []);
    const dc = { critical: 0, warning: 0, info: 0 };
    allF.filter((f) => findingMatches(f, true)).forEach((f) => { dc[f.severity] = (dc[f.severity] || 0) + 1; });
    Object.keys(dc).forEach((k) => { $("dc-" + k).textContent = dc[k]; });
    document.querySelectorAll("#diag-sev-chips .chip").forEach((c) => c.classList.toggle("active", diagSev.has(c.dataset.dsev)));
    document.querySelectorAll("#diag-range-chips .chip").forEach((c) => c.classList.toggle("active", String(diagRangeH || "") === c.dataset.drange && !$("diag-from").value && !$("diag-to").value));
    const shownN = allF.filter((f) => findingMatches(f, false)).length;
    $("diag-fcount").textContent = t("diag.fcount", { n: shownN, total: allF.length });
    $("diag-reports").innerHTML = reports.map((rep) => {
      const took = new Date(rep.finished) - new Date(rep.started);
      const byEv = Object.entries(rep.byEventId || {}).sort((x, y) => +x[0] - +y[0]).map(([id, n]) => `<span class="evchip">${id}: ${n}</span>`).join("");
      const vis = (rep.findings || []).filter((f) => findingMatches(f, false));
      const rows = vis.map((f) => `
        <tr class="sev-row ${f.severity}" data-finding="${esc(rep.kind)}|${esc(f.id)}">
          <td><span class="sev ${f.severity}">${esc(sevName(f.severity))}</span><div class="muted small mono">${esc(f.id)}</div></td>
          <td><b>${esc(tx(f.title))}</b><div class="muted small">${esc(t("kind." + f.kind))}</div></td>
          <td class="mono">${ltr(f.subject)}</td>
          <td class="mono">${(f.eventIds || []).join(", ")}</td>
          <td class="num mono">${f.count}</td>
          <td class="muted small">${esc(fmtDateTime(f.first))}<br>${esc(fmtDateTime(f.last))}</td>
          <td class="diagtxt" dir="auto">${esc(tx(f.diagnosis))}</td>
          <td class="fixtxt" dir="auto">${esc(tx(f.fix))}</td>
        </tr>`).join("");
      const errs = (rep.errors || []).map((e) => `<div class="note">${esc(e)}</div>`).join("") + (rep.notes || []).map((n) => `<div class="note">${esc(tx(n))}</div>`).join("");
      const sev = rep.bySeverity || {};
      return `<div class="box report">
        <div class="toolbar"><h3>${esc(t("diag.report." + rep.kind))} <span class="muted">· ${esc(t("diag.findingsCount", { n: rep.findings.length }))}</span></h3>
          <span class="sev critical">${sev.critical || 0}</span><span class="sev warning">${sev.warning || 0}</span><span class="sev info">${sev.info || 0}</span>
          <span class="spacer"></span><span class="muted">${esc(t("diag.export"))}</span>
          <button class="btn small" data-aexp="${rep.kind}|json">JSON</button><button class="btn small" data-aexp="${rep.kind}|csv">CSV</button></div>
        <div class="muted small">${esc(t("diag.meta", { n: rep.scanned, h: rep.windowHours, t: fmtDateTime(rep.finished), d: fmtDur(took) }))}</div>
        <div class="evchips"><span class="muted small">${esc(t("diag.byEvent"))}</span> ${byEv || "—"}</div>
        ${errs}
        ${vis.length !== (rep.findings || []).length ? `<div class="muted small">${esc(t("diag.fcount", { n: vis.length, total: rep.findings.length }))}</div>` : ""}
        ${rows ? `<div class="tablewrap tall"><table class="grid findings"><thead><tr>
          <th>${esc(t("col.severity"))}</th><th>${esc(t("col.finding"))}</th><th>${esc(t("col.subject"))}</th><th>${esc(t("col.events"))}</th>
          <th class="num">${esc(t("col.count"))}</th><th>${esc(t("col.window"))}</th><th>${esc(t("col.diagnosis"))}</th><th>${esc(t("col.fix"))}</th>
          </tr></thead><tbody>${rows}</tbody></table></div>` : `<div class="okbox">${esc(t((rep.findings || []).length ? "diag.noneMatch" : "diag.none"))}</div>`}
      </div>`;
    }).join("");
  }
  document.querySelectorAll("[data-audit]").forEach((b) => b.addEventListener("click", async () => {
    const kind = b.dataset.audit;
    S.audit.running = [...new Set([...(S.audit.running || []), kind])];
    renderDiagnostics();
    try {
      const rep = await api(`/api/audit/${kind}`, { method: "POST", body: JSON.stringify({ hours: +$("diag-hours").value }) });
      S.audit.reports = { ...(S.audit.reports || {}), [kind]: rep };
      toast(t("diag.done", { kind: t("diag.report." + kind), n: rep.findings.length }));
    } catch (e) { toast(t("diag.failed", { e: e.message })); }
    S.audit.running = (S.audit.running || []).filter((k) => k !== kind);
    renderAll();
  }));
  $("diag-sev-chips").addEventListener("click", (ev) => {
    const c = ev.target.closest(".chip"); if (!c) return;
    if (diagSev.has(c.dataset.dsev)) diagSev.delete(c.dataset.dsev); else diagSev.add(c.dataset.dsev);
    renderDiagnostics();
  });
  $("diag-range-chips").addEventListener("click", (ev) => {
    const c = ev.target.closest(".chip"); if (!c) return;
    diagRangeH = +c.dataset.drange || 0; $("diag-from").value = ""; $("diag-to").value = "";
    renderDiagnostics();
  });
  $("diag-reset").addEventListener("click", () => {
    diagSev.clear(); diagRangeH = 0;
    ["diag-q", "diag-kind", "diag-from", "diag-to"].forEach((id) => { $(id).value = ""; });
    renderDiagnostics();
  });
  $("diag-reports").addEventListener("click", (ev) => {
    const ex = ev.target.closest("[data-aexp]");
    if (ex) {
      const [kind, fmt] = ex.dataset.aexp.split("|");
      download(`/api/audit/${kind}/export?format=${fmt}&lang=${window.I18N.lang}`);
      return;
    }
    const row = ev.target.closest("[data-finding]"); if (!row) return;
    const [kind, id] = row.dataset.finding.split("|");
    const f = (S.audit.reports?.[kind]?.findings || []).find((x) => x.id === id); if (!f) return;
    const det = Object.entries(f.details || {}).map(([k, v]) => `<dt>${esc(k)}</dt><dd class="mono">${ltr(v)}</dd>`).join("");
    modal(`${f.id} — ${tx(f.title)}`, `
      <div class="finding-modal"><span class="sev ${f.severity}">${esc(sevName(f.severity))}</span>
      <h4>${esc(t("col.diagnosis"))}</h4><p dir="auto">${esc(tx(f.diagnosis))}</p>
      <h4>${esc(t("col.fix"))}</h4><p class="fixbox" dir="auto">${esc(tx(f.fix))}</p>
      ${det ? `<h4>${esc(t("diag.details"))}</h4><dl class="kv">${det}</dl>` : ""}
      ${f.samples?.length ? `<h4>${esc(t("diag.samples"))}</h4><ul class="samples">${f.samples.map((s) => `<li dir="ltr" class="mono">${esc(s)}</li>`).join("")}</ul>` : ""}</div>`);
  });

  // ---------- alerts ----------
  let aSev = "";
  function alertMatches(a) {
    const q = $("a-q").value.trim().toLowerCase(), cat = $("a-cat").value, un = $("a-unacked").checked;
    if (aSev && a.severity !== aSev) return false;
    if (cat && a.category !== cat) return false;
    if (un && a.acked) return false;
    if (q) {
      const hay = [a.title?.en, a.title?.ar, a.detail?.en, a.detail?.ar, a.source, a.category, ...Object.entries(a.fields || {}).flat()].join(" ").toLowerCase();
      if (!hay.includes(q)) return false;
    }
    return true;
  }
  function renderAlerts() {
    const c = S.acounts || { bySeverity: {}, unacked: 0, last24h: 0, total: 0 };
    const b = $("b-alerts");
    b.textContent = c.unacked;
    b.classList.toggle("zero", !c.unacked);
    b.classList.toggle("crit", (c.bySeverity.critical || 0) > 0);
    if (active !== "alerts") return;
    $("a-crit").textContent = c.bySeverity.critical || 0;
    $("a-warn").textContent = c.bySeverity.warning || 0;
    $("a-info").textContent = c.bySeverity.info || 0;
    $("a-24h").textContent = c.last24h || 0;
    $("a-unacked-n").textContent = c.unacked || 0;
    const sel = $("a-cat");
    if (sel.options.length === 1) ACATS.forEach((k) => sel.add(new Option(t("acat." + k), k)));
    document.querySelectorAll("#a-sev-chips .chip").forEach((ch) => ch.classList.toggle("active", ch.dataset.sevf === aSev));
    const rows = S.alerts.filter(alertMatches);
    $("a-table").tBodies[0].innerHTML = rows.slice(0, 1000).map((a) => `
      <tr class="sev-row ${a.severity} ${a.acked ? "acked" : ""}" data-alert="${esc(a.id)}">
        <td><span class="sev ${a.severity}">${esc(sevName(a.severity))}</span></td>
        <td class="muted small">${esc(fmtDateTime(a.updated || a.time))}<div>${esc(ago(a.updated || a.time))}</div></td>
        <td><span class="acat ${a.category}">${esc(t("acat." + a.category))}</span></td>
        <td><b dir="auto">${esc(tx(a.title))}</b></td>
        <td class="msg" dir="auto">${esc(tx(a.detail))}</td>
        <td class="num mono">${a.count > 1 ? "×" + a.count : ""}</td>
        <td class="muted small">${esc(t("src." + a.source))}</td>
        <td>${a.acked ? `<span class="muted small">✔ ${esc(t("alerts.acked"))}</span>` : `<button class="btn small ghost" data-ack="${esc(a.id)}">${esc(t("alerts.ack"))}</button>`}</td>
      </tr>`).join("") || `<tr><td colspan="8" class="muted">${esc(t("alerts.none"))}</td></tr>`;
    $("a-foot").textContent = t("alerts.foot", { n: rows.length, total: S.alerts.length });
  }
  $("a-sev-chips").addEventListener("click", (ev) => { const c = ev.target.closest(".chip"); if (c) { aSev = c.dataset.sevf; renderAlerts(); } });
  document.querySelectorAll("#tab-alerts .sev-card[data-sev]").forEach((c) => c.addEventListener("click", () => { aSev = aSev === c.dataset.sev ? "" : c.dataset.sev; renderAlerts(); }));
  $("a-table").addEventListener("click", async (ev) => {
    const ack = ev.target.closest("[data-ack]");
    if (ack) {
      ev.stopPropagation();
      try { await api("/api/alerts/ack", { method: "POST", body: JSON.stringify({ ids: [ack.dataset.ack] }) }); markAcked([ack.dataset.ack]); } catch (e) { toast(t("err.generic", { e: e.message })); }
      return;
    }
    const row = ev.target.closest("[data-alert]"); if (!row) return;
    const a = S.alerts.find((x) => x.id === row.dataset.alert); if (!a) return;
    const f = Object.entries(a.fields || {}).filter(([k]) => !k.startsWith("fix_")).map(([k, v]) => `<dt>${esc(k)}</dt><dd class="mono">${ltr(v)}</dd>`).join("");
    const fix = a.fields?.["fix_" + window.I18N.lang] || a.fields?.fix_en;
    modal(t("alerts.details"), `
      <div class="finding-modal"><span class="sev ${a.severity}">${esc(sevName(a.severity))}</span> <span class="acat ${a.category}">${esc(t("acat." + a.category))}</span>
      <h4 dir="auto">${esc(tx(a.title))}</h4><p dir="auto">${esc(tx(a.detail))}</p>
      ${fix ? `<h4>${esc(t("col.fix"))}</h4><p class="fixbox" dir="auto">${esc(fix)}</p>` : ""}
      <dl class="kv"><dt>ID</dt><dd class="mono">${esc(a.id)}</dd><dt>${esc(t("col.time"))}</dt><dd>${esc(fmtStamp(a.time))}</dd>
      <dt>${esc(t("col.lastSeen"))}</dt><dd>${esc(fmtStamp(a.updated))}</dd><dt>${esc(t("col.count"))}</dt><dd>${a.count}</dd>
      <dt>${esc(t("col.sourceMod"))}</dt><dd>${esc(t("src." + a.source))}</dd></dl>
      ${f ? `<h4>${esc(t("alerts.fields"))}</h4><dl class="kv">${f}</dl>` : ""}</div>`);
  });
  function markAcked(ids) {
    const all = !ids.length;
    S.alerts.forEach((a) => { if (all || ids.includes(a.id)) a.acked = true; });
    renderAll();
  }
  $("a-ack-all").addEventListener("click", async () => {
    try { await api("/api/alerts/ack", { method: "POST", body: JSON.stringify({ ids: [] }) }); markAcked([]); } catch (e) { toast(t("err.generic", { e: e.message })); }
  });
  $("a-clear").addEventListener("click", async () => {
    if (!(await confirmBox(t("alerts.clear"), t("alerts.clearConfirm")))) return;
    try { await api("/api/alerts/clear", { method: "POST", body: "{}" }); S.alerts = []; renderAll(); } catch (e) { toast(t("err.generic", { e: e.message })); }
  });
  function alertQuery() {
    const p = new URLSearchParams();
    if (aSev) p.set("severity", aSev);
    if ($("a-cat").value) p.set("category", $("a-cat").value);
    if ($("a-q").value.trim()) p.set("q", $("a-q").value.trim());
    if ($("a-unacked").checked) p.set("unacked", "1");
    p.set("lang", window.I18N.lang);
    return p;
  }
  function download(url) {
    const a = document.createElement("a");
    a.href = url + (url.includes("?") ? "&" : "?") + "token=" + encodeURIComponent(TOKEN);
    a.download = "";
    document.body.appendChild(a); a.click(); a.remove();
  }
  $("a-exp-json").addEventListener("click", () => { const p = alertQuery(); p.set("format", "json"); download("/api/alerts/export?" + p); });
  $("a-exp-csv").addEventListener("click", () => { const p = alertQuery(); p.set("format", "csv"); download("/api/alerts/export?" + p); });
  function onAlert(a, isNew) {
    const i = S.alerts.findIndex((x) => x.id === a.id);
    if (i >= 0) S.alerts.splice(i, 1);
    S.alerts.unshift(a);
    if (S.alerts.length > 2000) S.alerts.length = 2000;
    if (isNew && a.severity === "critical" && a.category !== "network-sweep") toast("⚠ " + tx(a.title));
  }

  // ---------- software ----------
  const appSort = sortable("app-table", "name", 1, () => renderSoftware());
  function renderSoftware() {
    const sw = S.software;
    const n = sw?.upgrades?.length;
    $("b-sw").textContent = n == null ? "–" : n;
    if (active !== "software" || !sw) return;
    const checking = sw.checking;
    const checked = sw.upgradesAt && !sw.upgradesAt.startsWith("0001");
    $("sw-refresh").disabled = checking;
    $("sw-refresh").innerHTML = checking ? `<span class="spin"></span> ${esc(t("sw.checking"))}` : esc(t("sw.check"));
    $("sw-when").textContent = checked ? t("sw.checked", { t: ago(sw.upgradesAt) }) : t("sw.notChecked");
    const e = $("sw-err");
    const msg = [sw.upgradesError, sw.appsError].filter(Boolean).join(" · ");
    e.hidden = !msg; e.textContent = msg;
    const busy = new Set(sw.upgrading || []);
    $("up-table").tBodies[0].innerHTML = (sw.upgrades || []).map((u) => `
      <tr><td>${esc(u.name)}</td><td class="mono">${ltr(u.id)}</td><td class="mono">${esc(u.version)}</td><td class="mono upd">${esc(u.available)}</td>
      <td class="muted">${esc(u.source)}</td><td class="cmd" title="${esc(t("sw.copy"))}" data-copy="${esc(u.command)}">${ltr(u.command)}</td>
      <td>${busy.has(u.id) ? `<span class="spin"></span> ${esc(t("sw.upgrading"))}` : `<button class="btn small" data-upgrade="${esc(u.id)}">${esc(t("sw.upgrade"))}</button>`}</td></tr>`).join("")
      || `<tr><td colspan="7" class="muted">${esc(checking ? t("sw.runningWinget") : checked ? t("sw.upToDate") : t("sw.pressCheck"))}</td></tr>`;
    $("sw-results").innerHTML = (sw.results || []).slice(0, 5).map((r) => `
      <details class="result"><summary><span class="${r.ok ? "ok-t" : "bad-t"}">${r.ok ? "✔" : "✖"}</span> ${esc(r.id)} <span class="muted">${fmtDateTime(r.finished)}</span></summary><pre dir="ltr">${esc(r.output)}</pre></details>`).join("");
    const q = $("app-q").value.trim().toLowerCase(), onlyUpd = $("app-upd").checked, showHidden = $("app-hidden").checked;
    const scope = $("app-scope").value, pub = $("app-pub").value;
    const all = sw.apps || [];
    const pubSel = $("app-pub");
    const pubs = [...new Set(all.filter((a) => showHidden || !a.hidden).map((a) => a.publisher).filter(Boolean))].sort((a, b) => a.localeCompare(b));
    if (pubSel.dataset.sig !== pubs.join("|")) {
      const v = pubSel.value;
      while (pubSel.options.length > 1) pubSel.remove(1);
      pubs.forEach((p) => pubSel.add(new Option(p, p)));
      pubSel.value = pubs.includes(v) ? v : "";
      pubSel.dataset.sig = pubs.join("|");
    }
    const apps = all.filter((a) => (showHidden || !a.hidden) && (!onlyUpd || a.available) && (!scope || a.scope === scope) && (!pub || a.publisher === pub) &&
      (!q || `${a.name} ${a.publisher} ${a.version} ${a.installLocation || ""}`.toLowerCase().includes(q))).sort(cmp(appSort));
    const visible = all.filter((a) => !a.hidden);
    const byScope = {};
    visible.forEach((a) => { byScope[a.scope] = (byScope[a.scope] || 0) + 1; });
    $("sw-sum").innerHTML = `<span class="swchip"><b>${visible.length}</b> ${esc(t("sw.sumApps"))}</span>` +
      Object.entries(byScope).map(([k, n]) => `<span class="swchip">${esc(t("scope." + k))} <b>${n}</b></span>`).join("") +
      `<span class="swchip muted">${esc(t("sw.sumHidden", { n: all.length - visible.length }))}</span>` +
      `<span class="swchip muted">${esc(t("sw.sumMsi", { n: all.filter((a) => a.msi).length }))}</span>`;
    $("app-count").textContent = t("sw.count", { n: apps.length, total: showHidden ? all.length : visible.length });
    $("app-table").tBodies[0].innerHTML = apps.map((a, i) => `
      <tr data-app="${i}" class="${a.hidden ? "dimrow" : ""}"><td>${esc(a.name)}${a.hidden ? ` <span class="pill">${esc(t("kind2." + (a.kind || "app")))}</span>` : ""}${a.msi ? ` <span class="pill test">MSI</span>` : ""}</td>
      <td class="mono">${esc(a.version)}</td><td class="mono upd">${esc(a.available || "")}</td><td class="muted">${esc(a.publisher)}</td>
      <td class="muted" title="${esc(a.dateSource ? t("dsrc." + a.dateSource) : "")}">${esc(a.installDate)}${a.dateSource === "key-write-time" ? " <span class=\"muted\">*</span>" : ""}</td>
      <td class="num muted">${a.sizeKB ? fmtBytes(a.sizeKB * 1024) : ""}</td><td class="muted">${esc(a.arch || "")}</td><td class="muted">${esc(t("scope." + a.scope))}</td></tr>`).join("")
      || `<tr><td colspan="8" class="muted">${esc(t("sw.none"))}</td></tr>`;
    S.appRows = apps;
  }
  $("app-table").addEventListener("click", (ev) => {
    const row = ev.target.closest("[data-app]"); if (!row) return;
    const a = (S.appRows || [])[+row.dataset.app]; if (!a) return;
    const kv = [["col.name", esc(a.name)], ["col.version", `<span class="mono">${esc(a.version || "—")}</span>`], ["col.update", a.available ? `<span class="upd mono">${esc(a.available)}</span> <span class="muted mono">${esc(a.wingetId || "")}</span>` : "—"],
      ["col.publisher", esc(a.publisher || "—")], ["col.installedOn", `${esc(a.installDate || "—")} <span class="muted small">${esc(a.dateSource ? t("dsrc." + a.dateSource) : "")}</span>`],
      ["col.size", a.sizeKB ? fmtBytes(a.sizeKB * 1024) : "—"], ["col.arch", esc(a.arch || "—")], ["col.scope", esc(t("scope." + a.scope))], ["sw.kind", esc(t("kind2." + (a.kind || "app")))],
      ["sw.location", a.installLocation ? `<span class="mono">${ltr(a.installLocation)}</span>` : "—"], ["sw.source", a.installSource ? `<span class="mono">${ltr(a.installSource)}</span>` : "—"],
      ["sw.uninstall", a.uninstall ? `<code class="wrap">${esc(a.uninstall)}</code>` : "—"], ["sw.url", a.url ? `<span class="mono">${ltr(a.url)}</span>` : "—"],
      ["sw.key", `<span class="mono">${ltr(a.key)}</span>`]];
    if (a.userSid) kv.push(["sw.sid", `<span class="mono">${ltr(a.userSid)}</span>`]);
    if (a.comments) kv.push(["sw.comments", esc(a.comments)]);
    modal(a.name, `<dl class="kv">${kv.map(([k, v]) => `<dt>${esc(t(k))}</dt><dd>${v}</dd>`).join("")}</dl>`,
      [{ label: t("sw.copyKey"), value: "key", ghost: true }, ...(a.uninstall ? [{ label: t("sw.copyUninstall"), value: "un", ghost: true }] : []), { label: t("btn.close"), value: false }])
      .then((v) => { if (v === "key") copyText(a.key); if (v === "un") copyText(a.uninstall); });
  });
  async function loadSoftware() {
    try { S.software = await api("/api/software"); renderAll(); } catch (e) { toast(t("sw.invFailed", { e: e.message })); }
  }
  $("sw-refresh").addEventListener("click", async () => {
    try {
      await api("/api/software/refresh", { method: "POST", body: "{}" });
      if (S.software) S.software.checking = true;
      renderAll(); toast(t("sw.checkingToast"));
    } catch (e) { toast(t("sw.refreshFailed", { e: e.message })); }
  });
  document.addEventListener("click", async (ev) => {
    const up = ev.target.closest("[data-upgrade]");
    if (up) {
      const id = up.dataset.upgrade;
      if (!(await confirmBox(t("sw.upgrade"), t("sw.confirm", { id })))) return;
      try { await api("/api/software/upgrade", { method: "POST", body: JSON.stringify({ id }) }); toast(t("sw.started", { id })); } catch (e) { toast(t("sw.failed", { e: e.message })); }
      return;
    }
    const cp = ev.target.closest("[data-copy]");
    if (cp) navigator.clipboard?.writeText(cp.dataset.copy).then(() => toast(t("sw.copied")));
  });

  // ---------- guide ----------
  let guideLang = "";
  function renderGuide() {
    if (guideLang === window.I18N.lang) return;
    guideLang = window.I18N.lang;
    $("guide").innerHTML = window.GUIDE.render(guideLang);
  }
  $("guide").addEventListener("click", (ev) => {
    const a = ev.target.closest("a[data-gid]"); if (!a) return;
    ev.preventDefault();
    document.getElementById("g-" + a.dataset.gid)?.scrollIntoView({ behavior: "smooth", block: "start" });
  });

  // ---------- render loop ----------
  let raf = 0;
  function renderAll() {
    if (raf) return;
    raf = requestAnimationFrame(() => {
      raf = 0;
      renderOverview(); renderNetwork(); renderRadar(); renderProcesses(); renderEvents();
      renderDiagnostics(); renderAlerts(); renderSoftware();
    });
  }
  // Every filter control re-renders on both "input" (typing, instant) and
  // "change" (selects / date pickers / checkboxes in all browsers).
  ["net-q", "net-proto", "net-state", "net-hide-local", "dev-q", "dev-class", "proc-q", "proc-cpu-min", "proc-mem-min",
    "ev-q", "ev-cat", "ev-chan", "ev-from", "ev-to", "diag-q", "diag-kind", "diag-from", "diag-to",
    "app-q", "app-upd", "app-hidden", "app-scope", "app-pub", "radar-q", "a-q", "a-cat", "a-unacked"].forEach((id) => {
    $(id).addEventListener("input", renderAll);
    $(id).addEventListener("change", renderAll);
  });

  // ---------- language ----------
  function setLang(l) {
    document.querySelectorAll(".lang-btn").forEach((b) => b.classList.toggle("active", b.dataset.lang === l));
    window.I18N.set(l);
    // Rebuild translated <option>s that were generated in JS.
    [["ev-cat", CAT_KEYS, catName], ["a-cat", ACATS, (k) => t("acat." + k)], ["diag-kind", FKINDS, (k) => t("kind." + k)], ["dev-class", DEV_CLASSES, (k) => t("dclass." + k)]].forEach(([id, keys, fn]) => {
      const sel = $(id), v = sel.value;
      while (sel.options.length > 1) sel.remove(1);
      keys.forEach((k) => sel.add(new Option(fn(k), k)));
      sel.value = v;
    });
    setConn(connState);
    renderMode();
    renderBanner();
    if (active === "guide") renderGuide();
    renderAll();
  }
  document.querySelectorAll(".lang-btn").forEach((b) => b.addEventListener("click", () => setLang(b.dataset.lang)));

  // ---------- API ----------
  async function api(path, opts = {}) {
    const r = await fetch(path, { ...opts, headers: { "Content-Type": "application/json", "X-SysPulse-Token": TOKEN, ...(opts.headers || {}) } });
    const body = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(body.error || r.statusText);
    return body;
  }
  function toast(msg) {
    const el = $("toast"); el.textContent = msg; el.hidden = false;
    clearTimeout(toast.t); toast.t = setTimeout(() => (el.hidden = true), 4000);
  }

  // ---------- WebSocket ----------
  let ws, retry = 500, connState = "connecting";
  function setConn(state) {
    connState = state;
    $("conn-dot").className = "dot " + (state === "live" ? "on" : state === "retry" ? "off" : "");
    $("conn-text").textContent = t(state === "live" ? "conn.live" : state === "retry" ? "conn.retry" : "conn.connecting");
  }
  function connect() {
    ws = new WebSocket(`${location.protocol === "https:" ? "wss" : "ws"}://${location.host}/ws?token=${encodeURIComponent(TOKEN)}`);
    ws.onopen = () => { retry = 500; setConn("live"); };
    ws.onclose = () => { setConn("retry"); setTimeout(connect, retry); retry = Math.min(retry * 2, 10000); };
    ws.onmessage = (m) => {
      const msg = JSON.parse(m.data);
      const d = msg.data;
      switch (msg.type) {
        case "snapshot":
          S.metrics = d.metrics; S.history = d.history || []; S.procs = d.processes || [];
          S.conns = new Map((d.connections || []).map((c) => [connKey(c), c]));
          S.netstats = d.netstats; S.events = d.events || []; S.evsum = d.eventsummary;
          S.evErr = d.eventError || ""; S.netErr = d.netError || "";
          S.events.forEach(normEvent);
          S.radar = d.radar; S.alerts = d.alerts || []; S.acounts = d.alertcounts; S.audit = d.audit || S.audit;
          S.devices = d.devices || []; S.selfTest = !!d.selfTest;
          // Re-show sweeps that are still active (e.g. after a page reload).
          S.banner = (d.radar?.incidents || []).filter((i) => i.active);
          renderBanner();
          break;
        case "metrics": S.metrics = d; S.history.push(d); if (S.history.length > 300) S.history.shift(); break;
        case "processes": S.procs = d || []; break;
        case "netstats": S.netstats = d; break;
        case "netdiff":
          S.newKeys = new Set();
          (d.removed || []).forEach((k) => S.conns.delete(k));
          (d.added || []).forEach((c) => { const k = connKey(c); S.conns.set(k, c); S.newKeys.add(k); });
          (d.changed || []).forEach((c) => S.conns.set(connKey(c), c));
          break;
        case "events": S.events = (d || []).map(normEvent).concat(S.events).slice(0, 5000); break;
        case "devices": S.devices = d || []; break;
        case "eventsummary": S.evsum = d; break;
        case "software": S.software = d; break;
        case "radar":
          S.radar = d;
          // Drop banner entries whose incident has closed.
          S.banner = S.banner.filter((b) => (d.incidents || []).some((i) => i.id === b.id && i.active));
          renderBanner();
          break;
        case "sweep": onSweep(d, !!d.new); break;
        case "alert": onAlert(d.alert, d.new); break;
        case "alertcounts": S.acounts = d; break;
        case "alertsreset": S.acounts = d; S.alerts = []; break;
        case "audit": S.audit.reports = { ...(S.audit.reports || {}), [d.kind]: d }; break;
        case "auditstate": S.audit = d; break;
      }
      renderAll();
    };
  }

  // ---------- mode badge ----------
  function renderMode() {
    const b = $("mode-badge");
    b.hidden = false;
    b.className = "mode-badge " + (MODE === "synthetic" ? "sim" : "live");
    b.textContent = t(MODE === "synthetic" ? "mode.synthetic" : "mode.live");
    b.title = t(MODE === "synthetic" ? "mode.syntheticTip" : "mode.liveTip");
  }

  // ---------- boot ----------
  renderSound();
  setLang(window.I18N.lang);
  connect();
})();
