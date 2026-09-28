/* SysPulse 4.0 — enterprise shell and new observability views.
 * Sidebar navigation, header telemetry strip, command palette, CPU-driven
 * EKG, health gauge, CPU & memory profiler, storage matrix, services
 * monitor, interface bandwidth meters, process hierarchy, high-resource
 * trackers and the threshold rules editor.
 * Strict CSP (script-src 'self'; style-src 'self'): no inline styles or
 * handlers; dynamic geometry is applied through the CSSOM only. */
(() => {
  "use strict";
  const SP = window.SysPulse;
  const { S, $, esc, ltr, t, tx, fmtBytes, fmtPct, api, modal, confirmBox, toast, copyText, applyWidths, setupCanvas, grid, sortable, cmp } = SP;
  const REDUCED = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  const clamp = (v, a, b) => Math.max(a, Math.min(b, v));
  const fmtRate = (bps) => {
    if (!bps || bps < 1) return "0 B/s";
    const u = ["B/s", "KB/s", "MB/s", "GB/s"];
    let i = 0;
    while (bps >= 1000 && i < u.length - 1) { bps /= 1000; i++; }
    return (bps >= 100 || i === 0 ? bps.toFixed(0) : bps.toFixed(1)) + " " + u[i];
  };
  const fmtBits = (bits) => {
    if (!bits) return "—";
    const u = ["bit/s", "Kbit/s", "Mbit/s", "Gbit/s", "Tbit/s"];
    let i = 0;
    while (bits >= 1000 && i < u.length - 1) { bits /= 1000; i++; }
    return (bits % 1 ? bits.toFixed(1) : bits.toFixed(0)) + " " + u[i];
  };
  const fmtNum = (n) => Number(n || 0).toLocaleString(SP.L());
  const rtl = () => document.documentElement.dir === "rtl";
  // t() returns the key itself for unknown keys; fall back to a raw value.
  const tOr = (key, raw) => { const v = t(key); return v === key ? raw : v; };
  const css = (name) => getComputedStyle(document.documentElement).getPropertyValue(name).trim();

  // Additional state carried by 4.0 messages.
  Object.assign(S, {
    ifs: [], ifHist: new Map(), ifTotals: [], ifErr: "", ifAvail: false,
    svcs: [], svcSum: null, svcAvail: false,
    rules: [], ruleStates: [], catalog: [], rulesFile: "",
    health: null, healthHist: [], procmeta: { services: {}, sockets: {} },
    coreHist: [], procTrack: new Map(),
  });

  // =========================================================================
  // Sidebar
  // =========================================================================
  const GROUP_OF = {};
  document.querySelectorAll(".nav-group").forEach((g) => g.querySelectorAll(".nav-item[data-view]").forEach((b) => { GROUP_OF[b.dataset.view] = g.dataset.group; }));
  const shell = $("shell");
  const store = { get: (k) => { try { return localStorage.getItem(k); } catch (_) { return null; } }, set: (k, v) => { try { localStorage.setItem(k, v); } catch (_) { /* ignore */ } } };
  function setCollapsed(on) {
    shell.classList.toggle("collapsed", on);
    store.set("syspulse.sidebar", on ? "collapsed" : "open");
    labelNav();
    // Canvases size themselves from their container; redraw after the transition.
    setTimeout(() => { window.dispatchEvent(new Event("resize")); }, 240);
  }
  function labelNav() {
    const col = shell.classList.contains("collapsed");
    document.querySelectorAll(".nav-item[data-view]").forEach((b) => {
      const lbl = t("nav." + b.dataset.view), badge = b.querySelector(".badge");
      b.title = col ? lbl + (badge && !badge.classList.contains("zero") && badge.textContent !== "0" ? ` (${badge.textContent})` : "") : "";
      b.setAttribute("aria-label", lbl);
    });
    $("side-collapse").title = t(col ? "side.expand" : "side.collapse");
    $("side-collapse").querySelector(".nl").textContent = t(col ? "side.expand" : "side.collapse");
  }
  $("side-collapse").addEventListener("click", () => setCollapsed(!shell.classList.contains("collapsed")));
  const openDrawer = (on) => { shell.classList.toggle("drawer", on); $("side-scrim").hidden = !on; };
  $("side-open").addEventListener("click", () => openDrawer(true));
  $("side-scrim").addEventListener("click", () => openDrawer(false));
  if (store.get("syspulse.sidebar") === "collapsed") shell.classList.add("collapsed");

  function crumbs(view) {
    const g = GROUP_OF[view];
    $("crumb-g").textContent = g ? t("grp." + g) : "";
    $("crumb-v").textContent = t("nav." + view);
    document.title = `${t("nav." + view)} · SysPulse ${document.querySelector(".brand .ver")?.textContent || ""}`;
    openDrawer(false);
  }
  SP.onView(crumbs);

  // =========================================================================
  // Header telemetry strip
  // =========================================================================
  function setBadge(id, value, cls) {
    const b = $(id); if (!b) return;
    b.textContent = value;
    const zero = value === 0 || value === "0" || value === "" || value == null;
    b.classList.toggle("zero", zero);
    if (cls !== undefined) { ["ok", "warn", "crit"].forEach((c) => b.classList.toggle(c, c === cls)); }
  }
  const sevClass = (v, warn, crit) => (v >= crit ? "crit" : v >= warn ? "warn" : "ok");
  function renderHeader() {
    const m = S.metrics;
    if (m) {
      $("host-line").textContent = `${m.hostname} · ${m.os}`;
      const hc = $("hs-cpu"), hm = $("hs-mem");
      hc.querySelector(".hs-v").textContent = fmtPct(m.cpu);
      hc.querySelector("i[data-w]").dataset.w = m.cpu.toFixed(1);
      hc.className = "hs " + sevClass(m.cpu, 70, 90);
      hm.querySelector(".hs-v").textContent = fmtPct(m.memPercent);
      hm.querySelector("i[data-w]").dataset.w = m.memPercent.toFixed(1);
      hm.className = "hs " + sevClass(m.memPercent, 80, 92);
      applyWidths($("hstats"));
      setBadge("b-cpu", Math.round(m.cpu) + "%", sevClass(m.cpu, 70, 90));
      const worst = Math.max(0, ...(m.disks || []).map((d) => d.percent));
      setBadge("b-disk", (m.disks || []).length ? Math.round(worst) + "%" : 0, sevClass(worst, 85, 92));
    }
    const [tin, tout] = totals();
    $("hs-net").querySelector(".hs-v").textContent = S.ifAvail ? `↓${fmtRate(tin)} ↑${fmtRate(tout)}` : "—";
    const h = S.health;
    if (h) {
      const el = $("hs-health");
      el.querySelector(".hs-v").textContent = Math.round(h.score);
      el.className = "hs grade-" + h.grade;
      setBadge("b-health", Math.round(h.score), h.score >= 90 ? "ok" : h.score >= 75 ? "warn" : "crit");
    }
    setBadge("b-if", S.ifs.filter((x) => x.up && x.kind !== "loopback").length);
    const sum = S.svcSum;
    if (sum) setBadge("b-svc", sum.autoFailed || 0);
    const firing = S.ruleStates.reduce((n, r) => n + (r.firing || 0), 0);
    setBadge("b-rules", firing);
    const sw = S.software;
    if (sw?.apps) setBadge("b-apps", sw.apps.filter((a) => !a.hidden).length);
    const reps = Object.values(S.audit?.reports || {});
    setBadge("b-diag", reps.reduce((n, r) => n + (r.findings || []).filter((f) => f.severity !== "info").length, 0));
    labelNavBadges();
  }
  let lastNavLabel = 0;
  function labelNavBadges() { if (shell.classList.contains("collapsed") && Date.now() - lastNavLabel > 3000) { lastNavLabel = Date.now(); labelNav(); } }

  // =========================================================================
  // CPU-driven EKG (sidebar brand + large monitor on the Health view)
  // =========================================================================
  // A PQRST complex is synthesised per beat. Heart rate follows the live
  // processor load (60 bpm idle → 180 bpm saturated), R-wave amplitude and
  // baseline jitter grow with load, and the trace colour moves from cyan to
  // amber to rose. With no telemetry for >5 s the trace flat-lines red.
  const gauss = (x, mu, sd) => Math.exp(-((x - mu) ** 2) / (2 * sd * sd));
  const pqrst = (ph) => 0.12 * gauss(ph, 0.14, 0.025) - 0.12 * gauss(ph, 0.235, 0.008) + 1.0 * gauss(ph, 0.255, 0.009)
    - 0.28 * gauss(ph, 0.278, 0.01) + 0.3 * gauss(ph, 0.47, 0.045);
  const ekgState = { cpu: 0, last: 0, lastData: 0 };
  function ekgLive() { return S.metrics && Date.now() - ekgState.lastData < 5000; }
  function ekgColor(cpu, live) { if (!live) return [248, 113, 113]; return cpu >= 85 ? [244, 63, 94] : cpu >= 60 ? [251, 191, 36] : [34, 211, 238]; }
  function makeMonitor(canvas, opts) {
    const mon = { c: canvas, buf: [], x: 0, opts };
    mon.resize = () => {
      const dpr = window.devicePixelRatio || 1;
      const w = Math.max(20, canvas.clientWidth), h = +canvas.getAttribute("height") || 32;
      canvas.width = Math.round(w * dpr); canvas.height = Math.round(h * dpr);
      canvas.style.height = h + "px";
      mon.w = w; mon.h = h; mon.dpr = dpr;
      mon.buf = new Array(Math.ceil(w)).fill(0); mon.x = 0;
      // Pre-fill one full sweep at the current rate so a monitor that was
      // hidden (0 px wide) is never shown as a flat line when it appears.
      if (ekgLive()) {
        const cpu = ekgState.cpu, dPhase = (60 + cpu * 1.2) / 60 / mon.opts.speed, ampK = 0.55 + (cpu / 100) * 0.45;
        for (let i = 0; i < mon.buf.length; i++) { mon.phase = ((mon.phase || 0) + dPhase) % 1; mon.buf[i] = pqrst(mon.phase) * ampK; }
      }
    };
    mon.resize();
    return mon;
  }
  const monitors = [makeMonitor($("ekg"), { speed: 46, line: 1.8, grid: false }), makeMonitor($("ekg-big"), { speed: 120, line: 2.4, grid: true })];
  window.addEventListener("resize", () => monitors.forEach((m) => m.resize()));
  // Sweep monitor: the write head moves left→right (right→left in RTL) and
  // overwrites the oldest samples; a blank band ahead of the head and an age
  // fade reproduce a hospital bedside monitor.
  function drawMonitor(mon, color, live) {
    const { c, w, h, dpr, buf } = mon;
    if (!w || !c.clientWidth) return;
    const g = c.getContext("2d");
    g.setTransform(dpr, 0, 0, dpr, 0, 0);
    g.clearRect(0, 0, w, h);
    if (mon.opts.grid) {
      g.strokeStyle = "rgba(34,211,238,.07)"; g.lineWidth = 1;
      for (let x = 0; x < w; x += 20) { g.beginPath(); g.moveTo(x + 0.5, 0); g.lineTo(x + 0.5, h); g.stroke(); }
      for (let y = 0; y < h; y += 20) { g.beginPath(); g.moveTo(0, y + 0.5); g.lineTo(w, y + 0.5); g.stroke(); }
    }
    const n = buf.length, head = mon.x, mid = h * 0.6, amp = h * 0.48;
    const gap = Math.max(6, Math.round(n * 0.05)), chunks = 6;
    const [r, gg, b] = color;
    const X = (i) => (rtl() ? w - 1 - i : i);
    g.lineWidth = mon.opts.line; g.lineJoin = "round"; g.lineCap = "round";
    g.shadowColor = `rgba(${r},${gg},${b},.85)`; g.shadowBlur = REDUCED ? 0 : 6;
    const span = n - gap;
    for (let ch = 0; ch < chunks; ch++) {
      const k0 = gap + Math.floor((ch * span) / chunks), k1 = gap + Math.floor(((ch + 1) * span) / chunks);
      g.strokeStyle = `rgba(${r},${gg},${b},${(0.25 + 0.75 * ((ch + 1) / chunks)).toFixed(3)})`;
      g.beginPath();
      let prev = -2;
      for (let k = Math.max(gap, k0 - 1); k < k1; k++) {
        const i = (head + k) % n; // oldest → newest
        const y = mid - buf[i] * amp;
        if (i !== prev + 1) g.moveTo(X(i), y); else g.lineTo(X(i), y);
        prev = i;
      }
      g.stroke();
    }
    g.shadowBlur = 0;
    if (live) {
      const i = (head - 1 + n) % n;
      g.fillStyle = "#ecfeff"; g.shadowColor = `rgb(${r},${gg},${b})`; g.shadowBlur = REDUCED ? 0 : 8;
      g.beginPath(); g.arc(X(i), mid - buf[i] * amp, mon.opts.line + 0.6, 0, Math.PI * 2); g.fill(); g.shadowBlur = 0;
    }
  }
  function ekgFrame(ts) {
    const dt = Math.min(0.1, ekgState.last ? (ts - ekgState.last) / 1000 : 0.016);
    ekgState.last = ts;
    const live = ekgLive();
    const target = live ? S.metrics.cpu || 0 : 0;
    ekgState.cpu += (target - ekgState.cpu) * Math.min(1, dt * 2.5); // ease toward the live load
    const cpu = ekgState.cpu;
    const bpm = 60 + cpu * 1.2;               // 60 bpm idle … 180 bpm saturated
    const ampK = 0.55 + (cpu / 100) * 0.45;   // stronger R wave under load
    const jitter = 0.012 + (cpu / 100) * 0.05; // noisier baseline under load
    const color = ekgColor(cpu, live);
    monitors.forEach((mon) => {
      if (!mon.c.clientWidth) return;
      if (mon.buf.length !== Math.ceil(mon.c.clientWidth)) mon.resize();
      mon.acc = (mon.acc || 0) + mon.opts.speed * dt;
      const dPhase = bpm / 60 / mon.opts.speed; // beats per pixel
      while (mon.acc >= 1) {
        mon.acc -= 1;
        mon.phase = ((mon.phase || 0) + dPhase) % 1;
        mon.buf[mon.x] = live ? pqrst(mon.phase) * ampK + (Math.random() - 0.5) * jitter : 0;
        mon.x = (mon.x + 1) % mon.buf.length;
      }
      drawMonitor(mon, color, live);
    });
    ekgState.bpm = live ? bpm : 0;
    if (!REDUCED) requestAnimationFrame(ekgFrame);
  }
  if (REDUCED) setInterval(() => ekgFrame(performance.now()), 250); else requestAnimationFrame(ekgFrame);

  // =========================================================================
  // Message plumbing
  // =========================================================================
  const HIST = 60;
  function pushRing(arr, v, max) { arr.push(v); if (arr.length > max) arr.splice(0, arr.length - max); }
  function ingestIfs(st, withHistory) {
    S.ifAvail = !!st.available; S.ifErr = st.error || "";
    S.ifs = st.interfaces || [];
    if (withHistory && st.history) {
      S.ifHist = new Map(Object.entries(st.history).map(([k, h]) => [+k, { in: h.in || [], out: h.out || [] }]));
    } else {
      const live = new Set();
      S.ifs.forEach((x) => {
        live.add(x.index);
        let h = S.ifHist.get(x.index);
        if (!h) { h = { in: [], out: [] }; S.ifHist.set(x.index, h); }
        pushRing(h.in, x.inBps, HIST); pushRing(h.out, x.outBps, HIST);
      });
      [...S.ifHist.keys()].forEach((k) => { if (!live.has(k)) S.ifHist.delete(k); });
    }
    pushRing(S.ifTotals, { in: st.totalIn || 0, out: st.totalOut || 0 }, HIST);
  }
  function ingestRules(st) {
    S.rules = st.rules || []; S.ruleStates = st.states || []; S.catalog = st.catalog || S.catalog; S.rulesFile = st.file || "";
  }
  function trackProcs() {
    // 60-sample per-PID rings for the high-resource trackers (sustained
    // CPU average and private-bytes growth), keyed by PID + start time so a
    // recycled PID never inherits another process's history.
    const now = Date.now(), seen = new Set();
    S.procs.forEach((p) => {
      if (!p.access) return;
      const k = p.pid + ":" + (p.started || 0);
      seen.add(k);
      let r = S.procTrack.get(k);
      if (!r) { r = { pid: p.pid, name: p.name, cpu: [], priv: [] }; S.procTrack.set(k, r); }
      pushRing(r.cpu, p.cpu, HIST); pushRing(r.priv, [now, p.private], HIST);
      r.ws = p.workingSet; r.name = p.name;
    });
    [...S.procTrack.keys()].forEach((k) => { if (!seen.has(k)) S.procTrack.delete(k); });
  }
  SP.onMessage((type, d) => {
    switch (type) {
      case "snapshot":
        if (d.interfaces) ingestIfs(d.interfaces, true);
        if (d.services) { S.svcAvail = !!d.services.available; S.svcSum = d.services.summary; S.svcs = d.services.services || []; }
        if (d.rules) ingestRules(d.rules);
        S.health = d.health && d.health.at ? d.health : null;
        S.procmeta = d.procmeta || S.procmeta;
        S.coreHist = (d.history || []).filter((m) => m.perCore).slice(-HIST).map((m) => m.perCore);
        S.healthHist = [];
        ekgState.lastData = Date.now();
        trackProcs();
        break;
      case "metrics":
        ekgState.lastData = Date.now();
        if (d.perCore) pushRing(S.coreHist, d.perCore, HIST);
        break;
      case "processes": trackProcs(); break;
      case "ifstats": ingestIfs(d, false); break;
      case "services":
        S.svcAvail = !!d.available; S.svcSum = d.summary;
        if (d.services) S.svcs = d.services;
        break;
      case "rules": ingestRules(d); break;
      case "rulestate": S.ruleStates = d || []; break;
      case "health": S.health = d; pushRing(S.healthHist, [d.at, d.score], 300); break;
      case "procmeta": S.procmeta = d || S.procmeta; break;
    }
  });
  const totals = () => { const x = S.ifTotals[S.ifTotals.length - 1]; return x ? [x.in, x.out] : [0, 0]; };

  // =========================================================================
  // Overview additions + health gauge
  // =========================================================================
  const GRADE_COLOR = { excellent: "#34d399", good: "#22d3ee", degraded: "#fbbf24", critical: "#f43f5e" };
  function renderOverviewExtra() {
    const h = S.health;
    if (h) {
      $("c-health").textContent = Math.round(h.score);
      $("c-health").className = "v grade-t-" + h.grade;
      $("c-health2").textContent = t("grade." + h.grade) + (h.factors?.length ? " · " + tx(h.factors[0].detail) : "");
    }
    const [tin, tout] = totals();
    $("c-net").textContent = S.ifAvail ? `↓ ${fmtRate(tin)}` : "—";
    $("c-net2").textContent = S.ifAvail ? `↑ ${fmtRate(tout)} · ${t("bw.upCount", { n: S.ifs.filter((x) => x.up && x.kind !== "loopback").length })}` : t("bw.na");
  }
  let ticksDrawn = false;
  function drawTicks() {
    if (ticksDrawn) return;
    ticksDrawn = true;
    const g = $("g-ticks"), ns = "http://www.w3.org/2000/svg";
    for (let i = 0; i <= 10; i++) {
      const a = Math.PI * (1 - i / 10), r1 = 86, r2 = i % 5 ? 80 : 74;
      const l = document.createElementNS(ns, "line");
      l.setAttribute("x1", (120 + r1 * Math.cos(a)).toFixed(2)); l.setAttribute("y1", (130 - r1 * Math.sin(a)).toFixed(2));
      l.setAttribute("x2", (120 + r2 * Math.cos(a)).toFixed(2)); l.setAttribute("y2", (130 - r2 * Math.sin(a)).toFixed(2));
      l.setAttribute("class", "g-tick");
      g.appendChild(l);
    }
  }
  function renderHealth() {
    drawTicks();
    const h = S.health;
    const score = h ? h.score : 0;
    $("g-fill").setAttribute("stroke-dasharray", `${score.toFixed(1)} 100`);
    $("g-fill").setAttribute("stroke", h ? GRADE_COLOR[h.grade] : "#334155");
    $("g-score").textContent = h ? Math.round(score) : "–";
    $("g-grade").textContent = h ? t("grade." + h.grade) : t("health.waiting");
    $("gauge").setAttribute("class", "gauge " + (h ? "grade-" + h.grade : ""));
    $("g-sub").textContent = h ? t("health.sub", { n: (h.factors || []).length, t: SP.fmtTime(h.at) }) : "";
    const m = S.metrics;
    $("pulse-stats").innerHTML = [
      [t("health.bpm"), ekgState.bpm ? Math.round(ekgState.bpm) : "—"],
      [t("cpu.total"), m ? fmtPct(m.cpu) : "—"],
      [t("cpu.kernel"), m ? fmtPct(m.kernelPct) : "—"],
      [t("ov.memory"), m ? fmtPct(m.memPercent) : "—"],
    ].map(([k, v]) => `<div><span class="k">${esc(k)}</span><b>${esc(v)}</b></div>`).join("");
    $("h-factors").innerHTML = (h?.factors || []).map((f) => `
      <div class="factor"><div class="f-top"><span>${esc(tx(f.detail))}</span><b class="neg">−${f.penalty.toFixed(1)}</b></div>
      <div class="meter hot"><i data-w="${clamp(f.penalty * 4, 2, 100).toFixed(1)}"></i></div>
      <div class="muted small">${esc(t("health.observed", { v: f.value }))}</div></div>`).join("")
      || `<div class="okbox">${esc(t(h ? "health.perfect" : "health.waiting"))}</div>`;
    applyWidths($("h-factors"));
    const firing = [];
    S.ruleStates.forEach((st) => {
      const r = S.rules.find((x) => x.id === st.id);
      (st.instances || []).filter((i) => i.firing).forEach((i) => firing.push({ r, i }));
    });
    $("h-firing").innerHTML = firing.map(({ r, i }) => `<div class="firing-row"><span class="sev ${esc(r?.severity || "info")}">${esc(t("sev." + (r?.severity || "info")))}</span>
      <b>${esc(ruleName(r))}</b>${i.instance ? ` <span class="mono muted">${ltr(i.label || i.instance)}</span>` : ""}<span class="spacer"></span><span class="mono">${esc(fmtMetric(r?.metric, i.value))}</span></div>`).join("")
      || `<div class="muted">${esc(t("health.noneFiring"))}</div>`;
    drawLine($("ch-health"), [S.healthHist.map((x) => x[1])], ["#34d399"], 100, "", 300);
  }

  // Generic multi-series line chart (fixed-width ring, newest on the right).
  function drawLine(c, series, colors, max, suffix, slots, fmtAxis) {
    if (!c || !c.clientWidth) return;
    const { g, w, h } = setupCanvas(c);
    const x0 = 44, y0 = 8, cw = w - x0 - 6, chh = h - 20;
    const top = max || Math.max(1, ...series.flat()) * 1.15;
    if (fmtAxis) {
      g.strokeStyle = "#1a2442"; g.fillStyle = "#6b7899"; g.font = "11px Segoe UI, Tahoma, sans-serif";
      for (let i = 0; i <= 4; i++) {
        const y = y0 + chh - (chh * i) / 4;
        g.beginPath(); g.moveTo(x0, y + 0.5); g.lineTo(x0 + cw, y + 0.5); g.stroke();
        g.fillText(fmtAxis((top * i) / 4), 2, y + 4);
      }
    } else grid(g, x0, y0, cw, chh, top, suffix);
    series.forEach((pts, si) => {
      if (pts.length < 2) return;
      const color = colors[si];
      const xs = (i) => x0 + (cw * (slots - pts.length + i)) / (slots - 1);
      const ys = (v) => y0 + chh - (chh * clamp(v || 0, 0, top)) / top;
      const grad = g.createLinearGradient(0, y0, 0, y0 + chh);
      grad.addColorStop(0, color + "55"); grad.addColorStop(1, color + "00");
      g.beginPath();
      pts.forEach((v, i) => (i ? g.lineTo(xs(i), ys(v)) : g.moveTo(xs(i), ys(v))));
      g.strokeStyle = color; g.lineWidth = 2; g.stroke();
      g.lineTo(xs(pts.length - 1), y0 + chh); g.lineTo(xs(0), y0 + chh); g.closePath(); g.fillStyle = grad; g.fill();
    });
  }

  // =========================================================================
  // CPU & memory profiler
  // =========================================================================
  // Heat colour: deep navy → cyan → amber → rose (perceptually ordered).
  const HEAT = [[0, [14, 22, 44]], [0.25, [8, 145, 178]], [0.5, [34, 211, 238]], [0.75, [251, 191, 36]], [1, [244, 63, 94]]];
  function heat(v) {
    const x = clamp(v / 100, 0, 1);
    for (let i = 1; i < HEAT.length; i++) {
      if (x <= HEAT[i][0]) {
        const [a, ca] = HEAT[i - 1], [b, cb] = HEAT[i], k = (x - a) / (b - a);
        return `rgb(${ca.map((c, j) => Math.round(c + (cb[j] - c) * k)).join(",")})`;
      }
    }
    return "rgb(244,63,94)";
  }
  function drawHeatmap() {
    const c = $("ch-heat"); if (!c.clientWidth) return;
    const rows = S.coreHist;
    const n = rows.length ? rows[rows.length - 1].length : 0;
    $("core-na").hidden = n > 0;
    c.hidden = n === 0;
    if (!n) return;
    const rowH = clamp(Math.floor(260 / n), 6, 22);
    const want = String(rowH * n + 18);
    if (c.getAttribute("height") !== want) { c.setAttribute("height", want); c.width = 0; } // force setupCanvas to re-rasterise
    const { g, w, h } = setupCanvas(c);
    const x0 = 48, cw = w - x0 - 4, colW = cw / HIST;
    g.font = "10.5px Segoe UI, Tahoma, sans-serif"; g.fillStyle = "#6b7899";
    for (let core = 0; core < n; core++) {
      const y = core * rowH;
      if (rowH >= 9 || core % 2 === 0) g.fillText("CPU " + core, 2, y + rowH - 2);
      rows.forEach((row, i) => {
        const x = x0 + (HIST - rows.length + i) * colW;
        g.fillStyle = heat(row[core] || 0);
        g.fillRect(x, y + 1, Math.ceil(colW), rowH - 2);
      });
      g.fillStyle = "#6b7899";
    }
    g.fillText("-60s", x0, h - 3); g.fillText("0s", w - 16, h - 3);
  }
  function renderCPU() {
    const m = S.metrics; if (!m) return;
    const pc = m.perCore || [];
    $("p-cpu").textContent = fmtPct(m.cpu);
    $("p-cores").textContent = t("ov.cores", { n: m.cores });
    $("p-kernel").textContent = fmtPct(m.kernelPct);
    $("p-user").textContent = fmtPct(m.userPct);
    if (pc.length) {
      let hi = 0; pc.forEach((v, i) => { if (v > pc[hi]) hi = i; });
      $("p-hot").textContent = fmtPct(pc[hi]);
      $("p-hot2").textContent = "CPU " + hi;
      $("p-imb").textContent = fmtPct(Math.max(...pc) - Math.min(...pc));
    } else { $("p-hot").textContent = "—"; $("p-hot2").textContent = t("cpu.noCoresShort"); $("p-imb").textContent = "—"; }
    $("core-grid").innerHTML = pc.map((v, i) => `<div class="core" title="CPU ${i}: ${v.toFixed(1)}%"><span class="cn">${i}</span><div class="cbar"><i data-h="${v.toFixed(1)}" class="${v >= 85 ? "hot" : v >= 60 ? "warm" : ""}"></i></div><span class="cv">${Math.round(v)}</span></div>`).join("");
    $("core-grid").querySelectorAll("i[data-h]").forEach((i) => { i.style.height = clamp(+i.dataset.h, 0, 100) + "%"; });
    drawHeatmap();
    const hist = S.history.slice(-300);
    drawLine($("ch-ku"), [hist.map((x) => x.kernelPct || 0), hist.map((x) => x.userPct || 0)], ["#f472b6", "#22d3ee"], 100, "%", 300);
    // Memory composition
    const md = m.memDetail || {};
    const used = m.memUsed, total = m.memTotal || 1;
    const st = $("mem-stack");
    st.querySelector(".ms-used").dataset.w = ((used / total) * 100).toFixed(1);
    st.querySelector(".ms-avail").dataset.w = (100 - (used / total) * 100).toFixed(1);
    applyWidths(st);
    const kv = [
      ["mem.total", fmtBytes(total)], ["mem.inUse", `${fmtBytes(used)} (${fmtPct(m.memPercent)})`], ["mem.available", fmtBytes(md.available ?? total - used)],
      ["mem.cached", md.cached != null ? fmtBytes(md.cached) : "—"],
      ["mem.commit", m.commitTotal ? `${fmtBytes(m.commitUsed)} / ${fmtBytes(m.commitTotal)} (${fmtPct((m.commitUsed / m.commitTotal) * 100)})` : m.commitUsed ? `${fmtBytes(m.commitUsed)} (${t("mem.noLimit")})` : "—"],
      ["mem.commitPeak", md.commitPeak ? fmtBytes(md.commitPeak) : "—"],
      ["mem.paged", md.kernelPaged != null ? fmtBytes(md.kernelPaged) : "—"], ["mem.nonpaged", md.kernelNonpaged != null ? fmtBytes(md.kernelNonpaged) : "—"],
      ["mem.pagefile", md.pageFileTotal ? fmtBytes(md.pageFileTotal) : "—"], ["mem.handles", md.handles ? fmtNum(md.handles) : "—"],
      ["ov.threads2", fmtNum(m.threads)],
    ];
    $("mem-kv").innerHTML = kv.map(([k, v]) => `<dt>${esc(t(k))}</dt><dd class="mono">${esc(v)}</dd>`).join("");
  }

  // =========================================================================
  // Storage matrix
  // =========================================================================
  const stSort = sortable("st-table", "mount", 1, () => SP.renderAll());
  const volState = (p) => (p >= 97 ? "critical" : p >= 92 ? "warning" : p >= 85 ? "watch" : "ok");
  function renderStorage() {
    const disks = (S.metrics?.disks || []).slice();
    const tot = disks.reduce((a, d) => a + d.total, 0), used = disks.reduce((a, d) => a + d.used, 0), free = disks.reduce((a, d) => a + d.free, 0);
    const worst = disks.reduce((a, d) => (d.percent > (a?.percent ?? -1) ? d : a), null);
    $("st-sum").innerHTML = [
      ["st.volumes", disks.length, ""], ["st.capacity", fmtBytes(tot), ""], ["st.used", fmtBytes(used), tot ? fmtPct((used / tot) * 100) : ""],
      ["st.free", fmtBytes(free), ""], ["st.fullest", worst ? worst.mount : "—", worst ? fmtPct(worst.percent) : ""],
    ].map(([k, v, sub]) => `<div class="card glass"><div class="k">${esc(t(k))}</div><div class="v small-v">${k === "st.fullest" ? ltr(v) : esc(v)}</div><div class="s">${esc(sub)}</div></div>`).join("");
    $("st-matrix").innerHTML = disks.map((d) => {
      const stt = volState(d.percent);
      return `<div class="vol glass ${stt}">
        <div class="vol-h"><b>${ltr(d.mount)}</b><span class="pill">${esc(tOr("dtype." + d.type, d.type))}</span><span class="spacer"></span><span class="vol-s ${stt}">${esc(t("st.state." + stt))}</span></div>
        <div class="vol-ring"><svg viewBox="0 0 36 36"><circle class="vr-bg" cx="18" cy="18" r="15.9155"/><circle class="vr-fg ${stt}" cx="18" cy="18" r="15.9155" pathLength="100" stroke-dasharray="${d.percent.toFixed(1)} 100"/></svg><span>${Math.round(d.percent)}%</span></div>
        <div class="vol-f"><span>${esc(t("ov.free", { f: fmtBytes(d.free), t: fmtBytes(d.total) }))}</span></div></div>`;
    }).join("") || `<div class="muted">${esc(t("ov.noVolumes"))}</div>`;
    disks.sort(cmp(stSort));
    $("st-table").tBodies[0].innerHTML = disks.map((d) => `<tr><td class="mono">${ltr(d.mount)}</td><td class="muted">${esc(d.type)}</td><td class="num">${fmtBytes(d.total)}</td>
      <td class="num">${fmtBytes(d.used)}</td><td class="num">${fmtBytes(d.free)}</td><td class="num"><span class="meter inline ${d.percent >= 92 ? "hot" : ""}"><i data-w="${d.percent.toFixed(1)}"></i></span> ${fmtPct(d.percent)}</td>
      <td><span class="vol-s ${volState(d.percent)}">${esc(t("st.state." + volState(d.percent)))}</span></td></tr>`).join("");
    applyWidths($("st-table"));
  }

  // =========================================================================
  // Services monitor
  // =========================================================================
  const START_TYPES = ["auto", "auto-delayed", "manual", "disabled", "boot", "system"];
  const svcSort = sortable("svc-table", "display", 1, () => SP.renderAll());
  let svcFilter = "";
  const svcFailed = (s) => s.state === "stopped" && s.exitCode && s.exitCode !== 1077;
  const isAuto = (s) => s.startType === "auto" || s.startType === "auto-delayed";
  function renderServices() {
    const sum = S.svcSum || {};
    const sel = $("svc-start");
    if (sel.options.length === 1) START_TYPES.forEach((k) => sel.add(new Option(t("start." + k), k)));
    $("svc-cards").innerHTML = [
      ["svc.total", sum.total ?? "—", "", ""], ["svc.running", sum.running ?? "—", "ok-t", "running"], ["svc.stopped", sum.stopped ?? "—", "", "stopped"],
      ["svc.autoFailed", sum.autoFailed ?? "—", sum.autoFailed ? "crit-t" : "", "failed"], ["svc.autoStopped", sum.autoStopped ?? "—", sum.autoStopped ? "warn-t" : "", "autostopped"],
      ["svc.disabled", sum.disabled ?? "—", "", "disabled"],
    ].map(([k, v, c, f]) => `<button class="card glass clickable" data-sfc="${f}"><div class="k">${esc(t(k))}</div><div class="v ${c}">${esc(v)}</div></button>`).join("");
    const err = $("svc-err");
    const emsg = !S.svcAvail ? t("svc.na") : sum.error ? t("svc.err", { e: sum.error }) : "";
    err.hidden = !emsg; err.textContent = emsg;
    document.querySelectorAll("#svc-chips .chip").forEach((c) => c.classList.toggle("active", c.dataset.sf === svcFilter));
    const q = $("svc-q").value.trim().toLowerCase(), st = sel.value;
    const rows = S.svcs.filter((s) => {
      if (st && s.startType !== st) return false;
      switch (svcFilter) {
        case "running": if (s.state !== "running") return false; break;
        case "stopped": if (s.state !== "stopped") return false; break;
        case "failed": if (!(isAuto(s) && svcFailed(s))) return false; break;
        case "autostopped": if (!(isAuto(s) && s.state === "stopped")) return false; break;
        case "disabled": if (s.startType !== "disabled") return false; break;
      }
      return !q || `${s.name} ${s.display} ${s.account || ""} ${s.binary || ""} ${s.pid || ""}`.toLowerCase().includes(q);
    }).sort(cmp(svcSort));
    $("svc-count").textContent = t("svc.count", { n: rows.length, total: S.svcs.length });
    $("svc-table").tBodies[0].innerHTML = rows.slice(0, 1500).map((s, i) => `<tr data-svc="${i}" class="${isAuto(s) && svcFailed(s) ? "sev-row critical" : ""}">
      <td>${esc(s.display)}</td><td class="mono">${ltr(s.name)}</td><td><span class="sstate ${esc(s.state)}">${esc(t("sstate." + s.state))}</span></td>
      <td>${esc(t("start." + (s.startType || "manual")))}</td><td class="num mono">${s.pid || ""}</td><td class="muted">${esc(t("stype." + (s.type || "other")))}</td>
      <td class="muted mono">${ltr(s.account || "")}</td><td class="num mono ${svcFailed(s) ? "crit-t" : "muted"}">${s.exitCode || ""}</td></tr>`).join("")
      || `<tr><td colspan="8" class="muted">${esc(t(S.svcAvail ? "svc.none" : "svc.na"))}</td></tr>`;
    S.svcRows = rows;
    $("svc-foot").textContent = sum.updated ? t("svc.foot", { t: SP.fmtTime(sum.updated) }) : "";
  }
  $("svc-chips").addEventListener("click", (ev) => { const c = ev.target.closest(".chip"); if (!c) return; svcFilter = c.dataset.sf; SP.renderAll(); });
  $("svc-cards").addEventListener("click", (ev) => { const c = ev.target.closest("[data-sfc]"); if (!c) return; svcFilter = svcFilter === c.dataset.sfc ? "" : c.dataset.sfc; SP.renderAll(); });
  $("svc-table").addEventListener("click", (ev) => {
    const row = ev.target.closest("[data-svc]"); if (!row) return;
    const s = S.svcRows[+row.dataset.svc]; if (!s) return;
    const kv = [["svc.col.display", esc(s.display)], ["svc.col.name", `<span class="mono">${ltr(s.name)}</span>`], ["col.state", esc(t("sstate." + s.state))],
      ["svc.col.start", esc(t("start." + (s.startType || "manual")))], ["col.pid", s.pid || "—"], ["col.type", esc(t("stype." + (s.type || "other")))],
      ["svc.col.account", s.account ? `<span class="mono">${ltr(s.account)}</span>` : "—"], ["svc.col.exit", s.exitCode ? `<span class="mono">${s.exitCode}</span> ${s.exitCode === 1077 ? esc(t("svc.neverStarted")) : ""}` : "0"],
      ["svc.binary", s.binary ? `<code class="wrap">${esc(s.binary)}</code>` : "—"], ["svc.desc", esc(s.description || "—")]];
    const btns = [{ label: t("svc.copyName"), value: "name", ghost: true }];
    if (s.pid) btns.push({ label: t("svc.inspectHost"), value: "pid", ghost: true });
    btns.push({ label: t("btn.close"), value: false });
    modal(s.display, `<dl class="kv">${kv.map(([k, v]) => `<dt>${esc(t(k))}</dt><dd>${v}</dd>`).join("")}</dl>`, btns).then((v) => {
      if (v === "name") copyText(s.name);
      if (v === "pid") SP.inspectProcess(s.pid);
    });
  });

  // =========================================================================
  // Interface bandwidth meters
  // =========================================================================
  const IF_ICON = { ethernet: "🖧", wifi: "📶", loopback: "↺", tunnel: "🔒", virtual: "🧊", cellular: "📡", other: "◇" };
  function sparkPath(vals, w, h, top) {
    if (!vals.length) return "";
    const step = w / (HIST - 1), off = HIST - vals.length;
    return vals.map((v, i) => `${i ? "L" : "M"}${((off + i) * step).toFixed(1)} ${(h - 1 - (h - 2) * clamp(v / top, 0, 1)).toFixed(1)}`).join(" ");
  }
  function spark(h) {
    const W = 240, H = 46;
    const top = Math.max(1024, ...h.in, ...h.out) * 1.1;
    const pin = sparkPath(h.in, W, H, top), pout = sparkPath(h.out, W, H, top);
    const area = pin ? `${pin} L${W} ${H} L${(((HIST - h.in.length) * W) / (HIST - 1)).toFixed(1)} ${H} Z` : "";
    return `<svg class="spark" viewBox="0 0 ${W} ${H}" preserveAspectRatio="none" aria-hidden="true"><path class="sp-area" d="${area}"/><path class="sp-in" d="${pin}"/><path class="sp-out" d="${pout}"/></svg>`;
  }
  function renderBandwidth() {
    const [tin, tout] = totals();
    const up = S.ifs.filter((x) => x.up && x.kind !== "loopback");
    $("bw-in").textContent = fmtRate(tin); $("bw-out").textContent = fmtRate(tout);
    const sumIn = up.reduce((a, x) => a + x.inTotal, 0), sumOut = up.reduce((a, x) => a + x.outTotal, 0);
    $("bw-in2").textContent = t("bw.sinceBoot", { v: fmtBytes(sumIn) }); $("bw-out2").textContent = t("bw.sinceBoot", { v: fmtBytes(sumOut) });
    $("bw-up").textContent = up.length;
    $("bw-up2").textContent = t("bw.phys", { p: up.filter((x) => x.physical).length, v: up.filter((x) => !x.physical).length });
    const top = up.slice().sort((a, b) => b.inBps + b.outBps - (a.inBps + a.outBps))[0];
    $("bw-top").innerHTML = top ? ltr(top.name) : "—";
    $("bw-top2").textContent = top ? `↓ ${fmtRate(top.inBps)} · ↑ ${fmtRate(top.outBps)}` : "";
    const err = $("bw-err"); const emsg = !S.ifAvail ? t("bw.na") : S.ifErr;
    err.hidden = !emsg; err.textContent = emsg || "";
    drawLine($("ch-bw"), [S.ifTotals.map((x) => x.in), S.ifTotals.map((x) => x.out)], ["#34d399", "#a78bfa"], 0, "", HIST, fmtRate);
    const q = $("bw-q").value.trim().toLowerCase(), showV = $("bw-virtual").checked, showL = $("bw-loop").checked, showD = $("bw-down").checked;
    const list = S.ifs.filter((x) => (showV || x.physical || x.kind === "loopback") && (showL || x.kind !== "loopback") && (showD || x.up) &&
      (!q || `${x.name} ${x.desc || ""} ${x.mac || ""} ${x.kind}`.toLowerCase().includes(q)));
    $("if-grid").innerHTML = list.map((x) => {
      const h = S.ifHist.get(x.index) || { in: [], out: [] };
      const util = x.speed ? x.util : null;
      return `<div class="ifc glass ${x.up ? "" : "down"}" data-if="${x.index}">
        <div class="ifc-h"><span class="ifi">${IF_ICON[x.kind] || "◇"}</span><div class="ifn"><b dir="auto">${esc(x.name)}</b><div class="muted small ifd" dir="auto" title="${esc(x.desc || "")}">${esc(x.desc || "")}</div></div>
          <span class="pill ${x.physical ? "phys" : "virt"}">${esc(t(x.physical ? "bw.physical" : "bw.virtual"))}</span><span class="pill">${esc(t("ifk." + x.kind))}</span></div>
        <div class="ifc-rates"><div><span class="k">↓ ${esc(t("bw.in"))}</span><b class="in-t">${fmtRate(x.inBps)}</b><span class="muted small">${Math.round(x.inPps || 0)} pkt/s</span></div>
          <div><span class="k">↑ ${esc(t("bw.out"))}</span><b class="out-t">${fmtRate(x.outBps)}</b><span class="muted small">${Math.round(x.outPps || 0)} pkt/s</span></div></div>
        ${spark(h)}
        <div class="ifc-f"><span>${esc(t("bw.link"))}: <b>${esc(fmtBits(x.speed))}</b></span>${util != null ? `<span class="meter inline ${util > 80 ? "hot" : ""}"><i data-w="${util.toFixed(1)}"></i></span><span>${util.toFixed(util < 10 ? 2 : 1)}%</span>` : ""}
          <span class="spacer"></span>${x.mac ? `<span class="mono muted">${ltr(x.mac)}</span>` : ""}</div>
        ${x.errors || x.discards ? `<div class="ifc-e small">${esc(t("bw.errs", { e: fmtNum(x.errors), d: fmtNum(x.discards) }))}</div>` : ""}
      </div>`;
    }).join("") || `<div class="muted">${esc(t(S.ifAvail ? "bw.none" : "bw.na"))}</div>`;
    applyWidths($("if-grid"));
  }
  ["bw-q", "bw-virtual", "bw-loop", "bw-down", "svc-q", "svc-start"].forEach((id) => { $(id).addEventListener("input", SP.renderAll); $(id).addEventListener("change", SP.renderAll); });
  $("if-grid").addEventListener("click", (ev) => {
    const c = ev.target.closest("[data-if]"); if (!c) return;
    const x = S.ifs.find((i) => i.index === +c.dataset.if); if (!x) return;
    const kv = [["bw.name", esc(x.name)], ["bw.adapter", esc(x.desc || "—")], ["bw.index", x.index], ["bw.kind", esc(t("ifk." + x.kind))],
      ["bw.class", esc(t(x.physical ? "bw.physical" : "bw.virtual"))], ["bw.status", esc(t(x.up ? "bw.up" : "bw.down"))], ["col.mac", x.mac ? ltr(x.mac) : "—"],
      ["bw.link", esc(fmtBits(x.speed))], ["bw.mtu", x.mtu || "—"], ["bw.in", fmtRate(x.inBps)], ["bw.out", fmtRate(x.outBps)],
      ["bw.totIn", fmtBytes(x.inTotal)], ["bw.totOut", fmtBytes(x.outTotal)], ["bw.errors", fmtNum(x.errors)], ["bw.discards", fmtNum(x.discards)]];
    modal(x.name, `<dl class="kv">${kv.map(([k, v]) => `<dt>${esc(t(k))}</dt><dd>${v}</dd>`).join("")}</dl>`);
  });

  // =========================================================================
  // Process hierarchy (Toolhelp32 PPID links, built client-side so every
  // 1 s sample re-renders without a second payload)
  // =========================================================================
  const expanded = new Set();
  let treeAllOpen = null; // null = default (depth < 2 open); true/false = user choice
  function buildTree(procs, svcMap) {
    const byPid = new Map(procs.map((p) => [p.pid, { p, kids: [], subCpu: p.cpu || 0, subWs: p.workingSet || 0, desc: 0, svcs: svcMap[p.pid] || [] }]));
    const roots = [];
    byPid.forEach((n) => {
      const par = byPid.get(n.p.ppid);
      // A parent that started after its "child" is a recycled PID (Windows reuses PIDs).
      const reused = par && par.p.started && n.p.started && par.p.started > n.p.started;
      if (!par || n.p.ppid === n.p.pid || n.p.pid === 0 || reused) roots.push(n); else par.kids.push(n);
    });
    const seen = new Set();
    const agg = (n, d) => {
      seen.add(n.p.pid); n.depth = d;
      n.kids = n.kids.filter((k) => !seen.has(k.p.pid));
      n.kids.forEach((k) => { agg(k, d + 1); n.subCpu += k.subCpu; n.subWs += k.subWs; n.desc += 1 + k.desc; });
    };
    roots.forEach((r) => agg(r, 0));
    return roots;
  }
  function sortTree(ns, key) {
    const f = { subCpu: (a, b) => b.subCpu - a.subCpu || b.subWs - a.subWs, subWs: (a, b) => b.subWs - a.subWs, name: (a, b) => a.p.name.localeCompare(b.p.name, undefined, { sensitivity: "base" }), pid: (a, b) => a.p.pid - b.p.pid }[key];
    ns.sort(f); ns.forEach((n) => sortTree(n.kids, key));
  }
  function renderTree() {
    const svcMap = S.procmeta?.services || {}, socks = S.procmeta?.sockets || {};
    const roots = buildTree(S.procs, svcMap);
    sortTree(roots, $("tree-sort").value);
    const q = $("tree-q").value.trim().toLowerCase();
    const match = (n) => `${n.p.name} ${n.p.pid} ${n.p.path || ""} ${n.svcs.join(" ")}`.toLowerCase().includes(q);
    // With a query, keep matching nodes plus their ancestors, and auto-expand the path.
    const keep = new Set(), hits = new Set();
    if (q) {
      const walk = (n, anc) => {
        let any = false;
        if (match(n)) { hits.add(n.p.pid); any = true; }
        n.kids.forEach((k) => { if (walk(k, anc.concat(n))) any = true; });
        if (any) keep.add(n.p.pid);
        return any;
      };
      roots.forEach((r) => walk(r, []));
    }
    const isOpen = (n) => (q ? keep.has(n.p.pid) : treeAllOpen === true ? true : treeAllOpen === false ? expanded.has(n.p.pid) : expanded.has(n.p.pid) || (n.depth < 1 && !expanded.has(-n.p.pid)));
    const rows = [];
    const emit = (n, guides) => {
      if (q && !keep.has(n.p.pid)) return;
      rows.push({ n, guides });
      if (n.kids.length && isOpen(n)) n.kids.forEach((k, i) => emit(k, guides.concat(i === n.kids.length - 1 ? "last" : "mid")));
    };
    roots.forEach((r) => emit(r, []));
    const shown = rows.slice(0, 3000);
    const memMax = Math.max(1, ...S.procs.map((p) => p.workingSet || 0));
    $("tree-table").tBodies[0].innerHTML = shown.map(({ n, guides }) => {
      const p = n.p, open = isOpen(n), hasKids = n.kids.length > 0;
      const indent = guides.map((g, i) => `<i class="tg ${i === guides.length - 1 ? g : "pipe"}"></i>`).join("");
      const caret = hasKids ? `<button class="tw ${open ? "open" : ""}" data-tw="${p.pid}" aria-label="${esc(t(open ? "tree.collapseNode" : "tree.expandNode"))}"><svg class="ico xs"><use href="#i-chev"/></svg></button>` : `<i class="tw-sp"></i>`;
      const wsPct = (p.workingSet / memMax) * 100, prPct = (p.private / memMax) * 100;
      const sc = socks[p.pid] || 0;
      const svcs = n.svcs.length ? `<span class="svc-list" title="${esc(n.svcs.join(", "))}">${n.svcs.slice(0, 3).map((x) => `<span class="pill svc">${esc(x)}</span>`).join("")}${n.svcs.length > 3 ? `<span class="muted small"> +${n.svcs.length - 3}</span>` : ""}</span>` : "";
      return `<tr data-pid="${p.pid}" class="${hits.has(p.pid) ? "hit" : ""} ${p.cpu >= 25 ? "hotrow" : ""}">
        <td class="tree-name"><span class="tind">${indent}</span>${caret}<b>${esc(p.name)}</b>${hasKids ? ` <span class="muted small">(${n.desc})</span>` : ""}</td>
        <td class="num mono">${p.pid}</td><td class="num">${p.access ? fmtPct(p.cpu) : `<span class="muted">—</span>`}</td>
        <td class="num ${n.subCpu >= 50 ? "hot-t" : ""}">${hasKids ? fmtPct(n.subCpu) : ""}</td>
        <td class="memcell">${p.access ? `<div class="mbar"><i class="ws" data-w="${wsPct.toFixed(1)}"></i><i class="pv" data-w="${prPct.toFixed(1)}"></i></div><span class="mono small">${fmtBytes(p.workingSet)} / ${fmtBytes(p.private)}</span>` : `<span class="muted small">${esc(t("proc.denied"))}</span>`}</td>
        <td class="num muted">${p.threads}</td><td class="num">${sc ? `<button class="linkbtn" data-socks="${p.pid}">${sc}</button>` : `<span class="muted">0</span>`}</td>
        <td>${svcs}</td>
        <td class="acts"><button class="iconbtn sm" data-pact="copy" title="${esc(t("act.copyPath"))}" aria-label="${esc(t("act.copyPath"))}">⧉</button><button class="iconbtn sm" data-pact="inspect" title="${esc(t("act.inspect"))}" aria-label="${esc(t("act.inspect"))}">🔍</button></td></tr>`;
    }).join("") || `<tr><td colspan="9" class="muted">${esc(t("proc.none"))}</td></tr>`;
    applyWidths($("tree-table"));
    $("tree-count").textContent = t("tree.count", { r: roots.length, n: S.procs.length });
    $("tree-foot").textContent = t("tree.foot", { n: rows.length }) + (rows.length > shown.length ? t("tree.first") : "");
  }
  $("tree-table").addEventListener("click", (ev) => {
    const tw = ev.target.closest("[data-tw]");
    if (tw) {
      const pid = +tw.dataset.tw, open = tw.classList.contains("open");
      if (treeAllOpen !== null) { // leave "all" mode, seeding the explicit set from what is visible
        if (treeAllOpen) S.procs.forEach((p) => expanded.add(p.pid));
        treeAllOpen = false;
      }
      if (open) { expanded.delete(pid); expanded.add(-pid); } else { expanded.add(pid); expanded.delete(-pid); }
      SP.renderAll(); return;
    }
    const row = ev.target.closest("[data-pid]"); if (!row) return;
    const pid = +row.dataset.pid;
    const sk = ev.target.closest("[data-socks]");
    if (sk) { $("net-q").value = String(pid); SP.showTab("sockets"); return; }
    const act = ev.target.closest("[data-pact]")?.dataset.pact;
    const p = S.procs.find((x) => x.pid === pid);
    if (act === "copy") { if (p) copyText(p.path || p.name, "act.pathCopied"); return; }
    if (act === "inspect" || ev.detail === 2) SP.inspectProcess(pid);
  });
  $("tree-expand").addEventListener("click", () => { treeAllOpen = true; expanded.clear(); SP.renderAll(); });
  $("tree-collapse").addEventListener("click", () => { treeAllOpen = false; expanded.clear(); SP.renderAll(); });
  ["tree-q", "tree-sort"].forEach((id) => { $(id).addEventListener("input", SP.renderAll); $(id).addEventListener("change", SP.renderAll); });

  // =========================================================================
  // High-resource trackers (client-side 60 s rings)
  // =========================================================================
  function hotBars(el, items, fmt) {
    const max = Math.max(1e-9, ...items.map((i) => i.v));
    el.innerHTML = items.map((i) => `<div class="bar clickable" data-hpid="${i.pid}"><div class="lbl" title="${esc(i.name)} (PID ${i.pid})">${esc(i.name)} <span class="muted small mono">#${i.pid}</span>
      <div class="meter ${i.hot ? "hot" : ""}"><i data-w="${((100 * i.v) / max).toFixed(1)}"></i></div></div><div class="n">${esc(fmt(i.v))}</div></div>`).join("") || `<div class="muted">—</div>`;
    applyWidths(el);
  }
  function renderTrackers() {
    const tr = [...S.procTrack.values()].filter((r) => r.pid !== 0);
    const avg = tr.map((r) => ({ pid: r.pid, name: r.name, v: r.cpu.reduce((a, b) => a + b, 0) / Math.max(1, r.cpu.length) }))
      .filter((x) => x.v >= 0.05).sort((a, b) => b.v - a.v).slice(0, 10).map((x) => ({ ...x, hot: x.v >= 25 }));
    hotBars($("hot-cpu"), avg, (v) => fmtPct(v));
    const mem = tr.map((r) => ({ pid: r.pid, name: r.name, v: r.ws || 0 })).sort((a, b) => b.v - a.v).slice(0, 10)
      .map((x) => ({ ...x, hot: S.metrics && x.v > S.metrics.memTotal * 0.1 }));
    hotBars($("hot-mem"), mem, fmtBytes);
    const grow = tr.filter((r) => r.priv.length >= 10).map((r) => {
      const [t0, v0] = r.priv[0], [t1, v1] = r.priv[r.priv.length - 1];
      return { pid: r.pid, name: r.name, v: t1 > t0 ? ((v1 - v0) / (t1 - t0)) * 60000 : 0 };
    }).filter((x) => x.v > 1 << 20).sort((a, b) => b.v - a.v).slice(0, 10).map((x) => ({ ...x, hot: x.v > 64 << 20 }));
    hotBars($("hot-grow"), grow, (v) => "+" + fmtBytes(v) + "/min");
    setBadge("b-hot", avg.filter((x) => x.hot).length);
  }
  ["hot-cpu", "hot-mem", "hot-grow"].forEach((id) => $(id).addEventListener("click", (ev) => { const b = ev.target.closest("[data-hpid]"); if (b) SP.inspectProcess(+b.dataset.hpid); }));

  // =========================================================================
  // Threshold rules engine editor
  // =========================================================================
  const OPS = [">", ">=", "<", "<="];
  const catOf = (k) => S.catalog.find((m) => m.key === k);
  const ruleName = (r) => (!r ? "—" : SP.I18N_LANG() === "ar" && r.nameAr ? r.nameAr : r.name);
  function fmtMetric(key, v) {
    const m = catOf(key); if (v == null || !m) return "—";
    const n = Math.abs(v) >= 100 || Number.isInteger(v) ? Math.round(v * 10) / 10 : Math.round(v * 100) / 100;
    switch (m.unit) {
      case "%": return n + "%";
      case "MB": return fmtBytes(v * 1048576);
      case "MB/s": return fmtRate(v * 1e6);
      case "count": case "state": case "score": return fmtNum(n);
      default: return n + " " + m.unit;
    }
  }
  const unitLabel = (m) => (m ? tOr("unit." + m.unit, m.unit) : "");
  function condText(r) {
    const m = catOf(r.metric);
    const base = `${m ? tx(m.label) : r.metric} ${r.op} ${fmtMetric(r.metric, r.threshold)}`;
    return r.for ? base + " " + t("rules.forN", { n: r.for }) : base;
  }
  function renderRules() {
    const q = $("rules-q").value.trim().toLowerCase();
    const stBy = new Map(S.ruleStates.map((s) => [s.id, s]));
    const rows = S.rules.filter((r) => !q || `${r.name} ${r.nameAr || ""} ${r.metric} ${r.scope || ""} ${condText(r)}`.toLowerCase().includes(q));
    $("rules-count").textContent = t("rules.count", { n: S.rules.filter((r) => r.enabled).length, total: S.rules.length });
    $("rules-table").tBodies[0].innerHTML = rows.map((r) => {
      const st = stBy.get(r.id) || {};
      let live;
      if (!r.enabled) live = `<span class="muted">${esc(t("rules.disabled"))}</span>`;
      else if (st.firing) live = `<span class="rstate firing">${esc(t("rules.firingN", { n: st.firing }))}</span>`;
      else if (st.pending) {
        const since = Math.min(...(st.instances || []).filter((i) => !i.firing && i.since).map((i) => i.since));
        const held = isFinite(since) ? Math.floor((Date.now() - since) / 1000) : 0;
        live = `<span class="rstate pending">${esc(t("rules.pendingN", { n: st.pending, s: held, f: r.for }))}</span>`;
      } else live = `<span class="rstate ok">${esc(t("rules.ok"))}</span>`;
      const last = st.last != null ? ` <span class="muted mono small">${esc(fmtMetric(r.metric, st.last))}</span>` : "";
      return `<tr data-rule="${esc(r.id)}" class="${st.firing ? "sev-row " + esc(r.severity) : ""} ${r.enabled ? "" : "dimrow"}">
        <td><label class="switch"><input type="checkbox" data-rtoggle="${esc(r.id)}" ${r.enabled ? "checked" : ""} aria-label="${esc(t("rules.col.on"))}"><i></i></label></td>
        <td><b>${esc(ruleName(r))}</b>${r.builtin ? ` <span class="pill">${esc(t("rules.builtin"))}</span>` : ""}</td>
        <td class="cond">${esc(condText(r))}</td><td class="mono">${r.scope ? ltr(r.scope) : `<span class="muted">${esc(t(catOf(r.metric)?.scoped ? "rules.allInst" : "rules.host"))}</span>`}</td>
        <td><span class="sev ${esc(r.severity)}">${esc(t("sev." + r.severity))}</span></td><td>${live}${last}</td><td class="num">${st.fired || 0}</td>
        <td class="acts"><button class="btn small ghost" data-redit="${esc(r.id)}">${esc(t("rules.edit"))}</button><button class="btn small ghost" data-rdel="${esc(r.id)}">${esc(t("rules.delete"))}</button></td></tr>`;
    }).join("") || `<tr><td colspan="8" class="muted">${esc(t("rules.none"))}</td></tr>`;
    $("rules-foot").textContent = S.rulesFile ? t("rules.persisted", { f: S.rulesFile }) : t("rules.memory");
  }
  function ruleForm(r) {
    const groups = [...new Set(S.catalog.map((m) => m.group))];
    const opts = groups.map((g) => `<optgroup label="${esc(t("mgrp." + g))}">${S.catalog.filter((m) => m.group === g).map((m) => `<option value="${esc(m.key)}" ${m.key === r.metric ? "selected" : ""}>${esc(tx(m.label))}</option>`).join("")}</optgroup>`).join("");
    return `<form class="rule-form" id="rule-form" autocomplete="off">
      <label class="fld wide"><span>${esc(t("rules.f.name"))}</span><input id="rf-name" maxlength="120" value="${esc(r.name || "")}" required></label>
      <label class="fld wide"><span>${esc(t("rules.f.nameAr"))}</span><input id="rf-nameAr" maxlength="240" dir="rtl" value="${esc(r.nameAr || "")}"></label>
      <label class="fld wide"><span>${esc(t("rules.f.metric"))}</span><select id="rf-metric">${opts}</select></label>
      <label class="fld"><span>${esc(t("rules.f.op"))}</span><select id="rf-op">${OPS.map((o) => `<option ${o === r.op ? "selected" : ""}>${esc(o)}</option>`).join("")}</select></label>
      <label class="fld"><span>${esc(t("rules.f.threshold"))} <em id="rf-unit"></em></span><input id="rf-thr" type="number" step="any" required value="${esc(r.threshold)}"></label>
      <label class="fld"><span>${esc(t("rules.f.for"))}</span><input id="rf-for" type="number" min="0" max="3600" step="1" value="${esc(r.for ?? 0)}"></label>
      <label class="fld"><span>${esc(t("rules.f.hyst"))} <em>${esc(t("rules.f.hystHint"))}</em></span><input id="rf-hyst" type="number" min="0" step="any" value="${esc(r.hysteresis || "")}"></label>
      <label class="fld wide" id="rf-scope-wrap"><span>${esc(t("rules.f.scope"))} <em id="rf-scope-hint"></em></span><input id="rf-scope" maxlength="160" dir="ltr" value="${esc(r.scope || "")}"></label>
      <label class="fld"><span>${esc(t("col.severity"))}</span><select id="rf-sev">${["critical", "warning", "info"].map((s) => `<option value="${s}" ${s === r.severity ? "selected" : ""}>${esc(t("sev." + s))}</option>`).join("")}</select></label>
      <label class="fld chkfld"><input type="checkbox" id="rf-en" ${r.enabled !== false ? "checked" : ""}><span>${esc(t("rules.f.enabled"))}</span></label>
      <div class="rf-preview wide" id="rf-preview"></div>
      <div class="rf-err wide" id="rf-err" hidden></div>
    </form>`;
  }
  function wireForm() {
    const upd = () => {
      const m = catOf($("rf-metric").value);
      $("rf-unit").textContent = m ? `(${unitLabel(m)}, ${m.min}–${m.max})` : "";
      $("rf-scope-wrap").hidden = !m?.scoped;
      $("rf-scope-hint").textContent = m?.scopeHint ? tx(m.scopeHint) : "";
      const r = readForm();
      const st = r.metric ? liveValueFor(r) : null;
      $("rf-preview").innerHTML = `<b>${esc(t("rules.preview"))}:</b> ${esc(condText(r))}${r.scope ? " · " + esc(t("rules.f.scope")) + " " + ltr(r.scope) : ""}` +
        (st != null ? ` <span class="muted">— ${esc(t("rules.nowValue", { v: fmtMetric(r.metric, st) }))}</span>` : "");
    };
    ["rf-metric", "rf-op", "rf-thr", "rf-for", "rf-scope", "rf-hyst"].forEach((id) => { $(id).addEventListener("input", upd); $(id).addEventListener("change", upd); });
    upd();
    setTimeout(() => $("rf-name").focus(), 0);
  }
  // Best-effort current value for the preview, from telemetry already in the browser.
  function liveValueFor(r) {
    const m = S.metrics; if (!m) return null;
    switch (r.metric) {
      case "cpu": return m.cpu; case "mem": return m.memPercent; case "cpu_kernel": return m.kernelPct;
      case "cpu_core_max": return m.perCore?.length ? Math.max(...m.perCore) : null;
      case "commit": return m.commitTotal ? (m.commitUsed / m.commitTotal) * 100 : null;
      case "sockets_new": return S.netstats?.newPerSec ?? null; case "sockets_total": return S.netstats?.total ?? null;
      case "established": return S.netstats?.byState?.ESTABLISHED ?? 0; case "health": return S.health?.score ?? null;
      default: return null;
    }
  }
  function readForm() {
    const num = (id) => { const v = $(id).value.trim(); return v === "" ? 0 : Number(v); };
    return { name: $("rf-name").value.trim(), nameAr: $("rf-nameAr").value.trim(), metric: $("rf-metric").value, op: $("rf-op").value,
      threshold: num("rf-thr"), for: Math.round(num("rf-for")), hysteresis: num("rf-hyst"),
      scope: catOf($("rf-metric").value)?.scoped ? $("rf-scope").value.trim() : "", severity: $("rf-sev").value, enabled: $("rf-en").checked };
  }
  async function editRule(r) {
    const isNew = !r.id;
    const base = isNew ? { name: "", metric: "cpu", op: ">", threshold: 85, for: 30, severity: "warning", enabled: true } : r;
    const p = modal(t(isNew ? "rules.newTitle" : "rules.editTitle"), ruleForm(base),
      [{ label: t("btn.cancel"), value: false, ghost: true }, { label: t(isNew ? "rules.create" : "rules.save"), value: "save" }]);
    wireForm();
    // Keep the dialog open on validation errors: re-open with the server's message.
    const v = await p;
    if (v !== "save") return;
    const body = readForm();
    try {
      await api(isNew ? "/api/rules" : `/api/rules/${encodeURIComponent(r.id)}`, { method: isNew ? "POST" : "PUT", body: JSON.stringify(body) });
      toast(t(isNew ? "rules.created" : "rules.saved", { n: body.name || tx(catOf(body.metric)?.label) }));
    } catch (e) {
      toast(t("rules.invalid", { e: e.message }));
      editRule({ ...r, ...body, id: r.id });
    }
  }
  $("rules-new").addEventListener("click", () => editRule({}));
  $("rules-reset").addEventListener("click", async () => {
    if (!(await confirmBox(t("rules.reset"), t("rules.resetConfirm")))) return;
    try { await api("/api/rules/reset", { method: "POST", body: "{}" }); toast(t("rules.resetDone")); } catch (e) { toast(t("err.generic", { e: e.message })); }
  });
  $("rules-q").addEventListener("input", SP.renderAll);
  $("rules-table").addEventListener("click", async (ev) => {
    const ed = ev.target.closest("[data-redit]"), del = ev.target.closest("[data-rdel]");
    if (ed) { const r = S.rules.find((x) => x.id === ed.dataset.redit); if (r) editRule(r); return; }
    if (del) {
      const r = S.rules.find((x) => x.id === del.dataset.rdel); if (!r) return;
      if (!(await confirmBox(t("rules.delete"), t("rules.deleteConfirm", { n: ruleName(r) })))) return;
      try { await api(`/api/rules/${encodeURIComponent(r.id)}`, { method: "DELETE" }); toast(t("rules.deleted")); } catch (e) { toast(t("err.generic", { e: e.message })); }
    }
  });
  $("rules-table").addEventListener("change", async (ev) => {
    const tg = ev.target.closest("[data-rtoggle]"); if (!tg) return;
    const r = S.rules.find((x) => x.id === tg.dataset.rtoggle); if (!r) return;
    const body = { name: r.name, nameAr: r.nameAr || "", metric: r.metric, op: r.op, threshold: r.threshold, for: r.for, scope: r.scope || "",
      severity: r.severity, hysteresis: r.hysteresis || 0, enabled: tg.checked };
    try { await api(`/api/rules/${encodeURIComponent(r.id)}`, { method: "PUT", body: JSON.stringify(body) }); } catch (e) { tg.checked = !tg.checked; toast(t("err.generic", { e: e.message })); }
  });

  // =========================================================================
  // Command palette (Ctrl/⌘ + K) — views, actions and live entities
  // =========================================================================
  const isMac = /Mac|iPhone|iPad/.test(navigator.platform || navigator.userAgent || "");
  $("cmdk-kbd").textContent = isMac ? "⌘ K" : "Ctrl K";
  let palItems = [], palSel = 0;
  const norm = (s) => String(s || "").toLowerCase();
  // Subsequence fuzzy score: consecutive and word-start matches rank higher.
  function fuzzy(q, s) {
    if (!q) return 1;
    s = norm(s);
    const direct = s.indexOf(q);
    if (direct >= 0) return 1000 - direct - s.length * 0.01 + (direct === 0 || /[\s\-_.(]/.test(s[direct - 1]) ? 200 : 0);
    let si = 0, score = 0, run = 0;
    for (const ch of q) {
      const i = s.indexOf(ch, si);
      if (i < 0) return 0;
      run = i === si ? run + 1 : 0; score += 1 + run * 2; si = i + 1;
    }
    return score;
  }
  function palSources() {
    const out = [];
    document.querySelectorAll(".nav-item[data-view]").forEach((b) => {
      const v = b.dataset.view;
      out.push({ kind: "view", icon: b.querySelector("use")?.getAttribute("href") || "#i-overview", label: t("nav." + v), sub: t("grp." + GROUP_OF[v]), keys: `${t("nav." + v)} ${t("grp." + GROUP_OF[v])} ${v} ${D_EN("nav." + v)}`, run: () => SP.showTab(v) });
    });
    const act = (label, keys, run, icon) => out.push({ kind: "action", icon: icon || "#i-chev", label, sub: t("cmd.action"), keys: label + " " + keys, run });
    act(t("cmd.toggleLang"), "language arabic english rtl عربي", () => SP.setLang(SP.I18N_LANG() === "ar" ? "en" : "ar"));
    act(t("cmd.toggleSidebar"), "sidebar collapse expand", () => setCollapsed(!shell.classList.contains("collapsed")), "#i-collapse");
    act(t("rules.new"), "rule alert threshold new", () => { SP.showTab("rules"); editRule({}); }, "#i-plus");
    act(t("sw.check"), "winget updates upgrade", () => { SP.showTab("updates"); $("sw-refresh").click(); }, "#i-update");
    act(t("alerts.ackAll"), "acknowledge alerts", () => { SP.showTab("alerts"); $("a-ack-all").click(); }, "#i-alert");
    act(t("diag.authBtn"), "audit security logon 4625", () => { SP.showTab("diagnostics"); document.querySelector('[data-audit="auth"]')?.click(); }, "#i-shield");
    act(t("diag.relBtn"), "audit reliability crash", () => { SP.showTab("diagnostics"); document.querySelector('[data-audit="reliability"]')?.click(); }, "#i-shield");
    act(t("dev.resolve"), "netbios mdns names", () => { SP.showTab("devices"); $("dev-resolve").click(); }, "#i-devices");
    S.procs.forEach((p) => out.push({ kind: "proc", icon: "#i-flame", label: p.name, sub: `PID ${p.pid} · ${fmtPct(p.cpu)} · ${fmtBytes(p.workingSet)}`, keys: `${p.name} ${p.pid} ${p.path || ""}`, run: () => SP.inspectProcess(p.pid), weight: 0.6 }));
    S.svcs.forEach((s) => out.push({ kind: "svc", icon: "#i-services", label: s.display, sub: `${s.name} · ${t("sstate." + s.state)}`, keys: `${s.display} ${s.name}`, run: () => { $("svc-q").value = s.name; SP.showTab("services"); }, weight: 0.55 }));
    S.ifs.forEach((x) => out.push({ kind: "if", icon: "#i-bandwidth", label: x.name, sub: `↓${fmtRate(x.inBps)} ↑${fmtRate(x.outBps)}`, keys: `${x.name} ${x.desc || ""} ${x.mac || ""}`, run: () => { $("bw-q").value = x.name; SP.showTab("bandwidth"); }, weight: 0.7 }));
    (S.devices || []).forEach((d) => out.push({ kind: "dev", icon: "#i-devices", label: d.hostname || d.ip, sub: `${d.ip} · ${d.vendor || d.mac}`, keys: `${d.hostname || ""} ${d.ip} ${d.mac} ${d.vendor || ""}`, run: () => { $("dev-q").value = d.ip; SP.showTab("devices"); }, weight: 0.6 }));
    const rem = new Map();
    S.conns.forEach((c) => { if (c.remoteAddr && !rem.has(c.remoteAddr)) rem.set(c.remoteAddr, c); });
    rem.forEach((c, ip) => out.push({ kind: "ip", icon: "#i-sockets", label: ip, sub: `${c.processName} · ${c.state}`, keys: `${ip} ${c.processName}`, run: () => { $("net-q").value = ip; SP.showTab("sockets"); }, weight: 0.5 }));
    return out;
  }
  const D_EN = (k) => (window.I18N.dict.en[k] || "");
  const KIND_LABEL = () => ({ view: t("cmd.k.view"), action: t("cmd.k.action"), proc: t("cmd.k.proc"), svc: t("cmd.k.svc"), if: t("cmd.k.if"), dev: t("cmd.k.dev"), ip: t("cmd.k.ip") });
  function palRender() {
    const q = norm($("pal-q").value.trim());
    const src = palSources();
    palItems = (q ? src.map((it) => ({ it, s: fuzzy(q, it.keys) * (it.weight || 1) })).filter((x) => x.s > 0).sort((a, b) => b.s - a.s).map((x) => x.it)
      : src.filter((x) => x.kind === "view" || x.kind === "action")).slice(0, 60);
    palSel = clamp(palSel, 0, Math.max(0, palItems.length - 1));
    const kl = KIND_LABEL();
    let lastKind = "";
    $("pal-list").innerHTML = palItems.map((it, i) => {
      const head = it.kind !== lastKind ? `<li class="pal-h" role="presentation">${esc(kl[it.kind])}</li>` : "";
      lastKind = it.kind;
      return `${head}<li class="pal-i ${i === palSel ? "sel" : ""}" role="option" aria-selected="${i === palSel}" data-pi="${i}"><svg class="ico sm"><use href="${esc(it.icon)}"/></svg><span class="pl" dir="auto">${esc(it.label)}</span><span class="ps muted small" dir="auto">${esc(it.sub || "")}</span></li>`;
    }).join("") || `<li class="pal-empty muted">${esc(t("cmd.none"))}</li>`;
    $("pal-list").querySelector(".pal-i.sel")?.scrollIntoView({ block: "nearest" });
  }
  function palOpen() { $("palette").hidden = false; $("pal-q").value = ""; palSel = 0; palRender(); $("pal-q").focus(); }
  function palClose() { $("palette").hidden = true; }
  function palRun(i) { const it = palItems[i]; if (!it) return; palClose(); it.run(); }
  $("cmdk-open").addEventListener("click", palOpen);
  $("pal-q").addEventListener("input", () => { palSel = 0; palRender(); });
  $("pal-q").addEventListener("keydown", (e) => {
    if (e.key === "ArrowDown") { palSel = Math.min(palItems.length - 1, palSel + 1); palRender(); e.preventDefault(); }
    else if (e.key === "ArrowUp") { palSel = Math.max(0, palSel - 1); palRender(); e.preventDefault(); }
    else if (e.key === "Enter") { palRun(palSel); e.preventDefault(); }
    else if (e.key === "Escape") { palClose(); e.preventDefault(); }
  });
  $("pal-list").addEventListener("mousemove", (e) => { const li = e.target.closest("[data-pi]"); if (li && +li.dataset.pi !== palSel) { palSel = +li.dataset.pi; palRender(); } });
  $("pal-list").addEventListener("click", (e) => { const li = e.target.closest("[data-pi]"); if (li) palRun(+li.dataset.pi); });
  $("palette").addEventListener("click", (e) => { if (e.target.id === "palette") palClose(); });

  // Global shortcuts: Ctrl/⌘+K palette · [ sidebar · / page filter · g then key → view.
  const typing = (el) => el && (el.isContentEditable || /^(INPUT|TEXTAREA|SELECT)$/.test(el.tagName));
  const GO = { o: "overview", h: "health", a: "alerts", r: "rules", c: "cpu", s: "storage", v: "services", n: "sockets", b: "bandwidth", d: "devices", x: "radar", t: "ptree", p: "procs", e: "events", g: "diagnostics", i: "software", u: "updates", m: "guide" };
  let gPending = 0;
  document.addEventListener("keydown", (e) => {
    if ((e.ctrlKey || e.metaKey) && !e.altKey && (e.key === "k" || e.key === "K")) { e.preventDefault(); $("palette").hidden ? palOpen() : palClose(); return; }
    if (!$("palette").hidden || !$("modal").hidden || typing(document.activeElement) || e.ctrlKey || e.metaKey || e.altKey) return;
    if (gPending && Date.now() - gPending < 1200 && GO[e.key]) { gPending = 0; SP.showTab(GO[e.key]); e.preventDefault(); return; }
    gPending = 0;
    if (e.key === "g") { gPending = Date.now(); return; }
    if (e.key === "[") { setCollapsed(!shell.classList.contains("collapsed")); e.preventDefault(); return; }
    if (e.key === "/") {
      const inp = document.querySelector(`#view-${SP.active} input[type=search]`);
      if (inp) { inp.focus(); inp.select(); e.preventDefault(); }
    }
  });

  // =========================================================================
  // Render loop registration
  // =========================================================================
  const RENDER = { health: renderHealth, cpu: renderCPU, storage: renderStorage, services: renderServices, bandwidth: renderBandwidth, ptree: renderTree, procs: renderTrackers, rules: renderRules };
  SP.onRender((view) => {
    renderHeader();
    if (view === "overview") renderOverviewExtra();
    if (view !== "procs") renderTrackersBadgeOnly();
    const fn = RENDER[view];
    if (fn) fn();
  });
  let trackTick = 0;
  function renderTrackersBadgeOnly() {
    if (++trackTick % 5) return;
    const hot = [...S.procTrack.values()].filter((r) => r.pid && r.cpu.length && r.cpu.reduce((a, b) => a + b, 0) / r.cpu.length >= 25).length;
    setBadge("b-hot", hot);
  }
  SP.onLang(() => {
    labelNav(); crumbs(SP.active);
    const sel = $("svc-start"), v = sel.value;
    while (sel.options.length > 1) sel.remove(1);
    START_TYPES.forEach((k) => sel.add(new Option(t("start." + k), k)));
    sel.value = v;
    if (!$("palette").hidden) palRender();
  });
  window.addEventListener("resize", () => SP.renderAll());
  labelNav();
})();
