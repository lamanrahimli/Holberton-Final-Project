/* Kharibulbul SIEM dashboard - vanilla JS single page app (no build step, no external libraries). */
(function () {
  "use strict";

  // ------------------------------------------------------------------ helpers
  const $ = (sel, root) => (root || document).querySelector(sel);
  const el = (tag, attrs, children) => {
    const node = document.createElement(tag);
    if (attrs) for (const [k, v] of Object.entries(attrs)) {
      if (v === null || v === undefined) continue;
      if (k === "class") node.className = v;
      else if (k === "html") node.innerHTML = v;
      else if (k.startsWith("on")) node.addEventListener(k.slice(2), v);
      else node.setAttribute(k, v);
    }
    for (const c of [].concat(children || [])) {
      if (c === null || c === undefined) continue;
      node.appendChild(typeof c === "string" ? document.createTextNode(c) : c);
    }
    return node;
  };
  const esc = (s) => String(s === undefined || s === null ? "" : s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const fmtTime = (iso) => { if (!iso) return "-"; const d = new Date(iso); return isNaN(d) ? iso : d.toLocaleString(); };
  const fmtNum = (n) => (n === undefined || n === null ? "-" : Number(n).toLocaleString());
  const ago = (sec) => sec < 60 ? `${Math.round(sec)}s` : sec < 3600 ? `${Math.round(sec / 60)}m` : sec < 86400 ? `${Math.round(sec / 3600)}h` : `${Math.round(sec / 86400)}d`;
  const SEV_COLORS = { critical: "#ff3b5c", high: "#ff7a45", medium: "#f5b400", low: "#38bdf8", informational: "#8a97b5" };
  const OPEN_STATUSES = "new,acknowledged,investigating,escalated";
  const store = { get: (k, d) => { try { return localStorage.getItem(k) || d; } catch (e) { return d; } }, set: (k, v) => { try { localStorage.setItem(k, v); } catch (e) { /* private mode */ } } };

  // the build this script was served as (index.html links app.js?v=<build>); compared with the server's in footer()
  const UI_BUILD = (() => { try { return new URL(document.currentScript.src).searchParams.get("v") || ""; } catch (e) { return ""; } })();

  let token = store.get("kb_token", "");
  // range: a relative value ("now-24h"), "all" (since the oldest stored event) or "custom" (from / to below)
  const state = { range: store.get("kb_range", "now-24h"), from: store.get("kb_from", ""), to: store.get("kb_to", ""), eventsQuery: "", eventsOffset: 0, timer: null };

  async function api(path, opts) {
    opts = opts || {};
    const headers = { "Content-Type": "application/json" };
    if (token) headers["Authorization"] = "Bearer " + token;
    const res = await fetch(path, { method: opts.method || "GET", headers, body: opts.body ? JSON.stringify(opts.body) : undefined });
    if (res.status === 401) {
      const t = prompt("This server requires an API token (api.token in config/server.yml):");
      if (t) { token = t; store.set("kb_token", t); return api(path, opts); }
      throw new Error("unauthorized");
    }
    if (!res.ok) {
      let msg = res.statusText;
      try { msg = (await res.json()).detail || msg; } catch (e) { /* ignore */ }
      throw new Error(msg);
    }
    const ct = res.headers.get("content-type") || "";
    return ct.includes("json") ? res.json() : res.text();
  }
  const qs = (obj) => Object.entries(obj).filter(([, v]) => v !== undefined && v !== null && v !== "").map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`).join("&");

  function toast(msg) {
    const t = el("div", { class: "toast" }, msg);
    document.body.appendChild(t);
    setTimeout(() => t.remove(), 3500);
  }
  function download(filename, text, type) {
    const blob = new Blob([text], { type: type || "text/plain" });
    const a = el("a", { href: URL.createObjectURL(blob), download: filename });
    document.body.appendChild(a); a.click(); a.remove();
  }
  async function copyText(text) {
    try { await navigator.clipboard.writeText(text); }
    catch (e) { const ta = el("textarea", { style: "position:fixed;opacity:0" }, text); document.body.appendChild(ta); ta.select(); document.execCommand("copy"); ta.remove(); }
    toast("copied");
  }

  // ------------------------------------------------------------------ time range (shared by Overview, Events, Alerts)
  const RANGES = [["15m", "now-15m"], ["1h", "now-1h"], ["6h", "now-6h"], ["24h", "now-24h"], ["7d", "now-7d"], ["30d", "now-30d"], ["90d", "now-90d"], ["1y", "now-365d"], ["all", "all"]];
  const toLocalInput = (iso) => { if (!iso) return ""; const d = new Date(iso); if (isNaN(d)) return ""; const p = (n) => String(n).padStart(2, "0"); return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}T${p(d.getHours())}:${p(d.getMinutes())}`; };
  function timeParams() {
    if (state.range === "custom" && state.from) return { from: state.from, to: state.to || undefined };
    return { from: state.range === "custom" ? "now-24h" : state.range };
  }
  function rangeLabel() {
    if (state.range === "custom" && state.from) return `${fmtTime(state.from)} → ${state.to ? fmtTime(state.to) : "now"}`;
    if (state.range === "all") return "all stored events";
    return "last " + (RANGES.find((r) => r[1] === state.range) || [state.range.replace("now-", "")])[0];
  }
  function rangePicker(onChange) {
    // quick ranges + an exact from / to date search; redraws itself, then calls onChange to reload the page's data
    const box = el("div", { class: "timerange" });
    const setRange = (val) => { state.range = val; store.set("kb_range", val); build(); onChange(); };
    function build() {
      box.innerHTML = "";
      for (const [label, val] of RANGES) {
        box.appendChild(el("button", { class: "small" + (state.range === val ? " active" : ""), title: val === "all" ? "everything that is stored - no date limit" : "last " + label, onclick: () => setRange(val) }, label));
      }
      const from = el("input", { type: "datetime-local", title: "from (local time)", value: state.range === "custom" ? toLocalInput(state.from) : "" });
      const to = el("input", { type: "datetime-local", title: "to (local time) - empty = now", value: state.range === "custom" ? toLocalInput(state.to) : "" });
      const apply = () => {
        if (!from.value) { toast("choose a start date"); return; }
        const f = new Date(from.value), t = to.value ? new Date(to.value) : null;
        if (isNaN(f) || (t && isNaN(t))) { toast("invalid date"); return; }
        if (t && t <= f) { toast("'to' must be later than 'from'"); return; }
        state.from = f.toISOString(); state.to = t ? t.toISOString() : "";
        store.set("kb_from", state.from); store.set("kb_to", state.to);
        setRange("custom");
      };
      for (const inp of [from, to]) inp.addEventListener("keydown", (e) => { if (e.key === "Enter") apply(); });
      box.appendChild(el("span", { class: "daterange" + (state.range === "custom" ? " active" : "") }, [el("span", { class: "muted" }, "from"), from, el("span", { class: "muted" }, "to"), to, el("button", { class: "small" + (state.range === "custom" ? " active" : ""), onclick: apply }, "apply dates")]));
    }
    build();
    return box;
  }

  // ------------------------------------------------------------------ charts (own SVG renderers)
  function axisLabel(buckets, i) {
    const d = new Date(buckets[i].ts);
    const span = buckets.length > 1 ? new Date(buckets[buckets.length - 1].ts) - new Date(buckets[0].ts) : 0;
    if (span > 36 * 3600 * 1000) return d.toLocaleDateString([], span > 300 * 86400000 ? { year: "2-digit", month: "short", day: "numeric" } : { month: "short", day: "numeric" });
    return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  }
  function areaChart(buckets, color, height) {
    height = height || 160;
    const w = 600, h = height, padL = 34, padB = 20, padT = 8;
    const max = Math.max(1, ...buckets.map((b) => b.count));
    const n = Math.max(1, buckets.length - 1);
    const x = (i) => padL + (i / n) * (w - padL - 4);
    const y = (v) => padT + (1 - v / max) * (h - padT - padB);
    const pts = buckets.map((b, i) => `${x(i).toFixed(1)},${y(b.count).toFixed(1)}`);
    const area = `M${x(0)},${y(0)} L` + pts.join(" L") + ` L${x(buckets.length - 1)},${y(0)} Z`;
    const ticks = [0, 0.5, 1].map((f) => `<text x="${padL - 6}" y="${y(max * f) + 4}" text-anchor="end" fill="#8a97b5" font-size="10">${Math.round(max * f)}</text><line x1="${padL}" x2="${w}" y1="${y(max * f)}" y2="${y(max * f)}" stroke="#26355a" stroke-dasharray="3 3"/>`).join("");
    const labels = [0, Math.floor(buckets.length / 2), buckets.length - 1].filter((i, k, a) => a.indexOf(i) === k && buckets[i]).map((i) => `<text x="${x(i)}" y="${h - 4}" text-anchor="${i === 0 ? "start" : i === buckets.length - 1 ? "end" : "middle"}" fill="#8a97b5" font-size="10">${esc(axisLabel(buckets, i))}</text>`).join("");
    return `<svg viewBox="0 0 ${w} ${h}" preserveAspectRatio="none">${ticks}<path d="${area}" fill="${color}" opacity="0.18"/><polyline points="${pts.join(" ")}" fill="none" stroke="${color}" stroke-width="2"/>${labels}</svg>`;
  }
  function barChart(buckets, color, height) {
    height = height || 160;
    const w = 600, h = height, padL = 34, padB = 20, padT = 8;
    const max = Math.max(1, ...buckets.map((b) => b.count));
    const bw = (w - padL - 4) / Math.max(1, buckets.length);
    const y = (v) => padT + (1 - v / max) * (h - padT - padB);
    const bars = buckets.map((b, i) => `<rect x="${(padL + i * bw + 1).toFixed(1)}" y="${y(b.count).toFixed(1)}" width="${Math.max(1, bw - 2).toFixed(1)}" height="${(y(0) - y(b.count)).toFixed(1)}" fill="${color}" rx="1"><title>${esc(fmtTime(b.ts))}: ${b.count}</title></rect>`).join("");
    const ticks = [0, 0.5, 1].map((f) => `<text x="${padL - 6}" y="${y(max * f) + 4}" text-anchor="end" fill="#8a97b5" font-size="10">${Math.round(max * f)}</text>`).join("");
    const labels = buckets.length ? [0, buckets.length - 1].filter((i, k, a) => a.indexOf(i) === k).map((i) => `<text x="${i === 0 ? padL : w - 4}" y="${h - 4}" text-anchor="${i === 0 ? "start" : "end"}" fill="#8a97b5" font-size="10">${esc(axisLabel(buckets, i))}</text>`).join("") : "";
    return `<svg viewBox="0 0 ${w} ${h}" preserveAspectRatio="none">${ticks}<line x1="${padL}" x2="${w}" y1="${y(0)}" y2="${y(0)}" stroke="#26355a"/>${bars}${labels}</svg>`;
  }
  function donut(entries) {
    const total = entries.reduce((a, e) => a + e.count, 0);
    if (!total) return `<div class="empty">no data</div>`;
    let acc = 0; const r = 42, c = 60, circ = 2 * Math.PI * r;
    const segs = entries.map((e) => { const frac = e.count / total; const dash = `${(frac * circ).toFixed(2)} ${(circ - frac * circ).toFixed(2)}`; const off = (-acc * circ).toFixed(2); acc += frac; return `<circle cx="${c}" cy="${c}" r="${r}" fill="none" stroke="${e.color}" stroke-width="14" stroke-dasharray="${dash}" stroke-dashoffset="${off}" transform="rotate(-90 ${c} ${c})"><title>${esc(e.key)}: ${e.count}</title></circle>`; }).join("");
    const legend = entries.map((e) => `<span><i style="background:${e.color}"></i>${esc(e.key)} ${e.count}</span>`).join("");
    return `<div style="display:flex;gap:14px;align-items:center"><svg viewBox="0 0 120 120" style="width:120px;height:120px">${segs}<text x="60" y="65" text-anchor="middle" fill="#e6ecf7" font-size="18" font-weight="700">${total}</text></svg><div class="legend" style="flex-direction:column;gap:4px">${legend}</div></div>`;
  }
  function multiLine(series, height) {
    // series: [{buckets, color, label}] sharing the same time axis
    height = height || 160;
    const w = 600, h = height, padL = 34, padB = 20, padT = 8;
    const all = series.flatMap((s) => s.buckets.map((b) => b.count));
    const max = Math.max(1, ...all);
    const n = Math.max(1, (series[0] ? series[0].buckets.length : 1) - 1);
    const x = (i) => padL + (i / n) * (w - padL - 4);
    const y = (v) => padT + (1 - v / max) * (h - padT - padB);
    const ticks = [0, 0.5, 1].map((f) => `<text x="${padL - 6}" y="${y(max * f) + 4}" text-anchor="end" fill="#8a97b5" font-size="10">${Math.round(max * f)}</text><line x1="${padL}" x2="${w}" y1="${y(max * f)}" y2="${y(max * f)}" stroke="#26355a" stroke-dasharray="3 3"/>`).join("");
    const lines = series.map((s) => {
      const pts = s.buckets.map((b, i) => `${x(i).toFixed(1)},${y(b.count).toFixed(1)}`).join(" ");
      return `<polyline points="${pts}" fill="none" stroke="${s.color}" stroke-width="2"><title>${esc(s.label)}</title></polyline>`;
    }).join("");
    const legend = series.map((s) => `<span><i style="background:${s.color}"></i>${esc(s.label)} ${s.buckets.reduce((a, b) => a + b.count, 0)}</span>`).join("");
    return `<svg viewBox="0 0 ${w} ${h}" preserveAspectRatio="none">${ticks}${lines}</svg><div class="legend">${legend}</div>`;
  }
  function hbars(terms, onClick) {
    const box = el("div", { class: "hbars" });
    if (!terms || !terms.length) { box.appendChild(el("div", { class: "empty" }, "no data")); return box; }
    const max = Math.max(1, ...terms.map((t) => t.count));
    for (const t of terms) {
      const bar = el("div", { class: "bar", title: String(t.key), onclick: () => onClick && onClick(t.key) }, [
        el("span", { class: "label" }, String(t.key === null ? "(none)" : t.key)),
        el("span", { class: "muted right" }, fmtNum(t.count)),
        el("div", { class: "track" }, el("div", { class: "fill", style: `width:${(100 * t.count / max).toFixed(1)}%` })),
      ]);
      box.appendChild(bar);
    }
    return box;
  }

  // ------------------------------------------------------------------ layout bits
  function sevPill(sev) { return el("span", { class: "pill sev-" + (sev || "informational") }, sev || "info"); }
  function badge(text, cls) { return el("span", { class: "badge " + (cls || "") }, text); }
  function closeDrawer() { $("#drawer-root").innerHTML = ""; }
  function drawer(title, body, wide) {
    const root = $("#drawer-root");
    root.innerHTML = "";
    const d = el("div", { class: "drawer" + (wide ? " wide" : "") }, [el("button", { class: "close small", onclick: closeDrawer }, "✕ close"), el("h2", {}, title), body]);
    root.appendChild(d);
  }
  document.addEventListener("keydown", (e) => {
    if (e.key !== "Escape" || !$("#drawer-root").firstChild) return;
    if (/^(TEXTAREA|INPUT|SELECT)$/.test((document.activeElement || {}).tagName || "")) { document.activeElement.blur(); return; }   // first Esc leaves the field, so an edit is not lost by accident
    closeDrawer();
  });
  function kvTable(doc) {
    const box = el("div", { class: "kv" });
    for (const k of Object.keys(doc).sort()) {
      if (k === "event.original") continue;
      const v = doc[k];
      box.appendChild(el("span", { class: "k" }, k));
      box.appendChild(el("span", { class: "v" }, typeof v === "object" ? JSON.stringify(v) : String(v)));
    }
    return box;
  }
  function geoText(doc, side) {
    const name = doc[`${side}.geo.country_name`] || doc[`${side}.geo.name`];
    if (!name) return "";
    const city = doc[`${side}.geo.city_name`], zone = doc[`${side}.geo.name`];
    return [zone && zone !== name ? zone : null, city, name].filter(Boolean).join(", ");
  }
  function eventDetail(doc) {
    const ecsBox = el("pre", {}, "loading…");
    const ecsDetails = el("details", {}, [el("summary", {}, "ECS document (nested JSON)"), ecsBox]);
    ecsDetails.addEventListener("toggle", async () => {
      if (!ecsDetails.open || ecsBox.dataset.loaded) return;
      try { ecsBox.textContent = JSON.stringify(await api(`/api/events/${doc["event.id"]}?format=ecs`), null, 2); ecsBox.dataset.loaded = "1"; } catch (e) { ecsBox.textContent = "Error: " + e.message; }
    });
    const problems = doc["kharibulbul.ecs.problems"];
    const body = el("div", {}, [
      el("p", {}, [el("strong", {}, doc.message || ""), " ", el("span", { class: "muted" }, fmtTime(doc["@timestamp"]))]),
      el("div", { class: "chips" }, [
        el("span", { class: "chip", onclick: () => searchFrom(`host.name:"${doc["host.name"]}"`) }, "host: " + (doc["host.name"] || "-")),
        el("span", { class: "chip", onclick: () => searchFrom(`event.action:"${doc["event.action"]}"`) }, "action: " + (doc["event.action"] || "-")),
        doc["user.name"] ? el("span", { class: "chip", onclick: () => searchFrom(`user.name:"${doc["user.name"]}"`) }, "user: " + doc["user.name"]) : null,
        doc["source.ip"] ? el("span", { class: "chip", onclick: () => searchFrom(`source.ip:${doc["source.ip"]}`) }, `source: ${doc["source.ip"]}` + (geoText(doc, "source") ? ` · ${geoText(doc, "source")}` : "")) : null,
        doc["destination.ip"] ? el("span", { class: "chip", onclick: () => searchFrom(`destination.ip:${doc["destination.ip"]}`) }, `destination: ${doc["destination.ip"]}` + (geoText(doc, "destination") ? ` · ${geoText(doc, "destination")}` : "")) : null,
        el("span", { class: "chip static", title: "Elastic Common Schema version this event is normalised to" }, "ECS " + (doc["ecs.version"] || "?") + (problems ? " · non-conformant" : " ✓")),
      ]),
      problems ? el("p", { class: "warn" }, "ECS problems: " + problems.join("; ")) : null,
      el("h3", {}, "Fields"), kvTable(doc),
      ecsDetails,
      el("details", {}, [el("summary", {}, "raw event"), el("pre", {}, doc["event.original"] || "")]),
    ]);
    drawer("Event " + (doc["event.code"] ? "(" + doc["event.dataset"] + " / " + doc["event.code"] + ")" : doc["event.dataset"] || ""), body);
  }
  function searchFrom(q) { state.eventsQuery = q; state.eventsOffset = 0; location.hash = "#/events"; if (currentRoute === "events") renderEvents(); }

  // ------------------------------------------------------------------ pages
  async function renderOverview() {
    const main = $("#main");
    main.innerHTML = "";
    const header = el("div", { class: "topbar" }, [el("h1", {}, "Overview"), el("span", { class: "muted" }, ""), el("div", { class: "grow" }), rangePicker(renderOverview), el("button", { class: "small", onclick: renderOverview }, "↻ refresh")]);
    main.appendChild(header);
    let d;
    try { d = await api(`/api/dashboard/overview?${qs(timeParams())}`); } catch (e) { main.appendChild(el("div", { class: "empty" }, "Error: " + e.message)); return; }
    const a = d.alerts || {};
    const crit = (a.by_severity || {}).critical || 0, high = (a.by_severity || {}).high || 0, escalated = (a.by_status || {}).escalated || 0;
    const stats = el("div", { class: "grid cols-5" }, [
      el("div", { class: "card stat accent-blue" }, [el("div", { class: "value" }, fmtNum(d.events_total)), el("div", { class: "label" }, `events · ${rangeLabel()}`)]),
      el("div", { class: "card stat accent-red" }, [el("div", { class: "value" }, fmtNum(a.open || 0)), el("div", { class: "label" }, `open alerts (${crit} critical, ${high} high${escalated ? `, ${escalated} escalated` : ""})`)]),
      el("div", { class: "card stat accent-amber" }, [el("div", { class: "value" }, fmtNum(d.auth_failures)), el("div", { class: "label" }, "authentication failures")]),
      el("div", { class: "card stat accent-green" }, [el("div", { class: "value" }, `${d.agents.online}/${d.agents.total}`), el("div", { class: "label" }, "agents online" + (d.agents.pending ? ` (${d.agents.pending} pending)` : ""))]),
      el("div", { class: "card stat" }, [el("div", { class: "value" }, fmtNum(d.store.events)), el("div", { class: "label" }, `events stored (${(d.store.size_bytes / 1048576).toFixed(1)} MB)` + (d.store.oldest ? ` since ${new Date(d.store.oldest).toLocaleDateString()}` : ""))]),
    ]);
    main.appendChild(stats);
    const charts = el("div", { class: "grid cols-2", style: "margin-top:14px" }, [
      el("div", { class: "card" }, [el("h3", {}, "Events over time"), el("div", { class: "chart", html: areaChart(d.events_histogram, "#38bdf8") })]),
      el("div", { class: "card" }, [el("h3", {}, "Alerts over time"), el("div", { class: "chart", html: barChart(d.alerts_histogram, "#ff7a45") })]),
    ]);
    main.appendChild(charts);
    const sevEntries = Object.entries(a.by_severity || {}).sort((x, y) => (SEV_COLORS[x[0]] ? 0 : 1) - (SEV_COLORS[y[0]] ? 0 : 1)).map(([k, v]) => ({ key: k, count: v, color: SEV_COLORS[k] || "#8a97b5" }));
    const row2 = el("div", { class: "grid cols-4", style: "margin-top:14px" }, [
      el("div", { class: "card" }, [el("h3", {}, "Alerts by severity"), el("div", { html: donut(sevEntries) })]),
      el("div", { class: "card" }, [el("h3", {}, "Top hosts"), hbars(d.top_hosts, (k) => searchFrom(`host.name:"${k}"`))]),
      el("div", { class: "card" }, [el("h3", {}, "Top event actions"), hbars(d.top_actions, (k) => searchFrom(`event.action:"${k}"`))]),
      el("div", { class: "card" }, [el("h3", {}, "Top source IPs"), hbars(d.top_source_ips, (k) => searchFrom(`source.ip:${k}`))]),
    ]);
    main.appendChild(row2);
    const row3 = el("div", { class: "grid cols-4", style: "margin-top:14px" }, [
      el("div", { class: "card" }, [el("h3", {}, "Datasets"), hbars(d.top_datasets, (k) => searchFrom(`event.dataset:${k}`))]),
      el("div", { class: "card" }, [el("h3", {}, "Top users"), hbars(d.top_users, (k) => searchFrom(`user.name:"${k}"`))]),
      el("div", { class: "card" }, [el("h3", {}, "Source countries (GeoIP)"), hbars(d.top_countries, (k) => searchFrom(`source.geo.country_name:"${k}"`))]),
      el("div", { class: "card" }, [el("h3", {}, "Destination countries (GeoIP)"), hbars(d.top_dest_countries, (k) => searchFrom(`destination.geo.country_name:"${k}"`))]),
    ]);
    main.appendChild(row3);
    const authSeries = [
      { buckets: (d.auth_histogram || {}).success || [], color: "#00AF66", label: "auth success" },
      { buckets: (d.auth_histogram || {}).failure || [], color: "#E4002B", label: "auth failure" },
    ];
    const row4 = el("div", { class: "grid cols-4", style: "margin-top:14px" }, [
      el("div", { class: "card" }, [el("h3", {}, "Authentication success vs failure"), el("div", { class: "chart", html: multiLine(authSeries) })]),
      el("div", { class: "card" }, [el("h3", {}, "Open alerts by ATT&CK tactic"), hbars(d.alert_tactics, () => { location.hash = "#/alerts"; })]),
      el("div", { class: "card" }, [el("h3", {}, "Events by asset criticality"), hbars(d.criticality, (k) => searchFrom(`kharibulbul.asset.criticality:${k}`))]),
      el("div", { class: "card" }, [el("h3", {}, "Top processes"), hbars(d.top_processes, (k) => searchFrom(`process.name:"${k}"`))]),
    ]);
    main.appendChild(row4);
    const tbl = el("table", {}, [el("thead", {}, el("tr", {}, ["time", "severity", "rule", "entity", "count", "status"].map((h) => el("th", {}, h)))), el("tbody", {}, (d.recent_alerts || []).map((al) => el("tr", { class: "row", onclick: () => openAlert(al.id) }, [
      el("td", { class: "mono" }, fmtTime(al.last_seen)), el("td", {}, sevPill(al.severity)), el("td", {}, [el("strong", {}, al["rule.name"]), el("div", { class: "muted" }, al["rule.id"])]),
      el("td", {}, al.entity), el("td", { class: "right" }, fmtNum(al.count)), el("td", {}, statusCell(al)),
    ])))]);
    main.appendChild(el("div", { class: "card", style: "margin-top:14px" }, [el("h3", {}, "Recent alerts"), (d.recent_alerts || []).length ? tbl : el("div", { class: "empty" }, "No alerts in this range. Run: kharibulbul simulate all")]));
    const rl = (a.by_rule || []);
    if (rl.length) main.appendChild(el("div", { class: "card", style: "margin-top:14px" }, [el("h3", {}, "Alerts by rule"), hbars(rl.map((r) => ({ key: `${r.rule_id} ${r.rule_name}`, count: r.count })))]));
  }

  async function renderEvents() {
    const main = $("#main");
    main.innerHTML = "";
    const input = el("input", { type: "search", placeholder: 'e.g. event.action:logon-failed AND source.ip:10.10.20.*   |   "certutil"   |   tags:threat-intel-match', value: state.eventsQuery });
    const run = () => { state.eventsQuery = input.value; state.eventsOffset = 0; load(); };
    input.addEventListener("keydown", (e) => { if (e.key === "Enter") run(); });
    const limitSel = el("select", {}, [50, 100, 200, 500].map((n) => el("option", { value: n }, String(n))));
    limitSel.value = "100";
    main.appendChild(el("div", { class: "topbar" }, [el("h1", {}, "Events"), el("div", { class: "grow" }), rangePicker(() => { state.eventsQuery = input.value; state.eventsOffset = 0; load(); })]));
    main.appendChild(el("div", { class: "toolbar" }, [input, limitSel, el("button", { class: "primary", onclick: run }, "Search"), el("button", { onclick: () => { input.value = ""; run(); } }, "clear")]));
    const help = el("div", { class: "muted", style: "font-size:12px;margin-bottom:10px" }, "Syntax: field:value · wildcards * ? · AND / OR / NOT · ( ) · field:>100 · _exists_:field · free text = full-text search. Time: a quick range, “all”, or exact from / to dates above. Click a value in the side panel to filter.");
    main.appendChild(help);
    const layout = el("div", { style: "display:grid;grid-template-columns:260px 1fr;gap:14px" });
    const side = el("div", {});
    const content = el("div", {});
    layout.appendChild(side); layout.appendChild(content);
    main.appendChild(layout);
    async function load() {
      content.innerHTML = '<div class="empty">Loading…</div>';
      const q = state.eventsQuery, t = timeParams();
      try {
        const [res, hist, ds, act, hosts] = await Promise.all([
          api(`/api/events?${qs({ q, from: t.from, to: t.to, limit: limitSel.value, offset: state.eventsOffset })}`),
          api(`/api/events/histogram?${qs({ q, from: t.from, to: t.to })}`),
          api(`/api/events/terms?${qs({ field: "event.dataset", q, from: t.from, to: t.to, size: 8 })}`),
          api(`/api/events/terms?${qs({ field: "event.action", q, from: t.from, to: t.to, size: 12 })}`),
          api(`/api/events/terms?${qs({ field: "host.name", q, from: t.from, to: t.to, size: 8 })}`),
        ]);
        side.innerHTML = "";
        const addTerm = (field) => (k) => { const term = `${field}:"${k}"`; input.value = input.value ? `${input.value} AND ${term}` : term; run(); };
        side.appendChild(el("div", { class: "card" }, [el("h3", {}, "Datasets"), hbars(ds.buckets, addTerm("event.dataset"))]));
        side.appendChild(el("div", { class: "card", style: "margin-top:10px" }, [el("h3", {}, "Actions"), hbars(act.buckets, addTerm("event.action"))]));
        side.appendChild(el("div", { class: "card", style: "margin-top:10px" }, [el("h3", {}, "Hosts"), hbars(hosts.buckets, addTerm("host.name"))]));
        content.innerHTML = "";
        content.appendChild(el("div", { class: "card" }, [el("h3", {}, `${fmtNum(res.total)} events · ${rangeLabel()}`), el("div", { class: "chart", html: barChart(hist.buckets, "#0092BC", 120) })]));
        const rows = res.hits.map((doc) => el("tr", { class: "row", onclick: () => eventDetail(doc) }, [
          el("td", { class: "mono" }, fmtTime(doc["@timestamp"])), el("td", {}, doc["host.name"] || "-"), el("td", { class: "mono" }, doc["event.dataset"] || "-"),
          el("td", {}, [doc["event.action"] || "-", doc["event.code"] ? el("div", { class: "muted" }, "code " + doc["event.code"]) : null]),
          el("td", {}, sevSmall(doc["event.severity"])), el("td", { class: "msg", title: doc.message || "" }, doc.message || ""),
        ]));
        const table = el("table", {}, [el("thead", {}, el("tr", {}, ["time", "host", "dataset", "action", "sev", "message"].map((h) => el("th", {}, h)))), el("tbody", {}, rows)]);
        const exportEcs = async () => {
          try { const r = await api(`/api/events?${qs({ q, from: t.from, to: t.to, limit: limitSel.value, offset: state.eventsOffset, format: "ecs" })}`); download("kharibulbul-export-ecs.json", JSON.stringify(r.hits, null, 2), "application/json"); } catch (e) { toast("Error: " + e.message); }
        };
        const pager = el("div", { class: "toolbar", style: "margin-top:10px" }, [
          el("button", { class: "small", disabled: state.eventsOffset === 0 ? "disabled" : null, onclick: () => { state.eventsOffset = Math.max(0, state.eventsOffset - Number(limitSel.value)); load(); } }, "← newer"),
          el("span", { class: "muted" }, `${res.hits.length ? state.eventsOffset + 1 : 0}-${state.eventsOffset + res.hits.length} of ${fmtNum(res.total)}`),
          el("button", { class: "small", disabled: state.eventsOffset + res.hits.length >= res.total ? "disabled" : null, onclick: () => { state.eventsOffset += Number(limitSel.value); load(); } }, "older →"),
          el("button", { class: "small", onclick: () => download("kharibulbul-export.json", JSON.stringify(res.hits, null, 2), "application/json") }, "⬇ export JSON"),
          el("button", { class: "small", title: "the same events as nested Elastic Common Schema documents", onclick: exportEcs }, "⬇ export ECS JSON"),
        ]);
        content.appendChild(el("div", { class: "card", style: "margin-top:10px" }, [res.hits.length ? table : el("div", { class: "empty" }, "No events match in this time range."), pager]));
      } catch (e) { content.innerHTML = `<div class="empty">Error: ${esc(e.message)}</div>`; }
    }
    load();
  }
  function sevSmall(score) { const s = score >= 95 ? "critical" : score >= 75 ? "high" : score >= 50 ? "medium" : score >= 30 ? "low" : "informational"; return el("span", { class: "pill sev-" + s, title: String(score) }, s[0].toUpperCase()); }

  // ------------------------------------------------------------------ alerts
  function statusCell(al) {
    const lvl = al.status === "escalated" && al.escalation ? ` L${al.escalation.level}` : "";
    return el("span", { class: "st-" + al.status, title: al.status === "escalated" && al.escalation ? `escalated to ${al.escalation.to}` : "" }, (al.status === "escalated" ? "⬆ " : "") + al.status.replace("_", " ") + lvl);
  }
  async function renderAlerts() {
    const main = $("#main");
    main.innerHTML = "";
    const statusSel = el("select", {}, [["", "any status"], ["new", "new"], ["acknowledged", "acknowledged"], ["investigating", "investigating"], ["escalated", "escalated"], ["closed", "closed"], ["false_positive", "false positive"], [OPEN_STATUSES, "open (new+ack+inv+escalated)"]].map(([v, l]) => el("option", { value: v }, l)));
    statusSel.value = OPEN_STATUSES;
    const sevSel = el("select", {}, [["", "any severity"], ["critical", "critical"], ["high", "high"], ["medium", "medium"], ["low", "low"], ["critical,high", "critical + high"]].map(([v, l]) => el("option", { value: v }, l)));
    const q = el("input", { type: "search", placeholder: "filter text (rule, host, user, ip…)" });
    main.appendChild(el("div", { class: "topbar" }, [el("h1", {}, "Alerts"), el("div", { class: "grow" }), rangePicker(() => load())]));
    main.appendChild(el("div", { class: "toolbar" }, [statusSel, sevSel, q, el("button", { class: "primary", onclick: () => load() }, "Apply")]));
    q.addEventListener("keydown", (e) => { if (e.key === "Enter") load(); });
    const box = el("div", {});
    main.appendChild(box);
    async function load() {
      box.innerHTML = '<div class="empty">Loading…</div>';
      const t = timeParams();
      try {
        const res = await api(`/api/alerts?${qs({ status: statusSel.value, severity: sevSel.value, q: q.value, from: t.from, to: t.to, limit: 500 })}`);
        box.innerHTML = "";
        const summary = await api(`/api/alerts/summary?${qs({ from: t.from })}`);
        const entries = Object.entries(summary.by_severity || {}).map(([k, v]) => ({ key: k, count: v, color: SEV_COLORS[k] || "#8a97b5" }));
        box.appendChild(el("div", { class: "grid cols-3" }, [
          el("div", { class: "card" }, [el("h3", {}, "By severity (range)"), el("div", { html: donut(entries) })]),
          el("div", { class: "card" }, [el("h3", {}, "By status"), hbars(Object.entries(summary.by_status || {}).map(([k, v]) => ({ key: k, count: v })), (k) => { statusSel.value = k; load(); })]),
          el("div", { class: "card" }, [el("h3", {}, "By rule"), hbars((summary.by_rule || []).map((r) => ({ key: r.rule_id + " " + r.rule_name, count: r.count })))]),
        ]));
        const rows = res.hits.map((al) => el("tr", { class: "row", onclick: () => openAlert(al.id, load) }, [
          el("td", { class: "mono" }, fmtTime(al.last_seen)), el("td", {}, sevPill(al.severity)),
          el("td", {}, [el("strong", {}, al["rule.name"]), el("div", { class: "muted" }, al["rule.id"] + " · " + al.kind)]),
          el("td", {}, [al.entity, al["source.geo.country_name"] ? el("div", { class: "muted" }, al["source.geo.country_name"]) : null]),
          el("td", { class: "right" }, fmtNum(al.count)), el("td", {}, (al.mitre || []).map((m) => el("span", { class: "tag" }, m.technique || ""))),
          el("td", {}, statusCell(al)), el("td", {}, al.status === "escalated" && al.escalation ? al.escalation.to : (al.assignee || "")),
        ]));
        box.appendChild(el("div", { class: "card", style: "margin-top:14px" }, [el("h3", {}, `${res.hits.length} alerts`), res.hits.length ? el("table", {}, [el("thead", {}, el("tr", {}, ["last seen", "severity", "rule", "entity", "count", "MITRE", "status", "assignee / escalated to"].map((h) => el("th", {}, h)))), el("tbody", {}, rows)]) : el("div", { class: "empty" }, "No alerts. Generate test data with: kharibulbul simulate all")]));
      } catch (e) { box.innerHTML = `<div class="empty">Error: ${esc(e.message)}</div>`; }
    }
    load();
  }

  async function openAlert(id, after) {
    let al;
    try { al = await api(`/api/alerts/${id}`); } catch (e) { toast("Error: " + e.message); return; }
    const assignee = el("input", { type: "text", placeholder: "assignee (analyst name)", value: al.assignee || "", style: "width:220px" });
    const notes = el("textarea", { rows: 3, placeholder: "investigation notes", style: "width:100%" }, al.notes || "");
    const setStatus = async (status) => {
      try { await api(`/api/alerts/${id}`, { method: "PATCH", body: { status, assignee: assignee.value, notes: notes.value } }); toast(`Alert → ${status}`); if (after) after(); openAlert(id, after); } catch (e) { toast("Error: " + e.message); }
    };
    // escalation: hand the alert to the next tier, optionally one severity step up
    const esc0 = al.escalation || {};
    const closed = al.status === "closed" || al.status === "false_positive";
    const nextLevel = Math.min(3, (esc0.level || 0) + 1);
    const tiers = { 1: "Tier 2 analyst", 2: "SOC lead / incident responder", 3: "Incident manager (CSIRT)" };
    const escTo = el("input", { type: "text", placeholder: `escalate to (default: ${tiers[nextLevel]})`, style: "width:280px" });
    const escReason = el("input", { type: "text", placeholder: "reason (what makes this more than routine?)" });
    const escRaise = el("input", { type: "checkbox", id: "esc-raise" }); escRaise.checked = al.severity !== "critical";
    const escalate = async () => {
      try {
        const r = await api(`/api/alerts/${id}/escalate`, { method: "POST", body: { to: escTo.value, reason: escReason.value, by: assignee.value, assignee: assignee.value, notes: notes.value, raise_severity: escRaise.checked } });
        toast(`Alert escalated to ${r.escalation.to} (level ${r.escalation.level})`); if (after) after(); openAlert(id, after);
      } catch (e) { toast("Error: " + e.message); }
    };
    const samples = (al.sample_events || []).map((s) => el("tr", {}, [el("td", { class: "mono" }, fmtTime(s["@timestamp"])), el("td", {}, s["host.name"] || ""), el("td", {}, s["event.action"] || ""), el("td", { class: "msg", title: s.message }, s.message || "")]));
    const history = (al.history || []).map((h) => el("tr", {}, [el("td", { class: "mono" }, fmtTime(h.ts)), el("td", {}, el("span", { class: "st-" + h.status }, h.status + (h.level ? ` L${h.level}` : ""))), el("td", {}, h.by || ""), el("td", {}, [h.to ? "→ " + h.to : "", h.reason ? el("div", { class: "muted" }, h.reason) : null])]));
    const body = el("div", {}, [
      el("p", {}, [sevPill(al.severity), " ", el("strong", {}, al.summary || ""), el("div", { class: "muted" }, `${al["rule.id"]} · ${al.kind} · first ${fmtTime(al.first_seen)} · last ${fmtTime(al.last_seen)} · ${al.count} events · status `), statusCell(al)]),
      esc0.level ? el("div", { class: "callout escalated" }, [el("strong", {}, `⬆ Escalated - level ${esc0.level} → ${esc0.to}`), el("div", {}, `by ${esc0.by || "?"} on ${fmtTime(esc0.ts)}` + (esc0.severity_before && esc0.severity_before !== esc0.severity_after ? ` · severity ${esc0.severity_before} → ${esc0.severity_after}` : "")), esc0.reason ? el("div", { class: "muted" }, esc0.reason) : null]) : null,
      el("p", {}, al["rule.description"] || ""),
      el("div", { class: "chips" }, [
        al["host.name"] ? el("span", { class: "chip", onclick: () => searchFrom(`host.name:"${al["host.name"]}"`) }, "host " + al["host.name"]) : null,
        al["user.name"] ? el("span", { class: "chip", onclick: () => searchFrom(`user.name:"${al["user.name"]}"`) }, "user " + al["user.name"]) : null,
        al["source.ip"] ? el("span", { class: "chip", onclick: () => searchFrom(`source.ip:${al["source.ip"]}`) }, "source " + al["source.ip"] + (al["source.geo.country_name"] ? ` · ${al["source.geo.country_name"]}` : "")) : null,
        ...(al.mitre || []).map((m) => el("a", { class: "chip", href: `https://attack.mitre.org/techniques/${(m.technique || "").replace(".", "/")}/`, target: "_blank", rel: "noopener" }, `ATT&CK ${m.technique} ${m.tactic || ""}`)),
      ]),
      el("h3", {}, "Triage"),
      el("div", { class: "toolbar" }, [assignee, el("button", { onclick: () => setStatus("acknowledged") }, "Acknowledge"), el("button", { onclick: () => setStatus("investigating") }, "Investigate"), el("button", { class: "primary", onclick: () => setStatus("closed") }, "Close"), el("button", { onclick: () => setStatus("false_positive") }, "False positive"), closed ? el("button", { onclick: () => setStatus("new") }, "Reopen") : null]),
      notes,
      el("h3", {}, "Escalate"),
      closed ? el("p", { class: "muted" }, `This alert is ${al.status.replace("_", " ")} - reopen it to escalate.`) : el("div", {}, [
        el("div", { class: "toolbar" }, [escTo, escReason]),
        el("div", { class: "toolbar" }, [el("label", { for: "esc-raise", class: "check" }, [escRaise, " raise severity one step"]), el("button", { class: "danger", onclick: escalate }, `⬆ Escalate to level ${nextLevel}`), el("span", { class: "muted" }, "notifies every enabled sink (console, file, webhook, e-mail)")]),
      ]),
      el("h3", {}, "Sample events"),
      el("table", {}, [el("thead", {}, el("tr", {}, ["time", "host", "action", "message"].map((h) => el("th", {}, h)))), el("tbody", {}, samples)]),
      al.playbook ? el("p", {}, [el("a", { href: `#/playbooks/${al.playbook.split("/").pop()}` }, "📘 Open playbook: " + al.playbook.split("/").pop())]) : null,
      history.length ? el("details", {}, [el("summary", {}, `history (${history.length})`), el("table", {}, [el("thead", {}, el("tr", {}, ["when", "status", "by", "detail"].map((h) => el("th", {}, h)))), el("tbody", {}, history)])]) : null,
      el("details", {}, [el("summary", {}, "alert JSON"), el("pre", {}, JSON.stringify(al, null, 2))]),
    ]);
    drawer(al["rule.name"], body);
  }

  // ------------------------------------------------------------------ agents
  const isLinkLocal = (ip) => /^fe80:/i.test(ip) || ip.startsWith("169.254.");
  function ipCell(a) {
    const ips = (a.ip || []).filter(Boolean);
    const shown = ips.filter((ip) => !isLinkLocal(ip)), hidden = ips.filter(isLinkLocal);
    if (!ips.length && !a.remote) return el("span", { class: "muted" }, a.status === "pending" ? "not connected yet" : "-");
    const primary = a.ip_primary || shown[0] || a.remote;
    return el("div", { class: "iplist" }, [
      el("strong", { class: "mono" }, primary || "-"),
      ...shown.filter((ip) => ip !== primary).map((ip) => el("span", { class: "tag" }, ip)),
      hidden.length ? el("span", { class: "muted", title: hidden.join("\n") }, ` +${hidden.length} link-local`) : null,
    ]);
  }
  async function renderAgents() {
    const main = $("#main");
    main.innerHTML = "";
    main.appendChild(el("div", { class: "topbar" }, [el("h1", {}, "Agents"), el("div", { class: "grow" }), el("button", { class: "primary", onclick: addAgentWizard }, "＋ Add agent"), el("button", { class: "small", onclick: renderAgents }, "↻ refresh")]));
    try {
      const res = await api("/api/agents");
      const remove = async (a) => {
        if (!confirm(`Remove agent "${a.name || a.id}" from the list?\n\nIts stored events stay. If the agent is still running it registers again by itself.`)) return;
        try { await api(`/api/agents/${a.id}`, { method: "DELETE" }); toast("agent removed"); renderAgents(); } catch (e) { toast("Error: " + e.message); }
      };
      const rows = res.agents.map((a) => el("tr", {}, [
        el("td", {}, el("span", { class: "status-" + a.status }, "● " + a.status)), el("td", {}, [el("strong", {}, a.name || a.id), el("div", { class: "muted mono" }, a.id)]),
        el("td", {}, a.host || ""), el("td", {}, ipCell(a)), el("td", { class: "mono" }, a.remote || "-"), el("td", {}, a.os || ""), el("td", {}, a.version || ""),
        el("td", { class: "right" }, a.status === "pending" ? "-" : el("a", { href: "#", onclick: (e) => { e.preventDefault(); searchFrom(`agent.id:${a.id}`); } }, fmtNum(a.events))),
        el("td", {}, a.status === "pending" ? "never" : `${ago(a.seconds_since_seen)} ago`), el("td", {}, fmtTime(a.first_seen)),
        el("td", {}, el("button", { class: "small", title: "remove from the list", onclick: () => remove(a) }, "✕")),
      ]));
      main.appendChild(el("div", { class: "card" }, res.agents.length ? el("table", {}, [el("thead", {}, el("tr", {}, ["status", "agent", "host", "IP addresses", "connected from", "os", "version", "events", "last seen", "first seen", ""].map((h) => el("th", {}, h)))), el("tbody", {}, rows)]) : el("div", { class: "empty" }, "No agents yet. Press “＋ Add agent” to connect the first host.")));
      main.appendChild(el("div", { class: "card md", style: "margin-top:14px" }, [el("h3", {}, "How an agent is added"), el("ol", {}, [
        el("li", {}, ["Press ", el("strong", {}, "＋ Add agent"), ", name the host, choose its operating system profile and the address under which it reaches this server."]),
        el("li", {}, "The server issues an agent id, lists the agent as pending and generates its configuration file."),
        el("li", {}, ["Copy the Kharibulbul folder and that file to the host and start ", el("code", {}, "python -m kharibulbul agent -c config/agent-<name>.yml"), " (the wizard shows the exact commands for the chosen system, including running it as a service)."]),
        el("li", {}, "The agent connects to TCP 5044, the row turns online and its IP addresses, version and event count appear here."),
      ]), el("p", { class: "muted" }, "IP addresses: the bold one is the address the host uses towards this server, the others are its remaining interfaces; “connected from” is what the server sees (it differs behind NAT). Statuses: online · silent (no heartbeat for 5 min) · disconnected · pending (enrolled, never connected).")]));
    } catch (e) { main.appendChild(el("div", { class: "empty" }, "Error: " + e.message)); }
  }
  async function addAgentWizard() {
    let info;
    try { info = await api("/api/agents/enroll/info"); } catch (e) { toast("Error: " + e.message); return; }
    const name = el("input", { type: "text", placeholder: "e.g. ws02, srv-web01", maxlength: 48 });
    const profile = el("select", {}, Object.entries(info.profiles).map(([k, v]) => el("option", { value: k }, v)));
    const hostList = el("datalist", { id: "kb-server-addresses" }, info.server_addresses.map((ip) => el("option", { value: ip })));
    const host = el("input", { type: "text", list: "kb-server-addresses", value: info.server_host });
    const port = el("input", { type: "number", value: info.port, min: 1, max: 65535, style: "width:100px" });
    const zone = el("input", { type: "text", placeholder: "optional label, e.g. workstations, dmz" });
    const out = el("div", {});
    const create = async () => {
      out.innerHTML = "";
      let r;
      try { r = await api("/api/agents/enroll", { method: "POST", body: { name: name.value.trim(), profile: profile.value, server_host: host.value.trim(), port: port.value, zone: zone.value.trim(), tls: info.tls } }); }
      catch (e) { out.appendChild(el("p", { class: "warn" }, "Error: " + e.message)); return; }
      toast(`agent ${r.agent.name} enrolled (pending)`);
      if (currentRoute === "agents") renderAgents();        // the new pending row appears behind the drawer
      const steps = el("ol", { class: "steps" }, r.steps.map((s) => el("li", {}, [el("strong", {}, s.title), el("div", {}, s.text), ...(s.commands || []).map((c) => el("pre", { class: "cmd", title: "click to copy", onclick: () => copyText(c) }, c))])));
      out.appendChild(el("div", { class: "callout" }, [el("strong", {}, `Agent “${r.agent.name}” is registered as pending.`), el("div", { class: "muted mono" }, "id " + r.agent.id)]));
      out.appendChild(el("h3", {}, "1 · Configuration file"));
      out.appendChild(el("div", { class: "toolbar" }, [el("button", { class: "primary", onclick: () => download(r.filename, r.config, "text/yaml") }, "⬇ download " + r.filename), el("button", { onclick: () => copyText(r.config) }, "copy")]));
      out.appendChild(el("pre", {}, r.config));
      out.appendChild(el("h3", {}, "2 · On the host"));
      out.appendChild(steps);
    };
    const body = el("div", {}, [
      el("p", { class: "muted" }, "Registers a new host and generates its agent configuration. Nothing is installed remotely: you copy the file to the host and start the agent there."),
      el("div", { class: "form" }, [
        el("label", {}, "Agent name"), name,
        el("label", {}, "System / profile"), profile,
        el("label", {}, "Server address (as seen from the host)"), el("div", {}, [host, hostList, el("div", { class: "muted" }, "this server's addresses: " + (info.server_addresses.join(", ") || "unknown") + (info.tls ? " · TLS is enabled" : "") + (info.secret_required ? " · shared secret required" : ""))]),
        el("label", {}, "Ingest port"), port,
        el("label", {}, "Zone label"), zone,
      ]),
      el("div", { class: "toolbar", style: "margin-top:12px" }, [el("button", { class: "primary", onclick: create }, "Create agent + configuration")]),
      out,
    ]);
    drawer("Add agent", body, true);
    name.focus();
  }

  // ------------------------------------------------------------------ rules
  async function renderRules() {
    const main = $("#main");
    main.innerHTML = "";
    const filter = el("input", { type: "search", placeholder: "filter rules (id, title, tag, technique)…" });
    const onlyCustom = el("input", { type: "checkbox", id: "only-custom" });
    main.appendChild(el("div", { class: "topbar" }, [el("h1", {}, "Detection rules"), el("div", { class: "grow" }),
      el("button", { class: "primary", onclick: () => ruleEditor() }, "＋ New rule"),
      el("button", { class: "small", onclick: async () => { try { const r = await api("/api/rules/reload", { method: "POST" }); toast(`reloaded ${r.loaded} rules`); renderRules(); } catch (e) { toast("Error: " + e.message); } } }, "⟳ reload from disk")]));
    main.appendChild(el("div", { class: "toolbar" }, [filter, el("label", { for: "only-custom", class: "check" }, [onlyCustom, " custom rules only"])]));
    const box = el("div", {});
    main.appendChild(box);
    try {
      const res = await api("/api/rules");
      const draw = () => {
        const needle = filter.value.trim().toLowerCase();
        const list = res.rules.filter((r) => (!onlyCustom.checked || r.custom) && (!needle || [r.id, r.title, (r.tags || []).join(" "), (r.mitre || []).map((m) => m.technique).join(" ")].join(" ").toLowerCase().includes(needle)));
        const rows = list.map((r) => {
          const tog = el("input", { type: "checkbox", class: "switch", title: "enable/disable" });
          tog.checked = r.enabled;
          tog.addEventListener("change", async () => { try { await api(`/api/rules/${r.id}/${tog.checked ? "enable" : "disable"}`, { method: "POST" }); toast(`${r.id} ${tog.checked ? "enabled" : "disabled"}`); } catch (e) { toast("Error: " + e.message); tog.checked = !tog.checked; } });
          return el("tr", {}, [
            el("td", {}, tog), el("td", { class: "mono nowrap" }, [r.id, r.custom ? badge("custom", "custom") : null]), el("td", {}, sevPill(r.severity)), el("td", {}, r.kind),
            el("td", {}, [el("a", { href: "#", onclick: (e) => { e.preventDefault(); openRule(r.id); } }, r.title), el("div", { class: "muted" }, (r.tags || []).join(", "))]),
            el("td", {}, (r.mitre || []).map((m) => el("span", { class: "tag" }, m.technique || ""))),
            el("td", { class: "right" }, fmtNum(r.stats.hits + (r.stats.hits_this_session || 0))), el("td", { class: "right" }, fmtNum(r.stats.alerts)), el("td", { class: "mono" }, r.stats.last_hit ? fmtTime(r.stats.last_hit) : "-"),
          ]);
        });
        box.innerHTML = "";
        box.appendChild(el("div", { class: "card" }, [el("h3", {}, `${list.length} of ${res.count} rules · ${res.custom || 0} custom`), list.length ? el("table", {}, [el("thead", {}, el("tr", {}, ["on", "id", "severity", "kind", "title", "MITRE", "hits", "alerts", "last hit"].map((h) => el("th", {}, h)))), el("tbody", {}, rows)]) : el("div", { class: "empty" }, onlyCustom.checked ? "No custom rules yet. Press “＋ New rule” to write one." : "No rule matches the filter.")]));
      };
      filter.addEventListener("input", draw); onlyCustom.addEventListener("change", draw);
      draw();
    } catch (e) { box.appendChild(el("div", { class: "empty" }, "Error: " + e.message)); }
  }
  async function openRule(id) {
    try {
      const r = await api(`/api/rules/${id}`);
      const del = async () => {
        if (!confirm(`Delete custom rule ${r.id}?\n\nThe file custom/rules/${r.id}.yml is removed. Existing alerts stay.`)) return;
        try { await api(`/api/rules/${r.id}`, { method: "DELETE" }); toast(`${r.id} deleted`); closeDrawer(); renderRules(); } catch (e) { toast("Error: " + e.message); }
      };
      const clone = async () => {
        let next = "KB-CUS-001";
        try { next = (await api("/api/rules/template")).id; } catch (e) { /* keep default */ }
        ruleEditor({ yaml: (r.yaml || "").replace(new RegExp("^id:\\s*" + r.id.replace(/[-/\\^$*+?.()|[\]{}]/g, "\\$&") + "\\s*$", "m"), "id: " + next) });
      };
      drawer(`${r.id} · ${r.title}`, el("div", {}, [
        el("p", {}, [sevPill(r.severity), " ", r.custom ? badge("custom", "custom") : badge("shipped", ""), " ", r.description]),
        el("p", { class: "muted" }, `kind: ${r.kind} · condition: ${r.condition || "(all selections)"} · suppress: ${r.suppress || "default"}s · playbook: ${r.playbook || "-"}`),
        r.falsepositives && r.falsepositives.length ? el("p", {}, ["False positives: ", r.falsepositives.join("; ")]) : null,
        el("div", { class: "toolbar" }, r.custom
          ? [el("button", { class: "primary", onclick: () => ruleEditor({ id: r.id, yaml: r.yaml }) }, "✎ Edit"), el("button", { class: "danger", onclick: del }, "Delete")]
          : [el("button", { onclick: clone }, "⧉ Clone as custom rule"), el("span", { class: "muted" }, "shipped rules are read-only")]),
        el("pre", {}, r.yaml || JSON.stringify(r.detection, null, 2)),
      ]));
    } catch (e) { toast("Error: " + e.message); }
  }
  async function ruleEditor(existing) {
    // existing: {id?, yaml} - with an id it is an edit of a custom rule, otherwise a new rule
    let yamlText = existing && existing.yaml;
    if (!yamlText) { try { yamlText = (await api("/api/rules/template")).yaml; } catch (e) { toast("Error: " + e.message); return; } }
    const editing = existing && existing.id;
    const ta = el("textarea", { class: "code", rows: 24, spellcheck: "false" }, yamlText);
    const samples = el("textarea", { class: "code", rows: 5, spellcheck: "false", placeholder: "optional: raw log lines to test against, one per line, e.g.\nSep 27 10:00:01 srv sshd[1]: Failed password for root from 10.10.99.10 port 1 ssh2" });
    const out = el("div", {});
    ta.addEventListener("keydown", (e) => { if (e.key === "Tab") { e.preventDefault(); const s = ta.selectionStart; ta.setRangeText("  ", s, ta.selectionEnd, "end"); } });
    const test = async () => {
      out.innerHTML = "";
      try {
        const lines = samples.value.split(/\r?\n/).filter((l) => l.trim());
        const r = await api("/api/rules/test", { method: "POST", body: { rule: ta.value, events: lines } });
        if (!r.valid) { out.appendChild(el("div", { class: "callout bad" }, [el("strong", {}, "Not valid"), el("ul", {}, r.errors.map((x) => el("li", {}, x)))])); return false; }
        const matched = r.events.filter((x) => x.matched).length;
        out.appendChild(el("div", { class: "callout good" }, [el("strong", {}, `Valid ${r.rule.kind} rule · ${r.rule.id}`),
          lines.length ? el("div", {}, `${r.events.length} sample events parsed, ${matched} matched the selection, ${r.alerts.length} alert(s) would be raised`) : el("div", { class: "muted" }, "add sample log lines below to see what it matches"),
          ...r.events.map((x) => el("div", { class: "mono " + (x.matched ? "ok" : "muted") }, `${x.matched ? "✓" : "·"} ${x["event.dataset"] || ""} ${x["event.action"] || ""} - ${x.message || ""}`)),
          ...r.alerts.map((a) => el("div", { class: "mono warn" }, `⚑ alert: count=${a.count} group=${a.group_key}`))]));
        return true;
      } catch (e) { out.appendChild(el("div", { class: "callout bad" }, "Error: " + e.message)); return false; }
    };
    const save = async () => {
      try {
        const r = editing ? await api(`/api/rules/${existing.id}`, { method: "PUT", body: { rule: ta.value } }) : await api("/api/rules", { method: "POST", body: { rule: ta.value } });
        toast(`${r.rule.id} saved · ${r.loaded} rules loaded`); closeDrawer(); if (currentRoute === "rules") renderRules(); openRule(r.rule.id);
      } catch (e) { out.innerHTML = ""; out.appendChild(el("div", { class: "callout bad" }, [el("strong", {}, "Not saved"), el("div", {}, e.message)])); }
    };
    drawer(editing ? `Edit ${existing.id}` : "New custom rule", el("div", {}, [
      el("p", { class: "muted" }, ["Sigma-like YAML: ", el("code", {}, "detection"), " selections with field|modifier: value (contains, startswith, endswith, re, cidr, gt/gte/lt/lte, exists, all, not), a ", el("code", {}, "condition"), ", optional ", el("code", {}, "threshold"), " or ", el("code", {}, "sequence"), ". Saved to custom/rules/ and active immediately. Field names: docs/SCHEMA.md (or open any event on the Events page)."]),
      ta,
      el("h3", {}, "Test before saving"), samples,
      el("div", { class: "toolbar", style: "margin-top:10px" }, [el("button", { onclick: test }, "Validate & test"), el("button", { class: "primary", onclick: save }, editing ? "Save changes" : "Save rule"), el("button", { onclick: closeDrawer }, "cancel")]),
      out,
    ]), true);
  }

  // ------------------------------------------------------------------ playbooks
  const safeHref = (url) => (/^(https?:\/\/|#|\/(?!\/)|mailto:)/i.test(url) ? url : "#");
  function renderMarkdown(md) {
    const lines = md.split(/\r?\n/);
    let html = "", inCode = false, inList = null, inTable = false;
    const inline = (s) => esc(s).replace(/`([^`]+)`/g, "<code>$1</code>").replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>").replace(/\[([^\]]+)\]\(([^)]+)\)/g, (m, text, url) => `<a href="${safeHref(url)}" target="_blank" rel="noopener">${text}</a>`);
    const closeList = () => { if (inList) { html += `</${inList}>`; inList = null; } };
    const closeTable = () => { if (inTable) { html += "</tbody></table>"; inTable = false; } };
    for (const raw of lines) {
      const line = raw.replace(/\s+$/, "");
      if (line.startsWith("```")) { closeList(); closeTable(); html += inCode ? "</pre>" : "<pre>"; inCode = !inCode; continue; }
      if (inCode) { html += esc(line) + "\n"; continue; }
      if (line.startsWith("|")) {
        if (/^\|\s*:?-+/.test(line)) continue;
        const cells = line.split("|").slice(1, -1).map((c) => c.trim());
        if (!inTable) { closeList(); html += "<table><thead><tr>" + cells.map((c) => `<th>${inline(c)}</th>`).join("") + "</tr></thead><tbody>"; inTable = true; continue; }
        html += "<tr>" + cells.map((c) => `<td>${inline(c)}</td>`).join("") + "</tr>"; continue;
      }
      closeTable();
      const h = line.match(/^(#{1,4})\s+(.*)/);
      if (h) { closeList(); html += `<h${h[1].length}>${inline(h[2])}</h${h[1].length}>`; continue; }
      const ul = line.match(/^\s*[-*]\s+(.*)/); const ol = line.match(/^\s*\d+[.)]\s+(.*)/);
      if (ul || ol) { const tag = ul ? "ul" : "ol"; if (inList !== tag) { closeList(); html += `<${tag}>`; inList = tag; } html += `<li>${inline((ul || ol)[1])}</li>`; continue; }
      closeList();
      if (!line.trim()) continue;
      html += `<p>${inline(line)}</p>`;
    }
    if (inCode) html += "</pre>";
    closeList(); closeTable();
    return html;
  }

  let playbookDraft = null;   // content handed to the "new playbook" editor by "use as template"
  async function renderPlaybooks(name) {
    const main = $("#main");
    main.innerHTML = "";
    main.appendChild(el("div", { class: "topbar" }, [el("h1", {}, "Response playbooks"), el("div", { class: "grow" }), el("button", { class: "primary", onclick: () => { location.hash = "#/playbooks/+new"; } }, "＋ New playbook")]));
    try {
      const res = await api("/api/playbooks");
      const items = res.items || res.playbooks.map((p) => ({ name: p, custom: false }));
      const layout = el("div", { style: "display:grid;grid-template-columns:300px 1fr;gap:14px" });
      const list = el("div", { class: "card" }, [el("h3", {}, `Playbooks (${items.length})`), ...items.map((p) => el("div", { class: "pbitem" + (p.name === name ? " active" : "") }, [el("a", { href: `#/playbooks/${encodeURIComponent(p.name)}` }, p.name), p.custom ? badge("custom", "custom") : null]))]);
      const view = el("div", { class: "card md" }, el("div", { class: "empty" }, "Select a playbook, or press “＋ New playbook” to write your own."));
      layout.appendChild(list); layout.appendChild(view); main.appendChild(layout);
      const editor = (pbName, content) => {
        // pbName empty = new playbook
        const nameInput = el("input", { type: "text", placeholder: "file name, e.g. PB-C01-phishing.md", value: pbName || "", maxlength: 84 });
        if (pbName) nameInput.setAttribute("disabled", "disabled");
        const ta = el("textarea", { class: "code", rows: 26, spellcheck: "false" }, content);
        const preview = el("div", { class: "md preview" });
        const refresh = () => { preview.innerHTML = renderMarkdown(ta.value); };
        ta.addEventListener("input", refresh); refresh();
        const save = async () => {
          try {
            const r = pbName ? await api(`/api/playbooks/${encodeURIComponent(pbName)}`, { method: "PUT", body: { content: ta.value } }) : await api("/api/playbooks", { method: "POST", body: { name: nameInput.value.trim(), content: ta.value } });
            toast(`${r.name} saved`);
            if (location.hash === `#/playbooks/${encodeURIComponent(r.name)}`) renderPlaybooks(r.name); else location.hash = `#/playbooks/${encodeURIComponent(r.name)}`;
          } catch (e) { toast("Error: " + e.message); }
        };
        view.className = "card";
        view.innerHTML = "";
        view.appendChild(el("h3", {}, pbName ? `Edit ${pbName}` : "New playbook"));
        view.appendChild(el("div", { class: "toolbar" }, [nameInput, el("button", { class: "primary", onclick: save }, "Save playbook"), el("button", { onclick: () => { if (pbName) renderPlaybooks(pbName); else location.hash = "#/playbooks"; } }, "cancel")]));
        view.appendChild(el("p", { class: "muted" }, "Markdown: # headings, lists, tables, **bold**, `code`, ```kql blocks for triage queries. Saved to custom/playbooks/; link it from a rule with playbook: custom/playbooks/<name>."));
        view.appendChild(el("div", { class: "split" }, [ta, preview]));
      };
      if (name === "+new") { editor("", playbookDraft || res.template || "# New playbook\n"); playbookDraft = null; return; }
      if (name) {
        const md = await api(`/api/playbooks/${encodeURIComponent(name)}`);
        const item = items.find((p) => p.name === name) || { custom: false };
        view.innerHTML = "";
        if (item.custom) {
          const del = async () => {
            if (!confirm(`Delete playbook ${name}?`)) return;
            try { await api(`/api/playbooks/${encodeURIComponent(name)}`, { method: "DELETE" }); toast(`${name} deleted`); location.hash = "#/playbooks"; } catch (e) { toast("Error: " + e.message); }
          };
          view.appendChild(el("div", { class: "toolbar" }, [badge("custom", "custom"), el("div", { class: "grow" }), el("button", { class: "primary", onclick: () => editor(name, md) }, "✎ Edit"), el("button", { class: "danger", onclick: del }, "Delete")]));
        } else {
          view.appendChild(el("div", { class: "toolbar" }, [badge("shipped", ""), el("span", { class: "muted" }, "read-only"), el("div", { class: "grow" }), el("button", { class: "small", onclick: () => { playbookDraft = md; location.hash = "#/playbooks/+new"; } }, "⧉ use as template")]));
        }
        view.appendChild(el("div", { class: "md", html: renderMarkdown(md) }));
      }
    } catch (e) { main.appendChild(el("div", { class: "empty" }, "Error: " + e.message)); }
  }

  // ------------------------------------------------------------------ router
  let currentRoute = "";
  const routes = { overview: renderOverview, events: renderEvents, alerts: renderAlerts, agents: renderAgents, rules: renderRules, playbooks: renderPlaybooks };
  function route() {
    const hash = location.hash.replace(/^#\/?/, "") || "overview";
    const [name, ...rest] = hash.split("/");
    currentRoute = routes[name] ? name : "overview";
    document.querySelectorAll("nav a.item").forEach((a) => a.classList.toggle("active", a.dataset.route === currentRoute));
    closeDrawer();
    routes[currentRoute](rest.join("/") ? decodeURIComponent(rest.join("/")) : undefined);
    if (state.timer) clearInterval(state.timer);
    if (currentRoute === "overview") state.timer = setInterval(() => { if (currentRoute === "overview" && !$("#drawer-root").firstChild && !/^(INPUT|SELECT)$/.test((document.activeElement || {}).tagName || "")) renderOverview(); }, 30000);
  }
  window.addEventListener("hashchange", route);
  $("#set-token").addEventListener("click", (e) => { e.preventDefault(); const t = prompt("API token (leave empty to clear):", token); if (t !== null) { token = t; store.set("kb_token", t); toast("token saved"); route(); } });
  async function footer() {
    try {
      const h = await api("/api/health");
      $("#footer-status").textContent = `${h.name} v${h.version} · up ${ago(h.uptime_seconds)}`;
      // the server has newer dashboard files than this tab is running: offer the reload instead of failing silently
      if (h.ui && UI_BUILD && h.ui !== UI_BUILD && !$("#ui-update")) {
        document.body.appendChild(el("div", { id: "ui-update", class: "update-bar" }, ["The dashboard was updated on the server. ", el("button", { class: "primary small", onclick: () => { location.href = `/ui/?v=${encodeURIComponent(h.ui)}${location.hash}`; } }, "Reload now")]));
      }
    } catch (e) { $("#footer-status").textContent = "server unreachable"; }
  }
  footer(); setInterval(footer, 30000);
  route();
})();
