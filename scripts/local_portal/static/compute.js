// ARG local portal - Compute: operating system versions, end of support, vulnerability-scan coverage, pending
// security updates, outdated packages, CVEs, SQL Server instances and App Service runtimes (compute.json).
// All data is rendered with textContent / DOM nodes (never innerHTML); no inline scripts (CSP: script-src 'self').
(function () {
  "use strict";

  const PAGE_SIZE = 100;
  const SUPPORT_ORDER = ["ended", "ending", "esu", "unknown", "appliance", "supported"];
  const SUPPORT_LABELS = { ended: "Support ended", ending: "Ending soon", esu: "On ESU", supported: "Supported",
    unknown: "Not identified", appliance: "Network appliance" };
  const SUPPORT_PILL = { ended: "sev-critical", ending: "sev-high", esu: "sev-medium", supported: "sev-low",
    unknown: "sev-info", appliance: "sev-info" };
  const SCANNER_LABELS = { covered: "Covered", none: "None", unverified: "Not verified" };
  const COLUMNS = {
    machines: [
      { key: "name", label: "Name" }, { key: "kindLabel", label: "Machine" }, { key: "os", label: "Operating system" },
      { key: "osReported", label: "Reported version" }, { key: "support", label: "Support", sortKey: "supportRank" },
      { key: "supportEnds", label: "Support ends" }, { key: "exposureLabel", label: "Public IP" },
      { key: "scannerLabel", label: "Vulnerability scanner" },
      { key: "updates", label: "Security updates", num: true }, { key: "outdated", label: "Outdated packages", num: true },
      { key: "cveCount", label: "CVEs", num: true }, { key: "sqlLabel", label: "SQL Server" },
      { key: "state", label: "State" }, { key: "env", label: "Environment" }, { key: "subscription", label: "Subscription" },
      { key: "resourceGroup", label: "Resource group" },
    ],
    sql: [
      { key: "name", label: "Instance" }, { key: "host", label: "Host" }, { key: "product", label: "Version" },
      { key: "edition", label: "Edition" }, { key: "build", label: "Build" }, { key: "service", label: "Service" },
      { key: "support", label: "Support", sortKey: "supportRank" }, { key: "supportEnds", label: "Support ends" },
      { key: "esuLabel", label: "ESU" }, { key: "status", label: "Status" }, { key: "subscription", label: "Subscription" },
      { key: "resourceGroup", label: "Resource group" },
    ],
    apps: [
      { key: "name", label: "App" }, { key: "kind", label: "Kind" }, { key: "runtime", label: "Runtime" },
      { key: "support", label: "Support", sortKey: "supportRank" }, { key: "supportEnds", label: "Support ends" },
      { key: "exposure", label: "Network exposure" }, { key: "state", label: "State" },
      { key: "subscription", label: "Subscription" }, { key: "resourceGroup", label: "Resource group" },
    ],
  };
  const TITLES = { machines: "Machines", sql: "SQL Server instances", apps: "App Service runtimes" };

  let data = null;
  let rows = { machines: [], sql: [], apps: [] };
  let lastRows = [];
  const state = { view: "machines", f: {}, sort: { key: "", dir: 1 }, page: 0, open: new Set() };

  const $ = (id) => document.getElementById(id);
  function el(tag, attrs, text) {
    const node = document.createElement(tag);
    Object.entries(attrs || {}).forEach(([k, v]) => { if (v !== undefined && v !== null) node.setAttribute(k, v); });
    if (text !== undefined && text !== null) node.textContent = String(text);
    return node;
  }
  const fmt = (n) => (n === undefined || n === null || n === "" ? "" : Number(n).toLocaleString());
  const leaf = (id) => (id || "").split("/").filter(Boolean).pop() || "";
  const rank = (s) => { const i = SUPPORT_ORDER.indexOf(s); return i < 0 ? 9 : i; };

  // ---- data ----------------------------------------------------------------

  function prepare(d) {
    const machines = (d.machines || []).map((m) => {
      const p = m.patches || {};
      const pk = m.packages || {};
      const cv = m.cves || {};
      const sql = m.sql || [];
      const haystack = [m.name, m.computer, m.os, m.osReported, m.image, m.family, m.supportNote, m.subscription,
        m.resourceGroup, m.env, (m.agents || []).join(" "), (p.names || []).join(" "), (pk.names || []).join(" "),
        (cv.ids || []).join(" "), sql.map((s) => [s.name, s.product, s.edition, s.build].join(" ")).join(" ")]
        .join(" ").toLowerCase();
      return Object.assign({}, m, {
        kindLabel: m.kind === "arc" ? "Arc server" : "Azure VM",
        supportRank: rank(m.support),
        exposureLabel: m.publicIp === null || m.publicIp === undefined ? "n/a (on-premises)" : m.publicIp ? (m.running ? "Yes" : "Yes (stopped)") : "No",
        scannerLabel: SCANNER_LABELS[m.scanner] || m.scanner,
        updates: m.patches ? (p.security || 0) + (p.critical || 0) : null,
        outdated: m.packages ? pk.count : null,
        cveCount: m.cves ? cv.count : null,
        sqlLabel: sql.length ? Array.from(new Set(sql.map((s) => s.product))).join(", ") + (sql.length > 1 ? " (" + sql.length + ")" : "") : "",
        haystack: haystack,
      });
    });
    const sql = (d.sql || []).map((s) => Object.assign({}, s, {
      host: leaf(s.machine), supportRank: rank(s.support),
      esuLabel: s.support === "esu" ? "Enrolled" : s.esuEnabled ? "Enabled" : s.esu ? "Not enrolled" : "",
      haystack: [s.name, leaf(s.machine), s.product, s.edition, s.build, s.service, s.supportNote, s.subscription,
        s.resourceGroup].join(" ").toLowerCase(),
    }));
    const apps = (d.apps || []).map((a) => Object.assign({}, a, {
      supportRank: rank(a.support),
      haystack: [a.name, a.kind, a.runtime, a.stack, a.version, a.supportNote, a.subscription, a.resourceGroup, a.exposure]
        .join(" ").toLowerCase(),
    }));
    return { machines: machines, sql: sql, apps: apps };
  }

  async function load() {
    $("compute-status").textContent = "Loading the Compute view…";
    let response, body;
    try {
      response = await fetch("/api/compute", { credentials: "same-origin" });
      body = await response.json().catch(() => ({}));
    } catch (err) {
      $("compute-status").textContent = "Could not load the Compute view. Check your connection and reload the page.";
      return;
    }
    if (response.status === 401) { location.href = "/login?next=/compute"; return; }
    if (!response.ok) {
      $("compute-status").textContent = body.detail || "No Compute data yet - press Refresh inventory (about 5 minutes).";
      return;
    }
    data = body;
    rows = prepare(data);
    const collected = String(data.collected_at || "").slice(0, 16).replace("T", " ");
    $("compute-meta").textContent = collected ? "Collected " + collected + " UTC" : "";
    $("compute-status").textContent = (data.warnings || []).length
      ? "Some sources could not be read: " + data.warnings.join("; ") : "";
    renderSources();
    readUrl();
    fillFilters();
    render();
  }

  function renderSources() {
    const s = (data.summary || {}).sources || {};
    const total = (data.summary || {}).machines || 0;
    $("compute-sources").textContent = "Data sources: operating system reported by " + fmt(s.osReported) + " of " + fmt(total) +
      " machines (the image for the rest), Update Manager assessment on " + fmt(s.patchAssessment) +
      ", Defender package findings on " + fmt(s.defenderPackages) + ", CVE results on " + fmt(s.cveScan) +
      ", Change Tracking on " + fmt(s.changeTracking) + ". Installed software and running services need Change " +
      "Tracking (Azure Monitor agent); CVEs need a vulnerability scanner (Defender for Servers).";
  }

  // ---- filters -------------------------------------------------------------

  const FILTERS = ["q", "sub", "family", "support", "kind", "state", "exposure", "scanner", "env", "critical", "pending"];

  function readUrl() {
    const params = new URLSearchParams(location.search);
    if (["machines", "sql", "apps"].includes(params.get("view"))) state.view = params.get("view");
    FILTERS.forEach((k) => { if (params.get(k)) state.f[k] = params.get(k); });
  }

  function writeUrl() {
    const params = new URLSearchParams();
    if (state.view !== "machines") params.set("view", state.view);
    FILTERS.forEach((k) => { if (state.f[k]) params.set(k, state.f[k]); });
    const query = params.toString();
    history.replaceState(null, "", location.pathname + (query ? "?" + query : ""));
  }

  function options(select, values, allLabel, labelFn) {
    const current = state.f[select.id.slice(2)] || "";
    select.replaceChildren(el("option", { value: "" }, allLabel));
    values.forEach(([value, count]) => {
      const option = el("option", { value: value }, (labelFn ? labelFn(value) : value) + " (" + fmt(count) + ")");
      if (value === current) option.selected = true;
      select.appendChild(option);
    });
  }

  function countBy(list, fn) {
    const counts = new Map();
    list.forEach((r) => { const k = fn(r); if (k) counts.set(k, (counts.get(k) || 0) + 1); });
    return Array.from(counts.entries()).sort((a, b) => b[1] - a[1] || String(a[0]).localeCompare(String(b[0])));
  }

  function fillFilters() {
    const list = rows[state.view];
    options($("c-sub"), countBy(list, (r) => r.subscription), "All subscriptions");
    const familyKey = state.view === "machines" ? (r) => r.family || "Not identified"
      : state.view === "sql" ? (r) => r.product : (r) => r.stack;
    options($("c-family"), countBy(list, familyKey), state.view === "apps" ? "All runtimes" : "All products");
    options($("c-support"), countBy(list, (r) => r.support).sort((a, b) => rank(a[0]) - rank(b[0])), "Any support status",
      (v) => SUPPORT_LABELS[v] || v);
    options($("c-env"), countBy(rows.machines, (r) => r.env), "All environments");
    $("c-q").value = state.f.q || "";
    $("c-kind").value = state.f.kind || "";
    $("c-state").value = state.f.state || "";
    $("c-exposure").value = state.f.exposure || "";
    $("c-scanner").value = state.f.scanner || "";
    $("c-critical").checked = state.f.critical === "1";
    const machineOnly = state.view !== "machines";
    ["c-kind", "c-state", "c-exposure", "c-scanner", "c-env", "c-critical"].forEach((id) => { $(id).disabled = machineOnly; });
    document.querySelectorAll(".view-switch .tab").forEach((tab) => {
      const active = tab.dataset.view === state.view;
      tab.classList.toggle("active", active);
      tab.setAttribute("aria-pressed", active ? "true" : "false");
    });
  }

  function matches(r) {
    const f = state.f;
    if (f.q) {
      const terms = f.q.toLowerCase().split(/\s+/).filter(Boolean);
      if (!terms.every((t) => r.haystack.includes(t))) return false;
    }
    if (f.sub && r.subscription !== f.sub) return false;
    if (f.support && r.support !== f.support) return false;
    if (f.family) {
      const value = state.view === "machines" ? (r.family || "Not identified") : state.view === "sql" ? r.product : r.stack;
      if (value !== f.family) return false;
    }
    if (state.view === "machines") {
      if (f.kind && r.kind !== f.kind) return false;
      if (f.state === "running" && !r.running) return false;
      if (f.state === "idle" && r.running) return false;
      if (f.exposure === "public" && !(r.publicIp && r.running)) return false;
      if (f.exposure === "none" && r.publicIp) return false;
      if (f.scanner && r.scanner !== f.scanner) return false;
      if (f.env && r.env !== f.env) return false;
      if (f.critical === "1" && !r.criticalPath) return false;
      if (f.pending === "1" && !(r.updates > 0)) return false;
    }
    return true;
  }

  function setFilter(key, value, view) {
    if (view && view !== state.view) { state.view = view; state.sort = { key: "", dir: 1 }; }
    state.f[key] = value;
    state.page = 0;
    fillFilters();
    render();
  }

  // ---- rendering -----------------------------------------------------------

  function renderTiles() {
    const s = data.summary || {};
    const sup = s.support || {};
    const sql = s.sql || {};
    const apps = s.apps || {};
    const tiles = $("compute-tiles");
    tiles.replaceChildren();
    const tile = (value, label, note, onClick, active) => {
      const t = el("button", { type: "button", class: "tile" + (active ? " active" : "") });
      t.append(el("strong", null, fmt(value)), el("span", null, label));
      if (note) t.appendChild(el("em", null, note));
      t.addEventListener("click", onClick);
      tiles.appendChild(t);
    };
    const reset = (view, key, value) => () => { state.f = {}; setFilter(key, value, view); };
    tile(s.machines, "Machines", fmt(s.vms) + " VMs · " + fmt(s.arc) + " Arc", reset("machines", "q", ""),
      state.view === "machines" && !Object.values(state.f).some(Boolean));
    tile(sup.ended, "OS support ended", sup.esu ? fmt(sup.esu) + " on ESU" : "", reset("machines", "support", "ended"),
      state.view === "machines" && state.f.support === "ended");
    tile(sup.ending, "OS support ends ≤ 180 days", "", reset("machines", "support", "ending"),
      state.view === "machines" && state.f.support === "ending");
    tile(s.criticalPath, "Critical path", "internet-facing with a known weakness", reset("machines", "critical", "1"),
      state.f.critical === "1");
    tile(s.noScanner, "Running without a scanner", fmt(s.noScannerExposed) + " internet-facing",
      reset("machines", "scanner", "none"), state.view === "machines" && state.f.scanner === "none");
    tile(s.pendingSecurity, "Security updates pending", "Update Manager assessment", reset("machines", "pending", "1"),
      state.f.pending === "1");
    tile(s.arcStale, "Arc agent disconnected / expired", "inventory may be stale", () => { state.f = {}; state.f.kind = "arc"; setFilter("state", "idle", "machines"); },
      state.view === "machines" && state.f.kind === "arc" && state.f.state === "idle");
    tile(sql.ended, "SQL Server past end of support", fmt(sql.instances) + " instances", reset("sql", "support", "ended"),
      state.view === "sql" && state.f.support === "ended");
    tile(apps.ended, "App runtimes past end of support", fmt(apps.total) + " apps · " + fmt(apps.ending) + " ending",
      reset("apps", "support", "ended"), state.view === "apps" && state.f.support === "ended");
  }

  function supportCell(r) {
    const td = el("td");
    td.appendChild(el("span", { class: "pill " + (SUPPORT_PILL[r.support] || "sev-info"), title: r.supportNote || "" },
      SUPPORT_LABELS[r.support] || r.support));
    return td;
  }

  function header(columns) {
    const tr = el("tr");
    columns.forEach((c) => {
      const th = el("th", { class: "sortable" + (c.num ? " num" : ""), scope: "col" });
      const key = c.sortKey || c.key;
      const arrow = state.sort.key === key ? (state.sort.dir > 0 ? " ▲" : " ▼") : "";
      const button = el("button", { type: "button", class: "sort" }, c.label + arrow);
      button.addEventListener("click", () => {
        state.sort = { key: key, dir: state.sort.key === key ? -state.sort.dir : (c.num ? -1 : 1) };
        render();
      });
      th.appendChild(button);
      tr.appendChild(th);
    });
    return tr;
  }

  function detailList(title, items, more) {
    if (!items || !items.length) return null;
    const box = el("div");
    box.appendChild(el("strong", null, title));
    const ul = el("ul", { class: "suggestions" });
    items.forEach((i) => ul.appendChild(el("li", null, i)));
    if (more) ul.appendChild(el("li", { class: "muted" }, "… and " + fmt(more) + " more"));
    box.appendChild(ul);
    return box;
  }

  function machineDetail(m, span) {
    const td = el("td", { colspan: span });
    const facts = [
      "Support: " + (m.supportNote || "-"),
      "OS source: " + (m.osSource === "machine" ? "reported by the machine (" + m.osReported + ")" : m.osSource === "image" ? "marketplace image " + m.image : "unknown"),
      "Vulnerability scanner: " + (m.scannerNote || "-"),
      "Defender for Servers: " + (m.defenderPlan || "not configured"),
      "Agents / extensions: " + ((m.agents || []).join(", ") || "none visible"),
    ];
    if (m.kind === "arc") facts.push("Arc agent: " + m.state + (m.lastSeen ? " since " + String(m.lastSeen).slice(0, 10) : "") + (m.esu ? " · ESU licence: " + m.esu : ""));
    if (m.patches) facts.push("Update Manager: " + fmt(m.patches.security) + " security, " + fmt(m.patches.critical) + " critical, " + fmt(m.patches.other) + " other update(s) pending" + (m.patches.reboot ? " · reboot pending" : "") + (m.patches.assessed ? " · assessed " + String(m.patches.assessed).slice(0, 10) : ""));
    else facts.push("Update Manager: no assessment" + (m.patchAssessment ? " (assessment mode " + m.patchAssessment + ")" : " - turn on periodic assessment to see missing updates"));
    const ul = el("ul", { class: "suggestions" });
    facts.forEach((f) => ul.appendChild(el("li", null, f)));
    (m.reasons || []).forEach((r) => ul.appendChild(el("li", { class: "low-util" }, r)));
    td.appendChild(ul);
    [detailList("Pending security / critical updates", (m.patches || {}).names, (m.patches || {}).more),
      detailList("Packages Defender reports as outdated", (m.packages || {}).names, (m.packages || {}).more),
      detailList("CVEs (critical / high first)", ((m.cves || {}).ids || []).slice(0, 40), Math.max(0, ((m.cves || {}).count || 0) - 40)),
      detailList("SQL Server instances", (m.sql || []).map((s) => s.name + " - " + s.product + (s.edition ? " " + s.edition : "") + (s.build ? " (" + s.build + ")" : "") + ": " + s.supportNote)),
    ].forEach((box) => { if (box) td.appendChild(box); });
    td.appendChild(el("div", { class: "muted small" }, m.id));
    return td;
  }

  function cell(r, c) {
    if (c.key === "support") return supportCell(r);
    const value = r[c.key];
    if (c.num) return el("td", { class: "num" }, value === null || value === undefined ? "–" : fmt(value));
    return el("td", null, value === null || value === undefined ? "" : value);
  }

  function sorted(list) {
    const { key, dir } = state.sort;
    if (!key) {
      return list.slice().sort((a, b) => (state.view === "machines" ? (b.criticalPath ? 1 : 0) - (a.criticalPath ? 1 : 0) : 0)
        || a.supportRank - b.supportRank || String(a.name).localeCompare(String(b.name)));
    }
    return list.slice().sort((a, b) => {
      const x = a[key], y = b[key];
      if (x === y) return 0;
      if (x === null || x === undefined || x === "") return 1;
      if (y === null || y === undefined || y === "") return -1;
      return (typeof x === "number" && typeof y === "number" ? x - y : String(x).localeCompare(String(y))) * dir;
    });
  }

  function hint() {
    const q = (state.f.q || "").trim();
    const hasCves = rows.machines.some((m) => m.cves);
    if (/cve-\d{4}-\d+/i.test(q) && !hasCves) {
      return "No machine reports CVE results to Azure - none has a vulnerability scanner that does (Defender for Servers " +
        "with vulnerability assessment). A CVE ID cannot be matched; search the affected product and version instead " +
        "(for example php, openssl 3.0, nginx).";
    }
    if (q) return "Matches name, operating system and version, image, agents, pending update names, outdated package names, CVE IDs and SQL Server versions; App runtimes also match the runtime and version.";
    return "Tip: search a product and version (php, openssl, Windows Server 2016, SQL Server 2016) to find every machine, SQL instance or app that runs it.";
  }

  function render() {
    renderTiles();
    writeUrl();
    $("c-hint").textContent = hint();
    const columns = COLUMNS[state.view];
    const list = sorted(rows[state.view].filter(matches));
    lastRows = list;
    const pages = Math.max(1, Math.ceil(list.length / PAGE_SIZE));
    state.page = Math.min(state.page, pages - 1);
    const slice = list.slice(state.page * PAGE_SIZE, (state.page + 1) * PAGE_SIZE);
    $("c-title").textContent = TITLES[state.view];
    $("c-count").textContent = fmt(list.length) + " of " + fmt(rows[state.view].length);
    $("c-page").textContent = "Page " + (state.page + 1) + " of " + pages;
    $("c-prev").disabled = state.page === 0;
    $("c-next").disabled = state.page >= pages - 1;
    const table = $("c-results");
    table.querySelector("thead").replaceChildren(header(columns));
    const tbody = table.querySelector("tbody");
    tbody.replaceChildren();
    if (!slice.length) {
      const tr = el("tr");
      tr.appendChild(el("td", { colspan: columns.length, class: "empty-state" }, "Nothing matches these filters."));
      tbody.appendChild(tr);
      return;
    }
    slice.forEach((r) => {
      const tr = el("tr", state.view === "machines" ? { class: "clickable", tabindex: "0", "aria-expanded": state.open.has(r.id) ? "true" : "false" } : null);
      columns.forEach((c) => tr.appendChild(cell(r, c)));
      tbody.appendChild(tr);
      if (state.view !== "machines") return;
      const toggle = () => { if (state.open.has(r.id)) state.open.delete(r.id); else state.open.add(r.id); render(); };
      tr.addEventListener("click", toggle);
      tr.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); toggle(); } });
      if (state.open.has(r.id)) {
        const detail = el("tr", { class: "detail" });
        detail.appendChild(machineDetail(r, columns.length));
        tbody.appendChild(detail);
      }
    });
  }

  function csv() {
    const columns = {
      machines: ["name", "kindLabel", "os", "osReported", "image", "family", "support", "supportEnds", "supportNote", "esu",
        "exposureLabel", "scannerLabel", "scannerNote", "defenderPlan", "updates", "outdated", "cveCount", "sqlLabel",
        "criticalPath", "state", "env", "subscription", "resourceGroup", "location", "id"],
      sql: ["name", "host", "product", "edition", "build", "service", "support", "supportEnds", "supportNote", "esuLabel",
        "status", "license", "subscription", "resourceGroup", "id"],
      apps: ["name", "kind", "runtime", "support", "supportEnds", "supportNote", "exposure", "state", "subscription",
        "resourceGroup", "id"],
    }[state.view];
    const escape = (v) => {
      let text = v === undefined || v === null ? "" : String(v);
      if (/^[=+\-@]/.test(text)) text = "'" + text; // no formula injection when opened in Excel
      return /[",\n;]/.test(text) ? '"' + text.replace(/"/g, '""') + '"' : text;
    };
    const lines = [columns.join(",")].concat(lastRows.map((r) => columns.map((c) => escape(r[c])).join(",")));
    const blob = new Blob(["﻿" + lines.join("\r\n")], { type: "text/csv;charset=utf-8" });
    const a = el("a", { href: URL.createObjectURL(blob), download: "compute-" + state.view + ".csv" });
    document.body.appendChild(a);
    a.click();
    setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 1000);
  }

  // ---- refresh (the estate refresh collects this view) ------------------------

  async function refresh() {
    const button = $("compute-refresh");
    button.disabled = true;
    $("compute-status").textContent = "Refreshing the estate inventory for all enabled subscriptions - about 5 minutes…";
    try {
      const response = await fetch("/api/estate/refresh", { method: "POST", credentials: "same-origin",
        headers: { "Content-Type": "application/json" }, body: "{}" });
      const started = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(started.detail || response.statusText);
      for (;;) {
        await new Promise((r) => setTimeout(r, 3000));
        const statusResponse = await fetch("/api/estate/status", { credentials: "same-origin" });
        if (statusResponse.status === 401) { location.href = "/login?next=/compute"; return; }
        if (!statusResponse.ok) throw new Error("Status request failed (" + statusResponse.status + ")");
        const status = await statusResponse.json();
        if (!status.running) { if (status.error) throw new Error(status.error); break; }
      }
      await load();
    } catch (err) {
      $("compute-status").textContent = "Refresh failed: " + err.message;
    } finally {
      button.disabled = false;
    }
  }

  // ---- wiring ----------------------------------------------------------------

  document.querySelectorAll(".view-switch .tab").forEach((tab) => tab.addEventListener("click", () => {
    if (!data) return;
    state.view = tab.dataset.view;
    state.sort = { key: "", dir: 1 };
    state.page = 0;
    ["family", "support"].forEach((k) => { delete state.f[k]; });
    fillFilters();
    render();
  }));
  let typing = null;
  $("c-q").addEventListener("input", () => {
    clearTimeout(typing);
    typing = setTimeout(() => setFilter("q", $("c-q").value.trim()), 200);
  });
  [["c-sub", "sub"], ["c-family", "family"], ["c-support", "support"], ["c-kind", "kind"], ["c-state", "state"],
    ["c-exposure", "exposure"], ["c-scanner", "scanner"], ["c-env", "env"]].forEach(([id, key]) => {
    $(id).addEventListener("change", () => { if (data) setFilter(key, $(id).value); });
  });
  $("c-critical").addEventListener("change", () => { if (data) setFilter("critical", $("c-critical").checked ? "1" : ""); });
  $("c-clear").addEventListener("click", () => { if (!data) return; state.f = {}; state.page = 0; fillFilters(); render(); });
  $("c-csv").addEventListener("click", () => { if (data) csv(); });
  $("c-prev").addEventListener("click", () => { state.page -= 1; render(); });
  $("c-next").addEventListener("click", () => { state.page += 1; render(); });
  $("compute-refresh").addEventListener("click", refresh);
  load();
})();
