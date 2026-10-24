// ARG local portal - Compute: operating system versions, end of support, vulnerability-scan coverage, pending
// security updates, outdated packages, CVEs, SQL Server instances, App Service runtimes and containers (compute.json).
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
      { key: "exposure", label: "Network exposure" }, { key: "urlLabel", label: "Hostname" }, { key: "state", label: "State" },
      { key: "subscription", label: "Subscription" }, { key: "resourceGroup", label: "Resource group" },
    ],
    images: [
      { key: "name", label: "Workload / container" }, { key: "kind", label: "Runs in" }, { key: "image", label: "Image" },
      { key: "registryLabel", label: "Registry" }, { key: "exposure", label: "Network exposure" },
      { key: "scan", label: "Defender scan" }, { key: "packageCount", label: "Outdated packages", num: true },
      { key: "high", label: "High", num: true }, { key: "state", label: "State" },
      { key: "subscription", label: "Subscription" }, { key: "resourceGroup", label: "Resource group" },
    ],
  };
  const TITLES = { machines: "Machines", sql: "SQL Server instances", apps: "App Service runtimes", images: "Containers" };
  const EXPANDS = ["machines", "images"];
  const urlLabel = (urls) => (urls && urls.length ? urls[0].replace(/^https:\/\//, "") + (urls.length > 1 ? " (+" + (urls.length - 1) + ")" : "") : "");

  let data = null;
  let rows = { machines: [], sql: [], apps: [], images: [] };
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
      supportRank: rank(a.support), urlLabel: urlLabel(a.urls),
      haystack: [a.name, a.kind, a.runtime, a.stack, a.version, a.supportNote, a.subscription, a.resourceGroup, a.exposure,
        (a.urls || []).join(" ")].join(" ").toLowerCase(),
    }));
    const images = (d.images || []).map((i) => Object.assign({}, i, {
      packageCount: (i.packages || []).length || null, high: i.high || null,
      haystack: [i.name, i.kind, i.image, i.registry, i.registryLabel, i.tag, i.exposure, i.scan, i.url,
        (i.packages || []).join(" "), i.subscription, i.resourceGroup].join(" ").toLowerCase(),
    }));
    return { machines: machines, sql: sql, apps: apps, images: images };
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
    if (["machines", "sql", "apps", "images", "cve"].includes(params.get("view"))) state.view = params.get("view");
    if (params.get("cve")) state.cve = params.get("cve");
    FILTERS.forEach((k) => { if (params.get(k)) state.f[k] = params.get(k); });
  }

  function writeUrl() {
    const params = new URLSearchParams();
    if (state.view !== "machines") params.set("view", state.view);
    FILTERS.forEach((k) => { if (state.f[k]) params.set(k, state.f[k]); });
    if (state.view === "cve" && state.cve) params.set("cve", state.cve);
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
    const list = rows[state.view] || rows.machines;
    options($("c-sub"), countBy(list, (r) => r.subscription), "All subscriptions");
    const images = state.view === "images";
    options($("c-family"), countBy(list, familyOf), state.view === "apps" ? "All runtimes" : images ? "All registries" : "All products");
    if (images) options($("c-support"), countBy(list, (r) => r.scan), "Any Defender scan status");
    else options($("c-support"), countBy(list, (r) => r.support).sort((a, b) => rank(a[0]) - rank(b[0])), "Any support status",
      (v) => SUPPORT_LABELS[v] || v);
    options($("c-env"), countBy(rows.machines, (r) => r.env), "All environments");
    $("c-q").value = state.f.q || "";
    $("c-kind").value = state.f.kind || "";
    $("c-state").value = state.f.state || "";
    $("c-exposure").value = state.f.exposure || "";
    $("c-scanner").value = state.f.scanner || "";
    $("c-critical").checked = state.f.critical === "1";
    const machineOnly = state.view !== "machines";
    ["c-kind", "c-scanner", "c-env", "c-critical"].forEach((id) => { $(id).disabled = machineOnly; });
    ["c-state", "c-exposure"].forEach((id) => { $(id).disabled = machineOnly && !images; });
    const label = (id, text) => { const node = $(id).parentNode.firstChild; if (node && node.nodeType === 3) node.textContent = text + " "; };
    label("c-family", state.view === "apps" ? "Runtime" : images ? "Registry" : "OS family / product");
    label("c-support", images ? "Defender scan" : "Support");
    const exposureText = images ? ["Any", "Internet-facing", "Not internet-facing"] : ["Any", "Public IP (running)", "No public IP"];
    Array.from($("c-exposure").options).forEach((o, i) => { o.textContent = exposureText[i] || o.textContent; });
    document.querySelectorAll(".view-switch .tab").forEach((tab) => {
      const active = tab.dataset.view === state.view;
      tab.classList.toggle("active", active);
      tab.setAttribute("aria-pressed", active ? "true" : "false");
    });
  }

  function familyOf(r) {
    return state.view === "machines" ? r.family || "Not identified" : state.view === "sql" ? r.product
      : state.view === "images" ? r.registryLabel : r.stack;
  }

  function matches(r) {
    const f = state.f;
    if (f.q) {
      const terms = f.q.toLowerCase().split(/\s+/).filter(Boolean);
      if (!terms.every((t) => r.haystack.includes(t))) return false;
    }
    if (f.sub && r.subscription !== f.sub) return false;
    if (f.support && (state.view === "images" ? r.scan : r.support) !== f.support) return false;
    if (f.family && familyOf(r) !== f.family) return false;
    if (state.view === "images") {
      if (f.state === "running" && !r.running) return false;
      if (f.state === "idle" && r.running) return false;
      if (f.exposure === "public" && !r.exposed) return false;
      if (f.exposure === "none" && r.exposed) return false;
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
    const images = s.images || {};
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
    if (images.total) {
      tile(images.exposed, "Internet-facing containers", fmt(images.total) + " containers · " + fmt(images.distinct) + " images",
        reset("images", "exposure", "public"), state.view === "images" && state.f.exposure === "public");
      tile(images.withFindings, "Containers with outdated packages", "Defender, images in Azure Container Registry",
        reset("images", "support", "outdated packages"), state.view === "images" && state.f.support === "outdated packages");
    }
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

  function imageDetail(i, span) {
    const td = el("td", { colspan: span });
    const ul = el("ul", { class: "suggestions" });
    [
      "Image: " + i.image + (i.digest ? " (pinned to " + i.digest.slice(0, 19) + "…)" : ""),
      "Registry: " + i.registryLabel + (i.registry !== i.registryLabel ? " (" + i.registry + ")" : ""),
      "Network exposure: " + i.exposure + (i.url ? " · " + i.url : ""),
      "Defender scan: " + i.scan + ({
        "no Defender findings": " - up to date, or not scanned: Defender for Containers / CSPM scans images in Azure Container Registry and reports only outdated packages",
        "not in Azure Container Registry": " - Defender does not scan this registry; pull it through Azure Container Registry to get it scanned",
        "no findings for this tag": " - other tags of this repository have findings, this one has none",
      }[i.scan] || ""),
      "State: " + (i.state || "-"),
    ].forEach((f) => ul.appendChild(el("li", null, f)));
    td.appendChild(ul);
    const box = detailList("Packages Defender reports as outdated", i.packages);
    if (box) td.appendChild(box);
    td.appendChild(el("div", { class: "muted small" }, i.id));
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
        || (state.view === "images" ? (b.exposed ? 1 : 0) - (a.exposed ? 1 : 0) || (b.packageCount || 0) - (a.packageCount || 0) : 0)
        || (a.supportRank || 0) - (b.supportRank || 0) || String(a.name).localeCompare(String(b.name)));
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
    if (q && state.view === "images") return "Matches workload, container, image, registry, tag, exposure, Defender scan status and outdated package names.";
    if (q) return "Matches name, operating system and version, image, agents, pending update names, outdated package names, CVE IDs and SQL Server versions; App runtimes also match the runtime, version and hostnames.";
    return "Tip: search a product and version (php, openssl, Windows Server 2016, SQL Server 2016) to find every machine, SQL instance or app that runs it.";
  }

  // ---- CVE check (/api/cve/<id>, /api/cve/kev - scripts/subscription_analysis/cve.py) ---------------------------

  const VERDICT_PILL = { "impacted": "sev-critical", "potentially impacted": "sev-high", "not affected": "sev-low" };
  let kevFor = null;
  let lastCve = null;

  async function getJson(url) {
    const response = await fetch(url, { credentials: "same-origin" });
    if (response.status === 401) { location.href = "/login?next=/compute"; throw new Error("signed out"); }
    const body = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(body.detail || response.statusText);
    return body;
  }

  async function loadKev() {
    const days = $("kev-days").value;
    if (kevFor === days) return;
    kevFor = days;
    $("kev-status").textContent = "Loading the CISA catalog…";
    const table = $("kev-table");
    let data;
    try {
      data = await getJson("/api/cve/kev?days=" + encodeURIComponent(days));
    } catch (err) {
      $("kev-status").textContent = err.message;
      kevFor = null;
      return;
    }
    $("kev-status").textContent = fmt(data.rows.length) + " of the " + fmt(data.total) + " known-exploited CVEs (catalog " +
      (data.catalogVersion || "?") + ") were added in this period and concern products this estate runs. KEV names the " +
      "product, not the versions - Check compares the versions.";
    const head = el("tr");
    ["Added", "CVE", "Vendor / product", "Vulnerability", "Resources", "Internet-facing", "Ransomware", "Due", ""]
      .forEach((h) => head.appendChild(el("th", { scope: "col" }, h)));
    table.querySelector("thead").replaceChildren(head);
    const body = table.querySelector("tbody");
    body.replaceChildren();
    data.rows.forEach((r) => {
      const tr = el("tr");
      const go = el("button", { type: "button", class: "secondary" }, "Check");
      go.addEventListener("click", () => { $("cve-id").value = r.cve; runCve(r.cve); });
      tr.append(el("td", null, r.dateAdded), el("td", null, r.cve), el("td", null, r.vendor + " / " + r.product),
        el("td", { title: r.description || "" }, r.name), el("td", { class: "num" }, fmt(r.resources) + " (" + r.kinds.join(", ") + ")"),
        el("td", { class: "num" }, fmt(r.exposed)), el("td", null, r.ransomware), el("td", null, r.dueDate));
      const td = el("td");
      td.appendChild(go);
      tr.appendChild(td);
      body.appendChild(tr);
    });
    if (!data.rows.length) {
      const tr = el("tr");
      tr.appendChild(el("td", { colspan: "9", class: "empty-state" }, "No known-exploited CVE of this period concerns a product this estate runs."));
      body.appendChild(tr);
    }
  }

  async function runCve(id) {
    const cveId = String(id || "").trim().toUpperCase();
    if (!/^CVE-\d{4}-\d{4,7}$/.test(cveId)) { $("cve-status").textContent = "Enter a CVE ID like CVE-2024-3094."; return; }
    state.cve = cveId;
    writeUrl();
    $("cve-status").textContent = "Looking up " + cveId + " in NVD…";
    $("cve-result").replaceChildren();
    $("cve-csv").disabled = true;
    let res;
    try {
      res = await getJson("/api/cve/" + encodeURIComponent(cveId));
    } catch (err) {
      $("cve-status").textContent = err.message;
      return;
    }
    lastCve = res;
    $("cve-status").textContent = "";
    renderCve(res);
  }

  function renderCve(res) {
    const box = $("cve-result");
    box.replaceChildren();
    const card = el("div", { class: "card breakdown cve-card" });
    const head = el("div", { class: "toolbar" });
    head.appendChild(el("h3", null, res.cve));
    if (res.severity) head.appendChild(el("span", { class: "pill " + ({ CRITICAL: "sev-critical", HIGH: "sev-high", MEDIUM: "sev-medium" }[res.severity] || "sev-low") },
      res.severity.toLowerCase() + (res.score ? " " + res.score : "")));
    if (res.kev) head.appendChild(el("span", { class: "pill sev-critical", title: res.kev.requiredAction || "" },
      "exploited in the wild (KEV, added " + res.kev.dateAdded + ")"));
    card.appendChild(head);
    if (!res.found) {
      card.appendChild(el("p", null, res.note));
      box.appendChild(card);
      return;
    }
    card.appendChild(el("p", { class: "small muted" }, "NVD status " + (res.status || "?") + " · published " +
      String(res.published || "").slice(0, 10) + (res.products.length ? " · affects " + res.products.slice(0, 8).join(", ") +
      (res.products.length > 8 ? " …" : "") : "")));
    card.appendChild(el("p", null, res.description));
    if (res.kev) card.appendChild(el("p", { class: "small" }, "CISA: " + (res.kev.requiredAction || "") + " Due " + res.kev.dueDate + "."));
    if (res.note) card.appendChild(el("p", { class: "small low-util" }, res.note));
    const counts = el("div", { class: "tree-row" });
    [["impacted", "sev-critical"], ["potentially impacted", "sev-high"], ["not affected", "sev-low"]].forEach(([k, cls]) =>
      counts.appendChild(el("span", { class: "pill " + cls }, fmt((res.counts || {})[k] || 0) + " " + k)));
    card.appendChild(counts);
    box.appendChild(card);
    if (!res.results.length) {
      box.appendChild(el("p", { class: "muted" }, "Nothing in this inventory runs an affected product."));
      return;
    }
    const wrap = el("div", { class: "table-wrap" });
    const table = el("table", { class: "estate" });
    const headRow = el("tr");
    ["Verdict", "Resource", "Kind", "Product / version", "Why", "Fixed in", "Internet-facing", "URL", "Subscription"]
      .forEach((h) => headRow.appendChild(el("th", { scope: "col" }, h)));
    table.appendChild(el("thead")).appendChild(headRow);
    const body = el("tbody");
    res.results.forEach((r) => {
      const tr = el("tr");
      const verdict = el("td");
      verdict.appendChild(el("span", { class: "pill " + (VERDICT_PILL[r.verdict] || "sev-info") }, r.verdict));
      tr.append(verdict, el("td", { title: r.id }, r.name), el("td", null, r.kind),
        el("td", null, r.label + (r.version && !String(r.label).includes(r.version) ? " · " + r.version : "")),
        el("td", null, r.reason), el("td", null, r.fixed || ""), el("td", null, r.exposed ? "yes" : ""));
      const url = el("td", { title: (r.urls || []).join("\n") });
      if ((r.urls || []).length) url.appendChild(el("a", { href: r.urls[0], target: "_blank", rel: "noopener noreferrer" }, urlLabel(r.urls)));
      tr.append(url, el("td", null, r.subscription || ""));
      body.appendChild(tr);
    });
    table.appendChild(body);
    wrap.appendChild(table);
    box.appendChild(wrap);
    $("cve-csv").disabled = false;
  }

  function cveCsv() {
    if (!lastCve || !lastCve.results) return;
    const columns = ["verdict", "name", "kind", "label", "version", "reason", "fixed", "exposed", "urls", "subscription", "id"];
    const escape = (v) => {
      let text = v === undefined || v === null ? "" : String(v);
      if (/^[=+\-@]/.test(text)) text = "'" + text; // no formula injection when opened in Excel
      return /[",\n;]/.test(text) ? '"' + text.replace(/"/g, '""') + '"' : text;
    };
    const value = (r, c) => (Array.isArray(r[c]) ? r[c].join(" ") : r[c]);
    const lines = [columns.join(",")].concat(lastCve.results.map((r) => columns.map((c) => escape(value(r, c))).join(",")));
    const blob = new Blob(["\ufeff" + lines.join("\r\n")], { type: "text/csv;charset=utf-8" });
    const a = el("a", { href: URL.createObjectURL(blob), download: lastCve.cve + "-impact.csv" });
    document.body.appendChild(a);
    a.click();
    setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 1000);
  }

  function render() {
    renderTiles();
    writeUrl();
    const isCve = state.view === "cve";
    $("cve-panel").hidden = !isCve;
    $("c-table-card").hidden = isCve;
    document.querySelector("#c-filters .filter-grid").hidden = isCve;
    $("c-hint").hidden = isCve;
    if (isCve) {
      loadKev();
      if (state.cve && (!lastCve || lastCve.cve !== state.cve)) { $("cve-id").value = state.cve; runCve(state.cve); }
      return;
    }
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
    const expands = EXPANDS.includes(state.view);
    slice.forEach((r) => {
      const key = state.view === "images" ? r.id + "|" + r.name : r.id;
      const tr = el("tr", expands ? { class: "clickable", tabindex: "0", "aria-expanded": state.open.has(key) ? "true" : "false" } : null);
      columns.forEach((c) => tr.appendChild(cell(r, c)));
      tbody.appendChild(tr);
      if (!expands) return;
      const toggle = () => { if (state.open.has(key)) state.open.delete(key); else state.open.add(key); render(); };
      tr.addEventListener("click", toggle);
      tr.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); toggle(); } });
      if (state.open.has(key)) {
        const detail = el("tr", { class: "detail" });
        detail.appendChild(state.view === "images" ? imageDetail(r, columns.length) : machineDetail(r, columns.length));
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
      apps: ["name", "kind", "runtime", "support", "supportEnds", "supportNote", "exposure", "urls", "state", "subscription",
        "resourceGroup", "id"],
      images: ["name", "workload", "kind", "image", "registry", "repository", "tag", "digest", "exposure", "url", "scan",
        "packages", "high", "state", "subscription", "resourceGroup", "id"],
    }[state.view];
    const escape = (v) => {
      let text = v === undefined || v === null ? "" : String(v);
      if (/^[=+\-@]/.test(text)) text = "'" + text; // no formula injection when opened in Excel
      return /[",\n;]/.test(text) ? '"' + text.replace(/"/g, '""') + '"' : text;
    };
    const value = (r, c) => (Array.isArray(r[c]) ? r[c].join(" ") : r[c]);
    const lines = [columns.join(",")].concat(lastRows.map((r) => columns.map((c) => escape(value(r, c))).join(",")));
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
  $("cve-form").addEventListener("submit", (e) => { e.preventDefault(); if (data) runCve($("cve-id").value); });
  $("kev-days").addEventListener("change", () => { if (data) loadKev(); });
  $("cve-csv").addEventListener("click", cveCsv);
  load();
})();
