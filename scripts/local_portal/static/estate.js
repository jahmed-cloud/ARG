// ARG local portal - Estate inventory: filter, group and drill into every resource and suggestion.
// All data is rendered with textContent / DOM nodes (never innerHTML); no inline scripts (CSP: script-src 'self').
(function () {
  "use strict";

  const PAGE_SIZE = 100;
  const SEVERITIES = ["critical", "high", "medium", "low", "info"];
  const FILTER_KEYS = ["q", "category", "type", "size", "sub", "region", "env", "state", "has", "stype", "sev", "hyg", "ext", "cpu"];
  const RESOURCE_COLUMNS = [
    { key: "name", label: "Name" }, { key: "typeLabel", label: "Type" }, { key: "size", label: "Size / SKU" },
    { key: "vcpu", label: "vCPU", num: true, compute: true }, { key: "ramGB", label: "RAM (GB)", num: true, compute: true },
    { key: "cpuAvg", label: "CPU avg 30 d", num: true, compute: true, pct: true },
    { key: "memAvg", label: "Memory avg 30 d", num: true, compute: true, pct: true },
    { key: "config", label: "Configuration" }, { key: "os", label: "OS / runtime" }, { key: "state", label: "State" },
    { key: "env", label: "Environment" }, { key: "location", label: "Region" }, { key: "subscription", label: "Subscription" },
    { key: "resourceGroup", label: "Resource group" }, { key: "cost30", label: "Last 30 d", num: true },
    { key: "suggestions", label: "Suggestions", num: true },
  ];
  const CPU_BANDS = [[5, "under 5 %"], [20, "5-20 %"], [50, "20-50 %"], [80, "50-80 %"], [101, "80 % and more"]];
  const cpuBand = (v) => (v === null || v === undefined ? "no data" : CPU_BANDS.find(([limit]) => v < limit)[1]);
  const hasCompute = (r) => r.type === "microsoft.compute/virtualmachines" || r.type === "microsoft.compute/virtualmachinescalesets";
  const SUGGESTION_COLUMNS = [
    { key: "severity", label: "Severity" }, { key: "title", label: "Suggestion" }, { key: "type", label: "Suggestion type" },
    { key: "resourceName", label: "Resource" }, { key: "typeLabel", label: "Resource type" },
    { key: "subscription", label: "Subscription" }, { key: "savingsUsd", label: "Est. saving / month (USD)", num: true },
    { key: "wave", label: "Wave", num: true },
  ];

  let estate = null;
  let byResource = new Map();
  const subs = new Map();
  const state = { view: "resources", f: {}, sort: { key: "", dir: 1 }, page: 0 };

  const $ = (id) => document.getElementById(id);
  function el(tag, attrs, text) {
    const node = document.createElement(tag);
    Object.entries(attrs || {}).forEach(([k, v]) => { if (v !== undefined && v !== null) node.setAttribute(k, v); });
    if (text !== undefined && text !== null) node.textContent = String(text);
    return node;
  }
  const fmt = (n) => (n === undefined || n === null || n === "" ? "" : Number(n).toLocaleString(undefined, { maximumFractionDigits: 0 }));
  const sevRank = (s) => { const i = SEVERITIES.indexOf(s); return i < 0 ? 9 : i; };

  // ---- data ----------------------------------------------------------------

  // estate.json (format 2) lists subscriptions and types once; rows reference them by index.
  function expand(data) {
    const subsList = data.subscriptions || [];
    const types = data.types || {};
    const resources = (data.resources || []).map((r) => {
      const sub = subsList[r.s] || {};
      const t = types[r.type] || {};
      return {
        id: r.id, name: r.name, type: r.type, typeLabel: t.label || r.type, category: t.category || "Other",
        subscriptionId: sub.id || "", subscription: sub.name || sub.id || "", folder: sub.folder || "",
        resourceGroup: r.rg || "", location: r.loc || "", kind: r.kind || "", size: r.size || "", config: r.cfg || "",
        os: r.os || "",
        state: r.state || "", env: r.env || "Unknown", managedBy: r.mb || "", sizeGB: r.gb || null, tags: r.tags || {},
        cost30: r.cost || 0, currency: r.cur || "", suggestions: r.n || 0, hygiene: r.h || 0, maxSeverity: r.sev || "",
        vcpu: r.vcpu || null, ramGB: r.ram || null, cpuAvg: r.cpu === undefined ? null : r.cpu,
        cpuMax: r.cpuMax === undefined ? null : r.cpuMax, memAvg: r.mem === undefined ? null : r.mem, subResource: !!r.sub,
      };
    });
    const suggestions = (data.suggestions || []).map((s) => {
      const sub = subsList[s.s] || {};
      const r = s.r === undefined || s.r === null ? null : resources[s.r];
      const report = sub.folder ? "/reports/" + sub.folder : "/reports";
      return {
        ref: s.ref || "", title: s.title || "", severity: s.sev || "info", type: s.type || "", wave: s.wave || "",
        hygiene: !!s.hy,
        savingsUsd: s.usd || 0, subscriptionId: sub.id || "", subscription: sub.name || sub.id || "",
        resourceId: r ? r.id : "", resourceName: r ? r.name : (s.name || "(subscription)"),
        category: r ? r.category : "Subscription", typeLabel: r ? r.typeLabel : "Subscription",
        link: report + (s.af ? "/05-deep-dive/" + s.af + "/README.md" : "/README.md"),
      };
    });
    return { generated_at: data.generated_at, inventory_at: data.inventory_at, source: data.source,
      subscriptions: subsList, resources: resources, suggestions: suggestions };
  }

  async function load() {
    $("estate-status").textContent = "Loading estate…";
    const response = await fetch("/api/estate", { credentials: "same-origin" });
    if (response.status === 401) { location.href = "/login?next=/estate"; return; }
    if (!response.ok) { $("estate-status").textContent = "Could not load the estate: " + response.statusText; return; }
    estate = expand(await response.json());
    _index = null;
    subs.clear();
    estate.subscriptions.forEach((s) => subs.set(s.id, s));
    byResource = new Map();
    estate.suggestions.forEach((s) => {
      if (!s.resourceId) return;
      const key = s.resourceId.toLowerCase();
      if (!byResource.has(key)) byResource.set(key, []);
      byResource.get(key).push(s);
    });
    estate.resources.forEach((r) => {
      r._key = r.id.toLowerCase();
      const tags = Object.entries(r.tags || {}).map(([k, v]) => k + "=" + v).join(" ");
      r._text = [r.name, r.resourceGroup, r.typeLabel, r.size, r.config, r.os, r.state, r.kind, r.subscription, tags].join(" ").toLowerCase();
    });
    const source = estate.source === "resource-graph"
      ? "live Resource Graph inventory from " + String(estate.inventory_at || "").slice(0, 16).replace("T", " ") + " UTC"
      : "inventory from the subscription reports - click Refresh inventory for a live, complete one";
    $("estate-meta").textContent = fmt(estate.resources.length) + " resources · " + estate.subscriptions.length +
      " subscriptions · " + fmt(estate.suggestions.length) + " suggestions";
    $("estate-status").textContent = "Source: " + source + ". Suggestions and cost come from the latest subscription reports.";
    readHash();
    render();
  }

  // ---- filtering -----------------------------------------------------------

  // VM / Arc extensions and license profiles sit on a machine; hidden unless ticked or their type is picked.
  const shownByDefault = (r, f) => !r.subResource || !!f.ext || (f.type && f.type === r.typeLabel);

  function resourceMatches(r, f, skip) {
    if (!shownByDefault(r, f)) return false;
    if (f.q && skip !== "q" && !r._text.includes(f.q.toLowerCase())) return false;
    if (f.cpu && skip !== "cpu" && (!hasCompute(r) || cpuBand(r.cpuAvg) !== f.cpu)) return false;
    if (f.category && skip !== "category" && r.category !== f.category) return false;
    if (f.type && skip !== "type" && r.typeLabel !== f.type) return false;
    if (f.size && skip !== "size" && (r.size || "(none)") !== f.size) return false;
    if (f.sub && skip !== "sub" && r.subscriptionId !== f.sub) return false;
    if (f.region && skip !== "region" && (r.location || "(none)") !== f.region) return false;
    if (f.env && skip !== "env" && r.env !== f.env) return false;
    if (f.state && skip !== "state" && (r.state || "(none)") !== f.state) return false;
    if (f.has && skip !== "has") {
      if (f.has === "any" && !r.suggestions) return false;
      if (f.has === "none" && r.suggestions) return false;
      if (f.has === "crit-high" && !["critical", "high"].includes(r.maxSeverity)) return false;
      if (f.has === "hygiene" && (r.suggestions || !r.hygiene)) return false;
    }
    if ((f.stype && skip !== "stype") || (f.sev && skip !== "sev")) {
      const list = byResource.get(r._key) || [];
      if (!list.some((s) => (!f.stype || skip === "stype" || s.type === f.stype) &&
                             (!f.sev || skip === "sev" || s.severity === f.sev) &&
                             (f.stype || f.hyg || !s.hygiene))) return false;
    }
    return true;
  }

  // Tag / naming findings are on almost every resource: hidden unless asked for (checkbox or suggestion type).
  const visibleSuggestion = (s, f) => !s.hygiene || !!f.hyg || (f.stype && f.stype === s.type);

  const RESOURCE_FILTERS = ["category", "type", "size", "region", "env", "state", "has"];
  function suggestionMatches(s, f, skip) {
    if (!visibleSuggestion(s, f)) return false;
    if (f.q && skip !== "q" && !(s.title + " " + s.resourceName + " " + s.type + " " + s.subscription).toLowerCase().includes(f.q.toLowerCase())) return false;
    if (f.sub && skip !== "sub" && s.subscriptionId !== f.sub) return false;
    if (f.stype && skip !== "stype" && s.type !== f.stype) return false;
    if (f.sev && skip !== "sev" && s.severity !== f.sev) return false;
    if (f.category && skip !== "category" && s.category !== f.category) return false;
    if (f.type && skip !== "type" && s.typeLabel !== f.type) return false;
    const other = RESOURCE_FILTERS.filter((k) => !["category", "type"].includes(k) && f[k] && k !== skip);
    if (other.length) {
      const r = s.resourceId && resourceIndex().get(s.resourceId.toLowerCase());
      if (!r) return false;
      const sub = Object.fromEntries(other.map((k) => [k, f[k]]));
      if (!resourceMatches(r, sub)) return false;
    }
    return true;
  }

  let _index = null;
  function resourceIndex() {
    if (!_index) { _index = new Map(); estate.resources.forEach((r) => _index.set(r._key, r)); }
    return _index;
  }

  const rows = (skip) => state.view === "resources"
    ? estate.resources.filter((r) => resourceMatches(r, state.f, skip))
    : estate.suggestions.filter((s) => suggestionMatches(s, state.f, skip));

  // ---- facets (select options, counted on the rows the *other* filters leave) ----

  function countBy(items, fn) {
    const counts = new Map();
    items.forEach((x) => { const k = fn(x); if (k === undefined) return; counts.set(k, (counts.get(k) || 0) + 1); });
    return Array.from(counts.entries()).sort((a, b) => b[1] - a[1] || String(a[0]).localeCompare(String(b[0])));
  }

  function fillSelect(id, key, entries, labelFn, allLabel) {
    const select = $(id);
    const current = state.f[key] || "";
    select.replaceChildren(el("option", { value: "" }, allLabel));
    entries.slice(0, 500).forEach(([value, count]) => {
      select.appendChild(el("option", { value: value }, (labelFn ? labelFn(value) : value) + " (" + fmt(count) + ")"));
    });
    if (current && !entries.some(([v]) => v === current)) select.appendChild(el("option", { value: current }, current + " (0)"));
    select.value = current;
  }

  function fillFilters() {
    const res = state.view === "resources";
    const base = (key) => (res ? estate.resources.filter((r) => resourceMatches(r, state.f, key)) : null);
    const sugg = (key) => estate.suggestions.filter((s) => suggestionMatches(s, state.f, key));
    const subName = (id) => (subs.get(id) || {}).name || id;
    if (res) {
      fillSelect("f-category", "category", countBy(base("category"), (r) => r.category), null, "All categories");
      fillSelect("f-type", "type", countBy(base("type"), (r) => r.typeLabel), null, "All types");
      fillSelect("f-size", "size", countBy(base("size"), (r) => r.size || "(none)"), null, "All sizes / SKUs");
      fillSelect("f-sub", "sub", countBy(base("sub"), (r) => r.subscriptionId), subName, "All subscriptions");
      fillSelect("f-region", "region", countBy(base("region"), (r) => r.location || "(none)"), null, "All regions");
      fillSelect("f-env", "env", countBy(base("env"), (r) => r.env), null, "All environments");
      fillSelect("f-state", "state", countBy(base("state"), (r) => r.state || "(none)"), null, "All states");
    } else {
      fillSelect("f-category", "category", countBy(sugg("category"), (s) => s.category), null, "All categories");
      fillSelect("f-type", "type", countBy(sugg("type"), (s) => s.typeLabel), null, "All types");
      fillSelect("f-sub", "sub", countBy(sugg("sub"), (s) => s.subscriptionId), subName, "All subscriptions");
      ["f-size", "f-region", "f-env", "f-state"].forEach((id) => {
        const key = id.slice(2);
        fillSelect(id, key, countBy(estate.resources.filter((r) => resourceMatches(r, state.f, key)),
          (r) => (key === "size" ? r.size : key === "region" ? r.location : r[key]) || "(none)"), null, "Any");
      });
    }
    const pick = (r) => (byResource.get(r._key) || []).filter((s) => visibleSuggestion(s, state.f));
    const suggestionPool = res ? base("stype").flatMap((r) => byResource.get(r._key) || []) : sugg("stype");
    fillSelect("f-stype", "stype", countBy(suggestionPool, (s) => s.type), null, "All suggestion types");
    const sevPool = res ? base("sev").flatMap(pick) : sugg("sev");
    fillSelect("f-sev", "sev", countBy(sevPool, (s) => s.severity).sort((a, b) => sevRank(a[0]) - sevRank(b[0])), null, "All severities");
    $("f-q").value = state.f.q || "";
    $("f-has").value = state.f.has || "";
    $("f-has").disabled = !res;
    $("f-hyg").checked = !!state.f.hyg;
    $("f-ext").checked = !!state.f.ext;
  }

  // ---- tiles and breakdowns ------------------------------------------------

  function renderTiles() {
    const tiles = $("tiles");
    tiles.replaceChildren();
    const visible = estate.resources.filter((r) => shownByDefault(r, state.f));
    const all = el("button", { type: "button", class: "tile" + (state.f.category ? "" : " active") });
    all.append(el("strong", null, fmt(visible.length)), el("span", null, "All resources"));
    all.addEventListener("click", () => setFilter("category", ""));
    tiles.appendChild(all);
    countBy(visible, (r) => r.category).forEach(([cat, count]) => {
      const withSugg = visible.filter((r) => r.category === cat && r.suggestions).length;
      const tile = el("button", { type: "button", class: "tile" + (state.f.category === cat ? " active" : ""),
        title: withSugg + " with suggestions" });
      tile.append(el("strong", null, fmt(count)), el("span", null, cat));
      if (withSugg) tile.appendChild(el("em", null, fmt(withSugg) + " with suggestions"));
      tile.addEventListener("click", () => setFilter("category", state.f.category === cat ? "" : cat));
      tiles.appendChild(tile);
    });
  }

  function panel(title, entries, key, labelFn) {
    if (!entries.length) return null;
    const box = el("div", { class: "card breakdown" });
    box.appendChild(el("h3", null, title));
    const max = entries[0][1] || 1;
    const list = el("ul");
    entries.slice(0, 12).forEach(([value, count]) => {
      const item = el("li");
      const button = el("button", { type: "button", class: "link-button" + (state.f[key] === value ? " active" : ""),
        title: "Filter: " + (labelFn ? labelFn(value) : value) });
      button.append(el("span", { class: "label" }, labelFn ? labelFn(value) : value), el("span", { class: "count" }, fmt(count)));
      const bar = el("span", { class: "bar" });
      bar.style.width = Math.max(2, Math.round((100 * count) / max)) + "%";
      button.appendChild(bar);
      button.addEventListener("click", () => setFilter(key, state.f[key] === value ? "" : value));
      item.appendChild(button);
      list.appendChild(item);
    });
    if (entries.length > 12) list.appendChild(el("li", { class: "muted small" }, "+ " + (entries.length - 12) + " more - use the filter above"));
    box.appendChild(list);
    return box;
  }

  function renderBreakdowns(current) {
    const target = $("breakdowns");
    target.replaceChildren();
    const subName = (id) => (subs.get(id) || {}).name || id;
    const compute = current.filter(hasCompute);
    const bandOrder = CPU_BANDS.map(([, label]) => label).concat(["no data"]);
    const panels = state.view === "resources" ? [
      panel("By type", countBy(current, (r) => r.typeLabel), "type"),
      panel(state.f.type ? "Sizes / SKUs of " + state.f.type : "Sizes / SKUs", countBy(current, (r) => r.size || "(none)"), "size"),
      compute.length ? panel("Average CPU, last 30 days (VMs / scale sets)", countBy(compute, (r) => cpuBand(r.cpuAvg))
        .sort((a, b) => bandOrder.indexOf(a[0]) - bandOrder.indexOf(b[0])), "cpu") : null,
      panel("By region", countBy(current, (r) => r.location || "(none)"), "region"),
      panel("By subscription", countBy(current, (r) => r.subscriptionId), "sub", subName),
      panel("By environment", countBy(current, (r) => r.env), "env"),
      panel("Suggestions on these resources", countBy(current.flatMap((r) => (byResource.get(r._key) || [])
        .filter((s) => visibleSuggestion(s, state.f))), (s) => s.type), "stype"),
    ] : [
      panel("By severity", countBy(current, (s) => s.severity).sort((a, b) => sevRank(a[0]) - sevRank(b[0])), "sev"),
      panel("By suggestion type", countBy(current, (s) => s.type), "stype"),
      panel("By resource type", countBy(current, (s) => s.typeLabel), "type"),
      panel("By subscription", countBy(current, (s) => s.subscriptionId), "sub", subName),
    ];
    panels.filter(Boolean).forEach((p) => target.appendChild(p));
  }

  // ---- table ---------------------------------------------------------------

  function sortRows(items, columns) {
    const col = columns.find((c) => c.key === state.sort.key);
    if (!col) {
      return state.view === "suggestions"
        ? items.sort((a, b) => sevRank(a.severity) - sevRank(b.severity) || (b.savingsUsd || 0) - (a.savingsUsd || 0))
        : items;
    }
    const dir = state.sort.dir;
    const value = (x) => (col.key === "severity" ? sevRank(x.severity) : x[col.key]);
    return items.sort((a, b) => {
      const va = value(a), vb = value(b);
      if (col.num || col.key === "severity") return ((Number(va) || 0) - (Number(vb) || 0)) * dir;
      return String(va || "").localeCompare(String(vb || "")) * dir;
    });
  }

  function header(columns) {
    const tr = el("tr");
    columns.forEach((c) => {
      const th = el("th", { class: c.num ? "num sortable" : "sortable", scope: "col" });
      const arrow = state.sort.key === c.key ? (state.sort.dir > 0 ? " ▲" : " ▼") : "";
      th.appendChild(el("button", { type: "button", class: "sort" }, c.label + arrow));
      th.addEventListener("click", () => {
        state.sort = { key: c.key, dir: state.sort.key === c.key ? -state.sort.dir : (c.num ? -1 : 1) };
        state.page = 0;
        render();
      });
      tr.appendChild(th);
    });
    return tr;
  }

  const sevPill = (s) => el("span", { class: "pill sev-" + s }, s);

  function cellValue(r, c) {
    const v = r[c.key];
    if (c.key === "cost30") return v ? fmt(v) + " " + (r.currency || "") : "";
    if (c.pct) return v === null || v === undefined ? "" : v.toFixed(1) + " %";
    if (c.key === "ramGB") return v ? String(v) : "";
    return v === null || v === undefined ? "" : v;
  }

  function resourceRow(r, columns) {
    const tr = el("tr", { class: "clickable", tabindex: "0" });
    columns.forEach((c) => {
      const td = el("td", c.num ? { class: "num" } : null);
      if (c.key === "name") td.appendChild(el("strong", null, r.name));
      else if (c.key === "suggestions") { if (r.suggestions) td.appendChild(el("span", { class: "pill sev-" + r.maxSeverity }, r.suggestions)); }
      else td.textContent = cellValue(r, c);
      if (c.key === "cpuAvg" && r.cpuMax !== null) td.title = "Peak " + r.cpuMax.toFixed(1) + " % (highest 1-minute value in 30 days)";
      if (c.key === "cpuAvg" && r.cpuAvg !== null && r.cpuAvg < 5) td.classList.add("low-util");
      tr.appendChild(td);
    });
    tr.addEventListener("click", () => toggleDetail(tr, r, columns.length));
    tr.addEventListener("keydown", (e) => { if (e.key === "Enter") toggleDetail(tr, r, columns.length); });
    return tr;
  }

  function toggleDetail(tr, r, span) {
    const next = tr.nextElementSibling;
    if (next && next.classList.contains("detail")) { next.remove(); return; }
    const detail = el("tr", { class: "detail" });
    const td = el("td", { colspan: String(span) });
    td.appendChild(el("div", { class: "mono small" }, r.id));
    if (hasCompute(r)) {
      td.appendChild(el("p", { class: "small" }, [
        r.vcpu ? r.vcpu + " vCPU, " + r.ramGB + " GB RAM" : null,
        r.cpuAvg !== null ? "CPU average " + r.cpuAvg.toFixed(1) + " %, peak " + (r.cpuMax || 0).toFixed(1) + " %" : "no CPU data (not running in the last 30 days)",
        r.memAvg !== null ? "memory used " + r.memAvg.toFixed(1) + " % on average" : null,
      ].filter(Boolean).join(" · ") + " - last 30 days, Azure Monitor"));
    }
    const links = el("p", { class: "small" });
    const portal = el("a", { href: "https://portal.azure.com/#resource" + r.id, target: "_blank", rel: "noopener" }, "Open in Azure portal");
    links.appendChild(portal);
    if (r.folder) { links.append(" · "); links.appendChild(el("a", { href: "/reports/" + r.folder + "/README.md" }, "Subscription report")); }
    if (r.kind) links.append(" · kind: " + r.kind);
    if (r.managedBy) links.append(" · managed by: " + r.managedBy.split("/").pop());
    td.appendChild(links);
    const tags = Object.entries(r.tags || {});
    if (tags.length) {
      const tagLine = el("p", { class: "tags" });
      tags.forEach(([k, v]) => tagLine.appendChild(el("span", { class: "tag" }, k + ": " + v)));
      td.appendChild(tagLine);
    }
    const all = (byResource.get(r._key) || []).slice().sort((a, b) => sevRank(a.severity) - sevRank(b.severity));
    const list = all.filter((s) => !s.hygiene);
    const hygiene = all.filter((s) => s.hygiene);
    const item = (s) => {
      const li = el("li");
      li.append(sevPill(s.severity), " ");
      li.appendChild(el("a", { href: s.link }, (s.ref ? s.ref + " - " : "") + s.title));
      if (s.savingsUsd) li.append(" · est. USD " + fmt(s.savingsUsd) + "/month");
      return li;
    };
    if (list.length) {
      const ul = el("ul", { class: "suggestions" });
      list.forEach((s) => ul.appendChild(item(s)));
      td.appendChild(ul);
    } else {
      td.appendChild(el("p", { class: "muted small" }, r.folder ? "No actionable suggestions for this resource." : "Subscription not analysed yet - run an analysis for suggestions."));
    }
    if (hygiene.length) {
      const box = el("details", { class: "small" });
      box.appendChild(el("summary", null, "Tag / naming hygiene (" + hygiene.length + ")"));
      const ul = el("ul", { class: "suggestions" });
      hygiene.forEach((s) => ul.appendChild(item(s)));
      box.appendChild(ul);
      td.appendChild(box);
    }
    detail.appendChild(td);
    tr.after(detail);
  }

  function suggestionRow(s) {
    const tr = el("tr");
    const sev = el("td");
    sev.appendChild(sevPill(s.severity));
    tr.appendChild(sev);
    const title = el("td");
    title.appendChild(el("a", { href: s.link }, (s.ref ? s.ref + " - " : "") + s.title));
    tr.appendChild(title);
    ["type", "resourceName", "typeLabel", "subscription"].forEach((k) => tr.appendChild(el("td", null, s[k])));
    tr.appendChild(el("td", { class: "num" }, s.savingsUsd ? fmt(s.savingsUsd) : ""));
    tr.appendChild(el("td", { class: "num" }, s.wave || ""));
    return tr;
  }

  function renderTable(current) {
    // vCPU / RAM / utilisation columns only when VMs or scale sets are in view - keeps other views narrow.
    const columns = state.view === "resources"
      ? RESOURCE_COLUMNS.filter((c) => !c.compute || current.some(hasCompute))
      : SUGGESTION_COLUMNS;
    const sorted = sortRows(current.slice(), columns);
    const pages = Math.max(1, Math.ceil(sorted.length / PAGE_SIZE));
    state.page = Math.min(state.page, pages - 1);
    const slice = sorted.slice(state.page * PAGE_SIZE, (state.page + 1) * PAGE_SIZE);
    const table = $("results");
    table.tHead.replaceChildren(header(columns));
    const body = table.tBodies[0];
    body.replaceChildren();
    slice.forEach((x) => body.appendChild(state.view === "resources" ? resourceRow(x, columns) : suggestionRow(x)));
    if (!slice.length) body.appendChild(el("tr", null)).appendChild(el("td", { colspan: String(columns.length), class: "muted" }, "Nothing matches these filters."));
    $("result-title").textContent = state.view === "resources" ? "Resources" : "Suggestions";
    $("result-count").textContent = fmt(current.length) + " match" + (current.length === 1 ? "" : "es") +
      (state.view === "resources" ? " · click a row for details and suggestions" : "");
    $("p-info").textContent = "Page " + (state.page + 1) + " of " + pages;
    $("p-prev").disabled = state.page === 0;
    $("p-next").disabled = state.page >= pages - 1;
    return sorted;
  }

  // ---- state / URL ---------------------------------------------------------

  function writeHash() {
    const params = new URLSearchParams();
    if (state.view !== "resources") params.set("view", state.view);
    FILTER_KEYS.forEach((k) => { if (state.f[k]) params.set(k, state.f[k]); });
    if (state.sort.key) params.set("sort", (state.sort.dir < 0 ? "-" : "") + state.sort.key);
    history.replaceState(null, "", "#" + params.toString());
  }

  function readHash() {
    const params = new URLSearchParams(location.hash.slice(1));
    state.view = params.get("view") === "suggestions" ? "suggestions" : "resources";
    state.f = {};
    FILTER_KEYS.forEach((k) => { if (params.get(k)) state.f[k] = params.get(k); });
    const sort = params.get("sort") || "";
    state.sort = sort ? { key: sort.replace(/^-/, ""), dir: sort.startsWith("-") ? -1 : 1 } : { key: "", dir: 1 };
  }

  function setFilter(key, value) {
    if (value) state.f[key] = value; else delete state.f[key];
    if (key === "category") { delete state.f.type; delete state.f.size; }
    if (key === "type") delete state.f.size;
    state.page = 0;
    render();
  }

  let lastRows = [];
  function render() {
    if (!estate) return;
    document.querySelectorAll(".view-switch .tab").forEach((t) => t.classList.toggle("active", t.dataset.view === state.view));
    const current = rows();
    renderTiles();
    fillFilters();
    renderBreakdowns(current);
    lastRows = renderTable(current);
    writeHash();
  }

  // ---- CSV -----------------------------------------------------------------

  function csv() {
    const columns = state.view === "resources"
      ? ["name", "typeLabel", "category", "size", "vcpu", "ramGB", "cpuAvg", "cpuMax", "memAvg", "config", "os", "state", "env", "location", "subscription", "resourceGroup", "cost30", "currency", "suggestions", "maxSeverity", "id"]
      : ["severity", "ref", "title", "type", "resourceName", "typeLabel", "category", "subscription", "savingsUsd", "wave", "resourceId"];
    const escape = (v) => {
      let text = v === undefined || v === null ? "" : String(v);
      if (/^[=+\-@]/.test(text)) text = "'" + text; // no formula injection when opened in Excel
      return /[",\n;]/.test(text) ? '"' + text.replace(/"/g, '""') + '"' : text;
    };
    const lines = [columns.join(",")].concat(lastRows.map((r) => columns.map((c) => escape(r[c])).join(",")));
    const blob = new Blob(["\ufeff" + lines.join("\r\n")], { type: "text/csv;charset=utf-8" });
    const a = el("a", { href: URL.createObjectURL(blob), download: "estate-" + state.view + ".csv" });
    document.body.appendChild(a);
    a.click();
    setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 1000);
  }

  // ---- refresh -------------------------------------------------------------

  async function refresh() {
    const button = $("estate-refresh");
    button.disabled = true;
    $("estate-status").textContent = "Refreshing the inventory from Resource Graph across all enabled subscriptions…";
    try {
      const response = await fetch("/api/estate/refresh", { method: "POST", credentials: "same-origin",
        headers: { "Content-Type": "application/json" }, body: "{}" });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(data.detail || response.statusText);
      for (;;) {
        await new Promise((r) => setTimeout(r, 3000));
        const status = await (await fetch("/api/estate/status", { credentials: "same-origin" })).json();
        if (!status.running) {
          if (status.error) throw new Error(status.error);
          break;
        }
      }
      _index = null;
      await load();
    } catch (err) {
      $("estate-status").textContent = "Refresh failed: " + err.message;
    } finally {
      button.disabled = false;
    }
  }

  // ---- wiring --------------------------------------------------------------

  function init() {
    if (!$("results")) return;
    let timer = null;
    $("f-q").addEventListener("input", (e) => {
      clearTimeout(timer);
      timer = setTimeout(() => setFilter("q", e.target.value.trim()), 200);
    });
    [["f-category", "category"], ["f-type", "type"], ["f-size", "size"], ["f-sub", "sub"], ["f-region", "region"],
     ["f-env", "env"], ["f-state", "state"], ["f-has", "has"], ["f-stype", "stype"], ["f-sev", "sev"]].forEach(([id, key]) => {
      $(id).addEventListener("change", (e) => setFilter(key, e.target.value));
    });
    $("f-hyg").addEventListener("change", (e) => setFilter("hyg", e.target.checked ? "1" : ""));
    $("f-ext").addEventListener("change", (e) => setFilter("ext", e.target.checked ? "1" : ""));
    $("f-clear").addEventListener("click", () => { state.f = {}; state.page = 0; render(); });
    $("f-csv").addEventListener("click", csv);
    $("f-link").addEventListener("click", async () => {
      try { await navigator.clipboard.writeText(location.href); $("f-link").textContent = "Link copied"; }
      catch (e) { $("f-link").textContent = "Copy from the address bar"; }
      setTimeout(() => { $("f-link").textContent = "Copy link"; }, 2000);
    });
    $("p-prev").addEventListener("click", () => { state.page -= 1; render(); });
    $("p-next").addEventListener("click", () => { state.page += 1; render(); });
    document.querySelectorAll(".view-switch .tab").forEach((tab) => tab.addEventListener("click", () => {
      state.view = tab.dataset.view;
      state.sort = { key: "", dir: 1 };
      if (state.view === "suggestions") delete state.f.has;
      state.page = 0;
      render();
    }));
    $("estate-refresh").addEventListener("click", refresh);
    window.addEventListener("hashchange", () => { readHash(); render(); });
    load();
  }

  document.addEventListener("DOMContentLoaded", init);
})();
