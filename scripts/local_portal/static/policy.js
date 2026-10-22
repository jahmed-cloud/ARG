// ARG local portal - Azure Policy analyzer: assignments, policy in effect per subscription, policies in force,
// exemptions and issues (/api/policy-analysis, scripts/subscription_analysis/policy_analyzer.py).
// All data is rendered with textContent / DOM nodes (never innerHTML); no inline scripts (CSP: script-src 'self').
(function () {
  "use strict";

  const PAGE_SIZE = 100;
  const VIEWS = ["issues", "tree", "assignments", "subscriptions", "policies", "exemptions"];
  // Microsoft's Azure architecture icons (unchanged, served by the portal) - always shown with the scope's name
  const ICONS = { "Management group": "/azure-icons/Management-Groups.svg", "Subscription": "/azure-icons/Subscriptions.svg",
    "Resource group": "/azure-icons/Resource-Groups.svg" };
  const POLICY_ICON = "/azure-icons/Policy.svg";
  const TITLES = { issues: "Issues", tree: "Assignment tree", assignments: "Assignments", subscriptions: "Policy in effect per subscription",
    policies: "Policies in force", exemptions: "Exemptions" };
  const SEV_PILL = { high: "sev-critical", medium: "sev-high", low: "sev-medium", info: "sev-info" };
  const CLASS_LABELS = { deny: "deny", remediate: "remediate", audit: "audit", disabled: "disabled" };
  const CLASS_ORDER = ["deny", "remediate", "audit", "disabled"];
  const DEFS_ON_NODE = 3;   // initiative / policy names shown on a tree row
  const COLUMNS = {
    assignments: [
      { key: "display", label: "Assignment" }, { key: "scopeText", label: "Scope" }, { key: "definition", label: "Definition" },
      { key: "typeLabel", label: "Type" }, { key: "policies", label: "Policies", num: true },
      { key: "effectsText", label: "Effects" }, { key: "enforcement", label: "Enforcement" },
      { key: "identity", label: "Identity" }, { key: "noncompliant", label: "Non-compliant", num: true },
      { key: "compliance", label: "Compliance %", num: true, pct: true }, { key: "exemptions", label: "Exemptions", num: true },
      { key: "created", label: "Created" }, { key: "issuesText", label: "Issues" },
    ],
    subscriptions: [
      { key: "name", label: "Subscription" }, { key: "path", label: "Management groups" },
      { key: "inherited", label: "Inherited", num: true }, { key: "direct", label: "Direct", num: true },
      { key: "resourceGroupAssignments", label: "Resource-group assignments", num: true },
      { key: "policies", label: "Policies", num: true }, { key: "deny", label: "Deny", num: true },
      { key: "remediate", label: "Remediate", num: true }, { key: "audit", label: "Audit", num: true },
      { key: "disabled", label: "Disabled", num: true }, { key: "compliance", label: "Compliance %", num: true, pct: true },
      { key: "noncompliant", label: "Non-compliant", num: true }, { key: "issuesText", label: "Issues" },
    ],
    policies: [
      { key: "display", label: "Policy" }, { key: "category", label: "Category" }, { key: "source", label: "Source" },
      { key: "strongest", label: "Strongest effect" }, { key: "effectsText", label: "Effects" },
      { key: "assignments", label: "Assignments", num: true }, { key: "scopesText", label: "Assigned at" },
      { key: "noncompliant", label: "Non-compliant", num: true }, { key: "flags", label: "Flags" },
    ],
    exemptions: [
      { key: "display", label: "Exemption" }, { key: "category", label: "Category" }, { key: "scopeText", label: "Scope" },
      { key: "assignment", label: "Assignment" }, { key: "policiesText", label: "Policies" },
      { key: "expires", label: "Expires" }, { key: "status", label: "Status" },
    ],
  };

  let data = null;
  let rows = {};
  let policyByKey = new Map();
  let assignmentById = new Map();
  let tree = { roots: [], nodes: {} };
  let lastRows = [];
  const state = { view: "issues", f: {}, sort: { key: "", dir: 1 }, page: 0, open: new Set(),
    treeOpen: null, selected: null, defOpen: new Set() };

  const $ = (id) => document.getElementById(id);
  function el(tag, attrs, text) {
    const node = document.createElement(tag);
    Object.entries(attrs || {}).forEach(([k, v]) => { if (v !== undefined && v !== null) node.setAttribute(k, v); });
    if (text !== undefined && text !== null) node.textContent = String(text);
    return node;
  }
  const fmt = (n) => (n === undefined || n === null || n === "" ? "" : Number(n).toLocaleString());
  const effectsText = (e) => Object.entries(e || {}).map(([k, n]) => n + " " + (CLASS_LABELS[k] || k)).join(" · ");
  function effectClass(effect) {
    const e = (effect || "").toLowerCase();
    if (e === "deny" || e === "denyaction") return "deny";
    if (e === "deployifnotexists" || e === "modify" || e === "append") return "remediate";
    if (e === "disabled") return "disabled";
    return "audit";
  }

  // ---- data ----------------------------------------------------------------

  function prepare(d) {
    policyByKey = new Map((d.policies || []).map((p) => [p.key, p]));
    const assignments = (d.assignments || []).map((a) => Object.assign({}, a, {
      scopeText: a.scopeKind + ": " + a.scopeLabel, typeLabel: a.initiative ? "Initiative" : "Policy",
      effectsText: effectsText(a.effects), issuesText: (a.issues || []).join(", "),
      haystack: [a.display, a.name, a.scopeLabel, a.definition, a.category, a.source, a.identity, (a.issues || []).join(" ")]
        .join(" ").toLowerCase(),
    }));
    const subscriptions = (d.subscriptions || []).map((s) => Object.assign({}, s, {
      remediate: (s.effects || {}).remediate || 0, audit: (s.effects || {}).audit || 0, disabled: (s.effects || {}).disabled || 0,
      issuesText: (s.issues || []).join(", "),
      haystack: [s.name, s.id, s.path, (s.issues || []).join(" ")].join(" ").toLowerCase(),
    }));
    const policies = (d.policies || []).map((p) => Object.assign({}, p, {
      effectsText: Object.entries(p.effects || {}).map(([k, n]) => k + " ×" + n).join(", "),
      scopesText: (p.scopes || []).slice(0, 3).join("; ") + ((p.scopes || []).length > 3 ? " +" + (p.scopes.length - 3) : ""),
      flags: [p.deprecated ? "deprecated" : "", p.preview ? "preview" : "", p.notEnforced ? p.notEnforced + "× not enforced" : ""]
        .filter(Boolean).join(", "),
      haystack: [p.display, p.key, p.category, p.source, (p.scopes || []).join(" ")].join(" ").toLowerCase(),
    }));
    const exemptions = (d.exemptions || []).map((e) => Object.assign({}, e, {
      scopeText: e.scopeKind ? e.scopeKind + ": " + e.scopeLabel : "", policiesText: e.policies ? String(e.policies) : "all",
      expires: e.expires || "never",
      haystack: [e.display, e.category, e.scopeLabel, e.assignment, e.status].join(" ").toLowerCase(),
    }));
    assignmentById = new Map(assignments.map((a) => [a.id, a]));
    tree = d.tree || { roots: [], nodes: {} };
    const issues = (d.issues || []).map((i) => Object.assign({}, i, {
      haystack: [i.title, i.detail, i.fix, (i.items || []).join(" ")].join(" ").toLowerCase(),
    }));
    return { issues: issues, assignments: assignments, subscriptions: subscriptions, policies: policies, exemptions: exemptions };
  }

  async function load() {
    $("policy-status").textContent = "Loading the policy analysis…";
    let response, body;
    try {
      response = await fetch("/api/policy-analysis", { credentials: "same-origin" });
      body = await response.json().catch(() => ({}));
    } catch (err) {
      $("policy-status").textContent = "Could not load the policy analysis. Check your connection and reload the page.";
      return;
    }
    if (response.status === 401) { location.href = "/login?next=/policy"; return; }
    if (!response.ok) { $("policy-status").textContent = body.detail || response.statusText; return; }
    data = body;
    rows = prepare(data);
    const collected = String(data.collected_at || "").slice(0, 16).replace("T", " ");
    $("policy-meta").textContent = collected ? "Collected " + collected + " UTC" : "";
    $("policy-status").textContent = (data.summary || {}).complianceDetail ? ""
      : "Per-subscription and per-policy compliance arrive with the next inventory refresh.";
    readUrl();
    fillFilters();
    render();
  }

  // ---- filters -------------------------------------------------------------

  const FILTERS = ["q", "scope", "effect", "source", "category", "enforcement", "status", "issues", "hidesubs", "node"];

  function readUrl() {
    const params = new URLSearchParams(location.search);
    if (VIEWS.includes(params.get("view"))) state.view = params.get("view");
    FILTERS.forEach((k) => { if (params.get(k)) state.f[k] = params.get(k); });
  }

  function writeUrl() {
    const params = new URLSearchParams();
    if (state.view !== "issues") params.set("view", state.view);
    FILTERS.forEach((k) => { if (state.f[k]) params.set(k, state.f[k]); });
    const query = params.toString();
    history.replaceState(null, "", location.pathname + (query ? "?" + query : ""));
  }

  function countBy(list, fn) {
    const counts = new Map();
    list.forEach((r) => { const k = fn(r); if (k) counts.set(k, (counts.get(k) || 0) + 1); });
    return Array.from(counts.entries()).sort((a, b) => b[1] - a[1] || String(a[0]).localeCompare(String(b[0])));
  }

  function options(select, key, values, allLabel) {
    const current = state.f[key] || "";
    select.replaceChildren(el("option", { value: "" }, allLabel));
    values.forEach(([value, count]) => {
      const option = el("option", { value: value }, value + " (" + fmt(count) + ")");
      if (value === current) option.selected = true;
      select.appendChild(option);
    });
  }

  const APPLIES = {
    scope: ["assignments", "exemptions"], effect: ["assignments", "subscriptions", "policies"], source: ["assignments", "policies"],
    category: ["assignments", "policies"], enforcement: ["assignments"], status: ["exemptions"],
    issues: ["assignments", "subscriptions", "policies"],
  };

  function fillFilters() {
    const list = rows[state.view] || [];
    options($("p-scope"), "scope", countBy(list, (r) => r.scopeKind), "Any scope");
    options($("p-source"), "source", countBy(list, (r) => r.source), "Any source");
    options($("p-category"), "category", countBy(list, (r) => r.category), "Any category");
    options($("p-status"), "status", countBy(rows.exemptions || [], (r) => r.status), "Any status");
    $("p-q").value = state.f.q || "";
    $("p-effect").value = state.f.effect || "";
    $("p-enforcement").value = state.f.enforcement || "";
    $("p-issues").checked = state.f.issues === "1";
    const ids = { scope: "p-scope", effect: "p-effect", source: "p-source", category: "p-category", enforcement: "p-enforcement",
      status: "p-status", issues: "p-issues" };
    Object.entries(APPLIES).forEach(([k, views]) => { $(ids[k]).disabled = !views.includes(state.view); });
    document.querySelectorAll(".view-switch .tab").forEach((tab) => {
      const active = tab.dataset.view === state.view;
      tab.classList.toggle("active", active);
      tab.setAttribute("aria-pressed", active ? "true" : "false");
    });
  }

  function matches(r) {
    const f = state.f;
    const on = (k) => f[k] && APPLIES[k] && APPLIES[k].includes(state.view);
    if (f.q) {
      const terms = f.q.toLowerCase().split(/\s+/).filter(Boolean);
      if (!terms.every((t) => r.haystack.includes(t))) return false;
    }
    if (on("scope") && r.scopeKind !== f.scope) return false;
    if (on("source") && r.source !== f.source) return false;
    if (on("category") && r.category !== f.category) return false;
    if (on("enforcement") && r.enforcement !== f.enforcement) return false;
    if (on("status") && r.status !== f.status) return false;
    if (on("effect")) {
      if (state.view === "policies") { if (r.strongest !== f.effect) return false; }
      else if (!((r.effects || {})[f.effect] > 0)) return false;
    }
    if (on("issues")) {
      if (state.view === "policies") { if (!r.flags) return false; }
      else if (!(r.issues || []).length) return false;
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
    const issues = s.issues || {};
    const tiles = $("policy-tiles");
    tiles.replaceChildren();
    const tile = (value, label, note, onClick, active) => {
      const t = el("button", { type: "button", class: "tile" + (active ? " active" : "") });
      t.append(el("strong", null, value), el("span", null, label));
      if (note) t.appendChild(el("em", null, note));
      t.addEventListener("click", onClick);
      tiles.appendChild(t);
    };
    const open = (view, key, value) => () => { state.f = {}; setFilter(key || "q", value || "", view); };
    tile(fmt((issues.high || 0) + (issues.medium || 0)), "Issues (high / medium)",
      fmt(issues.low || 0) + " low · " + fmt(issues.info || 0) + " info", open("issues"), state.view === "issues");
    tile(fmt(s.assignments), "Assignments", Object.entries(s.byScope || {}).map(([k, n]) => n + " " + k.toLowerCase()).join(" · "),
      open("assignments"), state.view === "assignments" && !state.f.enforcement);
    tile(fmt(s.policies), "Policies in force", effectsText(s.byEffect), open("policies"), state.view === "policies");
    tile(s.compliance === null || s.compliance === undefined ? "–" : s.compliance.toFixed(1) + " %", "Compliance",
      fmt(s.noncompliant) + " of " + fmt(s.evaluated) + " resources non-compliant", open("subscriptions"),
      state.view === "subscriptions");
    tile(fmt(s.subscriptionsWithoutDeny), "Subscriptions without Deny", "of " + fmt(s.subscriptions),
      open("subscriptions", "issues", "1"), false);
    tile(fmt(s.exemptionsNoExpiry), "Exemptions without an end date", "of " + fmt(s.exemptions),
      open("exemptions", "status", "no end date"), state.view === "exemptions" && state.f.status === "no end date");
  }

  function header(columns) {
    const tr = el("tr");
    columns.forEach((c) => {
      const th = el("th", { class: "sortable" + (c.num ? " num" : ""), scope: "col" });
      const arrow = state.sort.key === c.key ? (state.sort.dir > 0 ? " ▲" : " ▼") : "";
      const button = el("button", { type: "button", class: "sort" }, c.label + arrow);
      button.addEventListener("click", () => {
        state.sort = { key: c.key, dir: state.sort.key === c.key ? -state.sort.dir : (c.num ? -1 : 1) };
        render();
      });
      th.appendChild(button);
      tr.appendChild(th);
    });
    return tr;
  }

  function cell(r, c) {
    const v = r[c.key];
    if (c.num) {
      if (v === null || v === undefined) return el("td", { class: "num" }, "–");
      return el("td", { class: "num" }, c.pct ? Number(v).toFixed(1) : fmt(v));
    }
    if (c.key === "issuesText" && v) return el("td", { class: "low-util" }, v);
    return el("td", null, v === null || v === undefined ? "" : v);
  }

  function sorted(list) {
    const { key, dir } = state.sort;
    if (!key) return list;
    return list.slice().sort((a, b) => {
      const x = a[key], y = b[key];
      if (x === y) return 0;
      if (x === null || x === undefined || x === "") return 1;
      if (y === null || y === undefined || y === "") return -1;
      return (typeof x === "number" && typeof y === "number" ? x - y : String(x).localeCompare(String(y))) * dir;
    });
  }

  // The policies of an assignment's initiative (or its single policy) with the effect each runs with here, its
  // non-compliant resources and flags - in the Assignments view and in the tree.
  function membersBlock(a) {
    const box = el("div", { class: "members" });
    const members = (data.profiles || {})[a.profile] || [];
    if (!members.length) return box;
    const bad = a.memberNoncompliant || {};
    const counts = {};
    members.forEach(([, e]) => { const c = effectClass(e); counts[c] = (counts[c] || 0) + 1; });
    const head = el("div", { class: "tree-row" });
    head.appendChild(el("strong", null, (a.initiative ? "Policies in this initiative" : "Policy") + " (" + fmt(members.length) + ")"));
    CLASS_ORDER.filter((c) => counts[c]).forEach((c) => head.appendChild(chip(counts[c] + " " + c, "effect-" + c)));
    box.appendChild(head);
    const nameOf = (key) => String((policyByKey.get(key) || {}).display || key);
    const ordered = members.slice().sort((x, y) => (bad[y[0]] || 0) - (bad[x[0]] || 0)
      || CLASS_ORDER.indexOf(effectClass(x[1])) - CLASS_ORDER.indexOf(effectClass(y[1]))
      || nameOf(x[0]).localeCompare(nameOf(y[0])));
    const table = el("table", { class: "estate" });
    const headRow = el("tr");
    ["Policy", "Category", "Effect", "Non-compliant here", "Flags"].forEach((h) => headRow.appendChild(el("th", { scope: "col" }, h)));
    table.appendChild(el("thead")).appendChild(headRow);
    const body = el("tbody");
    const fill = (text) => {
      body.replaceChildren();
      const terms = (text || "").toLowerCase().split(/\s+/).filter(Boolean);
      let shown = 0;
      ordered.forEach(([key, effect]) => {
        const p = policyByKey.get(key) || {};
        const hay = [p.display, p.category, effect, effectClass(effect), key].join(" ").toLowerCase();
        if (terms.length && !terms.every((t) => hay.includes(t))) return;
        shown += 1;
        const tr = el("tr");
        tr.append(el("td", { title: key }, p.display || key), el("td", null, p.category || ""),
          el("td", null, (effect || "default") + " (" + effectClass(effect) + ")"),
          el("td", { class: "num" }, bad[key] ? fmt(bad[key]) : ""),
          el("td", null, [p.deprecated ? "deprecated" : "", p.preview ? "preview" : ""].filter(Boolean).join(", ")));
        body.appendChild(tr);
      });
      if (!shown) {
        const tr = el("tr");
        tr.appendChild(el("td", { colspan: "5", class: "muted" }, "No policy matches."));
        body.appendChild(tr);
      }
    };
    const tools = el("div", { class: "toolbar members-tools" });
    if (members.length > 10) {
      const filter = el("input", { type: "search", placeholder: "Filter policies: name, category, effect…",
        "aria-label": "Filter the policies of " + a.definition });
      filter.addEventListener("input", () => fill(filter.value));
      tools.appendChild(filter);
    }
    const download = el("button", { type: "button", class: "secondary" }, "Download policies (CSV)");
    download.addEventListener("click", () => {
      const rowsOut = ordered.map(([key, effect]) => {
        const p = policyByKey.get(key) || {};
        return { initiative: a.definition, assignment: a.display, policy: p.display || key, category: p.category || "",
          effect: effect || "default", effectClass: effectClass(effect), noncompliant: bad[key] || 0,
          deprecated: p.deprecated ? "yes" : "", preview: p.preview ? "yes" : "", definitionId: key };
      });
      saveCsv(rowsOut, ["initiative", "assignment", "policy", "category", "effect", "effectClass", "noncompliant",
        "deprecated", "preview", "definitionId"], "policies-" + (a.name || "assignment") + ".csv");
    });
    tools.appendChild(download);
    box.appendChild(tools);
    fill("");
    table.appendChild(body);
    const wrap = el("div", { class: "table-wrap" });
    wrap.appendChild(table);
    box.appendChild(wrap);
    return box;
  }

  function assignmentDetail(a, span) {
    const td = el("td", { colspan: span });
    const facts = [
      "Definition: " + a.definition + (a.source ? " (" + a.source + ")" : "") + " - " + a.definitionId,
      "Assignment ID: " + a.id,
      "Enforcement: " + (a.enforcement === "DoNotEnforce" ? "not enforced (DoNotEnforce)" : "enforced") +
        " · Managed identity: " + (a.identity || "none"),
    ];
    if ((a.notScopes || []).length) facts.push("Excluded scopes: " + a.notScopes.join(", "));
    const ul = el("ul", { class: "suggestions" });
    facts.forEach((f) => ul.appendChild(el("li", null, f)));
    (a.issues || []).forEach((i) => ul.appendChild(el("li", { class: "low-util" }, i)));
    td.appendChild(ul);
    td.appendChild(membersBlock(a));
    return td;
  }

  function renderIssues(list) {
    const box = $("p-issues-list");
    box.replaceChildren();
    if (!list.length) { box.appendChild(el("p", { class: "muted" }, "No issues match.")); return; }
    list.forEach((i) => {
      const card = el("div", { class: "card breakdown" });
      const head = el("div", { class: "toolbar" });
      head.append(el("span", { class: "pill " + (SEV_PILL[i.severity] || "sev-info") }, i.severity),
        el("h3", null, i.title + " (" + fmt(i.count) + ")"));
      card.appendChild(head);
      card.appendChild(el("p", null, i.detail));
      card.appendChild(el("p", { class: "small" }, "Fix: " + i.fix));
      const open = state.open.has(i.key);
      const items = el("ul", { class: "suggestions" });
      (open ? i.items : i.items.slice(0, 8)).forEach((x) => items.appendChild(el("li", { class: "small" }, x)));
      card.appendChild(items);
      if (i.items.length > 8 || i.count > i.items.length) {
        const more = el("button", { type: "button", class: "secondary" },
          open ? "Show fewer" : "Show all " + fmt(i.count));
        more.addEventListener("click", () => { if (open) state.open.delete(i.key); else state.open.add(i.key); render(); });
        card.appendChild(more);
      }
      box.appendChild(card);
    });
  }

  // ---- assignment tree -------------------------------------------------------

  function icon(kind) {
    const src = ICONS[kind];
    return src ? el("img", { class: "az-icon", src: src, alt: "", width: "18", height: "18" }) : el("span", { class: "tree-spacer" });
  }

  // Assignments made on the node's ancestors that reach it: none of the scopes between them is excluded (notScopes).
  function inheritedOf(nid) {
    const out = [];
    const node = tree.nodes[nid];
    const between = [node.scope];
    let parent = node.parent ? tree.nodes[node.parent] : null;
    while (parent && parent.kind !== "Group") {
      const ids = parent.assigned.filter((id) => {
        const notScopes = (assignmentById.get(id) || {}).notScopes || [];
        return !between.some((s) => notScopes.includes(s));
      });
      if (ids.length) out.push({ from: parent, ids: ids });
      between.push(parent.scope);
      parent = parent.parent ? tree.nodes[parent.parent] : null;
    }
    return out;
  }

  function matchedAssignments() {
    const terms = (state.f.q || "").toLowerCase().split(/\s+/).filter(Boolean);
    if (!terms.length) return null;
    return new Set((rows.assignments || []).filter((a) => terms.every((t) => a.haystack.includes(t))).map((a) => a.id));
  }

  function ancestorsOf(nid) {
    const out = [];
    let n = tree.nodes[nid];
    while (n && n.parent) { out.push(n.parent); n = tree.nodes[n.parent]; }
    return out;
  }

  function initialOpen() {
    const open = new Set();
    tree.roots.forEach((r) => {
      open.add(r);
      (tree.nodes[r].children || []).forEach((c) => { if (tree.nodes[c].kind === "Management group") open.add(c); });
    });
    return open;
  }

  function chip(text, cls, title) {
    return el("span", { class: "chip" + (cls ? " " + cls : ""), title: title || null }, text);
  }

  const bareSubscription = (n) => n.kind === "Subscription" && !n.assigned.length && !(n.children || []).length;

  function renderTreeNode(nid, matched, list) {
    const n = tree.nodes[nid];
    const hide = state.f.hidesubs === "1";
    if (hide && bareSubscription(n)) return;
    const li = el("li", { class: "tree-node", role: "treeitem" });
    const row = el("div", { class: "tree-row" + (state.selected === nid ? " selected" : "") });
    const kids = (n.children || []).filter((c) => !(hide && bareSubscription(tree.nodes[c])));
    const open = state.treeOpen.has(nid);
    if (kids.length) {
      li.setAttribute("aria-expanded", open ? "true" : "false");
      const toggle = el("button", { type: "button", class: "tree-toggle", "aria-label": (open ? "Collapse " : "Expand ") + n.label },
        open ? "▾" : "▸");
      toggle.addEventListener("click", () => { if (open) state.treeOpen.delete(nid); else state.treeOpen.add(nid); renderTree(); });
      row.appendChild(toggle);
    } else {
      row.appendChild(el("span", { class: "tree-spacer" }));
    }
    row.appendChild(icon(n.kind));
    row.appendChild(el("span", { class: "tree-kind" }, n.kind === "Group" ? "" : n.kind));
    const name = el("button", { type: "button", class: "tree-name" }, n.label);
    name.addEventListener("click", () => { state.selected = nid; state.f.node = nid; writeUrl(); renderTree(); });
    row.appendChild(name);
    if (matched) {
      const here = n.assigned.filter((id) => matched.has(id)).length;
      const through = n.kind === "Group" ? 0
        : inheritedOf(nid).reduce((sum, g) => sum + g.ids.filter((id) => matched.has(id)).length, 0);
      if (here) { row.classList.add("match-assigned"); row.appendChild(chip(here + " assigned here", "match-assigned")); }
      else if (through) { row.classList.add("match-applies"); row.appendChild(chip("in effect through a parent", "match-applies")); }
    }
    const defs = n.assigned.map((id) => assignmentById.get(id)).filter(Boolean);
    defs.slice(0, DEFS_ON_NODE).forEach((a) => row.appendChild(chip((a.initiative ? "Initiative: " : "Policy: ") + a.definition
      + (a.initiative ? " (" + a.policies + ")" : ""), a.initiative ? "def def-initiative" : "def", "Assignment: " + a.display)));
    if (defs.length > DEFS_ON_NODE) row.appendChild(chip("+" + (defs.length - DEFS_ON_NODE) + " more", "def"));
    if (n.assigned.length) {
      row.appendChild(chip(n.assigned.length + " assigned", "assigned"));
      Object.entries(n.effects || {}).forEach(([k, v]) => row.appendChild(chip(v + " " + k, "effect-" + k, "policies in the assignments made here")));
    }
    if (n.inherited) row.appendChild(chip(n.inherited + " inherited", "", "assignments made above that reach this scope"));
    if (n.kind !== "Subscription" && n.kind !== "Resource group" && n.subscriptions) {
      row.appendChild(chip(n.subscriptions + " subscription" + (n.subscriptions === 1 ? "" : "s"), ""));
    }
    if (n.assignedBelow) row.appendChild(chip(n.assignedBelow + " assigned below", ""));
    if (n.notEnforced) row.appendChild(chip(n.notEnforced + " not enforced", "warn"));
    if (n.issues) row.appendChild(chip(n.issues + " with issues", "warn"));
    li.appendChild(row);
    if (kids.length && open) {
      const ul = el("ul", { role: "group" });
      kids.forEach((c) => renderTreeNode(c, matched, ul));
      li.appendChild(ul);
    }
    list.appendChild(li);
  }

  // Assignments of a scope, each opening the policies of its initiative.
  function assignmentList(ids) {
    const list = el("div", { class: "tree-assignments" });
    ids.map((id) => assignmentById.get(id)).filter(Boolean).forEach((a) => {
      const open = state.defOpen.has(a.id);
      const item = el("div", { class: "tree-assignment" + (open ? " open" : "") });
      const head = el("div", { class: "tree-row" });
      const flip = () => { if (state.defOpen.has(a.id)) state.defOpen.delete(a.id); else state.defOpen.add(a.id); renderDetail(); };
      const toggle = el("button", { type: "button", class: "tree-toggle", "aria-expanded": open ? "true" : "false",
        "aria-label": (open ? "Hide" : "Show") + " the policies of " + a.definition }, open ? "▾" : "▸");
      toggle.addEventListener("click", flip);
      const name = el("button", { type: "button", class: "tree-name", title: (open ? "Hide" : "Show") + " its policies" }, a.definition);
      name.addEventListener("click", flip);
      head.append(toggle, chip(a.initiative ? "Initiative" : "Policy", a.initiative ? "def-initiative" : "def"), name);
      if (a.initiative) head.appendChild(el("span", { class: "muted small" }, fmt(a.policies) + " policies"));
      CLASS_ORDER.filter((c) => (a.effects || {})[c]).forEach((c) => head.appendChild(chip(a.effects[c] + " " + c, "effect-" + c)));
      if (a.enforcement === "DoNotEnforce") head.appendChild(chip("not enforced", "warn"));
      (a.issues || []).filter((i) => i !== "not enforced").forEach((i) => head.appendChild(chip(i, "warn")));
      item.appendChild(head);
      const meta = el("div", { class: "small muted tree-meta" });
      meta.append("Assignment " + a.display + (a.source ? " · " + a.source : "") +
        " · " + (a.noncompliant === null || a.noncompliant === undefined ? "no compliance data" : fmt(a.noncompliant) + " non-compliant") + " · ");
      const go = el("button", { type: "button", class: "link small" }, "open in Assignments");
      go.addEventListener("click", () => { state.view = "assignments"; state.f = { q: a.display }; state.open = new Set([a.id]); fillFilters(); render(); });
      meta.appendChild(go);
      item.appendChild(meta);
      if (open) item.appendChild(membersBlock(a));
      list.appendChild(item);
    });
    return list;
  }

  function renderDetail() {
    const box = $("t-detail");
    box.replaceChildren();
    const n = state.selected && tree.nodes[state.selected];
    if (!n) {
      box.appendChild(el("p", { class: "muted small" }, "Select a management group, subscription or resource group to see the assignments made on it and those it inherits."));
      return;
    }
    const head = el("div", { class: "tree-row" });
    head.append(icon(n.kind), el("span", { class: "tree-kind" }, n.kind === "Group" ? "" : n.kind), el("h3", null, n.label));
    box.appendChild(head);
    if (n.scope) box.appendChild(el("p", { class: "muted small" }, n.scope));
    const title = (text) => {
      const h = el("div", { class: "tree-row" });
      h.append(el("img", { class: "az-icon", src: POLICY_ICON, alt: "", width: "18", height: "18" }),
        el("span", { class: "tree-kind" }, "Azure Policy"), el("strong", null, text));
      return h;
    };
    box.appendChild(title("Assigned here (" + n.assigned.length + ")"));
    box.appendChild(n.assigned.length ? assignmentList(n.assigned) : el("p", { class: "muted small" }, "No assignments are made on this scope."));
    const inherited = n.kind === "Group" ? [] : inheritedOf(state.selected);
    const total = inherited.reduce((sum, g) => sum + g.ids.length, 0);
    box.appendChild(title("Inherited (" + total + ")"));
    if (!inherited.length) box.appendChild(el("p", { class: "muted small" }, "Nothing reaches this scope from above."));
    inherited.forEach((g) => {
      box.appendChild(el("p", { class: "small" }, "From " + g.from.label + " (" + g.from.kind.toLowerCase() + ")"));
      box.appendChild(assignmentList(g.ids));
    });
    if (n.subscriptions && n.kind !== "Subscription") {
      box.appendChild(el("p", { class: "muted small" }, fmt(n.subscriptions) + " subscriptions and " + fmt(n.assignedBelow) +
        " further assignments below this scope."));
    }
  }

  function renderTree() {
    if (!state.treeOpen) state.treeOpen = initialOpen();
    const matched = matchedAssignments();
    const list = $("t-tree");
    list.replaceChildren();
    const nodes = Object.values(tree.nodes);
    if (matched) {   // open the path to every scope where a matching assignment is made
      const assignedAt = nodes.filter((n) => n.assigned.some((id) => matched.has(id)));
      assignedAt.forEach((n) => ancestorsOf(n.id).forEach((a) => state.treeOpen.add(a)));
      const subs = nodes.filter((n) => n.kind === "Subscription" && (n.assigned.some((id) => matched.has(id))
        || inheritedOf(n.id).some((g) => g.ids.some((id) => matched.has(id))))).length;
      $("t-summary").textContent = fmt(matched.size) + " matching assignment(s), assigned at " + fmt(assignedAt.length) +
        " scope(s), in effect on " + fmt(subs) + " subscription(s).";
    } else {
      $("t-summary").textContent = fmt((data.summary || {}).assignments) + " assignments on " + fmt(nodes.length) +
        " scopes. Search an assignment or policy to see where it is assigned and where it applies.";
    }
    tree.roots.forEach((r) => renderTreeNode(r, matched, list));
    $("t-hide-subs").checked = state.f.hidesubs === "1";
    renderDetail();
  }

  function render() {
    renderTiles();
    writeUrl();
    const list = sorted((rows[state.view] || []).filter(matches));
    lastRows = list;
    $("p-title").textContent = TITLES[state.view];
    $("p-count").textContent = fmt(list.length) + " of " + fmt((rows[state.view] || []).length);
    const isIssues = state.view === "issues";
    const isTree = state.view === "tree";
    $("p-issues-list").hidden = !isIssues;
    $("p-tree-view").hidden = !isTree;
    $("p-table-wrap").hidden = isIssues || isTree;
    document.querySelector(".pager").hidden = isTree;
    if (isTree) {
      $("p-count").textContent = "";
      if (state.f.node && tree.nodes[state.f.node]) state.selected = state.f.node;
      renderTree();
      return;
    }
    const pages = isIssues ? 1 : Math.max(1, Math.ceil(list.length / PAGE_SIZE));
    state.page = Math.min(state.page, pages - 1);
    $("p-page").textContent = "Page " + (state.page + 1) + " of " + pages;
    $("p-prev").disabled = state.page === 0;
    $("p-next").disabled = state.page >= pages - 1;
    if (isIssues) { renderIssues(list); return; }
    const columns = COLUMNS[state.view];
    const slice = list.slice(state.page * PAGE_SIZE, (state.page + 1) * PAGE_SIZE);
    const table = $("p-results");
    table.querySelector("thead").replaceChildren(header(columns));
    const tbody = table.querySelector("tbody");
    tbody.replaceChildren();
    if (!slice.length) {
      const tr = el("tr");
      tr.appendChild(el("td", { colspan: columns.length, class: "empty-state" }, "Nothing matches these filters."));
      tbody.appendChild(tr);
      return;
    }
    const expandable = state.view === "assignments";
    slice.forEach((r) => {
      const tr = el("tr", expandable ? { class: "clickable", tabindex: "0", "aria-expanded": state.open.has(r.id) ? "true" : "false" } : null);
      columns.forEach((c) => tr.appendChild(cell(r, c)));
      tbody.appendChild(tr);
      if (!expandable) return;
      const toggle = () => { if (state.open.has(r.id)) state.open.delete(r.id); else state.open.add(r.id); render(); };
      tr.addEventListener("click", toggle);
      tr.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); toggle(); } });
      if (state.open.has(r.id)) {
        const detail = el("tr", { class: "detail" });
        detail.appendChild(assignmentDetail(r, columns.length));
        tbody.appendChild(detail);
      }
    });
  }

  function csv() {
    if (state.view === "tree") {   // one row per scope
      lastRows = Object.values(tree.nodes).map((n) => ({ kind: n.kind, label: n.label, assigned: n.assigned.length,
        inherited: n.inherited, assignedBelow: n.assignedBelow, subscriptions: n.subscriptions, notEnforced: n.notEnforced,
        issues: n.issues, parent: n.parent ? (tree.nodes[n.parent] || {}).label : "", scope: n.scope,
        assignments: n.assigned.map((id) => (assignmentById.get(id) || {}).display || id).join("; ") }));
    }
    const columns = state.view === "tree" ? ["kind", "label", "parent", "assigned", "inherited", "assignedBelow",
      "subscriptions", "notEnforced", "issues", "assignments", "scope"]
      : state.view === "issues" ? ["severity", "title", "count", "detail", "fix"]
      : COLUMNS[state.view].map((c) => c.key).concat(state.view === "assignments" ? ["definitionId", "id"] : state.view === "policies" ? ["key"] : ["id"]);
    saveCsv(lastRows, columns, "policy-" + state.view + ".csv");
  }

  function saveCsv(list, columns, filename) {
    const escape = (v) => {
      let text = v === undefined || v === null ? "" : String(v);
      if (/^[=+\-@]/.test(text)) text = "'" + text; // no formula injection when opened in Excel
      return /[",\n;]/.test(text) ? '"' + text.replace(/"/g, '""') + '"' : text;
    };
    const lines = [columns.join(",")].concat(list.map((r) => columns.map((c) => escape(r[c])).join(",")));
    const blob = new Blob(["\ufeff" + lines.join("\r\n")], { type: "text/csv;charset=utf-8" });
    const a = el("a", { href: URL.createObjectURL(blob), download: filename });
    document.body.appendChild(a);
    a.click();
    setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 1000);
  }

  // ---- refresh (the estate refresh collects the policy) -----------------------

  async function refresh() {
    const button = $("policy-refresh");
    button.disabled = true;
    $("policy-status").textContent = "Refreshing the estate inventory, including every policy assignment, definition, exemption and compliance state - about 5 minutes…";
    try {
      const response = await fetch("/api/estate/refresh", { method: "POST", credentials: "same-origin",
        headers: { "Content-Type": "application/json" }, body: "{}" });
      const started = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(started.detail || response.statusText);
      for (;;) {
        await new Promise((r) => setTimeout(r, 3000));
        const statusResponse = await fetch("/api/estate/status", { credentials: "same-origin" });
        if (statusResponse.status === 401) { location.href = "/login?next=/policy"; return; }
        if (!statusResponse.ok) throw new Error("Status request failed (" + statusResponse.status + ")");
        const status = await statusResponse.json();
        if (!status.running) { if (status.error) throw new Error(status.error); break; }
      }
      await load();
    } catch (err) {
      $("policy-status").textContent = "Refresh failed: " + err.message;
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
    fillFilters();
    render();
  }));
  let typing = null;
  $("p-q").addEventListener("input", () => {
    clearTimeout(typing);
    typing = setTimeout(() => setFilter("q", $("p-q").value.trim()), 200);
  });
  [["p-scope", "scope"], ["p-effect", "effect"], ["p-source", "source"], ["p-category", "category"],
    ["p-enforcement", "enforcement"], ["p-status", "status"]].forEach(([id, key]) => {
    $(id).addEventListener("change", () => { if (data) setFilter(key, $(id).value); });
  });
  $("p-issues").addEventListener("change", () => { if (data) setFilter("issues", $("p-issues").checked ? "1" : ""); });
  $("p-clear").addEventListener("click", () => { if (!data) return; state.f = {}; state.page = 0; fillFilters(); render(); });
  $("p-csv").addEventListener("click", () => { if (data) csv(); });
  $("p-prev").addEventListener("click", () => { state.page -= 1; render(); });
  $("p-next").addEventListener("click", () => { state.page += 1; render(); });
  $("policy-refresh").addEventListener("click", refresh);
  $("t-expand").addEventListener("click", () => { if (!data) return; state.treeOpen = new Set(Object.keys(tree.nodes)); renderTree(); });
  $("t-collapse").addEventListener("click", () => { if (!data) return; state.treeOpen = new Set(tree.roots); renderTree(); });
  $("t-hide-subs").addEventListener("change", () => {
    if (!data) return;
    state.f.hidesubs = $("t-hide-subs").checked ? "1" : "";
    writeUrl();
    renderTree();
  });
  load();
})();
