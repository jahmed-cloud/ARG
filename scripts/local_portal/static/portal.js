// ARG local portal - dashboard behaviour and mermaid rendering. No inline scripts (CSP: script-src 'self').
(function () {
  "use strict";

  function el(tag, attrs, text) {
    const node = document.createElement(tag);
    Object.entries(attrs || {}).forEach(([k, v]) => node.setAttribute(k, v));
    if (text !== undefined && text !== null) node.textContent = text;
    return node;
  }

  async function post(url, body) {
    const response = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body || {}),
      credentials: "same-origin",
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.detail || response.statusText);
    return data;
  }

  // ---- Report pages: render ```mermaid blocks when the library is available ----
  function renderMermaid() {
    const blocks = document.querySelectorAll("pre > code.language-mermaid");
    if (!blocks.length || !window.mermaid) return;
    blocks.forEach((code) => {
      const div = el("div", { class: "mermaid" }, code.textContent);
      code.parentElement.replaceWith(div);
    });
    window.mermaid.initialize({ startOnLoad: false, securityLevel: "strict", theme: "default" });
    window.mermaid.run({ querySelector: ".mermaid" });
  }

  // ---- Dashboard ----
  function initDashboard() {
    const table = document.getElementById("subs");
    if (!table) return;
    const analyzeSelected = document.getElementById("analyze-selected");
    const picks = () => Array.from(table.querySelectorAll("input.pick:checked")).map((c) => c.value);
    const syncButton = () => { analyzeSelected.disabled = picks().length === 0; };

    table.addEventListener("change", (e) => {
      if (e.target.id === "select-all") {
        table.querySelectorAll("tbody tr:not([hidden]) input.pick:not(:disabled)")
          .forEach((c) => { c.checked = e.target.checked; });
      }
      syncButton();
    });

    document.getElementById("filter").addEventListener("input", (e) => {
      const term = e.target.value.trim().toLowerCase();
      table.querySelectorAll("tbody tr[data-search]").forEach((row) => {
        row.hidden = term !== "" && !row.dataset.search.includes(term);
      });
    });

    async function analyze(ids) {
      try {
        await post("/api/analyze", { subscription_ids: ids });
        poll();
      } catch (err) {
        alert("Could not start analysis: " + err.message);
      }
    }

    table.addEventListener("click", (e) => {
      if (e.target.classList.contains("analyze")) analyze([e.target.dataset.id]);
    });
    analyzeSelected.addEventListener("click", () => analyze(picks()));

    document.getElementById("refresh").addEventListener("click", async (e) => {
      e.target.disabled = true;
      try { await post("/api/refresh"); } catch (err) { alert(err.message); }
      location.reload();
    });

    const seenCompleted = new Set();
    let firstPoll = true;

    function renderJobs(jobs) {
      const body = document.querySelector("#jobs tbody");
      body.replaceChildren();
      if (!jobs.length) {
        const row = el("tr");
        row.appendChild(el("td", { colspan: "5", class: "muted" }, "No analysis started in this session."));
        body.appendChild(row);
      }
      jobs.forEach((job) => {
        const row = el("tr");
        row.appendChild(el("td", {}, job.subscription_name));
        row.appendChild(el("td", { class: "status " + job.status }, job.status));
        const progressCell = el("td");
        const bar = el("progress", { max: "100", value: String(job.status === "completed" ? 100 : job.percent) });
        progressCell.appendChild(bar);
        progressCell.appendChild(el("div", { class: "muted small" }, job.error || job.message));
        row.appendChild(progressCell);
        row.appendChild(el("td", { class: "small" }, (job.started_at || job.queued_at || "").replace("T", " ").slice(0, 19)));
        const linkCell = el("td");
        if (job.folder) linkCell.appendChild(el("a", { href: "/reports/" + encodeURIComponent(job.folder) + "/README.md" }, "Open report"));
        row.appendChild(linkCell);
        body.appendChild(row);

        const badge = document.querySelector('.job-status[data-id="' + job.subscription_id.toLowerCase() + '"]');
        if (badge && (job.status === "queued" || job.status === "running")) badge.textContent = job.percent + "%";
        if (job.status === "completed" && !seenCompleted.has(job.id)) {
          seenCompleted.add(job.id);
          if (!firstPoll) setTimeout(() => location.reload(), 1500);
        }
      });
      firstPoll = false;
      return jobs.some((j) => j.status === "queued" || j.status === "running");
    }

    let timer = null;
    async function poll() {
      clearTimeout(timer);
      try {
        const response = await fetch("/api/state", { credentials: "same-origin" });
        if (response.status === 401) { location.href = "/login"; return; }
        const state = await response.json();
        const active = renderJobs(state.jobs || []);
        timer = setTimeout(poll, active ? 2500 : 15000);
      } catch (err) {
        timer = setTimeout(poll, 15000);
      }
    }
    poll();
  }

  // ---- Report pages: PDF export toolbar and print view ----
  function initExport() {
    const printNow = document.getElementById("print-now");
    if (printNow) printNow.addEventListener("click", () => window.print());

    const toolbar = document.querySelector(".doc-toolbar");
    if (!toolbar) return;
    const status = toolbar.querySelector(".export-status");
    toolbar.querySelectorAll("button.export-pdf").forEach((button) => {
      button.addEventListener("click", async () => {
        const buttons = toolbar.querySelectorAll("button.export-pdf");
        buttons.forEach((b) => { b.disabled = true; });
        status.textContent = "Generating PDF - this can take a minute for large reports...";
        try {
          const result = await post("/api/export-pdf", { folder: toolbar.dataset.folder, detail: button.dataset.detail });
          status.textContent = "";
          window.open(result.url, "_blank", "noopener");
        } catch (err) {
          status.textContent = "PDF export failed: " + err.message + " Use 'Print view' and your browser's Save as PDF.";
        } finally {
          buttons.forEach((b) => { b.disabled = false; });
        }
      });
    });
  }

  document.addEventListener("DOMContentLoaded", () => {
    renderMermaid();
    initDashboard();
    initExport();
  });
})();
