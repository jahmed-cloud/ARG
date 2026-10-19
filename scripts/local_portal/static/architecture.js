// ARG local portal - architecture diagrams: load the SVG, zoom (wheel / buttons), pan (drag), search, export.
(function () {
  "use strict";
  const stage = document.getElementById("arch-stage");
  const host = document.getElementById("arch-svg");
  const status = document.getElementById("arch-status");
  if (!stage || !host) return;
  const params = new URLSearchParams(window.location.search);
  const subscription = params.get("subscription") || "";
  const view = ["network", "landing"].indexOf(params.get("view")) >= 0 ? params.get("view") : "resources";
  const fileName = view === "landing" ? "landing-zone" : (subscription ? "subscription-" + subscription : "tenant") +
    (view === "network" ? "-network" : "-architecture");
  let svgText = "";
  let scale = 1, tx = 0, ty = 0;

  function svg() { return host.querySelector("svg"); }
  function size() {
    const el = svg();
    return el ? { w: el.width.baseVal.value, h: el.height.baseVal.value } : { w: 1, h: 1 };
  }
  function apply() {
    host.style.transform = "translate(" + tx + "px," + ty + "px) scale(" + scale + ")";
    const z = document.getElementById("arch-zoom");
    if (z) z.textContent = Math.round(scale * 100) + " %";
  }
  function zoomAt(factor, mx, my) {
    const next = Math.min(8, Math.max(0.03, scale * factor));
    tx = mx - (mx - tx) * (next / scale);
    ty = my - (my - ty) * (next / scale);
    scale = next;
    apply();
  }
  function fit() {
    const s = size();
    scale = Math.min(stage.clientWidth / s.w, stage.clientHeight / s.h, 1);
    tx = (stage.clientWidth - s.w * scale) / 2;
    ty = Math.max(8, (stage.clientHeight - s.h * scale) / 2);
    apply();
  }
  function centre(dx, dy) { zoomAt(1, 0, 0); tx += dx; ty += dy; apply(); }

  stage.addEventListener("wheel", function (e) {
    e.preventDefault();
    const r = stage.getBoundingClientRect();
    zoomAt(e.deltaY < 0 ? 1.15 : 1 / 1.15, e.clientX - r.left, e.clientY - r.top);
  }, { passive: false });

  let drag = null, moved = false;
  stage.addEventListener("pointerdown", function (e) {
    if (e.button !== 0) return;
    drag = { x: e.clientX, y: e.clientY, tx: tx, ty: ty };
    moved = false;
  });
  window.addEventListener("pointermove", function (e) {
    if (!drag) return;
    const dx = e.clientX - drag.x, dy = e.clientY - drag.y;
    if (Math.abs(dx) + Math.abs(dy) > 4) { moved = true; stage.classList.add("dragging"); }
    tx = drag.tx + dx; ty = drag.ty + dy;
    apply();
  });
  window.addEventListener("pointerup", function () { drag = null; stage.classList.remove("dragging"); });
  // a drag that ends on a subscription must not open it
  stage.addEventListener("click", function (e) { if (moved) { e.preventDefault(); e.stopPropagation(); } }, true);

  const picker = document.getElementById("arch-sub");
  if (picker) picker.addEventListener("change", function () { picker.form.submit(); });

  function button(id, fn) { const b = document.getElementById(id); if (b) b.addEventListener("click", fn); }
  button("arch-in", function () { zoomAt(1.25, stage.clientWidth / 2, stage.clientHeight / 2); });
  button("arch-out", function () { zoomAt(1 / 1.25, stage.clientWidth / 2, stage.clientHeight / 2); });
  button("arch-fit", fit);
  button("arch-100", function () { scale = 1; tx = 16; ty = 16; apply(); });

  function download(blob, name) {
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = name;
    document.body.appendChild(a);
    a.click();
    setTimeout(function () { URL.revokeObjectURL(a.href); a.remove(); }, 1000);
  }
  button("arch-svg-export", function () {
    download(new Blob([svgText], { type: "image/svg+xml" }), fileName + ".svg");
  });
  button("arch-png-export", function () {
    const s = size();
    const ratio = Math.min(2, 16000 / Math.max(s.w, s.h));
    const img = new Image();
    img.onload = function () {
      const canvas = document.createElement("canvas");
      canvas.width = Math.round(s.w * ratio);
      canvas.height = Math.round(s.h * ratio);
      const ctx = canvas.getContext("2d");
      ctx.fillStyle = "#ffffff";
      ctx.fillRect(0, 0, canvas.width, canvas.height);
      ctx.drawImage(img, 0, 0, canvas.width, canvas.height);
      canvas.toBlob(function (blob) { if (blob) download(blob, fileName + ".png"); }, "image/png");
    };
    img.onerror = function () { if (status) status.textContent = "PNG export failed - use SVG export."; };
    img.src = "data:image/svg+xml;base64," + btoa(unescape(encodeURIComponent(svgText)));
  });

  const search = document.getElementById("arch-search");
  if (search) {
    search.addEventListener("input", function () {
      const q = search.value.trim().toLowerCase();
      const el = svg();
      if (!el) return;
      el.querySelectorAll(".hit").forEach(function (n) { n.classList.remove("hit"); });
      if (q.length < 2) { if (status) status.textContent = ""; return; }
      const hits = Array.prototype.filter.call(el.querySelectorAll("[data-label]"), function (n) {
        return (n.getAttribute("data-label") || "").indexOf(q) >= 0;
      });
      hits.forEach(function (n) { (n.closest(".node") || n).classList.add("hit"); });
      if (status) status.textContent = hits.length + " match(es)";
      if (hits.length) {
        const b = hits[0].getBBox();
        scale = Math.max(scale, 0.8);
        tx = stage.clientWidth / 2 - (b.x + b.width / 2) * scale;
        ty = stage.clientHeight / 2 - (b.y + b.height / 2) * scale;
        apply();
      }
    });
  }

  fetch("/api/architecture.svg?view=" + view +
        (subscription ? "&subscription=" + encodeURIComponent(subscription) : ""),
        { credentials: "same-origin" })
    .then(function (r) { return r.ok ? r.text() : r.text().then(function (t) { throw new Error(t || r.statusText); }); })
    .then(function (text) {
      svgText = text;
      host.innerHTML = text;   // generated by ARG, every Azure-sourced value escaped (diagram.py)
      fit();
      if (status) status.textContent = "";
    })
    .catch(function (err) {
      if (status) status.textContent = "Diagram unavailable: " + err.message;
    });

  const details = document.getElementById("lz-details");
  if (details && view === "landing") {
    fetch("/api/landing-zone.html", { credentials: "same-origin" })
      .then(function (r) { return r.ok ? r.text() : r.text().then(function (t) { throw new Error(t || r.statusText); }); })
      .then(function (html) { details.innerHTML = html; })   // render_markdown output, HTML escaped (render.py)
      .catch(function (err) { details.textContent = "Details unavailable: " + err.message; });
  }
})();
