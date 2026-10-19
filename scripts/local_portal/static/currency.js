// ARG local portal - the Currency dropdown in the top bar: fills the choices from /api/currency, remembers the
// choice in a cookie (read by the server for reports, the dashboard and diagrams) and reloads the page.
(function () {
  "use strict";
  const select = document.getElementById("currency-pick");
  if (!select) return;
  fetch("/api/currency", { credentials: "same-origin" })
    .then(function (r) { return r.ok ? r.json() : null; })
    .then(function (data) {
      if (!data) return;
      select.innerHTML = "";
      data.options.forEach(function (o) {
        const option = document.createElement("option");
        option.value = o.code;
        option.textContent = o.code === "billing" ? "Billing currency" : o.code;
        option.title = o.label;
        if (o.code === data.selected) option.selected = true;
        select.appendChild(option);
      });
      select.title = data.date
        ? "Amounts in this currency. Billing currency: each subscription's own, at the rate on its invoice. Others: "
          + data.source + " of " + data.date + "."
        : "Exchange rates unavailable - billing currency or USD only.";
      select.disabled = false;
    })
    .catch(function () { /* the server-rendered choice stays */ });
  select.addEventListener("change", function () {
    document.cookie = "arg_currency=" + encodeURIComponent(select.value) + "; path=/; max-age=31536000; samesite=lax";
    window.location.reload();
  });
})();
