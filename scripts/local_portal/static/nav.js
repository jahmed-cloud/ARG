// ARG local portal - grouped main menu. Each group is a <details> element, so the menu works without this script;
// the script keeps one group open at a time and closes groups on Esc or a click elsewhere.
// No inline scripts (CSP: script-src 'self').
(function () {
  "use strict";

  const groups = Array.prototype.slice.call(document.querySelectorAll(".main-nav details.nav-menu"));
  if (groups.length === 0) return;

  function closeAll(except) {
    groups.forEach(function (group) {
      if (group !== except) group.open = false;
    });
  }

  groups.forEach(function (group) {
    group.addEventListener("toggle", function () {
      if (group.open) closeAll(group);
    });
    group.addEventListener("keydown", function (event) {
      if (event.key !== "Escape") return;
      group.open = false;
      group.querySelector("summary").focus();
    });
  });

  document.addEventListener("click", function (event) {
    groups.forEach(function (group) {
      if (group.open && !group.contains(event.target)) group.open = false;
    });
  });
})();
