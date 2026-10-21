// Progressive enhancement only: every page works without this file.
(function () {
  "use strict";

  function esc(s) {
    return String(s == null ? "" : s).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }

  function getJSON(url) {
    return fetch(url, { headers: { Accept: "application/json" } }).then(function (r) { return r.json(); });
  }

  // Scan form: input mode switch, and the authorisation gate for port scans.
  var form = document.getElementById("scan-form");
  if (form) {
    var mode = document.getElementById("mode");
    var modeButtons = form.querySelectorAll("[data-mode]");
    var panels = form.querySelectorAll("[data-panel]");
    modeButtons.forEach(function (btn) {
      btn.addEventListener("click", function () {
        mode.value = btn.dataset.mode;
        modeButtons.forEach(function (b) { b.classList.toggle("on", b === btn); });
        panels.forEach(function (p) { p.classList.toggle("hidden", p.dataset.panel !== btn.dataset.mode); });
      });
    });

    var active = document.getElementById("opt-active");
    var authRow = document.getElementById("auth-row");
    var auth = document.getElementById("opt-auth");
    if (active) {  // the port-scan option only exists when the server allows it
      active.addEventListener("change", function () {
        authRow.classList.toggle("hidden", !active.checked);
        if (!active.checked) auth.checked = false;
      });
    }
    form.addEventListener("submit", function (e) {
      if (active && active.checked && !auth.checked) {
        e.preventDefault();
        authRow.classList.remove("hidden");
        auth.focus();
        return;
      }
      var btn = document.getElementById("scan-btn");
      btn.disabled = true;
      btn.textContent = "Scanning";
    });
  }

  // Result page while a scan runs: refresh the check list, reload when finished.
  var progress = document.getElementById("progress");
  if (progress) {
    var id = progress.dataset.scanId;
    (function poll() {
      getJSON("/api/scan/" + id).then(function (d) {
        if (d.status === "done" || d.status === "error") { location.reload(); return; }
        var steps = d.progress || {};
        var rows = Object.keys(steps).map(function (k) {
          var s = steps[k];
          var meta = s.note || (s.status === "done" ? (s.findings ? s.findings + " findings" : "done") : s.status);
          return "<li><span>" + esc(s.title) + '</span><span class="mut">' + esc(meta) + "</span></li>";
        }).join("");
        progress.innerHTML = rows || '<li><span class="mut">Starting</span></li>';
        setTimeout(poll, 900);
      }).catch(function () { setTimeout(poll, 2000); });
    })();
  }

  // Batch page: fill in each row as its scan finishes.
  var batch = document.getElementById("batch");
  if (batch) {
    var ids = (batch.dataset.ids || "").split(",").filter(Boolean);
    (function tick() {
      var pending = 0;
      ids.forEach(function (sid) {
        var row = batch.querySelector('tr[data-id="' + sid + '"]');
        if (!row || row.dataset.done) return;
        pending++;
        getJSON("/api/scan/" + sid).then(function (d) {
          if (d.status !== "done" && d.status !== "error") return;
          row.dataset.done = "1";
          var r = d.result || {};
          row.querySelector(".risk").textContent = r.risk_score == null ? "error" : r.risk_score;
          row.querySelector(".grade").textContent = r.grade || "";
          row.querySelector(".verdict").textContent = r.verdict || "";
        }).catch(function () {});
      });
      if (pending) setTimeout(tick, 1200);
    })();
  }
})();
