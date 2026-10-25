// Progressive enhancement only: every page works without this file.
(function () {
  "use strict";

  var TONES = {
    "Malicious": "crit", "Likely malicious": "high", "Suspicious": "med", "Clean": "ok", "Unverified": "info",
    "Dangerous": "crit", "Low risk": "low", "No signals found": "ok", "Error": "info"
  };

  function esc(s) {
    return String(s == null ? "" : s).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }

  function getJSON(url) {
    return fetch(url, { headers: { Accept: "application/json" }, credentials: "same-origin" })
      .then(function (r) { if (!r.ok) throw new Error(r.status); return r.json(); });
  }

  function badge(v) {
    return '<span class="badge t-' + (TONES[v] || "info") + '">' + esc(v || "—") + "</span>";
  }

  function riskbar(score, v) {
    if (score == null) return '<span class="mut">–</span>';
    return '<div class="riskbar t-' + (TONES[v] || "info") + '"><div class="b"><i style="width:' +
      Math.max(3, score) + '%"></i></div><span>' + esc(score) + "</span></div>";
  }

  // ---- copy buttons ----------------------------------------------------------------------
  document.addEventListener("click", function (e) {
    var btn = e.target.closest ? e.target.closest("[data-copy]") : null;
    if (!btn || !navigator.clipboard) return;
    navigator.clipboard.writeText(btn.dataset.copy).then(function () {
      btn.classList.add("done");
      setTimeout(function () { btn.classList.remove("done"); }, 1200);
    }).catch(function () { /* clipboard blocked: nothing to do */ });
  });

  // ---- check all / none ------------------------------------------------------------------
  document.querySelectorAll("[data-check-all],[data-check-none]").forEach(function (b) {
    b.addEventListener("click", function () {
      var name = b.dataset.checkAll || b.dataset.checkNone;
      var on = !!b.dataset.checkAll;
      document.querySelectorAll('input[type=checkbox][name="' + name + '"]').forEach(function (c) { c.checked = on; });
    });
  });

  // ---- scan form: input modes, drop zone, authorisation gate -----------------------------
  var form = document.getElementById("scan-form");
  if (form) {
    var mode = document.getElementById("mode");
    var modeButtons = form.querySelectorAll("[data-mode]");
    var panels = form.querySelectorAll("[data-panel]");
    function setMode(m) {
      mode.value = m;
      modeButtons.forEach(function (b) {
        b.classList.toggle("on", b.dataset.mode === m);
        b.setAttribute("aria-selected", b.dataset.mode === m ? "true" : "false");
      });
      panels.forEach(function (p) { p.classList.toggle("hidden", p.dataset.panel !== m); });
      var focus = form.querySelector('[data-panel="' + m + '"] input[type=text], [data-panel="' + m + '"] textarea');
      if (focus) focus.focus();
    }
    modeButtons.forEach(function (btn) {
      btn.addEventListener("click", function () { setMode(btn.dataset.mode); });
    });

    var zone = document.getElementById("dropzone");
    if (zone) {
      var input = zone.querySelector("input[type=file]");
      var chosen = document.getElementById("chosen");
      var show = function () { chosen.textContent = input.files && input.files[0] ? input.files[0].name : ""; };
      input.addEventListener("change", show);
      ["dragenter", "dragover"].forEach(function (ev) {
        zone.addEventListener(ev, function (e) { e.preventDefault(); zone.classList.add("over"); });
      });
      ["dragleave", "drop"].forEach(function (ev) {
        zone.addEventListener(ev, function () { zone.classList.remove("over"); });
      });
      zone.addEventListener("drop", function (e) {
        e.preventDefault();
        if (e.dataTransfer && e.dataTransfer.files.length) { input.files = e.dataTransfer.files; show(); }
      });
    }

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
      form.querySelectorAll(".scan-btn").forEach(function (btn) {
        btn.disabled = true;
        btn.innerHTML = '<span class="spinner"></span> Scanning';
      });
    });
  }

  // ---- result page while a scan runs: live check list, reload when finished -------------
  var progress = document.getElementById("progress");
  if (progress) {
    var id = progress.dataset.scanId;
    (function poll() {
      getJSON("/api/scan/" + encodeURIComponent(id)).then(function (d) {
        if (d.status === "done" || d.status === "error") { location.reload(); return; }
        var steps = d.progress || {};
        var rows = Object.keys(steps).map(function (k) {
          var s = steps[k];
          var meta = s.note || (s.status === "done" ? (s.findings ? s.findings + " finding" + (s.findings > 1 ? "s" : "") : "done") : s.status);
          var mark = s.status === "running" ? '<span class="spinner"></span>' : "";
          return '<li class="' + esc(s.status) + '"><span>' + esc(s.title) + '</span><span class="st">' + mark + esc(meta) + "</span></li>";
        }).join("");
        progress.innerHTML = rows || '<li class="running"><span>Starting</span><span class="st"><span class="spinner"></span></span></li>';
        setTimeout(poll, 900);
      }).catch(function () { setTimeout(poll, 2000); });
    })();
  }

  // ---- batch page: fill in each row as its scan finishes --------------------------------
  var batch = document.getElementById("batch");
  if (batch) {
    var ids = (batch.dataset.ids || "").split(",").filter(Boolean);
    (function tick() {
      var pending = 0;
      ids.forEach(function (sid) {
        var row = batch.querySelector('tr[data-id="' + sid + '"]');
        if (!row || row.dataset.done) return;
        pending++;
        getJSON("/api/scan/" + encodeURIComponent(sid)).then(function (d) {
          if (d.status !== "done" && d.status !== "error") return;
          row.dataset.done = "1";
          var r = d.result || {};
          row.querySelector(".risk").innerHTML = riskbar(r.risk_score, r.verdict);
          var grade = row.querySelector(".grade");
          if (grade) grade.textContent = r.grade || "";
          row.querySelector(".verdict").innerHTML = badge(r.verdict || "Error");
        }).catch(function () {});
      });
      if (pending) setTimeout(tick, 1200);
    })();
  }

  // ---- mail pages: follow the background Gmail job, reload when it ends ------------------
  var job = document.getElementById("mail-job");
  if (job && job.dataset.running) {
    (function watch() {
      getJSON(job.dataset.url).then(function (d) {
        if (!d.running) { location.reload(); return; }
        setTimeout(watch, 2000);
      }).catch(function () { setTimeout(watch, 4000); });
    })();
  }
})();
