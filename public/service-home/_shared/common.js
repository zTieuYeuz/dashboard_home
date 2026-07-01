/* ═══════════════════════════════════════════════
   common.js — shared behaviour for service-home pages (2026-07-01)
   ───────────────────────────────────────────────
   • Theme toggle (persists to localStorage 'dh_theme')
   • Live clock (#clock, vi-VN 24h)
   The initial theme is already applied pre-paint by the worker-injected
   head script; this only wires the toggle button + ticking clock.
   Defensive null-checks so pages without a #themeToggle/#clock still work.
   ═══════════════════════════════════════════════ */
(function () {
  // Apply saved theme (redundant safety net alongside the worker head script)
  try {
    var saved = localStorage.getItem('dh_theme');
    if (saved === 'light' || saved === 'dark') document.documentElement.dataset.theme = saved;
  } catch (e) {}

  var tgl = document.getElementById('themeToggle');
  if (tgl) {
    tgl.addEventListener('click', function () {
      var next = document.documentElement.dataset.theme === 'light' ? 'dark' : 'light';
      document.documentElement.dataset.theme = next;
      try { localStorage.setItem('dh_theme', next); } catch (e) {}
    });
  }

  var clk = document.getElementById('clock');
  if (clk) {
    var tick = function () {
      clk.textContent = new Date().toLocaleTimeString('vi-VN', { hour12: false });
    };
    tick();
    setInterval(tick, 1000);
  }
})();
