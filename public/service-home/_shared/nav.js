/* ═══════════════════════════════════════════════
   Shared top navigation — service-home pages ONLY
   ───────────────────────────────────────────────
   Renders the primary nav links into the placeholder
   <nav class="topnav" id="sh-topnav"></nav> that each
   service-home page provides.

   The link matching the current URL is marked `.active`
   (so /service-home/services-embed.html highlights "Services").

   The ⚙ Settings link is emitted hidden by default;
   worker.js injects a head script that reveals it for admins
   (see worker.js — "Auto-inject Settings link"). We keep the
   element here so the worker just flips its display instead of
   creating it, and there is no duplicate.

   Loaded synchronously right after the placeholder so the nav
   is populated during parse (no visible flash).
   ═══════════════════════════════════════════════ */
(function () {
  var mount = document.getElementById('sh-topnav');
  if (!mount) return;

  var path = location.pathname;
  var links = [
    { href: '/', label: 'Overview' },
    { href: '/bookmarks.html', label: 'Bookmarks' },
    { href: '/service-home/services-embed.html', label: 'Services' }
  ];

  var html = links.map(function (l) {
    var active = (path === l.href) ? ' active' : '';
    return '<a class="topnav-item' + active + '" href="' + l.href + '">' + l.label + '</a>';
  }).join('');

  // Hidden by default — worker.js reveals for admins.
  html += '<a class="topnav-item" id="settings-link" href="/settings.html" style="display:none">⚙ Settings</a>';

  mount.innerHTML = html;
})();
