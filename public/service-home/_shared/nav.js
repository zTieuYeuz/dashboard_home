/* ═══════════════════════════════════════════════
   nav.js — NGUỒN DUY NHẤT cho thanh nav trên MỌI trang (2026-07-11).
   ───────────────────────────────────────────────
   Mỗi trang chỉ cần đặt <nav class="topnav" id="sh-topnav"></nav> +
   <script src="/service-home/_shared/nav.js"></script>. nav.js dựng link.

   RBAC-aware: CHỈ hiện link user được phép (đọc window.__USER__).
   ⚠ AN NINH THẬT do SERVER gate (_PAGE_PERM + _ADMIN_ONLY_PAGES trong
   worker.js injectUser) — nav chỉ là bề mặt UX. Ẩn link KHÔNG thay cho gate:
   khi thêm trang mới PHẢI thêm cả (a) rule ở LINKS đây, (b) gate ở worker.

   Thêm mục nav: thêm 1 dòng vào LINKS với rule:
     'all'         = mọi user đã đăng nhập
     'admin'       = chỉ admin  (phải kèm _ADMIN_ONLY_PAGES ở worker)
     '<permKey>'   = cần quyền đó != none (phải kèm _PAGE_PERM ở worker)

   Settings emit sẵn (ẩn) — worker.js reveal cho mọi user (trang settings
   phục vụ hồ sơ/MFA của chính user, không gate).
   ═══════════════════════════════════════════════ */
(function () {
  var mount = document.getElementById('sh-topnav');
  if (!mount) return;

  var U = (window.__USER__ && typeof window.__USER__ === 'object') ? window.__USER__ : {};
  var isAdmin = !!(U.isAdmin || U.role === 'admin');
  var perms = (U.permissions && typeof U.permissions === 'object') ? U.permissions : {};
  function can(key) { return isAdmin || (perms[key] && perms[key] !== 'none'); }

  var LINKS = [
    { href: '/',                                 label: 'Overview',  rule: 'all' },
    { href: '/noc.html',                         label: '📡 NOC', rule: 'admin', id: 'noc-link' },
    { href: '/bookmarks.html',                   label: 'Bookmarks', rule: 'all' },
    { href: '/service-home/services-embed.html', label: 'Services',  rule: 'services-hub' }
  ];

  var path = location.pathname;
  var html = LINKS.filter(function (l) {
    if (l.rule === 'all')   return true;
    if (l.rule === 'admin') return isAdmin;
    return can(l.rule);
  }).map(function (l) {
    var active = (path === l.href) ? ' active' : '';
    var idAttr = l.id ? ' id="' + l.id + '"' : '';
    return '<a class="topnav-item' + active + '"' + idAttr + ' href="' + l.href + '">' + l.label + '</a>';
  }).join('');

  // Settings — mọi user (tự quản hồ sơ/MFA). Ẩn sẵn, worker.js reveal.
  var sActive = (path === '/settings.html') ? ' active' : '';
  html += '<a class="topnav-item' + sActive + '" id="settings-link" href="/settings.html" style="display:none">⚙ Settings</a>';

  mount.innerHTML = html;
})();
