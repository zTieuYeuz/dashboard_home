/* ═══════════════════════════════════════════════
   OpenClaw Chat Widget — Dashboard floating bubble
   Iframes OpenClaw Control UI DIRECTLY (same-origin SPA → no CORS).
   Requires a Cloudflare Transform Rule on openclaw-service.home-server.id.vn
   that replaces X-Frame-Options with CSP frame-ancestors allowing the dashboard.
   Gateway token is fetched from /api/openclaw-token (session-gated) and passed
   via the URL hash so OpenClaw auto-authenticates.
   ═══════════════════════════════════════════════ */
(function () {
  var OC_ORIGIN    = 'https://openclaw-service.home-server.id.vn';  // "open in new tab" link
  var OC_APP       = '/oc/';   // same-origin reverse proxy (HTTP + WS) — no CORS
  var OC_TOKEN_API = '/api/openclaw-token';

  /* ── Styles ── */
  var s = document.createElement('style');
  s.textContent = [
    '#oc-wrap{position:fixed;bottom:24px;right:24px;z-index:9990}',
    '#oc-btn{width:52px;height:52px;border-radius:50%;background:var(--accent,#7c83fc);border:none;cursor:pointer;box-shadow:0 4px 16px rgba(0,0,0,.45);transition:transform .18s,box-shadow .18s;display:flex;align-items:center;justify-content:center}',
    '#oc-btn:hover{transform:scale(1.08);box-shadow:0 6px 22px rgba(0,0,0,.55)}',
    '#oc-panel{position:fixed;bottom:88px;right:24px;width:400px;height:600px;',
    'background:var(--surface,#1e1e2e);border-radius:16px;border:1px solid var(--border,rgba(255,255,255,.1));',
    'box-shadow:0 12px 40px rgba(0,0,0,.55);display:flex;flex-direction:column;overflow:hidden;',
    'z-index:9989;transform:translateY(14px) scale(.97);opacity:0;pointer-events:none;',
    'transition:transform .22s cubic-bezier(.4,0,.2,1),opacity .22s}',
    '#oc-panel.oc-on{transform:none;opacity:1;pointer-events:all}',
    '#oc-head{display:flex;align-items:center;justify-content:space-between;padding:11px 15px;',
    'background:var(--surface-2,#252535);border-bottom:1px solid var(--border,rgba(255,255,255,.08));flex-shrink:0}',
    '#oc-title{display:flex;align-items:center;gap:7px;color:var(--fg,#cdd6f4);font-size:13px;font-weight:600;font-family:inherit}',
    '#oc-open-btn{background:none;border:none;color:var(--muted,#9399b2);cursor:pointer;font-size:13px;',
    'padding:3px 7px;border-radius:6px;transition:background .15s;text-decoration:none;white-space:nowrap}',
    '#oc-open-btn:hover{background:rgba(255,255,255,.09);color:var(--fg,#cdd6f4)}',
    '#oc-x{background:none;border:none;color:var(--muted,#9399b2);cursor:pointer;font-size:17px;',
    'line-height:1;padding:3px 7px;border-radius:6px;transition:background .15s}',
    '#oc-x:hover{background:rgba(255,255,255,.09);color:var(--fg,#cdd6f4)}',
    '#oc-iframe{flex:1;border:none;width:100%;background:var(--bg,#181825)}',
    '@media(max-width:500px){#oc-panel{width:calc(100vw - 28px);height:74vh;right:14px;bottom:78px}',
    '#oc-wrap{right:14px;bottom:14px}}'
  ].join('');
  document.head.appendChild(s);

  /* ── DOM ── */
  var wrap = document.createElement('div');
  wrap.id = 'oc-wrap';
  wrap.innerHTML =
    '<div id="oc-panel">' +
      '<div id="oc-head">' +
        '<div id="oc-title">' +
          '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2">' +
          '<path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/></svg>' +
          'OpenClaw Assistant' +
        '</div>' +
        '<div style="display:flex;align-items:center;gap:4px">' +
          '<a id="oc-open-btn" href="' + OC_ORIGIN + '/" target="_blank" title="Mở tab mới">&#8599;</a>' +
          '<button id="oc-x" title="Đóng">&#10005;</button>' +
        '</div>' +
      '</div>' +
      '<iframe id="oc-iframe" src="about:blank" allow="microphone; camera; clipboard-read; clipboard-write"></iframe>' +
    '</div>' +
    '<button id="oc-btn" title="OpenClaw AI Assistant">' +
      '<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="2">' +
      '<path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/></svg>' +
    '</button>';
  document.body.appendChild(wrap);

  var panel  = document.getElementById('oc-panel');
  var btn    = document.getElementById('oc-btn');
  var xBtn   = document.getElementById('oc-x');
  var iframe = document.getElementById('oc-iframe');
  var opened = false;
  var loaded = false;

  function buildSrc(token) {
    /* SPA connects the gateway WebSocket same-origin under /oc (Worker proxies
       it through to openclaw-service); only the auth token is needed via hash. */
    var src = OC_APP;
    if (token) src += '#token=' + encodeURIComponent(token);
    return src;
  }

  function open() {
    opened = true;
    panel.classList.add('oc-on');
    if (!loaded) {
      loaded = true;
      fetch(OC_TOKEN_API, { credentials: 'include' })
        .then(function (r) { return r.ok ? r.json() : {}; })
        .then(function (cfg) { iframe.src = buildSrc(cfg && cfg.token ? cfg.token : ''); })
        .catch(function () { iframe.src = buildSrc(''); });
    }
  }
  function close() {
    opened = false;
    panel.classList.remove('oc-on');
  }
  function toggle() { if (opened) close(); else open(); }

  btn.addEventListener('click', toggle);
  xBtn.addEventListener('click', close);

  /* Esc key đóng panel */
  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape' && opened) close();
  });
})();
