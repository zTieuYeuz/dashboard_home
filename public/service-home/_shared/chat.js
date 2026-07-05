/* ═══════════════════════════════════════════════
   OpenClaw Chat Widget — Dashboard floating speed-dial
   ---------------------------------------------------
   • One master FAB (bottom-right). Hover or tap → fans out two mini bubbles:
       – "Chuyển trang" → opens the wayfinding switcher (window.__wfOpen)
       – "OpenClaw"     → opens the chat sidebar
     This replaces the two overlapping bubbles (#wf-fab + old #oc-btn).
   • Chat panel = right-docked tall sidebar.
   • /oc/ is proxied same-origin → we reach iframe.contentDocument and prune
     OpenClaw's own chrome (top search bar, "context used" badge, model selector).
   ═══════════════════════════════════════════════ */
(function () {
  if (window.__aiSupportInit) return;   // idempotent — injected globally + maybe per-page
  window.__aiSupportInit = 1;

  var OC_ORIGIN    = 'https://openclaw-service.home-server.id.vn';  // "open in new tab" link
  var OC_APP       = '/oc/';   // same-origin reverse proxy (HTTP + WS) — no CORS
  var OC_TOKEN_API = '/api/openclaw-token';
  var TITLE        = 'AI Support System';

  /* Exact CSS selectors of OpenClaw internal UI to hide (same-origin iframe). */
  var OC_HIDE_SELECTORS = [
    '[data-chat-model-select]',
    '[data-chat-thinking-select]'
  ];

  /* ── Styles ── */
  var s = document.createElement('style');
  s.textContent = [
    /* Hide the standalone wayfinding FAB — we drive it from the speed-dial now */
    '#wf-fab{display:none!important}',

    /* Speed-dial container — pointer-events:none so the tall (closed) column
       never captures hover/clicks; only the master + open items are interactive. */
    '#oc-dial{position:fixed;right:22px;bottom:22px;z-index:9990;display:flex;flex-direction:column-reverse;align-items:flex-end;gap:12px;pointer-events:none}',

    /* Master button */
    '#oc-master{width:44px;height:44px;border-radius:50%;background:var(--accent,#7c83fc);border:none;cursor:pointer;pointer-events:auto;',
    'box-shadow:0 4px 16px rgba(0,0,0,.45);display:flex;align-items:center;justify-content:center;color:#fff;',
    'transition:transform .2s cubic-bezier(.34,1.56,.64,1),box-shadow .18s}',
    '#oc-master:hover{box-shadow:0 6px 22px rgba(0,0,0,.55)}',
    '#oc-master svg{transition:transform .25s cubic-bezier(.4,0,.2,1)}',
    '#oc-dial.oc-dopen #oc-master{transform:rotate(135deg)}',
    '#oc-dial.oc-dopen #oc-master svg{transform:rotate(-135deg)}',

    /* Sub bubbles + labels */
    '.oc-item{display:flex;align-items:center;gap:10px;',
    'opacity:0;transform:translateY(14px) scale(.5);pointer-events:none;',
    'transition:opacity .2s ease,transform .24s cubic-bezier(.34,1.56,.64,1)}',
    '#oc-dial.oc-dopen .oc-item{opacity:1;transform:none;pointer-events:auto}',
    '#oc-dial.oc-dopen .oc-item:nth-of-type(2){transition-delay:.05s}',
    '.oc-lbl{font:600 12px/1 inherit;color:var(--fg,#cdd6f4);background:var(--surface-2,#252535);',
    'border:1px solid var(--border,rgba(255,255,255,.12));padding:7px 11px;border-radius:8px;white-space:nowrap;',
    'box-shadow:0 3px 10px rgba(0,0,0,.35)}',
    '.oc-sub{width:40px;height:40px;border-radius:50%;border:1px solid var(--border,rgba(255,255,255,.14));',
    'background:var(--surface,#1e1e2e);color:var(--fg,#cdd6f4);cursor:pointer;display:flex;align-items:center;',
    'justify-content:center;box-shadow:0 4px 14px rgba(0,0,0,.4);transition:transform .15s,border-color .15s,background .15s;flex-shrink:0}',
    '.oc-sub:hover{transform:scale(1.1);border-color:var(--accent,#7c83fc);background:var(--surface-2,#252535)}',

    /* Chat panel — right-docked tall sidebar */
    '#oc-panel{position:fixed;top:16px;right:16px;bottom:16px;width:420px;max-width:calc(100vw - 32px);',
    'background:var(--surface,#1e1e2e);border-radius:16px;border:1px solid var(--border,rgba(255,255,255,.1));',
    'box-shadow:0 12px 40px rgba(0,0,0,.55);display:flex;flex-direction:column;overflow:hidden;',
    'z-index:9989;transform:translateX(18px) scale(.98);opacity:0;pointer-events:none;',
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
    '#oc-body{flex:1;position:relative;min-height:0}',
    '#oc-iframe{position:absolute;inset:0;border:none;width:100%;height:100%;background:var(--bg,#181825)}',
    /* Lớp phủ "đang kết nối" — che lúc iframe nạp lại (đổi trang / reconnect) cho đỡ giật */
    '#oc-loading{position:absolute;inset:0;z-index:2;display:flex;flex-direction:column;align-items:center;',
    'justify-content:center;gap:12px;background:var(--surface,#1e1e2e);color:var(--muted,#9399b2);',
    'font:500 13px/1.4 inherit;transition:opacity .35s ease;pointer-events:none}',
    '#oc-loading.oc-hide{opacity:0}',
    '#oc-loading .oc-spin{width:26px;height:26px;border-radius:50%;border:2.5px solid rgba(255,255,255,.15);',
    'border-top-color:var(--accent,#7c83fc);animation:oc-rot .8s linear infinite}',
    '@keyframes oc-rot{to{transform:rotate(360deg)}}',
    '@media(max-width:500px){#oc-panel{width:calc(100vw - 24px);top:12px;right:12px;bottom:78px}',
    '#oc-dial{right:14px;bottom:14px}}'
  ].join('');
  document.head.appendChild(s);

  var ICON_CHAT = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/></svg>';
  var ICON_NAV  = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="9"/><polygon points="16 8 10.5 10.5 8 16 13.5 13.5 16 8"/></svg>';
  var ICON_PLUS = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"><path d="M12 5v14M5 12h14"/></svg>';

  /* ── DOM ── */
  var dial = document.createElement('div');
  dial.id = 'oc-dial';
  dial.innerHTML =
    /* master (bottom, because column-reverse) */
    '<button id="oc-master" title="Điều hướng & trợ lý">' + ICON_PLUS + '</button>' +
    /* sub 2: OpenClaw */
    '<div class="oc-item"><span class="oc-lbl">' + TITLE + '</span>' +
      '<button class="oc-sub" id="oc-sub-chat" title="' + TITLE + '">' + ICON_CHAT + '</button></div>' +
    /* sub 1: page switcher */
    '<div class="oc-item"><span class="oc-lbl">Chuyển trang</span>' +
      '<button class="oc-sub" id="oc-sub-wf" title="Chuyển trang nhanh">' + ICON_NAV + '</button></div>';
  document.body.appendChild(dial);

  var panelWrap = document.createElement('div');
  panelWrap.innerHTML =
    '<div id="oc-panel">' +
      '<div id="oc-head">' +
        '<div id="oc-title">' + ICON_CHAT.replace('width="18" height="18"', 'width="16" height="16"') +
          TITLE +
        '</div>' +
        '<div style="display:flex;align-items:center;gap:4px">' +
          '<button id="oc-x" title="Đóng">&#10005;</button>' +
        '</div>' +
      '</div>' +
      '<div id="oc-body">' +
        '<div id="oc-loading"><div class="oc-spin"></div><div>Đang kết nối trợ lý…</div></div>' +
        '<iframe id="oc-iframe" src="about:blank" allow="microphone; camera; clipboard-read; clipboard-write"></iframe>' +
      '</div>' +
    '</div>';
  document.body.appendChild(panelWrap);

  var panel   = document.getElementById('oc-panel');
  var master  = document.getElementById('oc-master');
  var subChat = document.getElementById('oc-sub-chat');
  var subWf   = document.getElementById('oc-sub-wf');
  var xBtn    = document.getElementById('oc-x');
  var iframe  = document.getElementById('oc-iframe');
  var loading = document.getElementById('oc-loading');
  var opened  = false;
  var loaded  = false;
  function showLoading() { if (loading) loading.classList.remove('oc-hide'); }
  function hideLoading() { if (loading) loading.classList.add('oc-hide'); }

  /* ── Speed-dial open/close ──
     Desktop: opens only when the pointer actually enters the master button (or an
     already-open item), not the tall empty column above it. Touch: tap the master. */
  var _dialT;
  function dialToggle() { dial.classList.toggle('oc-dopen'); }
  function dialOpen()   { clearTimeout(_dialT); dial.classList.add('oc-dopen'); }
  function dialClose()  { clearTimeout(_dialT); dial.classList.remove('oc-dopen'); }
  function dialCloseSoon() { clearTimeout(_dialT); _dialT = setTimeout(function () { dial.classList.remove('oc-dopen'); }, 160); }
  master.addEventListener('click', dialToggle);
  master.addEventListener('mouseenter', dialOpen);
  master.addEventListener('mouseleave', dialCloseSoon);
  [].forEach.call(dial.querySelectorAll('.oc-item'), function (it) {
    it.addEventListener('mouseenter', dialOpen);
    it.addEventListener('mouseleave', dialCloseSoon);
  });
  document.addEventListener('click', function (e) { if (!dial.contains(e.target)) dialClose(); });

  /* ── Prune OpenClaw's own chrome inside the same-origin iframe ── */
  function injectHideStyle(doc) {
    if (!doc || doc.getElementById('dash-oc-hide')) return;
    var st = doc.createElement('style');
    st.id = 'dash-oc-hide';
    st.textContent = OC_HIDE_SELECTORS.length
      ? (OC_HIDE_SELECTORS.join(',') + '{display:none!important}')
      : '';
    (doc.head || doc.documentElement).appendChild(st);
  }

  function prune(doc) {
    if (!doc) return;
    try {
      var nodes = doc.querySelectorAll('div,span,p,button,section,footer,header,li');
      for (var i = 0; i < nodes.length; i++) {
        var el = nodes[i];
        if (el.__ocH) continue;
        var t = (el.textContent || '').replace(/\s+/g, ' ').trim();
        /* "N% context used 74.7k / 1M" badge */
        if (/context used/i.test(t) && t.length < 44) { el.style.setProperty('display', 'none', 'important'); el.__ocH = 1; continue; }
        /* Model selector "HomeAI · Off" */
        if (/home\s*ai/i.test(t) && t.length < 30) { el.style.setProperty('display', 'none', 'important'); el.__ocH = 1; continue; }
      }
      /* Top bar (hamburger ☰ + search "Tìm kiếm ⌘K") — find the search element,
         then hide the compact top ancestor that wraps it (covers hamburger too). */
      var search = null;
      var cand = doc.querySelectorAll('input[placeholder],button,div,span');
      for (var j = 0; j < cand.length; j++) {
        var el2 = cand[j];
        var ph = (el2.getAttribute && el2.getAttribute('placeholder')) || '';
        var tt = (el2.textContent || '').replace(/\s+/g, ' ').trim();
        if (/tìm kiếm|⌘k/i.test(ph) || (/⌘k/i.test(tt) && tt.length < 20)) { search = el2; break; }
      }
      if (search && !search.__ocBar) {
        var node = search, bar = null, hop = 0;
        while (node && node !== doc.body && hop < 6) {
          var h = node.getBoundingClientRect ? node.getBoundingClientRect().height : 999;
          if (h > 0 && h < 100) bar = node; else if (h >= 100) break;
          node = node.parentElement; hop++;
        }
        (bar || search).style.setProperty('display', 'none', 'important');
        search.__ocBar = 1;
      }
      /* Model-selector row + its empty wrapper (vùng dư dưới ô chat) — ẩn cả thanh chứa nó */
      var msel = doc.querySelectorAll('[data-chat-model-select]');
      for (var k = 0; k < msel.length; k++) {
        if (msel[k].__ocBar) continue;
        var mn = msel[k], mbar = null, mh = 0;
        while (mn && mn !== doc.body && mh < 5) {
          var hh = mn.getBoundingClientRect ? mn.getBoundingClientRect().height : 999;
          if (hh > 0 && hh < 72) mbar = mn; else if (hh >= 72) break;
          mn = mn.parentElement; mh++;
        }
        (mbar || msel[k]).style.setProperty('display', 'none', 'important');
        msel[k].__ocBar = 1;
      }
    } catch (e) { /* cross-origin or transient — ignore */ }
  }

  var _pruneT = 0;
  function pruneThrottled(doc) {
    var now = Date.now();
    if (now - _pruneT < 400) return;
    _pruneT = now;
    prune(doc);
    scanActions(doc);
  }

  /* ── Nav bridge (Phase 1): AI gives the user a dashboard link inside the chat;
     clicking it opens that page in the TOP window (runs as the logged-in user →
     the page's own permission check applies) and logs an audit entry. We never
     auto-navigate — the user must click. Only same-origin dashboard *.html pages,
     never OpenClaw's own /oc routes. ── */
  function wireNavBridge(doc) {
    if (!doc || doc.__ocNav) return;
    doc.__ocNav = 1;
    doc.addEventListener('click', function (e) {
      var a = e.target && e.target.closest ? e.target.closest('a[href]') : null;
      if (!a) return;
      var href = a.getAttribute('href') || '';
      var u; try { u = new URL(href, doc.baseURI); } catch (_) { return; }
      if (u.origin !== location.origin) return;              // only same-origin dashboard
      var path = u.pathname;
      if (path.indexOf('/oc') === 0) return;                 // not OpenClaw's own routes
      if (!(path === '/' || /\.html$/i.test(path))) return;  // only dashboard pages
      e.preventDefault();
      var dest = path + u.search + u.hash;
      try {
        fetch('/api/ai/action', {
          method: 'POST', credentials: 'include',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ action: 'navigate', target: dest }),
        });
      } catch (_) {}
      try { window.top.location.href = dest; } catch (_) { window.location.href = dest; }
    }, true);
  }

  /* ── Action bridge (Phase 2): AI in khối ```dash-action {json}``` → kiểm quyền
     theo user → xác nhận nếu nguy hiểm → chạy /api/ai/exec bằng phiên user → báo
     kết quả. AI KHÔNG có quyền riêng; user bị giới hạn thì AI cũng bị chặn. ── */
  var _aiActions = {}, _aiReads = {};
  var _dialogOpen = false, _lastDoc = null, _expectUntil = 0;
  function loadAiActions() {
    fetch('/api/ai/actions', { credentials: 'include' })
      .then(function (r) { return r.ok ? r.json() : { actions: [] }; })
      .then(function (d) { (d.actions || []).forEach(function (a) { _aiActions[a.id] = a; }); })
      .catch(function () {});
  }
  function loadAiReads() {
    fetch('/api/ai/reads', { credentials: 'include' })
      .then(function (r) { return r.ok ? r.json() : { reads: [] }; })
      .then(function (d) { (d.reads || []).forEach(function (a) { _aiReads[a.id] = a; }); })
      .catch(function () {});
  }
  /* Khối JSON còn stream dở (thiếu param bắt buộc) → chưa xử, đợi hoàn chỉnh. */
  function _actionComplete(o) {
    var meta = _aiActions[o.action];
    if (!meta) return false;
    var req = (meta.params || []).filter(function (p) { return p.required; });
    for (var i = 0; i < req.length; i++) {
      var v = (o.params || {})[req[i].name];
      if (v === undefined || v === null || v === '') return false;
    }
    return true;
  }
  /* Phân biệt LỊCH SỬ vs MỚI bằng tín hiệu NHÂN QUẢ, không dựa vào thời gian:
     một hành động chỉ được bung hộp nếu nó xuất hiện TRONG "cửa sổ mong đợi" —
     tức là NGAY SAU khi user vừa gửi 1 tin nhắn trong OpenClaw (mở cửa sổ 90s).
     Khi tải/reload/chuyển trang mà user KHÔNG gửi gì → không có cửa sổ → mọi khối
     (kể cả lịch sử render chậm) chỉ bị ẩn, TUYỆT ĐỐI không bung hộp.
     Kèm: 1 đơn vị <pre> xử 1 lần (chống 2 hộp), 1 hộp/lần, huỷ không lặp. */
  function _openExpectWindow() { _expectUntil = Date.now() + 90000; }
  /* Bắt sự kiện user GỬI tin trong iframe OpenClaw (same-origin): Enter (bàn phím)
     hoặc ô nhập từ có chữ → rỗng (bắt cả nút Send). Gắn 1 lần mỗi document. */
  function wireSendWatch(doc) {
    if (!doc || doc.__ocSendWatch) return;
    doc.__ocSendWatch = 1;
    doc.addEventListener('keydown', function (e) {
      if (e.key === 'Enter' && !e.shiftKey) {
        var el = e.target;
        if (el && (el.tagName === 'TEXTAREA' || el.isContentEditable)) _openExpectWindow();
      }
    }, true);
    var prev = '';
    setInterval(function () {
      try {
        var ta = doc.querySelector('textarea');
        var v = ta ? ta.value : '';
        if (prev && !v) _openExpectWindow();   // ô nhập vừa bị xoá sạch = đã gửi
        prev = v;
      } catch (_) {}
    }, 700);
  }
  function scanActions(doc) {
    if (!doc) return;
    _lastDoc = doc;
    var blocks; try { blocks = doc.querySelectorAll('code,pre'); } catch (_) { return; }
    for (var i = 0; i < blocks.length; i++) {
      var b = blocks[i];
      // Gộp về 1 ĐƠN VỊ = thẻ <pre> ngoài cùng, để <pre> và <code> lồng nhau (cùng
      // nội dung) KHÔNG bị xử 2 lần → tránh 1 yêu cầu bung 2 hộp.
      var unit = b.closest('pre') || b;
      if (unit.__ocDone) continue;                    // đơn vị này đã xử (chạy hoặc lịch sử) → bỏ
      var t = (b.textContent || '').trim();
      if (t.charAt(0) !== '{' || (t.indexOf('"action"') < 0 && t.indexOf('"source"') < 0)) continue;
      var o; try { o = JSON.parse(t); } catch (_) { continue; }
      if (!o || (!o.action && !o.source)) continue;
      var isRead = !o.action && !!o.source;           // khối dash-read (đọc dữ liệu)
      // ẩn CẢ khung code (nhãn dash-action/dash-read + nút Sao chép), không chỉ <pre>
      try {
        var target = (unit.parentElement && unit.parentElement.childElementCount <= 4) ? unit.parentElement : unit;
        target.style.setProperty('display', 'none', 'important');
      } catch (_) {}
      if (Date.now() > _expectUntil) { unit.__ocDone = 1; continue; }  // ngoài cửa sổ = lịch sử → chỉ ẩn
      if (isRead) {                                    // ĐỌC: không hỏi xác nhận, chạy ngay
        unit.__ocDone = 1;
        handleAiReadRequest(o);
        continue;
      }
      if (!_actionComplete(o)) continue;              // JSON dở / thiếu param bắt buộc → đợi (chưa gắn cờ)
      if (_dialogOpen) continue;                       // 1 hộp/lần: để lần sau (chưa gắn cờ)
      unit.__ocDone = 1;                               // gắn cờ NGAY khi hiện → huỷ cũng không lặp
      handleAiActionRequest(o);
    }
  }
  function _userAllowsPerm(perm) {
    var U = window.__USER__ || {};
    if (U.isAdmin) return true;
    if (!perm) return true;
    var lvl = (U.permissions || {})[perm];
    return !!lvl && lvl !== 'none';
  }
  /* ĐỌC dữ liệu per-user: chạy /api/ai/read bằng cookie user; handler tự chặn theo
     quyền. Trả dữ liệu về chat cho AI trả lời. Thiếu quyền → báo user bị giới hạn. */
  function handleAiReadRequest(o) {
    var meta = _aiReads[o.source];
    if (!meta) { feedResultToAi('[ĐỌC] Nguồn "' + o.source + '" không tồn tại. Đừng bịa dữ liệu; nếu cần hãy dùng nguồn hợp lệ hoặc ghi log_unresolved.'); return; }
    if (!_userAllowsPerm(meta.perm)) {
      aiNotice('⛔ Bạn không có quyền xem: ' + meta.label, true);
      feedResultToAi('[ĐỌC] Người dùng KHÔNG có quyền xem "' + meta.label + '". Hãy báo họ bị giới hạn quyền này, KHÔNG bịa dữ liệu.');
      return;
    }
    aiNotice('⏳ Đang đọc: ' + meta.label + '…');
    fetch('/api/ai/read', {
      method: 'POST', credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ source: o.source }),
    }).then(function (r) { return r.json(); }).then(function (d) {
      if (d.ok) {
        var js; try { js = JSON.stringify(d.data); } catch (_) { js = ''; }
        if (js.length > 6000) js = js.slice(0, 6000) + '…(đã cắt bớt)';
        feedResultToAi('[DỮ LIỆU: ' + meta.label + '] ' + js + '\n\nHãy dùng dữ liệu này trả lời người dùng bằng tiếng Việt, ngắn gọn. KHÔNG bịa thêm.');
      } else if (d.denied) {
        aiNotice('⛔ ' + (d.error || 'Không có quyền'), true);
        feedResultToAi('[ĐỌC] ' + (d.error || 'Không có quyền xem nguồn này.'));
      } else {
        feedResultToAi('[ĐỌC] Không lấy được "' + meta.label + '": ' + (d.error || 'lỗi') + '. Hãy báo người dùng, đừng bịa.');
      }
    }).catch(function () { aiNotice('⚠️ Lỗi kết nối khi đọc dữ liệu.', true); });
  }
  function _userAllows(meta) {
    var U = window.__USER__ || {};
    if (U.isAdmin) return true;
    if (meta.adminOnly) return false;
    if (!meta.perm) return true;
    var lvl = (U.permissions || {})[meta.perm];
    return !!lvl && lvl !== 'none';
  }
  function handleAiActionRequest(o) {
    var meta = _aiActions[o.action];
    if (!meta) return;
    if (!_userAllows(meta)) {
      aiNotice('⛔ Bạn không có quyền: ' + meta.label + ' (cần quyền ' + (meta.perm || 'admin') + '). AI làm thay bạn nên cũng không thể.', true);
      return;
    }
    if (meta.danger === 'confirm') aiConfirm(meta, o.params || {}, function () { execAiAction(o, meta); });
    else execAiAction(o, meta);
  }
  function execAiAction(o, meta) {
    aiNotice('⏳ Đang thực hiện: ' + meta.label + '…');
    fetch('/api/ai/exec', {
      method: 'POST', credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action: o.action, params: o.params || {} }),
    }).then(function (r) { return r.json(); }).then(function (d) {
      var pstr = '';
      try { var pk = Object.keys(o.params || {}); if (pk.length) pstr = ' (' + pk.map(function (k) { return k + '=' + o.params[k]; }).join(', ') + ')'; } catch (_) {}
      if (d.ok) {
        aiNotice('✅ Đã làm: ' + (d.label || meta.label));
        feedResultToAi('[KẾT QUẢ HÀNH ĐỘNG] "' + (d.label || meta.label) + '"' + pstr + ' đã chạy THÀNH CÔNG. Hãy xác nhận ngắn gọn với người dùng bằng tiếng Việt, KHÔNG phát sinh thêm hành động.');
      } else {
        aiNotice('⚠️ ' + (d.error || 'Không thực hiện được'), true);
        feedResultToAi('[KẾT QUẢ HÀNH ĐỘNG] "' + meta.label + '"' + pstr + ' THẤT BẠI: ' + (d.error || 'không rõ lý do') + '. Hãy báo người dùng bằng tiếng Việt, KHÔNG tự thử lại.');
      }
    }).catch(function () { aiNotice('⚠️ Lỗi kết nối khi thực hiện.', true); });
  }

  /* Đẩy 1 câu kết quả NGƯỢC vào ô nhập của OpenClaw (iframe same-origin) rồi gửi,
     để AI biết hành động đã chạy ra sao và phản hồi lại người dùng. Bọc try/catch:
     nếu OpenClaw đổi DOM → im lặng thất bại, toast phía trên vẫn báo cho người dùng. */
  var _feedBusy = false;
  function feedResultToAi(text) {
    if (_feedBusy) return; _feedBusy = true;
    setTimeout(function () { _feedBusy = false; }, 1500);   // gộp nhiều kết quả sát nhau
    try {
      var win = iframe.contentWindow, doc = iframe.contentDocument;
      if (!win || !doc) return;
      var ta = doc.querySelector('textarea');
      if (!ta) {
        var ce = doc.querySelector('[contenteditable="true"]');
        if (!ce) return;
        ce.focus();
        try { doc.execCommand('insertText', false, text); } catch (_) { ce.textContent = text; }
        _sendEnter(win, ce); return;
      }
      var desc = Object.getOwnPropertyDescriptor(win.HTMLTextAreaElement.prototype, 'value');
      if (desc && desc.set) desc.set.call(ta, text); else ta.value = text;
      ta.dispatchEvent(new win.Event('input', { bubbles: true }));
      ta.focus();
      _sendEnter(win, ta);
    } catch (_) { /* OpenClaw DOM đổi — bỏ qua, đã có toast */ }
  }
  function _sendEnter(win, el) {
    setTimeout(function () {
      try {
        var opt = { key: 'Enter', code: 'Enter', keyCode: 13, which: 13, bubbles: true, cancelable: true };
        el.dispatchEvent(new win.KeyboardEvent('keydown', opt));
        el.dispatchEvent(new win.KeyboardEvent('keyup', opt));
      } catch (_) {}
    }, 60);
  }
  function aiNotice(msg, isWarn) {
    var n = document.createElement('div');
    n.textContent = msg;
    n.style.cssText = 'position:fixed;bottom:92px;right:22px;z-index:100000;max-width:320px;padding:11px 14px;border-radius:10px;font:500 13px/1.5 system-ui,sans-serif;color:#fff;background:' + (isWarn ? '#b4462f' : '#2c7a4b') + ';box-shadow:0 6px 20px rgba(0,0,0,.4)';
    document.body.appendChild(n);
    setTimeout(function () { n.style.transition = 'opacity .4s'; n.style.opacity = '0'; setTimeout(function () { n.remove(); }, 400); }, 4500);
  }
  function aiConfirm(meta, params, onOk) {
    if (_dialogOpen) return;                 // đã có 1 hộp đang mở → không chồng thêm
    _dialogOpen = true;
    function _done() { _dialogOpen = false; setTimeout(function () { scanActions(_lastDoc); }, 50); }
    var ov = document.createElement('div');
    ov.style.cssText = 'position:fixed;inset:0;z-index:100001;background:rgba(0,0,0,.55);display:flex;align-items:center;justify-content:center;padding:20px';
    var box = document.createElement('div');
    box.style.cssText = 'background:var(--surface,#1e1e2e);color:var(--fg,#eee);border:1px solid rgba(255,255,255,.14);border-radius:14px;max-width:400px;width:100%;padding:20px;font-family:system-ui,sans-serif';
    function line(txt, css) { var e = document.createElement('div'); e.textContent = txt; e.style.cssText = css; return e; }
    box.appendChild(line('⚠️ AI muốn thực hiện', 'font-size:15px;font-weight:700;margin-bottom:8px'));
    box.appendChild(line(meta.label, 'font-size:14px;margin-bottom:4px'));
    if (meta.desc) box.appendChild(line(meta.desc, 'font-size:12px;color:#aaa;margin-bottom:6px'));
    var pk = Object.keys(params || {});
    if (pk.length) {
      // Object lồng (vd data của biểu mẫu) → liệt kê từng dòng cho user soát kỹ trước khi Đồng ý
      var parts = [];
      pk.forEach(function (k) {
        var v = params[k];
        if (v && typeof v === 'object') {
          Object.keys(v).forEach(function (k2) { parts.push(k2 + ' = ' + v[k2]); });
        } else parts.push(k + ' = ' + v);
      });
      var pv = document.createElement('div');
      pv.style.cssText = 'font-size:12px;color:#bbb;font-family:monospace;margin-bottom:6px;max-height:180px;overflow:auto;background:rgba(255,255,255,.05);border-radius:8px;padding:8px 10px;white-space:pre-wrap';
      pv.textContent = parts.join('\n');
      box.appendChild(pv);
    }
    var row = document.createElement('div'); row.style.cssText = 'display:flex;gap:8px;justify-content:flex-end;margin-top:14px';
    var cancel = document.createElement('button'); cancel.textContent = 'Huỷ'; cancel.style.cssText = 'padding:8px 16px;border-radius:8px;border:1px solid rgba(255,255,255,.2);background:transparent;color:inherit;cursor:pointer';
    var ok = document.createElement('button'); ok.textContent = 'Đồng ý'; ok.style.cssText = 'padding:8px 16px;border-radius:8px;border:none;background:#b4462f;color:#fff;cursor:pointer;font-weight:600';
    cancel.onclick = function () { ov.remove(); _done(); };
    ok.onclick = function () { ov.remove(); _done(); onOk(); };
    row.appendChild(cancel); row.appendChild(ok); box.appendChild(row);
    ov.appendChild(box);
    ov.addEventListener('click', function (e) { if (e.target === ov) { ov.remove(); _done(); } });
    document.body.appendChild(ov);
  }
  loadAiActions();
  loadAiReads();

  function watchIframe() {
    var doc;
    try { doc = iframe.contentDocument; } catch (e) { return; }
    if (!doc || !doc.body) return;
    injectHideStyle(doc);
    prune(doc);
    wireNavBridge(doc);
    wireSendWatch(doc);
    scanActions(doc);
    try {
      var mo = new MutationObserver(function () { pruneThrottled(doc); });
      mo.observe(doc.body, { childList: true, subtree: true });
    } catch (e) { /* ignore */ }
  }

  iframe.addEventListener('load', function () {
    if (iframe.src && iframe.src.indexOf('about:blank') < 0) {
      // OpenClaw đã nạp xong → ẩn lớp phủ (chờ 1 nhịp cho SPA vẽ giao diện)
      setTimeout(hideLoading, 700);
    }
    setTimeout(watchIframe, 300);
    setTimeout(function () { prune(iframe.contentDocument); }, 1200);
    setTimeout(function () { prune(iframe.contentDocument); }, 3000);
  });

  /* Mỗi user dashboard = 1 SESSION OpenClaw riêng (`dash-<username>`), truyền qua
     hash `#session=` (Control UI hỗ trợ sẵn). Nếu chỉ truyền token mà không truyền
     session, SPA ép mọi người về session "main" → nhiều user/tab chat chung 1 kênh
     → lỗi "reply session initialization conflicted" + lộ lịch sử của nhau. */
  function _userKey() {
    var U = window.__USER__ || {};
    var n = U.username;
    if (!n) {
      try {
        var m = document.cookie.match(/(?:^|;\s*)dh_user=([^;]+)/);
        if (m) n = (JSON.parse(decodeURIComponent(m[1])) || {}).username;
      } catch (_) {}
    }
    n = (n || 'guest').toString().toLowerCase().replace(/[^a-z0-9_-]/g, '-').slice(0, 40);
    return 'dash-' + n;
  }
  function buildSrc(token) {
    var src = OC_APP + '#session=' + encodeURIComponent(_userKey());
    if (token) src += '&token=' + encodeURIComponent(token);
    return src;
  }

  function openChat() {
    opened = true;
    dialClose();
    panel.classList.add('oc-on');
    try { sessionStorage.setItem('ai_panel_open', '1'); } catch (_) {}
    if (!loaded) {
      loaded = true;
      showLoading();
      fetch(OC_TOKEN_API, { credentials: 'include' })
        .then(function (r) { return r.ok ? r.json() : {}; })
        .then(function (cfg) { iframe.src = buildSrc(cfg && cfg.token ? cfg.token : ''); })
        .catch(function () { iframe.src = buildSrc(''); });
    }
  }
  function closeChat() {
    opened = false;
    panel.classList.remove('oc-on');
    try { sessionStorage.removeItem('ai_panel_open'); } catch (_) {}
  }

  subChat.addEventListener('click', function () { if (opened) closeChat(); else openChat(); });
  subWf.addEventListener('click', function () {
    dialClose();
    if (window.__wfOpen) window.__wfOpen();
  });
  xBtn.addEventListener('click', closeChat);

  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape') { if (opened) closeChat(); dialClose(); }
  });

  /* Persist across navigation: if the panel was open before navigating, reopen it
     so the assistant stays visible until the user explicitly closes it. */
  try { if (sessionStorage.getItem('ai_panel_open') === '1') openChat(); } catch (_) {}
})();
