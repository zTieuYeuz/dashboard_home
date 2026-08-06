/* ═══════════════════════════════════════════════════════════════════════════
   dash-ssh — phía trình duyệt: NHIỀU phiên SSH song song + trợ lý AI
   ───────────────────────────────────────────────────────────────────────────
   Trang này do chính server.js phục vụ tại 127.0.0.1 nên MỌI THỨ cùng nguồn gốc
   — không dính chặn nội dung hỗn hợp / Private Network Access như khi nhúng từ
   dashboard. Xem đầu server.js để biết vì sao chọn cách này.

   NHIỀU TAB: mỗi tab = 1 WebSocket riêng = 1 phiên SSH riêng. Phía server không
   cần sửa gì — `wss.on('connection')` vốn đã tạo `conn`/`stream` riêng cho từng
   kết nối, nên N tab là N phiên độc lập, tab này rớt không ảnh hưởng tab kia.

   ⚠️ BẪY xterm.js: gọi fit() khi phần tử đang display:none sẽ đo ra kích thước
   RÁC (thường 0) → terminal vỡ layout khi bấm sang tab đó. Nên fit() LUÔN được
   gọi SAU khi tab đã hiện (xem activate()), không bao giờ gọi lúc tab còn ẩn.

   Che mật khẩu (redact) và đọc màn hình (readVisibleScreen) dùng CHUNG bộ luật
   với public/service-home/console-serial.html của dashboard — sửa một bên thì
   nhớ sửa bên kia, đừng để lệch.
   ═══════════════════════════════════════════════════════════════════════════ */
(function () {
'use strict';

/* Mã ghép nối nằm trong URL người dùng mở. Xử lý 3 việc, theo đúng thứ tự:
     1. Lấy từ URL (lần mở đầu tiên).
     2. Cất vào sessionStorage — BẮT BUỘC, nếu không thì bấm F5 là mất token và
        mọi thứ hỏng (đã dính lỗi này lúc kiểm thử). sessionStorage sống theo
        TAB trình duyệt: đóng tab là mất, không rơi vãi sang phiên sau.
     3. Xoá khỏi thanh địa chỉ, để lỡ chụp màn hình/quay video thì không lộ. */
  /* ── Mã ghép nối + cổng cầu nối ──────────────────────────────────────────
     Trang này chạy trên dashboard (HTTPS) nhưng mở WebSocket tới ws://127.0.0.1.
     Trình duyệt KHÔNG chặn: loopback được chuẩn Secure Contexts coi là nguồn
     đáng tin nên không tính là nội dung hỗn hợp.
     Token do anh dán 1 lần (chương trình dash-ssh in ra), nhớ trong localStorage. */
  var TOKEN = '', BRIDGE_PORT = 8022;
  try {
    TOKEN = localStorage.getItem('sshfield_tok') || '';
    BRIDGE_PORT = parseInt(localStorage.getItem('sshfield_port'), 10) || 8022;
  } catch (e) {}
  window.__sshfieldSave = function (t, p) {
    TOKEN = (t || '').trim(); BRIDGE_PORT = parseInt(p, 10) || 8022;
    try {
      localStorage.setItem('sshfield_tok', TOKEN);
      localStorage.setItem('sshfield_port', String(BRIDGE_PORT));
    } catch (e) {}
  };
  window.__sshfieldTok  = function () { return TOKEN; };
  window.__sshfieldPort = function () { return BRIDGE_PORT; };

var $ = function (id) { return document.getElementById(id); };

var RAW_MAX = 400000;

/* ══════════ Bộ màu terminal ══════════════════════════════════════════════
   6 kiểu quen thuộc nhất với dân kỹ thuật. Mỗi kiểu khai đủ 16 màu ANSI chứ
   không chỉ nền/chữ — thiết bị mạng in ra rất nhiều màu ANSI (Cisco, FortiGate),
   thiếu bảng 16 màu thì mỗi kiểu nhìn vẫn y hệt nhau ở phần quan trọng nhất. */
var THEMES = {
  dark: { name:'Tối (mặc định)', dark:true, t:{
    background:'#0f1216', foreground:'#e6edf3', cursor:'#3b82f6', selectionBackground:'#2a4a7a',
    black:'#1c2128', red:'#f87171', green:'#4ade80', yellow:'#fbbf24', blue:'#60a5fa',
    magenta:'#c084fc', cyan:'#22d3ee', white:'#e6edf3', brightBlack:'#6b7280', brightRed:'#fca5a5',
    brightGreen:'#86efac', brightYellow:'#fde047', brightBlue:'#93c5fd', brightMagenta:'#d8b4fe',
    brightCyan:'#67e8f9', brightWhite:'#ffffff' } },
  light: { name:'Sáng', dark:false, t:{
    background:'#ffffff', foreground:'#1a2029', cursor:'#2563eb', selectionBackground:'#bcd4f0',
    black:'#1a2029', red:'#c62828', green:'#2e7d32', yellow:'#a06000', blue:'#1565c0',
    magenta:'#7b1fa2', cyan:'#00838f', white:'#5b6472', brightBlack:'#8892a0', brightRed:'#e53935',
    brightGreen:'#43a047', brightYellow:'#c77800', brightBlue:'#1e88e5', brightMagenta:'#8e24aa',
    brightCyan:'#00acc1', brightWhite:'#1a2029' } },
  solarized: { name:'Solarized Dark', dark:true, t:{
    background:'#002b36', foreground:'#93a1a1', cursor:'#93a1a1', selectionBackground:'#073642',
    black:'#073642', red:'#dc322f', green:'#859900', yellow:'#b58900', blue:'#268bd2',
    magenta:'#d33682', cyan:'#2aa198', white:'#eee8d5', brightBlack:'#586e75', brightRed:'#cb4b16',
    brightGreen:'#586e75', brightYellow:'#657b83', brightBlue:'#839496', brightMagenta:'#6c71c4',
    brightCyan:'#93a1a1', brightWhite:'#fdf6e3' } },
  monokai: { name:'Monokai', dark:true, t:{
    background:'#272822', foreground:'#f8f8f2', cursor:'#f8f8f0', selectionBackground:'#49483e',
    black:'#272822', red:'#f92672', green:'#a6e22e', yellow:'#f4bf75', blue:'#66d9ef',
    magenta:'#ae81ff', cyan:'#a1efe4', white:'#f8f8f2', brightBlack:'#75715e', brightRed:'#fd5ff0',
    brightGreen:'#cfff87', brightYellow:'#ffe792', brightBlue:'#9bedff', brightMagenta:'#d0b3ff',
    brightCyan:'#c7fff9', brightWhite:'#ffffff' } },
  dracula: { name:'Dracula', dark:true, t:{
    background:'#282a36', foreground:'#f8f8f2', cursor:'#ff79c6', selectionBackground:'#44475a',
    black:'#21222c', red:'#ff5555', green:'#50fa7b', yellow:'#f1fa8c', blue:'#bd93f9',
    magenta:'#ff79c6', cyan:'#8be9fd', white:'#f8f8f2', brightBlack:'#6272a4', brightRed:'#ff6e6e',
    brightGreen:'#69ff94', brightYellow:'#ffffa5', brightBlue:'#d6acff', brightMagenta:'#ff92df',
    brightCyan:'#a4ffff', brightWhite:'#ffffff' } },
  matrix: { name:'Xanh lá cổ điển', dark:true, t:{
    background:'#000000', foreground:'#33ff66', cursor:'#33ff66', selectionBackground:'#0f5132',
    black:'#0b0b0b', red:'#ff5f5f', green:'#33ff66', yellow:'#c8ff4d', blue:'#39d0a0',
    magenta:'#7fffbf', cyan:'#66ffb2', white:'#b6ffcf', brightBlack:'#2f6b45', brightRed:'#ff8787',
    brightGreen:'#7cff9e', brightYellow:'#e6ff8a', brightBlue:'#6fe8c4', brightMagenta:'#a8ffd6',
    brightCyan:'#99ffd1', brightWhite:'#ecfff3' } },
};
var THEME_KEY = 'dark';

/* ══════════ Quản lý nhiều phiên ══════════ */
var sessions = [];      /* {id,label,host,term,fit,ws,connected,raw,wrap,tabEl,dotEl} */
var activeId = null;
var seq = 0;

function byId(id) { for (var i = 0; i < sessions.length; i++) if (sessions[i].id === id) return sessions[i]; return null; }
function active() { return byId(activeId); }

function themeNow() { return (THEMES[THEME_KEY] || THEMES.dark).t; }

/* Đổi bộ màu terminal, đồng thời kéo cả trang sáng/tối theo cho khỏi chỏi:
   terminal Solarized Dark nằm trong trang trắng toát nhìn rất chướng. */
function applyTheme(key) {
  if (!THEMES[key]) key = 'dark';
  THEME_KEY = key;
  document.documentElement.dataset.theme = THEMES[key].dark ? 'dark' : 'light';
  var t = themeNow();
  sessions.forEach(function (s) { s.term.options.theme = t; });
  try { localStorage.setItem('sshfield_theme', key); } catch (e) {}
}

function setDot(s, state) {
  if (!s.dotEl) return;
  s.dotEl.className = 'd' + (state ? ' ' + state : '');
}

function updateTopStatus() {
  var s = active();
  var thua = LAYOUT !== 'tabs' && sessions.length > MAX_PANES
    ? '  ·  ' + (sessions.length - MAX_PANES) + ' tab không lên lưới (tối đa ' + MAX_PANES + ')' : '';
  $('st').textContent = (!sessions.length ? 'Chưa có phiên nào'
    : (s ? (s.connected ? 'Đang mở: ' + s.label : s.label + ' — chưa kết nối') : sessions.length + ' phiên')) + thua;
}

function connectedCount() {
  return sessions.filter(function (x) { return x.connected; }).length;
}

/* ══════════ Bố cục: từng tab hay chia màn hình ══════════════════════════════
   'tabs'  → như cũ, mỗi lúc một terminal chiếm hết khung
   '2','3','4','auto' → lưới, MỌI phiên hiện cùng lúc (mục đích: vừa cấu hình
   switch vừa nhìn log trên server, không phải nhảy tab qua lại).
   Ở chế độ lưới, "tab đang chọn" vẫn còn ý nghĩa: đó là nơi nhận bàn phím. */
var LAYOUT = 'tabs';
var MAX_PANES = 10;      /* chia tối đa 10 ô — hơn nữa mỗi ô chỉ còn vài dòng, vô dụng */

var LAYOUTS = [
  { v:'tabs', n:'Từng tab (không chia)' },
  { v:'2',    n:'2 cột' },
  { v:'3',    n:'3 cột' },
  { v:'4',    n:'4 cột' },
  { v:'5',    n:'5 cột' },
  { v:'auto', n:'Tự động theo số tab' },
];

/* Ở chế độ chia, hiện tối đa MAX_PANES phiên đầu tiên. */
function shownSessions() {
  return LAYOUT === 'tabs' ? sessions : sessions.slice(0, MAX_PANES);
}

/* Đánh lại số 1,2,3… cho tab VÀ cho ô lưới. Thứ tự tab = thứ tự ô trên lưới, nên
   nhìn số là biết ngay tab nào ứng với ô nào — trước đây chỉ có tên, mà đi công
   trường thì mấy chục thiết bị tên na ná nhau, dò bằng mắt rất dễ nhầm.
   Số này cũng chính là phím tắt Alt+1…9. Phải gọi lại mỗi khi thêm/bớt phiên. */
function renumber() {
  sessions.forEach(function (s, i) {
    var n = i + 1;
    if (s.noEl) s.noEl.textContent = n;
    if (s.tabEl) s.tabEl.title = 'Phiên ' + n + ': ' + s.label + (n <= 9 ? '  (Alt+' + n + ')' : '');
    s.wrap.dataset.label = n + ' · ' + s.label;
  });
}

function applyLayout(mode) {
  LAYOUT = mode || 'tabs';
  var box = $('terms');
  var split = LAYOUT !== 'tabs';
  box.classList.toggle('split', split);

  /* Phiên thứ 11 trở đi bị ẩn khỏi lưới nhưng VẪN kết nối — ẩn bằng style riêng
     chứ không đóng, vì người ta chỉ muốn bớt chật màn hình chứ không muốn mất phiên. */
  var shown = shownSessions();
  sessions.forEach(function (x) {
    var inGrid = !split || shown.indexOf(x) >= 0;
    x.wrap.style.display = split ? (inGrid ? 'block' : 'none') : '';
    x.wrap.classList.toggle('active', x.id === activeId);
  });

  if (!split) {
    box.style.gridTemplateColumns = '';
    box.style.gridAutoRows = '';
  } else {
    var n = Math.max(1, shown.length);
    var cols = LAYOUT === 'auto' ? Math.ceil(Math.sqrt(n)) : parseInt(LAYOUT, 10);
    cols = Math.max(1, Math.min(cols, n));
    box.style.gridTemplateColumns = 'repeat(' + cols + ',minmax(0,1fr))';
    /* Chia đều chiều cao theo số hàng thực tế. Không đặt thì hàng cuối bị dẹp. */
    box.style.gridAutoRows = 'minmax(0,' + (100 / Math.ceil(n / cols)) + '%)';
  }
  try { localStorage.setItem('sshfield_layout', LAYOUT); } catch (e) {}
  if (menuLayout) menuLayout.set(LAYOUT, true);
  fitAll();
  updateTopStatus();
}

/* Đo lại MỌI terminal đang hiện rồi báo kích thước mới cho thiết bị — thiếu
   bước báo thì thiết bị vẫn tưởng 80x24, chữ xuống dòng lung tung. */
function fitAll() {
  setTimeout(function () {
    var shown = shownSessions();
    sessions.forEach(function (s) {
      if (LAYOUT === 'tabs' && s.id !== activeId) return;   // tab ẩn: đo ra rác
      if (LAYOUT !== 'tabs' && shown.indexOf(s) < 0) return;
      try { s.fit.fit(); } catch (e) {}
      if (s.connected && s.ws) {
        try { s.ws.send(JSON.stringify({ t:'size', cols:s.term.cols, rows:s.term.rows })); } catch (e) {}
      }
    });
  }, 30);
}

/* Hiện 1 tab, ẩn các tab khác. fit() PHẢI gọi sau khi đã hiện (xem ghi chú đầu file). */
function activate(id) {
  var s = byId(id);
  if (!s) return;
  activeId = id;
  sessions.forEach(function (x) {
    var on = x.id === id;
    x.wrap.classList.toggle('active', on);
    x.tabEl.classList.toggle('active', on);
  });
  $('empty').style.display = 'none';
  updateSessionBtns();
  /* ⚠️ DÙNG setTimeout, KHÔNG dùng requestAnimationFrame — rAF KHÔNG CHẠY khi tab
     trình duyệt ở chế độ nền. Đã dính lỗi thật: mở phiên rồi chuyển sang cửa sổ
     khác trong lúc chờ thì kết nối không bao giờ bắt đầu, đèn kẹt ở "đang kết
     nối" mãi. setTimeout vẫn chạy khi ẩn (bị giảm nhịp nhưng vẫn chạy). */
  setTimeout(function () {
    try { s.fit.fit(); } catch (e) {}
    if (s.connected && s.ws) {
      try { s.ws.send(JSON.stringify({ t: 'size', cols: s.term.cols, rows: s.term.rows })); } catch (e) {}
    }
    try { s.term.focus(); } catch (e) {}
  }, 0);
  updateTopStatus();
}

function closeSession(id) {
  var s = byId(id);
  if (!s) return;
  try { s.ws && s.ws.close(); } catch (e) {}
  try { s.term.dispose(); } catch (e) {}
  try { s.wrap.remove(); s.tabEl.remove(); } catch (e) {}
  sessions = sessions.filter(function (x) { return x.id !== id; });
  if (activeId === id) {
    if (sessions.length) activate(sessions[sessions.length - 1].id);
    else {
      activeId = null; $('empty').style.display = 'flex';
      $('bar2').style.display = 'none';
      updateTopStatus();
    }
  } else updateTopStatus();
  renumber();                                 // đóng tab giữa → các tab sau dồn số lên
  if (sessions.length) applyLayout(LAYOUT);   // lưới phải chia lại theo số phiên còn lại
  updateSessionBtns();
}

function openSession(host, port, user, pass) {
  var id = ++seq;
  var label = (user ? user + '@' : '') + host;

  /* Khung chứa terminal */
  var wrap = document.createElement('div');
  wrap.className = 'tw';
  wrap.dataset.label = label;        // renumber() sẽ thay bằng "số · tên" ngay sau đây
  $('terms').appendChild(wrap);

  /* Nút tab */
  var tabEl = document.createElement('div');
  tabEl.className = 'tab';
  var dotEl = document.createElement('span'); dotEl.className = 'd busy';
  var noEl = document.createElement('span'); noEl.className = 'no';   // số thứ tự, renumber() điền
  var nameEl = document.createElement('span'); nameEl.textContent = label;
  var closeEl = document.createElement('span'); closeEl.className = 'c'; closeEl.textContent = '×';
  closeEl.title = 'Đóng phiên';
  tabEl.appendChild(dotEl); tabEl.appendChild(noEl); tabEl.appendChild(nameEl); tabEl.appendChild(closeEl);
  $('tabs').appendChild(tabEl);

  var term = new Terminal({
    fontFamily: 'Consolas,"Cascadia Mono","DejaVu Sans Mono",monospace',
    fontSize: 14, cursorBlink: true, scrollback: 10000, theme: themeNow(),
  });
  var fitA = new FitAddon.FitAddon();
  term.loadAddon(fitA);

  /* cfg: giữ lại thông tin đăng nhập để nút "Kết nối lại" dùng — không cất thì
     ngắt xong muốn nối lại phải gõ tay IP/tài khoản/mật khẩu từ đầu.
     Chỉ nằm trong bộ nhớ của tab trình duyệt, không ghi ra đĩa, không gửi đi đâu. */
  var s = { id:id, label:label, host:host, term:term, fit:fitA, ws:null,
            connected:false, raw:'', wrap:wrap, tabEl:tabEl, dotEl:dotEl, noEl:noEl,
            cfg:{ port:port, user:user, pass:pass }, pend:'' };
  sessions.push(s);
  renumber();

  tabEl.onclick = function (e) { if (e.target === closeEl) return; activate(id); };
  closeEl.onclick = function (e) { e.stopPropagation(); closeSession(id); };
  /* Ở chế độ lưới, bấm vào ô nào thì ô đó nhận bàn phím. */
  wrap.addEventListener('mousedown', function () { if (activeId !== id) activate(id); });

  $('bar2').style.display = 'flex';

  /* Hiện tab TRƯỚC rồi mới open() — xterm cần phần tử đang hiển thị để đo đúng. */
  activate(id);
  term.open(wrap);
  try { fitA.fit(); } catch (e) {}
  /* Kết nối NGAY, không chờ callback vẽ nào cả (xem ghi chú rAF ở activate()).
     Kích thước ban đầu cứ để mặc định 80x24; fit lại sau vài chục mili-giây rồi
     gửi 'size' cập nhật — thà terminal lệch cỡ trong chớp mắt còn hơn không kết nối. */
  connectWs(s);
  applyLayout(LAYOUT);
  setTimeout(function () {
    try { fitA.fit(); } catch (e) {}
    if (s.connected && s.ws) { try { s.ws.send(JSON.stringify({ t:'size', cols:s.term.cols, rows:s.term.rows })); } catch (e) {} }
  }, 80);

  term.onData(function (d) {
    /* MultiExec: một lần gõ đi tới MỌI phiên đang mở. Nguy hiểm nên chỉ chạy khi
       ô "Gõ cho mọi tab" đang tích, và cả thanh công cụ đổi màu đỏ để nhắc. */
    if (MULTI) return sendAll(d);
    if (s.connected && s.ws) s.ws.send(JSON.stringify({ t: 'data', d: d }));
  });
  return s;
}

/* ══════════ Gõ cho mọi tab (MultiExec) ══════════ */
var MULTI = false;

function sendAll(d) {
  sessions.forEach(function (x) {
    if (x.connected && x.ws) { try { x.ws.send(JSON.stringify({ t:'data', d:d })); } catch (e) {} }
  });
}


function connectWs(s) {
  s.term.writeln('\x1b[90m[Đang kết nối ' + s.host + '…]\x1b[0m');
  setDot(s, 'busy');
  updateSessionBtns();

  var ws = new WebSocket('ws://127.0.0.1:' + BRIDGE_PORT + '/ws?t=' + encodeURIComponent(TOKEN));
  s.ws = ws;

  ws.onopen = function () {
    ws.send(JSON.stringify({
      t:'open', host:s.host, port:s.cfg.port || 22, user:s.cfg.user, pass:s.cfg.pass,
      cols:s.term.cols, rows:s.term.rows,
    }));
  };

  ws.onmessage = function (ev) {
    var m; try { m = JSON.parse(ev.data); } catch (e) { return; }
    if (m.t === 'ready') {
      s.connected = true; setDot(s, 'on');
      s.term.writeln('\x1b[32m[Đã kết nối ' + s.host + ']\x1b[0m\r\n');
      if (activeId === s.id) { s.term.focus(); updateTopStatus(); }
      updateSessionBtns();
      return;
    }
    if (m.t === 'data') {
      s.term.write(SYNTAX ? colorize(s, m.d) : m.d);
      /* raw để nguyên, KHÔNG tô màu: đây là thứ đưa cho AI đọc, thêm mã màu vào
         chỉ làm nhiễu và tốn token. */
      s.raw += m.d; if (s.raw.length > RAW_MAX) s.raw = s.raw.slice(-RAW_MAX);
      return;
    }
    if (m.t === 'err') {
      s.term.writeln('\r\n\x1b[31m[Lỗi] ' + m.m + '\x1b[0m\r\n');
      s.connected = false; setDot(s, 'err'); updateTopStatus(); updateSessionBtns(); return;
    }
    if (m.t === 'end') {
      s.term.writeln('\r\n\x1b[33m[Phiên đã đóng — bấm ▶ Kết nối lại, hoặc × để dọn tab]\x1b[0m\r\n');
      s.connected = false; setDot(s, 'err'); updateTopStatus(); updateSessionBtns(); return;
    }
  };

  ws.onerror = function () {
    s.term.writeln('\r\n\x1b[31m[Mất kết nối tới dash-ssh — cửa sổ lệnh còn chạy không?]\x1b[0m\r\n');
  };
  ws.onclose = function () {
    if (s.connected) s.term.writeln('\r\n\x1b[33m[Kết nối đã đóng]\x1b[0m\r\n');
    s.connected = false; setDot(s, 'err'); updateTopStatus(); updateSessionBtns();
  };
}

/* ══════════ Tô màu cú pháp ═════════════════════════════════════════════════
   Terminal thật không có "syntax highlight" — màu là do thiết bị tự gửi mã ANSI.
   Ở đây tự tô thêm cho những thứ hay phải soi bằng mắt: IP, MAC, số, và các từ
   trạng thái (up/down/error…). Rất hợp lúc đọc `show ip interface brief`.

   ⚠️ HAI CHỖ DỄ HỎNG, đã xử lý:
   1. KHÔNG được đụng vào mã ANSI thiết bị đã gửi → tách chuỗi theo mã escape,
      chỉ tô phần chữ thường ở giữa.
   2. Một mã escape có thể bị CẮT ĐÔI giữa hai gói WebSocket → giữ lại phần đuôi
      dang dở (s.pend), ghép vào gói sau rồi mới xử lý. Không làm bước này thì
      thỉnh thoảng màn hình lòi ra rác kiểu "[0;32m".                         */
var SYNTAX = true;

var ESC_SPLIT = /(\x1b\][\s\S]*?(?:\x07|\x1b\\)|\x1b\[[0-9;?]*[ -\/]*[@-~]|\x1b[@-Z\\-_])/;

/* ⚠️ MỘT LƯỢT DUY NHẤT, KHÔNG chạy nhiều .replace() nối nhau.
   Đã dính lỗi thật: tô "up" xong thành "\x1b[38;5;114mup", lượt sau tìm SỐ lại
   khớp đúng mấy con 38/5/114 vừa chèn vào, tô chồng lên → mã escape gãy đôi và
   màn hình lòi ra chữ "38;5;114m". Gộp tất cả vào một biểu thức, quét một lần
   thì phần vừa chèn không bao giờ bị quét lại.
   Thứ tự nhánh CÓ Ý NGHĨA: IP và MAC phải đứng trước SỐ, nếu không "192" trong
   192.168.1.1 bị bắt làm số trước rồi IP không còn nguyên vẹn để khớp. */
var RE_SYNTAX = new RegExp([
  '(\\b(?:\\d{1,3}\\.){3}\\d{1,3}(?:\\/\\d{1,2})?\\b)',                                  // 1 IP
  '(\\b(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}\\b|\\b(?:[0-9a-fA-F]{4}\\.){2}[0-9a-fA-F]{4}\\b)', // 2 MAC
  '(\\b(?:up|UP|Up|active|Active|ACTIVE|connected|Connected|enabled|Enabled|success|Success|OK|ok|permit|allow|established|Established|running|Running)\\b)', // 3 tốt
  '(\\b(?:down|DOWN|Down|inactive|disabled|Disabled|error|Error|ERROR|errors|fail|failed|Failed|FAILED|denied|Denied|deny|invalid|Invalid|unreachable|timeout|Timeout|drop|dropped|dropping)\\b)', // 4 xấu
  '(\\b\\d+(?:\\.\\d+)?\\b)',                                                             // 5 số
].join('|'), 'g');

/* \x1b[39m = "về màu chữ mặc định". Cố ý KHÔNG dùng \x1b[0m — cái đó xoá sạch
   cả in đậm/nền mà thiết bị đang đặt, tô màu xong lại làm hỏng định dạng gốc. */
function colorPlain(txt) {
  return txt.replace(RE_SYNTAX, function (m, ip, mac, good, bad) {
    var c = ip  ? '38;5;81'      // xanh lơ
          : mac ? '38;5;213'     // hồng
          : good ? '38;5;114'    // xanh lá
          : bad ? '38;5;203'     // đỏ
          :       '38;5;222';    // vàng nhạt — số
    return '\x1b[' + c + 'm' + m + '\x1b[39m';
  });
}

function colorize(s, chunk) {
  var data = (s.pend || '') + chunk;
  s.pend = '';
  /* Đuôi dang dở: có ESC mà chưa thấy ký tự kết thúc → cất lại chờ gói sau.
     Chặn ở 64 ký tự để lỡ thiết bị gửi rác thì không giữ mãi. */
  var lastEsc = data.lastIndexOf('\x1b');
  if (lastEsc >= 0 && data.length - lastEsc < 64 && !/[@-~]/.test(data.slice(lastEsc + 2))) {
    s.pend = data.slice(lastEsc);
    data = data.slice(0, lastEsc);
  }
  var parts = data.split(ESC_SPLIT);
  for (var i = 0; i < parts.length; i++) {
    if (parts[i] === undefined) { parts[i] = ''; continue; }
    if (i % 2 === 0) parts[i] = colorPlain(parts[i]);   // phần chẵn là chữ thường
  }
  return parts.join('');
}

/* ══════════ Ngắt / nối lại (mục 4) ══════════ */
function disconnectSession(s) {
  if (!s) return;
  try { s.ws && s.ws.close(); } catch (e) {}
  s.ws = null; s.connected = false; setDot(s, 'err');
  s.term.writeln('\r\n\x1b[33m[Đã ngắt kết nối — nội dung màn hình giữ nguyên]\x1b[0m\r\n');
  updateTopStatus(); updateSessionBtns();
}

function reconnectSession(s) {
  if (!s || s.connected) return;
  try { s.ws && s.ws.close(); } catch (e) {}
  s.term.writeln('\r\n\x1b[90m──────── kết nối lại ────────\x1b[0m');
  connectWs(s);
}

/* Nút chỉ sáng khi bấm được: đang nối thì cho Ngắt, đang rời thì cho Nối lại. */
function updateSessionBtns() {
  var s = active();
  var d = $('btnDisc'), r = $('btnRecon');
  if (!d || !r) return;
  d.disabled = !s || !s.connected;
  r.disabled = !s || s.connected;
  /* Hàm này được gọi ở MỌI chỗ trạng thái kết nối đổi, nên móc luôn phép kiểm
     "còn đủ 2 tab để gõ chung không" vào đây — khỏi rải lời gọi khắp nơi rồi sót. */
  recheckMulti();
  if (MULTI) paintMultiWarn();
}

/* ══════════ Thanh trên ══════════ */
function doOpen() {
  var host = $('host').value.trim();
  if (!host) { $('host').focus(); return; }
  if (!TOKEN) return;
  openSession(host, $('port').value.trim() || 22, $('user').value.trim(), $('pass').value);
  /* XOÁ SẠCH IP + tài khoản + mật khẩu ngay sau khi mở tab (anh Thoại yêu cầu).
     Trước đây giữ lại cho nhanh khi nhiều thiết bị chung một bộ đăng nhập, nhưng
     mật khẩu nằm chình ình trong ô nhập suốt buổi là rủi ro: máy để trên bàn nhà
     khách, ai đi ngang cũng thấy, F12 là đọc được. Gõ lại vài giây đổi lấy điều đó
     là đáng. Mật khẩu của phiên ĐANG MỞ vẫn nằm trong bộ nhớ tab để "Kết nối lại"
     dùng — không ghi ra đĩa, đóng tab là mất. */
  $('host').value = ''; $('user').value = ''; $('pass').value = '';
  $('host').focus();
}

$('btnGo').onclick = doOpen;
['host', 'port', 'user', 'pass'].forEach(function (id) {
  $(id).addEventListener('keydown', function (e) { if (e.key === 'Enter') doOpen(); });
});

/* ══════════ Thanh công cụ phiên ══════════ */
$('btnDisc').onclick  = function () { disconnectSession(active()); };
$('btnRecon').onclick = function () { reconnectSession(active()); };
/* Hai nút này nằm trên thanh chính nên có mặt ngay từ lúc mở trang, khi chưa có
   phiên nào — phải làm mờ ngay, không thì bấm vào chẳng xảy ra gì, tưởng hỏng. */
updateSessionBtns();

/* ── Menu thả xuống dùng chung ────────────────────────────────────────────
   Tự dựng thay vì <select> vì <select> bắt buộc phải có nhãn đứng trước mới
   hiểu được đang chọn cái gì → thanh công cụ vừa dài vừa rối. Ở đây bấm thẳng
   vào chữ "Bố cục" / "Màu" là ra danh sách, mục đang chọn có dấu ✓.
   items: [{v:giá trị, n:tên hiện ra}] · onPick(v) khi chọn. */
function makeMenu(rootId, items, onPick) {
  var root = $(rootId);
  var btn = root.querySelector('.mbtn');
  var pop = root.querySelector('.pop');
  var curEl = root.querySelector('.cur');
  var value = null;

  items.forEach(function (it) {
    var b = document.createElement('button');
    b.type = 'button';
    b.dataset.v = it.v;
    b.innerHTML = '<span class="tick">✓</span><span></span>';
    b.lastChild.textContent = it.n;      // textContent: tên tự đặt, không nhét HTML
    b.onclick = function () {
      close();
      if (it.v !== value) { api.set(it.v); onPick(it.v); }
    };
    pop.appendChild(b);
  });

  function close() { root.classList.remove('open'); }

  btn.onclick = function (e) {
    e.stopPropagation();
    var wasOpen = root.classList.contains('open');
    /* Đóng mọi menu khác trước — hai menu cùng mở thì chồng lên nhau. */
    Array.prototype.forEach.call(document.querySelectorAll('.menu.open'), function (m) {
      m.classList.remove('open');
    });
    if (!wasOpen) root.classList.add('open');
  };
  document.addEventListener('click', close);
  document.addEventListener('keydown', function (e) { if (e.key === 'Escape') close(); });

  var api = {
    set: function (v) {
      value = v;
      var found = items.filter(function (i) { return i.v === v; })[0];
      curEl.textContent = found ? found.n : '';
      Array.prototype.forEach.call(pop.children, function (b) {
        b.classList.toggle('on', b.dataset.v === v);
      });
    },
  };
  return api;
}

var menuLayout = null, menuTheme = null;

/* Bộ chọn màu — dựng từ THEMES nên thêm bộ màu mới chỉ phải sửa một chỗ. */
(function () {
  var items = Object.keys(THEMES).map(function (k) { return { v:k, n:THEMES[k].name }; });
  menuTheme = makeMenu('mTheme', items, applyTheme);
  var savedTheme = 'dark';
  try { savedTheme = localStorage.getItem('sshfield_theme') || 'dark'; } catch (e) {}
  if (!THEMES[savedTheme]) savedTheme = 'dark';
  menuTheme.set(savedTheme);
  applyTheme(savedTheme);
})();

(function () {
  menuLayout = makeMenu('mLayout', LAYOUTS, applyLayout);
  var savedLayout = 'tabs';
  try { savedLayout = localStorage.getItem('sshfield_layout') || 'tabs'; } catch (e) {}
  if (!LAYOUTS.filter(function (i) { return i.v === savedLayout; }).length) savedLayout = 'tabs';
  LAYOUT = savedLayout;
  menuLayout.set(savedLayout);
})();

(function () {
  var chk = $('chkSyntax');
  try { SYNTAX = localStorage.getItem('sshfield_syntax') !== '0'; } catch (e) {}
  chk.checked = SYNTAX;
  chk.onchange = function () {
    SYNTAX = chk.checked;
    try { localStorage.setItem('sshfield_syntax', SYNTAX ? '1' : '0'); } catch (e) {}
  };
})();

/* ══════════ Gõ cho mọi tab — kiểu MobaXterm ════════════════════════════════
   Bật lên là gõ ở tab nào cũng chạy trên MỌI tab đang kết nối.

   Hai điều kiện anh Thoại đặt ra, cả hai đều có lý do dùng thật:
   1. Phải có TỪ 2 TAB kết nối trở lên — một tab thì "gõ cho mọi tab" vô nghĩa,
      mà bật nhầm rồi quên tắt thì lần sau mở thêm tab là dính chưởng.
   2. Bật là CHIA MÀN HÌNH ngay — gõ mù cho nhiều máy mà chỉ nhìn thấy một cái
      là cách nhanh nhất để phá nhầm thiết bị. Phải thấy hết mới được gõ hết.

   CỐ Ý không nhớ giữa các lần mở trang: bật sẵn từ phiên trước rồi quên mất là
   công thức để chạy nhầm một lệnh trên cả chục thiết bị. */
var LAYOUT_BEFORE_MULTI = null;

$('chkMulti').onchange = function () {
  var chk = $('chkMulti');

  if (chk.checked) {
    var n = connectedCount();
    if (n < 2) {
      chk.checked = false;
      MULTI = false;
      $('bar2').classList.remove('multi');
      $('st').textContent = 'Cần ít nhất 2 tab đang kết nối mới gõ chung được (hiện có ' + n + ')';
      setTimeout(updateTopStatus, 3500);
      return;
    }
    MULTI = true;
    /* Nhớ bố cục cũ để lúc tắt còn trả lại đúng như anh đang để. */
    LAYOUT_BEFORE_MULTI = LAYOUT;
    applyLayout('auto');
  } else {
    MULTI = false;
    if (LAYOUT_BEFORE_MULTI !== null) { applyLayout(LAYOUT_BEFORE_MULTI); LAYOUT_BEFORE_MULTI = null; }
  }

  $('bar2').classList.toggle('multi', MULTI);
  paintMultiWarn();
  var s = active(); if (s) try { s.term.focus(); } catch (e) {}
};

/* Ghi rõ ĐANG GÕ CHO BAO NHIÊU TAB. Quan trọng khi mở hơn 10 tab: lưới chỉ hiện
   được 10 ô, nhưng phím vẫn đi tới TẤT CẢ các tab đang kết nối — không nói ra
   thì rất dễ tưởng "cái nào không thấy thì không dính". */
function paintMultiWarn() {
  var el = document.querySelector('.warnmx');
  if (!el) return;
  var n = connectedCount();
  el.textContent = '⚠ mọi phím đang đi tới TẤT CẢ ' + n + ' tab'
    + (n > MAX_PANES ? ' (lưới chỉ hiện được ' + MAX_PANES + ')' : '');
}

/* Tab rớt hết chỉ còn 1 thì tự tắt — điều kiện "ít nhất 2 tab" phải đúng cả lúc
   đang chạy, không riêng lúc bấm vào ô tích. */
function recheckMulti() {
  if (!MULTI) return;
  if (connectedCount() >= 2) return;
  MULTI = false;
  $('chkMulti').checked = false;
  $('bar2').classList.remove('multi');
  $('st').textContent = 'Đã tắt "gõ cho mọi tab" — không còn đủ 2 tab kết nối';
  setTimeout(updateTopStatus, 3500);
}

/* Đổi kích thước cửa sổ: chỉ đo lại tab đang xem — các tab ẩn sẽ tự fit() khi
   được bấm sang (đo lúc đang ẩn cho ra kích thước rác, xem ghi chú đầu file). */
window.addEventListener('resize', function () {
  if (!sessions.length) return;
  if (LAYOUT !== 'tabs') return fitAll();   // chia màn hình: mọi ô đều đổi cỡ
  var s = active(); if (!s) return;
  try { s.fit.fit(); } catch (e) {}
  if (s.connected && s.ws) s.ws.send(JSON.stringify({ t:'size', cols:s.term.cols, rows:s.term.rows }));
});

/* Alt+1..9 nhảy nhanh giữa các tab — mở 5-6 thiết bị thì bấm chuột mất thời gian. */
window.addEventListener('keydown', function (e) {
  if (!e.altKey || e.ctrlKey || e.metaKey) return;
  var n = parseInt(e.key, 10);
  if (n >= 1 && n <= 9 && sessions[n - 1]) { e.preventDefault(); activate(sessions[n - 1].id); }
});

/* ══════════ Trợ lý AI ══════════ */
/* KHÔNG gửi model từ trình duyệt nữa — để SERVER tự chọn theo key đang có
   (SSHFIELD_9ROUTER_KEY → 'ssh-field', không thì 'termix'). Gửi cứng từ đây thì
   ngày anh Thoại nạp key riêng, trang vẫn xin model cũ và upstream từ chối. */
var MODEL = null;
/* Số lượt gọi công cụ tối đa trong MỘT câu hỏi — chốt chống chạy vòng vô tận.
   Đặt riêng theo chế độ vì nhịp làm việc khác hẳn nhau:
     ask    — chỉ đọc, vài lượt là đủ
     agent  — chèn xong là DỪNG chờ anh bấm Enter (xem execTool), nên cũng ít
     bypass — chạy thật thì luôn đi theo cặp "chạy → đọc lại kết quả", một việc
              nhiều bước hết lượt rất nhanh; cho rộng hơn nhưng vẫn phải có trần.
   Hết lượt KHÔNG còn cụt ngang: giờ có nút "Tiếp tục" để đi tiếp. */
var LOOP_LIMIT = { ask: 6, agent: 8, bypass: 14 };
function maxLoops() { return LOOP_LIMIT[MODE] || 8; }
var LLM_URL = '/api/ssh-field-llm';

function stripAnsi(s) {
  return String(s)
    .replace(/\x1b\][\s\S]*?(\x07|\x1b\\)/g, '')
    .replace(/\x1b[\[\]][0-9;?]*[ -\/]*[@-~]/g, '')
    .replace(/\x1b[@-Z\\-_]/g, '')
    .replace(/\r\n/g, '\n').replace(/\r/g, '\n')
    .replace(/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/g, '')
    .replace(/[ \t]+\n/g, '\n');
}

/* Che secret TRƯỚC khi gửi lên LLM — cùng bộ luật với console-serial.html.
   Thà che nhầm còn hơn để lọt: đây là thiết bị thật của khách hàng. */
var _redacted = false;
function _mask() { _redacted = true; return '[ĐÃ CHE]'; }
/* ⚠️⚠️ KHOẢNG TRẮNG Ở ĐÂY KHÔNG ĐƯỢC PHÉP VẮT QUA XUỐNG DÒNG — đọc kỹ trước khi sửa.
   BUG THẬT (gặp 2026-08-06): dùng \s* / \s+ thì khoảng trắng ăn cả ký tự xuống dòng,
   nên "bí mật" bị che thật ra là TỪ ĐẦU TIÊN CỦA DÒNG SAU. Trên Cisco:

       MinhThoai>en
       Password:
       MinhThoai#          ← dấu nhắc MỚI, chứng tỏ đã vào enable mode

   bị biến thành "Password:\n[ĐÃ CHE]" → AI đọc xong tưởng vẫn đang chờ mật khẩu,
   báo sai trạng thái thiết bị cho anh Thoại. Che secret mà che nhầm luôn bằng chứng
   thì nguy hiểm hơn là không che: AI kết luận sai mà không ai biết vì sao.

   Vì vậy mọi luật dưới đây chỉ dùng [ \t] — bí mật và nhãn của nó LUÔN nằm CÙNG MỘT DÒNG.
   Cùng bộ luật với public/service-home/console-serial.html — sửa bên này thì sửa cả bên đó. */
function redact(s) {
  if (!s) return s;
  _redacted = false;
  return String(s)
    .replace(/-----BEGIN [^-\n]*PRIVATE KEY-----[\s\S]*?-----END [^-\n]*PRIVATE KEY-----/g, function () { return _mask() + ' (private key)'; })
    .replace(/\b((?:password|secret))([ \t]+\d[ \t]+)(\S+)/gi, function (m, k, mid) { return k + mid + _mask(); })
    .replace(/([a-z0-9_.\-]*(?:pass(?:word|wd|phrase)?|secret|token|api[_-]?key|access[_-]?key|client[_-]?secret|private[_-]?key|auth[_-]?token))([ \t]*[:=][ \t]*)(["']?)([^\s"'&]{3,})(\3)/gi,
      function (m, k, sep, q) { return k + sep + q + _mask() + q; })
    /* "(?:ENC[ \t]+)?" là bắt buộc: FortiOS ghi "set password ENC <chuỗi>". Thiếu nó thì
       luật này che nhầm đúng chữ "ENC" rồi dừng, để lộ nguyên giá trị thật phía sau. */
    .replace(/\b((?:password|passwd|secret|passphrase))([ \t]+)(?:ENC[ \t]+)?(?![ \t]*\d[ \t])(\S{3,})/gi,
      function (m, k, sp) { return k + sp + _mask(); })
    .replace(/(Authorization[ \t]*:[ \t]*(?:Bearer|Basic)[ \t]+)(\S+)/gi, function (m, p1) { return p1 + _mask(); })
    /* Kiểu FortiOS: "set psksecret ENC <chuỗi>" — luật chung ở trên KHÔNG bắt được vì
       không có ranh giới từ trước "secret" trong "psksecret", và giá trị lại nằm sau
       chữ ENC. Bỏ qua là lộ khoá VPN nguyên văn lên LLM. */
    .replace(/\b(set[ \t]+\S*(?:secret|password|passwd|psk)[ \t]+)(?:ENC[ \t]+)?(\S{4,})/gi,
      function (m, p1) { return p1 + _mask(); })
    .replace(/\bAKIA[0-9A-Z]{16}\b/g, function () { return _mask() + ' (AWS)'; });
}

/* ══════════════════════════════════════════════════════════════════════════
   DẤU NHẮC HIỆN TẠI — nói thẳng trạng thái, đừng bắt AI suy từ đống chữ
   ──────────────────────────────────────────────────────────────────────────
   Bài học từ vụ "AI tưởng vẫn đang chờ mật khẩu": bắt AI tự đọc màn hình rồi
   suy ra thiết bị đang ở chế độ nào là chỗ dễ sai nhất — chỉ cần một dòng bị
   che nhầm, hoặc màn hình có nhiều dấu nhắc cũ, là nó kết luận lệch.

   Ở đây tính SẴN từ dòng cuối cùng có nội dung (KHÔNG qua bộ che secret, vì dấu
   nhắc không phải bí mật) rồi đưa cho AI dưới dạng trường riêng. Một trường rõ
   ràng đáng tin hơn cả trang chữ. */
function doTrangThai(s) {
  var raw = stripAnsi(s.raw || '');
  var dong = raw.split('\n');
  var cuoi = '';
  for (var i = dong.length - 1; i >= 0; i--) {
    if (dong[i].trim()) { cuoi = dong[i].trim(); break; }
  }
  var o = { dau_nhac_cuoi_cung: cuoi.slice(-120) };

  /* Nhận diện chế độ theo ký tự kết thúc — đặc trưng của từng họ thiết bị */
  if (/\(config[^)]*\)\s*#$/.test(cuoi))      o.che_do = 'Cisco/Aruba — ĐANG TRONG CHẾ ĐỘ CẤU HÌNH (config)';
  else if (/#\s*$/.test(cuoi))                o.che_do = 'đặc quyền (enable/#) — chạy được lệnh show và cấu hình';
  else if (/>\s*$/.test(cuoi))                o.che_do = 'người dùng thường (>) — cần "enable" mới chạy được lệnh đặc quyền';
  else if (/password\s*:?\s*$/i.test(cuoi))   o.che_do = 'ĐANG CHỜ NHẬP MẬT KHẨU';
  else if (/login\s*:?\s*$/i.test(cuoi) || /username\s*:?\s*$/i.test(cuoi)) o.che_do = 'ĐANG CHỜ NHẬP TÊN ĐĂNG NHẬP';
  else if (PAGER_RE.test(cuoi))               o.che_do = 'ĐANG DỪNG Ở PHÂN TRANG (--More--) — gửi phím space';
  else if (/[$%]\s*$/.test(cuoi))             o.che_do = 'Linux shell';
  else if (/\]\s*[>#]\s*$/.test(cuoi))        o.che_do = 'MikroTik/khác';
  else o.che_do = 'chưa xác định được từ dấu nhắc — đọc kỹ output';

  o.luu_y = 'Đây là trạng thái THẬT tại thời điểm đọc, tính từ dòng cuối cùng của luồng dữ liệu. '
          + 'Nếu phần output bên dưới có vẻ mâu thuẫn (vd còn thấy dấu nhắc cũ ở giữa màn hình) thì TIN TRƯỜNG NÀY.';
  return o;
}

function readVisibleScreen(term) {
  var buf = term.buffer.active, lines = [];
  for (var i = 0; i < term.rows; i++) {
    var line = buf.getLine(buf.viewportY + i);
    if (line) lines.push(line.translateToString(true));
  }
  while (lines.length && lines[lines.length - 1].trim() === '') lines.pop();
  return lines.join('\n');
}

/* ══════════ Phạm vi AI: 1 tab hay tất cả ═══════════════════════════════════
   Lý do có Multi (anh Thoại): hỏng hệ thống ở công ty thì không phải một con
   switch — phải soi từng đoạn mới ra. Bắt AI đọc từng tab một rồi tự ghép trong
   đầu là chậm và dễ sót; cho nó đọc hết một lượt thì nó tự đối chiếu được.

   Multi bật là CHIA MÀN HÌNH luôn (tối đa 10 ô) — cùng nguyên tắc với "gõ cho
   mọi tab": AI đọc thiết bị nào thì anh phải nhìn thấy thiết bị đó, không để AI
   kết luận về thứ anh không thấy.

   CHÈN LỆNH thì VẪN CHỈ vào tab đang xem, kể cả ở chế độ Multi — đọc nhiều chỗ
   là an toàn, ghi nhiều chỗ thì không. */
var AI_SCOPE = 'single';
var AI_LAYOUT_BEFORE = null;

function setAiScope(scope) {
  AI_SCOPE = scope === 'multi' ? 'multi' : 'single';
  Array.prototype.forEach.call(document.querySelectorAll('#aiScope .sc'), function (b) {
    b.classList.toggle('on', b.dataset.scope === AI_SCOPE);
  });
  var note = $('aiScopeNote');
  if (AI_SCOPE === 'multi') {
    var n = connectedCount();
    if (note) note.textContent = n + ' tab';
    if (n >= 2) {
      if (AI_LAYOUT_BEFORE === null) AI_LAYOUT_BEFORE = LAYOUT;
      applyLayout('auto');
    }
  } else {
    if (note) note.textContent = '1 tab';
    if (AI_LAYOUT_BEFORE !== null) { applyLayout(AI_LAYOUT_BEFORE); AI_LAYOUT_BEFORE = null; }
  }
}

/* ══════════ Nhận diện loại thiết bị ════════════════════════════════════════
   Đoán từ dấu nhắc/banner. Không cần chính xác tuyệt đối — mục đích là để AI
   biết ngay "con này Cisco, con kia FortiGate" mà chọn đúng bộ lệnh, thay vì
   phải đọc hết output từng tab rồi mới suy ra. Đoán sai thì AI đọc kỹ sẽ tự
   đính chính; đoán đúng thì tiết kiệm hẳn một vòng gọi tool. */
function guessDevice(s) {
  /* CẮT ĐUÔI TRƯỚC rồi mới bóc mã màu. Làm ngược lại (bóc cả bộ đệm 400KB rồi
     mới cắt) tốn 3,4ms mỗi lần thay vì 0,1ms — mà hàm này chạy cho TỪNG phiên
     trong list_sessions, nhân lên là thấy. Đo thật, không phải đoán. */
  var tail = stripAnsi((s.raw || '').slice(-6000));
  /* Nhận cả DẤU VẾT của Cisco chứ không chỉ chữ "Cisco": tên cổng kiểu
     GigabitEthernet0/1, Vlan100 là đặc trưng rất riêng — banner nhiều khi đã cuộn
     mất từ lâu, nhưng output lệnh show thì lúc nào cũng có mấy tên cổng này. */
  if (/IOS Software|Cisco IOS|switchport|\(config-if\)#|GigabitEthernet\d|FastEthernet\d|\bVlan\d+\b/i.test(tail)) return 'Cisco IOS';
  if (/ArubaOS|Aruba|ProCurve/i.test(tail)) return 'Aruba/HPE';
  if (/FortiGate|FortiOS|get system status|config system interface/i.test(tail)) return 'FortiGate';
  if (/MikroTik|RouterOS|\[admin@[^\]]+\]/i.test(tail)) return 'MikroTik RouterOS';
  if (/JUNOS|Junos|configure exclusive/i.test(tail)) return 'Juniper JunOS';
  if (/root@|~[#$]|Ubuntu|CentOS|Debian|systemctl/i.test(tail)) return 'Linux';
  return 'chưa rõ';
}

/* ══════════ Trỏ tới ĐÚNG phiên cần thao tác ════════════════════════════════
   Trước đây mọi công cụ ghi chỉ chạy trên TAB ĐANG XEM → muốn đối chiếu hai đầu
   một đường link, AI phải nhờ anh Thoại bấm tab qua lại. Mà sự cố mạng thật thì
   nguyên nhân hay nằm ĐÚNG CHỖ GIÁP RANH giữa hai thiết bị, nên không cho AI tự
   chỉ định thiết bị là nó không bao giờ lần ra được.

   Nhận: số thứ tự tab (1,2,3…) hoặc một mẩu tên/IP. Không nêu thì lấy tab đang xem. */
function resolveSession(ref) {
  if (ref === undefined || ref === null || ref === '') return active();
  var n = parseInt(ref, 10);
  if (!isNaN(n) && String(n) === String(ref).trim() && sessions[n - 1]) return sessions[n - 1];
  var q = String(ref).toLowerCase();
  var hit = sessions.filter(function (s) { return s.label.toLowerCase().indexOf(q) >= 0; });
  return hit.length === 1 ? hit[0] : null;   // khớp mơ hồ = coi như không tìm thấy
}

/* Lỗi "không tìm thấy phiên" phải kèm DANH SÁCH phiên đang có — AI đoán sai tên
   thiết bị là chuyện thường; đưa danh sách thì lượt sau nó tự sửa được. */
function noSession(ref) {
  return { ok:false, error:'Không tìm thấy phiên "' + ref + '".',
           cac_phien_dang_co: sessions.map(function (s, i) { return (i + 1) + '. ' + s.label; }),
           hint:'Dùng số thứ tự tab (vd "session":2) hoặc một mẩu tên/IP đủ phân biệt.' };
}

/* Danh sách phiên — việc ĐẦU TIÊN nên gọi khi soi sự cố nhiều thiết bị. */
function listSessions() {
  if (!sessions.length) return { ok:false, error:'Chưa mở phiên nào.' };
  return {
    ok: true,
    tong_so: sessions.length,
    dang_xem: (active() && active().label) || null,
    danh_sach: sessions.map(function (s, i) {
      return { so_tab: i + 1, thiet_bi: s.label, loai: guessDevice(s),
               trang_thai: s.connected ? 'đang kết nối' : 'đã rớt' };
    }),
    hint: 'Mọi công cụ đều nhận "session": <số tab> hoặc <mẩu tên>. Không nêu thì chạy trên tab đang xem.',
  };
}

/* Gói dữ liệu một phiên cho AI. budget = số ký tự output tối đa được phép lấy —
   chia nhau khi đọc nhiều tab, không thì 10 thiết bị là vỡ cửa sổ ngữ cảnh. */
function packSession(s, budget) {
  markRead(s);        // gói dữ liệu con nào = AI đã thật sự đọc con đó
  var full = stripAnsi(s.raw).replace(/\n{3,}/g, '\n\n').trim();
  var o = {
    so_tab: sessions.indexOf(s) + 1,
    loai_thiet_bi: guessDevice(s),
    thiet_bi: s.label,
    dang_xem: s.id === activeId,
    trang_thai: s.connected ? 'đang kết nối' : 'đã rớt/chưa kết nối',
    trang_thai_hien_tai: doTrangThai(s),
    man_hinh_dang_thay: redact(readVisibleScreen(s.term) || '(màn hình trống)'),
  };
  if (full) o.output_gan_day = redact(full.slice(-budget));
  return o;
}

function readAllTerminals() {
  var live = sessions.filter(function (x) { return x.connected; });
  if (!live.length) return { ok:false, error:'Không có tab nào đang kết nối.' };

  /* Chia đều ngân sách, sàn 3000 ký tự/tab để mỗi thiết bị vẫn đủ ngữ cảnh. */
  var budget = Math.max(2500, Math.floor(12000 / live.length));
  _redacted = false;
  var res = {
    ok: true,
    pham_vi: 'TẤT CẢ ' + live.length + ' tab đang kết nối',
    tab_dang_xem: (active() && active().label) || null,
    cac_thiet_bi: live.map(function (s) { return packSession(s, budget); }),
    hint: 'Mỗi phần tử trong cac_thiet_bi là MỘT thiết bị riêng. Nêu rõ tên thiết bị trong mọi nhận xét. '
        + 'insert_command CHỈ chèn được vào tab đang xem (' + ((active() && active().label) || 'chưa có') + ').',
  };
  if (_redacted) res.note_baomat = 'Một số chuỗi nhạy cảm (mật khẩu/key/token) ĐÃ BỊ CHE trước khi gửi cho bạn.';
  return res;
}

/* AI làm việc với TAB ĐANG XEM — nói rõ trong kết quả để nó không nhầm
   lẫn giữa các thiết bị khi anh mở nhiều tab cùng lúc. */
function readTerminal(ref) {
  /* Nêu rõ session thì đọc ĐÚNG thiết bị đó, kể cả đang ở chế độ Multi — cần khi
     AI muốn soi kỹ một con đang nghi ngờ mà không phải kéo hết mọi tab về. */
  if (ref !== undefined && ref !== null && ref !== '') {
    var t = resolveSession(ref);
    if (!t) return noSession(ref);
    if (!t.connected) return { ok:false, error:'Phiên ' + t.label + ' chưa kết nối.' };
    var r = packSession(t, 8000);
    r.ok = true;
    r.trang_thai_hien_tai = doTrangThai(t);
    return r;
  }
  if (AI_SCOPE === 'multi') return readAllTerminals();
  var s = active();
  if (!s) return { ok:false, error:'Chưa mở phiên nào. Nhập IP rồi bấm "+ Mở tab mới" trước đã.' };
  if (!s.connected) return { ok:false, error:'Tab đang xem (' + s.label + ') chưa kết nối được.' };

  markRead(s);
  var full = stripAnsi(s.raw).replace(/\n{3,}/g, '\n\n').trim();
  var res = { ok:true, thiet_bi_dang_xem: s.label, loai_thiet_bi: guessDevice(s),
              trang_thai_hien_tai: doTrangThai(s),
              so_tab: sessions.indexOf(s) + 1 }, any = false;
  if (sessions.length > 1) {
    res.cac_tab_dang_mo = sessions.map(function (x, i) {
      return (i + 1) + '. ' + x.label + ' [' + guessDevice(x) + ']' + (x.id === s.id ? ' (ĐANG XEM)' : '');
    });
    res.luu_y = 'Anh Thoại đang mở nhiều thiết bị. Kết quả này CHỈ là tab đang xem. '
      + 'Muốn xem/thao tác thiết bị khác thì thêm "session": <số tab> vào công cụ — bạn tự đi được, không cần nhờ anh bấm tab.';
  }
  if (full) {
    res.full_output = redact(full.slice(-8000)); any = any || _redacted;
    res.hint = 'full_output = toàn bộ output từ lúc kết nối (kể cả phần đã cuộn khỏi màn hình). visible_screen chỉ là phần đang thấy.';
  } else {
    res.hint = 'Chưa có output — thử gõ Enter trong terminal.';
  }
  res.visible_screen = redact(readVisibleScreen(s.term) || '(màn hình trống)'); any = any || _redacted;
  if (any) res.note_baomat = 'Một số chuỗi nhạy cảm (mật khẩu/key/token) ĐÃ BỊ CHE trước khi gửi cho bạn. ĐỪNG yêu cầu user gõ lại các giá trị đó.';
  return res;
}

/* Chèn lệnh: ghi vào luồng SSH KHÔNG kèm Enter — thiết bị echo lại như user tự
   gõ, chờ Enter thật mới chạy. Người dùng luôn là người bấm nút cuối cùng. */
var LAST_INSERT = null;   /* {s, mark, cmd} — lệnh vừa chèn, chờ người dùng bấm Enter */

function insertCommand(cmd, ref) {
  var s = resolveSession(ref);
  if (typeof cmd !== 'string' || !cmd) return { ok:false, error:'Thiếu command.' };
  if (!s) return noSession(ref);
  if (!s.connected || !s.ws) return { ok:false, error:'Phiên ' + s.label + ' chưa kết nối.' };
  cmd = cmd.replace(/\r?\n/g, ' ').trim();
  /* Nhớ mốc để lát nữa lấy ĐÚNG phần output sinh ra sau khi anh Thoại bấm Enter —
     nhờ vậy lúc "xem tiếp" mình đưa luôn kết quả cho AI, khỏi tốn một vòng gọi
     model chỉ để nó xin đọc màn hình (xem moiDiTiep). */
  LAST_INSERT = { s: s, mark: s.raw.length, cmd: cmd };
  s.ws.send(JSON.stringify({ t:'data', d:cmd }));
  focusTarget(s);
  return { ok:true, inserted:cmd, thiet_bi:s.label,
           note:'Đã đặt lệnh lên dòng lệnh của ' + s.label + '. Anh xem lại rồi TỰ bấm Enter — mình không gửi Enter.' };
}

/* Thao tác lên thiết bị nào thì KÉO TAB ĐÓ RA TRƯỚC MẶT. Nguyên tắc xuyên suốt
   của trang này: AI gõ vào đâu thì anh Thoại phải nhìn thấy chỗ đó. Ở chế độ
   chia màn hình thì mọi ô đều thấy sẵn, chỉ cần tô sáng ô đang được thao tác. */
function focusTarget(s) {
  try { if (s.id !== activeId) activate(s.id); else s.term.focus(); } catch (e) {}
}

/* CHẠY THẲNG lệnh: chèn rồi tự gửi Enter. CHỈ tồn tại ở chế độ ByPass.
   Tách hẳn khỏi insertCommand để không bao giờ "lỡ tay" gửi Enter ở chế độ khác:
   hai việc khác nhau về bản chất thì phải là hai hàm khác nhau. */
/* Thiết bị mạng phân trang output: Cisco/Aruba in "--More--" rồi ĐỨNG CHỜ một
   phím. AI không biết chuyện đó thì tưởng lệnh treo và dừng luôn — anh Thoại đã
   gặp đúng cảnh này. Nhận ra dấu hiệu chờ phím thì báo thẳng cho AI. */
var PAGER_RE = /(--\s*more\s*--|--More--|<--- More --->|\(END\)|Press any key to continue|-- MORE --)\s*$/i;

/* ⚠️ Lấy output từ LUỒNG THÔ (s.raw), KHÔNG từ vùng hiển thị của xterm.
   Vùng hiển thị chỉ có đúng số dòng/cột mà cửa sổ đang có — cửa sổ hẹp thì chữ bị
   cắt cụt. Đã dính thật: "--More--" bị cắt còn "--", thế là hàm dò phân trang
   không nhận ra và AI vẫn tưởng lệnh treo. Luồng thô thì luôn đủ, không phụ
   thuộc kích thước cửa sổ. */
function rawSince(s, mark) {
  return stripAnsi(s.raw.slice(mark)).replace(/\n{3,}/g, '\n\n').trim();
}

/* Chạy lệnh rồi CHỜ MỘT NHỊP để lấy luôn kết quả về. Không chờ thì AI phải gọi
   thêm read_terminal mới thấy gì, tốn một vòng và hay bị đọc lúc màn hình chưa kịp
   in — vòng lặp vì thế trông như đứng máy. */
function runCommand(cmd, ref) {
  var s = resolveSession(ref);
  if (typeof cmd !== 'string' || !cmd) return Promise.resolve({ ok:false, error:'Thiếu command.' });
  if (!s) return Promise.resolve(noSession(ref));
  if (!s.connected || !s.ws) return Promise.resolve({ ok:false, error:'Phiên ' + s.label + ' chưa kết nối.' });
  cmd = cmd.replace(/\r?\n/g, ' ').trim();
  var mark = s.raw.length;          // đánh dấu để chỉ lấy phần MỚI sinh ra sau lệnh
  s.ws.send(JSON.stringify({ t:'data', d:cmd + '\r' }));
  focusTarget(s);
  return waitOutput(s, mark, { ok:true, ran:cmd, thiet_bi:s.label });
}

/* Gửi phím thô — để qua trang "--More--", thoát lệnh chạy dài (Ctrl+C), trả lời
   y/n. Chỉ nhận danh sách phím ĐÃ DUYỆT: mở cho gửi chuỗi tuỳ ý thì nó thành một
   run_command trá hình, lách hết mọi lớp xác nhận ở trên. */
var KEYS = {
  space:  ' ',      // qua trang tiếp ở --More--
  enter:  '\r',     // xuống 1 dòng ở --More--, hoặc xác nhận
  q:      'q',      // thoát phân trang
  ctrl_c: '\x03',   // cắt lệnh đang chạy (ping, tail -f…)
  esc:    '\x1b',
  y:      'y',
  n:      'n',
};

function sendKey(name, ref) {
  var s = resolveSession(ref);
  var k = KEYS[String(name || '').toLowerCase()];
  if (!k) return Promise.resolve({ ok:false, error:'Phím không hợp lệ. Chỉ nhận: ' + Object.keys(KEYS).join(', ') });
  if (!s) return Promise.resolve(noSession(ref));
  if (!s.connected || !s.ws) return Promise.resolve({ ok:false, error:'Phiên ' + s.label + ' chưa kết nối.' });
  var mark = s.raw.length;
  s.ws.send(JSON.stringify({ t:'data', d:k }));
  focusTarget(s);
  return waitOutput(s, mark, { ok:true, sent_key:name, thiet_bi:s.label });
}

/* Chờ thiết bị in xong rồi trả về ĐÚNG PHẦN OUTPUT MỚI của lệnh vừa gõ.
   Chỉ phần mới (không phải cả màn hình) vì đó là thứ AI cần, lại gọn — đỡ tốn
   ngữ cảnh và không lẫn với output của lệnh trước.

   Chờ tới 2.5s nhưng THOÁT SỚM ngay khi thiết bị im 400ms: lệnh show ngắn thì
   xong trong tích tắc, còn lệnh dài vẫn kịp in hết. Chờ cứng một con số thì
   hoặc là cụt output, hoặc là hội thoại ì ạch. */
function waitOutput(s, mark, base) {
  return new Promise(function (resolve) {
    var t0 = Date.now(), lastLen = -1, quietSince = 0;
    (function tick() {
      var len = s.raw.length;
      if (len !== lastLen) { lastLen = len; quietSince = Date.now(); }
      var yen = Date.now() - quietSince >= 300 && len > mark;
      if (yen || Date.now() - t0 > 1800) return done();
      setTimeout(tick, 120);
    })();

    function done() {
      var out = rawSince(s, mark);
      base.output_moi = redact(out.length > 3000 ? '…(đã cắt bớt phần đầu)…\n' + out.slice(-3000) : out);
      if (PAGER_RE.test(out)) {
        base.dang_cho_phim = true;
        base.huong_dan = 'THIẾT BỊ ĐANG DỪNG Ở "--More--" CHỜ MỘT PHÍM — không phải treo. '
          + 'Gọi send_key {"key":"space"} để xem tiếp (lặp lại tới hết), hoặc {"key":"q"} để thoát. '
          + 'Muốn hết bị phân trang: chạy "terminal length 0" (Cisco/Aruba).';
      } else {
        base.huong_dan = 'output_moi là toàn bộ output của lệnh vừa gõ. Cần xem lại phần cũ hơn thì gọi read_terminal.';
      }
      resolve(base);
    }
  });
}

/* ══════════════════════════════════════════════════════════════════════════
   Tra KHO KIẾN THỨC — thay cho việc nhồi mọi thứ vào lời nhắc
   ──────────────────────────────────────────────────────────────────────────
   Lời nhắc chỉ mang MỤC LỤC (ngắn); nội dung nặng nằm ở ssh-field-kb*.js, chỉ
   tải khi AI thật sự cần. Nhờ vậy kho lớn tuỳ ý mà không làm chậm từng lượt gọi —
   trước đây mỗi dòng thêm vào lời nhắc bị nhân với số lượt gọi trong một câu hỏi.
   Thêm kiến thức = thêm mục trong file kho, KHÔNG đụng vào lời nhắc. */
function kbLookup(topics) {
  if (!window.__NET_KB) return { ok:false, error:'Chưa nạp được kho kiến thức.' };
  if (!topics) return { ok:false, error:'Thiếu tham số "topic".', muc_luc: window.__NET_KB.topics() };
  var r = window.__NET_KB.get(topics);
  if (!r.noi_dung) {
    return { ok:false, error:'Không có mục ' + JSON.stringify(r.khong_co) + '.',
             muc_luc: window.__NET_KB.topics() };
  }
  var o = { ok:true, noi_dung: r.noi_dung };
  if (r.khong_co.length) o.khong_tim_thay = r.khong_co;
  return o;
}

var TOOLS = {
  kb_lookup:      function (p) { return Promise.resolve(kbLookup(p && (p.topic || p.topics))); },
  list_sessions:  function () { return Promise.resolve(listSessions()); },
  read_terminal:  function (p) { return Promise.resolve(readTerminal(p && p.session)); },
  insert_command: function (p) { return Promise.resolve(insertCommand(p && p.command, p && p.session)); },
  run_command:    function (p) { return runCommand(p && p.command, p && p.session); },
  send_key:       function (p) { return sendKey(p && p.key, p && p.session); },
};

/* ══════════ 3 CHẾ ĐỘ TRỢ LÝ ═══════════════════════════════════════════════
   ask    — chỉ đọc, KHÔNG có công cụ ghi. An toàn tuyệt đối.
   agent  — chèn được lệnh, mỗi lệnh anh phải bấm Đồng ý ngay trong khung chat.
            Lệnh vẫn KHÔNG tự chạy: chèn xong anh còn phải bấm Enter.
   bypass — AI tự gõ VÀ tự bấm Enter. Đổi lại phải theo đúng quy trình:
            đọc trước → lập kế hoạch → mới làm; lệnh nguy hiểm vẫn phải hỏi.

   Mỗi chế độ có LỜI NHẮC RIÊNG chứ không chỉ khoá nút: nói cho AI biết nó đang
   ở chế độ nào thì nó tự hành xử đúng, thay vì cứ đề xuất rồi bị chặn liên tục.  */
var MODES = {
  ask: {
    name: 'Ask', perm: 'ssh-field-ai-ask',
    tools: ['kb_lookup', 'list_sessions', 'read_terminal'],
    note: '<b>Ask</b> — chỉ đọc màn hình và trả lời. Không chèn, không chạy bất cứ thứ gì.',
  },
  agent: {
    name: 'AI Agent', perm: 'ssh-field-ai-agent',
    /* send_key có ở Agent vì không gõ được phím thì AI kẹt ngay ở "--More--" —
       lệnh anh vừa duyệt cho chèn cũng không xem hết được kết quả. */
    tools: ['kb_lookup', 'list_sessions', 'read_terminal', 'insert_command', 'send_key'],
    note: '<b>AI Agent</b> — được đặt lệnh lên dòng lệnh, nhưng <b>mỗi lệnh anh phải bấm Đồng ý</b>, và vẫn tự bấm Enter.',
  },
  bypass: {
    name: 'ByPass', perm: 'ssh-field-ai-bypass', danger: true,
    tools: ['kb_lookup', 'list_sessions', 'read_terminal', 'insert_command', 'run_command', 'send_key'],
    note: '⚠️ <b>ByPass</b> — AI <b>tự chạy lệnh</b> trên thiết bị thật. Bắt buộc: kiểm tra trước → trình kế hoạch → mới làm. Lệnh nguy hiểm vẫn hỏi anh.',
  },
};
var MODE = 'ask';

/* Lệnh có thể làm sập mạng cả công ty hoặc mất cấu hình. Ở ByPass vẫn PHẢI hỏi.
   Đây là lưới an toàn cuối: lời nhắc có thể bị AI hiểu sai, danh sách này thì không. */
var DANGEROUS = [
  /\breload\b/i, /\breboot\b/i, /\bshutdown\b(?!\s+-c)/i, /\bhalt\b/i, /\bpoweroff\b/i,
  /write\s+erase/i, /erase\s+startup/i, /factory[- ]?(default|reset)/i, /\bformat\b/i,
  /\brm\s+-[rf]/i, /\bmkfs\b/i, /\bdd\s+if=/i, />\s*\/dev\/[sh]d/i,
  /\bdelete\b.*\b(vlan|interface|route|policy)\b/i, /no\s+(vlan|interface|ip\s+route)/i,
  /\bshut\b/i, /passwd/i, /\buseradd\b/i, /\buserdel\b/i, /iptables\s+-F/i,
  /execute\s+factoryreset/i, /\bhalt\b/i, /system\s+reset/i,
];
function isDangerous(cmd) {
  return DANGEROUS.some(function (re) { return re.test(String(cmd || '')); });
}

var SYS_BASE = [
  'Bạn là kỹ sư mạng/hệ thống trợ lý AI trong "dash-ssh" — công cụ anh Thoại chạy trên laptop để SSH vào thiết bị TẠI HIỆN TRƯỜNG (mạng của khách, không phải mạng nhà).',
  'Trả lời tiếng Việt, ngắn gọn, chính xác kỹ thuật.',
  '',
  '⚠️ ĐÂY LÀ THIẾT BỊ THẬT ĐANG CHẠY, thường là hạ tầng của khách hàng. Gõ sai có thể làm sập mạng cả công ty người ta. Vì vậy:',
  '- Bạn KHÔNG BAO GIỜ tự chạy lệnh. Bạn chỉ ĐẶT lệnh lên dòng lệnh (insert_command) — anh Thoại tự bấm Enter.',
  '- Ưu tiên tuyệt đối lệnh CHỈ ĐỌC (show/display/get/cat) trước khi đề xuất bất kỳ lệnh nào thay đổi cấu hình.',
  '- CẢNH BÁO TO trước lệnh nguy hiểm: reload/reboot, write erase, xoá VLAN/route đang dùng, shutdown cổng uplink (tự cắt đường về của chính mình!), đổi IP quản trị, xoá policy firewall.',
  '- Với thiết bị mạng: NHẮC anh lưu cấu hình sau khi sửa (Cisco/Aruba "write memory", FortiGate tự lưu) — và nhắc backup TRƯỚC khi sửa nếu là thay đổi lớn.',
  '',
  '⚠️ NHIỀU TAB: anh Thoại thường mở NHIỀU thiết bị cùng lúc, mỗi thiết bị 1 tab. read_terminal có HAI chế độ, do anh chọn bằng nút trên bảng chat:',
  '- SINGLE (mặc định): kết quả có thiet_bi_dang_xem — bạn chỉ thấy tab đang xem.',
  '- MULTI SESSION: kết quả có pham_vi + mảng cac_thiet_bi, MỖI PHẦN TỬ LÀ MỘT THIẾT BỊ RIÊNG. Dùng khi anh bảo "soi cả hệ thống", "không biết đoạn nào hỏng", "so sánh mấy con switch".',
  '  Ở chế độ này: LUÔN nêu TÊN THIẾT BỊ trong từng nhận xét ("trên SW-Tang3 (tab 2) thì…"), đừng gộp chung thành kết luận mơ hồ.',
  '  Đối chiếu chéo giữa các thiết bị là việc quý nhất bạn làm được ở đây: tìm chỗ LỆCH cấu hình, VLAN thiếu một đầu, MTU/duplex không khớp, route một chiều.',
  '- Bạn TỰ CHỌN được thiết bị để thao tác bằng tham số "session" (số tab hoặc mẩu tên) — không phải nhờ anh bấm tab nữa.',
  '- NHƯNG phải nói rõ TRƯỚC mỗi lệnh là đang làm trên thiết bị nào. Chèn nhầm lệnh Cisco sang tab FortiGate là gây hại thật.',
  '- Không chắc tab nào là thiết bị nào: gọi list_sessions, đừng đoán.',
  '',
  'CÔNG CỤ — in MỘT khối mã đúng định dạng rồi DỪNG chờ kết quả:',
  '```ssh',
  '{"tool":"<tên>", ...tham số}',
  '```',
  '- read_terminal → đọc output. KHÔNG tham số (phạm vi single/multi do anh chọn, không phải bạn). DÙNG ĐẦU TIÊN để biết đang ở thiết bị gì — đừng đoán mò.',
  '- insert_command {"command":"..."} → đặt 1 lệnh lên dòng lệnh tab đang xem (không kèm Enter). Mỗi lần CHỈ 1 lệnh.',
  '- send_key {"key":"space|enter|q|ctrl_c|esc|y|n"} → gõ MỘT phím. Kết quả trả về kèm màn hình sau khi gõ.',
  '- list_sessions → danh sách MỌI thiết bị đang mở: số tab, tên, LOẠI THIẾT BỊ đoán sẵn, còn kết nối hay không. KHÔNG tham số.',
  '',
  '⭐ CHỌN THIẾT BỊ: mọi công cụ đều nhận thêm "session" — số tab (vd "session":2) hoặc một mẩu tên/IP (vd "session":"192.168.1.2").',
  '   Không nêu thì chạy trên tab đang xem. Thao tác vào tab nào thì tab đó tự được kéo ra trước mặt anh Thoại.',
  '   Nhờ tham số này bạn TỰ ĐI LẠI GIỮA CÁC THIẾT BỊ được — không phải nhờ anh bấm tab nữa.',
  '',
  '⚠️ MÀN HÌNH DỪNG Ở "--More--" — LỖI HAY GẶP NHẤT, ĐỌC KỸ:',
  'Thiết bị mạng (Cisco, Aruba, FortiGate…) in output theo TỪNG TRANG. Hết một trang nó in "--More--" rồi ĐỨNG CHỜ MỘT PHÍM.',
  'Lúc đó KHÔNG PHẢI lệnh bị treo, cũng KHÔNG PHẢI mất kết nối — nó đang đợi bạn.',
  'Kết quả tool sẽ có "dang_cho_phim": true. Khi thấy vậy:',
  '  • send_key {"key":"space"} → xem trang tiếp (lặp lại tới khi hết),',
  '  • hoặc send_key {"key":"q"} → thoát, nếu đã đủ thông tin cần.',
  'TỐT NHẤT: ngay đầu phiên hãy TẮT PHÂN TRANG rồi mới làm việc, khỏi phải bấm space liên tục:',
  '  Cisco/Aruba: "terminal length 0" · Juniper: "set cli screen-length 0"',
  '  FortiGate:   "config system console" → "set output standard" → "end"',
  '  Linux:       thêm "| cat" hoặc đặt PAGER=cat nếu lệnh mở less/more.',
  'Lệnh chạy hoài không dứt (ping liên tục, tail -f): send_key {"key":"ctrl_c"}.',
  '',
  'NHẬN DIỆN THIẾT BỊ trước khi ra lệnh (nhìn prompt/banner từ read_terminal đầu tiên):',
  '- Linux: prompt "user@host:~$" hoặc "[root@host ~]#". Phân biệt tiếp họ distro vì lệnh khác nhau: Debian/Ubuntu (apt, systemctl), RHEL/Rocky/Alma (dnf/yum), Alpine (apk, rc-service), SUSE (zypper).',
  '- Cisco IOS/IOS-XE: prompt "Switch>"/"Router#", lệnh "show running-config", "show ip interface brief".',
  '- Aruba/HPE (ArubaOS-Switch): prompt giống Cisco nhưng cú pháp VLAN khác ("vlan 10 tagged 1-4" thay vì "switchport"). Aruba CX lại khác nữa.',
  '- FortiGate: prompt "hostname #", lệnh "get system status", cấu hình kiểu "config system interface" → "edit port1" → "set ..." → "next"/"end".',
  '- MikroTik RouterOS: prompt "[admin@MikroTik] >", lệnh "/interface print".',
  '- Juniper JunOS: prompt "user@host>", có 2 chế độ operational/configure.',
  'ĐỪNG mặc định Cisco — mỗi hãng bộ lệnh riêng, gõ nhầm hãng thì lệnh vô nghĩa hoặc gây hại.',
  '',
  '⚠️⚠️ ĐỌC OUTPUT ĐÚNG CÁCH — mấy chỗ ĐÃ TỪNG ĐỌC SAI, gây kết luận nguy hiểm:',
  '',
  '1. "show interfaces trunk" — cột **Mode** (on/desirable/auto/nonegotiate) là chế độ **DTP/trunking**,',
  '   TUYỆT ĐỐI KHÔNG PHẢI giao thức gộp cổng. Thấy "Po1  on" mà kết luận "EtherChannel tĩnh, không LACP" là SAI.',
  '   Muốn biết giao thức gộp cổng, CHỈ có một chỗ: "show etherchannel summary" → cột **Protocol** (LACP / PAgP / - ).',
  '   Đọc luôn cờ trạng thái ở đó: Po1(SU) = S:Layer2 U:in use (kênh đang chạy);',
  '   cổng thành viên "(P)" = đã bundled vào kênh, "(D)" = down, "(I)" = standalone/không gộp được.',
  '   → LACP + tất cả cổng (P) = kênh KHOẺ, ĐỪNG đề xuất sửa.',
  '',
  '2. Trunk allowed "1-4094" KHÔNG có nghĩa là 4094 VLAN đang chạy qua đó. Đọc dòng',
  '   "Vlans allowed and active in management domain" — CHỈ những VLAN đó mới thật sự đi qua trunk.',
  '   Prune VLAN là VỆ SINH CẤU HÌNH (chặn VLAN lạ sau này), KHÔNG phải cách tăng băng thông. Đừng thổi phồng lợi ích.',
  '',
  '3. FortiGate: "get system interface physical" theo thiết kế CHỈ hiện cổng vật lý, KHÔNG BAO GIỜ hiện interface',
  '   aggregate/VLAN/software-switch. Không thấy LAG ở đó KHÔNG chứng minh được là không có LAG.',
  '   Muốn xem aggregate: "show system interface | grep -f aggregate" hoặc "get system interface".',
  '   Aggregate trên FortiOS mặc định chạy LACP active (đổi được bằng "set lacp-mode static").',
  '',
  '⛔ BA QUY TẮC BẮT BUỘC KHI KẾT LUẬN — vi phạm là gây hại thật:',
  '  a. TRƯỚC KHI nói "hai đầu không khớp / cấu hình sai", phải TRÍCH ĐÚNG DÒNG OUTPUT chứng minh,',
  '     và phải là dòng THẬT SỰ nói về thứ đó (xem 3 bẫy trên). Không trích được thì nói "chưa đủ dữ liệu".',
  '  b. ĐỌC LẠI những gì ĐÃ THU THẬP trong hội thoại trước khi chạy lệnh mới — câu trả lời rất hay nằm sẵn',
  '     trong output cũ. Và TUYỆT ĐỐI không kết luận trái ngược với chính mình ở lượt trước mà không nói rõ',
  '     "tôi đã nhầm ở chỗ X vì Y".',
  '  c. KHÔNG đề xuất sửa một thứ ĐANG CHẠY TỐT. Trước khi đụng vào trunk/etherchannel/LAG/route đang live,',
  '     phải chứng minh được nó ĐANG HỎNG (cổng down, cờ (I)/(D), lỗi tăng, traffic không qua).',
  '     "Có thể chưa tối ưu" KHÔNG phải lý do để sửa thứ đang gánh cả hệ thống — rủi ro mất kết nối lớn hơn cái lợi.',
  '     Cũng KHÔNG BAO GIỜ đề xuất hạ cấp (bỏ LAG về 1 cáp, tắt dự phòng) như một "phương án đơn giản".',
  '',
  'PHƯƠNG PHÁP CHẨN ĐOÁN (đi từ dưới lên theo mô hình OSI, đừng nhảy cóc):',
  '- Vật lý/cổng trước (cổng up chưa, tốc độ/duplex đúng chưa) → L2 (VLAN, trunk, MAC, spanning-tree) → L3 (IP, route, ARP) → dịch vụ.',
  '- Linux: tải máy (uptime/top) → đĩa (df -h) → dịch vụ (systemctl status) → nhật ký (journalctl -u <dịch vụ> -n 50) → mạng (ip a, ss -tlnp).',
  '- LUÔN đọc lại output SAU khi gõ lệnh để xác nhận kết quả — đừng chỉ tin là đã gõ lệnh thì xong.',
  '',
  '⚠️ BẪY HAY GẶP KHI LÀM QUA SSH (nhớ cảnh báo):',
  '- Sửa cấu hình mạng qua chính đường SSH đang dùng có thể TỰ CẮT KẾT NỐI của mình (đổi IP, sửa firewall, shutdown cổng). Cảnh báo trước và gợi ý cách an toàn ("reload in 5" của Cisco để tự rollback nếu mất liên lạc, hoặc làm qua console vật lý).',
  '- Lệnh chạy lâu (ping liên tục, tail -f) chiếm dòng lệnh — nhắc anh Ctrl+C để thoát.',
  '',
  'QUY TẮC:',
  '- Mỗi lượt chỉ in 1 khối ```ssh```. Sau [KẾT QUẢ TOOL], phân tích rồi tiếp tục hoặc trả lời.',
  '- Quy trình nhiều bước: làm TỪNG BƯỚC, chờ anh xác nhận đã bấm Enter và cho xem kết quả rồi mới sang bước kế.',
].join('\n');

/* Phần lời nhắc RIÊNG cho từng chế độ, nối vào cuối SYS_BASE. */
var SYS_MODE = {
  ask: [
    '',
    '═══ CHẾ ĐỘ HIỆN TẠI: ASK (chỉ đọc) ═══',
    'Bạn CHỈ có read_terminal. KHÔNG có insert_command, KHÔNG có run_command.',
    'Muốn anh chạy lệnh gì thì VIẾT RA cho anh tự gõ, kèm giải thích lệnh đó làm gì và rủi ro nếu có.',
    'Đừng in khối ```ssh``` gọi công cụ ghi — không tồn tại, gọi cũng bị chặn.',
  ].join('\n'),

  agent: [
    '',
    '═══ CHẾ ĐỘ HIỆN TẠI: AI AGENT (chèn lệnh, có xác nhận) ═══',
    'Bạn có read_terminal + insert_command. KHÔNG có run_command — bạn KHÔNG BAO GIỜ tự chạy lệnh.',
    'Mỗi lần insert_command, anh Thoại sẽ thấy một thẻ xác nhận trong khung chat và bấm Đồng ý / Từ chối.',
    'Bị từ chối thì ĐỪNG gọi lại lệnh đó — hỏi lý do hoặc đề xuất cách khác.',
    '⚠️ CHÈN XONG LÀ HẾT LƯỢT. Lệnh nằm chờ anh bấm Enter, nên đọc lại màn hình ngay lúc đó CHẮC CHẮN chưa thấy gì mới.',
    '   Hệ thống sẽ tự dừng lượt sau mỗi lần chèn. Việc của bạn: nói ngắn gọn "lệnh này để làm gì, bấm Enter xong sẽ thấy gì".',
    '   ĐỪNG gọi read_terminal ngay sau khi chèn — vô ích và đốt hết số lượt cho phép.',
  ].join('\n'),

  bypass: [
    '',
    '═══ CHẾ ĐỘ HIỆN TẠI: BYPASS (bạn TỰ CHẠY lệnh) ═══',
    'Bạn có read_terminal + insert_command + run_command + send_key. run_command GỬI LUÔN ENTER — lệnh chạy thật trên thiết bị của khách hàng.',
    'run_command trả về luôn màn hình sau khi chạy (output_moi) — ĐỌC NÓ, đừng gọi read_terminal lại cho thừa một vòng.',
    'Việc ĐẦU TIÊN nên làm trong phiên: tắt phân trang ("terminal length 0" với Cisco/Aruba) — không thì cứ vài dòng lại kẹt ở --More--.',
    '',
    'ĐỔI LẠI, BẮT BUỘC ĐI ĐÚNG 4 BƯỚC. TUYỆT ĐỐI KHÔNG NHẢY CÓC:',
    '  B1. KIỂM TRA TRƯỚC — gọi read_terminal, xác định đúng loại thiết bị và tình trạng hiện tại.',
    '      Chưa đọc mà đã run_command thì hệ thống CHẶN, không phải bạn muốn là được.',
    '  B2. LẬP KẾ HOẠCH TỈ MỈ — viết ra cho anh Thoại đọc, TRƯỚC KHI chạy bất cứ gì:',
    '      • mục tiêu · • từng lệnh sẽ chạy theo thứ tự · • lệnh nào chỉ đọc, lệnh nào thay đổi',
    '      • rủi ro và cách quay lui nếu hỏng · • dấu hiệu nào là thành công',
    '  B3. LÀM TỪNG BƯỚC — mỗi lần MỘT lệnh, chạy xong ĐỌC LẠI kết quả rồi mới sang bước kế.',
    '      Kết quả khác dự đoán thì DỪNG, báo anh, đừng cố đi tiếp theo kế hoạch cũ.',
    '  B4. BÁO CÁO — đã làm gì, kết quả ra sao, còn gì cần anh làm tay (vd: lưu cấu hình).',
    '',
    'VẪN PHẢI HỎI ANH (hệ thống tự bật thẻ xác nhận, không bỏ qua được):',
    '  reload/reboot/shutdown · write erase · factory reset · xoá VLAN/route/policy/interface',
    '  · rm -rf, mkfs, dd · đổi mật khẩu/tài khoản · xoá sạch firewall.',
    'Với những lệnh đó: giải thích rõ hậu quả TRƯỚC, để anh quyết.',
    '',
    'ƯU TIÊN AN TOÀN HƠN TỐC ĐỘ: đọc nhiều lần còn hơn ghi nhầm một lần. Không chắc thì hỏi.',
  ].join('\n'),
};


/* Khối hướng dẫn soi sự cố NHIỀU THIẾT BỊ — tách riêng vì nó nặng ~1.400 token.
   Chỉ nối vào lời nhắc khi thật sự có từ 2 tab trở lên; mở một tab mà vẫn gửi
   thì mỗi lượt gánh thêm chừng đó token vô ích, mà một câu hỏi có thể gọi 6-8
   lượt nên phí dồn lại rất nhanh. */
var SYS_MULTI = [
  '═══ SOI SỰ CỐ MẠNG TRÊN NHIỀU THIẾT BỊ — PHẦN QUAN TRỌNG NHẤT ═══',
  'Hỏng mạng ở một công ty gần như KHÔNG BAO GIỜ nằm gọn trong một thiết bị. Nguyên nhân hay nằm ở CHỖ GIÁP RANH:',
  'hai đầu một đường trunk khai VLAN lệch nhau, một bên bật LACP một bên không, MTU/duplex không khớp, route chỉ có một chiều,',
  'firewall chặn chiều về, DHCP relay trỏ sai. Xem từng máy riêng lẻ thì mỗi máy đều "bình thường" mà mạng vẫn hỏng.',
  '',
  'VÌ VẬY, QUY TRÌNH BẮT BUỘC KHI ANH THOẠI MỞ NHIỀU TAB:',
  '  Bước 1 — DỰNG BẢN ĐỒ. Gọi list_sessions trước tiên. Biết có mấy thiết bị, loại gì, con nào ở đâu trong đường đi.',
  '           Nếu chưa rõ vai trò từng con, HỎI anh Thoại một câu ngắn: "con nào là switch tầng nào / con nào nối ra WAN?"',
  '  Bước 2 — XÁC ĐỊNH ĐƯỜNG ĐI của luồng đang hỏng: từ máy nguồn → switch truy nhập → switch lõi → router/firewall → đích.',
  '           Chỉ soi những thiết bị NẰM TRÊN đường đó. Đừng quét tất cả cho đủ lệ.',
  '  Bước 3 — CHIA ĐÔI ĐƯỜNG ĐI (bisection). Kiểm ở khúc giữa trước: gói tin còn tới đây không?',
  '           Tới thì lỗi nằm ở nửa sau, không tới thì nửa trước. Mỗi lần kiểm loại được một nửa — nhanh hơn dò tuần tự rất nhiều.',
  '  Bước 4 — ĐỐI CHIẾU HAI ĐẦU. Với mỗi đường nối giữa hai thiết bị, đọc CÙNG MỘT hạng mục ở CẢ HAI ĐẦU rồi so:',
  '           VLAN cho phép trên trunk · native VLAN · trạng thái/tốc độ/duplex cổng · LACP/etherchannel · MTU · IP-mask cùng subnet chưa.',
  '           Dùng "session" để nhảy qua lại, đọc xong con này thì đọc ngay con kia — ĐỪNG kết luận khi mới xem một đầu.',
  '  Bước 5 — KIỂM CẢ CHIỀU VỀ. Rất nhiều sự cố là một chiều: đi được, về không được. Có route đi thì phải hỏi luôn "có route về chưa".',
  '  Bước 6 — KẾT LUẬN có bằng chứng: nêu rõ THIẾT BỊ NÀO, DÒNG OUTPUT NÀO chứng minh, rồi mới đề xuất cách sửa.',
  '           Không đủ bằng chứng thì nói thẳng "chưa đủ dữ liệu, cần xem thêm X" — ĐỪNG đoán bừa cho có kết luận.',
  '',
  'ĐỐI CHIẾU CHÉO — mấy cặp hay lệch nhất, gặp nhiều tab thì kiểm ngay:',
  '  • VLAN có trên switch này mà thiếu trên switch kia → máy cùng VLAN không thấy nhau',
  '  • Trunk: danh sách VLAN allowed hai đầu khác nhau, hoặc native VLAN lệch',
  '  • Cổng nối nhau: một bên up một bên down, hoặc auto-negotiate ra duplex khác nhau',
  '  • Định tuyến: A có route tới B nhưng B không có route về A',
  '  • Firewall/ACL: policy cho chiều đi mà thiếu chiều về, hoặc NAT che mất IP nguồn',
  '  • Spanning-tree: hai con cùng tranh root, hoặc cổng bị block ngoài dự tính',
  '  • Thời gian/NTP lệch → log các máy không khớp mốc, rất khó đối chiếu sự kiện',
  '',
  'TRÌNH BÀY KHI LÀM NHIỀU THIẾT BỊ: luôn mở đầu mỗi nhận xét bằng TÊN THIẾT BỊ ("Trên SW-Tang3 (tab 2): …").',
  'Không được gộp thành một câu chung chung — anh Thoại phải biết chỗ nào cần đụng tay vào.',
  '',
].join('\n');

/* Mục lục kho kiến thức — CHỈ tên mục + mô tả một dòng; nội dung nằm ở file kho.
   Đây là cách thay cho việc nhồi kiến thức vào lời nhắc: kho dày bao nhiêu tuỳ ý
   mà lời nhắc vẫn ngắn, vì lời nhắc bị gửi lại MỖI LƯỢT còn kho thì chỉ khi cần. */
function kbBlock() {
  if (!window.__NET_KB) return '';
  return [
    '',
    '═══ KHO KIẾN THỨC — TRA TRƯỚC KHI KẾT LUẬN ═══',
    'Có công cụ kb_lookup {"topic":"<tên mục>"} (tra nhiều mục: {"topic":"a,b"}). Nội dung trả về là',
    'kiến thức nền đã kiểm chứng: cách đọc output từng hãng, mô hình mạng, quy trình chẩn đoán.',
    '',
    'BẮT BUỘC tra kho TRƯỚC khi kết luận, trong các trường hợp:',
    '  • Sắp nói "cấu hình sai / hai đầu không khớp / cần sửa" → tra "bang-chung" + mục kỹ thuật liên quan',
    '  • Đọc output mà chưa chắc một cột/cờ nghĩa là gì → tra "doc-output-<hãng>"',
    '  • Chưa rõ đang đứng ở đâu trong mô hình mạng → tra "mo-hinh-mang"',
    '  • Trước khi đề xuất lệnh sửa thứ đang chạy → tra "an-toan-thao-tac"',
    'Tra kho KHÔNG đụng gì tới thiết bị và rất rẻ. Đoán mò rồi kết luận sai mới đắt.',
    'Kiến thức trong kho ĐÁNG TIN HƠN trí nhớ của bạn — có mâu thuẫn thì theo kho.',
    '',
    'MỤC LỤC:',
    window.__NET_KB.indexText(),
  ].join('\n');
}

function sysPrompt() {
  var p = SYS_BASE + (SYS_MODE[MODE] || SYS_MODE.ask);
  /* Nhiều tab mới cần hướng dẫn phối hợp — một tab thì gửi cũng vô ích. */
  if (sessions.length >= 2) p += '\n' + SYS_MULTI;
  p += '\n' + kbBlock();
  return p;
}


/* Nút Single / Multi session trên bảng chat */
Array.prototype.forEach.call(document.querySelectorAll('#aiScope .sc'), function (b) {
  b.onclick = function () { setAiScope(b.dataset.scope); };
});

/* ══════════ Chọn chế độ + gác theo quyền ══════════════════════════════════
   Chế độ nào user không được cấp thì nút khoá luôn (mờ, bấm không được) và ghi
   rõ lý do — hiện ra mà khoá tốt hơn giấu đi: người dùng biết có thứ đó tồn tại
   để đi xin, thay vì tưởng dashboard thiếu. Server vẫn kiểm lại độc lập. */
function _perms() {
  try {
    if (window.__USER__) return window.__USER__;
    var m = document.cookie.match(/(?:^|;\s*)dh_user=([^;]+)/);
    return m ? JSON.parse(decodeURIComponent(m[1])) : {};
  } catch (e) { return {}; }
}
function canMode(k) {
  var u = _perms();
  if (u.isAdmin) return true;
  return ((u.permissions || {})[MODES[k].perm] || 'none') !== 'none';
}

function setMode(k) {
  if (!MODES[k] || !canMode(k)) return;
  MODE = k;
  Array.prototype.forEach.call(document.querySelectorAll('#aiModes .md'), function (b) {
    b.classList.toggle('on', b.dataset.mode === k);
  });
  /* Chỉ ByPass mới hiện dòng cảnh báo. Hai chế độ kia đã có tooltip, in thêm chữ
     chỉ tổ chiếm chỗ của hội thoại — mà cảnh báo hiện ở mọi lúc thì thành nền,
     không ai đọc nữa; để dành cho đúng chỗ đáng cảnh báo. */
  var n = $('aiModeNote');
  if (MODES[k].danger) { n.innerHTML = MODES[k].note; n.style.display = ''; }
  else { n.style.display = 'none'; }
  try { localStorage.setItem('sshfield_aimode', k); } catch (e) {}
}

/* ⚠️ Phần DỰNG các nút chế độ nằm ở CUỐI file, sau khi `ta`/`btnSend` đã được
   gán — đặt ở đây thì lúc chạy chúng còn undefined và cả file chết ngay. */

/* ── Giao diện chat ── */
var panel = $('ai'), msgs = $('msgs'), ta = $('q'), btnSend = $('btnSend');
var chatHistory = [];   /* KHÔNG đặt tên 'history' — đụng window.history, lỗi im lặng */
var busy = false;

$('ai-btn').onclick = function () { panel.classList.toggle('open'); if (panel.classList.contains('open')) ta.focus(); };
$('aiX').onclick = function () { panel.classList.remove('open'); };
ta.onkeydown = function (e) { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); doSend(); } };
btnSend.onclick = doSend;

function addMsg(cls, text) {
  var d = document.createElement('div');
  d.className = 'm ' + cls; d.textContent = text;
  msgs.appendChild(d); msgs.scrollTop = msgs.scrollHeight;
  return d;
}
function note(t) { addMsg('m-t', t); }

function doSend() {
  var q = (ta.value || '').trim();
  if (!q || busy) return;
  var wc = msgs.querySelector('.wc'); if (wc) wc.remove();
  ta.value = ''; addMsg('m-u', q); chatHistory.push({ role:'user', content:q });
  runLoop();
}

/* ══════════ Nút Dừng ═══════════════════════════════════════════════════════
   Hai thứ phải cắt được, thiếu cái nào cũng vẫn thấy như bị treo:
     1. luồng đang tải dở từ LLM  → AbortController
     2. vòng lặp gọi công cụ      → cờ STOPPED, kiểm ở đầu mỗi bước
   Thẻ xác nhận đang chờ cũng phải được giải phóng (coi như từ chối), không thì
   lời hứa treo mãi và vòng lặp không bao giờ kết thúc. */
var STOPPED = false;
var CURRENT_ABORT = null;

function stopRun() {
  STOPPED = true;
  try { CURRENT_ABORT && CURRENT_ABORT.abort(); } catch (e) {}
  var q = pendingAsks; pendingAsks = [];
  q.forEach(function (f) { try { f(); } catch (e) {} });
}

function runLoop() {
  busy = true; STOPPED = false; clearReads();
  btnSend.style.display = 'none'; $('btnStop').style.display = '';
  var loops = 0, bubble = addMsg('m-a', '…');

  function step() {
    if (STOPPED) return finish(true);
    /* Bấm giờ từng chặng để biết chậm ở ĐÂU: chờ model hay chạy công cụ.
       Không có con số này thì mọi phàn nàn "nó chậm" đều chỉ đoán được. */
    var t0 = Date.now();
    streamLLM(function (full) { bubble.textContent = full || '…'; msgs.scrollTop = msgs.scrollHeight; })
      .then(function (full) {
        if (STOPPED) return finish(true);
        var dtModel = ((Date.now() - t0) / 1000).toFixed(1);
        var tool = parseTool(full);
        chatHistory.push({ role:'assistant', content:full });
        /* Bóc khối lệnh khỏi bong bóng NGAY, kể cả khi sắp dừng — trước đây lúc
           hết lượt thì khối ```ssh``` lòi ra màn hình dạng JSON thô, nhìn như lỗi. */
        var hienThi = full.replace(/```ssh[\s\S]*?```/g, '').trim();
        if (!tool || loops >= maxLoops()) {
          bubble.textContent = hienThi || (tool ? '⚙️ …' : '(không có nội dung)');
          note('🧠 model ' + dtModel + 's');
          if (tool) return finish(false, 'limit');
          return finish();
        }
        bubble.textContent = hienThi || '⚙️ đang xử lý…';
        loops++;
        var tTool = Date.now();
        execTool(tool).then(function (res) {
          if (STOPPED) return finish(true);
          var dtTool = ((Date.now() - tTool) / 1000).toFixed(1);
          note((res.__denied ? '⛔ ' : '⚙️ ') + tool.tool + (res.__denied ? ' (bỏ qua)' : ' ✓')
               + '   🧠 model ' + dtModel + 's · công cụ ' + dtTool + 's');
          chatHistory.push({ role:'user', content:'[KẾT QUẢ TOOL ' + tool.tool + ']\n' + JSON.stringify(res) });
          /* Agent vừa chèn lệnh xong → dừng lượt, chờ anh Thoại bấm Enter. */
          if (shouldPauseAfter(tool, res)) return finish(false, 'enter');
          bubble = addMsg('m-a', '…');
          step();
        });
      })
      .catch(function (e) {
        /* Bấm Dừng làm fetch ném AbortError — đó là mong muốn, không phải lỗi. */
        if (STOPPED || /abort/i.test(String(e && e.name || e))) return finish(true);
        bubble.textContent = '⚠️ Lỗi: ' + (e && e.message || e);
        finish();
      });
  }
  function finish(stopped, ly_do) {
    if (stopped) {
      note('⏹ Đã dừng theo yêu cầu.');
      /* Cho AI biết nó bị cắt giữa chừng — không nói thì lượt sau nó tưởng bước
         dở dang đã xong và đi tiếp từ chỗ sai. */
      chatHistory.push({ role:'user', content:'[NGƯỜI DÙNG BẤM DỪNG] Lượt vừa rồi bị cắt giữa chừng. Đừng cho là bước đang làm đã xong. Chờ chỉ dẫn mới.' });
    }
    busy = false; STOPPED = false; CURRENT_ABORT = null; pendingAsks = [];
    btnSend.style.display = ''; $('btnStop').style.display = 'none';

    /* Dừng vì hết lượt → mời đi tiếp bằng một nút, thay vì bỏ lửng.
       Trước đây chỉ in "đã đạt giới hạn số bước", anh Thoại không biết là AI còn
       việc dở hay đã xong, cũng không có cách nào cho nó chạy tiếp. */
    if (ly_do === 'limit') moiDiTiep('AI đã dùng hết ' + maxLoops() + ' lượt công cụ cho câu hỏi này mà vẫn còn việc dở.',
      '▶ Cho chạy tiếp');
    if (ly_do === 'enter') moiDiTiep('Lệnh đang nằm chờ trên dòng lệnh — anh bấm Enter trong terminal, xem kết quả rồi cho AI xem tiếp.',
      '▶ Tôi bấm Enter rồi, xem đi');

    ta.focus();
  }
  step();
}

/* Thẻ "đi tiếp" — dừng giữa chừng thì phải có lối đi tiếp ngay trong khung chat,
   chứ bắt anh Thoại gõ lại "làm tiếp đi" mỗi lần là phiền và dễ tưởng bị treo. */
function moiDiTiep(lyDo, nhan) {
  var box = document.createElement('div');
  box.className = 'ask';
  var t = document.createElement('div'); t.className = 't'; t.textContent = '⏸ Tạm dừng';
  var w = document.createElement('div'); w.className = 'who'; w.textContent = lyDo;
  var btns = document.createElement('div'); btns.className = 'btns';
  var go = document.createElement('button'); go.textContent = nhan;
  var no = document.createElement('button'); no.className = 'no'; no.textContent = 'Thôi, để đó';
  btns.appendChild(go); btns.appendChild(no);
  box.appendChild(t); box.appendChild(w); box.appendChild(btns);
  msgs.appendChild(box); msgs.scrollTop = msgs.scrollHeight;

  go.onclick = function () {
    box.remove();
    if (busy) return;

    /* ⚡ ĐÍNH KÈM LUÔN KẾT QUẢ, đừng bắt AI xin đọc.
       Trước đây bấm "xem tiếp" thì phải mất HAI vòng gọi model: vòng 1 để AI nói
       "cho tôi read_terminal", vòng 2 mới đọc kết quả và trả lời. Mỗi vòng là một
       lần chờ model — đó chính là quãng chậm anh Thoại thấy sau khi bấm Enter.
       Mình đã có sẵn output ngay trong trình duyệt (tốn ~4ms), nên gửi kèm luôn:
       còn MỘT vòng, nhanh gấp đôi ở đúng chỗ hay dùng nhất. */
    var kem = '';
    if (LAST_INSERT && LAST_INSERT.s && sessions.indexOf(LAST_INSERT.s) >= 0) {
      var out = rawSince(LAST_INSERT.s, LAST_INSERT.mark);
      if (out) {
        markRead(LAST_INSERT.s);          // đã thấy màn hình thật của con này
        kem = '\n\n[MÀN HÌNH SAU KHI BẤM ENTER — trên ' + LAST_INSERT.s.label + ', lệnh "' + LAST_INSERT.cmd + '"]\n'
            + redact(out.length > 3000 ? '…(cắt bớt phần đầu)…\n' + out.slice(-3000) : out)
            + '\n\nĐây là kết quả thật, KHÔNG cần gọi read_terminal nữa. Phân tích rồi làm bước tiếp.';
        LAST_INSERT = null;
      }
    }
    chatHistory.push({ role:'user', content:'[TIẾP TỤC] Làm tiếp phần còn dở.' + kem });
    runLoop();
  };
  no.onclick = function () { box.remove(); };
}

function parseTool(text) {
  var m = text.match(/```ssh\s*([\s\S]*?)```/);
  if (!m) return null;
  try { var o = JSON.parse(m[1].trim()); return (o && o.tool && TOOLS[o.tool]) ? o : null; } catch (e) { return null; }
}

/* ══════════ Thẻ XÁC NHẬN ngay trong khung chat ═════════════════════════════
   Trước dùng window.confirm(): hộp thoại của trình duyệt đè lên màn hình, che
   mất chính cái terminal và đoạn hội thoại mà anh cần đọc để quyết định — mà
   quyết định ở đây là "có gõ lệnh này vào thiết bị của khách hay không".
   Thẻ nằm trong luồng chat thì đọc được cả ngữ cảnh, và còn lưu lại để sau này
   xem lại đã đồng ý những gì. */
function askInChat(opts) {
  return new Promise(function (resolve) {
    var box = document.createElement('div');
    box.className = 'ask' + (opts.danger ? ' danger' : '');

    var t = document.createElement('div'); t.className = 't';
    t.textContent = (opts.danger ? '⛔ ' : '⚠️ ') + opts.title;

    var who = document.createElement('div'); who.className = 'who';
    who.textContent = 'Thiết bị: ' + (opts.device || '(không rõ)');

    var cmd = document.createElement('div'); cmd.className = 'cmd';
    cmd.textContent = opts.command;      // textContent: lệnh do AI sinh, không nhét HTML

    var btns = document.createElement('div'); btns.className = 'btns';
    var yes = document.createElement('button'); yes.textContent = opts.yesText || 'Đồng ý';
    var no  = document.createElement('button'); no.className = 'no'; no.textContent = 'Từ chối';
    btns.appendChild(yes); btns.appendChild(no);

    box.appendChild(t); box.appendChild(who); box.appendChild(cmd);
    if (opts.why) { var w = document.createElement('div'); w.className = 'who'; w.textContent = opts.why; box.appendChild(w); }
    box.appendChild(btns);
    msgs.appendChild(box); msgs.scrollTop = msgs.scrollHeight;

    function done(okv) {
      box.classList.add('done');
      btns.remove();
      var v = document.createElement('div'); v.className = 'verdict';
      v.textContent = okv ? '✅ Anh đã đồng ý' : '⛔ Anh đã từ chối';
      v.style.color = okv ? 'var(--ok)' : 'var(--err)';
      box.appendChild(v);
      msgs.scrollTop = msgs.scrollHeight;
      resolve(okv);
    }
    yes.onclick = function () { done(true); };
    no.onclick  = function () { done(false); };
    /* Bấm Dừng giữa chừng cũng phải giải phóng lời hứa này, không thì treo mãi. */
    pendingAsks.push(function () { if (box.isConnected && btns.isConnected) done(false); });
  });
}
var pendingAsks = [];

/* ĐÃ ĐỌC THIẾT BỊ NÀO trong lượt này — điều kiện bắt buộc của ByPass.
   Ban đầu chỉ là một cờ chung "đã đọc gì đó chưa", nhưng từ khi AI tự chọn được
   thiết bị thì cờ chung là hớ: đọc con A xong đi gõ thẳng vào con B vẫn lọt.
   Giờ đánh dấu TỪNG PHIÊN — muốn gõ vào con nào thì phải đọc đúng con đó trước.
   Đặt lại mỗi lượt hỏi: mỗi yêu cầu mới phải kiểm tra lại tình trạng thật, không
   được dựa vào thứ đã đọc từ mấy phút trước (mạng thay đổi liên tục). */
function markRead(s) { if (s) s.aiRead = true; }
function clearReads() { sessions.forEach(function (s) { s.aiRead = false; }); }

function execTool(tool) {
  var allowed = MODES[MODE].tools;
  /* Thiết bị ĐÍCH chứ không phải tab đang xem: từ khi AI chỉ định được session,
     thẻ xác nhận phải nêu đúng con mà lệnh sẽ chạy vào — nếu không thì lớp chặn
     cuối cùng thành vô nghĩa (anh duyệt cho con A, lệnh lại chạy vào con B). */
  var s = resolveSession(tool.session) || active();
  var cmd = typeof tool.command === 'string' ? tool.command : '';

  /* Chặn theo chế độ — lời nhắc đã nói rồi nhưng vẫn phải chặn bằng code:
     lời nhắc là mong muốn, code mới là bảo đảm. */
  if (allowed.indexOf(tool.tool) < 0) {
    return Promise.resolve({ __denied:true, ok:false,
      error:'Chế độ ' + MODES[MODE].name + ' không cho dùng "' + tool.tool + '".'
          + (MODE === 'ask' ? ' Hãy VIẾT lệnh ra cho anh Thoại tự gõ.' : '') });
  }

  /* ByPass: chưa đọc CHÍNH THIẾT BỊ ĐÓ thì chưa được gõ vào nó. Đây là bước B1
     trong quy trình 4 bước, và là thứ duy nhất trong quy trình ép được bằng code. */
  if (tool.tool === 'run_command' && (!s || !s.aiRead)) {
    return Promise.resolve({ __denied:true, ok:false,
      error:'Chưa đọc màn hình của ' + (s ? s.label : 'thiết bị này') + ' lần nào trong lượt này mà đã định gõ lệnh vào đó.',
      phai_lam:'Gọi read_terminal' + (s ? ' {"session":' + (sessions.indexOf(s) + 1) + '}' : '') + ' trước để xem thiết bị đang ở tình trạng nào, rồi trình kế hoạch.',
      vi_sao:'Mỗi thiết bị phải được kiểm tra riêng — đọc con này rồi gõ sang con khác là kiểu làm ẩu nguy hiểm nhất ở hiện trường.' });
  }

  var needAsk = false, danger = false, title = '', yesText = '';
  if (tool.tool === 'insert_command') {
    /* Agent: hỏi từng lệnh. ByPass: chèn (không Enter) thì không cần hỏi, trừ
       khi lệnh nằm trong danh sách nguy hiểm. */
    danger = isDangerous(cmd);
    needAsk = (MODE === 'agent') || danger;
    title = danger ? 'AI muốn đặt một lệnh NGUY HIỂM lên dòng lệnh'
                   : 'AI muốn đặt lệnh này lên dòng lệnh';
    yesText = 'Đồng ý chèn';
  } else if (tool.tool === 'run_command') {
    danger = isDangerous(cmd);
    needAsk = danger;                 // ByPass tự chạy, trừ lệnh nguy hiểm
    title = 'AI muốn TỰ CHẠY một lệnh NGUY HIỂM';
    yesText = 'Cho chạy';
  }

  if (!needAsk) return _run(tool);

  return askInChat({
    title: title,
    device: s ? s.label : null,
    command: cmd,
    danger: danger,
    yesText: yesText,
    why: tool.tool === 'run_command'
      ? 'Lệnh này CHẠY NGAY khi anh đồng ý (AI tự bấm Enter).'
      : 'Lệnh chỉ được đặt lên dòng lệnh — anh vẫn phải tự bấm Enter.',
  }).then(function (ok) {
    if (!ok) return { __denied:true, message:'Anh Thoại từ chối. Đừng gọi lại lệnh này; hỏi lý do hoặc đề xuất cách khác.' };
    return _run(tool);
  });
}

/* Ở chế độ Agent, chèn lệnh xong là HẾT VIỆC của lượt này: lệnh còn nằm chờ anh
   Thoại bấm Enter, nên đọc lại màn hình lúc này chắc chắn chưa thấy gì mới.
   Không dừng thì AI cứ chèn → đọc → chưa thấy gì → chèn lại… đốt sạch số lượt
   rồi báo "đã đạt giới hạn số bước" (đúng cảnh anh Thoại gặp).
   Dừng ở đây cũng đúng tinh thần của chế độ: người bấm Enter là người quyết. */
function shouldPauseAfter(tool, res) {
  return MODE === 'agent' && tool.tool === 'insert_command' && res && res.ok;
}

function _run(tool) {
  try { return Promise.resolve(TOOLS[tool.tool](tool)).catch(function (e) { return { ok:false, error:String(e && e.message || e) }; }); }
  catch (e) { return Promise.resolve({ ok:false, error:String(e && e.message || e) }); }
}

/* ══════════ Nén lịch sử — thứ làm AI chạy chậm nhất ════════════════════════
   Mỗi lượt gọi phải gửi LẠI TOÀN BỘ hội thoại. Kết quả tool thì to (một lần đọc
   3 tab có thể hơn 10 nghìn token) và nằm lại trong lịch sử mãi mãi → lượt sau
   gánh cả lượt trước, chi phí tăng theo bình phương số bước. Đo thật: một câu
   hỏi 6 bước ở chế độ ByPass phải nạp ~85 nghìn token, trong đó phần lớn là đọc
   lại chính thứ đã đọc.

   Cách chữa: chỉ giữ NGUYÊN VẸN 2 kết quả tool gần nhất — đó là thứ AI đang cần
   để suy luận tiếp. Kết quả cũ hơn thì lược, vì AI đã phân tích chúng ở các câu
   trả lời trước rồi (phần phân tích đó vẫn giữ nguyên trong lịch sử). Cần lại
   thì gọi tool đọc lại, rẻ hơn nhiều so với vác theo suốt buổi. */
var KEEP_FULL_TOOL_RESULTS = 2;

function compactHistory() {
  var idx = [];
  for (var i = 0; i < chatHistory.length; i++) {
    var m = chatHistory[i];
    if (m.role === 'user' && m.content.indexOf('[KẾT QUẢ TOOL') === 0) idx.push(i);
  }
  var keep = idx.slice(-KEEP_FULL_TOOL_RESULTS);
  idx.forEach(function (i) {
    if (keep.indexOf(i) >= 0) return;
    var c = chatHistory[i].content;
    if (c.length <= 400) return;
    var ten = (/^\[KẾT QUẢ TOOL ([^\]]+)\]/.exec(c) || [])[1] || 'tool';
    chatHistory[i] = { role:'user', content:
      '[KẾT QUẢ TOOL ' + ten + ' — ĐÃ LƯỢC cho gọn]\n' + c.slice(c.indexOf('\n') + 1, 300)
      + '\n…(phần còn lại đã bỏ bớt. Bạn đã phân tích nó ở trên rồi; cần xem lại thì gọi công cụ đọc lại.)' };
  });
}

/* Khoá ô nhập kèm đồng hồ đếm ngược khi hết hạn mức — cho người dùng biết CHÍNH
   XÁC còn bao lâu, thay vì đoán rồi bấm thử. */
var _khoaTimer = null;
function khoaVi(giay) {
  if (_khoaTimer) clearInterval(_khoaTimer);
  var conLai = Math.max(1, parseInt(giay, 10) || 60);
  var chuGoc = btnSend.textContent;
  ta.disabled = true; btnSend.disabled = true;
  function ve() {
    btnSend.textContent = conLai + 's';
    ta.placeholder = 'Hết lượt gọi AI — mở lại sau ' + conLai + ' giây';
    if (--conLai < 0) {
      clearInterval(_khoaTimer); _khoaTimer = null;
      ta.disabled = false; btnSend.disabled = false;
      btnSend.textContent = chuGoc;
      ta.placeholder = 'Hỏi gì đó… (Enter để gửi)';
    }
  }
  ve();
  _khoaTimer = setInterval(ve, 1000);
}

function streamLLM(onDelta, attempt) {
  attempt = attempt || 1;
  if (attempt === 1) compactHistory();
  /* mode đi kèm mỗi lượt: server tự kiểm quyền cho chế độ đó (xem console-serial.js).
     Giấu nút ngoài giao diện là chưa đủ — ai mở F12 cũng gọi thẳng API được. */
  var body = { mode:MODE, messages:[{ role:'system', content:sysPrompt() }].concat(chatHistory), stream:true };
  if (MODEL) body.model = MODEL;    // chỉ gửi khi cố tình ép model (thường là không)
  CURRENT_ABORT = new AbortController();
  return fetch(LLM_URL, { method:'POST', credentials:'include', signal:CURRENT_ABORT.signal,
                          headers:{ 'Content-Type':'application/json' }, body:JSON.stringify(body) })
    .then(function (r) {
      /* 524 = Cloudflare hết giờ chờ (9Router đôi khi chọn backend chậm) — tự thử lại. */
      if (r.status === 524 && attempt < 3) {
        onDelta('⏳ Phản hồi chậm, đang thử lại (' + (attempt + 1) + '/3)…');
        return streamLLM(onDelta, attempt + 1);
      }
      if (!r.ok) return r.text().then(function (t) {
        var o = null; try { o = JSON.parse(t); } catch (_) {}
        /* Hết hạn mức: khoá ô nhập đúng số giây còn phải chờ. Không khoá thì người
           dùng cứ bấm lại liên tục, lần nào cũng ăn lỗi y hệt (ảnh anh Thoại gửi). */
        if (r.status === 429 && o && o.retry_after) khoaVi(o.retry_after);
        throw new Error((o && o.error) || ('HTTP ' + r.status));
      });
      var reader = r.body.getReader(), dec = new TextDecoder(), buf = '', full = '';
      return (function pump() {
        return reader.read().then(function (res) {
          if (res.done) return full;
          buf += dec.decode(res.value, { stream:true });
          var lines = buf.split('\n'); buf = lines.pop();
          for (var i = 0; i < lines.length; i++) {
            var ln = lines[i].trim();
            if (ln.indexOf('data:') !== 0) continue;
            var payload = ln.slice(5).trim();
            if (payload === '[DONE]') continue;
            try {
              var jj = JSON.parse(payload);
              var delta = jj.choices && jj.choices[0] && jj.choices[0].delta;
              if (delta && delta.content) { full += delta.content; onDelta(full); }
            } catch (e) {}
          }
          return pump();
        });
      })();
    });
}

  /* Trang gọi vào sau khi dò được cầu nối — mở/khoá nút mở tab. */
  window.__sshfieldReady = function (ok) { $('btnGo').disabled = !ok; };
  $('btnGo').disabled = true;

/* ══════════ Dựng nút chế độ AI (đặt CUỐI FILE có lý do) ═══════════════════
   Khối này đụng `ta` và `btnSend` — hai biến của phần giao diện chat, khai bằng
   `var` nên bị kéo lên đầu nhưng CHƯA CÓ GIÁ TRỊ cho tới lúc dòng gán chạy.
   Đặt sớm hơn thì `ta.disabled` ném lỗi và cả file chết theo (đã dính lúc viết). */
(function () {
  var duoc = Object.keys(MODES).filter(canMode);
  Array.prototype.forEach.call(document.querySelectorAll('#aiModes .md'), function (b) {
    var k = b.dataset.mode;
    if (!canMode(k)) {
      b.disabled = true;
      b.title = 'Chưa được cấp quyền dùng chế độ ' + MODES[k].name + ' — nhờ admin cấp trong Settings → Role.';
    }
    b.onclick = function () { setMode(k); };
  });

  if (!duoc.length) {
    /* Có quyền mở trang nhưng không có quyền AI nào: khoá hẳn ô nhập, nói rõ lý
       do. Cố ý KHÔNG ẩn bảng chat — ẩn đi thì người dùng tưởng tính năng hỏng. */
    $('aiModeNote').innerHTML = '🔒 Anh chưa được cấp quyền dùng trợ lý AI ở chế độ nào. Nhờ admin cấp trong <b>Settings → Role</b>.';
    $('aiModeNote').style.display = '';
    ta.disabled = true; ta.placeholder = 'Chưa có quyền dùng trợ lý AI';
    btnSend.disabled = true;
    return;
  }

  var saved = null;
  try { saved = localStorage.getItem('sshfield_aimode'); } catch (e) {}
  /* Mặc định về chế độ AN TOÀN NHẤT mà user có quyền, KHÔNG phải chế độ mạnh nhất.
     Nhớ lại chế độ cũ thì tiện, nhưng ByPass thì CỐ Ý KHÔNG NHỚ — mở trang ra mà
     AI đã sẵn sàng tự chạy lệnh trên thiết bị khách hàng là quá nguy hiểm; muốn
     dùng thì mỗi lần phải chủ động bật lại. */
  var start = (saved && saved !== 'bypass' && canMode(saved)) ? saved
            : (duoc.indexOf('ask') >= 0 ? 'ask' : duoc[0]);
  setMode(start);
})();

$('btnStop').onclick = stopRun;
})();
