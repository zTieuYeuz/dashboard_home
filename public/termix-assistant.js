/* ═══════════════════════════════════════════════════════════════════
   termix-assistant.js — Nút 🤖 AI nổi NHÚNG TRONG Termix (SSH terminal)
   -------------------------------------------------------------------
   Nạp TỰ ĐỘNG bởi patcher trong src/termix.js (opts.aiAssistant) — không
   phải sửa Termix. Chạy same-origin trên dashboard (trang Termix phục vụ
   qua /proxy/termix-home).

   Kiến trúc (khác PNETLab — KHÔNG cần bridge):
   - ĐỌC màn hình: đọc thẳng DOM xterm.js (.xterm-rows) của terminal đang
     hiển thị → AI thấy ĐÚNG cái đang trên màn hình để tư vấn chính xác.
   - CHÈN lệnh: qua window.__termixInsert() (patcher phơi ra) — gửi lệnh vào
     socket SSH đang mở, ĐẶT lên dòng lệnh nhưng KHÔNG kèm Enter. User tự
     xem rồi bấm Enter để chạy. AI KHÔNG BAO GIỜ tự chạy.
   - LLM: proxy /api/termix-llm (Worker gắn secret 9Router, gác session+ssh,
     stream SSE). Key không lộ trong browser.
   - Giao thức tool: model in khối ```ssh {json}``` → JS thực thi → nạp kết
     quả lại → lặp (giống pnet-assistant, model-agnostic).
   ═══════════════════════════════════════════════════════════════════ */
(function () {
  'use strict';
  if (window.__TERMIX_AI__) return; window.__TERMIX_AI__ = 1;

  var MODEL = 'pnetlab';          // alias 9Router của anh (chỉ là tên định tuyến — đổi ở đây nếu muốn model khác)
  var MAX_TOOL_LOOPS = 12;

  function proxyBase() { try { return location.origin; } catch (e) { return 'https://dashboard.home-server.id.vn'; } }
  var LLM_URL = proxyBase() + '/api/termix-llm';

  /* ── ĐỌC màn hình terminal đang hiển thị (tab active) ── */
  function readVisible() {
    var xs = Array.prototype.slice.call(document.querySelectorAll('.xterm'));
    if (!xs.length) return { ok: false, error: 'Không tìm thấy terminal nào — anh đã mở phiên SSH tới host chưa?' };
    // Ưu tiên terminal ĐANG hiển thị (tab active): có kích thước + nằm trong DOM thấy được.
    var vis = xs.filter(function (el) { return el.offsetParent !== null && el.clientHeight > 40; });
    var el = vis.length ? vis[vis.length - 1] : xs[xs.length - 1];
    var rows = el.querySelector('.xterm-rows');
    var text = '';
    if (rows && rows.children.length) {
      var lines = [];
      for (var i = 0; i < rows.children.length; i++) {
        lines.push((rows.children[i].textContent || '').replace(/ /g, ' ').replace(/\s+$/, ''));
      }
      while (lines.length && lines[lines.length - 1] === '') lines.pop();   // bỏ dòng trống cuối
      text = lines.join('\n');
    } else {
      text = (el.textContent || '');
    }
    return { terminals: xs.length, screen: text };
  }

  /* ── Lọc mã điều khiển ANSI/escape để ra text đọc được ── */
  function stripAnsi(s) {
    return String(s)
      .replace(/\x1b\][\s\S]*?(\x07|\x1b\\)/g, '')       // OSC ... BEL/ST
      .replace(/\x1b[\[\]][0-9;?]*[ -\/]*[@-~]/g, '')      // CSI / SGR màu
      .replace(/\x1b[@-Z\\-_]/g, '')                        // escape đơn
      .replace(/\r\n/g, '\n').replace(/\r/g, '\n')         // CR -> xuống dòng
      .replace(/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/g, '')    // ký tự điều khiển còn lại (giữ \t \n)
      .replace(/[ \t]+\n/g, '\n');                         // bỏ khoảng trắng cuối dòng
  }

  /* ── Che các chuỗi nhạy cảm TRƯỚC KHI gửi lên LLM (mật khẩu/key/token…) ──
     Không hoàn hảo (không thể bắt hết mọi định dạng) nhưng chặn các mẫu rủi ro cao phổ biến.
     Ưu tiên an toàn: thà che nhầm một chút còn hơn để lộ. */
  var _redacted = false;
  function _mask() { _redacted = true; return '[ĐÃ CHE]'; }
  function redact(s) {
    if (!s) return s;
    _redacted = false;
    var out = String(s)
      // Khối private key PEM (SSH/TLS)
      .replace(/-----BEGIN [^-\n]*PRIVATE KEY-----[\s\S]*?-----END [^-\n]*PRIVATE KEY-----/g, function () { return _mask() + ' (private key)'; })
      // Cisco: "password 7 <hash>", "secret 5 <hash>"
      .replace(/\b((?:password|secret))(\s+\d\s+)(\S+)/gi, function (m, k, mid) { return k + mid + _mask(); })
      // key = value / key: value cho các key nhạy cảm (bắt cả key có tiền tố: db_password, admin_token…)
      .replace(/([a-z0-9_.\-]*(?:pass(?:word|wd|phrase)?|secret|token|api[_-]?key|access[_-]?key|client[_-]?secret|private[_-]?key|auth[_-]?token))(\s*[:=]\s*)(["']?)([^\s"'&]{3,})(\3)/gi,
        function (m, k, sep, q) { return k + sep + q + _mask() + q; })
      // "password <value>" / "secret <value>" (Cisco/plain) — value không có khoảng trắng
      .replace(/\b((?:password|passwd|secret|passphrase))(\s+)(?!\d\s)(\S{3,})/gi, function (m, k, sp) { return k + sp + _mask(); })
      // Authorization: Bearer/Basic <token>
      .replace(/(Authorization\s*:\s*(?:Bearer|Basic)\s+)(\S+)/gi, function (m, p1) { return p1 + _mask(); })
      // AWS Access Key ID
      .replace(/\bAKIA[0-9A-Z]{16}\b/g, function () { return _mask() + ' (AWS)'; });
    return out;
  }

  /* ── ĐỌC terminal: ưu tiên full_output (đã gom cả phần cuộn khỏi màn hình) ── */
  function readTerminal() {
    var vis = readVisible();
    // full_output: toàn bộ dữ liệu server gửi trong phiên (patcher gom từ socket SSH) → đọc được
    // cả output/log dài đã cuộn khỏi màn hình, không cần user bấm Space.
    var full = '';
    try { if (typeof window.__termixReadFull === 'function') full = stripAnsi(window.__termixReadFull()); } catch (e) {}
    full = (full || '').replace(/\n{3,}/g, '\n\n').trim();

    if (!vis.terminals && !full) return { ok: false, error: 'Không tìm thấy terminal nào — anh đã mở phiên SSH tới host chưa?' };

    var anyRedacted = false;
    var res = { ok: true, terminals: vis.terminals };
    if (full) {
      var rf = redact(full.slice(-24000)); anyRedacted = anyRedacted || _redacted;   // ~24KB cuối là quá đủ
      res.full_output = rf;
      res.hint = 'full_output = TOÀN BỘ output đã gom trong phiên (kể cả phần cuộn khỏi màn hình). Đọc cái này cho output/log dài. visible_screen chỉ là phần đang thấy.';
    } else {
      res.hint = 'Chưa gom được scrollback (định dạng WS lạ hoặc chưa có dữ liệu) — chỉ có visible_screen. Nếu output dài bị cắt: nhờ anh tắt pager (Cisco: "terminal length 0"; Linux: thêm "| cat" thay vì để "less/more").';
    }
    var vscr = (vis.screen && vis.screen.trim()) ? redact(vis.screen.slice(-4000)) : '(màn hình trống)';
    anyRedacted = anyRedacted || _redacted;
    res.visible_screen = vscr;
    if (anyRedacted) res.note_baomat = 'Một số chuỗi nhạy cảm (mật khẩu/key/token) đã bị CHE [ĐÃ CHE] trước khi gửi cho bạn — đúng chính sách bảo mật. ĐỪNG yêu cầu user gõ lại các giá trị đó; nếu cần dùng, hướng dẫn user tự thao tác.';
    return res;
  }

  /* ── CHÈN lệnh lên dòng lệnh (KHÔNG kèm Enter) ── */
  function insertCommand(cmd) {
    if (typeof cmd !== 'string' || !cmd) return { ok: false, error: 'Thiếu command (chuỗi lệnh).' };
    cmd = cmd.replace(/\r?\n/g, ' ').trim();   // 1 dòng, tuyệt đối không tự xuống dòng/Enter
    if (typeof window.__termixInsert !== 'function')
      return { ok: false, error: 'Chưa nạp được cầu nối terminal (patcher). Anh thử tải lại trang Termix.' };
    var r = window.__termixInsert(cmd);
    if (!r || !r.ok)
      return { ok: false, error: 'Không chèn được vào terminal (' + ((r && r.reason) || '?') + '). Thường do chưa mở/kết nối phiên SSH tới host. Anh mở phiên SSH rồi thử lại — hoặc mình đọc rõ lệnh ra để anh tự gõ.', command_to_type: cmd };
    return { ok: true, inserted: cmd, note: 'Đã đặt lệnh lên dòng lệnh. Anh XEM lại rồi bấm Enter để chạy (mình không tự chạy). Chạy xong bảo mình để mình đọc kết quả.' };
  }

  var TOOLS = {
    read_terminal: function () { return Promise.resolve(readTerminal()); },
    insert_command: function (p) { return Promise.resolve(insertCommand(p && p.command)); },
  };

  var SYS = [
    'Bạn là trợ lý quản trị hệ thống (Linux/Unix/server) tích hợp thẳng trong Termix — một web SSH client. Anh Thoại đang SSH vào SERVER THẬT của mình qua terminal này.',
    'Trả lời tiếng Việt, ngắn gọn, chính xác kỹ thuật.',
    '',
    '⚠️ ĐÂY LÀ SERVER THẬT, KHÔNG PHẢI LAB. Một lệnh sai có thể gây hỏng thật/mất dữ liệu/mất kết nối. Vì vậy:',
    '- Bạn KHÔNG BAO GIỜ tự chạy lệnh. Bạn chỉ ĐẶT lệnh lên dòng lệnh (insert_command), rồi anh Thoại TỰ xem và bấm Enter. Luôn nói rõ điều này.',
    '- TUYỆT ĐỐI không đề xuất lệnh phá huỷ (rm -rf, mkfs, dd, > /dev/sdX, chmod -R trên /, thay đổi firewall/iptables/ssh có thể tự khoá mình ra, shutdown/reboot, killall tiến trình quan trọng…) trừ khi anh yêu cầu RÕ RÀNG — và khi đó phải CẢNH BÁO to, giải thích hậu quả, chờ anh xác nhận.',
    '- Ưu tiên lệnh CHỈ ĐỌC (chẩn đoán) trước: xem trạng thái, log, cấu hình. Chỉ đề xuất lệnh THAY ĐỔI khi đã hiểu rõ nguyên nhân.',
    '- Trước khi chèn 1 lệnh, giải thích NGẮN lệnh đó làm gì.',
    '',
    'CÔNG CỤ — để dùng, in ra MỘT khối mã đúng định dạng rồi DỪNG chờ kết quả:',
    '```ssh',
    '{"tool":"<tên>", ...tham số}',
    '```',
    '- read_terminal → đọc output terminal. Trả về: full_output = TOÀN BỘ dữ liệu đã gom trong phiên (kể cả phần đã cuộn khỏi màn hình → output/log DÀI vẫn đọc được hết, KHÔNG cần bảo anh bấm Space cuộn); visible_screen = phần đang thấy. KHÔNG tham số. DÙNG ĐẦU TIÊN. Khi output dài: đọc full_output, đừng bảo anh cuộn tay. Nếu full_output thiếu và đó là do pager (Cisco "--More--", Linux less/more): gợi ý anh tắt pager ("terminal length 0" trên Cisco, hoặc thêm "| cat") rồi chạy lại.',
    '- insert_command {"command":"..."} → ĐẶT 1 lệnh lên dòng lệnh của phiên SSH đang mở (không kèm Enter). Anh Thoại tự bấm Enter để chạy. Mỗi lần CHỈ 1 lệnh.',
    '',
    'CÁCH LÀM VIỆC (vì bạn không tự chạy được — phối hợp turn-by-turn với anh):',
    '1. read_terminal để xem màn hình hiện tại (lỗi gì, đang ở host/thư mục nào, shell gì).',
    '2. Phân tích, giải thích ngắn, rồi insert_command MỘT lệnh chẩn đoán.',
    '3. SAU KHI insert_command: DỪNG LẠI. Nhắc anh "bấm Enter chạy rồi bảo mình" — ĐỪNG gọi read_terminal ngay (chưa có output mới cho tới khi anh chạy).',
    '4. Khi anh báo đã chạy: read_terminal lại để đọc kết quả THẬT → phân tích tiếp → lệnh kế.',
    '',
    'NHẬN DIỆN MÔI TRƯỜNG trước khi ra lệnh (nhìn prompt/output từ read_terminal):',
    '- Hệ điều hành/họ distro: Debian/Ubuntu (apt, systemd) vs RHEL/CentOS/Rocky (yum/dnf, systemd) vs Alpine (apk, OpenRC — KHÔNG có systemd, dùng "rc-service"/"rc-status") vs BSD. Đừng mặc định systemd/apt cho mọi máy.',
    '- Có systemd không: nếu có → "systemctl status <svc>", "journalctl -u <svc> -e --no-pager"; nếu Alpine/OpenRC → "rc-service <svc> status", "cat /var/log/...".',
    '- Đang là root hay user thường (prompt # vs $): lệnh cần quyền thì nhắc "sudo" nếu không phải root.',
    '',
    'PHƯƠNG PHÁP CHẨN ĐOÁN (chẩn đoán như sysadmin thật, đi từ triệu chứng → bằng chứng → nguyên nhân, KHÔNG kết luận vội):',
    '- Dịch vụ chết/không chạy: kiểm tra trạng thái service → đọc log của chính service (journalctl -u … / file log) → kiểm cấu hình (thường có lệnh test cấu hình: "nginx -t", "sshd -t", "apachectl configtest", "named-checkconf") → cổng có lắng nghe không ("ss -tlnp" / "netstat -tlnp").',
    '- Hết dung lượng/đầy đĩa: "df -h" (phân vùng đầy), "du -sh /*" hoặc "du -xh --max-depth=1 / | sort -h" (thư mục ngốn), kiểm inode "df -i".',
    '- Tải cao/chậm: "uptime", "top -bn1 | head -20", "free -m" (RAM/swap), "iostat"/"vmstat" nếu có, "dmesg -T | tail" (lỗi kernel/OOM killer).',
    '- Mạng/không kết nối được: "ip a"/"ip r", "ping", "ss -tlnp" (đang nghe cổng nào), "curl -v <url>" hoặc "curl -I", phân giải DNS "dig"/"nslookup"/"getent hosts", firewall "iptables -L -n"/"nft list ruleset"/"ufw status" (chỉ ĐỌC).',
    '- Quyền/không truy cập được file: "ls -la <path>", "namei -l <path>", "id", kiểm SELinux "getenforce"/"ausearch" (RHEL) hoặc AppArmor "aa-status".',
    '- Cron/tác vụ không chạy: "crontab -l", "systemctl list-timers", log ("journalctl -u cron"/"/var/log/syslog").',
    '- LUÔN trích DẪN dòng output thật (từ read_terminal) khi kết luận — không nói chung chung "có vẻ ổn"/"chắc do X" mà không có bằng chứng.',
    '',
    'THIẾT BỊ KHÔNG PHẢI SHELL LINUX (vd anh mở Windows qua RDP/VNC trong Termix, hoặc một TUI):',
    '- Nếu read_terminal cho thấy đây KHÔNG phải shell CLI (màn hình đồ hoạ/khó đọc/không phải text lệnh): nói THẲNG "mình không điều khiển được màn hình đồ hoạ này". Đừng giả vờ gõ được.',
    '- Vẫn có thể giúp GIÁN TIẾP: chỉ ra chính xác lỗi anh đang thấy (nếu đọc được chữ trên màn hình), giải thích, và hướng dẫn anh tự thao tác. Nêu rõ "cái này anh tự làm giúp".',
    '',
    'QUY TẮC:',
    '- Mỗi lượt chỉ in 1 khối ```ssh```. Sau [KẾT QUẢ TOOL], phân tích rồi tiếp tục hoặc trả lời.',
    '- insert_command sẽ đặt lệnh cho anh xem — LUÔN nhắc anh tự bấm Enter, và mỗi lần chỉ 1 lệnh.',
  ].join('\n');

  /* ── UI ── */
  var css = document.createElement('style');
  css.textContent =
    '#tmxai-btn{position:fixed;bottom:20px;right:20px;height:50px;width:auto;padding:0 16px;display:inline-flex;align-items:center;gap:6px;' +
    'border:none;border-radius:25px;cursor:pointer;background:linear-gradient(135deg,#43e97b,#38f9d7);color:#06371f;font-size:15px;font-weight:700;' +
    'box-shadow:0 3px 14px rgba(0,0,0,.4);z-index:2147483000;transition:transform .12s}' +
    '#tmxai-btn:hover{transform:translateY(-1px)}' +
    '#tmxai-panel{position:fixed;bottom:84px;right:20px;width:390px;max-width:calc(100vw - 30px);height:560px;max-height:calc(100vh - 120px);' +
    'background:#0f1b17;border:1px solid rgba(255,255,255,.12);border-radius:14px;z-index:2147483000;display:none;flex-direction:column;overflow:hidden;' +
    'box-shadow:0 10px 44px rgba(0,0,0,.6);font-family:"Segoe UI",system-ui,sans-serif}' +
    '#tmxai-panel.open{display:flex}' +
    '#tmxai-hd{background:linear-gradient(135deg,#0b5137,#0a3d2c);padding:11px 14px;display:flex;justify-content:space-between;align-items:center;color:#fff;font-weight:700;font-size:14px}' +
    '#tmxai-hd .x{cursor:pointer;opacity:.7;font-size:16px}#tmxai-hd .x:hover{opacity:1}' +
    '#tmxai-msgs{flex:1;overflow-y:auto;padding:12px;display:flex;flex-direction:column;gap:9px}' +
    '.tmx-m{max-width:88%;padding:9px 12px;border-radius:13px;font-size:13px;line-height:1.55;white-space:pre-wrap;word-break:break-word}' +
    '.tmx-u{align-self:flex-end;background:linear-gradient(135deg,#0b5137,#0a3d2c);color:#eafff4;border-bottom-right-radius:4px}' +
    '.tmx-a{align-self:flex-start;background:rgba(255,255,255,.06);color:#e6fff2;border-bottom-left-radius:4px}' +
    '.tmx-t{align-self:flex-start;background:rgba(67,233,123,.1);border:1px solid rgba(67,233,123,.28);color:#7dffb8;font-size:11.5px;padding:6px 10px;border-radius:9px}' +
    '#tmxai-in{display:flex;gap:7px;padding:10px;border-top:1px solid rgba(255,255,255,.09)}' +
    '#tmxai-in textarea{flex:1;background:rgba(255,255,255,.05);border:1px solid rgba(255,255,255,.14);border-radius:9px;padding:8px 10px;color:#eafff4;font-size:13px;resize:none;outline:none;font-family:inherit;height:38px}' +
    '#tmxai-in button{background:linear-gradient(135deg,#43e97b,#38f9d7);border:none;border-radius:9px;width:42px;color:#06371f;font-size:16px;cursor:pointer}' +
    '#tmxai-in button:disabled{opacity:.5;cursor:default}' +
    '.tmx-wc{color:#8fc7ac;font-size:12.5px;text-align:center;padding:14px 8px;line-height:1.6}';
  document.head.appendChild(css);

  var btn = document.createElement('button');
  btn.id = 'tmxai-btn'; btn.title = 'Trợ lý SSH AI'; btn.type = 'button'; btn.innerHTML = '🤖 <span>AI</span>';
  document.body.appendChild(btn);

  var panel = document.createElement('div'); panel.id = 'tmxai-panel';
  panel.innerHTML =
    '<div id="tmxai-hd"><span>🤖 Trợ lý SSH</span><span class="x" title="Đóng">✕</span></div>' +
    '<div id="tmxai-msgs"><div class="tmx-wc">Chào anh! Mình đọc được màn hình terminal đang mở và gợi ý lệnh chẩn đoán/sửa.<br><br>Mình <b>không tự chạy</b> — chỉ đặt lệnh lên dòng lệnh, anh xem rồi bấm Enter.<br><br>Thử: <i>"đọc màn hình xem có lỗi gì"</i> · <i>"nginx không lên, check giúp"</i> · <i>"đĩa đầy chưa"</i>.</div></div>' +
    '<div id="tmxai-in"><textarea placeholder="Hỏi về server đang SSH…" rows="1"></textarea><button title="Gửi">▶</button></div>';
  document.body.appendChild(panel);

  var msgs = panel.querySelector('#tmxai-msgs');
  var ta = panel.querySelector('textarea');
  var send = panel.querySelector('#tmxai-in button');
  var history = [];
  var busy = false;

  btn.onclick = function () { panel.classList.toggle('open'); if (panel.classList.contains('open')) ta.focus(); };
  panel.querySelector('.x').onclick = function () { panel.classList.remove('open'); };
  ta.onkeydown = function (e) { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); doSend(); } };
  send.onclick = doSend;

  function addMsg(cls, text) { var d = document.createElement('div'); d.className = 'tmx-m ' + cls; d.textContent = text; msgs.appendChild(d); msgs.scrollTop = msgs.scrollHeight; return d; }
  function note(text) { addMsg('tmx-t', text); }

  function doSend() {
    var q = (ta.value || '').trim(); if (!q || busy) return;
    var wc = msgs.querySelector('.tmx-wc'); if (wc) wc.remove();
    ta.value = ''; addMsg('tmx-u', q); history.push({ role: 'user', content: q });
    runLoop();
  }

  /* Agentic loop: LLM → nếu có khối ```ssh``` thì thực thi → nạp kết quả → lặp */
  function runLoop() {
    busy = true; send.disabled = true;
    var loops = 0;
    var bubble = addMsg('tmx-a', '…');
    step();

    function step() {
      streamLLM(function onDelta(full) { bubble.textContent = full || '…'; msgs.scrollTop = msgs.scrollHeight; })
        .then(function (full) {
          var tool = parseTool(full);
          history.push({ role: 'assistant', content: full });
          if (!tool || loops >= MAX_TOOL_LOOPS) {
            if (tool && loops >= MAX_TOOL_LOOPS) note('⚠️ Đã đạt giới hạn số bước tool.');
            finish(); return;
          }
          bubble.textContent = full.replace(/```ssh[\s\S]*?```/g, '').trim() || '⚙️ đang xử lý…';
          loops++;
          execTool(tool).then(function (res) {
            note((res.__denied ? '⛔ ' : '⚙️ ') + tool.tool + (res.__denied ? ' (bỏ qua)' : ' ✓'));
            history.push({ role: 'user', content: '[KẾT QUẢ TOOL ' + tool.tool + ']\n' + JSON.stringify(res) });
            bubble = addMsg('tmx-a', '…');
            step();
          });
        })
        .catch(function (e) { bubble.textContent = '⚠️ Lỗi: ' + (e && e.message || e); finish(); });
    }
    function finish() { busy = false; send.disabled = false; ta.focus(); }
  }

  function parseTool(text) {
    var m = text.match(/```ssh\s*([\s\S]*?)```/);
    if (!m) return null;
    try { var o = JSON.parse(m[1].trim()); return (o && o.tool && TOOLS[o.tool]) ? o : null; } catch (e) { return null; }
  }

  function execTool(tool) {
    // insert_command: hiện NGUYÊN VĂN lệnh cho anh xem trước khi đặt vào terminal.
    if (tool.tool === 'insert_command') {
      var cmd = (typeof tool.command === 'string') ? tool.command : '';
      var ok = window.confirm('AI muốn ĐẶT lệnh này lên dòng lệnh terminal (anh vẫn phải tự bấm Enter để chạy):\n\n  ' + cmd + '\n\nĐồng ý đặt vào?');
      if (!ok) return Promise.resolve({ __denied: true, message: 'Người dùng từ chối chèn lệnh này.' });
    }
    try { return Promise.resolve(TOOLS[tool.tool](tool)).catch(function (e) { return { ok: false, error: String(e && e.message || e) }; }); }
    catch (e) { return Promise.resolve({ ok: false, error: String(e && e.message || e) }); }
  }

  /* Gọi proxy 9Router, đọc SSE, trả full text; onDelta(full) mỗi lần có thêm chữ */
  function streamLLM(onDelta) {
    var body = { model: MODEL, messages: [{ role: 'system', content: SYS }].concat(history), stream: true };
    return fetch(LLM_URL, { method: 'POST', credentials: 'include', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) })
      .then(function (r) {
        if (!r.ok) return r.text().then(function (t) { var e; try { e = JSON.parse(t).error; } catch (_) {} throw new Error(e || ('HTTP ' + r.status)); });
        var reader = r.body.getReader(), dec = new TextDecoder(), buf = '', full = '';
        return (function pump() {
          return reader.read().then(function (res) {
            if (res.done) return full;
            buf += dec.decode(res.value, { stream: true });
            var lines = buf.split('\n'); buf = lines.pop();
            for (var i = 0; i < lines.length; i++) {
              var ln = lines[i].trim(); if (ln.indexOf('data:') !== 0) continue;
              var payload = ln.slice(5).trim(); if (payload === '[DONE]') continue;
              try {
                var jj = JSON.parse(payload);
                var delta = jj.choices && jj.choices[0] && jj.choices[0].delta;
                if (delta && delta.content) { full += delta.content; onDelta(full); }
              } catch (e) { /* chunk lẻ */ }
            }
            return pump();
          });
        })();
      });
  }
})();
