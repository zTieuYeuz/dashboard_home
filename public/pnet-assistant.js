/* ═══════════════════════════════════════════════════════════════════
   pnet-assistant.js — Nút 🤖 AI nổi NHÚNG TRONG PNETLab
   -------------------------------------------------------------------
   Nạp bằng 1 dòng trong main.blade.php của PNETLab:
     <script src="https://dashboard.home-server.id.vn/pnet-assistant.js" defer></script>
   Toàn bộ code nằm trong repo dashboard (version-control) → update PNETLab
   chỉ mất 1 dòng loader, ráp lại tức thì.

   Kiến trúc:
   - Chạy trong ORIGIN của PNETLab → TOOLS gọi /api/labs/session/* same-origin
     bằng CHÍNH phiên user đang đăng nhập, thao tác trên LAB user đang mở.
   - LLM: gọi proxy /api/pnet-llm trên dashboard (Worker gắn secret 9Router key,
     stream SSE). Key KHÔNG lộ trong browser.
   - Giao thức tool: model in khối ```pnet {json}``` → JS thực thi → nạp kết quả
     lại → lặp (giống dash-action của dashboard, model-agnostic, không cần
     function-calling passthrough của 9Router).
   ═══════════════════════════════════════════════════════════════════ */
(function () {
  'use strict';
  if (window.__PNET_AI__) return; window.__PNET_AI__ = 1;
  // Không hiện ở trang đăng nhập (chưa có phiên → tool vô dụng)
  if (/\/auth\/login/i.test(location.pathname)) return;

  var MODEL = 'pnetlab';          // alias 9Router của anh (đổi ở đây nếu muốn model khác)
  var MAX_TOOL_LOOPS = 16;        // chẩn đoán mạng thật cần nhiều bước (check nhiều switch, nhiều lớp OSI) — 6 quá ít, hay bị cắt ngang

  /* Proxy base = origin của chính file script này (tự đúng cho staging & prod) */
  function proxyBase() {
    try { var s = document.querySelector('script[src*="pnet-assistant.js"]'); if (s) return new URL(s.src).origin; } catch (e) {}
    return 'https://dashboard.home-server.id.vn';
  }
  var LLM_URL = proxyBase() + '/api/pnet-llm';
  var CONSOLE_URL = proxyBase() + '/api/pnet-console';

  /* ── Helpers gọi PNETLab same-origin ── */
  function xsrf() { try { var m = document.cookie.match(/XSRF-TOKEN=([^;]+)/); return m ? decodeURIComponent(m[1]) : ''; } catch (e) { return ''; } }
  function pnetGet(path) {
    return fetch(path, { credentials: 'include', headers: { 'X-Requested-With': 'XMLHttpRequest', 'X-XSRF-TOKEN': xsrf() } }).then(function (r) { return r.json().catch(function () { return {}; }); });
  }
  function pnetForm(path, obj) {
    return fetch(path, {
      method: 'POST', credentials: 'include',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'X-Requested-With': 'XMLHttpRequest', 'X-XSRF-TOKEN': xsrf() },
      body: new URLSearchParams(obj || {}).toString(),
    }).then(function (r) { return r.json().catch(function () { return {}; }); });
  }
  function nodeStatus(s) { return ({ 0: 'stopped', 1: 'building', 2: 'running', 3: 'running' })[s] || String(s); }

  /* ── Tools (thao tác trên LAB user đang mở — session hiện tại) ── */
  var MUTATING = { start_node: 1, stop_node: 1, export_config: 1, run_console: 1 };
  var TOOLS = {
    // /topology trả nodes+networks+lines cho lab ĐANG MỞ, KHÔNG cần factory/create
    // (đúng endpoint functions.js dùng để vẽ; /nodes cần bind nên rỗng trên trang legacy).
    get_topology: function () {
      // /topology = cấu trúc + status ĐỊNH NGHĨA (luôn 0). Trạng thái CHẠY THẬT (running/stopped)
      // phải lấy từ /nodestatus (POST) — chính endpoint functions.js poll để tô xanh/đỏ node.
      // Nối dây vật lý: KHÔNG có field "links" phẳng — phải suy từ node.ethernets[].network_id:
      // 2 interface (của 2 node khác nhau, hoặc cùng node) trỏ CÙNG network_id != 0 → nối nhau qua bridge đó.
      return Promise.all([
        pnetGet('/api/labs/session/topology'),
        pnetForm('/api/labs/session/nodestatus', {})
      ]).then(function (a) {
        var d = (a[0] && a[0].data) || {};
        var live = (a[1] && a[1].data) || {};   // { "<id>": statusNum }  (0=stopped, 2=running)
        var toArr = function (x) { return Array.isArray(x) ? x : Object.keys(x || {}).map(function (k) { var o = (x[k] || {}); o.id = o.id || k; return o; }); };
        var rawNodes = toArr(d.nodes);
        var nodes = rawNodes.map(function (n) {
          var st = (live[n.id] !== undefined) ? live[n.id] : n.status;   // ưu tiên trạng thái LIVE
          var tpl = n.template || n.type || '';
          // Gợi ý loại console theo template — CHỈ để AI cân nhắc trước, KHÔNG chặn cứng:
          // nhiều image qemu (FortiGate-VM, vMX, CHR MikroTik...) vẫn dùng serial console
          // qua telnet y hệt IOL — chỉ hệ điều hành có GUI thật (Windows) mới chắc chắn là VNC.
          var hint = (tpl === 'iol' || tpl === 'dynamips' || tpl === 'vpcs') ? 'text' :
                     (tpl === 'qemu') ? 'text_or_vnc — thử run_console trước, nếu output toàn ký tự lạ thì đây là VNC' :
                     (tpl === 'docker') ? 'unknown' : 'unknown';
          return { id: n.id, name: n.name, template: tpl, status: nodeStatus(st), console_port: n.port ? parseInt(n.port, 10) : null, console_hint: hint };
        });
        var running = nodes.filter(function (x) { return x.status === 'running'; }).length;

        // Suy port-nối-port: gom mọi (node, interface) theo network_id, ghép cặp trong cùng nhóm.
        var byNet = {};   // network_id -> [{node, iface}]
        rawNodes.forEach(function (n) {
          var eth = n.ethernets || {};
          Object.keys(eth).forEach(function (k) {
            var e = eth[k]; var nid = e.network_id;
            if (!nid) return;   // 0 = chưa cắm dây
            (byNet[nid] = byNet[nid] || []).push({ node: n.name, iface: e.name });
          });
        });
        var links = [];
        Object.keys(byNet).forEach(function (nid) {
          var ends = byNet[nid];
          for (var i = 0; i < ends.length; i++) for (var j = i + 1; j < ends.length; j++) {
            links.push(ends[i].node + ':' + ends[i].iface + ' — ' + ends[j].node + ':' + ends[j].iface);
          }
        });

        return { node_count: nodes.length, running_count: running, nodes: nodes, links: links };
      });
    },
    get_config: function (p) {
      return pnetGet('/api/labs/session/configs/' + parseInt(p.node_id, 10)).then(function (r) {
        var d = r && r.data; var cfg = (d && typeof d === 'object') ? (d.data || '') : (d || '');
        return { node_id: p.node_id, config: cfg || '(trống — node chưa có startup config hoặc chưa bật)' };
      });
    },
    start_node: function (p) { return withId(p, function (id) { return pnetForm('/api/labs/session/nodes/start', { id: id }).then(fmtOk); }); },
    stop_node: function (p) { return withId(p, function (id) { return pnetForm('/api/labs/session/nodes/stop', { id: id }).then(fmtOk); }); },
    export_config: function (p) {
      var b = {};
      if (p.node_id != null && p.node_id !== '') { var id = parseInt(p.node_id, 10); if (!Number.isInteger(id)) return Promise.resolve(badId(p.node_id)); b.id = id; }
      return pnetForm('/api/labs/session/nodes/export', b).then(fmtOk);
    },
    // ĐÃ THỬ NGHIỆM KỸ (2026-07-24) và XÁC NHẬN: API /api/labs/session/configs/edit trả "success"
    // nhưng KHÔNG hề ghi vào lab thật (kiểm chứng bằng cách đọc thẳng file .unl trên server sau khi
    // gọi — config_data vẫn rỗng/không đổi, thử cả plain text lẫn base64, node chạy lẫn dừng).
    // → Không có cách nào qua API để AI tự ghi startup-config. Cách DUY NHẤT đáng tin (đúng cách
    // PNETLab thiết kế, xem doc export-and-import-startup-configuration): gõ lệnh trực tiếp vào
    // console thiết bị rồi "write memory", sau đó gọi export_config để lưu vào lab. AI hiện CHƯA
    // có quyền gõ console (cần cầu nối riêng, Phase 3 — chưa xây). Nên KHÔNG cung cấp push_config;
    // trả lỗi rõ ràng nếu model cũ vẫn cố gọi, để nó không báo "đã ghi" sai sự thật với user.
    push_config: function () {
      return Promise.resolve({ ok: false, error: 'Chưa hỗ trợ ghi config qua AI (API PNETLab không lưu được kiểu này). Hãy tự cấu hình qua console thiết bị rồi gõ "write memory", sau đó nhờ mình export_config để lưu vào lab.' });
    },
    // Gõ lệnh THẬT vào console node (Phase 3) — telnet thẳng qua console-bridge trên VM PNETLab,
    // né hẳn Guacamole/WebSocket (đã lỗi qua tunnel cả ngày). Cần console_port từ get_topology
    // (chỉ có khi node đang running). Đây là cách DUY NHẤT đáng tin để thật sự cấu hình thiết bị.
    run_console: function (p) {
      var port = parseInt(p.console_port, 10);
      var cmds = Array.isArray(p.commands) ? p.commands.filter(function (c) { return typeof c === 'string'; }) : [];
      if (!Number.isInteger(port)) return Promise.resolve({ ok: false, error: 'Thiếu console_port (lấy từ get_topology.nodes[].console_port — node phải đang RUNNING).' });
      if (!cmds.length) return Promise.resolve({ ok: false, error: 'Thiếu commands (mảng chuỗi lệnh CLI).' });
      return fetch(CONSOLE_URL, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ port: port, commands: cmds }) })
        .then(function (r) { return r.json().catch(function () { return { ok: false, error: 'HTTP ' + r.status }; }); })
        .then(function (res) {
          // Phát hiện console KHÔNG PHẢI dạng text (vd VNC/RDP như Windows): output toàn ký tự
          // không đọc được thay vì text CLI bình thường. Báo rõ thay vì trả rác cho model đoán mò.
          if (res && res.ok && Array.isArray(res.results)) {
            var allOut = res.results.map(function (r2) { return r2.output || ''; }).join('');
            var printable = allOut.replace(/[\x20-\x7E\r\n\tÀ-ỹ]/g, '').length;
            if (allOut.length > 20 && printable / allOut.length > 0.35) {
              res.warning = 'Output chứa nhiều ký tự không phải text CLI thường — console này CÓ THỂ là dạng đồ hoạ (VNC/RDP, ví dụ Windows), KHÔNG gõ lệnh CLI được qua đây. Nếu đúng, hãy chẩn đoán GIÁN TIẾP qua switch/router node này đang cắm vào (xem PHƯƠNG PHÁP CHẨN ĐOÁN cho thiết bị không gõ được console).';
            }
          }
          return res;
        })
        .catch(function (e) { return { ok: false, error: 'Không gọi được console-bridge: ' + (e && e.message || e) }; });
    },
  };
  // node_id AI gửi phải là SỐ nguyên (id thật của node, lấy từ get_topology) — không phải tên "SW1".
  // Gửi sai kiểu → parseInt ra NaN → server 400 khó hiểu. Chặn sớm, báo AI rõ để nó tự sửa & thử lại.
  function badId(v) { return { ok: false, error: 'node_id phải là SỐ nguyên (vd 1, 2, 3) lấy từ get_topology.nodes[].id — nhận được: ' + JSON.stringify(v) + '. Hãy get_topology lại để lấy đúng id.' }; }
  function withId(p, fn) { var id = parseInt(p.node_id, 10); if (!Number.isInteger(id)) return Promise.resolve(badId(p.node_id)); return fn(id); }
  function fmtOk(r) { return { ok: r && r.status === 'success', message: (r && r.message) || ('code ' + (r && r.code)) }; }

  var SYS = [
    'Bạn là trợ lý mạng tích hợp thẳng trong PNETLab, giúp anh Thoại vận hành lab (router/switch/PC ảo).',
    'QUAN TRỌNG: Bạn CHÍNH LÀ user — mọi tool chạy trong phiên của user và tác động lên ĐÚNG lab user đang mở sẵn.',
    'TUYỆT ĐỐI KHÔNG tự mở/tạo/chuyển lab. get_topology luôn đọc lab user đang mở hiện tại. Nếu get_topology trả rỗng thì báo user "chưa mở lab nào", ĐỪNG tự mở.',
    'Trả lời tiếng Việt, ngắn gọn, kỹ thuật.',
    '',
    'CÔNG CỤ: để dùng, in ra MỘT khối mã đúng định dạng (rồi DỪNG, chờ kết quả):',
    '```pnet',
    '{"tool":"<tên>", ...tham số}',
    '```',
    'Danh sách tool:',
    '- get_topology → nodes (id, tên, template, trạng thái running/stopped, console_port, console_hint) + links (dây nối vật lý dạng "SW1:e0/0 — SW2:e0/1"). KHÔNG tham số. console_hint="text" = chắc gõ lệnh được; "text_or_vnc" = chưa chắc, thử run_console rồi xem warning; khác = không rõ, cứ thử.',
    '- get_config {"node_id":N} → xem startup config 1 node.',
    '- start_node {"node_id":N} → bật node.',
    '- stop_node {"node_id":N} → tắt node.',
    '- export_config {"node_id":N} → lưu config từ node ĐANG CHẠY vào lab (bỏ node_id = lưu tất cả). Gọi sau khi đã gõ "write memory" trong console (qua run_console) để chốt lại vĩnh viễn.',
    '- run_console {"console_port":P,"commands":["cmd1","cmd2",...]} → GÕ LỆNH CLI THẬT vào console node đang chạy (P lấy từ get_topology.nodes[].console_port), TRẢ VỀ output thật của từng lệnh. Đây là cách DUY NHẤT để cấu hình node CÓ console dạng TEXT (xem console_hint của node).',
    '',
    'ĐA HÃNG THIẾT BỊ — lab KHÔNG chỉ có Cisco IOS. Anh Thoại sẽ thêm nhiều loại: router/switch nhiều hãng (Cisco IOS/NX-OS, Juniper JunOS, MikroTik RouterOS, Fortinet FortiGate…), và cả server Windows/Linux (console dạng ĐỒ HOẠ, xem mục riêng bên dưới).',
    '- TRƯỚC KHI gõ lệnh cấu hình: xác định đang nói chuyện với hệ điều hành nào — nhìn banner/prompt trả về từ run_console đầu tiên (vd Enter suông): Cisco IOS prompt "Router>"/"Switch#"; JunOS có chữ "JUNOS" và prompt "user@host>"; MikroTik có prompt "[admin@MikroTik] >"; FortiGate prompt "hostname #" và lệnh kiểu "config system interface". ĐỪNG mặc định là Cisco IOS nếu banner không khớp.',
    '- Bảng lệnh tương đương (tự suy ra lệnh đúng theo hệ điều hành đã nhận diện, đây chỉ là gợi ý phổ biến, không phải danh sách đủ):',
    '  · Xem interface: IOS "show ip interface brief" | JunOS "show interfaces terse" | MikroTik "/interface print" | FortiGate "get system interface".',
    '  · Xem routing: IOS "show ip route" | JunOS "show route" | MikroTik "/ip route print" | FortiGate "get router info routing-table all".',
    '  · Vào chế độ cấu hình: IOS "enable" rồi "configure terminal", "end" khi xong | JunOS "configure", "commit" rồi "exit" | MikroTik gõ lệnh trực tiếp không cần enable | FortiGate "config <mục>" rồi "end".',
    '  · Lưu vĩnh viễn: IOS "write memory" | JunOS "commit" (đã lưu ngay) | MikroTik tự lưu ngay | FortiGate tự lưu ngay khi "end". CHỈ IOS/IOL cần bước "write memory" + export_config riêng như mô tả dưới — các hệ khác có thể tự lưu, hỏi lại bằng get_config sau khi export_config để xác nhận.',
    '',
    'CÁCH CẤU HÌNH THIẾT BỊ CÓ CONSOLE TEXT (dùng run_console — bạn TỰ LÀM được, không cần user gõ tay):',
    '- KHÔNG có API ghi trực tiếp startup-config (đã thử nghiệm, PNETLab không hỗ trợ) — mọi thay đổi PHẢI qua console.',
    '- Node phải đang RUNNING (start_node nếu chưa) mới có console_port hợp lệ.',
    '- Với Cisco IOS: gõ xong lệnh cấu hình, gõ THÊM "write memory" trong CÙNG lần gọi run_console hoặc lần sau — bước GHI VÀO NVRAM THẬT, bắt buộc để export_config lấy được. Hệ khác xem bảng tương đương ở trên.',
    '- Rồi gọi export_config để chốt config vào lab (để còn nguyên sau khi đóng/mở lại lab).',
    '- Luôn ĐỌC output của run_console để biết lệnh có chạy đúng không (lỗi cú pháp tuỳ hệ điều hành, vd IOS "% Invalid input") — nếu lỗi, TỰ SỬA và gõ lại, đừng báo user "đã xong" khi output cho thấy lỗi.',
    '',
    'THIẾT BỊ KHÔNG GÕ ĐƯỢC CONSOLE (VNC/RDP — vd server Windows, hoặc bất kỳ node nào run_console báo "warning" là output không phải text):',
    '- ĐÂY LÀ GIỚI HẠN THẬT, đừng giả vờ gõ được. Nói thẳng với user: "mình chưa điều khiển được console đồ hoạ (VNC/RDP) của node này".',
    '- NHƯNG vẫn CHẨN ĐOÁN GIÁN TIẾP được: dùng get_topology.links tìm switch/router đang nối trực tiếp với node đó → run_console vào THIẾT BỊ MẠNG đó (không phải vào node VNC) để kiểm tra: port nối tới node này có up không, đã học được MAC chưa (vd IOS "show mac address-table"), có ARP entry chưa (vd IOS "show ip arp"), thử ping từ switch/router tới IP của node đó nếu biết IP. Việc này cho biết node có kết nối mạng bình thường không dù không sửa được cấu hình bên trong nó.',
    '- Nếu qua kiểm tra gián tiếp thấy vấn đề nằm ở CẤU HÌNH BÊN TRONG node VNC (vd IP sai, service tắt) mà không phải ở phía mạng: báo rõ cho user để họ tự vào console đồ hoạ (qua PNETLab UI) kiểm tra tiếp — đừng đoán mò nội dung bên trong khi không thấy được.',
    '',
    'PHƯƠNG PHÁP CHẨN ĐOÁN MẠNG (bắt buộc theo — chẩn đoán như kỹ sư mạng thật, ĐỪNG đoán mò hay kết luận vội):',
    'Đi từ lớp thấp lên cao (bottom-up OSI), đừng bỏ qua bước nào. Mỗi lớp phải CHẠY LỆNH THẬT (run_console, đúng cú pháp theo hệ điều hành đã nhận diện) để xác minh, không suy đoán từ config tĩnh:',
    '1. TẦNG VẬT LÝ/LIÊN KẾT: get_topology xem node nào running/stopped + link nối port nào — port chưa nối hoặc node stopped là nguyên nhân phổ biến nhất, loại trừ TRƯỚC. Rồi run_console lệnh "xem interface" (xem bảng tương đương) để thấy port up/down THẬT — trạng thái topology tĩnh có thể khác trạng thái interface thật (shutdown, err-disabled).',
    '2. TẦNG 2 (switch): "show vlan brief" (VLAN tồn tại + port nào thuộc VLAN nào), "show interfaces trunk" (trunk có lên không, allowed vlan, native vlan có khớp 2 đầu không — sai native VLAN là lỗi rất hay gặp), "show spanning-tree" (port có bị blocking không), "show etherchannel summary" nếu có port-channel (bundle có đủ port, có "SU"/"P" không hay bị "I" độc lập — sai giao thức LACP/PAgP hoặc mode 2 đầu không khớp là lỗi hay gặp nhất).',
    '3. TẦNG 3 (routing, nếu có router/L3 switch): "show ip route", "show ip interface brief" (IP + trạng thái), "show ip protocols" nếu dùng định tuyến động. Kiểm tra IP/subnet mask khớp giữa 2 đầu 1 link.',
    '4. SO SÁNH HAI ĐẦU: lỗi mạng thường do 2 THIẾT BỊ KHÔNG KHỚP NHAU (vd trunk mode 1 bên "trunk" 1 bên "auto", VLAN allowed khác nhau, port-channel mode LACP active/passive không khớp, MTU/speed/duplex lệch). Đừng chỉ xem 1 switch rồi kết luận — luôn kiểm tra CẢ HAI phía của 1 kết nối trước khi báo "OK" hoặc "lỗi".',
    '5. SAU KHI SỬA: chạy lại đúng lệnh show đã dùng để phát hiện lỗi, XÁC NHẬN đã hết lỗi thật (đừng chỉ tin "write memory" thành công là xong) — rồi mới báo user.',
    '- Khi user nói mơ hồ ("mạng chậm", "không ping được", "cấu hình port-channel"): tự đặt giả thuyết theo thứ tự trên, kiểm tra từng cái bằng lệnh show thật, đừng hỏi lại user quá nhiều nếu tự kiểm tra được.',
    '- Luôn nêu RÕ bằng chứng (trích dẫn dòng output thật) khi kết luận, không nói chung chung "có vẻ ổn" hay "chắc là do X" mà không dẫn ra output cụ thể.',
    '',
    'QUY TẮC:',
    '- Mỗi lượt chỉ in 1 khối ```pnet```. Sau khi nhận [KẾT QUẢ TOOL], phân tích rồi tiếp tục hoặc trả lời.',
    '- Khi chẩn đoán lỗi hoặc cấu hình: get_topology TRƯỚC (hiểu tổng thể + lấy console_port) → get_config (config đã lưu) → run_console để thực hiện thật.',
    '- Các tool thay đổi (start/stop/export/run_console) sẽ được HỎI XÁC NHẬN với anh trước khi chạy — cứ đề xuất, hệ thống tự hỏi. run_console sẽ hiện NGUYÊN VĂN các lệnh cho user xem trước khi đồng ý.',
  ].join('\n');

  /* ── UI ── */
  var css = document.createElement('style');
  css.textContent =
    // Nút gắn trong toolbar topology (cạnh Physical)
    '#pnetai-btn{display:inline-flex;align-items:center;gap:5px;height:30px;padding:0 11px;margin-right:7px;border:none;border-radius:7px;cursor:pointer;' +
    'vertical-align:middle;background:linear-gradient(135deg,#4facfe,#00f2fe);color:#fff;font-size:13px;font-weight:600;box-shadow:0 1px 5px rgba(0,0,0,.25);transition:transform .12s}' +
    '#pnetai-btn:hover{transform:translateY(-1px)}' +
    // Biến thể nổi (fallback khi không có toolbar) — góc TRÁI để không đụng bubble dashboard
    '#pnetai-btn.pai-float{position:fixed;bottom:20px;left:20px;right:auto;height:50px;width:auto;padding:0 16px;border-radius:25px;font-size:15px;z-index:2147483000;margin:0}' +
    '#pnetai-panel{position:fixed;bottom:20px;right:20px;width:390px;max-width:calc(100vw - 30px);height:560px;max-height:calc(100vh - 120px);' +
    'background:#12172a;border:1px solid rgba(255,255,255,.1);border-radius:14px;z-index:2147483000;display:none;flex-direction:column;overflow:hidden;' +
    'box-shadow:0 10px 44px rgba(0,0,0,.55);font-family:"Segoe UI",system-ui,sans-serif}' +
    '#pnetai-panel.open{display:flex}' +
    '#pnetai-hd{background:linear-gradient(135deg,#0f3460,#16213e);padding:11px 14px;display:flex;justify-content:space-between;align-items:center;color:#fff;font-weight:700;font-size:14px}' +
    '#pnetai-hd .x{cursor:pointer;opacity:.7;font-size:16px}#pnetai-hd .x:hover{opacity:1}' +
    '#pnetai-msgs{flex:1;overflow-y:auto;padding:12px;display:flex;flex-direction:column;gap:9px}' +
    '.pai-m{max-width:88%;padding:9px 12px;border-radius:13px;font-size:13px;line-height:1.55;white-space:pre-wrap;word-break:break-word}' +
    '.pai-u{align-self:flex-end;background:linear-gradient(135deg,#0f3460,#16213e);color:#eaf2ff;border-bottom-right-radius:4px}' +
    '.pai-a{align-self:flex-start;background:rgba(255,255,255,.06);color:#e6f1ff;border-bottom-left-radius:4px}' +
    '.pai-t{align-self:flex-start;background:rgba(79,172,254,.1);border:1px solid rgba(79,172,254,.28);color:#7fd4ff;font-size:11.5px;padding:6px 10px;border-radius:9px}' +
    '#pnetai-in{display:flex;gap:7px;padding:10px;border-top:1px solid rgba(255,255,255,.09)}' +
    '#pnetai-in textarea{flex:1;background:rgba(255,255,255,.05);border:1px solid rgba(255,255,255,.14);border-radius:9px;padding:8px 10px;color:#eaf2ff;font-size:13px;resize:none;outline:none;font-family:inherit;height:38px}' +
    '#pnetai-in button{background:linear-gradient(135deg,#4facfe,#00f2fe);border:none;border-radius:9px;width:42px;color:#fff;font-size:16px;cursor:pointer}' +
    '#pnetai-in button:disabled{opacity:.5;cursor:default}' +
    '.pai-wc{color:#8aa0c6;font-size:12.5px;text-align:center;padding:14px 8px;line-height:1.6}';
  document.head.appendChild(css);

  var btn = document.createElement('button');
  btn.id = 'pnetai-btn'; btn.title = 'Trợ lý mạng AI'; btn.type = 'button'; btn.innerHTML = '🤖 <span>AI</span>';
  var panel = document.createElement('div'); panel.id = 'pnetai-panel';
  panel.innerHTML =
    '<div id="pnetai-hd"><span>🤖 Trợ lý mạng PNETLab</span><span class="x" title="Đóng">✕</span></div>' +
    '<div id="pnetai-msgs"><div class="pai-wc">Xin chào! Mình xem được topology, config, và bật/tắt/sửa node trong lab anh đang mở.<br><br>Thử: <i>"lab đang có gì?"</i> hoặc <i>"kiểm tra lỗi giúp mình"</i>.</div></div>' +
    '<div id="pnetai-in"><textarea placeholder="Hỏi về lab đang mở…" rows="1"></textarea><button title="Gửi">▶</button></div>';
  document.body.appendChild(panel);

  /* ── Gắn nút: ưu tiên vào toolbar cạnh "Physical"; không có thì nổi góc trái ── */
  function findPhysical() {
    var els = document.querySelectorAll('button,a,span,div,label,li');
    for (var i = 0; i < els.length; i++) {
      var el = els[i];
      if (el.children.length === 0 && (el.textContent || '').trim() === 'Physical') return el;
    }
    return null;
  }
  var _mo = null, _inToolbar = false;
  function mountBtn() {
    if (_inToolbar && btn.parentNode) return;   // đã gắn cạnh Physical → thôi quét
    var phys = findPhysical();
    if (phys) {
      var anchor = phys.closest ? (phys.closest('button,a,li,div') || phys) : phys;
      btn.classList.remove('pai-float');
      anchor.parentNode.insertBefore(btn, anchor);  // chèn TRƯỚC "Physical" (bên trái)
      _inToolbar = true;
      if (_mo) { _mo.disconnect(); _mo = null; }   // xong việc, ngừng theo dõi
    } else if (!btn.parentNode) {
      btn.classList.add('pai-float');
      document.body.appendChild(btn);
    }
  }
  mountBtn();
  // Topology nạp động (/legacy/topology) → theo dõi DOM tới khi toolbar "Physical" xuất hiện
  if (!_inToolbar) {
    try { _mo = new MutationObserver(function () { mountBtn(); }); _mo.observe(document.body, { childList: true, subtree: true }); } catch (e) {}
  }

  var msgs = panel.querySelector('#pnetai-msgs');
  var ta = panel.querySelector('textarea');
  var send = panel.querySelector('#pnetai-in button');
  var history = [];   // {role, content} gửi cho LLM (không gồm system)
  var busy = false;

  btn.onclick = function () { panel.classList.toggle('open'); if (panel.classList.contains('open')) ta.focus(); };
  panel.querySelector('.x').onclick = function () { panel.classList.remove('open'); };
  ta.onkeydown = function (e) { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); doSend(); } };
  send.onclick = doSend;

  function addMsg(cls, text) { var d = document.createElement('div'); d.className = 'pai-m ' + cls; d.textContent = text; msgs.appendChild(d); msgs.scrollTop = msgs.scrollHeight; return d; }
  function note(text) { addMsg('pai-t', text); }

  function doSend() {
    var q = (ta.value || '').trim(); if (!q || busy) return;
    var wc = msgs.querySelector('.pai-wc'); if (wc) wc.remove();
    ta.value = ''; addMsg('pai-u', q); history.push({ role: 'user', content: q });
    runLoop();
  }

  /* Agentic loop: gọi LLM → nếu có khối ```pnet``` thì thực thi → nạp kết quả → lặp */
  function runLoop() {
    busy = true; send.disabled = true;
    var loops = 0;
    var bubble = addMsg('pai-a', '…');
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
          // bỏ khối pnet khỏi bong bóng hiển thị (chỉ giữ phần chữ)
          bubble.textContent = full.replace(/```pnet[\s\S]*?```/g, '').trim() || '⚙️ đang thao tác…';
          loops++;
          execTool(tool).then(function (res) {
            note((res.__denied ? '⛔ ' : '⚙️ ') + tool.tool + (res.__denied ? ' (bỏ qua)' : ' ✓'));
            history.push({ role: 'user', content: '[KẾT QUẢ TOOL ' + tool.tool + ']\n' + JSON.stringify(res) });
            bubble = addMsg('pai-a', '…');
            step();
          });
        })
        .catch(function (e) { bubble.textContent = '⚠️ Lỗi: ' + (e && e.message || e); finish(); });
    }
    function finish() { busy = false; send.disabled = false; ta.focus(); }
  }

  function parseTool(text) {
    var m = text.match(/```pnet\s*([\s\S]*?)```/);
    if (!m) return null;
    try { var o = JSON.parse(m[1].trim()); return (o && o.tool && TOOLS[o.tool]) ? o : null; } catch (e) { return null; }
  }

  function execTool(tool) {
    // Tool thay đổi trạng thái → hỏi xác nhận
    if (tool.tool === 'run_console') {
      var cmdList = (Array.isArray(tool.commands) ? tool.commands : []).join('\n  ');
      var okC = window.confirm('AI muốn GÕ LỆNH vào console node ' + (tool.console_port || '?') + ':\n\n  ' + cmdList + '\n\nĐồng ý?');
      if (!okC) return Promise.resolve({ __denied: true, message: 'Người dùng từ chối gõ lệnh này.' });
    } else if (MUTATING[tool.tool]) {
      var label = { start_node: 'BẬT', stop_node: 'TẮT', export_config: 'LƯU config' }[tool.tool];
      var ok = window.confirm('AI muốn ' + label + ' node ' + (tool.node_id != null ? tool.node_id : '(tất cả)') + '.\nĐồng ý?');
      if (!ok) return Promise.resolve({ __denied: true, message: 'Người dùng từ chối thao tác này.' });
    }
    try { return Promise.resolve(TOOLS[tool.tool](tool)).catch(function (e) { return { ok: false, error: String(e && e.message || e) }; }); }
    catch (e) { return Promise.resolve({ ok: false, error: String(e && e.message || e) }); }
  }

  /* Gọi proxy 9Router, đọc SSE, trả về full text; onDelta(full) mỗi lần có thêm chữ */
  function streamLLM(onDelta) {
    var body = { model: MODEL, messages: [{ role: 'system', content: SYS }].concat(history), stream: true };
    return fetch(LLM_URL, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) })
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
                var j = JSON.parse(payload);
                var delta = j.choices && j.choices[0] && j.choices[0].delta;
                if (delta && delta.content) { full += delta.content; onDelta(full); }
              } catch (e) { /* chunk lẻ, bỏ qua */ }
            }
            return pump();
          });
        })();
      });
  }
})();
