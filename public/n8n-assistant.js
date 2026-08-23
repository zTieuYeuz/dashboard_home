/* ═══════════════════════════════════════════════════════════════════
   n8n-assistant.js — Nút 🤖 AI nổi NHÚNG TRONG n8n (qua /n8n-proxy)
   -------------------------------------------------------------------
   Nạp TỰ ĐỘNG bởi handleN8nHomeProxy (worker.js) — không phải sửa n8n.
   Chạy same-origin trên dashboard (n8n phục vụ qua /n8n-proxy).

   Khác Termix/PNETLab/Console-Serial: đọc/ghi workflow qua n8n PUBLIC
   API chính thức (server Worker gắn X-N8N-API-KEY, KHÔNG lộ ra browser)
   — không dùng session n8n của user (API nội bộ /rest/* không tài liệu,
   dễ sai giữa các bản n8n). AI KHÔNG BAO GIỜ tự ghi khi chưa xác nhận.
   ═══════════════════════════════════════════════════════════════════ */
(function () {
  'use strict';
  if (window.__N8N_AI__) return; window.__N8N_AI__ = 1;

  var MODEL = 'N8N';   // 9Router phân biệt HOA/THƯỜNG — alias đúng là "N8N" viết hoa
  var MAX_TOOL_LOOPS = 12;
  var API_BASE = location.origin;
  var LLM_URL  = API_BASE + '/api/n8n-ai-llm';
  var WF_URL   = API_BASE + '/api/n8n-ai/workflow';
  var DOCS_URL = API_BASE + '/api/n8n-ai/docs';

  /* ── Lấy workflow ID đang mở từ URL (qua proxy: /n8n-proxy/workflow/<id>) ── */
  function currentWorkflowId() {
    var m = location.pathname.match(/\/workflow\/([\w-]+)/);
    return m ? m[1] : null;
  }

  function apiGet(url) {
    return fetch(url, { credentials: 'include', headers: { 'Content-Type': 'application/json' } })
      .then(function (r) { return r.json().catch(function () { return { error: 'bad response' }; }); })
      .catch(function (e) { return { error: 'network', message: 'Không gọi được server: ' + (e && e.message || e) }; });
  }
  function apiPost(url, body) {
    return fetch(url, { method: 'POST', credentials: 'include', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) })
      .then(function (r) { return r.json().catch(function () { return { error: 'bad response' }; }); })
      .catch(function (e) { return { error: 'network', message: 'Không gọi được server: ' + (e && e.message || e) }; });
  }

  /* Che secret trong tham số node trước khi cho AI đọc — cùng bộ luật với các assistant khác */
  var _redacted = false;
  function _mask() { _redacted = true; return '[ĐÃ CHE]'; }
  function redactDeep(v) {
    _redacted = false;
    function walk(x) {
      if (typeof x === 'string') return x;   // che theo TÊN KEY (dưới), không cần soi trong chuỗi
      if (Array.isArray(x)) return x.map(walk);
      if (x && typeof x === 'object') {
        var out = {};
        for (var k in x) {
          if (/pass(word|wd|phrase)?|secret|token|api[_-]?key|access[_-]?key|client[_-]?secret|private[_-]?key|auth[_-]?token/i.test(k)) {
            out[k] = _mask();
          } else out[k] = walk(x[k]);
        }
        return out;
      }
      return x;
    }
    return walk(v);
  }

  /* ── Tool: đọc workflow đang mở ── */
  /* Mặc định trả BẢN TÓM TẮT (tên/type/version mỗi node + connections) — đủ để hiểu workflow.
     Tham số THẬT của node chỉ trả khi AI hỏi rõ ({"detail":true} hoặc {"node_name":"..."}),
     vì đổ nguyên 40 node đầy đủ tốn ~2.500 token và nằm lại trong lịch sử suốt các vòng sau. */
  function readWorkflow(p) {
    var wfId = currentWorkflowId();
    if (!wfId) return Promise.resolve({ ok: false, error: 'Không xác định được workflow đang mở — anh mở 1 workflow cụ thể trong n8n trước (không phải trang danh sách).' });
    return apiGet(WF_URL + '?id=' + encodeURIComponent(wfId)).then(function (res) {
      if (!res || !res.ok) return { ok: false, error: (res && res.message) || (res && res.error) || 'Đọc workflow thất bại.' };
      var wf = res.workflow || {};
      var nodes = wf.nodes || [];
      var out = {
        ok: true,
        workflow_id: wfId,
        name: wf.name,
        active: !!wf.active,
        node_count: nodes.length,
        nodes_summary: nodes.map(function (n) {
          return { name: n.name, type: n.type, typeVersion: n.typeVersion, disabled: !!n.disabled };
        }),
        connections: wf.connections || {},
        warning: wf.active ? '⚠️ Workflow này ĐANG ACTIVE (đang chạy thật) — sửa/thêm node có thể ảnh hưởng ngay lập tức.' : undefined,
      };
      var wantName = p && p.node_name;
      if (wantName) {
        var one = nodes.find(function (n) { return n.name === wantName; });
        out.node_detail = one ? redactDeep(one) : null;
        if (!one) out.node_detail_error = 'Không có node tên "' + wantName + '".';
      } else if (p && p.detail) {
        out.nodes_full = redactDeep(nodes).slice(0, 40);
      } else {
        out.hint = 'Chỉ có tóm tắt. Cần xem tham số thật của 1 node → gọi lại read_workflow với {"node_name":"tên node"}.';
      }
      return out;
    });
  }

  /* ── Tool: xem lịch sử chạy gần đây + chi tiết node lỗi (nếu có) — CHỈ ĐỌC ── */
  function checkExecution() {
    var wfId = currentWorkflowId();
    if (!wfId) return Promise.resolve({ ok: false, error: 'Không xác định được workflow đang mở.' });
    return apiGet(API_BASE + '/api/n8n-ai/executions?workflowId=' + encodeURIComponent(wfId)).then(function (res) {
      if (!res || !res.ok) return { ok: false, error: (res && res.message) || (res && res.error) || 'Không đọc được lịch sử chạy.' };
      return res;
    });
  }

  /* Đặt giá trị lồng nhau kiểu "a.b.c" vào object (tạo object trung gian nếu chưa có) */
  function setDeep(obj, path, value) {
    var parts = String(path).split('.');
    var cur = obj;
    for (var i = 0; i < parts.length - 1; i++) {
      if (typeof cur[parts[i]] !== 'object' || cur[parts[i]] === null) cur[parts[i]] = {};
      cur = cur[parts[i]];
    }
    cur[parts[parts.length - 1]] = value;
  }

  /* ── Tool: sửa 1 tham số của node có sẵn (AN TOÀN NHẤT — không đụng connections) ── */
  function updateNodeParameter(p) {
    var wfId = currentWorkflowId();
    if (!wfId) return Promise.resolve({ ok: false, error: 'Không xác định được workflow đang mở.' });
    if (!p || !p.node_name || !p.param_path) return Promise.resolve({ ok: false, error: 'Thiếu node_name/param_path.' });
    return apiGet(WF_URL + '?id=' + encodeURIComponent(wfId)).then(function (res) {
      if (!res || !res.ok) return { ok: false, error: (res && res.message) || 'Không đọc được workflow hiện tại.' };
      var wf = res.workflow || {};
      var nodes = wf.nodes || [];
      var target = nodes.find(function (n) { return n.name === p.node_name; });
      if (!target) return { ok: false, error: 'Không tìm thấy node tên "' + p.node_name + '". Dùng read_workflow để xem danh sách node chính xác.' };
      if (!target.parameters || typeof target.parameters !== 'object') target.parameters = {};
      setDeep(target.parameters, p.param_path, p.value);
      // n8n Public API chỉ có PUT (full replace) — phải gửi lại ĐỦ name/nodes/connections/settings,
      // không chỉ field vừa đổi (xác nhận qua lỗi thật "PATCH method not allowed" + tài liệu n8n).
      var body = { name: wf.name, nodes: nodes, connections: wf.connections || {}, settings: wf.settings || {} };
      return apiPost(WF_URL, { workflowId: wfId, patch: body }).then(function (r2) {
        if (!r2 || !r2.ok) return { ok: false, error: (r2 && r2.message) || (r2 && r2.error) || 'Ghi thất bại.' };
        return { ok: true, note: 'Đã cập nhật "' + p.param_path + '" của node "' + p.node_name + '". Nút "🔄 Tải lại workflow" sẽ tự hiện trong chat để xem thay đổi.' };
      });
    });
  }

  /* ── Tool: thêm node mới (RỦI RO CAO HƠN — có thể kèm nối dây) ── */
  function addNode(p) {
    var wfId = currentWorkflowId();
    if (!wfId) return Promise.resolve({ ok: false, error: 'Không xác định được workflow đang mở.' });
    if (!p || !p.name || !p.type) return Promise.resolve({ ok: false, error: 'Thiếu name/type cho node mới.' });
    return apiGet(WF_URL + '?id=' + encodeURIComponent(wfId)).then(function (res) {
      if (!res || !res.ok) return { ok: false, error: (res && res.message) || 'Không đọc được workflow hiện tại.' };
      var wf = res.workflow || {};
      var nodes = (wf.nodes || []).slice();
      if (nodes.some(function (n) { return n.name === p.name; })) return { ok: false, error: 'Đã có node tên "' + p.name + '" — chọn tên khác.' };
      var newNode = {
        id: (window.crypto && crypto.randomUUID) ? crypto.randomUUID() : ('node_' + Date.now()),
        name: p.name,
        type: p.type,
        typeVersion: p.typeVersion || 1,
        position: Array.isArray(p.position) ? p.position : [600, 300],
        parameters: p.parameters || {},
      };
      nodes.push(newNode);
      var connections = Object.assign({}, wf.connections || {});
      if (p.connect_from) {
        var src = p.connect_from;
        if (!nodes.some(function (n) { return n.name === src; })) return { ok: false, error: 'connect_from "' + src + '" không phải node có sẵn trong workflow.' };
        var srcConn = connections[src] ? JSON.parse(JSON.stringify(connections[src])) : { main: [[]] };
        if (!srcConn.main) srcConn.main = [[]];
        if (!srcConn.main[0]) srcConn.main[0] = [];
        srcConn.main[0].push({ node: p.name, type: 'main', index: 0 });
        connections[src] = srcConn;
      }
      // PUT full-replace — phải gửi đủ name/settings, không chỉ nodes/connections.
      var body = { name: wf.name, nodes: nodes, connections: connections, settings: wf.settings || {} };
      return apiPost(WF_URL, { workflowId: wfId, patch: body }).then(function (r2) {
        if (!r2 || !r2.ok) return { ok: false, error: (r2 && r2.message) || (r2 && r2.error) || 'Ghi thất bại.' };
        return { ok: true, note: 'Đã thêm node "' + p.name + '" (' + p.type + ')' + (p.connect_from ? ' và nối từ "' + p.connect_from + '"' : '') + '. Nút "🔄 Tải lại workflow" sẽ tự hiện trong chat để xem thay đổi.' };
      });
    });
  }

  /* ── Tool: thêm NHIỀU node cùng lúc (1 lần đọc + 1 lần xác nhận + 1 lần ghi) ── */
  /* Giống cách n8n's official MCP server tạo workflow (submit toàn bộ node list 1 lần) —   */
  /* tránh phải lặp lại add_node từng node (mỗi lần tốn 1 vòng LLM + 1 hộp confirm) khi cần  */
  /* dựng cả 1 workflow nhiều bước cùng lúc.                                                */
  function addNodes(p) {
    var wfId = currentWorkflowId();
    if (!wfId) return Promise.resolve({ ok: false, error: 'Không xác định được workflow đang mở.' });
    if (!p || !Array.isArray(p.nodes) || !p.nodes.length) return Promise.resolve({ ok: false, error: 'Thiếu mảng nodes.' });
    return apiGet(WF_URL + '?id=' + encodeURIComponent(wfId)).then(function (res) {
      if (!res || !res.ok) return { ok: false, error: (res && res.message) || 'Không đọc được workflow hiện tại.' };
      var wf = res.workflow || {};
      var nodes = (wf.nodes || []).slice();
      var connections = Object.assign({}, wf.connections || {});
      var added = [];
      for (var i = 0; i < p.nodes.length; i++) {
        var n = p.nodes[i];
        if (!n || !n.name || !n.type) return { ok: false, error: 'Node thứ ' + (i + 1) + ' trong mảng thiếu name/type.' };
        if (nodes.some(function (x) { return x.name === n.name; })) return { ok: false, error: 'Đã có node tên "' + n.name + '" — chọn tên khác.' };
        var newNode = {
          id: (window.crypto && crypto.randomUUID) ? crypto.randomUUID() : ('node_' + Date.now() + '_' + i),
          name: n.name,
          type: n.type,
          typeVersion: n.typeVersion || 1,
          position: Array.isArray(n.position) ? n.position : [600 + i * 220, 300],
          parameters: n.parameters || {},
        };
        nodes.push(newNode);
        added.push(newNode.name);
        if (n.connect_from) {
          var src = n.connect_from;
          if (!nodes.some(function (x) { return x.name === src; })) return { ok: false, error: 'connect_from "' + src + '" không phải node có sẵn (kể cả node vừa thêm trước đó trong cùng lần gọi này).' };
          var srcConn = connections[src] ? JSON.parse(JSON.stringify(connections[src])) : { main: [[]] };
          if (!srcConn.main) srcConn.main = [[]];
          if (!srcConn.main[0]) srcConn.main[0] = [];
          srcConn.main[0].push({ node: n.name, type: 'main', index: 0 });
          connections[src] = srcConn;
        }
      }
      var body = { name: wf.name, nodes: nodes, connections: connections, settings: wf.settings || {} };
      return apiPost(WF_URL, { workflowId: wfId, patch: body }).then(function (r2) {
        if (!r2 || !r2.ok) return { ok: false, error: (r2 && r2.message) || (r2 && r2.error) || 'Ghi thất bại.' };
        return { ok: true, note: 'Đã thêm ' + added.length + ' node: ' + added.join(', ') + '. Nút "🔄 Tải lại workflow" sẽ tự hiện trong chat để xem thay đổi.' };
      });
    });
  }

  /* ── Tool: tra TÀI LIỆU CHÍNH CHỦ n8n (qua MCP docs.n8n.io, đi vòng qua Worker) ──
     Đây là thứ vá đúng điểm yếu "đoán mò": trước đây AI chỉ suy ra cú pháp node từ
     các node đã có sẵn trong workflow đang mở, nên gặp node lạ là sai. */
  function searchDocs(p) {
    var q = (p && p.query || '').trim();
    if (!q) return Promise.resolve({ ok: false, error: 'Thiếu query.' });
    return apiPost(DOCS_URL, { tool: 'searchDocumentation', query: q }).then(function (r) {
      if (!r || !r.ok) return { ok: false, error: (r && r.message) || (r && r.error) || 'Tra tài liệu thất bại.' };
      return { ok: true, results: r.text };
    });
  }
  function readDoc(p) {
    var u = (p && p.url || '').trim();
    if (!u) return Promise.resolve({ ok: false, error: 'Thiếu url.' });
    return apiPost(DOCS_URL, { tool: 'getPage', url: u }).then(function (r) {
      if (!r || !r.ok) return { ok: false, error: (r && r.message) || (r && r.error) || 'Đọc trang tài liệu thất bại.' };
      return { ok: true, page: r.text };
    });
  }

  /* ── Tool: đọc SCHEMA THẬT của 1 node type từ chính n8n đang chạy ──
     n8n phục vụ /types/nodes.json (cần cookie phiên n8n — script này chạy TRONG iframe
     n8n nên browser tự gửi kèm). File rất lớn nên chỉ tải 1 lần/phiên rồi lọc.
     ⚠️ CHƯA verify được từ phía em (cần cookie n8n của anh Thoại) → code phòng thủ:
     mọi trường hợp không đọc/không hiểu được đều trả lỗi RÕ để AI quay sang search_docs. */
  var _nodeTypesCache = null;
  function loadNodeTypes() {
    if (_nodeTypesCache) return Promise.resolve(_nodeTypesCache);
    return fetch('/n8n-proxy/types/nodes.json', { credentials: 'include' })
      .then(function (r) { if (!r.ok) throw new Error('HTTP ' + r.status); return r.json(); })
      .then(function (j) {
        var list = Array.isArray(j) ? j : (j && Array.isArray(j.data) ? j.data : null);
        if (!list) throw new Error('định dạng nodes.json không như mong đợi');
        _nodeTypesCache = list; return list;
      });
  }
  function getNodeSchema(p) {
    var want = (p && p.type || '').trim();
    if (!want) return Promise.resolve({ ok: false, error: 'Thiếu type.' });
    return loadNodeTypes().then(function (list) {
      var hit = list.find(function (n) { return n && n.name === want; });
      if (!hit) {
        var near = list.filter(function (n) { return n && n.name && n.name.toLowerCase().indexOf(want.toLowerCase().split('.').pop()) > -1; })
          .slice(0, 12).map(function (n) { return n.name; });
        return { ok: false, error: 'Không có node type "' + want + '" trên n8n này.', gợi_ý: near };
      }
      // Rút gọn: chỉ tên/kiểu/mặc định/lựa chọn của từng property — đủ để soạn "parameters" đúng,
      // bỏ phần mô tả dài dòng để không nuốt hết cửa sổ ngữ cảnh.
      var props = (hit.properties || []).slice(0, 60).map(function (pr) {
        return {
          name: pr.name, type: pr.type, required: !!pr.required, default: pr.default,
          options: Array.isArray(pr.options) ? pr.options.slice(0, 15).map(function (o) { return o && (o.value !== undefined ? o.value : o.name); }) : undefined,
          displayOptions: pr.displayOptions,
        };
      });
      return {
        ok: true, type: hit.name, displayName: hit.displayName,
        typeVersion_hỗ_trợ: hit.version, description: hit.description,
        credentials: (hit.credentials || []).map(function (c) { return c && c.name; }),
        properties: props,
        note: props.length >= 60 ? 'Đã cắt bớt, chỉ hiện 60 property đầu.' : undefined,
      };
    }).catch(function (e) {
      return { ok: false, error: 'Không đọc được schema node từ n8n (' + (e && e.message || e) + '). Dùng search_docs để tra tài liệu thay thế.' };
    });
  }

  /* ── Tool: HỎI anh Thoại bằng UI nút bấm (giống bảng câu hỏi của Claude Code) ──
     Vì sao là tool chứ không để AI hỏi bằng lời: hỏi bằng lời thì anh phải gõ trả lời,
     AI lại phải đoán ý câu trả lời → thêm vòng LLM. Ở đây AI ra sẵn phương án, anh bấm
     chọn, kết quả trả về là dữ liệu có cấu trúc → gom cả 3 câu vào ĐÚNG 1 vòng. */
  function askUser(p) {
    var qs = (p && p.questions) || [];
    if (!qs.length) return Promise.resolve({ ok: false, error: 'Thiếu questions.' });
    qs = qs.slice(0, 5);
    return new Promise(function (resolve) {
      var box = document.createElement('div');
      box.className = 'n8m n8-ask'; box.setAttribute('data-transient', '1');
      var picked = {};
      qs.forEach(function (q, qi) {
        var wrap = document.createElement('div'); wrap.className = 'n8-q';
        var t = document.createElement('div'); t.className = 'n8-qt';
        t.textContent = (qi + 1) + '. ' + (q.question || '');
        wrap.appendChild(t);
        var opts = document.createElement('div'); opts.className = 'n8-opts';
        (q.options || []).slice(0, 6).forEach(function (o) {
          var label = typeof o === 'string' ? o : (o && (o.label || o.value) || '');
          var b = document.createElement('button');
          b.type = 'button'; b.className = 'n8-opt'; b.textContent = label;
          if (typeof o === 'object' && o && o.description) b.title = o.description;
          b.onclick = function () {
            picked[q.question || ('q' + qi)] = label;
            var sib = opts.querySelectorAll('.n8-opt');
            for (var i = 0; i < sib.length; i++) sib[i].classList.remove('sel');
            b.classList.add('sel');
            var free = wrap.querySelector('.n8-free'); if (free) free.value = '';
          };
          opts.appendChild(b);
        });
        wrap.appendChild(opts);
        var free = document.createElement('input');
        free.type = 'text'; free.className = 'n8-free'; free.placeholder = 'hoặc tự nhập…';
        free.oninput = function () {
          if (free.value.trim()) {
            picked[q.question || ('q' + qi)] = free.value.trim();
            var sib = opts.querySelectorAll('.n8-opt');
            for (var i = 0; i < sib.length; i++) sib[i].classList.remove('sel');
          }
        };
        wrap.appendChild(free);
        box.appendChild(wrap);
      });
      var go = document.createElement('button');
      go.type = 'button'; go.className = 'n8-ask-go'; go.textContent = '✓ Gửi câu trả lời';
      go.onclick = function () {
        var missing = qs.filter(function (q, qi) { return !picked[q.question || ('q' + qi)]; });
        if (missing.length) { go.textContent = '⚠️ Còn ' + missing.length + ' câu chưa chọn'; setTimeout(function () { go.textContent = '✓ Gửi câu trả lời'; }, 1600); return; }
        box.remove();
        var lines = Object.keys(picked).map(function (k) { return '• ' + k + ' → ' + picked[k]; });
        addMsg('n8m-u', lines.join('\n'));
        resolve({ ok: true, answers: picked });
      };
      box.appendChild(go);
      msgs.appendChild(box); msgs.scrollTop = msgs.scrollHeight;
    });
  }

  var TOOLS = {
    read_workflow: function (p) { return readWorkflow(p); },
    ask: function (p) { return askUser(p); },
    check_execution: function () { return checkExecution(); },
    search_docs: function (p) { return searchDocs(p); },
    read_doc: function (p) { return readDoc(p); },
    get_node_schema: function (p) { return getNodeSchema(p); },
    update_node_parameter: function (p) { return updateNodeParameter(p); },
    add_node: function (p) { return addNode(p); },
    add_nodes: function (p) { return addNodes(p); },
  };
  var MUTATING = { update_node_parameter: 1, add_node: 1, add_nodes: 1 };

  var SYS = [
    'Bạn là trợ lý AI tích hợp trong n8n (workflow automation), giúp anh Thoại hiểu và chỉnh sửa workflow đang mở.',
    'Trả lời tiếng Việt, ngắn gọn, chính xác kỹ thuật. Anh Thoại là SysAdmin/kỹ sư hạ tầng — nói thẳng vào kỹ thuật, không giải thích vòng vo những thứ cơ bản.',
    '',
    'BỐI CẢNH CHUYÊN MÔN (dùng để suy luận automation cho đúng thực tế của anh):',
    '- Anh vận hành homelab + hệ thống công ty: FortiGate (firewall/VPN/policy), VMware, PNETLab, camera Frigate, Cloudflare Tunnel/Workers, Docker/CasaOS, n8n, SSH/serial console tới switch-router.',
    '- Automation anh cần thường thuộc 4 nhóm: (1) NETWORK — gọi API thiết bị, thu thập trạng thái interface/VPN/policy, cảnh báo khi rớt; (2) DEVOPS — webhook CI/CD, backup cấu hình, deploy, health-check; (3) SYSTEM — giám sát tài nguyên, log, chứng chỉ hết hạn, dọn dẹp định kỳ; (4) SUPPORT — nhận yêu cầu qua mail/Telegram, phân loại, tạo ticket, trả lời tự động.',
    '- Khi thiết kế workflow cho các nhóm trên, LUÔN nghĩ tới: xử lý lỗi (node lỗi thì sao), chống spam cảnh báo (gửi lặp mỗi lần chạy), idempotency (chạy lại không nhân đôi tác dụng), và bảo mật (đừng in secret ra log/message).',
    '',
    'NẾU ANH GỬI ẢNH: đọc kỹ ảnh trước khi trả lời — thường là ảnh chụp lỗi n8n, sơ đồ mạng, cấu hình thiết bị, hoặc canvas workflow. Trích dẫn đúng chữ/thông số bạn ĐỌC ĐƯỢC trong ảnh; nếu ảnh mờ/thiếu phần quan trọng thì nói rõ chỗ nào không đọc được thay vì đoán.',
    '',
    '⚠️ ĐÂY LÀ AUTOMATION THẬT — 1 workflow có thể đang ACTIVE (chạy sống, xử lý webhook/email/dữ liệu thật). Vì vậy:',
    '- LUÔN gọi read_workflow TRƯỚC khi trả lời hoặc sửa gì — để biết chính xác cấu trúc, tên node, và workflow có đang active không. KHÔNG đoán tên/type node.',
    '- Nếu workflow đang active (field "active":true / có warning), CẢNH BÁO RÕ trước khi đề xuất sửa.',
    '- Việc GHI (update_node_parameter/add_node) LUÔN cần anh xác nhận qua hộp thoại — bạn không tự ý ghi.',
    '- update_node_parameter (sửa 1 tham số node có sẵn) AN TOÀN HƠN NHIỀU so với add_node (thêm node mới, có thể phải nối dây) — ưu tiên dùng update_node_parameter khi có thể; chỉ dùng add_node khi thực sự cần thêm bước mới.',
    '',
    '🚫 TUYỆT ĐỐI KHÔNG ĐOÁN cú pháp node. Bạn CÓ công cụ tra cứu thật — dùng chúng:',
    '- Trước khi tạo/sửa BẤT KỲ node nào mà bạn không chắc 100% về "type" hoặc tên tham số trong "parameters" → PHẢI gọi get_node_schema (chính xác nhất, lấy từ n8n đang chạy) và/hoặc search_docs (tài liệu chính chủ n8n).',
    '- Sai "type" → n8n báo "Unrecognized node type"; sai tên tham số → node tạo ra rỗng/không chạy. Cả hai đều do đoán mò, và đều tránh được bằng 1 lần tra cứu.',
    '- Nếu get_node_schema báo lỗi không đọc được → chuyển sang search_docs, ĐỪNG bỏ cuộc và cũng đừng đoán.',
    '- Khi anh Thoại nhờ dựng workflow có node bạn chưa từng thấy (Gmail, Telegram, Schedule Trigger…), quy trình ĐÚNG là: search_docs (hoặc get_node_schema) TRƯỚC → có type + tham số thật → mới add_nodes. KHÔNG hỏi anh những thứ tài liệu đã trả lời được.',
    '',
    'CÔNG CỤ — in MỘT khối mã đúng định dạng rồi DỪNG chờ kết quả:',
    '```n8n',
    '{"tool":"<tên>", ...tham số}',
    '```',
    '- ask {"questions":[{"question":"...","options":[{"label":"...","description":"..."}]}, ...]} → HỎI anh Thoại bằng bảng nút bấm. Mỗi câu 2–4 phương án; anh bấm chọn (hoặc tự nhập) rồi bạn nhận lại câu trả lời có cấu trúc. Đặt phương án BẠN KHUYÊN DÙNG lên đầu và ghi "(nên dùng)" trong label.',
    '- read_workflow → mặc định trả TÓM TẮT (tên/type/version mỗi node + connections) — đủ để hiểu workflow, tốn ít token. Cần xem THAM SỐ THẬT của 1 node cụ thể → gọi lại {"node_name":"tên node"}. Chỉ dùng {"detail":true} (đổ hết mọi node) khi thật sự cần so sánh nhiều node. DÙNG ĐẦU TIÊN luôn.',
    '- get_node_schema {"type":"n8n-nodes-base.gmail"} → SCHEMA THẬT của node type đó lấy từ chính n8n đang chạy: danh sách property (tên/kiểu/mặc định/lựa chọn), typeVersion hỗ trợ, credentials cần. ĐÂY LÀ NGUỒN CHÍNH XÁC NHẤT để soạn "parameters" — ưu tiên dùng trước khi add_node/add_nodes. Nếu sai tên type, tool trả về danh sách gợi ý gần đúng.',
    '- search_docs {"query":"..."} → tra TÀI LIỆU CHÍNH CHỦ n8n (docs.n8n.io). Dùng khi cần hiểu CÁCH cấu hình/vận hành (vd "Schedule Trigger cron 7am timezone", "Gmail node get many messages filter"). Trả về đoạn trích + link trang.',
    '- read_doc {"url":"https://docs.n8n.io/..."} → đọc TOÀN VĂN 1 trang tài liệu (dùng link mà search_docs trả về khi cần chi tiết hơn).',
    '  ⚠️ search_docs/read_doc gửi truy vấn ra dịch vụ NGOÀI (docs.n8n.io) — CHỈ gửi câu hỏi kỹ thuật chung. TUYỆT ĐỐI không đưa nội dung workflow, tên/giá trị credentials, hay dữ liệu chạy thật vào query.',
    '- check_execution → đọc LỊCH SỬ CHẠY THẬT gần đây (5 lần) + CHI TIẾT node nào lỗi trong lần lỗi gần nhất (hoặc lần gần nhất nếu không có lỗi) — mỗi node kèm trạng thái + thông báo lỗi thật nếu có. KHÔNG tham số. Đây là cách DUY NHẤT biết workflow có đang hư/lỗi ở node nào — ĐỪNG đoán mò khi user hỏi "sao workflow lỗi"/"check giúp", LUÔN gọi tool này để xem bằng chứng thật.',
    '- update_node_parameter {"node_name":"...", "param_path":"a.b.c", "value":...} → sửa 1 tham số của node có sẵn (param_path dùng dấu chấm cho tham số lồng nhau, vd "url" hoặc "options.timeout").',
    '- add_node {"name":"...", "type":"...", "typeVersion":1, "position":[x,y], "parameters":{...}, "connect_from":"tên node nguồn (tuỳ chọn)"} → thêm ĐÚNG 1 node mới, tuỳ chọn nối input từ 1 node có sẵn.',
    '- add_nodes {"nodes":[{"name":"...","type":"...","typeVersion":1,"position":[x,y],"parameters":{...},"connect_from":"..."}, ...]} → thêm NHIỀU node CÙNG LÚC trong 1 lần ghi (1 lần xác nhận duy nhất). connect_from của node sau được phép trỏ tới node vừa khai báo trước đó TRONG CÙNG mảng này (không cần add_node riêng từng cái).',
    '',
    'KHI USER HỎI "WORKFLOW BỊ LỖI/HƯ Ở ĐÂU" HOẶC "CHECK GIÚP":',
    '- Gọi read_workflow trước (biết cấu trúc) rồi check_execution (biết lỗi thật ở node nào, thông báo lỗi gì).',
    '- ⚠️ GIỚI HẠN THẬT phải biết: bạn KHÔNG có cách nào tự "bấm chạy thử" workflow ngay bây giờ (n8n không có API chính thức cho việc đó) — chỉ đọc được LỊCH SỬ các lần đã chạy TRƯỚC ĐÓ (qua webhook/lịch/thủ công trong quá khứ). Nếu user muốn xem kết quả một lần chạy MỚI, phải nhờ user tự bấm nút "Execute Workflow" trong n8n rồi hỏi lại — bạn không tự trigger được.',
    '- Nếu check_execution báo "chưa có lần chạy nào" → nói thẳng, đừng suy diễn.',
    '- Khi thấy node lỗi, trích dẫn ĐÚNG thông báo lỗi thật (field "error") trong câu trả lời — không đoán chung chung.',
    '',
    '📋 KHI ANH YÊU CẦU TẠO / DỰNG MỘT WORKFLOW MỚI — quy trình BẮT BUỘC, đúng thứ tự:',
    'B1. Phân tích câu nói của anh: mục tiêu thật là gì, dữ liệu vào từ đâu, ra đi đâu, chạy lúc nào, thất bại thì sao.',
    'B2. Gọi ask với ÍT NHẤT 3 CÂU HỎI cho những chỗ CÒN MƠ HỒ và sẽ làm workflow sai nếu đoán bừa. Ưu tiên hỏi về: lịch chạy/điều kiện kích hoạt · phạm vi & bộ lọc dữ liệu · đích đến và định dạng thông báo · cách xử lý khi lỗi/rỗng.',
    '   • KHÔNG hỏi những gì tra cứu được (tên node, cú pháp tham số, cách cấu hình) — cái đó tự tra bằng search_docs/get_node_schema.',
    '   • KHÔNG hỏi tên credentials: cứ để trống trong node, anh tự chọn trong giao diện n8n (nói rõ điều này cho anh).',
    '   • Mỗi câu phải có phương án mặc định hợp lý đứng đầu, ghi "(nên dùng)" — để anh chỉ cần bấm là xong.',
    'B3. Sau khi có câu trả lời: tra cứu (get_node_schema/search_docs) cho các node cần dùng.',
    'B4. Gọi add_nodes MỘT LẦN với đầy đủ node + nối dây.',
    '→ Gộp hết thắc mắc vào MỘT lần ask (3–5 câu) thay vì hỏi lắt nhắt nhiều lượt: vừa đỡ mất thời gian của anh, vừa tiết kiệm token.',
    '',
    'QUY TẮC:',
    '- Mỗi lượt chỉ in 1 khối ```n8n```. Sau [KẾT QUẢ TOOL], phân tích rồi tiếp tục hoặc trả lời.',
    '- TIẾT KIỆM TOKEN: đừng gọi lại tool đã có kết quả trong lịch sử; đừng nhắc lại nguyên văn dữ liệu tool vừa đọc (chỉ nêu kết luận); trả lời gọn, không viết lại yêu cầu của anh.',
    '- Sau khi ghi thành công, KHÔNG cần dặn anh Thoại tự reload — giao diện chat tự hiện sẵn nút "🔄 Tải lại workflow" ngay bên dưới, anh chỉ việc bấm.',
    '- Khi anh yêu cầu DỰNG CẢ 1 WORKFLOW (nhiều bước/node cùng lúc từ đầu) → dùng add_nodes với ĐẦY ĐỦ các node trong 1 lần gọi duy nhất (không lặp add_node từng cái) — nhanh hơn nhiều vì chỉ tốn 1 vòng hỏi-đáp + 1 lần xác nhận thay vì N lần.',
    '- Chỉ dùng add_node (số ít) khi thực sự CHỈ thêm đúng 1 node vào workflow đã có sẵn.',
  ].join('\n');

  /* ── UI (tông màu hồng cam — gần màu thương hiệu n8n) ── */
  var css = document.createElement('style');
  css.textContent =
    /* Góc PHẢI dưới, NẰM CÙNG HÀNG và ngay BÊN TRÁI nút tròn "+" — giống bố cục các trang
       khác (anh Thoại chốt 2026-08-16: "AI nằm kế bên dấu +, không nằm trên").
       Nút "+" của n8n rộng ~44px đặt cách mép phải ~18px → mép trái nó ở ~62px. Để 78px cho
       hở đúng 16px. Bản cũ để 64px nên chỉ hở 4px, nhìn dính vào nhau. */
    '#n8nai-btn{position:fixed;bottom:20px;right:78px;height:44px;width:auto;padding:0 14px;display:inline-flex;align-items:center;gap:6px;' +
    'border:none;border-radius:22px;cursor:pointer;background:linear-gradient(135deg,#ff6d5a,#ea4b6a);color:#3a0a10;font-size:14px;font-weight:700;' +
    'box-shadow:0 3px 14px rgba(0,0,0,.4);z-index:2147483000;transition:transform .12s}' +
    '#n8nai-btn:hover{transform:translateY(-1px)}' +
    '#n8nai-panel{position:fixed;bottom:76px;right:20px;width:390px;max-width:calc(100vw - 30px);height:560px;max-height:calc(100vh - 120px);' +
    'background:#1a0e10;border:1px solid rgba(255,255,255,.12);border-radius:14px;z-index:2147483000;display:none;flex-direction:column;overflow:hidden;' +
    'box-shadow:0 10px 44px rgba(0,0,0,.6);font-family:"Segoe UI",system-ui,sans-serif}' +
    '#n8nai-panel.open{display:flex}' +
    '#n8nai-hd{background:linear-gradient(135deg,#8a1f2e,#5a1420);padding:11px 14px;display:flex;justify-content:space-between;align-items:center;color:#fff;font-weight:700;font-size:14px}' +
    '#n8nai-hd .x{cursor:pointer;opacity:.7;font-size:16px}#n8nai-hd .x:hover{opacity:1}' +
    '#n8nai-msgs{flex:1;overflow-y:auto;padding:12px;display:flex;flex-direction:column;gap:9px}' +
    '.n8m{max-width:88%;padding:9px 12px;border-radius:13px;font-size:13px;line-height:1.55;white-space:pre-wrap;word-break:break-word}' +
    '.n8m-u{align-self:flex-end;background:linear-gradient(135deg,#8a1f2e,#5a1420);color:#ffe9ec;border-bottom-right-radius:4px}' +
    '.n8m-a{align-self:flex-start;background:rgba(255,255,255,.06);color:#ffe0e4;border-bottom-left-radius:4px}' +
    '.n8m-t{align-self:flex-start;background:rgba(255,109,90,.1);border:1px solid rgba(255,109,90,.28);color:#ff9d8f;font-size:11.5px;padding:6px 10px;border-radius:9px}' +
    '.n8-reload{background:linear-gradient(135deg,#ff6d5a,#ea4b6a);border:none;border-radius:7px;padding:4px 10px;margin-left:4px;color:#3a0a10;font-size:11.5px;font-weight:700;cursor:pointer;font-family:inherit}' +
    '.n8-reload:hover{filter:brightness(1.1)}' +
    /* Bảng câu hỏi dạng nút bấm */
    '.n8-ask{align-self:stretch;max-width:100%;background:rgba(255,255,255,.05);border:1px solid rgba(255,109,90,.3);border-radius:12px;padding:11px}' +
    '.n8-q{margin-bottom:11px}.n8-q:last-of-type{margin-bottom:8px}' +
    '.n8-qt{color:#ffd9d3;font-size:12.5px;font-weight:600;margin-bottom:6px;line-height:1.45}' +
    '.n8-opts{display:flex;flex-wrap:wrap;gap:5px;margin-bottom:5px}' +
    '.n8-opt{background:rgba(255,255,255,.07);border:1px solid rgba(255,255,255,.16);border-radius:8px;padding:5px 9px;color:#ffe0e4;font-size:12px;cursor:pointer;font-family:inherit;text-align:left}' +
    '.n8-opt:hover{background:rgba(255,109,90,.18)}' +
    '.n8-opt.sel{background:linear-gradient(135deg,#ff6d5a,#ea4b6a);color:#3a0a10;font-weight:700;border-color:transparent}' +
    '.n8-free{width:100%;box-sizing:border-box;background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.12);border-radius:7px;padding:5px 8px;color:#ffe9ec;font-size:12px;outline:none;font-family:inherit}' +
    '.n8-ask-go{width:100%;background:linear-gradient(135deg,#ff6d5a,#ea4b6a);border:none;border-radius:9px;padding:7px;color:#3a0a10;font-size:12.5px;font-weight:700;cursor:pointer;font-family:inherit}' +
    /* Ảnh đính kèm */
    '#n8nai-clip{background:rgba(255,255,255,.07);border:1px solid rgba(255,255,255,.14);border-radius:9px;width:34px;color:#ffb3a8;font-size:15px;cursor:pointer;font-family:inherit}' +
    '#n8nai-clip:hover{background:rgba(255,109,90,.18)}' +
    '.n8-thumbs{display:flex;gap:5px;flex-wrap:wrap;padding:0 10px 6px}' +
    '.n8-thumb{position:relative;width:44px;height:44px;border-radius:7px;overflow:hidden;border:1px solid rgba(255,255,255,.18)}' +
    '.n8-thumb img{width:100%;height:100%;object-fit:cover;display:block}' +
    '.n8-thumb span{position:absolute;top:0;right:0;background:rgba(0,0,0,.7);color:#fff;font-size:11px;line-height:1;padding:2px 4px;cursor:pointer}' +
    '.n8m-img{max-width:180px;border-radius:9px;display:block;margin-top:4px}' +
    '.n8-usage{align-self:center;color:#9c6f6a;font-size:10.5px;padding:2px 0}' +
    '#n8nai-in{display:flex;gap:7px;padding:10px;border-top:1px solid rgba(255,255,255,.09)}' +
    '#n8nai-in textarea{flex:1;background:rgba(255,255,255,.05);border:1px solid rgba(255,255,255,.14);border-radius:9px;padding:8px 10px;color:#ffe9ec;font-size:13px;resize:none;outline:none;font-family:inherit;height:38px}' +
    '#n8nai-in button{background:linear-gradient(135deg,#ff6d5a,#ea4b6a);border:none;border-radius:9px;width:42px;color:#3a0a10;font-size:16px;cursor:pointer}' +
    '#n8nai-in button:disabled{opacity:.5;cursor:default}' +
    '.n8-wc{color:#d99a92;font-size:12.5px;text-align:center;padding:14px 8px;line-height:1.6}';
  document.head.appendChild(css);

  var btn = document.createElement('button');
  btn.id = 'n8nai-btn'; btn.title = 'Trợ lý AI cho workflow'; btn.type = 'button'; btn.innerHTML = '🤖 <span>AI</span>';
  document.body.appendChild(btn);

  var panel = document.createElement('div'); panel.id = 'n8nai-panel';
  panel.innerHTML =
    '<div id="n8nai-hd"><span>🤖 Trợ lý n8n</span><span class="x" title="Đóng">✕</span></div>' +
    '<div id="n8nai-msgs"><div class="n8-wc">Chào anh! Mở 1 workflow rồi hỏi mình — mình đọc được toàn bộ node + kết nối.<br><br>Sửa/thêm node mình LUÔN xin xác nhận trước, không tự ý ghi.<br><br>Thử: <i>"workflow này làm gì"</i> · <i>"tại sao node X lỗi"</i> · <i>"đổi URL của node HTTP Request"</i>.</div></div>' +
    '<div class="n8-thumbs"></div>' +
    '<div id="n8nai-in">' +
      '<input type="file" accept="image/*" multiple hidden>' +
      '<button id="n8nai-clip" type="button" title="Đính kèm ảnh (chụp màn hình lỗi, sơ đồ…)">📎</button>' +
      '<textarea placeholder="Hỏi về workflow đang mở… (dán ảnh bằng Ctrl+V được)" rows="1"></textarea>' +
      '<button title="Gửi">▶</button>' +
    '</div>';
  document.body.appendChild(panel);

  var msgs = panel.querySelector('#n8nai-msgs');
  var ta = panel.querySelector('textarea');
  var send = panel.querySelector('#n8nai-in button');
  var clip = panel.querySelector('#n8nai-clip');
  var fileIn = panel.querySelector('input[type=file]');
  var thumbs = panel.querySelector('.n8-thumbs');
  var chatHistory = [];   // KHÔNG đặt tên 'history' — đụng độ window.history
  var pending = [];       // ảnh đã nén, chờ gửi kèm tin nhắn kế tiếp
  var busy = false;
  var dirtyWrite = false;  // đã ghi thành công → canvas n8n đang hiển thị dữ liệu CŨ
  btn.onclick = function () { panel.classList.toggle('open'); if (panel.classList.contains('open')) ta.focus(); };
  panel.querySelector('.x').onclick = function () { panel.classList.remove('open'); };
  ta.onkeydown = function (e) { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); doSend(); } };
  send.onclick = doSend;

  /* ── Ảnh đính kèm ──────────────────────────────────────────────────────────
     Đã tự test 2026-07-26: alias N8N chạy trên gpt-5 và ĐỌC ĐƯỢC ảnh (gửi
     content dạng mảng [{type:'text'},{type:'image_url'}] → model mô tả đúng ảnh).
     Ảnh gốc chụp màn hình 2-4 MP tốn RẤT nhiều token, nên nén xuống ≤1024px +
     JPEG q0.75 trước khi gửi — chữ trong ảnh chụp màn hình vẫn đọc tốt. */
  var IMG_MAX_SIDE = 1024, IMG_MAX = 4;

  function shrinkImage(file) {
    return new Promise(function (resolve, reject) {
      var fr = new FileReader();
      fr.onerror = function () { reject(new Error('không đọc được file')); };
      fr.onload = function () {
        var img = new Image();
        img.onerror = function () { reject(new Error('không phải ảnh hợp lệ')); };
        img.onload = function () {
          var w = img.width, h = img.height;
          var sc = Math.min(1, IMG_MAX_SIDE / Math.max(w, h));
          var cv = document.createElement('canvas');
          cv.width = Math.round(w * sc); cv.height = Math.round(h * sc);
          cv.getContext('2d').drawImage(img, 0, 0, cv.width, cv.height);
          resolve(cv.toDataURL('image/jpeg', 0.75));
        };
        img.src = fr.result;
      };
      fr.readAsDataURL(file);
    });
  }

  function renderThumbs() {
    thumbs.innerHTML = '';
    pending.forEach(function (url, i) {
      var d = document.createElement('div'); d.className = 'n8-thumb';
      var im = document.createElement('img'); im.src = url; d.appendChild(im);
      var x = document.createElement('span'); x.textContent = '✕'; x.title = 'Bỏ ảnh';
      x.onclick = function () { pending.splice(i, 1); renderThumbs(); };
      d.appendChild(x);
      thumbs.appendChild(d);
    });
  }

  function addFiles(files) {
    var list = [].slice.call(files || []).filter(function (f) { return f && /^image\//.test(f.type); });
    if (!list.length) return;
    if (pending.length + list.length > IMG_MAX) { note('⚠️ Tối đa ' + IMG_MAX + ' ảnh mỗi lượt (ảnh tốn nhiều token).'); list = list.slice(0, IMG_MAX - pending.length); }
    list.forEach(function (f) {
      shrinkImage(f).then(function (url) { pending.push(url); renderThumbs(); })
        .catch(function (e) { note('⚠️ Bỏ qua 1 ảnh: ' + (e && e.message || e)); });
    });
  }

  clip.onclick = function () { fileIn.click(); };
  fileIn.onchange = function () { addFiles(fileIn.files); fileIn.value = ''; };
  ta.addEventListener('paste', function (e) {
    var items = (e.clipboardData && e.clipboardData.files) || null;
    if (items && items.length) { addFiles(items); e.preventDefault(); }
  });

  function addMsg(cls, text) { var d = document.createElement('div'); d.className = 'n8m ' + cls; d.textContent = text; msgs.appendChild(d); msgs.scrollTop = msgs.scrollHeight; return d; }
  function note(text) { addMsg('n8m-t', text); }

  /* ── Tải lại canvas sau khi AI ghi ─────────────────────────────────────────
     n8n là SPA: ghi qua Public API xong thì canvas vẫn hiển thị bản CŨ trong bộ
     nhớ. Anh Thoại không F5 được vì n8n chạy trong iframe — F5 reload TRANG CHA
     nên iframe quay về URL gốc (trang danh sách) → văng khỏi workflow đang mở.
     Script này chạy BÊN TRONG iframe, nên location.reload() ở đây chỉ nạp lại
     riêng iframe với đúng URL /n8n-proxy/workflow/<id> → về lại đúng workflow.
     Chat được cất vào sessionStorage rồi dựng lại để không mất mạch hội thoại. */
  function ssKey() { return 'n8nai_state:' + (currentWorkflowId() || '-'); }

  function saveAndReload() {
    var arr = [];
    var els = msgs.querySelectorAll('.n8m');
    for (var i = 0; i < els.length; i++) {
      if (els[i].getAttribute('data-transient')) continue;   // bỏ hàng chứa nút bấm
      arr.push({ c: els[i].className, t: els[i].textContent });
    }
    // Bỏ ảnh base64 khỏi bản lưu — 4 ảnh có thể ~1MB, dễ vượt quota 5MB của sessionStorage
    // và cũng không cần: AI đã đọc + mô tả ảnh trong các tin nhắn phía sau rồi.
    var hist = chatHistory.map(function (m) {
      if (!Array.isArray(m.content)) return m;
      var txt = m.content.filter(function (c) { return c.type === 'text'; }).map(function (c) { return c.text; }).join(' ');
      return { role: m.role, content: txt + ' [ảnh đã gửi trước khi tải lại]' };
    });
    try { sessionStorage.setItem(ssKey(), JSON.stringify({ ui: arr, hist: hist })); } catch (e) { /* quota/private mode — vẫn reload */ }
    location.reload();
  }

  function offerReload() {
    var row = document.createElement('div');
    row.className = 'n8m n8m-t'; row.setAttribute('data-transient', '1');
    row.appendChild(document.createTextNode('Canvas n8n vẫn đang hiện bản cũ — '));
    var b = document.createElement('button');
    b.type = 'button'; b.className = 'n8-reload'; b.textContent = '🔄 Tải lại workflow';
    b.onclick = saveAndReload;
    row.appendChild(b);
    msgs.appendChild(row); msgs.scrollTop = msgs.scrollHeight;
  }

  (function restoreState() {
    var raw; try { raw = sessionStorage.getItem(ssKey()); } catch (e) { return; }
    if (!raw) return;
    try { sessionStorage.removeItem(ssKey()); } catch (e) { /* ignore */ }
    var st; try { st = JSON.parse(raw); } catch (e) { return; }
    var wc = msgs.querySelector('.n8-wc'); if (wc) wc.remove();
    (st.ui || []).forEach(function (m) {
      var d = document.createElement('div'); d.className = m.c; d.textContent = m.t; msgs.appendChild(d);
    });
    chatHistory = st.hist || [];
    panel.classList.add('open');
    note('🔄 Đã tải lại — canvas giờ hiện đúng thay đổi vừa ghi.');
  })();

  function doSend() {
    var q = (ta.value || '').trim();
    if ((!q && !pending.length) || busy) return;
    var wc = msgs.querySelector('.n8-wc'); if (wc) wc.remove();
    ta.value = '';
    var imgs = pending.slice(); pending = []; renderThumbs();

    var bubble = addMsg('n8m-u', q || '(ảnh)');
    imgs.forEach(function (url) { var im = document.createElement('img'); im.className = 'n8m-img'; im.src = url; bubble.appendChild(im); });

    if (imgs.length) {
      // Định dạng multimodal của OpenAI: content là MẢNG phần tử text/image_url.
      var parts = [{ type: 'text', text: q || 'Xem ảnh này và phân tích giúp tôi.' }];
      imgs.forEach(function (url) { parts.push({ type: 'image_url', image_url: { url: url } }); });
      chatHistory.push({ role: 'user', content: parts });
    } else {
      chatHistory.push({ role: 'user', content: q });
    }
    runLoop();
  }

  /* ── Nén lịch sử trước khi gửi LLM (tiết kiệm token) ────────────────────────
     Kết quả tool là JSON to (read_workflow, docs, schema…). Chúng chỉ cần đầy đủ
     ở vòng NGAY SAU khi chạy; các vòng sau AI đã rút ra kết luận rồi. Nên giữ
     nguyên vẹn 2 kết quả tool gần nhất, các kết quả cũ hơn cắt còn phần đầu.
     Ảnh cũng bị bỏ khỏi lượt CŨ — ảnh tốn token nhất và AI đã mô tả nó ở vòng
     ngay sau đó rồi. Giữ nguyên thứ tự + phần tử system ở đầu để không phá
     prompt-cache của OpenAI (đo được: prefix không đổi → cache 99% prompt). */
  var TOOL_KEEP_FULL = 2, TOOL_OLD_CHARS = 400;
  function packHistory() {
    var toolIdx = [];
    chatHistory.forEach(function (m, i) {
      if (m.role === 'user' && typeof m.content === 'string' && m.content.indexOf('[KẾT QUẢ TOOL') === 0) toolIdx.push(i);
    });
    var keep = toolIdx.slice(-TOOL_KEEP_FULL);
    return chatHistory.map(function (m, i) {
      if (Array.isArray(m.content)) {
        var isLast = i >= chatHistory.length - 2;   // lượt ảnh mới nhất thì giữ ảnh
        if (isLast) return m;
        var txt = m.content.filter(function (c) { return c.type === 'text'; }).map(function (c) { return c.text; }).join(' ');
        return { role: m.role, content: txt + ' [ảnh đã gửi ở lượt trước]' };
      }
      if (toolIdx.indexOf(i) > -1 && keep.indexOf(i) === -1 && m.content.length > TOOL_OLD_CHARS) {
        return { role: m.role, content: m.content.slice(0, TOOL_OLD_CHARS) + '\n…(đã rút gọn để tiết kiệm token)' };
      }
      return m;
    });
  }

  function runLoop() {
    busy = true; send.disabled = true;
    var loops = 0;
    var turnTokens = { prompt: 0, cached: 0, out: 0 };
    var bubble = addMsg('n8m-a', '…');
    step();

    function step() {
      /* Vòng ĐẦU của lượt: AI phải hiểu ý anh Thoại + lên kế hoạch → cho suy nghĩ ('low').
         Các vòng sau: đã có dữ liệu tool trong tay, chỉ cần tiêu hoá và quyết định bước kế
         → 'minimal' (đo thật: 0 reasoning token, 1,4s so với 3,4–4,0s mặc định). */
      var effort = loops === 0 ? 'low' : 'minimal';
      streamLLM(function onDelta(full) { bubble.textContent = full || '…'; msgs.scrollTop = msgs.scrollHeight; }, 1, effort, turnTokens)
        .then(function (full) {
          var tool = parseTool(full);
          chatHistory.push({ role: 'assistant', content: full });
          if (!tool || loops >= MAX_TOOL_LOOPS) {
            if (tool && loops >= MAX_TOOL_LOOPS) note('⚠️ Đã đạt giới hạn số bước tool.');
            finish(); return;
          }
          bubble.textContent = full.replace(/```n8n[\s\S]*?```/g, '').trim() || '⚙️ đang xử lý…';
          loops++;
          execTool(tool).then(function (res) {
            if (MUTATING[tool.tool] && res && res.ok) dirtyWrite = true;
            note((res.__denied ? '⛔ ' : '⚙️ ') + tool.tool + (res.__denied ? ' (bỏ qua)' : ' ✓'));
            chatHistory.push({ role: 'user', content: '[KẾT QUẢ TOOL ' + tool.tool + ']\n' + JSON.stringify(res) });
            bubble = addMsg('n8m-a', '…');
            step();
          });
        })
        .catch(function (e) { bubble.textContent = '⚠️ Lỗi: ' + (e && e.message || e); finish(); });
    }
    function finish() {
      busy = false; send.disabled = false; ta.focus();
      if (turnTokens.prompt || turnTokens.out) {
        var d = document.createElement('div');
        d.className = 'n8-usage'; d.setAttribute('data-transient', '1');
        d.textContent = '⛽ lượt này: ' + turnTokens.prompt + ' token vào'
          + (turnTokens.cached ? ' (' + turnTokens.cached + ' được cache, rẻ hơn ~90%)' : '')
          + ' · ' + turnTokens.out + ' ra · ' + (loops + 1) + ' vòng';
        msgs.appendChild(d); msgs.scrollTop = msgs.scrollHeight;
      }
      if (dirtyWrite) { dirtyWrite = false; offerReload(); }
    }
  }

  function parseTool(text) {
    var m = text.match(/```n8n\s*([\s\S]*?)```/);
    if (!m) return null;
    try { var o = JSON.parse(m[1].trim()); return (o && o.tool && TOOLS[o.tool]) ? o : null; } catch (e) { return null; }
  }

  function execTool(tool) {
    if (MUTATING[tool.tool]) {
      var desc = tool.tool === 'update_node_parameter'
        ? 'Sửa node "' + tool.node_name + '" — tham số "' + tool.param_path + '" = ' + JSON.stringify(tool.value)
        : tool.tool === 'add_nodes'
        ? 'Thêm ' + ((tool.nodes && tool.nodes.length) || 0) + ' node MỚI:\n  ' + (tool.nodes || []).map(function (n) {
            return '- ' + n.name + ' (' + n.type + ')' + (n.connect_from ? ' ← nối từ "' + n.connect_from + '"' : '');
          }).join('\n  ')
        : 'Thêm node MỚI "' + tool.name + '" (' + tool.type + ')' + (tool.connect_from ? ' nối từ "' + tool.connect_from + '"' : '');
      var ok = window.confirm('AI muốn GHI vào workflow thật:\n\n  ' + desc + '\n\n⚠️ Đây là thay đổi automation thật — đồng ý?');
      if (!ok) return Promise.resolve({ __denied: true, message: 'Người dùng từ chối thao tác này.' });
    }
    try { return Promise.resolve(TOOLS[tool.tool](tool)).catch(function (e) { return { ok: false, error: String(e && e.message || e) }; }); }
    catch (e) { return Promise.resolve({ ok: false, error: String(e && e.message || e) }); }
  }

  function streamLLM(onDelta, attempt, effort, tally) {
    attempt = attempt || 1;
    // system LUÔN đứng đầu và KHÔNG BAO GIỜ đổi giữa các vòng → OpenAI tự cache prefix này
    // (đo thật: lần gọi thứ 2 cached 7.936/8.003 token). Đừng chèn gì động vào SYS.
    var body = { model: MODEL, messages: [{ role: 'system', content: SYS }].concat(packHistory()), stream: true };
    if (effort) body.reasoning_effort = effort;
    return fetch(LLM_URL, { method: 'POST', credentials: 'include', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) })
      .then(function (r) {
        // HTTP 524 = Cloudflare Edge timeout (9Router thỉnh thoảng chọn backend chậm phía sau) —
        // KHÔNG phải lỗi cố định, tự thử lại thường ăn ngay vì lần sau có thể trúng backend khác.
        if (r.status === 524 && attempt < 3) {
          onDelta('⏳ 9Router phản hồi chậm (524), đang thử lại (' + (attempt + 1) + '/3)…');
          return streamLLM(onDelta, attempt + 1, effort, tally);
        }
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
                // 9Router phát 2 khối usage: 1 bản "estimated" của nó, 1 bản THẬT của OpenAI
                // (nhận ra nhờ có prompt_tokens_details). Chỉ cộng bản thật để số liệu đúng.
                if (tally && jj.usage && jj.usage.prompt_tokens_details) {
                  tally.prompt += jj.usage.prompt_tokens || 0;
                  tally.out += jj.usage.completion_tokens || 0;
                  tally.cached += (jj.usage.prompt_tokens_details.cached_tokens) || 0;
                }
              } catch (e) { /* chunk lẻ */ }
            }
            return pump();
          });
        })();
      });
  }
})();
