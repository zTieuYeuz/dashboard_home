/* ═══════════════════════════════════════════════════════════════════
   PNETLab bridge — AI ĐỌC & ĐIỀU KHIỂN lab qua tài khoản riêng "ai-agent"
   -------------------------------------------------------------------
   Vì sao account riêng: PNETLab chỉ cho 1 PHIÊN mỗi tài khoản. Nếu AI dùng
   chung account admin của anh Thoai → anh bị đá ra mỗi lần AI đọc. Account
   ai-agent (role admin) do anh tạo trong PNETLab; mật khẩu để ở Cloudflare
   secret PNETLAB_PASS (không hardcode).

   Worker chạy ở EDGE → không với tới LAN IP 192.168.110.16. Phải gọi qua
   tunnel công khai pnetlab.home-server.id.vn (đã xác minh login + API OK).

   Contract API đã dò & xác minh (2026-07-23):
     POST /store/public/auth/login/login  {username,password,offline,captcha}
          + header X-XSRF-TOKEN (lấy từ cookie XSRF-TOKEN) → 202 {result:true}
     GET  /api/auth?lang=                       → thông tin user
     GET  /api/folders            (?path=/X)    → folders[] + labs[]
     POST /api/labs/session/factory/create {path:"/CCNA/lab.unl"}  → bind lab
     GET  /api/labs/session/nodes               → nodes (envelope {code,data})
     GET  /api/labs/session/networks            → networks
     GET  /api/labs/session/configs/{id}        → startup config 1 node
     POST /api/labs/session/nodes/start   form  id=N   → start node (form-urlencoded!)
     POST /api/labs/session/nodes/stop    form  id=N   → stop node
     POST /api/labs/session/nodes/export  form  id=N   → export config (rỗng = tất cả)
     POST /api/labs/session/configs/edit  form  id=N&data=... → push startup config

   Quyền: gác ở tầng reads.js/actions.js bằng key 'hub-pnetlab'. User không
   có quyền thì AI cũng bị chặn 403 (giống mọi nguồn khác).
   ═══════════════════════════════════════════════════════════════════ */
import { json, getSession, hasPerm, cleanEnv, bridgeWebSocket } from './core.js';

const PNET = 'https://pnetlab.home-server.id.vn';
const SKEY = 'pnetlab:aisess';   // KV cache phiên ai-agent
const STTL = 1800;               // 30 phút

/* ── Cookie helpers (Workers không có cookie jar, tự quản) ── */
function jarFrom(resp, prev) {
  const jar = Object.assign({}, prev || {});
  let list = [];
  try { list = resp.headers.getSetCookie(); } catch { const h = resp.headers.get('set-cookie'); if (h) list = [h]; }
  for (const sc of list) {
    const first = String(sc).split(';')[0];
    const i = first.indexOf('=');
    if (i > 0) jar[first.slice(0, i).trim()] = first.slice(i + 1).trim();
  }
  return jar;
}
function cookieStr(jar) { return Object.entries(jar).map(([k, v]) => k + '=' + v).join('; '); }
function xsrfOf(jar) { const t = jar['XSRF-TOKEN'] || ''; try { return decodeURIComponent(t); } catch { return t; } }

/* ── Đăng nhập tươi, trả {cookie, xsrf} ── */
async function freshLogin(env) {
  const user = env.PNETLAB_USER || 'ai-agent';
  const pass = env.PNETLAB_PASS;
  if (!pass) throw new Error('Chưa cấu hình PNETLAB_PASS (chạy: wrangler secret put PNETLAB_PASS). AI chưa thể truy cập PNETLab.');

  // 1. Seed cookie phiên + XSRF-TOKEN
  let r = await fetch(PNET + '/store/public/auth/login/offline', { headers: { 'User-Agent': 'HomeLabDashboard/1.0' } });
  let jar = jarFrom(r);

  // 2. Login (Laravel cần X-XSRF-TOKEN khớp cookie)
  r = await fetch(PNET + '/store/public/auth/login/login', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-XSRF-TOKEN': xsrfOf(jar),
      'X-Requested-With': 'XMLHttpRequest',
      'Cookie': cookieStr(jar),
    },
    body: JSON.stringify({ username: user, password: pass, offline: true, captcha: '' }),
  });
  jar = jarFrom(r, jar);
  let d = null; try { d = await r.json(); } catch { /* non-json */ }
  if (!(d && d.result)) throw new Error('Đăng nhập PNETLab thất bại (HTTP ' + r.status + '). Kiểm tra account ai-agent + PNETLAB_PASS.');

  return { cookie: cookieStr(jar), xsrf: xsrfOf(jar) };
}

/* ── Lấy phiên (cache KV, tự login nếu chưa có) ── */
async function getSess(env, force) {
  if (!force) {
    const c = await env.DASHBOARD_KV.get(SKEY, 'json');
    if (c && c.cookie) return c;
  }
  const s = await freshLogin(env);
  await env.DASHBOARD_KV.put(SKEY, JSON.stringify(s), { expirationTtl: STTL });
  return s;
}

/* ── Gọi API (tự re-login 1 lần khi phiên hết hạn) ──
   opts.form = object → gửi application/x-www-form-urlencoded (giống jQuery frontend)
   opts.json = object → gửi application/json */
async function api(env, method, path, opts) {
  opts = opts || {};
  const build = (s) => {
    const h = { 'Cookie': s.cookie, 'X-XSRF-TOKEN': s.xsrf, 'X-Requested-With': 'XMLHttpRequest' };
    let body;
    if (opts.form) { h['Content-Type'] = 'application/x-www-form-urlencoded'; body = new URLSearchParams(opts.form).toString(); }
    else if (opts.json !== undefined) { h['Content-Type'] = 'application/json'; body = JSON.stringify(opts.json); }
    return fetch(PNET + path, { method, headers: h, body });
  };

  let s = await getSess(env);
  let r = await build(s);
  let d = null; try { d = await r.clone().json(); } catch { /* non-json */ }

  const expired = r.status === 401 || r.status === 419 || (d && (d.code === 90001 || d.code === 90003));
  if (expired) {
    s = await getSess(env, true);   // force login mới
    r = await build(s);
    d = null; try { d = await r.clone().json(); } catch { /* non-json */ }
  }
  return { status: r.status, data: d };
}

/* ── Chuẩn hoá đường dẫn lab: "/CCNA/lab1" → "/CCNA/lab1.unl" ── */
function normLab(p) {
  p = String(p || '').trim();
  if (!p) return '';
  if (!p.startsWith('/')) p = '/' + p;
  if (!/\.unl$/i.test(p)) p = p + '.unl';
  return p;
}

/* ── Bind lab vào phiên (mọi thao tác cần lab phải gọi trước) ── */
async function ensureLab(env, labPath) {
  const lab = normLab(labPath);
  if (!lab) throw new Error('Thiếu đường dẫn lab. Ví dụ: /CCNA/ten-lab.unl (dùng nguồn pnetlab_labs để lấy danh sách).');
  const r = await api(env, 'POST', '/api/labs/session/factory/create', { json: { path: lab } });
  if (r.status !== 200) {
    const msg = (r.data && r.data.message) || ('HTTP ' + r.status);
    throw new Error('Không mở được lab "' + lab + '": ' + msg);
  }
  return lab;
}

/* Lấy mảng dữ liệu từ envelope {code,status,data} */
function arrData(r) { return (r.data && r.data.data) || []; }

/* ═══════════════ READS (trả Response qua json()) ═══════════════ */

/* Danh sách folder + lab (gốc, và drill 1 cấp vào từng folder con). */
export async function pnetReadLabs(env) {
  const root = await api(env, 'GET', '/api/folders');
  if (root.status !== 200) return json({ error: 'Không đọc được danh sách lab (HTTP ' + root.status + ')' }, 502);
  const rd = root.data && root.data.data || {};
  const folders = [];
  for (const f of (rd.folders || [])) {
    if (!f.path || f.name === '..') continue;
    let labs = [];
    try {
      const sub = await api(env, 'GET', '/api/folders?path=' + encodeURIComponent(f.path));
      if (sub.status === 200) {
        const sd = sub.data && sub.data.data || {};
        labs = (sd.labs || []).map(l => ({ name: l.name || l.file, path: l.path || (f.path + '/' + (l.file || l.name)) }));
      }
    } catch { /* folder không drill được → chỉ trả tên folder */ }
    folders.push({ name: f.name, path: f.path, labs });
  }
  const rootLabs = (rd.labs || []).map(l => ({ name: l.name || l.file, path: l.path || ('/' + (l.file || l.name)) }));
  return json({ folders, rootLabs, note: 'Dùng "path" của lab để đọc topology/config hoặc điều khiển node.' });
}

/* Topology 1 lab: nodes (id, tên, template, trạng thái) + networks (kết nối). */
export async function pnetReadTopology(env, params) {
  const lab = await ensureLab(env, params && params.lab);
  const nodesR = await api(env, 'GET', '/api/labs/session/nodes');
  const netsR = await api(env, 'GET', '/api/labs/session/networks');
  const nodesRaw = arrData(nodesR);
  // PNETLab trả nodes dạng object {id:{...}} hoặc mảng — chuẩn hoá về mảng gọn cho AI
  const nodes = (Array.isArray(nodesRaw) ? nodesRaw : Object.entries(nodesRaw).map(([id, n]) => Object.assign({ id }, n)))
    .map(n => ({ id: n.id, name: n.name, template: n.template || n.type, status: n.status, statusText: _nodeStatus(n.status) }));
  return json({ lab, node_count: nodes.length, nodes, networks: arrData(netsR) });
}

function _nodeStatus(s) { return ({ 0: 'stopped', 1: 'building', 2: 'building', 3: 'running' })[s] || String(s); }

/* Startup config của 1 node. */
export async function pnetReadNodeConfig(env, params) {
  const lab = await ensureLab(env, params && params.lab);
  const id = parseInt(params && params.node_id, 10);
  if (!Number.isInteger(id)) return json({ error: 'Thiếu node_id (số nguyên). Dùng pnetlab_topology để lấy id node.' }, 400);
  const r = await api(env, 'GET', '/api/labs/session/configs/' + id);
  if (r.status !== 200) return json({ error: 'Không đọc được config node ' + id + ' (HTTP ' + r.status + '). Node có thể chưa bật hoặc chưa có startup config.' }, 502);
  const d = r.data && r.data.data;
  const cfg = (d && typeof d === 'object') ? (d.data || '') : (d || '');
  return json({ lab, node_id: id, config: cfg });
}

/* ═══════════════ ACTIONS (trả Response qua json()) ═══════════════ */

export async function pnetStartNode(env, params) {
  const lab = await ensureLab(env, params && params.lab);
  const id = parseInt(params && params.node_id, 10);
  if (!Number.isInteger(id)) return json({ ok: false, error: 'Thiếu node_id' }, 400);
  const r = await api(env, 'POST', '/api/labs/session/nodes/start', { form: { id } });
  const ok = r.status === 200 && r.data && r.data.status === 'success';
  return json({ ok, lab, node_id: id, message: (r.data && r.data.message) || ('HTTP ' + r.status) });
}

export async function pnetStopNode(env, params) {
  const lab = await ensureLab(env, params && params.lab);
  const id = parseInt(params && params.node_id, 10);
  if (!Number.isInteger(id)) return json({ ok: false, error: 'Thiếu node_id' }, 400);
  const r = await api(env, 'POST', '/api/labs/session/nodes/stop', { form: { id } });
  const ok = r.status === 200 && r.data && r.data.status === 'success';
  return json({ ok, lab, node_id: id, message: (r.data && r.data.message) || ('HTTP ' + r.status) });
}

/* Export config: node_id rỗng = export TẤT CẢ node (tương đương write mem). */
export async function pnetExportConfig(env, params) {
  const lab = await ensureLab(env, params && params.lab);
  const form = {};
  const id = parseInt(params && params.node_id, 10);
  if (Number.isInteger(id)) form.id = id;
  const r = await api(env, 'POST', '/api/labs/session/nodes/export', { form });
  const ok = r.status === 200 && r.data && r.data.status === 'success';
  return json({ ok, lab, scope: Number.isInteger(id) ? ('node ' + id) : 'tất cả node', message: (r.data && r.data.message) || ('HTTP ' + r.status) });
}

/* ĐÃ GỠ (2026-07-24): pnetPushConfig / POST /api/labs/session/configs/edit — xác nhận bằng
   thực nghiệm (đọc thẳng file .unl trên server sau khi gọi) rằng API này trả "success" nhưng
   KHÔNG ghi vào lab thật (config_data không đổi), thử cả node chạy/dừng, plain text/base64.
   Cách duy nhất đáng tin để lưu config: gõ lệnh vào console + "write memory" trên thiết bị,
   rồi gọi pnetExportConfig (đọc NVRAM live → ghi vào lab) — đây là cơ chế PNETLab thật sự dùng. */

/* ═══════════════════════════════════════════════════════════════════
   PROXY 9Router cho nút 🤖 nhúng TRONG PNETLab (pnet-assistant.js)
   -------------------------------------------------------------------
   [2026-07-27] MIGRATE sang gác bằng SESSION DASHBOARD — trước đây PNETLab
   nhúng bằng iframe KHÁC ORIGIN nên trình duyệt không gửi cookie `dh_session`,
   phải chặn tạm bằng Origin-header + secret `X-Pnet-Key` (giả mạo Origin được
   bằng curl, X-Pnet-Key phải tự tay chèn vào default.js trên VM PNETLab, mất
   mỗi khi PNETLab update). Giờ PNETLab được phục vụ qua `handlePnetlabHomeProxy`
   CÙNG ORIGIN với dashboard (`/proxy/pnetlab-home/...`) → cookie session tự
   động gửi kèm → gác bằng `hasPerm('hub-pnetlab')` như mọi route khác, mạnh
   hơn nhiều và không cần secret/sửa file gì trên VM PNETLab nữa.
   ═══════════════════════════════════════════════════════════════════ */
const NINE_ROUTER = 'https://9router.home-server.id.vn/v1/chat/completions';
// [2026-07-25] 9Router chuyển từ instance root → administrator: MỖI tính năng giờ có
// alias + secret RIÊNG (trước đây dùng chung NINE_ROUTER_KEY + allowlist 2 tên) — tránh
// 1 key hỏng làm chết cả 3 tính năng, và anh dễ theo dõi/thu hồi riêng từng cái.
const LLM_MODELS = new Set(['pnetlab']);
const LLM_RL_MAX = 60;                                  // request / 5 phút / user

export async function handlePnetLlm(request, env) {
  if (request.method !== 'POST') return json({ error: 'method' }, 405);
  const session = await getSession(request, env);
  if (!session) return json({ error: 'Chưa đăng nhập' }, 401);
  if (!(await hasPerm(env, session, 'hub-pnetlab'))) return json({ error: 'Không có quyền PNETLab' }, 403);

  const key = env.PNETLAB_9ROUTER_KEY;
  if (!key) return json({ error: 'Chưa cấu hình PNETLAB_9ROUTER_KEY (wrangler secret put PNETLAB_9ROUTER_KEY).' }, 503);

  // Rate-limit theo user (KV, cửa sổ 5 phút) — trước đây theo IP vì không có session
  const rlKey = 'pnetllm:rl:' + session.username;
  const cnt = parseInt((await env.DASHBOARD_KV.get(rlKey)) || '0', 10);
  if (cnt >= LLM_RL_MAX) return json({ error: 'Quá nhiều yêu cầu, thử lại sau ít phút.' }, 429);
  await env.DASHBOARD_KV.put(rlKey, String(cnt + 1), { expirationTtl: 300 });

  let body; try { body = await request.json(); } catch { return json({ error: 'bad json' }, 400); }
  const model = LLM_MODELS.has(body.model) ? body.model : 'pnetlab';
  const payload = Object.assign({}, body, { model, stream: true });

  let upstream;
  try {
    upstream = await fetch(NINE_ROUTER, {
      method: 'POST',
      headers: { 'Authorization': 'Bearer ' + key, 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
  /* `j(...)` (chép nhầm từ bản console-serial nơi có alias tên j) → ReferenceError thật:
     hàm này dùng json(...) ở mọi chỗ khác. Chỉ lộ khi 9Router chết, mà đúng lúc đó lẽ ra
     phải trả 502 nói rõ lý do thì Worker lại ném lỗi → 500 vô nghĩa. Sửa 2026-08-15. */
  } catch (e) { return json({ error: '9Router không phản hồi: ' + ((e && e.message) || e) }, 502); }

  // Stream thẳng SSE về browser (same-origin, không cần CORS nữa)
  return new Response(upstream.body, {
    status: upstream.status,
    headers: { 'Content-Type': 'text/event-stream; charset=utf-8', 'Cache-Control': 'no-cache' },
  });
}

/* ═══════════════════════════════════════════════════════════════════
   PROXY console-bridge — AI GÕ LỆNH THẬT vào console node (Phase 3, 2026-07-24)
   -------------------------------------------------------------------
   Vì sao cần: đã xác nhận configs/edit KHÔNG ghi được config qua API (xem
   comment phía trên) — cách duy nhất để cấu hình node là gõ lệnh console.
   console-bridge (_ops/pnetlab-console-bridge.py) chạy trên VM PNETLab,
   telnet THẲNG vào cổng console nội bộ của node (né Guacamole/WebSocket
   hoàn toàn — thứ đã lỗi cả ngày qua tunnel). Worker gắn secret
   PNET_CONSOLE_SECRET (ẩn khỏi browser) rồi forward tới route tunnel RIÊNG
   của console-bridge (PNET_CONSOLE_URL) — hạ tầng này KHÔNG đổi.
   [2026-07-27] Chỉ đổi CÁCH GÁC route này — session dashboard thay vì
   Origin+X-Pnet-Key, cùng lý do đã giải thích ở handlePnetLlm phía trên. */
const CONSOLE_RL_MAX = 30;   // request / 5 phút / user — thao tác console nặng hơn chat

export async function handlePnetConsole(request, env) {
  if (request.method !== 'POST') return json({ error: 'method' }, 405);
  const session = await getSession(request, env);
  if (!session) return json({ error: 'Chưa đăng nhập' }, 401);
  if (!(await hasPerm(env, session, 'hub-pnetlab'))) return json({ error: 'Không có quyền PNETLab' }, 403);

  const bridgeUrl = env.PNET_CONSOLE_URL;      // vd https://pnetlab-console.home-server.id.vn/exec
  const secret = env.PNET_CONSOLE_SECRET;
  if (!bridgeUrl || !secret) return json({ error: 'Chưa cấu hình PNET_CONSOLE_URL/PNET_CONSOLE_SECRET (wrangler secret put).' }, 503);

  const rlKey = 'pnetcon:rl:' + session.username;
  const cnt = parseInt((await env.DASHBOARD_KV.get(rlKey)) || '0', 10);
  if (cnt >= CONSOLE_RL_MAX) return json({ error: 'Quá nhiều yêu cầu console, thử lại sau ít phút.' }, 429);
  await env.DASHBOARD_KV.put(rlKey, String(cnt + 1), { expirationTtl: 300 });

  let body; try { body = await request.json(); } catch { return json({ error: 'bad json' }, 400); }
  const port = parseInt(body.port, 10);
  const commands = Array.isArray(body.commands) ? body.commands.filter(c => typeof c === 'string').slice(0, 40) : [];
  if (!Number.isInteger(port)) return json({ error: 'Thiếu port (số nguyên, port console của node)' }, 400);
  if (!commands.length) return json({ error: 'Thiếu commands (mảng chuỗi lệnh)' }, 400);

  let upstream;
  try {
    upstream = await fetch(bridgeUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Bridge-Secret': secret },
      body: JSON.stringify({ port, commands }),
    });
  } catch (e) { return json({ error: 'console-bridge không phản hồi: ' + ((e && e.message) || e) }, 502); }

  let data; try { data = await upstream.json(); } catch { data = { ok: false, error: 'console-bridge trả dữ liệu không hợp lệ' }; }
  return json(data, upstream.status);
}

/* ═══════════════════════════════════════════════════════════════════
   REVERSE-PROXY trang web PNETLab qua dashboard (2026-07-27)
   -------------------------------------------------------------------
   VÌ SAO: trước đây PNETLab nhúng bằng iframe TRỎ THẲNG sang domain thật
   (`https://pnetlab.home-server.id.vn/...`) — domain đó KHÔNG có Cloudflare
   Access, ai biết link là vào thẳng được, không cần qua dashboard. Anh Thoại
   muốn bắt buộc mọi người đăng nhập qua dashboard — đúng mô hình đã áp dụng
   cho Termix/Camera Home: đặt Cloudflare Access lên domain PNETLab, Worker
   này cầm Service Token (PNETLAB_HOME_CF_CLIENT_ID/_SECRET) để vượt qua thay
   mặt user ĐÃ đăng nhập dashboard; ai gõ thẳng link đó (không qua dashboard)
   sẽ bị chính Cloudflare Access chặn ở edge.

   LỢI ÍCH PHỤ: vì giờ PNETLab chạy CÙNG ORIGIN với dashboard, cookie session
   `dh_session` tự động gửi kèm mọi request trong iframe → handlePnetLlm/
   handlePnetConsole ở trên gác được bằng session thật (đã migrate) → KHÔNG
   còn cần khoá PNET_AI_KEY hay phải tự tay sửa default.js trên VM PNETLab để
   gán window.__PNET_AI_KEY__ — script trợ lý AI được TỰ ĐỘNG tiêm vào đây
   (giống hệt cách handleN8nHomeProxy đang làm cho n8n), sống sót qua các lần
   PNETLab tự update (không như default.js bị ghi đè mất loader).

   PHẠM VI TỐI THIỂU CÓ CHỦ Ý: KHÔNG proxy WebSocket cho web UI. Guacamole/
   WebSocket của PNETLab qua tunnel đã có tiền sử lỗi nặng (xem comment
   console-bridge phía trên, "đã lỗi cả ngày qua tunnel") — console CLI đã né
   hẳn bằng console-bridge riêng (telnet thô). Nếu sau test thật phát hiện
   trang PNETLab cần WebSocket cho tính năng khác (chưa có bằng chứng), bổ
   sung sau theo đúng pattern đã kiểm chứng ở handleTermixProxy (src/termix.js). */
const PNETLAB_HOME_ORIGIN = 'https://pnetlab.home-server.id.vn';
const PNETLAB_HOME_BASE = '/proxy/pnetlab-home';

/* ⚠️ BÀI HỌC LỚN (2026-07-27) — VÌ SAO PHẢI GIỮ NGUYÊN PATH GỐC `/store/*`, `/themes/*`
   -------------------------------------------------------------------
   Lần đầu viết proxy này em phục vụ PNETLab dưới prefix `/proxy/pnetlab-home/...` (giống
   Termix/n8n) → TRẮNG TRANG HOÀN TOÀN. Đọc thẳng bundle React của PNETLab
   (`/store/public/react/js/app.js`) mới thấy nguyên nhân thật: PNETLab KHÔNG phải app
   jQuery+Blade thuần như em tưởng — nó là SPA react-router v4, và route được khai báo
   HARDCODE đúng 1 dòng:
       path:"/store/public/:folder/:page/:func"
   Router match `window.location.pathname` với pattern đó. Thêm bất kỳ prefix nào vào
   pathname → không route nào khớp → React render rỗng → `<div id="app">` trắng bóc.
   Không có `basename` để cấu hình (chỉ khai báo propTypes, không truyền giá trị), nên
   KHÔNG thể sửa từ phía proxy bằng cách rewrite URL — rewrite bao nhiêu cũng vô ích vì
   vấn đề nằm ở pathname của CHÍNH TRANG, không phải ở các URL bên trong trang.

   → Giải pháp: phục vụ PNETLab tại ĐÚNG path gốc `/store/*` và `/themes/*` trên dashboard
   (đã kiểm tra: dashboard không dùng 2 namespace này cho bất cứ thứ gì). Khi đó pathname
   y hệt bản gốc → router khớp hoàn hảo, và toàn bộ asset dưới `/store/...` tự đúng đường
   mà không cần rewrite gì cả.

   Ngoại lệ DUY NHẤT: `/api/*` — PNETLab gọi `/api/labs`, `/api/auth/logout`... TRÙNG
   namespace API của dashboard, không thể phục vụ trực tiếp. Những cái này (và chỉ những
   cái này) được rewrite sang `/proxy/pnetlab-home/api/*` bằng JS patch + HTML rewrite.
   React Router không quan tâm URL của API call, nên đổi chúng hoàn toàn an toàn. */
/* Danh sách namespace gốc phục vụ NGUYÊN path (không thêm prefix).
   Rà từ chính các bundle của PNETLab (app.js, chunk react, mainCtrl.js, default.js):
     /store   — toàn bộ app + asset chính
     /themes  — CSS/JS giao diện (adminLTE, jsPlumb, unetlab.css)
     /legacy  — trang topology cũ; mở 1 bài lab là `window.location.href="/legacy/topology"`
     /images   — icon thiết bị trên sơ đồ (`/images/icons/…`, `/images/vendor/…`) VÀ icon loại
                node ngay tại gốc (`/images/wireshark.png`, `/images/router.png`...) — cái sau
                do JS nối chuỗi động (`'/images/'+type+'.png'`) nên không lộ ra khi grep chuỗi
                tĩnh trong bundle, chỉ phát hiện được qua Console thật (404 khi thiếu). Ban đầu
                em khai hẹp `/images/icons` + `/images/vendor`, phải mở rộng thành cả nhánh
                `/images` sau khi thấy 404 icon loại node trên production.
     /fonts/vendor  — font primereact/primeicons trong bundle React
     /html5   — console Guacamole (mở Terminal trên node); asset bên trong dùng path TƯƠNG ĐỐI
                (`webjars/…`, `app.css`) nên tự resolve đúng khi giữ nguyên base /html5/
   ⚠️ TUYỆT ĐỐI KHÔNG thêm `/auth`: dashboard đang dùng `/auth/microsoft*` cho SSO. Trong bundle
   PNETLab, `/auth/...` chỉ xuất hiện kèm `APP_CENTER` (user.pnetlab.com) — link ra ngoài, không
   phải path nội bộ.
   ⚠️ `/fonts` để NGUYÊN CẢ NHÁNH thì sẽ CƯỚP của n8n: `worker.js` có route fallback asset n8n
   bắt `/assets/ /static/ /icons/ /fonts/ /rest/ /push/ /webhook/ /types/ /templates/`. Đã rà:
   PNETLab chỉ dùng `/fonts/vendor/...` nên khai báo hẹp tới nhánh con — cùng lý do, đừng mở
   rộng thành `/fonts`. `/images` KHÔNG nằm trong danh sách fallback n8n nên mở cả nhánh an toàn
   (đã kiểm tra: dashboard không dùng `/images` cho bất cứ gì). */
const PNETLAB_PASSTHRU = ['/store', '/themes', '/legacy', '/html5', '/images', '/fonts/vendor'];

/* ⚠️ Bug thật đã gặp: webpack (bundle React) đặt tên CHUNK DÙNG CHUNG nhiều trang kiểu
   `vendors~./store/public/react/pages/admin-Lab_sessionsView-js~...~<hash>` — publicPath là "/"
   nên URL request thực tế là `/vendors~./store/...js`, path này KHÔNG bắt đầu bằng "/store/" (dù
   chứa chuỗi đó ở giữa) nên lọt khỏi mọi passthru ở trên → 404 → `ChunkLoadError`, hiện rõ nhất khi
   bấm vào 1 lab ĐANG CHẠY (cần chunk "admin-Lab_sessionsView"). Các chunk RIÊNG từng trang thì tên
   bắt đầu bằng "./" (vd "./store/public/react/pages/admin-LabsCreate-js") — "./" tự chuẩn hoá mất
   khi ghép URL nên vô tình rơi đúng vào /store/, KHÔNG cần xử lý riêng; chỉ chunk DÙNG CHUNG
   ("vendors~...") mới lọt lưới. Khớp bằng PREFIX thô (không cần dấu "/" theo sau như các mục trên,
   vì ký tự kế tiếp luôn là "." của tên chunk, không phải path segment mới) — khác `public/vendor/`
   (số ít, có dấu "/") của Termix nên không đụng nhau. */
const PNETLAB_PASSTHRU_PREFIX = ['/vendors~'];

/* Chuẩn hoá 1 URL/path bất kỳ trong HTML hoặc header về đường đi đúng trên dashboard:
   - bỏ origin PNETLab (kể cả bản URL-encode trong query param như `link=https%3A%2F%2F...`)
   - path bare "/" → PNETLab tự coi đây là TRANG CHỦ CỦA CHÍNH NÓ (đã gặp thật ở nhiều nút/link
     khác nhau — "close lab" tự redirect, nút "Main" trên thanh admin...); "/" trong ngữ cảnh
     proxy này lại là trang chủ DASHBOARD (chưa từng bypass Cloudflare Access) → đưa thẳng về
     ĐÚNG trang chủ THẬT của PNETLab thay vì để nó thoát ra ngoài
   - path thuộc PNETLAB_PASSTHRU  → giữ nguyên (router cần đúng pathname)
   - path khác (chủ yếu /api/...) → thêm prefix /proxy/pnetlab-home */
const PNETLAB_HOME_ENTRY = '/store/public/admin/main/view';
function pnetPath(path) {
  if (!path || path.charAt(0) !== '/') return path;
  if (path === '/') return PNETLAB_HOME_ENTRY;
  if (path.indexOf(PNETLAB_HOME_BASE) === 0) return path;
  if (PNETLAB_PASSTHRU.some(p => path === p || path.indexOf(p + '/') === 0)) return path;
  if (PNETLAB_PASSTHRU_PREFIX.some(p => path.indexOf(p) === 0)) return path;
  return PNETLAB_HOME_BASE + path;
}
function rewriteUrlLike(str) {
  if (!str) return str;
  let out = str;

  // (1) Dạng URL-encode nằm trong query param — vd `?link=https%3A%2F%2Fpnetlab...%2Fstore%2F...`
  // PNETLab dùng param này để biết đưa trình duyệt về đâu sau khi đăng nhập xong; bỏ sót nó
  // thì đăng nhập xong sẽ bị đẩy thẳng ra domain gốc (đã bị Cloudflare Access chặn).
  const encOrigin = encodeURIComponent(PNETLAB_HOME_ORIGIN);
  if (out.indexOf(encOrigin) !== -1) {
    out = out.split(encOrigin).map((seg, i) => {
      if (i === 0) return seg;
      const m = seg.match(/^(?:%2F|%2f)[^&#]*/);
      if (!m) return seg;
      let decoded; try { decoded = decodeURIComponent(m[0]); } catch { return seg; }
      return encodeURIComponent(pnetPath(decoded)) + seg.slice(m[0].length);
    }).join('');
  }

  // (2) Dạng thô `https://pnetlab.home-server.id.vn/...` — cắt origin, định tuyến lại phần path.
  out = out.split(PNETLAB_HOME_ORIGIN).map((seg, i) => {
    if (i === 0) return seg;
    const m = seg.match(/^\/[^?#"'\s]*/);
    if (!m) return seg;
    return pnetPath(m[0]) + seg.slice(m[0].length);
  }).join('');

  return out;
}

export async function handlePnetlabHomeProxy(request, env) {
  const session = await getSession(request, env);
  if (!session) return new Response('Unauthorized', { status: 401 });
  if (!(await hasPerm(env, session, 'hub-pnetlab'))) return new Response('Forbidden', { status: 403 });

  // Handler này nhận 2 kiểu đường vào:
  //   /store/... , /themes/...        → path GỐC của PNETLab, gửi lên upstream y nguyên
  //   /proxy/pnetlab-home/api/...     → path có prefix (chỉ dùng cho /api/* vì trùng dashboard)
  const reqUrl  = new URL(request.url);
  const subPath = reqUrl.pathname.indexOf(PNETLAB_HOME_BASE) === 0
    ? (reqUrl.pathname.slice(PNETLAB_HOME_BASE.length) || '/')
    : reqUrl.pathname;
  const target  = `${PNETLAB_HOME_ORIGIN}${subPath}${reqUrl.search}`;

  const clientId     = cleanEnv(env.PNETLAB_HOME_CF_CLIENT_ID);
  const clientSecret = cleanEnv(env.PNETLAB_HOME_CF_CLIENT_SECRET);

  /* ── WebSocket proxy — console Guacamole (/html5/…) của PNETLab ──
     Ban đầu route này cố tình trả 501 ("phạm vi tối thiểu"), nhưng thực tế mở Terminal trên
     node trong topology là bật hẳn Guacamole HTML5 → BẮT BUỘC phải có WebSocket, không có thì
     cửa sổ Terminal trắng bóc. Dùng ĐÚNG mẫu đã chạy ổn định ở handleTermixProxy
     (src/termix.js) — mẫu đó vốn cũng viết cho Guacamole nên khớp hoàn toàn:
       • fetch tới `https://…` (KHÔNG dùng scheme wss://) và CHỈ set Upgrade — Connection/
         Sec-WebSocket-Version do Workers tự quản; tự set tay là `response.webSocket` = null.
       • ép Origin = origin PNETLab để Guacamole không từ chối vì cross-origin.
       • chuyển tiếp Sec-WebSocket-Protocol (Guacamole yêu cầu subprotocol 'guacamole') và
         echo lại trong response 101. */
  if (request.headers.get('Upgrade')?.toLowerCase() === 'websocket') {
    const wsHeaders = new Headers();
    wsHeaders.set('Upgrade', 'websocket');
    wsHeaders.set('Host', new URL(PNETLAB_HOME_ORIGIN).hostname);
    wsHeaders.set('Origin', PNETLAB_HOME_ORIGIN);
    if (clientId && clientSecret) {
      wsHeaders.set('CF-Access-Client-Id',     clientId);
      wsHeaders.set('CF-Access-Client-Secret', clientSecret);
    }
    const wsCookie = (request.headers.get('cookie') || '').split(';').map(c => c.trim())
      .filter(c => c && !c.startsWith('dh_session=') && !c.startsWith('dh_user='))
      .join('; ');
    if (wsCookie) wsHeaders.set('Cookie', wsCookie);
    const swp = request.headers.get('Sec-WebSocket-Protocol');
    if (swp) wsHeaders.set('Sec-WebSocket-Protocol', swp);

    let upResp;
    try { upResp = await fetch(target, { headers: wsHeaders }); }
    catch (e) { return new Response('PNETLab WS error: ' + e.message, { status: 502 }); }

    const upSock = upResp.webSocket;
    if (!upSock) {
      const body = await upResp.text().catch(() => '(no body)');
      return new Response(
        'PNETLab WS: upstream không nâng cấp được (HTTP ' + upResp.status + ') — ' + body.slice(0, 500),
        { status: 502 }
      );
    }

    const { 0: client, 1: server } = new WebSocketPair();
    server.accept();
    upSock.accept();

    /* Nối 2 chiều bằng helper dùng chung (src/core.js), bật log chẩn đoán qua tag 'pnet-ws'
       — vẫn xem được bằng `wrangler tail` y như trước (rớt chiều nào, sau bao lâu, do send()
       lỗi thật hay đầu kia tự đóng).

       ⚠️ SỬA 2026-08-09 — bản vá 'error' thêm hồi 2026-07-30 ở đây KHÔNG BAO GIỜ CHẠY: nó gọi
       close(1011,…) mà 1011 là mã BỊ CẤM truyền vào close() (chỉ nhận 1000 hoặc 3000–4999) →
       ném lỗi → `catch {}` nuốt sạch → phiên Guacamole vẫn không được giải phóng đúng như
       triệu chứng cũ. Nhánh 'close' còn tệ hơn: rớt bất thường là code 1006, cũng bị cấm y vậy.
       bridgeWebSocket() quy mọi mã lạ về 1000 nên lệnh đóng mới thật sự chạy. */
    /* keepAlive (thêm 2026-08-17): Cloudflare cắt WebSocket KHÔNG có lưu lượng sau khoảng
       100 giây. Console lab rất hay im lặng lâu — gõ một lệnh rồi ngồi đọc output, hoặc để
       đó chạy ping/debug rồi quay đi làm việc khác. Im lặng đủ lâu là CF đóng, mà kiểu đứt
       này KHÔNG sinh lỗi nào ở tab Network và chữ trên màn hình vẫn còn nguyên → nhìn hệt
       như "treo", phải bấm reconnect. Khớp với mô tả của anh Thoại: cỡ 20–45 phút một lần.

       '3.nop;' là lệnh "không làm gì" do CHÍNH giao thức Guacamole định nghĩa để giữ kết nối
       — không phải mẹo tự chế. Chỉ gửi VỀ PHÍA TRÌNH DUYỆT, không đẩy ngược lên guacd.
       Gác theo subprotocol để nếu sau này PNETLab có WebSocket khác (không phải Guacamole)
       thì tuyệt đối không bị chèn gói lạ vào. Xem chú thích đầy đủ ở bridgeWebSocket(). */
    const _laGuac = /guacamole/i.test(swp || '');
    bridgeWebSocket(server, upSock, {
      tag: 'pnet-ws',
      keepAlive: _laGuac ? { ms: 45000, data: '3.nop;' } : null,
    });

    const wsRespHeaders = new Headers();
    const echoSwp = upResp.headers.get('Sec-WebSocket-Protocol') || swp;
    if (echoSwp) wsRespHeaders.set('Sec-WebSocket-Protocol', echoSwp);
    return new Response(null, { status: 101, webSocket: client, headers: wsRespHeaders });
  }

  const fwdHeaders = {};
  for (const [k, v] of request.headers) {
    const kl = k.toLowerCase();
    // Bỏ accept-encoding: để upstream trả body KHÔNG nén, tránh trường hợp stream body nén được
    // chuyển thẳng về browser trong khi header content-encoding đã bị gỡ bên dưới → body hỏng.
    if (['host', 'cf-connecting-ip', 'x-forwarded-for', 'cookie', 'accept-encoding'].includes(kl)) continue;
    fwdHeaders[k] = v;
  }
  fwdHeaders['Host'] = new URL(PNETLAB_HOME_ORIGIN).hostname;
  if (clientId && clientSecret) {
    fwdHeaders['CF-Access-Client-Id']     = clientId;
    fwdHeaders['CF-Access-Client-Secret'] = clientSecret;
  }
  // Lọc cookie phiên dashboard — PNETLab không cần và không được nhận (giống n8n-proxy/termix-proxy).
  const rawCookie = request.headers.get('cookie') || '';
  const fwdCookie = rawCookie.split(';').map(c => c.trim())
    .filter(c => c && !c.startsWith('dh_session=') && !c.startsWith('dh_user='))
    .join('; ');
  if (fwdCookie) fwdHeaders['Cookie'] = fwdCookie;

  let upstream;
  try {
    upstream = await fetch(target, {
      method: request.method,
      headers: fwdHeaders,
      redirect: 'manual',
      ...(request.method !== 'GET' && request.method !== 'HEAD' ? { body: request.body } : {}),
    });
  } catch (e) {
    return new Response('PNETLab proxy error: ' + e.message, { status: 502 });
  }

  const rh = new Headers();
  for (const [k, v] of upstream.headers) {
    const kl = k.toLowerCase();
    if (kl === 'x-frame-options') continue;
    if (kl === 'content-security-policy') continue;
    if (kl === 'content-encoding') continue;
    if (kl === 'content-length') continue;
    if (kl === 'set-cookie') continue;
    rh.set(k, v);
  }
  /* Tài nguyên tĩnh BẤT BIẾN (bundle JS/CSS/font/ảnh có content-hash trong tên) thì cho
     trình duyệt giữ lại; còn HTML/API vẫn no-store để phần gác quyền và rewrite luôn đúng.
     Trước đây ép no-store cho MỌI thứ → mỗi lần mở PNETLab là tải lại từ đầu vài MB bundle,
     vừa chậm vừa tốn CPU Worker cho việc chuyển tiếp. Dùng 'private' (không phải 'public')
     vì nội dung sau lớp đăng nhập — KHÔNG để CDN dùng chung bản đã tải cho người chưa
     đăng nhập (đúng bài học đã gặp với /_settings/ và /downloads/). (2026-08-16) */
  const _batBien = /\.(js|css|woff2?|ttf|otf|png|jpe?g|gif|svg|webp|ico|map)(\?|$)/i.test(subPath);
  rh.set('Cache-Control', _batBien
    ? 'private, max-age=86400'
    : 'no-store, no-cache, must-revalidate');

  // Rewrite Set-Cookie: bỏ Domain, ép SameSite=None;Secure (bắt buộc vì chạy trong iframe).
  // ⚠️ PHẢI dùng getSetCookie() — `Headers.getAll()` KHÔNG tồn tại trên runtime Workers hiện đại,
  // nên `headers.getAll ? ... : []` luôn rơi vào nhánh [] → MẤT SẠCH cookie phiên PNETLab.
  // Triệu chứng thật đã gặp: đăng nhập PNETLab thành công (server trả result:true) nhưng browser
  // không nhận được cookie `_session` → request tiếp theo `/api/auth` trả 401 → AngularJS
  // `unlMainController` không set `$scope.loaded = true` → `<div ng-if="loaded">` không render
  // → trang rỗng hoàn toàn (nhìn thấy nền tối của dashboard xuyên qua iframe = "màn hình đen").
  let rawCookies = [];
  try { rawCookies = upstream.headers.getSetCookie(); }
  catch { const h = upstream.headers.get('set-cookie'); if (h) rawCookies = [h]; }
  for (const c of rawCookies) {
    let rewritten = String(c).replace(/;\s*Domain=[^;,]*/gi, '').replace(/;\s*SameSite=\w+/gi, '; SameSite=None');
    if (!/;\s*Secure/i.test(rewritten)) rewritten += '; Secure';
    rh.append('Set-Cookie', rewritten);
  }

  // Redirect: nếu Cloudflare Access chặn (thiếu/sai Service Token), PNETLab/CF sẽ 3xx sang
  // cloudflareaccess.com — bắt lỗi rõ ràng thay vì để trình duyệt redirect lạc origin (mẫu Termix).
  const loc = upstream.headers.get('Location');
  if (loc) {
    if (/cloudflareaccess\.com/i.test(loc)) {
      return new Response(
        '<html><body style="font-family:sans-serif;padding:2rem;color:#333">'
        + '<h2>⚠ PNETLab — Service Token không hợp lệ</h2>'
        + '<p>Worker proxy tới <code>pnetlab.home-server.id.vn</code> nhưng bị Cloudflare Access chặn (thiếu/sai Service Token).</p>'
        + '<p>Kiểm tra secret <code>PNETLAB_HOME_CF_CLIENT_ID</code> / <code>PNETLAB_HOME_CF_CLIENT_SECRET</code> đã set đúng chưa (wrangler secret put).</p>'
        + '</body></html>',
        { status: 502, headers: { 'Content-Type': 'text/html; charset=utf-8' } }
      );
    }
    rh.set('Location', rewriteUrlLike(loc));
  }

  const ct = upstream.headers.get('Content-Type') || '';

  // ⚠️ Bug thật đã gặp: PNETLab tự "postLogin()" gọi lại sau khi đóng lab (LAB==null, param==null)
  // → `window.location.href = "/"` (functions.js), coi "/" là trang chủ CHÍNH NÓ. Trong proxy này
  // "/" là trang chủ DASHBOARD (chưa nằm trong app bypass Cloudflare Access nào) → PNETLab tự điều
  // hướng iframe của mình sang trang bị Cloudflare Access chặn → "This content is blocked", KHÔNG
  // liên quan gì đến quyền hạn dashboard. Vá thẳng chuỗi này khi proxy — đưa PNETLab về ĐÚNG trang
  // chủ của chính nó (`/store/public/admin/main/view`, luôn nằm trong passthru) thay vì để nó tự
  // nhảy ra ngoài phạm vi đã bypass. Áp cho MỌI response text/javascript (không chỉ functions.js
  // — PNETLab có thể lặp lại pattern này ở bundle khác, và chuỗi đủ đặc thù để không đụng nhầm gì).
  if (ct.includes('javascript')) {
    /* ⚠️ CHẶN LẶP LẠI SỰ CỐ 502 CỦA PROXY n8n (2026-08-09 → vá ở đây 2026-08-16)
       ─────────────────────────────────────────────────────────────────────────
       Đọc TRỌN file JS vào bộ nhớ rồi regex chính là khuôn mẫu đã làm proxy n8n vượt
       hạn mức CPU của Worker → chunk trả 502 → Vue kẹt nửa chừng → cả trang đứng hình.
       Mất rất lâu mới lần ra vì triệu chứng trông y hệt lỗi mạng.

       KHÁC n8n ở chỗ: phép thay thế dưới đây là CẦN THIẾT THẬT (vá lỗi PNETLab tự nhảy
       `location.href="/"` sang trang chủ dashboard → dính Cloudflare Access → "This
       content is blocked"). Nên không bỏ được, chỉ tránh áp lên file to.

       Bỏ qua thư viện bên thứ ba (vendors~*, *.min.js…) và mọi file > 1 MB: chuỗi cần
       vá là mã ỨNG DỤNG của PNETLab (functions.js, thanh admin…), thư viện ngoài không
       chứa logic điều hướng riêng của PNETLab. File to lại đúng là loại đốt CPU nhiều nhất. */
    const _cl = parseInt(upstream.headers.get('Content-Length') || '0', 10);
    const _laThuVien = /\/vendors[~-]|\/chunk[-.]|\.min\.js(\?|$)|\/runtime[~.-]/i.test(subPath);
    if (_laThuVien || _cl > 1048576) {
      /* Chuyển thẳng dạng luồng — không đệm, không regex, gần như 0 CPU. */
      return new Response(upstream.body, { status: upstream.status, headers: rh });
    }
    let js = await upstream.text();
    // Bắt mọi biến thể (có/không "window.", khoảng trắng khác nhau, nháy đơn/kép) thay vì chỉ
    // đúng 1 chuỗi — PNETLab lặp lại pattern "về trang chủ chính nó" ở nhiều chỗ khác nhau
    // (postLogin() sau khi đóng lab, nút "Main" trên thanh admin...), không chỉ đúng 1 dòng.
    js = js.replace(/(window\.)?location\.href\s*=\s*(["'])\/\2/g,
      (m, w, q) => `${w || ''}location.href = ${q}${PNETLAB_HOME_ENTRY}${q}`);

    /* ⚠️ NẮN LẠI ĐỊA CHỈ TRỢ LÝ AI CÒN SÓT TRONG MÃ CỦA PNETLab (2026-08-17)
       ─────────────────────────────────────────────────────────────────────
       Hồi mới làm, dòng loader trợ lý được chèn TAY vào cuối
       `/opt/unetlab/html/store/public/assets/js/default.js` trên máy PNETLab, và địa chỉ
       lúc đó trỏ về STAGING (`dashboard-homelab-staging.*.workers.dev`). Sau này proxy đã
       tự tiêm thẻ script (xem chỗ chèn vào `</head>` bên dưới) nên dòng đó thành thừa —
       nhưng KHÔNG AI GỠ, và nó vẫn nằm trong file.

       Hậu quả trên PRODUCTION (anh Thoại báo 2026-08-17):
       1. Trình duyệt tải script từ tên miền `*.workers.dev` → Symantec Endpoint Protection
          chặn thẳng ("Malicious Site Blocked") vì tên miền đó hay bị lạm dụng.
       2. NGUY HIỂM HƠN: `proxyBase()` trong pnet-assistant.js lấy origin từ THẺ SCRIPT ĐẦU
          TIÊN nó tìm thấy → vớ phải thẻ staging → mọi lệnh gọi `/api/pnet-llm` và
          `/api/pnet-console` của người dùng PRODUCTION bắn sang máy chủ STAGING.

       Nắn mọi địa chỉ tuyệt đối trỏ tới pnet-assistant.js về đúng origin đang phục vụ.
       Nạp 2 lần vẫn vô hại vì chính file đó có chốt `if (window.__PNET_AI__) return;`.
       Đây là LƯỚI AN TOÀN — vẫn nên gỡ hẳn dòng loader trên máy PNETLab. */
    js = js.replace(/https?:\/\/[^"'\s)]*\/pnet-assistant\.js/g,
      new URL(request.url).origin + '/pnet-assistant.js');

    rh.set('Content-Type', ct);
    return new Response(js, { status: upstream.status, headers: rh });
  }

  if (!ct.includes('text/html')) {
    return new Response(upstream.body, { status: upstream.status, headers: rh });
  }

  // ── HTML response: rewrite path tuyệt đối + tự tiêm trợ lý AI ──
  let html = await upstream.text();

  // Patch các API mạng của trình duyệt ($.ajax, fetch, XHR) để URL do JS build lúc chạy cũng
  // được định tuyến đúng. CHỈ đổi những path KHÔNG thuộc passthru (thực tế là `/api/*` — trùng
  // namespace API dashboard); `/store/*`, `/themes/*` giữ nguyên để react-router còn khớp.
  const patch = `<script>
(function(){
var B='${PNETLAB_HOME_BASE}';
var O='pnetlab.home-server.id.vn';
var PASS=${JSON.stringify(PNETLAB_PASSTHRU)};
var PASSPFX=${JSON.stringify(PNETLAB_PASSTHRU_PREFIX)};
var HOME='${PNETLAB_HOME_ENTRY}';
function route(p){
  if(typeof p!=='string'||p.charAt(0)!=='/') return p;
  if(p==='/') return HOME;
  if(p.indexOf(B)===0) return p;
  for(var i=0;i<PASS.length;i++){ if(p===PASS[i]||p.indexOf(PASS[i]+'/')===0) return p; }
  for(var j=0;j<PASSPFX.length;j++){ if(p.indexOf(PASSPFX[j])===0) return p; }
  return B+p;
}
function rw(u){
  if(typeof u!=='string'||!u) return u;
  if(u.indexOf('http')===0 && u.indexOf(O)!==-1){
    var i=u.indexOf(O)+O.length;
    return route(u.slice(i)||'/');
  }
  if(u.charAt(0)==='/' && u.slice(0,2)!=='//') return route(u);
  return u;
}
if(window.jQuery){
  var _ajax=window.jQuery.ajax;
  window.jQuery.ajax=function(opts){
    if(typeof opts==='string'){ var extra=arguments[1]||{}; opts=Object.assign({url:opts},extra); }
    if(opts&&opts.url) opts.url=rw(opts.url);
    return _ajax.call(this,opts);
  };
}
var _F=window.fetch;
window.fetch=function(u,o){ return _F.call(this,rw(u),o); };
var _X=XMLHttpRequest.prototype.open;
XMLHttpRequest.prototype.open=function(m,u){ return _X.apply(this,[m,rw(u)].concat([].slice.call(arguments,2))); };
})();
</` + `script>`;
  html = html.replace('<head>', '<head>' + patch);

  // Rewrite src/href/action trong HTML tĩnh (link/form không qua JS ở trên).
  // PNETLab viết hầu hết `<script src>`/`<link href>` bằng URL TUYỆT ĐỐI
  // (`https://pnetlab.home-server.id.vn/store/public/...`) → phải cắt origin để tải qua proxy
  // (domain gốc đã bị Cloudflare Access chặn, trình duyệt không có Service Token).
  // Blade template ghi khoảng trắng không đều quanh dấu "=" (`href = "..."`) → regex nới \s*.
  html = html.replace(/(\s(?:src|href|action)\s*=\s*["'])([^"']+)(["'])/gi, (m, attr, url, q) => {
    if (url.indexOf(PNETLAB_HOME_ORIGIN) === 0) {
      return attr + pnetPath(url.slice(PNETLAB_HOME_ORIGIN.length) || '/') + q;
    }
    if (url.charAt(0) === '/' && url.slice(0, 2) !== '//') {
      return attr + pnetPath(url) + q;
    }
    return m;
  });

  // Tự tiêm trợ lý AI — KHÔNG còn cần sửa default.js trên VM PNETLab.
  // BỎ QUA `/html5/*`: đó là console Guacamole chạy trong IFRAME CON bên trong cửa sổ Terminal
  // của trang topology. Tiêm vào đó thì nút 🤖 mọc thêm lần nữa ngay giữa cửa sổ Terminal, trong
  // khi trang topology (iframe cha) đã có sẵn nút rồi → thừa và che mất màn hình console.
  /* Nắn địa chỉ trợ lý còn sót trong HTML — cùng lý do với bản vá ở nhánh JS phía trên
     (thẻ script trỏ về staging làm Symantec chặn VÀ làm proxyBase() bắn API sang staging). */
  html = html.replace(/https?:\/\/[^"'\s)]*\/pnet-assistant\.js/g,
    new URL(request.url).origin + '/pnet-assistant.js');

  if (!/^\/html5(\/|$)/.test(subPath)) {
    html = html.replace('</head>',
      '<script src="' + new URL(request.url).origin + '/pnet-assistant.js" defer></' + 'script></head>');
  }

  rh.set('Content-Type', ct);
  return new Response(html, { status: upstream.status, headers: rh });
}
