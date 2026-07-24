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
import { json } from './core.js';

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
   Vì sao proxy: 9Router chặn CORS (401 preflight) + không được lộ API key
   trong browser. Nút chat gọi endpoint này (cross-origin từ pnetlab origin),
   Worker gắn secret NINE_ROUTER_KEY rồi forward + stream SSE trả về.
   Bảo vệ: chỉ nhận Origin pnetlab + rate-limit theo IP + ép model allowlist +
   chỉ forward tới đúng 9Router. Threat model homelab: lạm dụng chỉ tốn quota
   gateway riêng của anh (Origin có thể giả bởi non-browser nhưng bị chặn số lần).
   ═══════════════════════════════════════════════════════════════════ */
const NINE_ROUTER = 'https://9router.home-server.id.vn/v1/chat/completions';
const PNET_ORIGIN = 'https://pnetlab.home-server.id.vn';
const LLM_MODELS = new Set(['pnetlab', 'AI-Home']);   // chỉ cho các alias của anh
const LLM_RL_MAX = 60;                                  // request / 5 phút / IP

function _cors(origin) {
  const ok = origin === PNET_ORIGIN;
  return {
    'Access-Control-Allow-Origin': ok ? PNET_ORIGIN : 'null',
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Max-Age': '86400',
    'Vary': 'Origin',
  };
}

export async function handlePnetLlm(request, env) {
  const origin = request.headers.get('Origin') || '';
  if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: _cors(origin) });
  const cjson = (obj, status) => new Response(JSON.stringify(obj), { status, headers: Object.assign({ 'Content-Type': 'application/json' }, _cors(origin)) });
  if (request.method !== 'POST') return cjson({ error: 'method' }, 405);
  if (origin !== PNET_ORIGIN) return cjson({ error: 'forbidden origin' }, 403);

  const key = env.NINE_ROUTER_KEY;
  if (!key) return cjson({ error: 'Chưa cấu hình NINE_ROUTER_KEY (wrangler secret put NINE_ROUTER_KEY).' }, 503);

  // Rate-limit theo IP (KV, cửa sổ 5 phút)
  const ip = request.headers.get('CF-Connecting-IP') || '?';
  const rlKey = 'pnetllm:rl:' + ip;
  const cnt = parseInt((await env.DASHBOARD_KV.get(rlKey)) || '0', 10);
  if (cnt >= LLM_RL_MAX) return cjson({ error: 'Quá nhiều yêu cầu, thử lại sau ít phút.' }, 429);
  await env.DASHBOARD_KV.put(rlKey, String(cnt + 1), { expirationTtl: 300 });

  let body; try { body = await request.json(); } catch { return cjson({ error: 'bad json' }, 400); }
  const model = LLM_MODELS.has(body.model) ? body.model : 'pnetlab';
  const payload = Object.assign({}, body, { model, stream: true });

  let upstream;
  try {
    upstream = await fetch(NINE_ROUTER, {
      method: 'POST',
      headers: { 'Authorization': 'Bearer ' + key, 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
  } catch (e) { return cjson({ error: '9Router không phản hồi: ' + ((e && e.message) || e) }, 502); }

  // Stream thẳng SSE về browser (kèm CORS)
  return new Response(upstream.body, {
    status: upstream.status,
    headers: Object.assign({ 'Content-Type': 'text/event-stream; charset=utf-8', 'Cache-Control': 'no-cache' }, _cors(origin)),
  });
}

/* ═══════════════════════════════════════════════════════════════════
   PROXY console-bridge — AI GÕ LỆNH THẬT vào console node (Phase 3, 2026-07-24)
   -------------------------------------------------------------------
   Vì sao cần: đã xác nhận configs/edit KHÔNG ghi được config qua API (xem
   comment phía trên) — cách duy nhất để cấu hình node là gõ lệnh console.
   console-bridge (_ops/pnetlab-console-bridge.py) chạy trên VM PNETLab,
   telnet THẲNG vào cổng console nội bộ của node (né Guacamole/WebSocket
   hoàn toàn — thứ đã lỗi cả ngày qua tunnel). Worker giữ vai trò y hệt
   /api/pnet-llm: gắn secret PNET_CONSOLE_SECRET (ẩn khỏi browser), chỉ
   nhận Origin pnetlab, rate-limit, forward tới route tunnel riêng của
   console-bridge (PNET_CONSOLE_URL, secret vì đây là named route riêng
   không cố định như 9router). */
const CONSOLE_RL_MAX = 30;   // request / 5 phút / IP — thao tác console nặng hơn chat

export async function handlePnetConsole(request, env) {
  const origin = request.headers.get('Origin') || '';
  if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: _cors(origin) });
  const cjson = (obj, status) => new Response(JSON.stringify(obj), { status, headers: Object.assign({ 'Content-Type': 'application/json' }, _cors(origin)) });
  if (request.method !== 'POST') return cjson({ error: 'method' }, 405);
  if (origin !== PNET_ORIGIN) return cjson({ error: 'forbidden origin' }, 403);

  const bridgeUrl = env.PNET_CONSOLE_URL;      // vd https://pnetlab-console.home-server.id.vn/exec
  const secret = env.PNET_CONSOLE_SECRET;
  if (!bridgeUrl || !secret) return cjson({ error: 'Chưa cấu hình PNET_CONSOLE_URL/PNET_CONSOLE_SECRET (wrangler secret put).' }, 503);

  const ip = request.headers.get('CF-Connecting-IP') || '?';
  const rlKey = 'pnetcon:rl:' + ip;
  const cnt = parseInt((await env.DASHBOARD_KV.get(rlKey)) || '0', 10);
  if (cnt >= CONSOLE_RL_MAX) return cjson({ error: 'Quá nhiều yêu cầu console, thử lại sau ít phút.' }, 429);
  await env.DASHBOARD_KV.put(rlKey, String(cnt + 1), { expirationTtl: 300 });

  let body; try { body = await request.json(); } catch { return cjson({ error: 'bad json' }, 400); }
  const port = parseInt(body.port, 10);
  const commands = Array.isArray(body.commands) ? body.commands.filter(c => typeof c === 'string').slice(0, 40) : [];
  if (!Number.isInteger(port)) return cjson({ error: 'Thiếu port (số nguyên, port console của node)' }, 400);
  if (!commands.length) return cjson({ error: 'Thiếu commands (mảng chuỗi lệnh)' }, 400);

  let upstream;
  try {
    upstream = await fetch(bridgeUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Bridge-Secret': secret },
      body: JSON.stringify({ port, commands }),
    });
  } catch (e) { return cjson({ error: 'console-bridge không phản hồi: ' + ((e && e.message) || e) }, 502); }

  let data; try { data = await upstream.json(); } catch { data = { ok: false, error: 'console-bridge trả dữ liệu không hợp lệ' }; }
  return cjson(data, upstream.status);
}
