/* ═══════════════════════════════════════════════════════════════════
   Dashboard MCP server (Model Context Protocol, Streamable HTTP)
   -------------------------------------------------------------------
   Exposes read-only dashboard data as MCP tools for external agents
   (OpenClaw / Antigravity). Access is managed from Settings → "Kết nối AI":
     • per-app token (KV mcp_clients) — each app scoped to specific tools
     • per-tool global enable/disable (KV mcp_tools)
     • global MCP on/off (KV mcp_config)
     • call audit (KV mcp_audit)
   Legacy secret AGENT_MCP_TOKEN keeps working as a full-access token.

   Stateless streamable-http: initialize, ping, tools/list, tools/call.
   ═══════════════════════════════════════════════════════════════════ */
import { json, getSession, logActivity } from '../core.js';
import { ACTION_REGISTRY } from './actions.js';
import { READ_REGISTRY } from './reads.js';
import { getForms } from './movi.js';

const MCP_PROTOCOL = '2024-11-05';
const SERVER_INFO  = { name: 'dashboard-mcp', version: '1.0.0' };

/* ── Tool catalog (metadata for the admin UI + the MCP tool list) ──
   LƯU Ý: các tool ĐỌC dữ liệu dịch vụ (fortigate/vmware/asus/casaos/rustdesk…)
   ĐÃ CHUYỂN sang cơ chế per-user `dash-read` (src/ai/reads.js) để giới hạn theo
   quyền user. MCP chỉ còn tool meta (pages/actions/log) không lộ dữ liệu nhạy cảm. */
export const TOOL_CATALOG = [
  {
    name: 'list_dashboard_pages',
    label: 'Danh sách trang',
    dataDesc: 'các trang dashboard + quyền cần có',
    sensitive: false,
    description:
      'Liệt kê các trang trong dashboard (id, tên, đường dẫn URL, quyền cần có, mô tả). ' +
      'Dùng khi cần biết dashboard có trang gì, hoặc để đưa cho người dùng LINK mở trang. ' +
      'Muốn đưa người dùng tới 1 trang: trả về link markdown tới "url" của trang đó (vd [FortiGate Home](/service-home/fortigate.html)); ' +
      'người dùng bấm link, dashboard sẽ mở trang — CHỈ mở được nếu họ có quyền.',
    inputSchema: { type: 'object', properties: {}, additionalProperties: false },
  },
  {
    name: 'log_unresolved',
    label: 'Ghi câu hỏi khó',
    dataDesc: 'lưu câu hỏi AI chưa xử lý được cho admin',
    sensitive: false,
    description:
      'Gọi tool này KHI bạn không trả lời được, không có công cụ phù hợp, hoặc yêu cầu vượt quá ' +
      'những gì bạn làm được. Nó lưu lại câu hỏi + lý do để admin đọc và xử lý sau. ' +
      'Sau khi gọi, hãy báo người dùng: "Mình chưa xử lý được, đã ghi lại để admin xem giúp bạn."',
    inputSchema: {
      type: 'object',
      properties: {
        question: { type: 'string', description: 'Câu hỏi/yêu cầu của người dùng' },
        reason:   { type: 'string', description: 'Vì sao chưa làm được' },
      },
      required: ['question'], additionalProperties: false,
    },
  },
  {
    name: 'list_dashboard_reads',
    label: 'Danh sách nguồn đọc',
    dataDesc: 'các nguồn dash-read (đọc dữ liệu theo quyền user)',
    sensitive: false,
    description:
      'Liệt kê các NGUỒN ĐỌC dữ liệu sống (id, quyền cần, mô tả). Để đọc 1 nguồn, in ra khối mã ' +
      '```dash-read chứa JSON {"source":"<id>"} — dashboard sẽ đọc BẰNG QUYỀN của người dùng đang ' +
      'đăng nhập rồi trả dữ liệu về chat cho bạn. User thiếu quyền thì bị từ chối — hãy báo họ bị giới hạn. ' +
      'Gọi tool này khi cần biết có nguồn dữ liệu nào / id nguồn chính xác.',
    inputSchema: { type: 'object', properties: {}, additionalProperties: false },
  },
  {
    name: 'list_dashboard_forms',
    label: 'Danh sách biểu mẫu n8n',
    dataDesc: 'các biểu mẫu nghiệp vụ (tạo user Movi…) + trường + quy tắc',
    sensitive: false,
    description:
      'Liệt kê các BIỂU MẪU nghiệp vụ gửi tới n8n (vd tạo user Movi): id, trường bắt buộc, định dạng, ' +
      'quy tắc thu thập. Khi user yêu cầu một nghiệp vụ (tạo user, cấp phát…): gọi tool này lấy spec, ' +
      'HỎI user từng thông tin còn thiếu đúng theo rules, xác nhận lại toàn bộ, rồi in khối ' +
      '```dash-action {"action":"form_submit","params":{"form":"<id>","data":{...}}} — dashboard sẽ ' +
      'validate lần cuối + hỏi user bấm Đồng ý mới gửi. Thiếu/sai trường là bị từ chối, đừng gửi bừa.',
    inputSchema: { type: 'object', properties: {}, additionalProperties: false },
  },
  {
    name: 'list_dashboard_actions',
    label: 'Danh sách hành động',
    dataDesc: 'các việc AI có thể LÀM + quyền cần',
    sensitive: false,
    description:
      'Liệt kê các HÀNH ĐỘNG (ghi/điều khiển) mà AI có thể thực hiện thay mặt người dùng: ' +
      'id, tên, quyền cần có, mức nguy hiểm (safe/confirm), mô tả, tham số. ' +
      'Bạn KHÔNG tự thực thi. Để làm 1 hành động, hãy in ra một khối mã ```dash-action chứa JSON ' +
      '{"action":"<id>","params":{...}} — dashboard sẽ hỏi người dùng xác nhận (nếu nguy hiểm), ' +
      'chạy bằng phiên của họ (chặn theo quyền), và báo kết quả lại. Nếu người dùng không có quyền, ' +
      'hành động sẽ bị từ chối — hãy nói rõ với họ rằng họ bị giới hạn quyền đó.',
    inputSchema: { type: 'object', properties: {}, additionalProperties: false },
  },
];

/* Dashboard pages the AI may point the user to. `perm` = permission key the
   user needs (null = open to all logged-in). Actions run as the logged-in
   user, so the page itself enforces access — this list is guidance only. */
export const PAGE_CATALOG = [
  { id: 'home',      name: 'Trang chủ',       url: '/',                                 perm: null,        desc: 'Tổng quan tất cả dịch vụ' },
  { id: 'fortigate', name: 'FortiGate Home',  url: '/service-home/fortigate.html',      perm: 'fortigate', desc: 'Firewall nhà: interfaces, VPN, SSL-VPN, policy, DDNS/public IP' },
  { id: 'camera',    name: 'Camera Home',     url: '/service-home/camera-home.html',    perm: 'camera',    desc: 'Camera Frigate: xem live, playback, sự kiện AI' },
  { id: 'vmware',    name: 'VMware ESXi',     url: '/service-home/vmware-home.html',     perm: 'esxi',      desc: 'Máy ảo trên ESXi: bật/tắt, trạng thái' },
  { id: 'casaos',    name: 'CasaOS',          url: '/service-home/casaos.html',         perm: 'casaos',    desc: 'Home server OS' },
  { id: 'asus',      name: 'ASUS Router',     url: '/service-home/asus.html',           perm: 'asus',      desc: 'Router mạng nhà' },
  { id: 'n8n',       name: 'n8n Automation',  url: '/service-home/n8n.html',            perm: 'n8n',       desc: 'Workflow automation' },
  { id: 'ssh',       name: 'SSH Terminal',    url: '/service-home/ssh.html',            perm: 'ssh',       desc: 'Web SSH (Termix)' },
  { id: 'rustdesk',  name: 'RustDesk',        url: '/service-home/rustdesk.html',       perm: 'rustdesk',  desc: 'Remote desktop máy nhân viên' },
  { id: 'settings',  name: 'Cài đặt',         url: '/settings.html',                    perm: null,        desc: 'Tài khoản, MFA; quản trị (chỉ admin)' },
];

async function runTool(name, _args, env) {
  // Lưu ý: các tool đọc dữ liệu get_* ĐÃ GỠ — dữ liệu sống nay đọc theo quyền user
  // qua dash-read (src/ai/reads.js). MCP chỉ còn tool meta bên dưới.
  if (name === 'list_dashboard_pages') {
    return { pages: PAGE_CATALOG };
  }
  if (name === 'log_unresolved') {
    const q = (_args.question || '').toString().trim().slice(0, 1000);
    const reason = (_args.reason || '').toString().trim().slice(0, 1000);
    if (!q) return { ok: false, error: 'thiếu question' };
    const list = await getJson(env, 'ai_unresolved', []);
    list.unshift({ id: 'u_' + newToken().slice(0, 8), question: q, reason, time: Date.now() });
    await env.DASHBOARD_KV.put('ai_unresolved', JSON.stringify(list.slice(0, 200)));
    return { ok: true, saved: true, note: 'Đã ghi lại cho admin.' };
  }
  if (name === 'list_dashboard_forms') {
    const forms = await getForms(env);
    return {
      forms: forms.map(f => ({ id: f.id, label: f.label, desc: f.desc, perm: f.perm || null,
        adminOnly: !!f.adminOnly, fields: f.fields || [], rules: f.rules || '' })),
      howto: 'Thu thập đủ field theo rules → in ```dash-action {"action":"form_submit","params":{"form":"<id>","data":{...}}}```.',
    };
  }
  if (name === 'list_dashboard_reads') {
    return {
      reads: READ_REGISTRY.map(r => ({ id: r.id, perm: r.perm, label: r.label, desc: r.desc })),
      howto: 'In khối ```dash-read {"source":"<id>"}``` — dashboard đọc bằng quyền user rồi trả dữ liệu về chat.',
    };
  }
  if (name === 'list_dashboard_actions') {
    return {
      actions: ACTION_REGISTRY.filter(a => !a.disabled).map(a => ({
        id: a.id, label: a.label, perm: a.perm, danger: a.danger,
        desc: a.desc, params: a.params || [],
      })),
      howto: 'In khối ```dash-action {"action":"<id>","params":{...}}``` để yêu cầu thực hiện.',
    };
  }
  throw new Error('Unknown tool: ' + name);
}

/* ── helpers ── */
async function sha256hex(s) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s));
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
}
async function getJson(env, key, def) {
  try { const v = await env.DASHBOARD_KV.get(key, 'json'); return v == null ? def : v; }
  catch { return def; }
}
function newToken() {
  const a = new Uint8Array(24); crypto.getRandomValues(a);
  return [...a].map(b => b.toString(16).padStart(2, '0')).join('');
}
function constEq(a, b) {
  if (!a || !b || a.length !== b.length) return false;
  let d = 0; for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return d === 0;
}
/* Sanitize a KB file path: forward slashes for folders, no traversal, safe chars,
   default .md extension. e.g. "network/vlan" → "network/vlan.md". */
function cleanKbPath(p) {
  p = (p || '').toString().trim().replace(/\\/g, '/')
    .replace(/^\/+/, '').replace(/\.\.+/g, '')
    .replace(/[^a-zA-Z0-9._\/\- ]/g, '').replace(/\/{2,}/g, '/').slice(0, 200);
  if (!p) return '';
  if (!/\.[a-z0-9]+$/i.test(p)) p += '.md';
  return p;
}

/* Resolve the presented bearer token → a client (or null). */
async function resolveClient(env, presented) {
  if (!presented) return null;
  const legacy = (env.AGENT_MCP_TOKEN || '').replace(/^﻿/, '').trim();
  if (legacy && constEq(legacy, presented)) {
    return { id: 'legacy', name: 'Token gốc (legacy)', allowedTools: '*', enabled: true };
  }
  const clients = await getJson(env, 'mcp_clients', []);
  if (!clients.length) return null;
  const h = await sha256hex(presented);
  const c = clients.find(x => x.tokenHash === h);
  return (c && c.enabled) ? c : null;
}

/* Tools a client may use = allowedTools ∩ globally-enabled tools. */
async function allowedToolsFor(env, client) {
  const toolCfg = await getJson(env, 'mcp_tools', {});
  const globalOn = TOOL_CATALOG.filter(t => toolCfg[t.name]?.enabled !== false).map(t => t.name);
  if (client.allowedTools === '*' || !Array.isArray(client.allowedTools)) return globalOn;
  return globalOn.filter(n => client.allowedTools.includes(n));
}

async function audit(env, entry) {
  try {
    const log = await getJson(env, 'mcp_audit', []);
    log.unshift({ ...entry, time: Date.now() });
    await env.DASHBOARD_KV.put('mcp_audit', JSON.stringify(log.slice(0, 60)));
  } catch { /* best-effort */ }
}

/* ── JSON-RPC plumbing ── */
function rpcResult(id, result) { return { jsonrpc: '2.0', id: id ?? null, result }; }
function rpcError(id, code, message) { return { jsonrpc: '2.0', id: id ?? null, error: { code, message } }; }
function jsonResp(obj, status = 200) {
  return new Response(obj === null ? '' : JSON.stringify(obj), {
    status, headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
  });
}

/* Tombstone chuyển tiếp: client còn AGENTS.md cũ gọi tool get_* (đã gỡ) → KHÔNG
   trả dữ liệu, chỉ trả hướng dẫn để AI tự chuyển sang dash-read ngay trong phiên.
   Đặt TRƯỚC check allowed (an toàn: không lộ dữ liệu gì). */
const TOMBSTONE_READS = {
  get_fortigate_home: 'fortigate_home', get_vmware_home: 'vmware_home',
  get_asus_router: 'asus_router', get_asus_clients: 'asus_clients',
  get_casaos: 'casaos', get_rustdesk: 'rustdesk',
};

async function handleMessage(msg, ctx) {
  const { env, allowed, client } = ctx;
  const id = msg && msg.id, method = msg && msg.method, params = (msg && msg.params) || {};
  if (method && method.indexOf('notifications/') === 0) return null;
  if (method === 'tools/call' && TOMBSTONE_READS[params.name]) {
    await audit(env, { clientId: client.id, clientName: client.name, tool: params.name, ok: true, reason: 'tombstone→dash-read' });
    return rpcResult(id, { content: [{ type: 'text', text:
      'Tool này đã được thay bằng cơ chế đọc theo quyền user. ĐỪNG gọi lại tool này. ' +
      'Hãy in ra khối mã sau trong câu trả lời để dashboard đọc dữ liệu giúp bạn:\n' +
      '```dash-read\n{"source":"' + TOMBSTONE_READS[params.name] + '"}\n```' }] });
  }

  if (method === 'initialize') {
    return rpcResult(id, {
      protocolVersion: params.protocolVersion || MCP_PROTOCOL,
      capabilities: { tools: { listChanged: false } },
      serverInfo: SERVER_INFO,
    });
  }
  if (method === 'ping') return rpcResult(id, {});
  if (method === 'tools/list') {
    const tools = TOOL_CATALOG.filter(t => allowed.includes(t.name))
      .map(t => ({ name: t.name, description: t.description, inputSchema: t.inputSchema }));
    return rpcResult(id, { tools });
  }
  if (method === 'tools/call') {
    const nm = params.name;
    if (!allowed.includes(nm)) {
      await audit(env, { clientId: client.id, clientName: client.name, tool: nm, ok: false, reason: 'not-allowed' });
      return rpcResult(id, { content: [{ type: 'text', text: 'Công cụ không được phép hoặc đã tắt: ' + nm }], isError: true });
    }
    try {
      const data = await runTool(nm, params.arguments || {}, env);
      await audit(env, { clientId: client.id, clientName: client.name, tool: nm, ok: true });
      return rpcResult(id, { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] });
    } catch (e) {
      await audit(env, { clientId: client.id, clientName: client.name, tool: nm, ok: false, reason: 'error' });
      return rpcResult(id, { content: [{ type: 'text', text: 'Error: ' + ((e && e.message) || e) }], isError: true });
    }
  }
  return rpcError(id, -32601, 'Method not found: ' + method);
}

export async function handleMcp(request, env) {
  const presented = (request.headers.get('Authorization') || '').replace(/^Bearer\s+/i, '').trim();
  const client = await resolveClient(env, presented);
  if (!client) return jsonResp(rpcError(null, -32001, 'Unauthorized'), 401);

  const cfg = await getJson(env, 'mcp_config', {});
  if (cfg.enabled === false) return jsonResp(rpcError(null, -32002, 'MCP disabled'), 403);

  if (request.method !== 'POST') {
    return new Response('Method Not Allowed', { status: 405, headers: { 'Allow': 'POST' } });
  }
  let body;
  try { body = await request.json(); }
  catch { return jsonResp(rpcError(null, -32700, 'Parse error'), 400); }

  const allowed = await allowedToolsFor(env, client);
  const ctx = { env, allowed, client };

  if (Array.isArray(body)) {
    const out = [];
    for (const msg of body) { const r = await handleMessage(msg, ctx); if (r) out.push(r); }
    return out.length ? jsonResp(out) : new Response(null, { status: 202 });
  }
  const r = await handleMessage(body, ctx);
  return r ? jsonResp(r) : new Response(null, { status: 202 });
}

/* ═══════════════════════════════════════════════════════════════════
   ADMIN API (worker gates isAdminUser before calling these)
   ═══════════════════════════════════════════════════════════════════ */

/* GET/PUT /api/admin/ai-config — who can use the OpenClaw chat */
export async function handleAdminAiConfig(request, env) {
  if (request.method === 'GET') {
    const cfg = await getJson(env, 'ai_config', {});
    return json({
      enabled: cfg.enabled !== false,
      access: cfg.access || { all: false, roles: ['admin'], users: [] },
      model: 'HomeAI',
    });
  }
  if (request.method === 'PUT') {
    let b; try { b = await request.json(); } catch { return json({ error: 'Invalid JSON' }, 400); }
    const cfg = {
      enabled: b.enabled !== false,
      access: {
        all: !!(b.access && b.access.all),
        roles: Array.isArray(b.access && b.access.roles) ? b.access.roles.slice(0, 50) : ['admin'],
        users: Array.isArray(b.access && b.access.users) ? b.access.users.slice(0, 500) : [],
      },
    };
    await env.DASHBOARD_KV.put('ai_config', JSON.stringify(cfg));
    return json({ ok: true, ...cfg });
  }
  return json({ error: 'Method not allowed' }, 405);
}

function maskClient(c, audits) {
  const last = audits.find(a => a.clientId === c.id);
  return {
    id: c.id, name: c.name, enabled: c.enabled !== false,
    allowedTools: c.allowedTools === '*' ? '*' : (c.allowedTools || []),
    tokenHint: c.tokenHint || '', createdAt: c.createdAt || 0,
    lastUsedAt: last ? last.time : 0,
  };
}

/* /api/admin/mcp[...] — clients, tools, config, audit */
export async function handleAdminMcp(request, env) {
  const url = new URL(request.url);
  const p = url.pathname.replace(/^\/api\/admin\/mcp/, '') || '/';
  const method = request.method;

  const clients = await getJson(env, 'mcp_clients', []);
  const auditLog = await getJson(env, 'mcp_audit', []);

  // GET /api/admin/mcp  → aggregate view
  if (p === '/' && method === 'GET') {
    const cfg = await getJson(env, 'mcp_config', {});
    const toolCfg = await getJson(env, 'mcp_tools', {});
    return json({
      enabled: cfg.enabled !== false,
      endpoint: url.origin + '/mcp',
      clients: clients.map(c => maskClient(c, auditLog)),
      tools: TOOL_CATALOG.map(t => ({
        name: t.name, label: t.label, dataDesc: t.dataDesc, sensitive: !!t.sensitive,
        enabled: toolCfg[t.name]?.enabled !== false,
      })),
      audit: auditLog.slice(0, 40),
      unresolved: (await getJson(env, 'ai_unresolved', [])).slice(0, 100),
    });
  }

  // DELETE /api/admin/mcp/unresolved/:id  — admin đọc xong xoá
  const mUn = p.match(/^\/unresolved\/([^/]+)$/);
  if (mUn && method === 'DELETE') {
    let list = await getJson(env, 'ai_unresolved', []);
    list = list.filter(x => x.id !== mUn[1]);
    await env.DASHBOARD_KV.put('ai_unresolved', JSON.stringify(list));
    return json({ ok: true });
  }

  // PUT /api/admin/mcp/config  → { enabled }
  if (p === '/config' && method === 'PUT') {
    let b; try { b = await request.json(); } catch { return json({ error: 'Invalid JSON' }, 400); }
    await env.DASHBOARD_KV.put('mcp_config', JSON.stringify({ enabled: b.enabled !== false }));
    return json({ ok: true });
  }

  // PUT /api/admin/mcp/tools  → { toolName: bool, ... }
  if (p === '/tools' && method === 'PUT') {
    let b; try { b = await request.json(); } catch { return json({ error: 'Invalid JSON' }, 400); }
    const cfg = {};
    for (const t of TOOL_CATALOG) cfg[t.name] = { enabled: b[t.name] !== false };
    await env.DASHBOARD_KV.put('mcp_tools', JSON.stringify(cfg));
    return json({ ok: true });
  }

  // POST /api/admin/mcp/clients  → create; returns token ONCE
  if (p === '/clients' && method === 'POST') {
    let b; try { b = await request.json(); } catch { return json({ error: 'Invalid JSON' }, 400); }
    const name = (b.name || '').toString().trim().slice(0, 60) || 'Ứng dụng mới';
    const tok = newToken();
    const rec = {
      id: 'c_' + newToken().slice(0, 10),
      name, enabled: true,
      allowedTools: Array.isArray(b.allowedTools) ? b.allowedTools : [],
      tokenHash: await sha256hex(tok),
      tokenHint: tok.slice(-6),
      createdAt: Date.now(),
    };
    clients.push(rec);
    await env.DASHBOARD_KV.put('mcp_clients', JSON.stringify(clients));
    return json({ ok: true, id: rec.id, token: tok, client: maskClient(rec, auditLog) });
  }

  // /api/admin/mcp/clients/:id  (PUT update, DELETE)  +  /token (POST regen)
  const mId = p.match(/^\/clients\/([^/]+)(\/token)?$/);
  if (mId) {
    const id = mId[1], isTokenOp = !!mId[2];
    const idx = clients.findIndex(c => c.id === id);
    if (idx < 0) return json({ error: 'Not found' }, 404);

    if (isTokenOp && method === 'POST') {
      const tok = newToken();
      clients[idx].tokenHash = await sha256hex(tok);
      clients[idx].tokenHint = tok.slice(-6);
      await env.DASHBOARD_KV.put('mcp_clients', JSON.stringify(clients));
      return json({ ok: true, token: tok, client: maskClient(clients[idx], auditLog) });
    }
    if (!isTokenOp && method === 'PUT') {
      let b; try { b = await request.json(); } catch { return json({ error: 'Invalid JSON' }, 400); }
      if (typeof b.name === 'string') clients[idx].name = b.name.trim().slice(0, 60);
      if (typeof b.enabled === 'boolean') clients[idx].enabled = b.enabled;
      if (Array.isArray(b.allowedTools)) clients[idx].allowedTools = b.allowedTools;
      await env.DASHBOARD_KV.put('mcp_clients', JSON.stringify(clients));
      return json({ ok: true, client: maskClient(clients[idx], auditLog) });
    }
    if (!isTokenOp && method === 'DELETE') {
      clients.splice(idx, 1);
      await env.DASHBOARD_KV.put('mcp_clients', JSON.stringify(clients));
      return json({ ok: true });
    }
  }

  // ── Dạy AI: kho kiến thức (KB) — file dạng cây thư mục ──
  if (p === '/kb' && method === 'GET') {
    const files = await getJson(env, 'ai_knowledge', []);
    return json({ files });
  }
  if (p === '/kb' && method === 'PUT') {
    let b; try { b = await request.json(); } catch { return json({ error: 'Invalid JSON' }, 400); }
    const path = cleanKbPath(b.path);
    if (!path) return json({ error: 'Đường dẫn không hợp lệ' }, 400);
    const content = (b.content || '').toString().slice(0, 100000);
    let files = await getJson(env, 'ai_knowledge', []);
    const i = files.findIndex(f => f.path === path);
    const rec = { path, content, updated: Date.now() };
    if (i >= 0) files[i] = rec; else files.push(rec);
    files.sort((a, b2) => a.path.localeCompare(b2.path));
    await env.DASHBOARD_KV.put('ai_knowledge', JSON.stringify(files.slice(0, 500)));
    return json({ ok: true, path });
  }
  if (p === '/kb/delete' && method === 'POST') {
    let b; try { b = await request.json(); } catch { return json({ error: 'Invalid JSON' }, 400); }
    const path = cleanKbPath(b.path);
    let files = await getJson(env, 'ai_knowledge', []);
    files = files.filter(f => f.path !== path);
    await env.DASHBOARD_KV.put('ai_knowledge', JSON.stringify(files));
    return json({ ok: true });
  }

  return json({ error: 'Not found' }, 404);
}

/* GET /api/ai/knowledge — token-gated dump of all KB files, for a sync script on
   the OpenClaw box to mirror into ~/.openclaw/workspace/ (so the agent "learns" it). */
export async function handleAiKnowledge(request, env) {
  const presented = (request.headers.get('Authorization') || '').replace(/^Bearer\s+/i, '').trim();
  const client = await resolveClient(env, presented);
  if (!client) {
    const session = await getSession(request, env);
    if (!session || session.role !== 'admin') return json({ error: 'Unauthorized' }, 401);
  }
  const files = await getJson(env, 'ai_knowledge', []);
  return json({ files: files.map(f => ({ path: f.path, content: f.content })) });
}

/* ═══════════════════════════════════════════════════════════════════
   AI ACTION BRIDGE (Phase 1) — audit + knowledge guide
   ═══════════════════════════════════════════════════════════════════ */

/* POST /api/ai/action — chat.js logs an AI-initiated action here. Session-gated,
   so it is always attributed to the real logged-in user (not the AI). The action
   itself already ran through the user's own session + permission checks. */
export async function handleAiAction(request, env) {
  const session = await getSession(request, env);
  if (!session) return json({ error: 'Unauthorized' }, 401);
  let b; try { b = await request.json(); } catch { b = {}; }
  const action = (b.action || '').toString().slice(0, 40);
  const target = (b.target || '').toString().slice(0, 200);
  await logActivity(env, {
    action: 'ai:' + (action || 'action'),
    username: session.username || '?',
    ip: request.headers.get('CF-Connecting-IP') || '?',
    success: true,
    detail: 'AI thực hiện thay mặt user → ' + target,
  });
  return json({ ok: true });
}

/* GET /api/ai/guide — markdown the operator loads into OpenClaw's workspace
   (~/.openclaw/workspace/AGENTS.md or a bootstrap-extra-file) so the agent knows
   the dashboard + the rules. Token-gated (MCP client token) so it can be curl'd
   from the OpenClaw box. */
export async function handleAiGuide(request, env) {
  const presented = (request.headers.get('Authorization') || '').replace(/^Bearer\s+/i, '').trim();
  const client = await resolveClient(env, presented);
  if (!client) {
    // Fall back to an admin session (operator viewing in-browser)
    const session = await getSession(request, env);
    if (!session || session.role !== 'admin') return json({ error: 'Unauthorized' }, 401);
  }
  const pages = PAGE_CATALOG.map(p =>
    `- **${p.name}** — \`${p.url}\`${p.perm ? ` (cần quyền: \`${p.perm}\`)` : ''} — ${p.desc}`).join('\n');
  const tools = TOOL_CATALOG.map(t => `- \`${t.name}\` — ${t.dataDesc}${t.sensitive ? ' (nhạy cảm)' : ''}`).join('\n');
  const md = `# AI Support System — Hướng dẫn vận hành dashboard

Bạn là **AI Support System** — trợ lý điều khiển một dashboard quản trị home-lab. Bạn giúp người dùng XEM thông tin, ĐIỀU HƯỚNG, và (dần dần) thực hiện thao tác trong dashboard.

## NGUYÊN TẮC CỐT LÕI (bắt buộc)
1. **Bạn hành động THAY MẶT người đang đăng nhập — KHÔNG có quyền riêng.** Mọi thao tác chạy bằng phiên của họ và bị hệ phân quyền của dashboard chặn. Nếu họ không có quyền với một dịch vụ, việc đó sẽ THẤT BẠI — đừng hứa hay giả vờ làm được. Không tìm cách vượt quyền.
2. **Hành động nguy hiểm** (khởi động lại thiết bị, chặn/xoá user, đổi cấu hình, tạo/xoá policy, xoá dữ liệu…): LUÔN mô tả rõ hậu quả và **hỏi người dùng xác nhận** trước khi làm. Dashboard cũng sẽ hiện hộp xác nhận riêng.
3. Trả lời **ngắn gọn, tiếng Việt, thân thiện**. Không bịa thông tin — nếu không chắc, hãy dùng công cụ để lấy dữ liệu thật.
4. Chỉ hoạt động **trong phạm vi dashboard**. Không thực hiện yêu cầu ngoài dashboard trừ khi được cấp công cụ tương ứng.

## ĐIỀU HƯỚNG — đưa người dùng tới một trang
KHÔNG tự ý chuyển trang. Hãy **đưa link markdown** tới đường dẫn (\`url\`) của trang; người dùng bấm, dashboard sẽ mở giúp và **tự kiểm tra quyền**. Sau khi mở, bong bóng trợ lý vẫn mở để tiếp tục.
> Ví dụ: người dùng nói "mở camera" → bạn trả lời: "Đây nhé: [Camera Home](/service-home/camera-home.html)".

## XEM thông tin (dữ liệu sống → dash-read, theo quyền user)
Để lấy dữ liệu THẬT của bất kỳ dịch vụ nào, in khối \`\`\`dash-read {"source":"<id>"}\`\`\` — dashboard đọc bằng quyền của user rồi trả về (xem KB "07-doc-du-lieu-per-user" để biết danh sách nguồn). Ví dụ hỏi trạng thái firewall nhà → \`dash-read {"source":"fortigate_home"}\`. MCP tool chỉ còn tool META: \`list_dashboard_reads\` (danh sách nguồn đọc), \`list_dashboard_pages\`, \`list_dashboard_actions\`, \`log_unresolved\` — KHÔNG còn tool đọc dữ liệu get_*.

## KHI KHÔNG LÀM ĐƯỢC (quan trọng)
Nếu bạn **không trả lời được**, **không có công cụ phù hợp**, hoặc yêu cầu **vượt quá khả năng/quyền**: gọi tool \`log_unresolved\` với \`question\` (yêu cầu của user) + \`reason\` (vì sao chưa làm được). Rồi báo người dùng: "Mình chưa xử lý được, đã ghi lại để admin xem giúp bạn." ĐỪNG bịa câu trả lời khi không chắc.

## Các trang trong dashboard
${pages}

## Công cụ hiện có
${tools}

## ĐIỀU KHIỂN — thực hiện hành động thay mặt người dùng
Bạn CÓ THỂ thực hiện một số thao tác ghi/điều khiển. Gọi tool \`list_dashboard_actions\` để xem danh sách hành động + quyền cần + mức nguy hiểm.

Để yêu cầu thực hiện, hãy MÔ TẢ rõ việc sắp làm rồi in ra MỘT khối mã đúng định dạng này (dashboard sẽ bắt được và xử lý):
\`\`\`dash-action
{"action":"fortigate_reboot","params":{}}
\`\`\`

Sau khi bạn in khối đó, dashboard sẽ:
1. **Kiểm tra quyền của người dùng** — nếu họ KHÔNG có quyền, hành động bị từ chối (403). Khi đó bạn PHẢI nói rõ với họ: họ bị giới hạn quyền này nên không làm được (đừng cố lách).
2. **Việc nguy hiểm** (danger=confirm): dashboard hiện hộp xác nhận — người dùng phải bấm Đồng ý mới chạy.
3. Chạy **bằng phiên của người dùng** (không phải quyền riêng của bạn) và báo kết quả lại.

Tuyệt đối KHÔNG in khối \`dash-action\` cho hành động không có trong \`list_dashboard_actions\`.

_(Tài liệu do dashboard tự sinh — cập nhật khi thêm trang/công cụ. Nạp lại bằng: curl .../api/ai/guide.)_
`;
  // Nhúng kho kiến thức (Dạy AI) vào guide → nạp 1 lần là AI đọc được hết
  let full = md;
  const kb = await getJson(env, 'ai_knowledge', []);
  if (kb.length) {
    full += '\n\n## Kiến thức do admin dạy\n' +
      'Dưới đây là kiến thức riêng của hệ thống này — ưu tiên dùng khi liên quan.\n';
    for (const f of kb) {
      full += `\n### ${f.path}\n${(f.content || '').slice(0, 8000)}\n`;
    }
  }
  return new Response(full, {
    status: 200,
    headers: { 'Content-Type': 'text/markdown; charset=utf-8', 'Cache-Control': 'no-store' },
  });
}
