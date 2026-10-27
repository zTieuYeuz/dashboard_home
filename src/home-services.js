/* ═══════════════════════════════════════════════
   home-services.js — split out of worker.js (2026-07-01). Logic UNCHANGED.
   ═══════════════════════════════════════════════ */
import {
  cleanEnv,
  json,
  whFrom
} from './core.js';

export const CASAOS_BASE = 'https://casaos.home-server.id.vn';

export async function handleCasaOS(env) {
  const user = env.CASAOS_USER;
  const pass = env.CASAOS_PASSWORD;
  if (!user || !pass) return json({ error: 'CASAOS_USER / CASAOS_PASSWORD not configured' }, 500);

  // ── Step 1: Login ──
  let token;
  try {
    const loginRes = await fetch(`${CASAOS_BASE}/v1/users/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: user, password: pass }),
      signal: AbortSignal.timeout(20000),
    });
    if (!loginRes.ok) return json({ error: `CasaOS login failed: ${loginRes.status}` }, 502);
    const loginData = await loginRes.json();
    token = loginData?.data?.token?.access_token;
    if (!token) return json({ error: 'No access_token in login response' }, 502);
  } catch (e) {
    return json({ error: `CasaOS login error: ${e.message}` }, 502);
  }

  // NOTE: CasaOS uses raw token, NOT "Bearer <token>"
  const opts = {
    headers: { 'Authorization': token },
    signal: AbortSignal.timeout(20000),
  };
  const safeJson = async (url) => {
    try {
      const r = await fetch(url, opts);
      if (!r.ok) return null;
      const d = await r.json();
      return d?.data !== undefined ? d.data : d;
    } catch { return null; }
  };

  // ── Step 2: Fetch in parallel ──
  const [sysRaw, appsRaw, hwRaw] = await Promise.all([
    safeJson(`${CASAOS_BASE}/v1/sys/utilization`),
    safeJson(`${CASAOS_BASE}/v2/app_management/web/appgrid`),
    safeJson(`${CASAOS_BASE}/v1/sys/hardware`),
  ]);

  // ── Parse system ──
  const cpu  = sysRaw?.cpu  || {};
  const mem  = sysRaw?.mem  || {};
  const disk = sysRaw?.sys_disk || {};
  const net  = (sysRaw?.net || [])[0] || {};

  // ── Parse apps ──
  const rawApps = Array.isArray(appsRaw) ? appsRaw : [];
  const apps = rawApps
    .filter(a => a.name)
    .map(a => ({
      name:          a.name,
      title:         a.title?.custom || a.title?.en_us || a.title?.en_US || a.name,
      icon:          a.icon || null,
      status:        a.status || 'unknown',
      port:          a.port  || null,
      image:         a.image || null,
      scheme:        a.scheme || 'http',
      hostname:      a.hostname || null,
      appType:       a.app_type,
      authorType:    a.author_type,
      isUncontrolled: !!a.is_uncontrolled,
    }));

  const running = apps.filter(a => a.status === 'running').length;
  const stopped = apps.filter(a => a.status === 'exited' || a.status === 'stopped').length;

  return json({
    system: {
      cpu: {
        model:       cpu.model       || '',
        cores:       cpu.num         || 0,
        percent:     cpu.percent     || 0,
        temperature: cpu.temperature || 0,
      },
      memory: {
        totalGB:     Math.round((mem.total || 0) / 1073741824 * 10) / 10,
        usedGB:      Math.round((mem.used  || 0) / 1073741824 * 10) / 10,
        usedPercent: Math.round(mem.usedPercent || 0),
      },
      disk: {
        totalGB:    Math.round((disk.size || 0) / 1073741824 * 10) / 10,
        usedGB:     Math.round((disk.used || 0) / 1073741824 * 10) / 10,
        availGB:    Math.round((disk.avail || 0) / 1073741824 * 10) / 10,
        usedPercent: disk.size > 0 ? Math.round(disk.used / disk.size * 100) : 0,
        healthy:    disk.health !== false,
      },
      network: {
        name:       net.name      || '',
        sentGB:     Math.round((net.bytesSent || 0) / 1073741824 * 100) / 100,
        recvGB:     Math.round((net.bytesRecv || 0) / 1073741824 * 100) / 100,
        state:      net.state     || '',
      },
      arch: hwRaw?.arch || '',
    },
    apps,
    stats: { total: apps.length, running, stopped },
  });
}

/* ── CasaOS: login lấy token (raw, KHÔNG "Bearer") ── */
async function casaosLogin(env) {
  const user = env.CASAOS_USER, pass = env.CASAOS_PASSWORD;
  if (!user || !pass) throw new Error('CASAOS_USER / CASAOS_PASSWORD chưa cấu hình');
  const r = await fetch(`${CASAOS_BASE}/v1/users/login`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: user, password: pass }),
    signal: AbortSignal.timeout(20000),
  });
  if (!r.ok) throw new Error(`CasaOS login failed: ${r.status}`);
  const d = await r.json();
  const token = d?.data?.token?.access_token;
  if (!token) throw new Error('No access_token in CasaOS login');
  return token;
}

/* POST control 1 app/container CasaOS: body {id, action: start|stop|restart}.
   CasaOS đổi endpoint theo phiên bản → thử lần lượt vài dạng đã biết, dùng cái
   nào trả về < 400 thì dừng. Trả về endpoint đã dùng để lần test đầu chốt đúng. */
export async function handleCasaosAppState(request, env) {
  if (request.method !== 'POST') return json({ error: 'POST required' }, 405);
  let b; try { b = await request.json(); } catch { return json({ error: 'Invalid JSON body' }, 400); }
  const id = (b.id || '').toString().trim();
  const action = (b.action || '').toString().trim().toLowerCase();
  if (!id) return json({ error: 'Thiếu id (tên app/container)' }, 400);
  if (['start', 'stop', 'restart'].indexOf(action) < 0) return json({ error: 'action phải là start | stop | restart' }, 400);

  let token; try { token = await casaosLogin(env); } catch (e) { return json({ error: e.message }, 502); }
  const H = { 'Authorization': token, 'Content-Type': 'application/json' };
  const eid = encodeURIComponent(id);
  // CasaOS v2: đổi state 1 compose-app = PUT /compose/{id}?action=<x> kèm BODY là chính
  // nội dung compose (lấy từ GET). Không có body → "value is required"; body {} → "main
  // service not been specified". Nên: GET compose trước, rồi PUT lại kèm action.
  const actMap = { start: 'start', stop: 'stop', restart: 'restart' };
  const act = actMap[action];

  // Bước 1: GET compose hiện tại
  let composeBody;
  try {
    const g = await fetch(`${CASAOS_BASE}/v2/app_management/compose/${eid}`, { headers: H, signal: AbortSignal.timeout(20000) });
    if (!g.ok) return json({ ok: false, error: `CasaOS GET compose ${g.status}` }, 502);
    const gd = await g.json();
    composeBody = gd && gd.data ? (gd.data.compose !== undefined ? gd.data.compose : gd.data) : null;
    if (!composeBody) return json({ ok: false, error: 'Không đọc được compose của app này' }, 502);
    // GET serialize khác PUT deserialize (vd networks.external: bool vs object) → bỏ
    // các nhánh dễ vênh mà lifecycle action không cần.
    if (composeBody && typeof composeBody === 'object') { try { delete composeBody.networks; delete composeBody.volumes; } catch (_) {} }
  } catch (e) { return json({ ok: false, error: 'CasaOS GET compose lỗi: ' + e.message }, 502); }

  // Bước 2: PUT lại kèm ?action= (thử JSON body và YAML-content nếu cần)
  const tried = [];
  const puts = [
    { ct: 'application/json',        body: JSON.stringify(composeBody) },
    { ct: 'application/yaml',        body: (typeof composeBody === 'string' ? composeBody : null) },
  ];
  for (const p of puts) {
    if (p.body == null) continue;
    const short = `PUT /compose/${id}?action=${act} (${p.ct})`;
    try {
      const r = await fetch(`${CASAOS_BASE}/v2/app_management/compose/${eid}?action=${act}`, {
        method: 'PUT', headers: { 'Authorization': token, 'Content-Type': p.ct }, body: p.body, signal: AbortSignal.timeout(25000),
      });
      const txt = await r.text().catch(() => '');
      tried.push(`${short} → ${r.status} ${txt.slice(0, 90).replace(/\s+/g, ' ')}`);
      if (r.status < 400) return json({ ok: true, id, action, via: short, resp: txt.slice(0, 160) });
      if (r.status === 401 || r.status === 403) return json({ ok: false, error: `CasaOS ${r.status}: ${txt.slice(0, 160)}`, via: short }, 502);
    } catch (e) { tried.push(`${short} → ${e.message}`); }
  }
  return json({ ok: false, error: 'PUT compose chưa nhận — gửi anh Thoai danh sách "tried" để chốt.', tried }, 502);
}


/* ═══════════════════════════════════════════════
   VMware Home — via n8n webhook (SOAP handled by n8n)
   ═══════════════════════════════════════════════ */
export async function handleVmwareHome(env) {
  const n8nUser = cleanEnv(env.HOME_N8N_USER);
  const n8nPass = cleanEnv(env.HOME_N8N_PASS);
  const wh      = whFrom(env, 'HOME_WH_VMWARE_JSON', 'data', 'HOME_WH_VMWARE_DATA');
  if (!wh) return json({ error: 'HOME_WH_VMWARE_DATA not configured' }, 500);
  const hdrs = { 'Content-Type': 'application/json' };
  if (n8nUser) hdrs['Authorization'] = 'Basic ' + btoa(unescape(encodeURIComponent(`${n8nUser}:${n8nPass}`)));
  try {
    const resp = await fetch(wh, { headers: hdrs, signal: AbortSignal.timeout(30000) });
    if (!resp.ok) { const t = await resp.text(); return json({ error: `n8n error ${resp.status}: ${t.slice(0,200)}` }, 502); }
    const raw  = await resp.json();
    const data = Array.isArray(raw) ? raw[0] : raw;
    return json(data);
  } catch (e) { return json({ error: 'Failed to reach n8n', detail: e.message }, 502); }
}

export async function handleVmwareHomePower(request, env) {
  if (request.method !== 'POST') return json({ error: 'POST required' }, 405);
  const n8nUser = cleanEnv(env.HOME_N8N_USER);
  const n8nPass = cleanEnv(env.HOME_N8N_PASS);
  const wh      = whFrom(env, 'HOME_WH_VMWARE_JSON', 'power', 'HOME_WH_VMWARE_POWER');
  if (!wh) return json({ error: 'HOME_WH_VMWARE_POWER not configured' }, 500);
  let body;
  try { body = await request.json(); } catch { return json({ error: 'Invalid JSON body' }, 400); }
  const hdrs = { 'Content-Type': 'application/json' };
  if (n8nUser) hdrs['Authorization'] = 'Basic ' + btoa(unescape(encodeURIComponent(`${n8nUser}:${n8nPass}`)));
  try {
    const resp = await fetch(wh, { method: 'POST', headers: hdrs, body: JSON.stringify(body), signal: AbortSignal.timeout(30000) });
    if (!resp.ok) { const t = await resp.text(); return json({ error: `n8n error ${resp.status}: ${t.slice(0,200)}` }, 502); }
    const raw  = await resp.json();
    return json(Array.isArray(raw) ? raw[0] : raw);
  } catch (e) { return json({ error: 'Failed to reach n8n', detail: e.message }, 502); }
}

/* ═══════════════════════════════════════════════
   FortiGate Home — 5 workflows riêng, gọi song song
   Mỗi workflow độc lập: 1 fail không ảnh hưởng cái khác
   ═══════════════════════════════════════════════ */
export async function handleFortigateWebhook(env) {
  const n8nUser = cleanEnv(env.HOME_N8N_USER);
  const n8nPass = cleanEnv(env.HOME_N8N_PASS);
  const hdrs = { 'Content-Type': 'application/json' };
  if (n8nUser) hdrs['Authorization'] = 'Basic ' + btoa(unescape(encodeURIComponent(`${n8nUser}:${n8nPass}`)));

  // Helper: gọi 1 webhook, trả null nếu lỗi/timeout
  const call = (url, ms = 12000) => {
    const u = cleanEnv(url);
    if (!u) return Promise.resolve(null);
    return fetch(u, { method: 'POST', headers: hdrs, body: '{}', signal: AbortSignal.timeout(ms) })
      .then(r => r.ok ? r.json() : null)
      .catch(() => null);
  };

  const whSys    = whFrom(env, 'HOME_WH_FG_JSON', 'system', 'HOME_WH_FG_SYSTEM');
  const whRes    = whFrom(env, 'HOME_WH_FG_JSON', 'resources', 'HOME_WH_FG_RESOURCES');
  const whIface  = whFrom(env, 'HOME_WH_FG_JSON', 'interfaces', 'HOME_WH_FG_INTERFACES');
  const whVpn    = whFrom(env, 'HOME_WH_FG_JSON', 'vpn', 'HOME_WH_FG_VPN');
  const whSsl    = whFrom(env, 'HOME_WH_FG_JSON', 'ssl', 'HOME_WH_FG_SSL');
  const whPolicy = whFrom(env, 'HOME_WH_FG_JSON', 'policies', 'HOME_WH_FG_POLICIES');
  const whDdns   = whFrom(env, 'HOME_WH_FG_JSON', 'ddns', 'HOME_WH_FG_DDNS');

  if (!whSys) return json({ error: 'HOME_WH_FG_SYSTEM not configured' }, 500);

  // Gọi tất cả song song — tổng thời gian = max(các nhóm)
  const [sys, res, iface, vpn, ssl, policy, ddns] = await Promise.all([
    call(whSys),
    call(whRes),
    call(whIface),
    call(whVpn),
    call(whSsl),
    call(whPolicy),
    call(whDdns, 8000),
  ]);

  const merged = {
    system:     sys?.system     || {},
    resources:  res?.resources  || {},
    interfaces: iface?.interfaces || [],
    vpn:        vpn?.vpn        || [],
    ssl:        ssl?.ssl        || { activeUsers: 0, maxTunnels: null, numTunnels: 0, users: [] },
    policies:   policy?.policies  || [],
    ddns:       ddns?.ddns      || [],
    stats: {
      ...(iface?.stats  || {}),
      ...(vpn?.stats    || {}),
      ...(ssl?.stats    || {}),
      ...(policy?.stats || {}),
      ...(ddns?.stats   || {}),
    },
  };

  return new Response(JSON.stringify(merged), {
    headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
  });
}

export async function handleFortigateBW(env) {
  const n8nUser = cleanEnv(env.HOME_N8N_USER);
  const n8nPass = cleanEnv(env.HOME_N8N_PASS);
  const hdrs = { 'Content-Type': 'application/json' };
  if (n8nUser) hdrs['Authorization'] = 'Basic ' + btoa(unescape(encodeURIComponent(`${n8nUser}:${n8nPass}`)));
  const whIface = whFrom(env, 'HOME_WH_FG_JSON', 'interfaces', 'HOME_WH_FG_INTERFACES');
  if (!whIface) return json({ error: 'HOME_WH_FG_INTERFACES not configured' }, 500);
  try {
    const r = await fetch(whIface, { method: 'POST', headers: hdrs, body: '{}', signal: AbortSignal.timeout(8000) });
    if (!r.ok) return json({ error: 'webhook failed' }, 502);
    const data = await r.json();
    const raw = Array.isArray(data) ? data[0] : data;
    return new Response(JSON.stringify(raw || {}), {
      headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
    });
  } catch(e) {
    return json({ error: e.message }, 500);
  }
}

export async function handleFortigateReboot(env) {
  const wh = whFrom(env, 'HOME_WH_FG_JSON', 'reboot', 'HOME_WH_FG_REBOOT');
  if (!wh) return json({ error: 'HOME_WH_FG_REBOOT not configured' }, 500);
  const n8nUser = cleanEnv(env.HOME_N8N_USER);
  const n8nPass = cleanEnv(env.HOME_N8N_PASS);
  const hdrs = { 'Content-Type': 'application/json' };
  if (n8nUser) hdrs['Authorization'] = 'Basic ' + btoa(unescape(encodeURIComponent(`${n8nUser}:${n8nPass}`)));
  try {
    const r = await fetch(wh, {
      method: 'POST',
      headers: hdrs,
      body: '{}',
      signal: AbortSignal.timeout(15000),
    });
    if (!r.ok) return json({ error: 'n8n upstream error', status: r.status }, 502);
    return new Response(await r.text(), {
      headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
    });
  } catch (e) {
    return json({ error: 'Failed to reach n8n', detail: e.message }, 502);
  }
}


/* ═══════════════════════════════════════════════
   ASUS Router — via n8n webhooks (local IP)
   ═══════════════════════════════════════════════ */


export async function handleAsusWebhook(env) {
  const n8nUser = cleanEnv(env.HOME_N8N_USER);
  const n8nPass = cleanEnv(env.HOME_N8N_PASS);
  const hdrs = { 'Content-Type': 'application/json' };
  if (n8nUser) hdrs['Authorization'] = 'Basic ' + btoa(unescape(encodeURIComponent(`${n8nUser}:${n8nPass}`)));
  const call = (url, ms = 15000) => {
    const u = cleanEnv(url);
    if (!u) return Promise.resolve(null);
    return fetch(u, { method: 'POST', headers: hdrs, body: '{}', signal: AbortSignal.timeout(ms) })
      .then(r => r.ok ? r.json() : null).catch(() => null);
  };
  const whMain    = whFrom(env, 'HOME_WH_ASUS_JSON', 'main', 'HOME_WH_ASUS_MAIN');
  const whClients = whFrom(env, 'HOME_WH_ASUS_JSON', 'clients', 'HOME_WH_ASUS_CLIENTS');
  if (!whMain) return json({ error: 'HOME_WH_ASUS_MAIN not configured' }, 500);
  const [main, clients] = await Promise.all([call(whMain), call(whClients)]);
  return new Response(JSON.stringify({
    system:         main?.system         || {},
    resources:      main?.resources      || {},
    wan:            main?.wan            || {},
    ddns:           main?.ddns           || {},
    wifi:           main?.wifi           || {},
    portForwarding: main?.portForwarding || { enabled: false, rules: [] },
    dhcpStatic:     main?.dhcpStatic     || [],
    vpn:            main?.vpn            || { server: { enabled: false }, client: { active: false, proto: '' } },
    aiProtection:   main?.aiProtection   || { enabled: false },
    qos:            main?.qos            || { enabled: false },
    clients:        clients?.clients     || [],
    stats:          { ...(main?.stats || {}), ...(clients?.stats || {}) },
  }), { headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' } });
}

export async function handleAsusClients(env) {
  const n8nUser = cleanEnv(env.HOME_N8N_USER);
  const n8nPass = cleanEnv(env.HOME_N8N_PASS);
  const hdrs = { 'Content-Type': 'application/json' };
  if (n8nUser) hdrs['Authorization'] = 'Basic ' + btoa(unescape(encodeURIComponent(`${n8nUser}:${n8nPass}`)));
  const whClients = whFrom(env, 'HOME_WH_ASUS_JSON', 'clients', 'HOME_WH_ASUS_CLIENTS');
  if (!whClients) return json({ error: 'HOME_WH_ASUS_CLIENTS not configured' }, 500);
  try {
    const r = await fetch(whClients, { method: 'POST', headers: hdrs, body: '{}', signal: AbortSignal.timeout(15000) });
    const d = r.ok ? await r.json() : null;
    return new Response(JSON.stringify({ clients: d?.clients || [], stats: d?.stats || {} }), { headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' } });
  } catch (e) {
    return json({ error: e.message }, 500);
  }
}

export async function handleAsusBw(env) {
  const n8nUser = cleanEnv(env.HOME_N8N_USER);
  const n8nPass = cleanEnv(env.HOME_N8N_PASS);
  const hdrs = { 'Content-Type': 'application/json' };
  if (n8nUser) hdrs['Authorization'] = 'Basic ' + btoa(unescape(encodeURIComponent(`${n8nUser}:${n8nPass}`)));
  const whMain = whFrom(env, 'HOME_WH_ASUS_JSON', 'main', 'HOME_WH_ASUS_MAIN');
  if (!whMain) return json({ error: 'HOME_WH_ASUS_MAIN not configured' }, 500);
  try {
    const r = await fetch(whMain, { method: 'POST', headers: hdrs, body: '{}', signal: AbortSignal.timeout(15000) });
    const d = r.ok ? await r.json() : null;
    return new Response(JSON.stringify({ wan: d?.wan || {} }), { headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' } });
  } catch (e) {
    return json({ error: e.message }, 500);
  }
}

export async function handleAsusReboot(request, env) {
  if (request.method !== 'POST') return json({ error: 'POST required' }, 405);
  const n8nUser = cleanEnv(env.HOME_N8N_USER);
  const n8nPass = cleanEnv(env.HOME_N8N_PASS);
  const whReboot = whFrom(env, 'HOME_WH_ASUS_JSON', 'reboot', 'HOME_WH_ASUS_REBOOT');
  if (!whReboot) return json({ error: 'HOME_WH_ASUS_REBOOT not configured' }, 500);
  const hdrs = { 'Content-Type': 'application/json' };
  if (n8nUser) hdrs['Authorization'] = 'Basic ' + btoa(unescape(encodeURIComponent(`${n8nUser}:${n8nPass}`)));
  try {
    await fetch(whReboot, { method: 'POST', headers: hdrs, body: '{}', signal: AbortSignal.timeout(20000) })
      .catch(() => {});
    return json({ success: true, message: 'Reboot command sent' });
  } catch (e) {
    return json({ success: true, message: 'Reboot command sent (router may have disconnected)' });
  }
}


/* ═══════════════════════════════════════════════
   Web Proxy — fetch any HTTPS URL, strip frame-blocking headers
   so it can be embedded in an iframe on the dashboard
   ═══════════════════════════════════════════════ */

/* ═══════════════════════════════════════════════
   FortiGate POOL — cấp phát container Chrome theo người dùng.
   Quyền 'services-hub: read' → truy cập slot admin (slot view để reserved).
   Mỗi slot = 1 container (kasm = màn hình, nav = điều khiển đổi site).
   Thêm slot khi anh Thoai tạo container + tunnel tương ứng.
   ═══════════════════════════════════════════════ */
