/* ═══════════════════════════════════════════════
   home-services.js — split out of worker.js (2026-07-01). Logic UNCHANGED.
   ═══════════════════════════════════════════════ */
import {
  RUSTDESK_BASE,
  cleanEnv,
  json
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

/* ═══════════════════════════════════════════════
   RustDesk — self-hosted (lejianwen/rustdesk-api)
   Login lấy token (cache KV 1h), liệt kê peers + groups.
   Token header = "api-token" (KHÔNG phải Authorization: Bearer)
   ═══════════════════════════════════════════════ */
export async function rustdeskToken(env) {
  const cached = await env.DASHBOARD_KV.get('rustdesk_token');
  if (cached) return cached;
  const user = cleanEnv(env.RUSTDESK_ADMIN_USER);
  const pass = cleanEnv(env.RUSTDESK_ADMIN_PASS);
  if (!user || !pass) throw new Error('RUSTDESK_ADMIN_USER / RUSTDESK_ADMIN_PASS chưa cấu hình');
  const r = await fetch(`${RUSTDESK_BASE}/api/admin/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: user, password: pass }),
    signal: AbortSignal.timeout(20000),
  });
  if (!r.ok) throw new Error(`RustDesk login failed: ${r.status}`);
  const d = await r.json();
  const token = d?.data?.token;
  if (!token) throw new Error('Không nhận được token từ RustDesk');
  await env.DASHBOARD_KV.put('rustdesk_token', token, { expirationTtl: 3600 });
  return token;
}

export async function handleRustdesk(env) {
  let token;
  try { token = await rustdeskToken(env); }
  catch (e) { return json({ error: e.message }, 502); }

  const api = async (path) => {
    const call = (tk) => fetch(`${RUSTDESK_BASE}${path}`, {
      headers: { 'api-token': tk },
      signal: AbortSignal.timeout(20000),
    });
    let r = await call(token);
    if (r.status === 401 || r.status === 403) {
      // token hết hạn → xóa cache, login lại 1 lần
      await env.DASHBOARD_KV.delete('rustdesk_token');
      try { token = await rustdeskToken(env); } catch { return null; }
      r = await call(token);
    }
    return r.ok ? r.json() : null;
  };

  const [peerRaw, groupRaw, connRaw, userRaw, loginRaw, fileRaw] = await Promise.all([
    api('/api/admin/peer/list?page=1&page_size=200'),
    api('/api/admin/group/list?page=1&page_size=100'),
    api('/api/admin/audit_conn/list?page=1&page_size=60'),
    api('/api/admin/user/list?page=1&page_size=1'),
    api('/api/admin/login_log/list?page=1&page_size=30'),
    api('/api/admin/audit_file/list?page=1&page_size=40'),
  ]);

  if (!peerRaw) return json({ error: 'Không lấy được danh sách máy từ RustDesk' }, 502);

  const groups = {};
  (groupRaw?.data?.list || []).forEach(g => { groups[g.id] = g.name; });

  const now = Math.floor(Date.now() / 1000);
  const rawPeers = peerRaw?.data?.list || [];

  // map peer_id → tên hiển thị để dịch connection log
  const peerName = {};
  rawPeers.forEach(p => { peerName[p.id] = p.alias || p.hostname || p.id; });

  const devices = rawPeers.map(p => ({
    id:         p.id,
    hostname:   p.hostname || p.id,
    alias:      p.alias || '',
    username:   p.username || '',
    os:         p.os || '',
    cpu:        (p.cpu || '').replace(/\s+/g, ' ').trim(),
    memory:     p.memory || '',
    version:    p.version || '',
    lastOnline: p.last_online_time || 0,
    lastIp:     p.last_online_ip || '',
    firstSeen:  p.created_at || '',
    group:      groups[p.group_id] || '',
    online:     p.last_online_time ? (now - p.last_online_time) < 60 : false,
  }));

  // ── Connection log: chuẩn hoá + dịch peer_id sang tên ──
  const _toEpoch = (s) => {
    if (!s) return 0;
    // "2026-06-13 12:15:49" (server giờ Asia/Shanghai) → epoch xấp xỉ để tính thời lượng
    const m = /^(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2}):(\d{2})/.exec(s);
    if (!m) return 0;
    return Math.floor(Date.UTC(+m[1], +m[2]-1, +m[3], +m[4], +m[5], +m[6]) / 1000);
  };
  const connections = (connRaw?.data?.list || []).map(c => {
    const start = _toEpoch(c.created_at);
    const end = c.close_time || 0;
    let dur = (end && start && end > start) ? (end - start) : 0;
    if (dur > 86400 * 7) dur = 0; // bỏ giá trị vô lý
    return {
      id:        c.id,
      toPeer:    c.peer_id || '',
      toName:    peerName[c.peer_id] || c.peer_id || '',
      fromPeer:  c.from_peer || '',
      fromName:  c.from_name || (c.from_peer ? (peerName[c.from_peer] || c.from_peer) : ''),
      ip:        c.ip || '',
      startStr:  c.created_at || '',
      duration:  dur,
      hasSession: c.session_id && c.session_id !== '0',
    };
  });

  // ── Login log (đăng nhập admin panel) ──
  const logins = (loginRaw?.data?.list || []).map(l => ({
    id:       l.id,
    client:   l.client || '',
    type:     l.type || '',
    ip:       l.ip || '',
    platform: l.platform || '',
    deviceId: l.device_id || '',
    at:       l.created_at || '',
  }));

  // ── File transfer log ──
  const fileTransfers = (fileRaw?.data?.list || []).map(f => ({
    id:       f.id,
    toPeer:   f.peer_id || '',
    toName:   peerName[f.peer_id] || f.peer_id || '',
    fromPeer: f.from_peer || '',
    fromName: f.from_name || (f.from_peer ? (peerName[f.from_peer] || f.from_peer) : ''),
    ip:       f.ip || '',
    isFile:   !!f.is_file,
    path:     f.path || '',
    info:     f.info || '',
    num:      f.num || 0,
    type:     f.type,          // hướng truyền (gửi/nhận)
    at:       f.created_at || '',
  }));

  const onlineCount = devices.filter(d => d.online).length;
  const grpSet = {}; devices.forEach(d => { if (d.group) grpSet[d.group] = 1; });
  // số phiên remote thật trong hôm nay (theo ngày server)
  const todayStr = (connRaw?.data?.list || [])[0]?.created_at?.slice(0, 10) || '';
  const connToday = connections.filter(c => c.hasSession && c.startStr.slice(0, 10) === todayStr).length;

  const osCount = {};
  devices.forEach(d => {
    const o = (d.os || '').toLowerCase();
    const k = o.indexOf('windows') >= 0 ? 'Windows'
            : (o.indexOf('mac') >= 0 || o.indexOf('darwin') >= 0) ? 'macOS'
            : o.indexOf('android') >= 0 ? 'Android'
            : (o.indexOf('linux') >= 0) ? 'Linux' : 'Khác';
    osCount[k] = (osCount[k] || 0) + 1;
  });

  return json({
    devices,
    connections,
    logins,
    fileTransfers,
    stats: {
      total:    devices.length,
      online:   onlineCount,
      offline:  devices.length - onlineCount,
      groups:   Object.keys(grpSet).length,
      users:    userRaw?.data?.total || 0,
      connToday,
      connTotal: connRaw?.data?.total || connections.length,
      fileTotal: fileRaw?.data?.total || 0,
      loginTotal: loginRaw?.data?.total || 0,
      os:       osCount,
    },
    fetchedAt: now,
  });
}

/* ═══════════════════════════════════════════════
   VMware Home — via n8n webhook (SOAP handled by n8n)
   ═══════════════════════════════════════════════ */
export async function handleVmwareHome(env) {
  const n8nUser = cleanEnv(env.HOME_N8N_USER);
  const n8nPass = cleanEnv(env.HOME_N8N_PASS);
  const wh      = cleanEnv(env.HOME_WH_VMWARE_DATA);
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
  const wh      = cleanEnv(env.HOME_WH_VMWARE_POWER);
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
   Movi VMware — n8n webhook proxy (thay thế SOAP trực tiếp)
   Secrets: MOVI_WH_VMWARE01_DATA, MOVI_WH_VMWARE01_POWER
            MOVI_WH_VMWARE02_DATA, MOVI_WH_VMWARE02_POWER
            Auth: MOVI_N8N_USER / MOVI_N8N_PASS
   ═══════════════════════════════════════════════ */
export async function handleMoviVmwareData(env, hostNum) {
  const moviUser = cleanEnv(env.MOVI_N8N_USER);
  const moviPass = cleanEnv(env.MOVI_N8N_PASS);
  const wh = cleanEnv(env[`MOVI_WH_VMWARE0${hostNum}_DATA`]);
  if (!wh) return json({ error: `MOVI_WH_VMWARE0${hostNum}_DATA not configured` }, 500);
  const hdrs = { 'Content-Type': 'application/json' };
  if (moviUser) hdrs['Authorization'] = 'Basic ' + btoa(unescape(encodeURIComponent(`${moviUser}:${moviPass}`)));
  try {
    const resp = await fetch(wh, { headers: hdrs, signal: AbortSignal.timeout(30000) });
    if (!resp.ok) { const t = await resp.text(); return json({ error: `n8n error ${resp.status}: ${t.slice(0,200)}` }, 502); }
    const raw = await resp.json();
    return json(Array.isArray(raw) ? raw[0] : raw);
  } catch (e) { return json({ error: 'Failed to reach n8n', detail: e.message }, 502); }
}

export async function handleMoviVmwarePower(request, env, hostNum) {
  if (request.method !== 'POST') return json({ error: 'POST required' }, 405);
  const moviUser = cleanEnv(env.MOVI_N8N_USER);
  const moviPass = cleanEnv(env.MOVI_N8N_PASS);
  const wh = cleanEnv(env[`MOVI_WH_VMWARE0${hostNum}_POWER`]);
  if (!wh) return json({ error: `MOVI_WH_VMWARE0${hostNum}_POWER not configured` }, 500);
  let body;
  try { body = await request.json(); } catch { return json({ error: 'Invalid JSON body' }, 400); }
  const hdrs = { 'Content-Type': 'application/json' };
  if (moviUser) hdrs['Authorization'] = 'Basic ' + btoa(unescape(encodeURIComponent(`${moviUser}:${moviPass}`)));
  try {
    const resp = await fetch(wh, { method: 'POST', headers: hdrs, body: JSON.stringify(body), signal: AbortSignal.timeout(30000) });
    if (!resp.ok) { const t = await resp.text(); return json({ error: `n8n error ${resp.status}: ${t.slice(0,200)}` }, 502); }
    const raw = await resp.json();
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

  const whSys    = cleanEnv(env.HOME_WH_FG_SYSTEM);
  const whRes    = cleanEnv(env.HOME_WH_FG_RESOURCES);
  const whIface  = cleanEnv(env.HOME_WH_FG_INTERFACES);
  const whVpn    = cleanEnv(env.HOME_WH_FG_VPN);
  const whSsl    = cleanEnv(env.HOME_WH_FG_SSL);
  const whPolicy = cleanEnv(env.HOME_WH_FG_POLICIES);
  const whDdns   = cleanEnv(env.HOME_WH_FG_DDNS);

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
  const whIface = cleanEnv(env.HOME_WH_FG_INTERFACES);
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
  const wh = cleanEnv(env.HOME_WH_FG_REBOOT);
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
  const whMain    = cleanEnv(env.HOME_WH_ASUS_MAIN);
  const whClients = cleanEnv(env.HOME_WH_ASUS_CLIENTS);
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
  const whClients = cleanEnv(env.HOME_WH_ASUS_CLIENTS);
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
  const whMain = cleanEnv(env.HOME_WH_ASUS_MAIN);
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
  const whReboot = cleanEnv(env.HOME_WH_ASUS_REBOOT);
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
