/* ═══════════════════════════════════════════════
   meraki.js — split out of worker.js (2026-07-01). Logic UNCHANGED.
   ═══════════════════════════════════════════════ */
import {
  cleanEnv,
  getSession,
  hasPerm,
  hasWritePerm,
  json,
  logActivity,
  moviN8nAuth
} from './core.js';

export async function handleMerakiDevices(request, env) {
  const session = await getSession(request, env);
  if (!session) return json({ error: 'Unauthorized' }, 401);
  if (!(await hasPerm(env, session, 'meraki'))) return json({ error: 'Không có quyền truy cập Meraki' }, 403);

  const N8N_URL  = cleanEnv(env.MOVI_WH_MERAKI_DEVICES);
  const N8N_AUTH = moviN8nAuth(env);

  try {
    const resp = await fetch(N8N_URL, { headers: { 'Authorization': N8N_AUTH } });
    if (!resp.ok) return json({ error: 'n8n upstream error', status: resp.status }, 502);
    const raw = await resp.json();

    // n8n trả raw array, transform thành format chuẩn
    const list = Array.isArray(raw) ? raw : (raw.devices || []);
    const TYPE_ICON = { switch: '🔀', wireless: '📡', appliance: '🔥', camera: '📷' };

    const devices = list.map(function(d) {
      const ip = d.lanIp || d.wan1Ip || d.wan2Ip || '—';
      // Nếu firmware chứa "Not running configured version" → coi là cần chú ý
      const firmwareOk = d.firmware && !d.firmware.includes('Not running');
      return {
        name:       d.name || '—',
        mac:        d.mac  || null,
        model:      d.model || '—',
        serial:     d.serial || '—',
        lanIp:      ip,
        productType: d.productType || 'switch',
        typeIcon:   TYPE_ICON[d.productType] || '📦',
        tags:       Array.isArray(d.tags) ? d.tags : (d.tags ? String(d.tags).split(',').map(function(t){return t.trim();}).filter(Boolean) : []),
        firmware:   d.firmware || '—',
        firmwareOk: firmwareOk,
        status:     firmwareOk ? 'online' : 'alerting',
        lastReportedAt: d.configurationUpdatedAt || null,
        url:        d.url || null,
      };
    });

    return json({ devices, total: devices.length, fetchedAt: new Date().toISOString() });
  } catch (e) {
    return json({ error: 'Failed to reach n8n', detail: e.message }, 502);
  }
}

/* ── Meraki Clients Proxy ── */
export async function handleMerakiClients(request, env) {
  const session = await getSession(request, env);
  if (!session) return json({ error: 'Unauthorized' }, 401);
  if (!(await hasPerm(env, session, 'meraki'))) return json({ error: 'Không có quyền truy cập Meraki' }, 403);

  const N8N_URL  = cleanEnv(env.MOVI_WH_MERAKI_CLIENTS);
  const N8N_AUTH = moviN8nAuth(env);

  try {
    const resp = await fetch(N8N_URL, {
      headers: { 'Authorization': N8N_AUTH },
      cf: { cacheTtl: 60, cacheEverything: false },
    });
    if (!resp.ok) return json({ error: 'n8n upstream error', status: resp.status }, 502);
    const data = await resp.json();
    // n8n trả array, lấy phần tử đầu
    const payload = Array.isArray(data) ? data[0] : data;
    // Normalize raw Meraki client fields that the API doesn't return
    const rawList = Array.isArray(payload) ? payload : (payload.clients || []);
    const clients = rawList.map(c => {
      const wired  = c.recentDeviceConnection === 'Wired' || !c.ssid;
      const online = c.status === 'Online';
      const recv   = (c.usage && c.usage.recv) || 0;
      const sent   = (c.usage && c.usage.sent) || 0;
      return {
        ...c,
        name:   c.name   || c.description || c.mac,
        ssid:   c.ssid   || (wired ? 'Wired' : '—'),
        signal: c.signal != null ? c.signal : (wired ? 0 : online ? 3 : 1),
        rxKbps: c.rxKbps != null ? c.rxKbps : Math.round(recv / 10),
        txKbps: c.txKbps != null ? c.txKbps : Math.round(sent / 10),
      };
    });
    return json({ clients });
  } catch (e) {
    return json({ error: 'Failed to reach n8n', detail: e.message }, 502);
  }
}

/* ── Meraki Client Policy: block / unblock — meraki:write required ── */
export async function handleMerakiClientPolicy(request, env) {
  const session = await getSession(request, env);
  if (!session) return json({ error: 'Unauthorized' }, 401);
  if (!(await hasWritePerm(env, session, 'meraki'))) return json({ error: 'Cần quyền meraki:write để thực hiện thao tác này' }, 403);
  if (request.method !== 'POST') return json({ error: 'Method not allowed' }, 405);

  let body;
  try { body = await request.json(); } catch (e) { return json({ error: 'Invalid JSON body' }, 400); }
  const mac = String((body && body.mac) || '').trim().toLowerCase();
  const policy = String((body && body.policy) || '').trim();
  const MAC_RE = /^[0-9a-f]{2}([:-]?)([0-9a-f]{2}\1){4}[0-9a-f]{2}$/;
  if (!MAC_RE.test(mac)) return json({ error: 'MAC không hợp lệ' }, 400);
  if (policy !== 'Blocked' && policy !== 'Normal') {
    return json({ error: "policy phải là 'Blocked' hoặc 'Normal'" }, 400);
  }

  const N8N_URL  = cleanEnv(env.MOVI_WH_MERAKI_CLIENT_POLICY);
  const N8N_AUTH = moviN8nAuth(env);
  try {
    const resp = await fetch(N8N_URL, {
      method: 'POST',
      headers: { 'Authorization': N8N_AUTH, 'Content-Type': 'application/json' },
      body: JSON.stringify({ mac, policy }),
      signal: AbortSignal.timeout(30000),
    });
    const text = await resp.text();
    if (!resp.ok) {
      return json({ error: 'n8n upstream error', status: resp.status, detail: text.slice(0, 300) }, 502);
    }
    let data; try { data = JSON.parse(text); } catch (e) { data = { raw: text }; }
    const payload = Array.isArray(data) ? data[0] : data;
    // Persist blocked-clients list in KV
    try {
      const bl = await env.DASHBOARD_KV.get('meraki_blocked_clients', 'json') || [];
      if (policy === 'Blocked') {
        if (!bl.find(b => b.mac === mac)) {
          bl.push({
            mac,
            name: String((body && body.name) || '').trim() || mac,
            ip: String((body && body.ip) || '').trim() || '—',
            blockedAt: new Date().toISOString(),
            blockedBy: session.username,
          });
        }
      } else {
        const idx = bl.findIndex(b => b.mac === mac);
        if (idx !== -1) bl.splice(idx, 1);
      }
      await env.DASHBOARD_KV.put('meraki_blocked_clients', JSON.stringify(bl));
    } catch (e) {}
    // Log the admin action for auditing
    await logActivity(env, { action: 'meraki-client-policy', username: session.username, ip: request.headers.get('CF-Connecting-IP') || '?', success: true, detail: `${policy} client ${mac}` });
    return json({ success: true, mac, policy, result: payload });
  } catch (e) {
    return json({ error: 'Failed to reach n8n', detail: e.message }, 502);
  }
}

/* ── Meraki Blocked Clients list (GET) — meraki:write required ── */
export async function handleMerakiBlockedClients(request, env) {
  const session = await getSession(request, env);
  if (!session) return json({ error: 'Unauthorized' }, 401);
  if (!(await hasWritePerm(env, session, 'meraki'))) return json({ error: 'Cần quyền meraki:write để xem danh sách chặn' }, 403);
  const list = await env.DASHBOARD_KV.get('meraki_blocked_clients', 'json') || [];
  return json({ blocked: list });
}

/* ── Meraki Device Status Proxy ── */
export async function handleMerakiDeviceStatus(request, env) {
  const session = await getSession(request, env);
  if (!session) return json({ error: 'Unauthorized' }, 401);
  if (!(await hasPerm(env, session, 'meraki'))) return json({ error: 'Không có quyền truy cập Meraki' }, 403);

  const N8N_URL  = cleanEnv(env.MOVI_WH_MERAKI_DEV_STATUS);
  const N8N_AUTH = moviN8nAuth(env);

  try {
    const resp = await fetch(N8N_URL, { headers: { 'Authorization': N8N_AUTH } });
    if (!resp.ok) return json({ error: 'n8n upstream error', status: resp.status }, 502);
    const raw = await resp.json();
    // n8n trả [{ devices: [...] }] hoặc raw array
    const first = Array.isArray(raw) ? raw[0] : raw;
    const list = (first && first.devices) || (first && first.statuses) || (Array.isArray(raw) ? raw : []);

    const statuses = list.map(d => ({
      name:           d.name || '—',
      serial:         d.serial || '—',
      model:          d.model || '—',
      productType:    d.productType || '—',
      status:         d.status || 'offline',
      publicIp:       d.publicIp || '—',
      lastReportedAt: d.lastReportedAt || null,
    }));

    const online   = statuses.filter(d => d.status === 'online').length;
    const offline  = statuses.filter(d => d.status === 'offline').length;
    const alerting = statuses.filter(d => d.status === 'alerting').length;
    const dormant  = statuses.filter(d => d.status === 'dormant').length;

    return json({ statuses, total: statuses.length, online, offline, alerting, dormant, fetchedAt: new Date().toISOString() });
  } catch (e) {
    return json({ error: 'Failed to reach n8n', detail: e.message }, 502);
  }
}

/* ── Meraki Switch Ports (via n8n webhook) ── */
export async function handleMerakiSwitchPorts(request, env) {
  const session = await getSession(request, env);
  if (!session) return json({ error: 'Unauthorized' }, 401);
  if (!(await hasPerm(env, session, 'meraki'))) return json({ error: 'Không có quyền truy cập Meraki' }, 403);
  const N8N_URL  = cleanEnv(env.MOVI_WH_MERAKI_SW_PORTS);
  const N8N_AUTH = moviN8nAuth(env);
  try {
    const resp = await fetch(N8N_URL, { headers: { 'Authorization': N8N_AUTH }, signal: AbortSignal.timeout(60000) });
    if (!resp.ok) return json({ error: 'n8n upstream error', status: resp.status }, 502);
    const raw = await resp.json();
    const switches = Array.isArray(raw) ? raw : [raw];
    const totalPorts     = switches.reduce((s, sw) => s + (sw.totalPorts || 0), 0);
    const connectedPorts = switches.reduce((s, sw) => s + (sw.connectedPorts || 0), 0);
    const errorPorts     = switches.reduce((s, sw) => s + (sw.errorPorts || 0), 0);
    const deadSwitches   = switches.filter(sw => sw.connectedPorts === 0).length;
    return json({ switches, totalSwitches: switches.length, totalPorts, connectedPorts, errorPorts, deadSwitches, fetchedAt: new Date().toISOString() });
  } catch (e) {
    return json({ error: 'Failed to reach n8n', detail: e.message + ' (timeout 90s)', }, 502);
  }
}

/* ── Meraki Switch Port Configs (W5b) ── */
export async function handleMerakiSwitchPortConfigs(request, env) {
  const session = await getSession(request, env);
  if (!session) return json({ error: 'Unauthorized' }, 401);
  if (!(await hasPerm(env, session, 'meraki'))) return json({ error: 'Không có quyền truy cập Meraki' }, 403);
  const N8N_URL  = cleanEnv(env.MOVI_WH_MERAKI_PORT_CFG);
  const N8N_AUTH = moviN8nAuth(env);
  try {
    const resp = await fetch(N8N_URL, { headers: { 'Authorization': N8N_AUTH }, signal: AbortSignal.timeout(50000) });
    if (!resp.ok) return json({ error: 'n8n upstream error', status: resp.status }, 502);
    const raw = await resp.json();
    const configs = Array.isArray(raw) ? raw : [raw];
    return json({ configs, fetchedAt: new Date().toISOString() });
  } catch (e) {
    return json({ error: 'Failed to reach n8n', detail: e.message }, 502);
  }
}

/* ── Meraki Link Aggregations (W5c) ── */
export async function handleMerakiLinkAggregations(request, env) {
  const session = await getSession(request, env);
  if (!session) return json({ error: 'Unauthorized' }, 401);
  if (!(await hasPerm(env, session, 'meraki'))) return json({ error: 'Không có quyền truy cập Meraki' }, 403);
  const N8N_URL  = cleanEnv(env.MOVI_WH_MERAKI_LINK_AGG);
  const N8N_AUTH = moviN8nAuth(env);
  try {
    const resp = await fetch(N8N_URL, {
      headers: { 'Authorization': N8N_AUTH },
      signal: AbortSignal.timeout(60000)   // 60s — loop qua nhiều networks có thể chậm hơn
    });
    if (!resp.ok) return json({ error: 'n8n upstream error', status: resp.status }, 502);
    const raw  = await resp.json();
    const data = Array.isArray(raw) ? raw[0] : raw;
    return json({
      aggregations: data.aggregations || [],   // [ { id, label, networkId, memberCount, members[] } ]
      portMap:      data.portMap      || {},    // { "serial:portId": { aggId, label, memberCount, members[] } }
      aggIndex:     data.aggIndex     || {},    // { aggId: { label, networkId, members[] } }
      totalGroups:  data.totalGroups  || 0,
      totalPorts:   data.totalPorts   || 0,
      fetchedAt:    data.fetchedAt    || new Date().toISOString()
    });
  } catch (e) {
    return json({ error: 'Failed to reach n8n', detail: e.message }, 502);
  }
}

/* ── Meraki WAN Uplinks (W6a) ── */
export async function handleMerakiUplinks(request, env) {
  const session = await getSession(request, env);
  if (!session) return json({ error: 'Unauthorized' }, 401);
  if (!(await hasPerm(env, session, 'meraki'))) return json({ error: 'Không có quyền truy cập Meraki' }, 403);
  const N8N_URL  = cleanEnv(env.MOVI_WH_MERAKI_UPLINKS);
  const N8N_AUTH = moviN8nAuth(env);
  try {
    const resp = await fetch(N8N_URL, {
      headers: { 'Authorization': N8N_AUTH },
      signal: AbortSignal.timeout(30000)
    });
    if (!resp.ok) return json({ error: 'n8n upstream error', status: resp.status }, 502);
    const raw  = await resp.json();
    const data = Array.isArray(raw) ? raw[0] : raw;
    return json({
      devices:     data.devices     || [],
      totalActive: data.totalActive || 0,
      totalDown:   data.totalDown   || 0,
      fetchedAt:   data.fetchedAt   || new Date().toISOString()
    });
  } catch (e) {
    return json({ error: 'Failed to reach n8n', detail: e.message }, 502);
  }
}

/* ── Meraki L3 Switch Routing (W6b) — SVIs + Static Routes ── */
export async function handleMerakiL3Routing(request, env) {
  const session = await getSession(request, env);
  if (!session) return json({ error: 'Unauthorized' }, 401);
  if (!(await hasPerm(env, session, 'meraki'))) return json({ error: 'Không có quyền truy cập Meraki' }, 403);
  const N8N_URL  = cleanEnv(env.MOVI_WH_MERAKI_L3);
  const N8N_AUTH = moviN8nAuth(env);
  try {
    const resp = await fetch(N8N_URL, {
      headers: { 'Authorization': N8N_AUTH },
      signal: AbortSignal.timeout(60000)   // loop nhiều switches có thể chậm
    });
    if (!resp.ok) return json({ error: 'n8n upstream error', status: resp.status }, 502);
    const raw  = await resp.json();
    const data = Array.isArray(raw) ? raw[0] : raw;
    return json({
      interfaces:    data.interfaces    || [],   // SVIs (VLAN interfaces với IP)
      staticRoutes:  data.staticRoutes  || [],   // L3 static routes trên switch
      totalInterfaces: data.totalInterfaces || 0,
      totalRoutes:     data.totalRoutes     || 0,
      fetchedAt:       data.fetchedAt       || new Date().toISOString()
    });
  } catch (e) {
    return json({ error: 'Failed to reach n8n', detail: e.message }, 502);
  }
}

/* ── Meraki Events Proxy ── */
export async function handleMerakiEvents(request, env) {
  const session = await getSession(request, env);
  if (!session) return json({ error: 'Unauthorized' }, 401);
  if (!(await hasPerm(env, session, 'meraki'))) return json({ error: 'Không có quyền truy cập Meraki' }, 403);

  const N8N_URL  = cleanEnv(env.MOVI_WH_MERAKI_EVENTS);
  const N8N_AUTH = moviN8nAuth(env);

  try {
    const resp = await fetch(N8N_URL, { headers: { 'Authorization': N8N_AUTH } });
    if (!resp.ok) return json({ error: 'n8n upstream error', status: resp.status }, 502);
    const raw = await resp.json();
    // Code Node trả { events, total, high, medium, fetchedAt }
    const payload = Array.isArray(raw) ? raw[0] : raw;
    return json(payload);
  } catch (e) {
    return json({ error: 'Failed to reach n8n', detail: e.message }, 502);
  }
}

/* ── FortiGate Movi — SD-WAN Rules ── */
export async function handleMoviSdwanRules(request, env) {
  const session = await getSession(request, env);
  if (!session) return json({ error: 'Unauthorized' }, 401);
  if (!(await hasPerm(env, session, 'fortigate-movi'))) return json({ error: 'Không có quyền truy cập FortiGate Movi' }, 403);
  const N8N_URL  = cleanEnv(env.MOVI_WH_FG_SDWAN_RULES);
  const N8N_AUTH = moviN8nAuth(env);
  try {
    const resp = await fetch(N8N_URL, { headers: { 'Authorization': N8N_AUTH }, signal: AbortSignal.timeout(15000) });
    if (!resp.ok) return json({ error: 'n8n upstream error', status: resp.status }, 502);
    const raw  = await resp.json();
    const data = Array.isArray(raw) ? raw[0] : raw;
    return json({
      rules:     data.rules    || [],
      total:     data.total    || 0,
      enabled:   data.enabled  || 0,
      fetchedAt: data.fetchedAt || new Date().toISOString()
    });
  } catch (e) {
    return json({ error: 'Failed to reach n8n', detail: e.message }, 502);
  }
}

/* ── FortiGate Movi — SD-WAN Members ── */
export async function handleMoviSdwan(request, env) {
  const session = await getSession(request, env);
  if (!session) return json({ error: 'Unauthorized' }, 401);
  if (!(await hasPerm(env, session, 'fortigate-movi'))) return json({ error: 'Không có quyền truy cập FortiGate Movi' }, 403);
  const N8N_URL  = cleanEnv(env.MOVI_WH_FG_SDWAN_MEMBERS);
  const N8N_AUTH = moviN8nAuth(env);
  try {
    const resp = await fetch(N8N_URL, { headers: { 'Authorization': N8N_AUTH }, signal: AbortSignal.timeout(15000) });
    if (!resp.ok) return json({ error: 'n8n upstream error', status: resp.status }, 502);
    const raw  = await resp.json();
    const data = Array.isArray(raw) ? raw[0] : raw;
    return json({
      members:   data.members   || [],
      total:     data.total     || 0,
      zone:      data.zone      || '',
      fetchedAt: data.fetchedAt || new Date().toISOString()
    });
  } catch (e) {
    return json({ error: 'Failed to reach n8n', detail: e.message }, 502);
  }
}

/* ── Camera Movi — Aliases (admin rename) ── */
