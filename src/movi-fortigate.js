/* ═══════════════════════════════════════════════
   movi-fortigate.js — split out of worker.js (2026-07-01). Logic UNCHANGED.
   ═══════════════════════════════════════════════ */
import {
  cleanEnv,
  getSession,
  hasPerm,
  hasWritePerm,
  json,
  moviN8nAuth
} from './core.js';

export async function handleMoviInterfaces(request, env) {
  const session = await getSession(request, env);
  if (!session) return json({ error: 'Unauthorized' }, 401);
  if (!(await hasPerm(env, session, 'fortigate-movi'))) return json({ error: 'Không có quyền truy cập FortiGate Movi' }, 403);
  const N8N_URL  = cleanEnv(env.MOVI_WH_FG_INTERFACES);
  const N8N_AUTH = moviN8nAuth(env);
  try {
    const resp = await fetch(N8N_URL, {
      headers: { 'Authorization': N8N_AUTH },
      signal: AbortSignal.timeout(15000)
    });
    if (!resp.ok) return json({ error: 'n8n upstream error', status: resp.status }, 502);
    const raw  = await resp.json();
    const data = Array.isArray(raw) ? raw[0] : raw;
    return json({
      interfaces: data.interfaces || [],
      ts:         data.ts         || Date.now(),
      fetchedAt:  data.fetchedAt  || new Date().toISOString()
    });
  } catch (e) {
    return json({ error: 'Failed to reach n8n', detail: e.message }, 502);
  }
}

/* ── FortiGate Movi — Firewall Policy Hit ── */
export async function handleMoviPolicy(request, env) {
  const session = await getSession(request, env);
  if (!session) return json({ error: 'Unauthorized' }, 401);
  if (!(await hasPerm(env, session, 'fortigate-movi'))) return json({ error: 'Không có quyền truy cập FortiGate Movi' }, 403);
  const N8N_URL  = cleanEnv(env.MOVI_WH_FG_POLICY);
  const N8N_AUTH = moviN8nAuth(env);
  try {
    const resp = await fetch(N8N_URL, { headers: { 'Authorization': N8N_AUTH }, signal: AbortSignal.timeout(15000) });
    if (!resp.ok) return json({ error: 'n8n upstream error', status: resp.status }, 502);
    const raw  = await resp.json();
    const data = Array.isArray(raw) ? raw[0] : raw;
    return json({ policies: data.policies || [], total: data.total || 0, fetchedAt: data.fetchedAt || new Date().toISOString() });
  } catch (e) { return json({ error: 'Failed to reach n8n', detail: e.message }, 502); }
}

/* ── FortiGate Movi — Routing Table ── */
export async function handleMoviDhcp(request, env) {
  const session = await getSession(request, env);
  if (!session) return json({ error: 'Unauthorized' }, 401);
  if (!(await hasPerm(env, session, 'fortigate-movi'))) return json({ error: 'Không có quyền truy cập FortiGate Movi' }, 403);
  const N8N_URL  = cleanEnv(env.MOVI_WH_FG_ROUTING);
  const N8N_AUTH = moviN8nAuth(env);
  try {
    const resp = await fetch(N8N_URL, { headers: { 'Authorization': N8N_AUTH }, signal: AbortSignal.timeout(15000) });
    if (!resp.ok) return json({ error: 'n8n upstream error', status: resp.status }, 502);
    const raw  = await resp.json();
    const data = Array.isArray(raw) ? raw[0] : raw;
    return json({ routes: data.routes || data.leases || [], total: data.total || 0, fetchedAt: data.fetchedAt || new Date().toISOString() });
  } catch (e) { return json({ error: 'Failed to reach n8n', detail: e.message }, 502); }
}

/* ── FortiGate Movi — SSL VPN ── */
export async function handleMoviSslVpn(request, env) {
  const session = await getSession(request, env);
  if (!session) return json({ error: 'Unauthorized' }, 401);
  if (!(await hasPerm(env, session, 'fortigate-movi'))) return json({ error: 'Không có quyền truy cập FortiGate Movi' }, 403);
  const N8N_URL  = cleanEnv(env.MOVI_WH_FG_SSL_VPN);
  const N8N_AUTH = moviN8nAuth(env);
  try {
    const resp = await fetch(N8N_URL, {
      headers: { 'Authorization': N8N_AUTH },
      signal: AbortSignal.timeout(15000)
    });
    if (!resp.ok) return json({ error: 'n8n upstream error', status: resp.status }, 502);
    const raw  = await resp.json();
    const data = Array.isArray(raw) ? raw[0] : raw;
    return json({
      sessions:  data.sessions  || [],
      total:     data.total     || 0,
      fetchedAt: data.fetchedAt || new Date().toISOString()
    });
  } catch (e) {
    return json({ error: 'Failed to reach n8n', detail: e.message }, 502);
  }
}

/* ── FortiGate Movi — VPN IPSec ── */
export async function handleMoviVpn(request, env) {
  const session = await getSession(request, env);
  if (!session) return json({ error: 'Unauthorized' }, 401);
  if (!(await hasPerm(env, session, 'fortigate-movi'))) return json({ error: 'Không có quyền truy cập FortiGate Movi' }, 403);
  const N8N_URL  = cleanEnv(env.MOVI_WH_FG_VPN);
  const N8N_AUTH = moviN8nAuth(env);
  try {
    const resp = await fetch(N8N_URL, {
      headers: { 'Authorization': N8N_AUTH },
      signal: AbortSignal.timeout(15000)
    });
    if (!resp.ok) return json({ error: 'n8n upstream error', status: resp.status }, 502);
    const raw  = await resp.json();
    const data = Array.isArray(raw) ? raw[0] : raw;
    return json({
      tunnels:  data.tunnels  || [],
      total:    data.total    || 0,
      up:       data.up       || 0,
      down:     data.down     || 0,
      fetchedAt: data.fetchedAt || new Date().toISOString()
    });
  } catch (e) {
    return json({ error: 'Failed to reach n8n', detail: e.message }, 502);
  }
}

/* ── FortiGate Movi — License ── */
export async function handleMoviLicense(request, env) {
  const session = await getSession(request, env);
  if (!session) return json({ error: 'Unauthorized' }, 401);
  if (!(await hasPerm(env, session, 'fortigate-movi'))) return json({ error: 'Không có quyền truy cập FortiGate Movi' }, 403);
  const N8N_URL  = cleanEnv(env.MOVI_WH_FG_LICENSE);
  const N8N_AUTH = moviN8nAuth(env);
  try {
    const resp = await fetch(N8N_URL, {
      headers: { 'Authorization': N8N_AUTH },
      signal: AbortSignal.timeout(15000)
    });
    if (!resp.ok) return json({ error: 'n8n upstream error', status: resp.status }, 502);
    const raw  = await resp.json();
    const data = Array.isArray(raw) ? raw[0] : raw;
    return json({
      licenses:   data.licenses   || [],
      hasWarning: data.hasWarning || false,
      fetchedAt:  data.fetchedAt  || new Date().toISOString()
    });
  } catch (e) {
    return json({ error: 'Failed to reach n8n', detail: e.message }, 502);
  }
}

/* ── FortiGate Movi — System Info ── */
export async function handleMoviSystem(request, env) {
  const session = await getSession(request, env);
  if (!session) return json({ error: 'Unauthorized' }, 401);
  if (!(await hasPerm(env, session, 'fortigate-movi'))) return json({ error: 'Không có quyền truy cập FortiGate Movi' }, 403);
  const N8N_URL  = cleanEnv(env.MOVI_WH_FG_SYSTEM);
  const N8N_AUTH = moviN8nAuth(env);
  try {
    const resp = await fetch(N8N_URL, {
      headers: { 'Authorization': N8N_AUTH },
      signal: AbortSignal.timeout(15000)
    });
    if (!resp.ok) return json({ error: 'n8n upstream error', status: resp.status }, 502);
    const raw  = await resp.json();
    const data = Array.isArray(raw) ? raw[0] : raw;

    // Normalize CPU — n8n may return number or [{current: N, historical: ...}]
    let cpu = null;
    if (typeof data.cpu === 'number') cpu = data.cpu;
    else if (Array.isArray(data.cpu) && data.cpu.length > 0) cpu = data.cpu[0].current ?? null;

    // Normalize MEM
    let mem = null;
    if (typeof data.mem === 'number') mem = data.mem;
    else if (Array.isArray(data.mem) && data.mem.length > 0) mem = data.mem[0].current ?? null;

    // Normalize sessions — may be number or array
    let sessions = 0;
    if (typeof data.sessions === 'number') sessions = data.sessions;
    else if (Array.isArray(data.sessions) && data.sessions.length > 0) sessions = data.sessions[0].current ?? 0;

    return json({
      hostname:  data.hostname  || '',
      model:     data.model     || '',
      version:   data.version   || '',
      build:     data.build     || '',
      serial:    data.serial    || '',
      uptime:    data.uptime    || 0,
      cpu, mem, sessions,
      fetchedAt: data.fetchedAt || new Date().toISOString()
    });
  } catch (e) {
    return json({ error: 'Failed to reach n8n', detail: e.message }, 502);
  }
}

export async function handleMoviFirewallUsers(request, env) {
  const session = await getSession(request, env);
  if (!session) return json({ error: 'Unauthorized' }, 401);
  if (!(await hasPerm(env, session, 'fortigate-movi'))) return json({ error: 'Không có quyền truy cập FortiGate Movi' }, 403);
  const N8N_URL  = cleanEnv(env.MOVI_WH_FG_FIREWALL_USERS);
  const N8N_AUTH = moviN8nAuth(env);
  if (!N8N_URL) return json({ error: 'MOVI_WH_FG_FIREWALL_USERS chưa được cấu hình' }, 503);
  try {
    const resp = await fetch(N8N_URL, { headers: { 'Authorization': N8N_AUTH }, signal: AbortSignal.timeout(15000) });
    if (!resp.ok) return json({ error: 'n8n upstream error', status: resp.status }, 502);
    return json(await resp.json());
  } catch (e) { return json({ error: e.message }, 502); }
}

export async function handleMoviFortiviewSource(request, env) {
  const session = await getSession(request, env);
  if (!session) return json({ error: 'Unauthorized' }, 401);
  if (!(await hasPerm(env, session, 'fortigate-movi'))) return json({ error: 'Không có quyền truy cập FortiGate Movi' }, 403);
  const N8N_URL  = cleanEnv(env.MOVI_WH_FG_FORTIVIEW_SOURCE);
  const N8N_AUTH = moviN8nAuth(env);
  if (!N8N_URL) return json({ error: 'MOVI_WH_FG_FORTIVIEW_SOURCE chưa được cấu hình' }, 503);
  try {
    const resp = await fetch(N8N_URL, { headers: { 'Authorization': N8N_AUTH }, signal: AbortSignal.timeout(20000) });
    if (!resp.ok) return json({ error: 'n8n upstream error', status: resp.status }, 502);
    return json(await resp.json());
  } catch (e) { return json({ error: e.message }, 502); }
}

export async function handleMoviFirewallDeauth(request, env) {
  const session = await getSession(request, env);
  if (!session) return json({ error: 'Unauthorized' }, 401);
  if (!(await hasWritePerm(env, session, 'fortigate-movi'))) return json({ error: 'Cần quyền Write trên FortiGate Movi để deauth user' }, 403);
  const N8N_URL  = cleanEnv(env.MOVI_WH_FG_FIREWALL_DEAUTH);
  const N8N_AUTH = moviN8nAuth(env);
  if (!N8N_URL) return json({ error: 'MOVI_WH_FG_FIREWALL_DEAUTH chưa được cấu hình' }, 503);
  let body; try { body = await request.json(); } catch { return json({ error: 'Invalid JSON' }, 400); }
  if (!body || !body.ip) return json({ error: 'Thiếu trường ip' }, 400);
  try {
    const resp = await fetch(N8N_URL, {
      method: 'POST',
      headers: { 'Authorization': N8N_AUTH, 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip: body.ip, username: body.username || '' }),
      signal: AbortSignal.timeout(15000),
    });
    if (!resp.ok) return json({ error: 'n8n upstream error', status: resp.status }, 502);
    return json(await resp.json());
  } catch (e) { return json({ error: e.message }, 502); }
}

