/* ═══════════════════════════════════════════════
   core.js — shared foundation split out of worker.js (2026-07-01).
   Constants, env/crypto utils, config cache, session, permissions,
   rate-limit, json/escHtml, logActivity. Logic UNCHANGED — pure move.
   Imported by worker.js and every domain module.
   ═══════════════════════════════════════════════ */
export const SESSION_COOKIE    = 'dh_session';
export const SESSION_TTL       = 60 * 60 * 8;      // default fallback only — runtime reads from KV system_config
export const ALL_SERVICES      = ['esxi','n8n','casaos','fortigate','asus','ssh','camera','camera_playback','camera_download','app_camera','camera_autoopen','rustdesk','nas','frigate','openclaw','kasm','services-hub','hub-fortigate','hub-asus','hub-esxi','hub-nas','hub-casaos','hub-kasm','hub-openclaw','hub-n8n','hub-frigate','hub-camera-nvr','meraki','topology','fortigate-movi','camera-movi','n8n-movi','vmware01-movi','vmware02-movi','tool-movi-create-user','tool-movi-block-user','tool-movi-delete-user','tool-movi-asset-search','tool-movi-check-email','tool-movi-azure-group','tool-movi-fg-policy-lan','tool-movi-fg-policy-wifi','ssh-movi'];

/* ── Strip BOM + trim any env/config string value ── */
export function cleanEnv(v) { return (v || '').replace(/^﻿/, '').trim(); }

/* ── Short-TTL cache for system_config (read on nearly every request) ──
   Returns the config object, or {} on absence/error (matches the old
   `... || {}` semantics). Writers call _invalidateCfgCache() for instant
   effect; other readers see changes within CFG_CACHE_TTL_MS. */
let _cfgCache = null; // { cfg, exp }
export const CFG_CACHE_TTL_MS = 8000;
export function _invalidateCfgCache() { _cfgCache = null; }
export async function _getCfg(env) {
  if (_cfgCache && _cfgCache.exp > Date.now()) return _cfgCache.cfg;
  let cfg;
  try { cfg = await env.DASHBOARD_KV.get('system_config', 'json'); } catch (_) { cfg = null; }
  cfg = cfg || {};
  _cfgCache = { cfg, exp: Date.now() + CFG_CACHE_TTL_MS };
  return cfg;
}

/* ── IP CIDR whitelist matching ── */
export function _ipToInt(ip) {
  const parts = (ip || '').split('.');
  if (parts.length !== 4) return null;
  return parts.reduce((acc, o) => ((acc << 8) | (parseInt(o, 10) & 0xFF)) >>> 0, 0);
}
export function _ipInCidr(ip, cidr) {
  const c = (cidr || '').trim();
  if (!c.includes('/')) return ip === c;
  const [net, b] = c.split('/');
  const bits = parseInt(b, 10);
  if (bits < 0 || bits > 32) return false;
  const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
  const ipN = _ipToInt(ip), netN = _ipToInt(net);
  if (ipN === null || netN === null) return false;
  return (ipN & mask) === (netN & mask);
}
export function checkIpWhitelist(ip, list) {
  if (!Array.isArray(list) || list.length === 0) return true;
  return list.some(c => _ipInCidr(ip, c));
}

/* ── Email notification via n8n webhook (best-effort, never blocks login) ── */
export function notifyEmail(env, ctx, event, data) {
  const work = async () => {
    try {
      const cfg = await _getCfg(env);
      if (!cfg.emailEnabled) return;
      const wh = cleanEnv(cfg.emailWebhook);
      if (!wh) return;
      const evts = cfg.emailEvents || {};
      if (!evts[event]) return;
      await fetch(wh, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ event, ...data, timestamp: new Date().toISOString(), emailTo: cleanEnv(cfg.emailAdminAddress) }),
        signal: AbortSignal.timeout(8000),
      });
    } catch (_) { /* never block main flow */ }
  };
  if (ctx) ctx.waitUntil(work()); else work();
}

/* ── Password hashing ──
   New format (string): "pbkdf2$<iter>$<saltHex>$<hashHex>"
   Legacy format: bare 64-hex SHA-256(pw + ':dh-salt-2024'). Verified for
   backward-compat, then transparently re-hashed to PBKDF2 on next login. */
export const PW_PBKDF2_ITER = 100000; // Cloudflare Workers WebCrypto max supported

export function _bytesToHex(buf) {
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
}
export function _hexToBytes(hex) {
  return Uint8Array.from((hex.match(/../g) || []).map(h => parseInt(h, 16)));
}
export function _constEq(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}

export async function _sha256Hex(str) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(str));
  return _bytesToHex(buf);
}
export async function _pbkdf2Hex(password, saltHex, iter) {
  const key = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt: _hexToBytes(saltHex), iterations: iter },
    key, 256);
  return _bytesToHex(bits);
}

// Produce a fresh strong hash string (per-user random salt).
export async function hashPw(password) {
  const saltHex = _bytesToHex(crypto.getRandomValues(new Uint8Array(16)));
  const hash = await _pbkdf2Hex(password, saltHex, PW_PBKDF2_ITER);
  return `pbkdf2$${PW_PBKDF2_ITER}$${saltHex}$${hash}`;
}

// Verify a password against a stored hash (new or legacy format).
export async function verifyPw(password, stored) {
  if (!stored || typeof stored !== 'string') return false;
  if (stored.startsWith('pbkdf2$')) {
    const [, iterS, saltHex, hashHex] = stored.split('$');
    const iter = parseInt(iterS, 10) || PW_PBKDF2_ITER;
    return _constEq(await _pbkdf2Hex(password, saltHex, iter), hashHex);
  }
  // Legacy SHA-256 + static salt
  return _constEq(await _sha256Hex(password + ':dh-salt-2024'), stored);
}

export function getSessionToken(request) {
  const cookie = request.headers.get('cookie') || '';
  for (const part of cookie.split(';')) {
    const [k, ...vs] = part.trim().split('=');
    if (k.trim() === SESSION_COOKIE) return vs.join('=').trim();
  }
  return null;
}

export async function getSession(request, env) {
  const token = getSessionToken(request);
  if (!token) return null;
  let result;
  const cached = _sessionCache.get(token);
  if (cached && cached.exp > Date.now()) {
    result = cached.session;
  } else {
    const session = await env.DASHBOARD_KV.get(`session:${token}`, 'json');
    if (!session || Date.now() > session.expires) {
      if (session) await env.DASHBOARD_KV.delete(`session:${token}`).catch(() => {});
      _sessionCache.delete(token);
      return null;
    }
    result = { ...session, token };
    _sessionCache.set(token, { session: result, exp: Date.now() + SESSION_CACHE_TTL_MS });
  }
  // ── IP binding (tùy chọn) — chống dùng lại cookie phiên bị trộm từ IP khác ──
  // MẶC ĐỊNH TẮT: nhiều user mobile đổi IP khi chuyển WiFi/4G → bật cứng sẽ rớt phiên oan.
  // Chỉ kích hoạt khi admin đặt system_config.enforceIpBinding = true.
  if (result.boundIp) {
    try {
      const cfg = await _getCfg(env);
      if (cfg.enforceIpBinding) {
        const curIp = request.headers.get('cf-connecting-ip')
          || (request.headers.get('x-forwarded-for') || '').split(',')[0].trim();
        if (curIp && curIp !== result.boundIp) return null;
      }
    } catch (_) { /* lỗi đọc config → không chặn, tránh khóa nhầm toàn hệ thống */ }
  }
  return result;
}

/* ── Brute-force throttle (KV-backed, best-effort) ── */
export async function rlGet(env, key) {
  return parseInt(await env.DASHBOARD_KV.get(`rl:${key}`) || '0', 10);
}
export async function rlBump(env, key, windowSec) {
  const n = (await rlGet(env, key)) + 1;
  await env.DASHBOARD_KV.put(`rl:${key}`, String(n), { expirationTtl: windowSec });
  return n;
}
export async function rlClear(env, key) {
  await env.DASHBOARD_KV.delete(`rl:${key}`).catch(() => {});
}

export async function ensureAdmin(env) {
  const admin = await env.DASHBOARD_KV.get('user:admin', 'json');
  if (!admin) {
    // Fail closed: never auto-create a weak default admin. Operator must set
    // the ADMIN_PASSWORD secret to bootstrap the first admin account.
    if (!env.ADMIN_PASSWORD || String(env.ADMIN_PASSWORD).length < 10) return false;
    await env.DASHBOARD_KV.put('user:admin', JSON.stringify({
      password: await hashPw(env.ADMIN_PASSWORD), role: 'admin', permissions: {}, created: Date.now()
    }));
    await env.DASHBOARD_KV.put('userlist', JSON.stringify(['admin']));
  }
  return true;
}

/* ── Helper: merge one policy_group object into eff ── */
export function _mergePolicyGroup(g, eff) {
  if (!g) return;
  if (g.role === 'admin' && eff.role !== 'admin') eff.role = 'admin';
  for (const [k, v] of Object.entries(g.permissions || {})) {
    const cur = eff.permissions[k];
    if (!cur || cur === 'none') eff.permissions[k] = v;
    else if (cur === 'read' && v === 'write') eff.permissions[k] = 'write';
  }
  for (const [k, v] of Object.entries(g.panels || {})) {
    if (!v) continue;
    const cur = eff.panels[k];
    if (!cur) { eff.panels[k] = v; }
    else if ((v === 'write' || v === true) && cur !== 'write' && cur !== true) { eff.panels[k] = v; }
  }
  for (const c of (g.cameras || [])) { if (!eff.cameras.includes(c)) eff.cameras.push(c); }
}

/**
 * Get canManagePerms for a session — always reads from live user KV.
 * We intentionally bypass the session cache because:
 *  1. Old sessions (pre-feature) have canManagePerms=undefined
 *  2. Sessions created before admin SET delegation have canManagePerms=[]
 *  3. Admin may revoke/change delegation → session would be stale
 * Live KV read ensures real-time accuracy for all these cases.
 */
export async function getSessionDelegateServices(env, session) {
  const user = await env.DASHBOARD_KV.get(`user:${session.username}`, 'json');
  if (!user || !Array.isArray(user.canManagePerms)) return [];
  return user.canManagePerms.filter(s => ALL_SERVICES.includes(s));
}

/**
 * Returns true if the session represents an admin — either by account role (fast, no KV)
 * or via a policy group with role='admin' (requires computeEffectivePermissions).
 * Use this everywhere instead of session.role === 'admin' so group-based admins work.
 */
export async function isAdminUser(env, session) {
  if (!session) return false;
  if (session.role === 'admin') return true;  // fast path — no KV needed
  const eff = await computeEffectivePermissions(env, session.username);
  return !!(eff && eff.role === 'admin');
}

/* ── Short-TTL cache for effective permissions (hot path) ──
   computeEffectivePermissions reads user + multiple groups from KV and runs on
   EVERY authenticated page load and API permission check. Caching collapses the
   duplicate reads that happen within a single request (isAdminUser + hasPerm)
   and across rapid successive requests. User-level changes call
   _invalidateEffCache(username) for instant effect; group/policy-group edits
   rely on the short TTL (changes apply within EFF_CACHE_TTL_MS). */
export const _effCache = new Map(); // username -> { eff, exp }
export const EFF_CACHE_TTL_MS = 8000;
export function _invalidateEffCache(username) { if (username) _effCache.delete(username); }

/* ── Short-TTL in-memory session cache (hot path) ──
   getSession does a KV read on EVERY authenticated request, including per-frame
   camera snapshot fetches. This cache collapses those reads so the KV is hit at
   most once per SESSION_CACHE_TTL_MS per token. Logout and invalidateUserSessions
   call _invalidateSessionCache for instant effect. */
export const _sessionCache = new Map(); // token -> { session, exp }
export const SESSION_CACHE_TTL_MS = 30_000;
export function _invalidateSessionCache(token) { if (token) _sessionCache.delete(token); }

export async function computeEffectivePermissions(env, username) {
  const _c = _effCache.get(username);
  if (_c && _c.exp > Date.now()) return _c.eff;
  const user = await env.DASHBOARD_KV.get(`user:${username}`, 'json');
  if (!user) return null;
  const eff = {
    role: user.role || 'user',
    permissions: { ...(user.permissions || {}) },
    panels:      { ...(user.panels || {}) },
    cameras:     [...(user.cameras || [])],
    groups:      [...(user.groups || [])],
    userGroups:  [...(user.userGroups || [])],
    canManagePerms: Array.isArray(user.canManagePerms)
      ? user.canManagePerms.filter(s => ALL_SERVICES.includes(s))
      : [],
    sysPerms:    sanitizeSysPerms(user.sysPerms || {}),
    mfaEnabled:  !!(user.mfaEnabled),
    isSaml:      !!(user.microsoftEmail),
  };

  // Track processed policy groups to avoid double-applying
  const processed = new Set();

  // 1. Direct policy group assignments — fetch all in parallel
  const directGids = eff.groups.filter(gid => { processed.add(gid); return true; });
  if (directGids.length > 0) {
    const groups = await Promise.all(directGids.map(gid => env.DASHBOARD_KV.get(`policy_group:${gid}`, 'json')));
    groups.forEach(g => _mergePolicyGroup(g, eff));
  }

  // 2. User Groups → Role Management Groups — fetch user_groups in parallel, then policy_groups in parallel
  if (eff.userGroups.length > 0) {
    const userGroups = await Promise.all(eff.userGroups.map(ugid => env.DASHBOARD_KV.get(`user_group:${ugid}`, 'json')));
    const pgIds = [];
    for (const ug of userGroups) {
      if (!ug) continue;
      for (const pgid of (ug.roleGroups || [])) {
        if (!processed.has(pgid)) { processed.add(pgid); pgIds.push(pgid); }
      }
    }
    if (pgIds.length > 0) {
      const policyGroups = await Promise.all(pgIds.map(pgid => env.DASHBOARD_KV.get(`policy_group:${pgid}`, 'json')));
      policyGroups.forEach(g => _mergePolicyGroup(g, eff));
    }
  }

  _effCache.set(username, { eff, exp: Date.now() + EFF_CACHE_TTL_MS });
  // Bound memory: purge expired entries when the map grows large
  if (_effCache.size > 200) {
    const now = Date.now();
    for (const [k, v] of _effCache) if (v.exp <= now) _effCache.delete(k);
  }
  return eff;
}

/**
 * Quick permission gate: returns true if session user has any non-'none' value
 * for the given page key (e.g. 'meraki', 'fortigate-movi', 'camera-movi').
 * Admin role always passes. Non-admins have effective permissions computed.
 */
export async function hasPerm(env, session, permKey) {
  if (!session) return false;
  if (session.role === 'admin') return true;
  const eff = await computeEffectivePermissions(env, session.username);
  if (!eff) return false;
  if (eff.role === 'admin') return true;  // catches users promoted since last login
  return (eff.permissions[permKey] || 'none') !== 'none';
}

/**
 * Write-level permission gate: returns true only if the user has 'write' (or is admin).
 * Used for destructive/mutating actions like block/unblock clients.
 */
export async function hasWritePerm(env, session, permKey) {
  if (!session) return false;
  if (session.role === 'admin') return true;
  const eff = await computeEffectivePermissions(env, session.username);
  if (!eff) return false;
  if (eff.role === 'admin') return true;
  return (eff.permissions[permKey] || 'none') === 'write';
}

/** Whitelist permission keys/values để chặn XSS qua group names/permission keys */
export function sanitizePermissions(raw) {
  if (!raw || typeof raw !== 'object') return {};
  const out = {};
  const VALID_VALS = ['none', 'read', 'write'];
  for (const k of Object.keys(raw)) {
    if (ALL_SERVICES.includes(k) && VALID_VALS.includes(raw[k])) out[k] = raw[k];
  }
  return out;
}
export function sanitizeSysPerms(raw) {
  if (!raw || typeof raw !== 'object') return {};
  const out = {};
  if (raw.addUser === true) out.addUser = true;
  if (raw.systemConfig === true) out.systemConfig = true;
  if (raw.resetMfa === true) out.resetMfa = true;
  if (raw.blockUser === true) out.blockUser = true;
  return out;
}
export function sanitizePanels(raw) {
  if (!raw || typeof raw !== 'object') return {};
  const out = {};
  const VALID_VALS = ['read', 'write', false, true];
  for (const k of Object.keys(raw)) {
    // panel key must start with a known service ID
    const svc = ALL_SERVICES.find(s => k.startsWith(s + '.'));
    if (svc && k.length <= 64 && VALID_VALS.includes(raw[k])) out[k] = raw[k];
  }
  return out;
}
export function sanitizeCameraIds(raw) {
  if (!Array.isArray(raw)) return [];
  return raw.filter(c => typeof c === 'string' && /^[a-zA-Z0-9_-]{1,64}$/.test(c));
}
export function sanitizeName(s, maxLen = 64) {
  if (typeof s !== 'string') return '';
  // strip HTML tags / control chars
  return s.replace(/<[^>]*>/g, '').replace(/[^\x20-\x7EÀ-ɏ]/g, '').trim().slice(0, maxLen);
}
/** Store value as-is if its JSON is within maxBytes; otherwise store truncated string representation. */
export function _truncateJson(v, maxBytes) {
  try {
    const s = JSON.stringify(v);
    if (s.length <= maxBytes) return v;
    return { _truncated: true, preview: s.slice(0, maxBytes) };
  } catch (_) { return null; }
}

export const DEFAULT_CAMERAS = [
  { id: 'cam01', name: 'Camera 01',          type: 'analog',  stream: 'cam01' },
  { id: 'cam03', name: 'Camera 03',          type: 'analog',  stream: 'cam03' },
  { id: 'cam04', name: 'Camera 04',          type: 'ip',      stream: 'cam04' },
  { id: 'cam05', name: 'Camera 05',          type: 'ip',      stream: 'cam05' },
  { id: 'cam06', name: 'Camera 06',          type: 'ip',      stream: 'cam06' },
  { id: 'cam07', name: 'Camera Phòng Khách', type: 'unknown', stream: null    },
  { id: 'cam08', name: 'Camera 08',          type: 'unknown', stream: null    },
  { id: 'cam09', name: 'Camera 09',          type: 'unknown', stream: null    },
];

export const DEFAULT_CAMERAS_MOVI = [
  { id: 'cam1',  name: 'Camera 1',  type: 'ip', stream: 'cam1'  },
  { id: 'cam2',  name: 'Camera 2',  type: 'ip', stream: 'cam2'  },
  { id: 'cam3',  name: 'Camera 3',  type: 'ip', stream: 'cam3'  },
  { id: 'cam4',  name: 'Camera 4',  type: 'ip', stream: 'cam4'  },
  { id: 'cam5',  name: 'Camera 5',  type: 'ip', stream: 'cam5'  },
  { id: 'cam6',  name: 'Camera 6',  type: 'ip', stream: 'cam6'  },
  { id: 'cam7',  name: 'Camera 7',  type: 'ip', stream: 'cam7'  },
  { id: 'cam8',  name: 'Camera 8',  type: 'ip', stream: 'cam8'  },
  { id: 'cam9',  name: 'Camera 9',  type: 'ip', stream: 'cam9'  },
  { id: 'cam10', name: 'Camera 10', type: 'ip', stream: 'cam10' },
  { id: 'cam11', name: 'Camera 11', type: 'ip', stream: 'cam11' },
  { id: 'cam12', name: 'Camera 12', type: 'ip', stream: 'cam12' },
  { id: 'cam13', name: 'Camera 13', type: 'ip', stream: 'cam13' },
  { id: 'cam14', name: 'Camera 14', type: 'ip', stream: 'cam14' },
  { id: 'cam15', name: 'Camera 15', type: 'ip', stream: 'cam15' },
  { id: 'cam16', name: 'Camera 16', type: 'ip', stream: 'cam16' },
];

/* ── Activity Log ── */
export async function logActivity(env, { action, username, ip, success, detail }) {
  try {
    const [log, cfg] = await Promise.all([
      env.DASHBOARD_KV.get('activity_log', 'json').then(v => v || []),
      _getCfg(env),
    ]);
    const retDays = Math.max(7, cfg.auditRetentionDays ?? 30);
    const cutoff  = Date.now() - retDays * 24 * 60 * 60 * 1000;
    log.unshift({ ts: Date.now(), action, username: username||'?', ip: ip||'?', success: !!success, detail: detail||'' });
    const trimmed = log.filter(l => l.ts >= cutoff).slice(0, 500);
    await env.DASHBOARD_KV.put('activity_log', JSON.stringify(trimmed), { expirationTtl: retDays * 24 * 60 * 60 });
  } catch(e) { /* non-critical */ }
}

export function json(data, status = 200) {
  // No wildcard CORS: the dashboard is same-origin; cookie-auth'd JSON must
  // not be readable by arbitrary cross-origin sites.
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json',
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
    },
  });
}

export function _escHtml(s) { return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }

/* ── shared config + helpers (moved 2026-07-01) ── */
export const N8N_BASE        = 'https://n8n-home.home-server.id.vn/api/v1';
export const MOVI_N8N_BASE   = 'https://n8n.movi-finance.com/api/v1';
export const RUSTDESK_BASE   = 'https://rustdesk.home-server.id.vn';

export function moviN8nAuth(env) {
  const u = cleanEnv(env.MOVI_N8N_USER);
  const p = cleanEnv(env.MOVI_N8N_PASS);
  if (!u || !p) throw new Error('MOVI_N8N_USER / MOVI_N8N_PASS not configured');
  return 'Basic ' + btoa(unescape(encodeURIComponent(u + ':' + p)));
}

