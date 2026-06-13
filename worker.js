/* ═══════════════════════════════════════════════
   Auth & User Management System
   ═══════════════════════════════════════════════ */
const SESSION_COOKIE    = 'dh_session';
const SESSION_TTL       = 60 * 60 * 8;      // default fallback only — runtime reads from KV system_config
const ALL_SERVICES      = ['esxi','n8n','casaos','9router','fortigate','asus','ssh','uptime-kuma','camera','camera_playback','camera_download','meraki','topology','fortigate-movi','camera-movi','n8n-movi','vmware01-movi','vmware02-movi','tool-movi-create-user','tool-movi-block-user','tool-movi-delete-user','tool-movi-asset-search','tool-movi-check-email','tool-movi-azure-group','tool-movi-fg-policy-lan','tool-movi-fg-policy-wifi','ssh-movi'];

/* Idle-timer script injected into every authenticated HTML page.
   T = idle timeout ms, W = warning threshold ms (must be < T) */
function makeIdleScript(T, W) {
return `<script>(function(){
  var T=${T},W=${W},last=Date.now(),bn=null,tk=null;

  /* Reset timer on any user interaction */
  window._idleReset = function() {
    last = Date.now();
    if (bn) { bn.style.display = 'none'; clearInterval(tk); tk = null; }
  };
  ['mousemove','mousedown','keydown','scroll','touchstart','click','pointerdown'].forEach(function(e) {
    document.addEventListener(e, window._idleReset, { passive: true, capture: true });
  });
  /* Reset timer when user switches back to this tab */
  document.addEventListener('visibilitychange', function() {
    if (!document.hidden) window._idleReset();
  });

  function fmt(ms) {
    var s = Math.ceil(ms / 1000), m = Math.floor(s / 60); s %= 60;
    return (m ? m + ' phút ' : '') + s + ' giây';
  }

  function showBanner() {
    if (!bn) {
      bn = document.createElement('div');
      bn.style.cssText = 'position:fixed;top:0;left:0;right:0;z-index:99999;'
        + 'background:#7c2d12;color:#fed7aa;'
        + 'padding:12px 20px;display:flex;align-items:center;'
        + 'justify-content:space-between;gap:12px;'
        + 'font-family:system-ui,sans-serif;font-size:13px;font-weight:500;'
        + 'box-shadow:0 2px 14px rgba(0,0,0,.55);';
      bn.innerHTML =
        '<span>⚠️ Phiên không hoạt động — tự đăng xuất sau <strong id="_ic"></strong></span>'
        + '<div style="display:flex;gap:8px;flex-shrink:0">'
        + '<button onclick="window._idleReset()" style="background:#ea580c;color:#fff;border:none;padding:6px 16px;border-radius:6px;font-size:12px;font-weight:600;cursor:pointer">Gia hạn phiên</button>'
        + '</div>';
      document.body.appendChild(bn);
    }
    bn.style.display = 'flex';
    /* Update countdown every second */
    clearInterval(tk);
    tk = setInterval(function() {
      var r = T - (Date.now() - last);
      var el = document.getElementById('_ic');
      if (el) el.textContent = fmt(Math.max(0, r));
      if (r <= 0) clearInterval(tk);
    }, 1000);
  }

  /* Check idle state every 10 seconds */
  setInterval(function() {
    var idle = Date.now() - last;
    if (idle >= T) {
      fetch('/api/auth/logout', { method: 'POST' }).finally(function() {
        window.location.href = '/login.html?reason=idle';
      });
    } else if (idle >= W) {
      showBanner();
    }
  }, 10000);
})();<\/script>`;
}

/* ── Strip BOM + trim any env/config string value ── */
function cleanEnv(v) { return (v || '').replace(/^﻿/, '').trim(); }

/* ── Short-TTL cache for system_config (read on nearly every request) ──
   Returns the config object, or {} on absence/error (matches the old
   `... || {}` semantics). Writers call _invalidateCfgCache() for instant
   effect; other readers see changes within CFG_CACHE_TTL_MS. */
let _cfgCache = null; // { cfg, exp }
const CFG_CACHE_TTL_MS = 8000;
function _invalidateCfgCache() { _cfgCache = null; }
async function _getCfg(env) {
  if (_cfgCache && _cfgCache.exp > Date.now()) return _cfgCache.cfg;
  let cfg;
  try { cfg = await env.DASHBOARD_KV.get('system_config', 'json'); } catch (_) { cfg = null; }
  cfg = cfg || {};
  _cfgCache = { cfg, exp: Date.now() + CFG_CACHE_TTL_MS };
  return cfg;
}

/* ── IP CIDR whitelist matching ── */
function _ipToInt(ip) {
  const parts = (ip || '').split('.');
  if (parts.length !== 4) return null;
  return parts.reduce((acc, o) => ((acc << 8) | (parseInt(o, 10) & 0xFF)) >>> 0, 0);
}
function _ipInCidr(ip, cidr) {
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
function checkIpWhitelist(ip, list) {
  if (!Array.isArray(list) || list.length === 0) return true;
  return list.some(c => _ipInCidr(ip, c));
}

/* ── Email notification via n8n webhook (best-effort, never blocks login) ── */
function notifyEmail(env, ctx, event, data) {
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
const PW_PBKDF2_ITER = 100000; // Cloudflare Workers WebCrypto max supported

function _bytesToHex(buf) {
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
}
function _hexToBytes(hex) {
  return Uint8Array.from((hex.match(/../g) || []).map(h => parseInt(h, 16)));
}
function _constEq(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}

async function _sha256Hex(str) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(str));
  return _bytesToHex(buf);
}
async function _pbkdf2Hex(password, saltHex, iter) {
  const key = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt: _hexToBytes(saltHex), iterations: iter },
    key, 256);
  return _bytesToHex(bits);
}

// Produce a fresh strong hash string (per-user random salt).
async function hashPw(password) {
  const saltHex = _bytesToHex(crypto.getRandomValues(new Uint8Array(16)));
  const hash = await _pbkdf2Hex(password, saltHex, PW_PBKDF2_ITER);
  return `pbkdf2$${PW_PBKDF2_ITER}$${saltHex}$${hash}`;
}

// Verify a password against a stored hash (new or legacy format).
async function verifyPw(password, stored) {
  if (!stored || typeof stored !== 'string') return false;
  if (stored.startsWith('pbkdf2$')) {
    const [, iterS, saltHex, hashHex] = stored.split('$');
    const iter = parseInt(iterS, 10) || PW_PBKDF2_ITER;
    return _constEq(await _pbkdf2Hex(password, saltHex, iter), hashHex);
  }
  // Legacy SHA-256 + static salt
  return _constEq(await _sha256Hex(password + ':dh-salt-2024'), stored);
}

function getSessionToken(request) {
  const cookie = request.headers.get('cookie') || '';
  for (const part of cookie.split(';')) {
    const [k, ...vs] = part.trim().split('=');
    if (k.trim() === SESSION_COOKIE) return vs.join('=').trim();
  }
  return null;
}

async function getSession(request, env) {
  const token = getSessionToken(request);
  if (!token) return null;
  const cached = _sessionCache.get(token);
  if (cached && cached.exp > Date.now()) return cached.session;
  const session = await env.DASHBOARD_KV.get(`session:${token}`, 'json');
  if (!session || Date.now() > session.expires) {
    if (session) await env.DASHBOARD_KV.delete(`session:${token}`).catch(() => {});
    _sessionCache.delete(token);
    return null;
  }
  const result = { ...session, token };
  _sessionCache.set(token, { session: result, exp: Date.now() + SESSION_CACHE_TTL_MS });
  return result;
}

/* ── Brute-force throttle (KV-backed, best-effort) ── */
async function rlGet(env, key) {
  return parseInt(await env.DASHBOARD_KV.get(`rl:${key}`) || '0', 10);
}
async function rlBump(env, key, windowSec) {
  const n = (await rlGet(env, key)) + 1;
  await env.DASHBOARD_KV.put(`rl:${key}`, String(n), { expirationTtl: windowSec });
  return n;
}
async function rlClear(env, key) {
  await env.DASHBOARD_KV.delete(`rl:${key}`).catch(() => {});
}

async function ensureAdmin(env) {
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

async function handleLogin(request, env, ctx) {
  if (request.method !== 'POST') return json({ error: 'POST required' }, 405);
  await ensureAdmin(env);
  let body; try { body = await request.json(); } catch { return json({ error: 'Invalid JSON' }, 400); }
  const { username, password } = body || {};
  if (!username || !password) return json({ error: 'Thiếu username hoặc password' }, 400);
  const ip = request.headers.get('cf-connecting-ip') || request.headers.get('x-forwarded-for') || 'unknown';

  // ── 0. Cloudflare Turnstile verification (bot protection) ──
  const turnstileSecret = (env.CF_TURNSTILE_SECRET_KEY || '').trim();
  if (turnstileSecret) {
    const cfToken = (body.cfTurnstileToken || '').trim();
    if (!cfToken) return json({ error: 'Vui lòng hoàn thành xác minh bảo mật (Turnstile).' }, 400);
    try {
      const tsRes = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: `secret=${encodeURIComponent(turnstileSecret)}&response=${encodeURIComponent(cfToken)}&remoteip=${encodeURIComponent(ip)}`,
      });
      const tsData = await tsRes.json();
      if (!tsData.success) {
        await logActivity(env, { action: 'login_blocked_turnstile', username, ip, success: false, detail: `Turnstile fail: ${(tsData['error-codes']||[]).join(',')}` });
        return json({ error: 'Xác minh bảo mật thất bại. Vui lòng thử lại.' }, 403);
      }
    } catch (tsErr) {
      // Turnstile API down — fail open to not lock out all users, but log it
      await logActivity(env, { action: 'turnstile_error', username, ip, success: false, detail: tsErr.message });
    }
  }

  // Load system config once for all security checks
  const cfg = await _getCfg(env);

  // ── 1. IP Whitelist check ──
  const ipWhitelist = Array.isArray(cfg.ipWhitelist) ? cfg.ipWhitelist.filter(s => s && s.trim()) : [];
  if (ipWhitelist.length > 0 && !checkIpWhitelist(ip, ipWhitelist)) {
    await logActivity(env, { action: 'login_blocked_ip', username, ip, success: false, detail: 'IP not in whitelist' });
    return json({ error: 'Địa chỉ IP của bạn không được phép đăng nhập vào hệ thống.' }, 403);
  }

  // ── 3. Rate limit (per-IP brute force, window = lockout duration) ──
  const lockoutMin = Math.max(1, cfg.lockoutDurationMin ?? 15);
  const WIN = lockoutMin * 60;
  const maxAttempts = Math.min(20, Math.max(3, cfg.maxLoginAttempts ?? 8));
  if ((await rlGet(env, `ip:${ip}`)) >= 20 || (await rlGet(env, `u:${ip}:${username}`)) >= maxAttempts) {
    await logActivity(env, { action: 'login_blocked', username, ip, success: false, detail: 'Rate limited' });
    return json({ error: `Quá nhiều lần thử. Vui lòng chờ ${lockoutMin} phút rồi thử lại.` }, 429);
  }

  const user = await env.DASHBOARD_KV.get(`user:${username}`, 'json');

  // ── 4. Per-user account lockout check ──
  if (user && user.locked) {
    const permanentLock = !cfg.lockoutDurationMin || cfg.lockoutDurationMin === 0;
    if (!permanentLock && user.lockedAt && (Date.now() - user.lockedAt) >= lockoutMin * 60000) {
      // Auto-unlock: lockout window expired
      user.locked = false;
      user.loginAttempts = 0;
      delete user.lockedAt;
      await env.DASHBOARD_KV.put(`user:${username}`, JSON.stringify(user));
    } else {
      const remainMin = (!permanentLock && user.lockedAt)
        ? Math.max(1, Math.ceil((user.lockedAt + lockoutMin * 60000 - Date.now()) / 60000))
        : 0;
      const errMsg = remainMin > 0
        ? `Tài khoản bị khóa. Tự động mở khóa sau ${remainMin} phút nữa.`
        : 'Tài khoản bị khóa. Liên hệ admin để mở khóa.';
      await logActivity(env, { action: 'login_blocked_locked', username, ip, success: false, detail: 'Account locked' });
      return json({ error: errMsg }, 403);
    }
  }

  // ── 4b. Blocked-by-admin check ──
  if (user && user.blocked) {
    await logActivity(env, { action: 'login_blocked_user', username, ip, success: false, detail: 'Account blocked by admin' });
    return json({ error: 'Tài khoản đã bị chặn bởi quản trị viên. Vui lòng liên hệ admin để được hỗ trợ.' }, 403);
  }

  // ── 4c. Per-user login time restriction ──
  if (user && user.loginTimeEnabled) {
    const tz = user.loginTimeZone || 'Asia/Ho_Chi_Minh';
    const nowStr = new Date().toLocaleTimeString('en-GB', { hour12: false, hour: '2-digit', minute: '2-digit', timeZone: tz });
    const start  = user.loginTimeStart || '00:00';
    const end    = user.loginTimeEnd   || '23:59';
    if (nowStr < start || nowStr > end) {
      await logActivity(env, { action: 'login_blocked_time', username, ip, success: false,
        detail: `${username} outside allowed hours ${start}–${end} (${tz})` });
      return json({ error: `Tài khoản này chỉ được đăng nhập trong khung giờ ${start} – ${end}.` }, 403);
    }
  }

  if (!user || !(await verifyPw(password, user.password))) {
    await rlBump(env, `ip:${ip}`, WIN);
    await rlBump(env, `u:${ip}:${username}`, WIN);
    await logActivity(env, { action: 'login_fail', username, ip, success: false, detail: 'Wrong credentials' });

    // Per-user attempt tracking → lock when threshold reached
    if (user) {
      user.loginAttempts = (user.loginAttempts || 0) + 1;
      if (user.loginAttempts >= maxAttempts) {
        user.locked = true;
        user.lockedAt = Date.now();
        await env.DASHBOARD_KV.put(`user:${username}`, JSON.stringify(user));
        await logActivity(env, { action: 'account_locked', username, ip, success: false, detail: `Locked after ${user.loginAttempts} failed attempts` });
        // Best-effort email notification (don't await to not block response)
        notifyEmail(env, ctx, 'account_locked', { username, ip, attempts: user.loginAttempts });
      } else {
        await env.DASHBOARD_KV.put(`user:${username}`, JSON.stringify(user));
      }
    }
    return json({ error: 'Sai tên đăng nhập hoặc mật khẩu' }, 401);
  }

  // Password correct — clear rate limits & reset attempt counter
  await rlClear(env, `ip:${ip}`);
  await rlClear(env, `u:${ip}:${username}`);
  if (user.loginAttempts > 0) {
    user.loginAttempts = 0;
    await env.DASHBOARD_KV.put(`user:${username}`, JSON.stringify(user));
  }

  // Transparently migrate legacy SHA-256 hashes to PBKDF2 on successful login
  if (!String(user.password || '').startsWith('pbkdf2$')) {
    try { user.password = await hashPw(password);
      await env.DASHBOARD_KV.put(`user:${username}`, JSON.stringify(user)); } catch {}
  }

  // ── 5. Password expiry check ──
  const pwExpiryDays = cfg.pwExpiryDays ?? 0;
  if (pwExpiryDays > 0) {
    const age = user.pwChangedAt ? Date.now() - user.pwChangedAt : Infinity;
    if (age >= pwExpiryDays * 86400000 && !user.mustChangePassword) {
      user.mustChangePassword = true;
      await env.DASHBOARD_KV.put(`user:${username}`, JSON.stringify(user));
      notifyEmail(env, ctx, 'password_expired', { username, ip });
    }
  }

  // First-login setup: force password change + MFA setup before creating session
  if (user.mustChangePassword || user.mustSetupMfa) {
    const setupToken = crypto.randomUUID();
    await env.DASHBOARD_KV.put(`setup_temp:${setupToken}`, JSON.stringify({
      username,
      mustChangePassword: !!user.mustChangePassword,
      mustSetupMfa: !!user.mustSetupMfa,
      expires: Date.now() + 600_000, // 10 minutes
    }), { expirationTtl: 600 });
    await logActivity(env, { action: 'login_setup_required', username, ip, success: true,
      detail: user.mustChangePassword ? 'Must change password + setup MFA' : 'Must setup MFA' });
    return json({ setupRequired: true, setupToken, step: user.mustChangePassword ? 'changePassword' : 'setupMfa' });
  }

  // If MFA is enabled for this user, don't create session yet — return temp token
  if (user.mfaEnabled && user.mfaSecret) {
    const tempToken = crypto.randomUUID();
    await env.DASHBOARD_KV.put(`mfa_temp:${tempToken}`, JSON.stringify({
      username, expires: Date.now() + 300_000 // 5 minutes
    }), { expirationTtl: 300 });
    await logActivity(env, { action: 'login_mfa', username, ip, success: true, detail: 'MFA required' });
    return json({ mfaRequired: true, tempToken });
  }

  const sessionTtl = Math.max(1, cfg.sessionTtlHours ?? 8) * 3600;

  // ── 6. Max concurrent sessions enforcement ──
  const maxSessions = cfg.maxConcurrentSessions ?? 0;
  if (maxSessions > 0) {
    const listed = await env.DASHBOARD_KV.list({ prefix: 'session:' });
    const userSessions = [];
    for (const k of listed.keys) {
      const s = await env.DASHBOARD_KV.get(k.name, 'json');
      if (s && s.username === username && Date.now() < (s.expires || 0)) {
        userSessions.push({ key: k.name, createdAt: s.createdAt || (s.expires - sessionTtl * 1000) });
      }
    }
    if (userSessions.length >= maxSessions) {
      // Remove oldest session(s) to make room
      userSessions.sort((a, b) => a.createdAt - b.createdAt);
      const toKick = userSessions.slice(0, userSessions.length - maxSessions + 1);
      await Promise.all(toKick.map(s => env.DASHBOARD_KV.delete(s.key)));
    }
  }

  const token = crypto.randomUUID();
  const canManagePerms = (user.canManagePerms || []).filter(s => ALL_SERVICES.includes(s));
  await env.DASHBOARD_KV.put(`session:${token}`, JSON.stringify({
    username, role: user.role, permissions: user.permissions || {},
    canManagePerms,
    boundIp: ip,
    createdAt: Date.now(),
    expires: Date.now() + sessionTtl * 1000
  }), { expirationTtl: sessionTtl });

  // Set both: HttpOnly session cookie + readable user-info cookie for client JS
  const userInfo = encodeURIComponent(JSON.stringify({
    username, role: user.role,
    permissions: user.permissions || {},
    isAdmin: user.role === 'admin',
    canManagePerms,
  }));
  const h = new Headers({ 'Content-Type': 'application/json' });
  h.append('Set-Cookie', `${SESSION_COOKIE}=${token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${sessionTtl}`);
  h.append('Set-Cookie', `dh_user=${userInfo}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${sessionTtl}`);
  await logActivity(env, { action: 'login_success', username, ip, success: true });
  notifyEmail(env, ctx, 'login_success', { username, ip });
  return new Response(JSON.stringify({ success: true, role: user.role }), { status: 200, headers: h });
}

async function handleSessionRefresh(request, env) {
  const session = await getSession(request, env);
  if (!session) return json({ error: 'No session' }, 401);
  const token = session.token;
  const refreshCfg = await _getCfg(env);
  const refreshTtl = Math.max(1, refreshCfg.sessionTtlHours ?? 8) * 3600;
  const newExpires = Date.now() + refreshTtl * 1000;
  // Re-read role from KV so role changes take effect without full re-login
  const refreshUser = await env.DASHBOARD_KV.get(`user:${session.username}`, 'json');
  const freshRole = (refreshUser && refreshUser.role) || session.role;
  await env.DASHBOARD_KV.put(`session:${token}`, JSON.stringify({
    username: session.username, role: freshRole,
    permissions: session.permissions || {},
    boundIp: session.boundIp || '',
    expires: newExpires,
  }), { expirationTtl: refreshTtl });
  const h = new Headers({ 'Content-Type': 'application/json' });
  h.append('Set-Cookie', `${SESSION_COOKIE}=${token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${refreshTtl}`);
  return new Response(JSON.stringify({ ok: true }), { status: 200, headers: h });
}

/** Xóa tất cả session KV của một user (dùng khi delete / demote / đổi password) */
async function invalidateUserSessions(env, username) {
  _invalidateEffCache(username);  // also drop cached effective permissions
  // also evict any in-memory session cache entries for this user
  for (const [tok, entry] of _sessionCache) {
    if (entry.session && entry.session.username === username) _sessionCache.delete(tok);
  }
  try {
    const listed = await env.DASHBOARD_KV.list({ prefix: 'session:' });
    await Promise.all(listed.keys.map(async k => {
      const s = await env.DASHBOARD_KV.get(k.name, 'json');
      if (s && s.username === username) await env.DASHBOARD_KV.delete(k.name);
    }));
  } catch (_) { /* best-effort */ }
}

async function handleLogout(request, env) {
  const session = await getSession(request, env);
  const logUser = session?.username || 'unknown';
  const ip = request.headers.get('cf-connecting-ip') || request.headers.get('x-forwarded-for') || 'unknown';
  const token = getSessionToken(request);
  if (token) { _invalidateSessionCache(token); await env.DASHBOARD_KV.delete(`session:${token}`).catch(() => {}); }
  await logActivity(env, { action: 'logout', username: logUser, ip, success: true });
  const h = new Headers({ 'Content-Type': 'application/json' });
  h.append('Set-Cookie', `${SESSION_COOKIE}=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0`);
  h.append('Set-Cookie', `dh_user=; Secure; SameSite=Lax; Path=/; Max-Age=0`);
  return new Response(JSON.stringify({ success: true }), { status: 200, headers: h });
}

async function handleListUsers(request, env) {
  const session = await getSession(request, env);
  if (!session) return json({ error: 'Unauthorized' }, 401);

  const list = await env.DASHBOARD_KV.get('userlist', 'json') || ['admin'];

  if (await isAdminUser(env, session)) {
    const data = await Promise.all(list.map(u => env.DASHBOARD_KV.get(`user:${u}`, 'json')));
    const users = data.map((d, i) => !d ? null : ({
      username:         list[i],
      role:             d.role,
      permissions:      d.permissions || {},
      panels:           d.panels || {},
      cameras:          d.cameras || [],
      groups:           d.groups || [],
      userGroups:       d.userGroups || [],
      canManagePerms:   d.canManagePerms || [],
      sysPerms:         sanitizeSysPerms(d.sysPerms || {}),
      locked:           !!d.locked,
      blocked:          !!d.blocked,
      blockedAt:        d.blockedAt || null,
      blockedBy:        d.blockedBy || null,
      loginAttempts:    d.loginAttempts || 0,
      lockedAt:         d.lockedAt || null,
      pwChangedAt:      d.pwChangedAt || null,
      loginTimeEnabled: !!d.loginTimeEnabled,
      loginTimeStart:   d.loginTimeStart || '06:00',
      loginTimeEnd:     d.loginTimeEnd   || '23:00',
      loginTimeZone:    d.loginTimeZone  || 'Asia/Ho_Chi_Minh',
      microsoftEmail:   d.microsoftEmail || null,
      mfaEnabled:       !!d.mfaEnabled,
    })).filter(Boolean);
    return json({ users });
  }

  // Non-admin: check if they have delegation rights or sysPerms.addUser
  const callerUser = await env.DASHBOARD_KV.get(`user:${session.username}`, 'json');
  const canManage = (callerUser && Array.isArray(callerUser.canManagePerms)) ? callerUser.canManagePerms.filter(s => ALL_SERVICES.includes(s)) : [];
  const hasSysAddUser    = !!(callerUser?.sysPerms?.addUser);
  const hasSysResetMfa   = !!(callerUser?.sysPerms?.resetMfa);
  const hasSysBlockUser  = !!(callerUser?.sysPerms?.blockUser);
  if (!canManage.length && !hasSysAddUser && !hasSysResetMfa && !hasSysBlockUser) return json({ error: 'Admin required' }, 403);

  // Return filtered list: basic info + only the managed service permissions
  const users = [];
  for (const u of list) {
    if (u === session.username) continue; // skip self
    const d = await env.DASHBOARD_KV.get(`user:${u}`, 'json');
    if (!d) continue;
    const filteredPerms = {};
    for (const svc of canManage) filteredPerms[svc] = (d.permissions || {})[svc] || 'none';
    users.push({
      username:    u,
      role:        d.role,
      permissions: filteredPerms,
      panels:      {},
      cameras:     [],
      groups:      d.groups || [],
      userGroups:  d.userGroups || [],
      mfaEnabled:  !!d.mfaEnabled,
      blocked:     !!d.blocked,
      blockedAt:   d.blockedAt || null,
      blockedBy:   d.blockedBy || null,
    });
  }
  return json({ users, delegateMode: true, canManagePerms: canManage, sysPerms: sanitizeSysPerms(callerUser?.sysPerms || {}) });
}

async function handleCreateUser(request, env) {
  try {
    const session = await getSession(request, env);
    if (!session) return json({ error: 'Unauthorized' }, 401);
    const isAdmin = await isAdminUser(env, session);
    if (!isAdmin) {
      // Only sysPerms.addUser grants user creation — service delegation (canManagePerms) does NOT
      const callerRaw = await env.DASHBOARD_KV.get(`user:${session.username}`, 'json');
      if (!callerRaw?.sysPerms?.addUser) return json({ error: 'Admin required' }, 403);
    }
    if (request.method !== 'POST') return json({ error: 'POST required' }, 405);
    let body; try { body = await request.json(); } catch { return json({ error: 'Invalid JSON' }, 400); }
    const { username, password } = body || {};
    if (!username || !password) return json({ error: 'Thiếu username hoặc password' }, 400);
    if (!/^[a-zA-Z0-9_.@-]{3,64}$/.test(username)) return json({ error: 'Username không hợp lệ (3-64 ký tự, a-z 0-9 . @ _ -)' }, 400);
    // Parallel: check existence, load userlist, load config — all needed before creating
    const [existing, curList, createCfg] = await Promise.all([
      env.DASHBOARD_KV.get(`user:${username}`),
      env.DASHBOARD_KV.get('userlist', 'json'),
      _getCfg(env)
    ]);
    if (existing) return json({ error: 'User đã tồn tại' }, 409);
    const list = curList || ['admin'];
    const maxUsers = Math.max(1, (createCfg || {}).maxUsers ?? 50);
    if (list.length >= maxUsers) return json({ error: `Đã đạt giới hạn tối đa ${maxUsers} người dùng. Không thể tạo thêm user mới.` }, 400);
    const pwMinLen = Math.max(4, (createCfg || {}).pwMinLength ?? 6);
    if (password.length < pwMinLen) return json({ error: `Mật khẩu tối thiểu ${pwMinLen} ký tự` }, 400);
    const hashed = await hashPw(password);
    // Delegated managers can only create 'user' role, not admin
    const allowedRoles = isAdmin ? ['user', 'admin'] : ['user'];
    const role = allowedRoles.includes(body?.role) ? body.role : 'user';
    // Delegated managers can assign policy groups (same as admin)
    const groups = Array.isArray(body?.groups) ? body.groups : [];
    await env.DASHBOARD_KV.put(`user:${username}`, JSON.stringify({
      password: hashed, role, groups, userGroups: [], permissions: {}, panels: {}, cameras: [], created: Date.now(),
      mustChangePassword: true,  // Force password change on first login
      mustSetupMfa: true,        // Force MFA setup on first login
    }));
    if (!list.includes(username)) { list.push(username); await env.DASHBOARD_KV.put('userlist', JSON.stringify(list)); }
    if (!isAdmin) await logActivity(env, { action: 'delegate-create-user', username: session.username, success: true, detail: `Created user: ${username}` });
    return json({ success: true, username });
  } catch (e) {
    // Don't leak internal error details (stack traces, file paths, etc.)
    console.error('handleCreateUser error:', e);
    return json({ error: 'Lỗi tạo user. Vui lòng thử lại.' }, 500);
  }
}

async function handleLinkMicrosoftEmail(request, env, username) {
  const session = await getSession(request, env);
  if (!session) return json({ error: 'Unauthorized' }, 401);
  if (!(await isAdminUser(env, session))) return json({ error: 'Admin required' }, 403);
  let body; try { body = await request.json(); } catch { return json({ error: 'Invalid JSON' }, 400); }
  const email = (body.microsoftEmail || '').toLowerCase().trim();
  if (email && !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) return json({ error: 'Email không hợp lệ' }, 400);
  const user = await env.DASHBOARD_KV.get(`user:${username}`, 'json');
  if (!user) return json({ error: 'User không tồn tại' }, 404);
  // Check trùng email với user khác
  if (email) {
    const userlist = await env.DASHBOARD_KV.get('userlist', 'json') || [];
    for (const u of userlist) {
      if (u === username) continue;
      const other = await env.DASHBOARD_KV.get(`user:${u}`, 'json');
      if (other && (other.microsoftEmail || '').toLowerCase().trim() === email)
        return json({ error: `Email "${email}" đã được liên kết với user "${u}"` }, 409);
    }
  }
  if (email) user.microsoftEmail = email;
  else delete user.microsoftEmail;
  await env.DASHBOARD_KV.put(`user:${username}`, JSON.stringify(user));
  _invalidateEffCache(username);
  await logActivity(env, { action: 'link_microsoft_email', username: session.username, success: true,
    detail: email ? `Linked ${username} → ${email}` : `Unlinked ${username}` });
  return json({ success: true, username, microsoftEmail: email || null });
}

async function handleUpdatePermissions(request, env, username) {
  const session = await getSession(request, env);
  if (!session) return json({ error: 'Unauthorized' }, 401);
  if (username === 'admin') return json({ error: 'Không thể sửa quyền admin' }, 400);
  let body; try { body = await request.json(); } catch { return json({ error: 'Invalid JSON' }, 400); }

  const user = await env.DASHBOARD_KV.get(`user:${username}`, 'json');
  if (!user) return json({ error: 'User not found' }, 404);

  if (await isAdminUser(env, session)) {
    // Admin: full control over all permissions
    user.permissions = sanitizePermissions(body.permissions || {});
    await env.DASHBOARD_KV.put(`user:${username}`, JSON.stringify(user));
    _invalidateEffCache(username);
    return json({ success: true, username, permissions: user.permissions });
  }

  // Non-admin: check delegation rights
  if (username === session.username) return json({ error: 'Không thể tự xét quyền cho bản thân qua tính năng này' }, 400);
  // Block delegated users from editing admin accounts
  if (user.role === 'admin') return json({ error: 'Không thể chỉnh quyền của tài khoản admin' }, 403);
  const callerUser = await env.DASHBOARD_KV.get(`user:${session.username}`, 'json');
  const canManage = (callerUser && Array.isArray(callerUser.canManagePerms)) ? callerUser.canManagePerms.filter(s => ALL_SERVICES.includes(s)) : [];
  if (!canManage.length) return json({ error: 'Không có quyền thay đổi permissions của người khác' }, 403);

  // Apply changes only for services they're allowed to manage
  const newPerms = sanitizePermissions(body.permissions || {});
  user.permissions = user.permissions || {};
  for (const svc of canManage) {
    if (newPerms[svc] !== undefined) user.permissions[svc] = newPerms[svc];
  }
  await env.DASHBOARD_KV.put(`user:${username}`, JSON.stringify(user));
  _invalidateEffCache(username);
  await logActivity(env, { action: 'delegate-update-perm', username: session.username, success: true, detail: `Updated perms for ${username} (managed services: ${canManage.join(', ')})` });
  return json({ success: true, username, permissions: user.permissions });
}

/* ── Delegation: Admin sets which services a user can manage permissions for ── */
async function handleSetManagePerms(request, env, username) {
  const session = await getSession(request, env);
  if (!session || !(await isAdminUser(env, session))) return json({ error: 'Admin required' }, 403);
  if (username === 'admin') return json({ error: 'Không thể sửa quyền admin' }, 400);
  let body; try { body = await request.json(); } catch { return json({ error: 'Invalid JSON' }, 400); }
  const user = await env.DASHBOARD_KV.get(`user:${username}`, 'json');
  if (!user) return json({ error: 'User not found' }, 404);
  const canManagePerms = Array.isArray(body.canManagePerms)
    ? body.canManagePerms.filter(s => ALL_SERVICES.includes(s))
    : [];
  user.canManagePerms = canManagePerms;
  await env.DASHBOARD_KV.put(`user:${username}`, JSON.stringify(user));
  _invalidateEffCache(username);
  await logActivity(env, { action: 'delegate-set-manage-perms', username: session.username, success: true, detail: `canManagePerms for ${username}: [${canManagePerms.join(', ')}]` });
  return json({ success: true, username, canManagePerms });
}

async function handleSetSysPerms(request, env, username) {
  const session = await getSession(request, env);
  if (!session || !(await isAdminUser(env, session))) return json({ error: 'Admin required' }, 403);
  if (username === 'admin') return json({ error: 'Không thể sửa admin' }, 400);
  let body; try { body = await request.json(); } catch { return json({ error: 'Invalid JSON' }, 400); }
  const user = await env.DASHBOARD_KV.get(`user:${username}`, 'json');
  if (!user) return json({ error: 'User not found' }, 404);
  user.sysPerms = sanitizeSysPerms(body.sysPerms || {});
  await env.DASHBOARD_KV.put(`user:${username}`, JSON.stringify(user));
  _invalidateEffCache(username);
  await logActivity(env, { action: 'set-sys-perms', username: session.username, success: true, detail: `sysPerms for ${username}: ${JSON.stringify(user.sysPerms)}` });
  return json({ success: true, username, sysPerms: user.sysPerms });
}

async function handleDeleteUser(request, env, username) {
  const session = await getSession(request, env);
  if (!session || !(await isAdminUser(env, session))) return json({ error: 'Admin required' }, 403);
  if (username === 'admin') return json({ error: 'Không thể xoá admin' }, 400);
  await invalidateUserSessions(env, username);   // xóa session trước khi xóa user
  await env.DASHBOARD_KV.delete(`user:${username}`);
  const list = (await env.DASHBOARD_KV.get('userlist', 'json') || []).filter(u => u !== username);
  await env.DASHBOARD_KV.put('userlist', JSON.stringify(list));
  await logActivity(env, { action: 'user-delete', username: session.username, success: true, detail: `Deleted user: ${username}` });
  return json({ success: true });
}

async function handleUnlockUser(request, env, username) {
  const session = await getSession(request, env);
  if (!session || !(await isAdminUser(env, session))) return json({ error: 'Admin required' }, 403);
  const user = await env.DASHBOARD_KV.get(`user:${username}`, 'json');
  if (!user) return json({ error: 'User not found' }, 404);
  user.locked = false;
  user.loginAttempts = 0;
  delete user.lockedAt;
  await env.DASHBOARD_KV.put(`user:${username}`, JSON.stringify(user));
  await logActivity(env, { action: 'user-unlock', username: session.username,
    ip: request.headers.get('CF-Connecting-IP') || '?', success: true, detail: `Unlocked: ${username}` });
  return json({ success: true });
}

/* ── Admin reset MFA for a user (unblocks lost-authenticator lockout) ──
   Clears the secret + recovery codes and forces a fresh MFA setup on next login. */
async function handleAdminResetMfa(request, env, username) {
  const session = await getSession(request, env);
  if (!session) return json({ error: 'Unauthorized' }, 401);
  const isAdmin = await isAdminUser(env, session);
  const callerRaw = isAdmin ? null : await env.DASHBOARD_KV.get(`user:${session.username}`, 'json');
  if (!isAdmin && !callerRaw?.sysPerms?.resetMfa) return json({ error: 'Admin required' }, 403);
  const user = await env.DASHBOARD_KV.get(`user:${username}`, 'json');
  if (!user) return json({ error: 'User not found' }, 404);
  // Non-admin with resetMfa perm cannot touch admin accounts
  if (!isAdmin && (user.role === 'admin' || username === 'admin')) return json({ error: 'Không thể reset MFA tài khoản admin' }, 403);
  user.mfaEnabled   = false;
  user.mfaSecret    = null;
  user.mfaRecovery  = [];
  user.mustSetupMfa = true;   // force re-enrol on next login (local accounts require MFA)
  await env.DASHBOARD_KV.put(`user:${username}`, JSON.stringify(user));
  _invalidateEffCache(username);
  await invalidateUserSessions(env, username);  // kick existing sessions
  await logActivity(env, { action: 'admin-reset-mfa', username: session.username,
    ip: request.headers.get('CF-Connecting-IP') || '?', success: true, detail: `Reset MFA for: ${username}` });
  return json({ success: true });
}

async function handleBlockUser(request, env, username) {
  const session = await getSession(request, env);
  if (!session) return json({ error: 'Unauthorized' }, 401);
  const isAdmin = await isAdminUser(env, session);
  const callerRaw = isAdmin ? null : await env.DASHBOARD_KV.get(`user:${session.username}`, 'json');
  if (!isAdmin && !callerRaw?.sysPerms?.blockUser) return json({ error: 'Admin required' }, 403);
  if (username === 'admin') return json({ error: 'Không thể chặn tài khoản admin gốc' }, 400);
  if (username === session.username) return json({ error: 'Không thể tự chặn tài khoản của mình' }, 400);
  let body; try { body = await request.json(); } catch { return json({ error: 'Invalid JSON' }, 400); }
  const user = await env.DASHBOARD_KV.get(`user:${username}`, 'json');
  if (!user) return json({ error: 'User not found' }, 404);
  // Non-admin with blockUser perm cannot block admin accounts
  if (!isAdmin && user.role === 'admin') return json({ error: 'Không thể chặn tài khoản admin' }, 403);
  const block = !!body.blocked;
  user.blocked = block;
  if (block) {
    user.blockedAt = Date.now();
    user.blockedBy = session.username;
  } else {
    delete user.blockedAt;
    delete user.blockedBy;
  }
  await env.DASHBOARD_KV.put(`user:${username}`, JSON.stringify(user));
  _invalidateEffCache(username);
  if (block) await invalidateUserSessions(env, username);
  const ip = request.headers.get('CF-Connecting-IP') || '?';
  await logActivity(env, { action: block ? 'user-blocked' : 'user-unblocked', username: session.username,
    ip, success: true, detail: `${block ? 'Blocked' : 'Unblocked'} user: ${username}` });
  return json({ success: true, blocked: block });
}

async function handleSaveUserLoginTime(request, env, username) {
  const session = await getSession(request, env);
  if (!session || !(await isAdminUser(env, session))) return json({ error: 'Admin required' }, 403);
  let body; try { body = await request.json(); } catch { return json({ error: 'Invalid JSON' }, 400); }
  const user = await env.DASHBOARD_KV.get(`user:${username}`, 'json');
  if (!user) return json({ error: 'User not found' }, 404);
  user.loginTimeEnabled = !!body.loginTimeEnabled;
  if (body.loginTimeStart && /^\d{2}:\d{2}$/.test(body.loginTimeStart)) user.loginTimeStart = body.loginTimeStart;
  if (body.loginTimeEnd   && /^\d{2}:\d{2}$/.test(body.loginTimeEnd))   user.loginTimeEnd   = body.loginTimeEnd;
  const allowedTz = ['Asia/Ho_Chi_Minh','Asia/Bangkok','Asia/Singapore','UTC','Asia/Tokyo'];
  if (body.loginTimeZone && allowedTz.includes(body.loginTimeZone)) user.loginTimeZone = body.loginTimeZone;
  await env.DASHBOARD_KV.put(`user:${username}`, JSON.stringify(user));
  await logActivity(env, { action: 'user-update-login-time', username: session.username,
    ip: request.headers.get('CF-Connecting-IP') || '?', success: true, detail: `Login time set for: ${username}` });
  return json({ success: true });
}

async function handleForceLogoutAll(request, env, ctx) {
  const session = await getSession(request, env);
  if (!session || !(await isAdminUser(env, session))) return json({ error: 'Admin required' }, 403);
  const listed = await env.DASHBOARD_KV.list({ prefix: 'session:' });
  let kicked = 0;
  await Promise.all(listed.keys.map(async k => {
    if (k.name !== `session:${session.token}`) {
      await env.DASHBOARD_KV.delete(k.name);
      kicked++;
    }
  }));
  const ip = request.headers.get('CF-Connecting-IP') || '?';
  await logActivity(env, { action: 'force-logout-all', username: session.username, ip, success: true, detail: `Kicked ${kicked} sessions` });
  notifyEmail(env, ctx, 'force_logout_all', { admin: session.username, kicked, ip });
  return json({ success: true, kicked });
}

/* ── List active sessions (admin) ──
   Returns an opaque sid = first 16 hex of SHA-256(token) instead of the raw
   token, so the session cookie value is never exposed to the client. */
async function handleListSessions(request, env) {
  const session = await getSession(request, env);
  if (!session || !(await isAdminUser(env, session))) return json({ error: 'Admin required' }, 403);
  const listed = await env.DASHBOARD_KV.list({ prefix: 'session:' });
  const now = Date.now();
  const curSid = await _sha256Hex(session.token);
  const rows = await Promise.all(listed.keys.map(async k => {
    const s = await env.DASHBOARD_KV.get(k.name, 'json');
    if (!s || (s.expires && now > s.expires)) return null;
    const token = k.name.slice('session:'.length);
    const sid = (await _sha256Hex(token)).slice(0, 16);
    return {
      sid,
      username:   s.username || '?',
      ip:         s.boundIp || '?',
      authMethod: s.authMethod || 'local',
      createdAt:  s.createdAt || null,
      expires:    s.expires || null,
      current:    (await _sha256Hex(token)) === curSid,
    };
  }));
  const sessions = rows.filter(Boolean).sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0));
  return json({ sessions, total: sessions.length });
}

/* ── Kick one session by opaque sid (admin) ── */
async function handleKickSession(request, env, sid) {
  const session = await getSession(request, env);
  if (!session || !(await isAdminUser(env, session))) return json({ error: 'Admin required' }, 403);
  if (!/^[a-f0-9]{16}$/.test(sid || '')) return json({ error: 'sid không hợp lệ' }, 400);
  const listed = await env.DASHBOARD_KV.list({ prefix: 'session:' });
  let kicked = null;
  for (const k of listed.keys) {
    const token = k.name.slice('session:'.length);
    if ((await _sha256Hex(token)).slice(0, 16) === sid) {
      const s = await env.DASHBOARD_KV.get(k.name, 'json').catch(() => null);
      await env.DASHBOARD_KV.delete(k.name);
      kicked = s && s.username ? s.username : '?';
      break;
    }
  }
  if (kicked === null) return json({ error: 'Session không tồn tại (có thể đã hết hạn)' }, 404);
  await logActivity(env, { action: 'session-kick', username: session.username,
    ip: request.headers.get('CF-Connecting-IP') || '?', success: true, detail: `Kicked session of ${kicked}` });
  return json({ success: true, kicked });
}

/* ── Backup: export all config as a JSON file (admin) ──
   ⚠ Includes password hashes + MFA secrets — treat the file as a secret. */
async function handleBackup(request, env) {
  const session = await getSession(request, env);
  if (!session || !(await isAdminUser(env, session))) return json({ error: 'Admin required' }, 403);
  const userlist = await env.DASHBOARD_KV.get('userlist', 'json') || [];
  const users = {};
  await Promise.all(userlist.map(async u => { users[u] = await env.DASHBOARD_KV.get(`user:${u}`, 'json'); }));
  const policyGroupIds = await env.DASHBOARD_KV.get('policy_groups', 'json') || [];
  const policyGroups = {};
  await Promise.all(policyGroupIds.map(async id => { policyGroups[id] = await env.DASHBOARD_KV.get(`policy_group:${id}`, 'json'); }));
  const userGroupIds = await env.DASHBOARD_KV.get('user_groups', 'json') || [];
  const userGroups = {};
  await Promise.all(userGroupIds.map(async id => { userGroups[id] = await env.DASHBOARD_KV.get(`user_group:${id}`, 'json'); }));
  const backup = {
    _meta: { version: 1, exportedAt: new Date().toISOString(), exportedBy: session.username },
    userlist, users,
    policyGroupIds, policyGroups,
    userGroupIds, userGroups,
    systemConfig:      await env.DASHBOARD_KV.get('system_config', 'json'),
    cameraList:        await env.DASHBOARD_KV.get('camera_list', 'json'),
    cameraListMovi:    await env.DASHBOARD_KV.get('camera_list_movi', 'json'),
    cameraAliasesMovi: await env.DASHBOARD_KV.get('camera_aliases_movi', 'json'),
  };
  await logActivity(env, { action: 'config-backup', username: session.username,
    ip: request.headers.get('CF-Connecting-IP') || '?', success: true, detail: `Exported ${userlist.length} users` });
  const fname = 'dashboard-backup-' + new Date().toISOString().slice(0, 10) + '.json';
  return new Response(JSON.stringify(backup, null, 2), {
    headers: { 'Content-Type': 'application/json', 'Content-Disposition': `attachment; filename="${fname}"`, 'Cache-Control': 'no-store' },
  });
}

/* ── Restore config from a backup file (admin) ──
   Validates shape + guarantees at least one admin survives, then overwrites KV. */
async function handleRestore(request, env) {
  const session = await getSession(request, env);
  if (!session || !(await isAdminUser(env, session))) return json({ error: 'Admin required' }, 403);
  if (request.method !== 'POST') return json({ error: 'POST required' }, 405);
  let body; try { body = await request.json(); } catch { return json({ error: 'File backup không phải JSON hợp lệ' }, 400); }
  if (!body || typeof body !== 'object' || !body._meta || !Array.isArray(body.userlist) || typeof body.users !== 'object' || !body.users) {
    return json({ error: 'File backup không đúng định dạng (thiếu _meta / userlist / users)' }, 400);
  }
  if (body.confirm !== true) return json({ error: 'Cần xác nhận trước khi khôi phục' }, 400);
  // Safety: at least one admin-role account must exist after restore (avoid lockout)
  const hasAdmin = body.userlist.some(u => { const o = body.users[u]; return o && o.role === 'admin'; });
  if (!hasAdmin) return json({ error: 'File backup không có tài khoản admin nào — từ chối để tránh khóa cứng hệ thống.' }, 400);

  // Validate each user object minimally
  for (const u of body.userlist) {
    const o = body.users[u];
    if (!o || typeof o !== 'object' || typeof o.password !== 'string') {
      return json({ error: `User "${u}" trong backup thiếu trường password — file hỏng.` }, 400);
    }
  }

  // Remove users that are no longer in the backup (and their sessions)
  const currentList = await env.DASHBOARD_KV.get('userlist', 'json') || [];
  const newSet = new Set(body.userlist);
  for (const u of currentList) {
    if (!newSet.has(u)) {
      await invalidateUserSessions(env, u);
      await env.DASHBOARD_KV.delete(`user:${u}`).catch(() => {});
    }
  }
  // Write users + list
  for (const u of body.userlist) await env.DASHBOARD_KV.put(`user:${u}`, JSON.stringify(body.users[u]));
  await env.DASHBOARD_KV.put('userlist', JSON.stringify(body.userlist));

  // Policy groups
  if (Array.isArray(body.policyGroupIds) && body.policyGroups) {
    await env.DASHBOARD_KV.put('policy_groups', JSON.stringify(body.policyGroupIds));
    for (const id of body.policyGroupIds) if (body.policyGroups[id]) await env.DASHBOARD_KV.put(`policy_group:${id}`, JSON.stringify(body.policyGroups[id]));
  }
  // User groups
  if (Array.isArray(body.userGroupIds) && body.userGroups) {
    await env.DASHBOARD_KV.put('user_groups', JSON.stringify(body.userGroupIds));
    for (const id of body.userGroupIds) if (body.userGroups[id]) await env.DASHBOARD_KV.put(`user_group:${id}`, JSON.stringify(body.userGroups[id]));
  }
  // System config + cameras
  if (body.systemConfig)      await env.DASHBOARD_KV.put('system_config', JSON.stringify(body.systemConfig));
  if (body.cameraList)        await env.DASHBOARD_KV.put('camera_list', JSON.stringify(body.cameraList));
  if (body.cameraListMovi)    await env.DASHBOARD_KV.put('camera_list_movi', JSON.stringify(body.cameraListMovi));
  if (body.cameraAliasesMovi) await env.DASHBOARD_KV.put('camera_aliases_movi', JSON.stringify(body.cameraAliasesMovi));

  _effCache.clear();        // drop all cached permissions
  _invalidateCfgCache();    // drop cached system config
  await logActivity(env, { action: 'config-restore', username: session.username,
    ip: request.headers.get('CF-Connecting-IP') || '?', success: true, detail: `Restored ${body.userlist.length} users from backup (${body._meta.exportedAt || '?'})` });
  return json({ success: true, users: body.userlist.length });
}

async function handleTestEmail(request, env) {
  const session = await getSession(request, env);
  if (!session) return json({ error: 'Session expired' }, 401);
  if (!(await isAdminUser(env, session))) return json({ error: 'Admin required' }, 403);
  const cfg = await env.DASHBOARD_KV.get('system_config', 'json') || {};
  if (!cfg.emailEnabled) return json({ error: 'Email notifications chưa được bật' }, 400);
  const wh = cleanEnv(cfg.emailWebhook);
  if (!wh) return json({ error: 'Webhook URL chưa được cấu hình' }, 400);
  const ip = request.headers.get('CF-Connecting-IP') || '?';
  try {
    const res = await fetch(wh, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        event: 'test',
        username: session.username,
        ip,
        timestamp: new Date().toISOString(),
        emailTo: cleanEnv(cfg.emailAdminAddress),
        message: 'Test email từ Dashboard — nếu nhận được email này, webhook đang hoạt động đúng.',
      }),
      signal: AbortSignal.timeout(8000),
    });
    if (!res.ok) return json({ error: `Webhook trả về HTTP ${res.status}` }, 502);
    return json({ success: true });
  } catch (e) {
    return json({ error: `Không thể kết nối webhook: ${e.message}` }, 502);
  }
}

async function handleChangePw(request, env, username, ctx) {
  const session = await getSession(request, env);
  if (!session) return json({ error: 'Not authenticated' }, 401);
  if (!(await isAdminUser(env, session)) && session.username !== username) return json({ error: 'Forbidden' }, 403);
  let body; try { body = await request.json(); } catch { return json({ error: 'Invalid JSON' }, 400); }
  const pwCfg = await _getCfg(env);
  const pwMin = Math.max(4, pwCfg.pwMinLength ?? 6);
  if (!body?.password || body.password.length < pwMin) return json({ error: `Password quá ngắn (tối thiểu ${pwMin} ký tự)` }, 400);
  const user = await env.DASHBOARD_KV.get(`user:${username}`, 'json');
  if (!user) return json({ error: 'User not found' }, 404);
  // ── MFA verification: required when user changes their OWN password and MFA is enabled ──
  const isSelfChange = session.username === username;
  if (isSelfChange && user.mfaSecret) {
    const mfaCode = String(body.mfaCode || '').trim();
    if (!mfaCode) return json({ error: 'Vui lòng nhập mã MFA để xác nhận đổi mật khẩu' }, 400);
    if (!(await verifyTotp(user.mfaSecret, mfaCode))) return json({ error: 'Mã MFA không đúng. Vui lòng kiểm tra lại.' }, 400);
  }
  user.password = await hashPw(body.password);
  user.pwChangedAt = Date.now();         // track for password expiry
  user.mustChangePassword = false;       // clear forced-change flag
  await env.DASHBOARD_KV.put(`user:${username}`, JSON.stringify(user));
  // Invalidate all existing sessions so old sessions can't reuse stale auth
  await invalidateUserSessions(env, username);
  await logActivity(env, { action: 'password-change', username: session.username, success: true, detail: `Changed password for: ${username}` });
  notifyEmail(env, ctx, 'password_changed', { username, changedBy: session.username });
  return json({ success: true });
}

/* ═══════════════════════════════════════════════
   Policy Groups & Granular Permissions
   ═══════════════════════════════════════════════ */

/* ── Helper: merge one policy_group object into eff ── */
function _mergePolicyGroup(g, eff) {
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
async function getSessionDelegateServices(env, session) {
  const user = await env.DASHBOARD_KV.get(`user:${session.username}`, 'json');
  if (!user || !Array.isArray(user.canManagePerms)) return [];
  return user.canManagePerms.filter(s => ALL_SERVICES.includes(s));
}

/**
 * Returns true if the session represents an admin — either by account role (fast, no KV)
 * or via a policy group with role='admin' (requires computeEffectivePermissions).
 * Use this everywhere instead of session.role === 'admin' so group-based admins work.
 */
async function isAdminUser(env, session) {
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
const _effCache = new Map(); // username -> { eff, exp }
const EFF_CACHE_TTL_MS = 8000;
function _invalidateEffCache(username) { if (username) _effCache.delete(username); }

/* ── Short-TTL in-memory session cache (hot path) ──
   getSession does a KV read on EVERY authenticated request, including per-frame
   camera snapshot fetches. This cache collapses those reads so the KV is hit at
   most once per SESSION_CACHE_TTL_MS per token. Logout and invalidateUserSessions
   call _invalidateSessionCache for instant effect. */
const _sessionCache = new Map(); // token -> { session, exp }
const SESSION_CACHE_TTL_MS = 30_000;
function _invalidateSessionCache(token) { if (token) _sessionCache.delete(token); }

/* ── Worker-level JPEG cache for latest.jpg snapshot polling ──
   3 parallel browser workers × N cameras = N×3 requests/sec to Frigate.
   This cache lets only 1 request per 250ms per camera reach Frigate;
   the other workers get an instant in-memory response. */
const _snapJpgCache = new Map(); // subPath → { bytes: Uint8Array, ct: string, exp: number }
const SNAP_JPG_TTL_MS = 250;

async function computeEffectivePermissions(env, username) {
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
async function hasPerm(env, session, permKey) {
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
async function hasWritePerm(env, session, permKey) {
  if (!session) return false;
  if (session.role === 'admin') return true;
  const eff = await computeEffectivePermissions(env, session.username);
  if (!eff) return false;
  if (eff.role === 'admin') return true;
  return (eff.permissions[permKey] || 'none') === 'write';
}

/** Whitelist permission keys/values để chặn XSS qua group names/permission keys */
function sanitizePermissions(raw) {
  if (!raw || typeof raw !== 'object') return {};
  const out = {};
  const VALID_VALS = ['none', 'read', 'write'];
  for (const k of Object.keys(raw)) {
    if (ALL_SERVICES.includes(k) && VALID_VALS.includes(raw[k])) out[k] = raw[k];
  }
  return out;
}
function sanitizeSysPerms(raw) {
  if (!raw || typeof raw !== 'object') return {};
  const out = {};
  if (raw.addUser === true) out.addUser = true;
  if (raw.systemConfig === true) out.systemConfig = true;
  if (raw.resetMfa === true) out.resetMfa = true;
  if (raw.blockUser === true) out.blockUser = true;
  return out;
}
function sanitizePanels(raw) {
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
function sanitizeCameraIds(raw) {
  if (!Array.isArray(raw)) return [];
  return raw.filter(c => typeof c === 'string' && /^[a-zA-Z0-9_-]{1,64}$/.test(c));
}
function sanitizeName(s, maxLen = 64) {
  if (typeof s !== 'string') return '';
  // strip HTML tags / control chars
  return s.replace(/<[^>]*>/g, '').replace(/[^\x20-\x7EÀ-ɏ]/g, '').trim().slice(0, maxLen);
}
/** Store value as-is if its JSON is within maxBytes; otherwise store truncated string representation. */
function _truncateJson(v, maxBytes) {
  try {
    const s = JSON.stringify(v);
    if (s.length <= maxBytes) return v;
    return { _truncated: true, preview: s.slice(0, maxBytes) };
  } catch (_) { return null; }
}

async function handleListGroups(request, env) {
  const session = await getSession(request, env);
  if (!session) return json({ error: 'Unauthorized' }, 401);
  // Allow admin, delegated managers, or users with sysPerms.addUser (read-only for group assignment during user creation)
  if (!(await isAdminUser(env, session))) {
    const callerRaw = await env.DASHBOARD_KV.get(`user:${session.username}`, 'json');
    const delegateSvcs = await getSessionDelegateServices(env, session);
    if (!delegateSvcs.length && !callerRaw?.sysPerms?.addUser) return json({ error: 'Admin required' }, 403);
  }
  const ids = await env.DASHBOARD_KV.get('policy_groups', 'json') || [];
  const groups = [];
  for (const id of ids) {
    const g = await env.DASHBOARD_KV.get(`policy_group:${id}`, 'json');
    if (g) groups.push(g);
  }
  return json({ groups });
}

async function handleCreateGroup(request, env) {
  const session = await getSession(request, env);
  if (!session) return json({ error: 'Unauthorized' }, 401);
  if (request.method !== 'POST') return json({ error: 'POST required' }, 405);
  const isAdmin = await isAdminUser(env, session);
  const delegateSvcs = isAdmin ? null : await getSessionDelegateServices(env, session);
  if (!isAdmin && (!delegateSvcs || !delegateSvcs.length)) return json({ error: 'Admin required' }, 403);
  let body; try { body = await request.json(); } catch { return json({ error: 'Invalid JSON' }, 400); }
  const name = sanitizeName(String(body?.name || ''));
  if (!name || name.length > 64) return json({ error: 'Tên group không hợp lệ' }, 400);
  const id = name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '') || ('g-' + Date.now());
  if (await env.DASHBOARD_KV.get(`policy_group:${id}`)) return json({ error: 'Group đã tồn tại' }, 409);
  // Delegated users cannot create admin-role groups
  const allowedGroupRoles = isAdmin ? ['user', 'admin'] : ['user'];
  const rawPerms = sanitizePermissions(body?.permissions);
  // Delegated users: permissions limited to their managed services
  const permissions = isAdmin ? rawPerms
    : Object.fromEntries(Object.entries(rawPerms).filter(([k]) => delegateSvcs.includes(k)));
  const group = {
    id, name,
    description: sanitizeName(String(body?.description || ''), 256),
    role:        allowedGroupRoles.includes(body?.role) ? body.role : null,
    permissions,
    panels:      isAdmin ? sanitizePanels(body?.panels) : {},
    cameras:     isAdmin ? sanitizeCameraIds(body?.cameras) : [],
    created: Date.now(),
    createdBy: session.username,
  };
  await env.DASHBOARD_KV.put(`policy_group:${id}`, JSON.stringify(group));
  const ids = await env.DASHBOARD_KV.get('policy_groups', 'json') || [];
  if (!ids.includes(id)) { ids.push(id); await env.DASHBOARD_KV.put('policy_groups', JSON.stringify(ids)); }
  if (!isAdmin) await logActivity(env, { action: 'delegate-create-policygroup', username: session.username, success: true, detail: `Created group: ${name}` });
  return json({ success: true, group });
}

async function handleUpdateGroup(request, env, groupId) {
  const session = await getSession(request, env);
  if (!session) return json({ error: 'Unauthorized' }, 401);
  const isAdmin = await isAdminUser(env, session);
  const delegateSvcs = isAdmin ? null : await getSessionDelegateServices(env, session);
  if (!isAdmin && (!delegateSvcs || !delegateSvcs.length)) return json({ error: 'Admin required' }, 403);
  const group = await env.DASHBOARD_KV.get(`policy_group:${groupId}`, 'json');
  if (!group) return json({ error: 'Group not found' }, 404);
  let body; try { body = await request.json(); } catch { return json({ error: 'Invalid JSON' }, 400); }
  if (isAdmin) {
    if (body.name        !== undefined) group.name        = sanitizeName(String(body.name));
    if (body.description !== undefined) group.description = sanitizeName(String(body.description), 256);
    if (body.role        !== undefined) group.role        = ['user', 'admin'].includes(body.role) ? body.role : null;
    if (body.permissions !== undefined) group.permissions = sanitizePermissions(body.permissions);
    if (body.panels      !== undefined) group.panels      = sanitizePanels(body.panels);
    if (body.cameras     !== undefined) group.cameras     = sanitizeCameraIds(body.cameras);
  } else {
    // Delegated user: can update name/description; permissions limited to managed services; cannot set admin role
    if (body.name        !== undefined) group.name        = sanitizeName(String(body.name));
    if (body.description !== undefined) group.description = sanitizeName(String(body.description), 256);
    if (body.role !== undefined) group.role = (body.role === 'user') ? 'user' : (body.role === '' || body.role === null) ? null : group.role; // never allow 'admin'
    if (body.permissions !== undefined) {
      const newPerms = sanitizePermissions(body.permissions);
      group.permissions = group.permissions || {};
      for (const svc of delegateSvcs) {
        if (newPerms[svc] !== undefined) group.permissions[svc] = newPerms[svc];
      }
    }
    await logActivity(env, { action: 'delegate-update-policygroup', username: session.username, success: true, detail: `Updated group: ${group.name} (services: ${delegateSvcs.join(',')})` });
  }
  await env.DASHBOARD_KV.put(`policy_group:${groupId}`, JSON.stringify(group));
  return json({ success: true, group });
}

async function handleDeleteGroup(request, env, groupId) {
  const session = await getSession(request, env);
  if (!session || !(await isAdminUser(env, session))) return json({ error: 'Admin required' }, 403);
  await env.DASHBOARD_KV.delete(`policy_group:${groupId}`);
  const ids = (await env.DASHBOARD_KV.get('policy_groups', 'json') || []).filter(id => id !== groupId);
  await env.DASHBOARD_KV.put('policy_groups', JSON.stringify(ids));
  const userlist = await env.DASHBOARD_KV.get('userlist', 'json') || [];
  if (userlist.length > 0) {
    const allUsers = await Promise.all(userlist.map(u => env.DASHBOARD_KV.get(`user:${u}`, 'json')));
    await Promise.all(allUsers.map((user, i) => {
      if (!user || !user.groups || !user.groups.includes(groupId)) return Promise.resolve();
      user.groups = user.groups.filter(g => g !== groupId);
      _invalidateEffCache(userlist[i]);
      return env.DASHBOARD_KV.put(`user:${userlist[i]}`, JSON.stringify(user));
    }));
  }
  return json({ success: true });
}

/* ═══════════════════════════════════════════════
   User Groups (gom users → gán Role Management Groups)
   KV:  user_groups          → string[]  (list of IDs)
        user_group:{id}      → { id, name, description, members[], roleGroups[], created }
   ═══════════════════════════════════════════════ */

async function handleListUserGroups(request, env) {
  const session = await getSession(request, env);
  if (!session) return json({ error: 'Unauthorized' }, 401);
  if (!(await isAdminUser(env, session))) {
    const callerRaw = await env.DASHBOARD_KV.get(`user:${session.username}`, 'json');
    const delegateSvcs = await getSessionDelegateServices(env, session);
    if (!delegateSvcs.length && !callerRaw?.sysPerms?.addUser) return json({ error: 'Admin required' }, 403);
  }
  const ids = await env.DASHBOARD_KV.get('user_groups', 'json') || [];
  const groups = [];
  for (const id of ids) {
    const g = await env.DASHBOARD_KV.get(`user_group:${id}`, 'json');
    if (g) groups.push(g);
  }
  return json({ groups });
}

async function handleCreateUserGroup(request, env) {
  const session = await getSession(request, env);
  if (!session) return json({ error: 'Unauthorized' }, 401);
  if (!(await isAdminUser(env, session))) {
    const delegateSvcs = await getSessionDelegateServices(env, session);
    if (!delegateSvcs.length) return json({ error: 'Admin required' }, 403);
  }
  if (request.method !== 'POST') return json({ error: 'POST required' }, 405);
  let body; try { body = await request.json(); } catch { return json({ error: 'Invalid JSON' }, 400); }
  const name = sanitizeName(String(body?.name || ''));
  if (!name || name.length < 1) return json({ error: 'Tên User Group không hợp lệ' }, 400);
  // Unique ID: prefix ug- + slug + timestamp
  const slug = name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '') || 'grp';
  const id = `ug-${slug}-${Date.now().toString(36)}`;
  const group = {
    id, name,
    description: sanitizeName(String(body?.description || ''), 256),
    members:    [],
    roleGroups: [],
    created: Date.now(),
  };
  await env.DASHBOARD_KV.put(`user_group:${id}`, JSON.stringify(group));
  const ids = await env.DASHBOARD_KV.get('user_groups', 'json') || [];
  if (!ids.includes(id)) { ids.push(id); await env.DASHBOARD_KV.put('user_groups', JSON.stringify(ids)); }
  await logActivity(env, { action: 'user-group-create', username: session.username,
    ip: request.headers.get('CF-Connecting-IP') || '?', success: true, detail: `Created: ${name}` });
  return json({ success: true, group });
}

async function handleUpdateUserGroup(request, env, groupId) {
  const session = await getSession(request, env);
  if (!session) return json({ error: 'Unauthorized' }, 401);
  if (!(await isAdminUser(env, session))) {
    const delegateSvcs = await getSessionDelegateServices(env, session);
    if (!delegateSvcs.length) return json({ error: 'Admin required' }, 403);
  }
  const group = await env.DASHBOARD_KV.get(`user_group:${groupId}`, 'json');
  if (!group) return json({ error: 'User Group not found' }, 404);
  let body; try { body = await request.json(); } catch { return json({ error: 'Invalid JSON' }, 400); }

  const prevMembers = [...(group.members || [])];

  if (body.name        !== undefined) group.name        = sanitizeName(String(body.name));
  if (body.description !== undefined) group.description = sanitizeName(String(body.description), 256);
  if (body.roleGroups  !== undefined) group.roleGroups  = Array.isArray(body.roleGroups)
    ? body.roleGroups.filter(s => typeof s === 'string' && s.length < 128).slice(0, 50)
    : group.roleGroups;
  if (body.members !== undefined) {
    group.members = Array.isArray(body.members)
      ? body.members.filter(s => typeof s === 'string' && s.length < 128).slice(0, 500)
      : group.members;
  }

  await env.DASHBOARD_KV.put(`user_group:${groupId}`, JSON.stringify(group));

  // Sync userGroups[] on user objects (add/remove references)
  const newMembers = group.members;
  const added   = newMembers.filter(u => !prevMembers.includes(u));
  const removed = prevMembers.filter(u => !newMembers.includes(u));
  for (const uname of added) {
    const u = await env.DASHBOARD_KV.get(`user:${uname}`, 'json');
    if (u) {
      u.userGroups = [...new Set([...(u.userGroups || []), groupId])];
      await env.DASHBOARD_KV.put(`user:${uname}`, JSON.stringify(u));
      _invalidateEffCache(uname);
    }
  }
  for (const uname of removed) {
    const u = await env.DASHBOARD_KV.get(`user:${uname}`, 'json');
    if (u) {
      u.userGroups = (u.userGroups || []).filter(g => g !== groupId);
      await env.DASHBOARD_KV.put(`user:${uname}`, JSON.stringify(u));
      _invalidateEffCache(uname);
    }
  }

  await logActivity(env, { action: 'user-group-update', username: session.username,
    ip: request.headers.get('CF-Connecting-IP') || '?', success: true, detail: `Updated: ${group.name}` });
  return json({ success: true, group });
}

async function handleDeleteUserGroup(request, env, groupId) {
  const session = await getSession(request, env);
  if (!session || !(await isAdminUser(env, session))) return json({ error: 'Admin required' }, 403);
  const group = await env.DASHBOARD_KV.get(`user_group:${groupId}`, 'json');
  if (!group) return json({ error: 'User Group not found' }, 404);
  // Remove userGroups ref from all member users
  for (const uname of (group.members || [])) {
    const u = await env.DASHBOARD_KV.get(`user:${uname}`, 'json');
    if (u) {
      u.userGroups = (u.userGroups || []).filter(g => g !== groupId);
      await env.DASHBOARD_KV.put(`user:${uname}`, JSON.stringify(u));
      _invalidateEffCache(uname);
    }
  }
  await env.DASHBOARD_KV.delete(`user_group:${groupId}`);
  const ids = (await env.DASHBOARD_KV.get('user_groups', 'json') || []).filter(id => id !== groupId);
  await env.DASHBOARD_KV.put('user_groups', JSON.stringify(ids));
  await logActivity(env, { action: 'user-group-delete', username: session.username,
    ip: request.headers.get('CF-Connecting-IP') || '?', success: true, detail: `Deleted: ${group.name}` });
  return json({ success: true });
}

async function handleUpdateUserGroups(request, env, username) {
  const session = await getSession(request, env);
  if (!session) return json({ error: 'Unauthorized' }, 401);
  const isAdmin = await isAdminUser(env, session);
  if (!isAdmin) {
    // Delegate với canManagePerms cũng được phép assign groups
    const callerUser = await env.DASHBOARD_KV.get(`user:${session.username}`, 'json');
    const delegateSvcs = (callerUser && Array.isArray(callerUser.canManagePerms))
      ? callerUser.canManagePerms.filter(s => ALL_SERVICES.includes(s)) : [];
    if (!delegateSvcs.length) return json({ error: 'Admin required' }, 403);
  }
  if (username === 'admin') return json({ error: 'Không thể sửa admin' }, 400);
  const user = await env.DASHBOARD_KV.get(`user:${username}`, 'json');
  if (!user) return json({ error: 'User not found' }, 404);
  // Block delegated users from modifying admin users' groups
  if (!isAdmin && user.role === 'admin') return json({ error: 'Không thể sửa nhóm của tài khoản admin' }, 403);
  let body; try { body = await request.json(); } catch { return json({ error: 'Invalid JSON' }, 400); }
  if (isAdmin) {
    // Admin can assign any group
    user.groups = Array.isArray(body.groups) ? body.groups : [];
  } else {
    // [F-02 fix] Delegate: preserve existing admin-role groups, block adding new ones
    const currentAdminGroups = [];
    for (const gid of (user.groups || [])) {
      const g = await env.DASHBOARD_KV.get(`policy_group:${gid}`, 'json');
      if (g && g.role === 'admin') currentAdminGroups.push(gid);
    }
    const requested = Array.isArray(body.groups) ? body.groups : [];
    const safeNew = [];
    for (const gid of requested) {
      if (currentAdminGroups.includes(gid)) continue; // already preserved below
      const g = await env.DASHBOARD_KV.get(`policy_group:${gid}`, 'json');
      if (g && g.role === 'admin') continue; // delegate cannot assign admin-role groups
      safeNew.push(gid);
    }
    user.groups = [...currentAdminGroups, ...safeNew];
  }
  // Validate: mỗi user chỉ được join tối đa 1 nhóm có role (role-management group)
  if (user.groups && user.groups.length > 0) {
    const groupData = await Promise.all(user.groups.map(gid => env.DASHBOARD_KV.get(`policy_group:${gid}`, 'json')));
    const roleGroups = groupData.filter(g => g && g.role);
    if (roleGroups.length > 1) {
      return json({ error: `Mỗi user chỉ được join 1 nhóm Role Management. Đang cố gán: ${roleGroups.map(g => '"'+g.name+'"').join(', ')}` }, 400);
    }
  }
  // Allow role change — CHỈ ADMIN mới được đổi role (delegate KHÔNG được)
  const oldRole = user.role;
  if (body.role !== undefined && isAdmin) {
    const allowed = ['user', 'admin'];
    if (allowed.includes(body.role)) user.role = body.role;
  }
  await env.DASHBOARD_KV.put(`user:${username}`, JSON.stringify(user));
  _invalidateEffCache(username);
  const ip = request.headers.get('cf-connecting-ip') || 'unknown';
  // If role changed, invalidate existing sessions so change takes effect immediately
  if (body.role !== undefined && body.role !== oldRole) {
    await invalidateUserSessions(env, username);
    await logActivity(env, { action: 'role-change', username: session.username, ip, success: true,
      detail: `${username}: ${oldRole} → ${user.role}` });
  }
  await logActivity(env, { action: 'group-update', username: session.username, ip, success: true,
    detail: `${username} groups: [${user.groups.join(', ')}]` });
  return json({ success: true, username, groups: user.groups });
}

async function handleUpdateUserPanels(request, env, username) {
  const session = await getSession(request, env);
  if (!session || !(await isAdminUser(env, session))) return json({ error: 'Admin required' }, 403);
  if (username === 'admin') return json({ error: 'Không thể sửa admin' }, 400);
  const user = await env.DASHBOARD_KV.get(`user:${username}`, 'json');
  if (!user) return json({ error: 'User not found' }, 404);
  let body; try { body = await request.json(); } catch { return json({ error: 'Invalid JSON' }, 400); }
  // Allow saving permissions + panels + cameras atomically in a single write (avoids race condition)
  if (body.permissions !== undefined) user.permissions = sanitizePermissions(body.permissions);
  user.panels  = sanitizePanels(body.panels || {});
  user.cameras = Array.isArray(body.cameras) ? body.cameras : (user.cameras || []);
  await env.DASHBOARD_KV.put(`user:${username}`, JSON.stringify(user));
  _invalidateEffCache(username);
  return json({ success: true, username, permissions: user.permissions, panels: user.panels, cameras: user.cameras });
}

const DEFAULT_CAMERAS = [
  { id: 'cam01', name: 'Camera 01',          type: 'analog',  stream: 'cam01' },
  { id: 'cam03', name: 'Camera 03',          type: 'analog',  stream: 'cam03' },
  { id: 'cam04', name: 'Camera 04',          type: 'ip',      stream: 'cam04' },
  { id: 'cam05', name: 'Camera 05',          type: 'ip',      stream: 'cam05' },
  { id: 'cam06', name: 'Camera 06',          type: 'ip',      stream: 'cam06' },
  { id: 'cam07', name: 'Camera Phòng Khách', type: 'unknown', stream: null    },
];

const DEFAULT_CAMERAS_MOVI = [
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

async function handleMoviCameraList(request, env) {
  const session = await getSession(request, env);
  if (!session) return json({ error: 'Unauthorized' }, 401);
  if (request.method === 'GET') {
    let list = await env.DASHBOARD_KV.get('camera_list_movi', 'json');
    if (!Array.isArray(list)) {
      list = DEFAULT_CAMERAS_MOVI;
      await env.DASHBOARD_KV.put('camera_list_movi', JSON.stringify(list));
    }
    return json({ cameras: list });
  }
  if (request.method === 'PUT') {
    if (!(await isAdminUser(env, session))) return json({ error: 'Admin required' }, 403);
    let body; try { body = await request.json(); } catch { return json({ error: 'Invalid JSON' }, 400); }
    const cameras = Array.isArray(body.cameras) ? body.cameras : [];
    await env.DASHBOARD_KV.put('camera_list_movi', JSON.stringify(cameras));
    return json({ success: true, cameras });
  }
  return json({ error: 'Method not allowed' }, 405);
}

async function handleCameraList(request, env) {
  const session = await getSession(request, env);
  if (!session) return json({ error: 'Unauthorized' }, 401);
  if (request.method === 'GET') {
    let list = await env.DASHBOARD_KV.get('camera_list', 'json');
    if (!Array.isArray(list)) {
      // First-time: seed defaults into KV so policy.html camera tab is populated
      list = DEFAULT_CAMERAS;
      await env.DASHBOARD_KV.put('camera_list', JSON.stringify(list));
    }
    return json({ cameras: list });
  }
  if (request.method === 'PUT') {
    if (!(await isAdminUser(env, session))) return json({ error: 'Admin required' }, 403);
    let body; try { body = await request.json(); } catch { return json({ error: 'Invalid JSON' }, 400); }
    const cameras = Array.isArray(body.cameras) ? body.cameras : [];
    await env.DASHBOARD_KV.put('camera_list', JSON.stringify(cameras));
    return json({ success: true, cameras });
  }
  return json({ error: 'Method not allowed' }, 405);
}

/* ═══════════════════════════════════════════════
   TOTP / MFA — RFC 6238 (SHA-1, 30s window, 6 digits)
   Compatible with Microsoft Authenticator, Google Authenticator
   ═══════════════════════════════════════════════ */
const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function b32Decode(s) {
  s = s.toUpperCase().replace(/=+$/, '').replace(/\s/g, '');
  let bits = 0, val = 0;
  const out = [];
  for (const c of s) {
    const i = B32.indexOf(c);
    if (i < 0) continue;
    val = (val << 5) | i;
    bits += 5;
    if (bits >= 8) { out.push((val >>> (bits - 8)) & 0xff); bits -= 8; }
  }
  return new Uint8Array(out);
}

function b32Encode(bytes) {
  let bits = 0, val = 0, out = '';
  for (const b of bytes) {
    val = (val << 8) | b;
    bits += 8;
    while (bits >= 5) { out += B32[(val >>> (bits - 5)) & 31]; bits -= 5; }
  }
  if (bits > 0) out += B32[(val << (5 - bits)) & 31];
  return out;
}

async function totpCode(secret, windowOffset = 0) {
  const key = b32Decode(secret);
  const counter = Math.floor(Date.now() / 1000 / 30) + windowOffset;
  const buf = new ArrayBuffer(8);
  new DataView(buf).setBigUint64(0, BigInt(counter), false);
  const ck = await crypto.subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']);
  const hmac = new Uint8Array(await crypto.subtle.sign('HMAC', ck, buf));
  const off = hmac[19] & 0xf;
  const code = (((hmac[off] & 0x7f) << 24) | (hmac[off+1] << 16) | (hmac[off+2] << 8) | hmac[off+3]) % 1000000;
  return code.toString().padStart(6, '0');
}

async function verifyTotp(secret, code) {
  if (!secret || !code || String(code).length !== 6) return false;
  for (let w = -1; w <= 1; w++) {
    if (await totpCode(secret, w) === String(code)) return true;
  }
  return false;
}

/* ── MFA recovery codes (one-time backup codes) ──
   Plaintext shown to user ONCE at setup; only SHA-256 hashes stored.
   Used to log in when the authenticator device is lost. */
function _genRecoveryCodes(n) {
  const out = [];
  for (let i = 0; i < (n || 8); i++) {
    const s = b32Encode(crypto.getRandomValues(new Uint8Array(5))).slice(0, 8);
    out.push(s.slice(0, 4) + '-' + s.slice(4, 8));
  }
  return out;
}
function _normRecovery(code) { return String(code || '').toUpperCase().replace(/[^A-Z0-9]/g, ''); }
async function _hashRecovery(code) { return _sha256Hex('rc:' + _normRecovery(code)); }
async function _genRecoveryHashes(codes) { return Promise.all(codes.map(_hashRecovery)); }
/** If `code` matches an unused recovery hash, consume it (mutates user.mfaRecovery) and return true. */
async function tryConsumeRecovery(user, code) {
  if (!user || !Array.isArray(user.mfaRecovery) || !user.mfaRecovery.length) return false;
  const norm = _normRecovery(code);
  if (norm.length < 6) return false;            // TOTP is 6 digits; recovery codes are 8 base32 chars
  const h = await _hashRecovery(code);
  const idx = user.mfaRecovery.findIndex(x => _constEq(x, h));
  if (idx < 0) return false;
  user.mfaRecovery.splice(idx, 1);              // single-use: remove on success
  return true;
}

/* ── MFA API handlers ── */

// Generate QR code server-side so the browser never needs to reach external services.
// Worker egress always works; browser network may block external QR APIs (VPN, firewall).
async function _fetchQrDataUrl(otpauth) {
  try {
    const url = `https://api.qrserver.com/v1/create-qr-code/?size=200x200&margin=8&data=${encodeURIComponent(otpauth)}`;
    const res = await fetch(url);
    if (!res.ok) return null;
    const bytes = new Uint8Array(await res.arrayBuffer());
    let bin = '';
    for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return `data:image/png;base64,${btoa(bin)}`;
  } catch (_) { return null; }
}

async function handleMfaSetup(request, env) {
  const session = await getSession(request, env);
  if (!session) return json({ error: 'Not authenticated' }, 401);
  const raw = crypto.getRandomValues(new Uint8Array(20));
  const secret = b32Encode(raw);
  const label   = encodeURIComponent(`HomeLab:${session.username}`);
  const issuer  = encodeURIComponent('HomeLab Dashboard');
  const otpauth = `otpauth://totp/${label}?secret=${secret}&issuer=${issuer}&algorithm=SHA1&digits=6&period=30`;
  const qrDataUrl = await _fetchQrDataUrl(otpauth);
  return json({ secret, otpauth, qrDataUrl });
}

async function handleMfaEnable(request, env) {
  const session = await getSession(request, env);
  if (!session) return json({ error: 'Not authenticated' }, 401);
  if (request.method !== 'POST') return json({ error: 'POST required' }, 405);
  let body; try { body = await request.json(); } catch { return json({ error: 'Invalid JSON' }, 400); }
  const { secret, code, currentCode } = body || {};
  if (!secret || !code) return json({ error: 'Thiếu secret hoặc code' }, 400);

  const user = await env.DASHBOARD_KV.get(`user:${session.username}`, 'json');
  if (!user) return json({ error: 'User not found' }, 404);

  // [H1] Security: if MFA already active, require current OTP before allowing
  // secret rotation. Prevents session-hijack → permanent MFA takeover.
  if (user.mfaEnabled && user.mfaSecret) {
    if (!currentCode) return json({ error: 'Cần xác minh mã MFA hiện tại trước khi thay đổi.' }, 400);
    if (!(await verifyTotp(user.mfaSecret, currentCode)))
      return json({ error: 'Mã MFA hiện tại không đúng. Vui lòng thử lại.' }, 400);
  }

  if (!(await verifyTotp(secret, code)))
    return json({ error: 'Mã OTP mới không đúng. Kiểm tra đồng hồ thiết bị.' }, 400);

  user.mfaEnabled = true;
  user.mfaSecret  = secret;
  // Generate fresh one-time recovery codes (replace any previous set)
  const recoveryCodes = _genRecoveryCodes(8);
  user.mfaRecovery = await _genRecoveryHashes(recoveryCodes);
  await env.DASHBOARD_KV.put(`user:${session.username}`, JSON.stringify(user));
  _invalidateEffCache(session.username);
  return json({ success: true, recoveryCodes });
}

async function handleMfaDisable(request, env) {
  const session = await getSession(request, env);
  if (!session) return json({ error: 'Not authenticated' }, 401);
  if (request.method !== 'POST') return json({ error: 'POST required' }, 405);

  const user = await env.DASHBOARD_KV.get(`user:${session.username}`, 'json');
  if (!user) return json({ error: 'User not found' }, 404);

  // Local accounts: MFA is mandatory and cannot be disabled
  if (!user.microsoftEmail) {
    return json({ error: 'MFA là bắt buộc đối với tài khoản local và không thể tắt. Bạn chỉ có thể đổi mã MFA (reset secret).' }, 403);
  }

  // SAML/Microsoft accounts: MFA is optional — allow disable with OTP confirmation
  if (!user.mfaEnabled || !user.mfaSecret) {
    return json({ success: true, message: 'MFA chưa được bật.' });
  }

  let body; try { body = await request.json(); } catch { body = {}; }
  const { code } = body || {};
  if (!code) return json({ error: 'Cần nhập mã OTP hiện tại để tắt MFA.' }, 400);
  if (!(await verifyTotp(user.mfaSecret, String(code)))) {
    return json({ error: 'Mã OTP không đúng.' }, 400);
  }

  user.mfaEnabled = false;
  user.mfaSecret  = null;
  await env.DASHBOARD_KV.put(`user:${session.username}`, JSON.stringify(user));
  _invalidateEffCache(session.username);
  const ip = request.headers.get('cf-connecting-ip') || request.headers.get('x-forwarded-for') || 'unknown';
  await logActivity(env, { action: 'mfa_disabled', username: session.username, ip, success: true, detail: 'SAML user disabled MFA' });
  return json({ success: true });
}

async function handleMfaStatus(request, env) {
  const session = await getSession(request, env);
  if (!session) return json({ error: 'Not authenticated' }, 401);
  const user = await env.DASHBOARD_KV.get(`user:${session.username}`, 'json');
  return json({ enabled: !!(user && user.mfaEnabled) });
}

async function handleMfaVerify(request, env) {
  if (request.method !== 'POST') return json({ error: 'POST required' }, 405);
  let body; try { body = await request.json(); } catch { return json({ error: 'Invalid JSON' }, 400); }
  const { tempToken, code } = body || {};
  if (!tempToken || !code) return json({ error: 'Thiếu tempToken hoặc code' }, 400);
  const ip = request.headers.get('cf-connecting-ip') || request.headers.get('x-forwarded-for') || 'unknown';
  const temp = await env.DASHBOARD_KV.get(`mfa_temp:${tempToken}`, 'json');
  if (!temp || Date.now() > temp.expires) {
    if (temp) await env.DASHBOARD_KV.delete(`mfa_temp:${tempToken}`).catch(() => {});
    return json({ error: 'Phiên xác thực đã hết hạn. Vui lòng đăng nhập lại.' }, 401);
  }
  // Cap OTP guesses per temp token (TOTP = 1e6 space); burn token after 6 misses
  if ((await rlGet(env, `mfa:${tempToken}`)) >= 6) {
    await env.DASHBOARD_KV.delete(`mfa_temp:${tempToken}`).catch(() => {});
    await logActivity(env, { action: 'mfa_blocked', username: temp?.username, ip, success: false, detail: 'Too many OTP attempts' });
    return json({ error: 'Sai mã quá nhiều lần. Vui lòng đăng nhập lại.' }, 429);
  }
  const user = await env.DASHBOARD_KV.get(`user:${temp.username}`, 'json');
  if (!user || !user.mfaEnabled) return json({ error: 'Lỗi xác thực MFA' }, 400);
  let mfaOk = await verifyTotp(user.mfaSecret, code);
  let usedRecovery = false;
  if (!mfaOk && await tryConsumeRecovery(user, code)) {
    mfaOk = true; usedRecovery = true;
    await env.DASHBOARD_KV.put(`user:${temp.username}`, JSON.stringify(user)); // persist consumed code
  }
  if (!mfaOk) {
    await rlBump(env, `mfa:${tempToken}`, 360);
    await logActivity(env, { action: 'mfa_fail', username: temp?.username, ip, success: false, detail: 'Wrong OTP' });
    return json({ error: 'Mã OTP không đúng' }, 400);
  }
  await rlClear(env, `mfa:${tempToken}`);
  await env.DASHBOARD_KV.delete(`mfa_temp:${tempToken}`).catch(() => {});
  if (usedRecovery) await logActivity(env, { action: 'mfa_recovery_used', username: temp.username, ip, success: true, detail: `Recovery code used · ${(user.mfaRecovery||[]).length} còn lại` });
  // Create full session — use dynamic TTL from system_config
  const mfaCfg = await _getCfg(env);
  const mfaSessionTtl = Math.max(1, mfaCfg.sessionTtlHours ?? 8) * 3600;
  const token = crypto.randomUUID();
  await env.DASHBOARD_KV.put(`session:${token}`, JSON.stringify({
    username: temp.username, role: user.role, permissions: user.permissions || {},
    boundIp: ip,
    expires: Date.now() + mfaSessionTtl * 1000
  }), { expirationTtl: mfaSessionTtl });
  const userInfo = encodeURIComponent(JSON.stringify({
    username: temp.username, role: user.role,
    permissions: user.permissions || {},
    isAdmin: user.role === 'admin'
  }));
  const h = new Headers({ 'Content-Type': 'application/json' });
  h.append('Set-Cookie', `${SESSION_COOKIE}=${token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${mfaSessionTtl}`);
  h.append('Set-Cookie', `dh_user=${userInfo}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${mfaSessionTtl}`);
  await logActivity(env, { action: 'mfa_success', username: temp.username, ip, success: true });
  return new Response(JSON.stringify({ success: true, role: user.role }), { status: 200, headers: h });
}

/* ── Microsoft OIDC SSO ── */

async function handleMicrosoftAuth(request, env) {
  const clientId = cleanEnv(env.SAML_AZURE_CLIENT_ID);
  const tenantId = cleanEnv(env.SAML_AZURE_TENANT_ID);
  const origin   = new URL(request.url).origin;
  if (!clientId || !tenantId) return Response.redirect(`${origin}/login.html?sso_error=` + encodeURIComponent('Microsoft SSO chưa được cấu hình'), 302);

  const state = crypto.randomUUID();
  const ip    = request.headers.get('cf-connecting-ip') || 'unknown';
  await env.DASHBOARD_KV.put(`ms_state:${state}`, JSON.stringify({ ip, created: Date.now() }), { expirationTtl: 600 });

  const redirectUri = `${origin}/auth/microsoft/callback`;
  const params      = new URLSearchParams({
    client_id:     clientId,
    response_type: 'code',
    redirect_uri:  redirectUri,
    response_mode: 'query',
    scope:         'openid profile email User.Read',
    state,
  });
  return Response.redirect(`https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/authorize?${params}`, 302);
}

async function handleMicrosoftCallback(request, env, ctx) {
  const url       = new URL(request.url);
  const code      = url.searchParams.get('code');
  const state     = url.searchParams.get('state');
  const msError   = url.searchParams.get('error');
  const msErrDesc = url.searchParams.get('error_description');

  const clientId     = cleanEnv(env.SAML_AZURE_CLIENT_ID);
  const tenantId     = cleanEnv(env.SAML_AZURE_TENANT_ID);
  const clientSecret = cleanEnv(env.SAML_AZURE_CLIENT_SECRET);

  const _origin = new URL(request.url).origin;
  const fail = (msg) => Response.redirect(`${_origin}/login.html?sso_error=` + encodeURIComponent(msg), 302);

  if (msError)        return fail(msErrDesc || msError);
  if (!code || !state) return fail('Thiếu thông tin xác thực từ Microsoft');
  if (!clientId || !tenantId || !clientSecret) return fail('Microsoft SSO chưa được cấu hình đầy đủ');

  // Validate state (CSRF protection)
  const storedState = await env.DASHBOARD_KV.get(`ms_state:${state}`, 'json');
  if (!storedState) return fail('Phiên xác thực đã hết hạn. Vui lòng thử lại.');
  await env.DASHBOARD_KV.delete(`ms_state:${state}`).catch(() => {});

  const origin      = new URL(request.url).origin;
  const redirectUri = `${origin}/auth/microsoft/callback`;

  // Exchange authorization code → tokens
  let tokenData;
  try {
    const tokenRes = await fetch(`https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/token`, {
      method:  'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body:    new URLSearchParams({
        client_id:     clientId,
        client_secret: clientSecret,
        code,
        redirect_uri:  redirectUri,
        grant_type:    'authorization_code',
        scope:         'openid profile email User.Read',
      }),
    });
    tokenData = await tokenRes.json();
  } catch (e) {
    return fail('Không thể liên hệ Microsoft. Vui lòng thử lại.');
  }
  if (tokenData.error) return fail(tokenData.error_description || tokenData.error);

  // Decode ID token (JWT) — token đến từ Microsoft qua HTTPS server-side, đã tin cậy
  let idPayload;
  try {
    const part = (tokenData.id_token || '').split('.')[1] || '';
    // Base64url → base64 → decode
    const b64 = part.replace(/-/g, '+').replace(/_/g, '/').padEnd(part.length + (4 - part.length % 4) % 4, '=');
    idPayload = JSON.parse(atob(b64));
  } catch (e) {
    return fail('Không thể đọc thông tin từ Microsoft token');
  }

  // Validate basic claims
  if (idPayload.exp && Math.floor(Date.now() / 1000) > idPayload.exp) return fail('Token Microsoft đã hết hạn');
  if (idPayload.aud && idPayload.aud !== clientId) return fail('Token không hợp lệ (aud mismatch)');
  // Issuer must be a Microsoft v2.0 endpoint (rejects tokens minted elsewhere)
  if (!/^https:\/\/login\.microsoftonline\.com\/[^/]+\/v2\.0$/.test(idPayload.iss || ''))
    return fail('Token không hợp lệ (iss không phải Microsoft)');
  // For a single-tenant config (tenantId is a GUID), the token's tenant (tid)
  // must match — blocks valid tokens issued for a different Azure tenant.
  const _isGuidTenant = /^[0-9a-f-]{36}$/i.test(tenantId);
  if (_isGuidTenant && idPayload.tid && idPayload.tid !== tenantId)
    return fail('Token không hợp lệ (tenant mismatch)');

  // Extract email — Microsoft có thể trả về các field khác nhau tùy tenant
  const msEmail = (idPayload.preferred_username || idPayload.email || idPayload.unique_name || '').toLowerCase().trim();
  if (!msEmail) return fail('Không lấy được email từ tài khoản Microsoft');

  const ip  = request.headers.get('cf-connecting-ip') || request.headers.get('x-forwarded-for') || 'unknown';
  const cfg = await _getCfg(env);

  // Kiểm tra domain được phép (nếu có cấu hình SAML_AZURE_ALLOWED_DOMAIN)
  const allowedDomain = cleanEnv(env.SAML_AZURE_ALLOWED_DOMAIN).toLowerCase();
  if (allowedDomain) {
    const emailDomain = msEmail.split('@')[1] || '';
    if (emailDomain !== allowedDomain)
      return fail(`Domain "${emailDomain}" không được phép đăng nhập. Chỉ chấp nhận @${allowedDomain}`);
  }

  const emailPrefix = msEmail.split('@')[0].replace(/[^a-zA-Z0-9_.@-]/g, '').slice(0, 64);
  const userlist    = await env.DASHBOARD_KV.get('userlist', 'json') || [];
  let matchedUser = null, matchedUsername = null;

  // Bước 1: Tìm user đã được liên kết với email Microsoft này
  for (const uname of userlist) {
    const u = await env.DASHBOARD_KV.get(`user:${uname}`, 'json');
    if (!u) continue;
    if ((u.microsoftEmail || '').toLowerCase().trim() === msEmail) {
      matchedUser = u; matchedUsername = uname; break;
    }
  }

  // Bước 2: Auto-link theo username prefix đã bị tắt (bảo mật — kẻ tấn công có thể dùng email
  // trùng tên để chiếm tài khoản). Admin phải dùng API PUT /api/admin/users/:username/microsoft-email
  // để liên kết thủ công. Bước 1 đã xử lý đủ trường hợp đã liên kết rồi.

  // Bước 3: Không tìm thấy → TỪ CHỐI. Admin phải tạo user và liên kết microsoftEmail trước.
  // Không auto-create: bất kỳ Azure tenant user nào cũng có thể lấy token hợp lệ nếu Azure App
  // chưa bật "Assignment required" — auto-create sẽ cho phép người lạ vào dashboard.
  if (!matchedUser) {
    await logActivity(env, { action: 'login_microsoft_rejected', ip, success: false, detail: `No dashboard account linked to ${msEmail}` });
    return new Response(`<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Truy cập bị từ chối</title>
<style>body{font-family:system-ui,sans-serif;background:#09090b;color:#f4f4f5;display:flex;align-items:center;justify-content:center;height:100vh;margin:0}
.box{text-align:center;max-width:420px;padding:32px;background:#18181b;border:1px solid #27272a;border-radius:16px}
.icon{font-size:48px;margin-bottom:16px}.title{font-size:18px;font-weight:700;color:#f87171;margin-bottom:10px}
.msg{font-size:14px;color:#a1a1aa;line-height:1.6;margin-bottom:8px}
.email{font-size:13px;color:#60a5fa;font-family:monospace;background:#1e2a3a;padding:4px 10px;border-radius:6px;display:inline-block;margin:8px 0 16px}
.note{font-size:12px;color:#71717a;margin-top:12px}
.btn{margin-top:18px;padding:8px 20px;background:#3f3f46;color:#f4f4f5;border:none;border-radius:6px;cursor:pointer;font-size:13px;text-decoration:none;display:inline-block}
</style></head><body><div class="box">
<div class="icon">🚫</div>
<div class="title">Tài khoản chưa được cấp quyền</div>
<div class="msg">Tài khoản Microsoft của bạn chưa được liên kết với dashboard.</div>
<div class="email">${msEmail}</div>
<div class="msg">Vui lòng liên hệ admin để được cấp quyền truy cập.</div>
<div class="note">Admin cần tạo tài khoản và liên kết email Azure trong phần Cài đặt Hệ thống.</div>
<a class="btn" href="/login.html">← Quay lại đăng nhập</a>
</div></body></html>`, { status: 403, headers: { 'Content-Type': 'text/html;charset=UTF-8' } });
  }

  if (matchedUser.locked) return fail('Tài khoản bị khóa. Vui lòng liên hệ admin.');
  if (matchedUser.blocked) return fail('Tài khoản đã bị chặn bởi quản trị viên. Vui lòng liên hệ admin.');

  // ── MFA check for SSO users: if MFA enabled, require TOTP before creating session ──
  if (matchedUser.mfaEnabled && matchedUser.mfaSecret) {
    const mfaTempToken = crypto.randomUUID();
    await env.DASHBOARD_KV.put(`ms_mfa_temp:${mfaTempToken}`, JSON.stringify({
      username: matchedUsername,
      boundIp: ip,
      expires: Date.now() + 300_000,
    }), { expirationTtl: 300 });
    await logActivity(env, { action: 'login_microsoft_mfa_required', username: matchedUsername, ip, success: true, detail: 'MFA step required for SSO' });
    const t = mfaTempToken;
    const mfaHtml = `<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Xác minh MFA</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>body{font-family:system-ui,sans-serif;background:#09090b;color:#f4f4f5;display:flex;align-items:center;justify-content:center;height:100vh;margin:0}
.box{text-align:center;width:320px;padding:0 16px}
.icon{font-size:40px;margin-bottom:12px}
h3{margin:0 0 6px;font-size:16px;font-weight:600}
p{color:#a1a1aa;font-size:13px;margin:0 0 14px;line-height:1.5}
.inp-otp{width:100%;padding:12px;background:#18181b;border:1px solid #3f3f46;border-radius:8px;color:#f4f4f5;font-size:22px;letter-spacing:6px;text-align:center;box-sizing:border-box;outline:none}
.inp-rc{width:100%;padding:12px;background:#18181b;border:1px solid #3f3f46;border-radius:8px;color:#f4f4f5;font-size:18px;letter-spacing:3px;text-align:center;box-sizing:border-box;outline:none;font-family:monospace}
.inp-otp:focus,.inp-rc:focus{border-color:#2563eb}
.btn{width:100%;padding:11px;margin-top:12px;background:#2563eb;color:#fff;border:none;border-radius:8px;font-size:14px;font-weight:600;cursor:pointer}
.btn:hover{background:#1d4ed8}.btn:disabled{opacity:.5;cursor:not-allowed}
.err{color:#ef4444;font-size:13px;margin-top:10px;min-height:18px}
.toggle-rc{display:block;margin-top:12px;color:#71717a;font-size:12px;text-decoration:none;cursor:pointer}
.toggle-rc:hover{color:#a1a1aa}
</style></head><body><div class="box">
<div class="icon">🔐</div>
<h3>Xác minh hai bước</h3>
<p id="sub">Đăng nhập Microsoft thành công.<br>Nhập mã 6 số từ ứng dụng authenticator.</p>
<div id="otp-group"><input type="text" id="otp" class="inp-otp" maxlength="6" inputmode="numeric" pattern="[0-9]*" placeholder="000000" autocomplete="one-time-code" autofocus></div>
<div id="rc-group" style="display:none"><input type="text" id="rc" class="inp-rc" maxlength="9" placeholder="XXXX-XXXX" autocomplete="off" autocapitalize="characters"></div>
<div class="err" id="err"></div>
<button class="btn" id="btn" onclick="doVerify()">🔑 Xác minh</button>
<a class="toggle-rc" id="toggle" onclick="toggleRC()">🔑 Dùng mã khôi phục</a>
</div><script>
var T='${t}';
var useRC=false;
var otpInp=document.getElementById('otp');
var rcInp=document.getElementById('rc');
var btn=document.getElementById('btn');
var err=document.getElementById('err');
otpInp.addEventListener('input',function(){this.value=this.value.replace(/\\D/g,'');if(this.value.length===6)doVerify();});
otpInp.addEventListener('keydown',function(e){if(e.key==='Enter')doVerify();});
rcInp.addEventListener('input',function(){var p=this.selectionStart;this.value=this.value.toUpperCase();this.setSelectionRange(p,p);});
rcInp.addEventListener('keydown',function(e){if(e.key==='Enter')doVerify();});
function toggleRC(){
  useRC=!useRC;
  err.textContent='';
  document.getElementById('otp-group').style.display=useRC?'none':'';
  document.getElementById('rc-group').style.display=useRC?'':'none';
  document.getElementById('toggle').textContent=useRC?'← Dùng mã OTP':'🔑 Dùng mã khôi phục';
  document.getElementById('sub').textContent=useRC?'Nhập một trong các mã khôi phục (XXXX-XXXX) đã lưu khi kích hoạt MFA.':'Đăng nhập Microsoft thành công. Nhập mã 6 số từ ứng dụng authenticator.';
  if(useRC){rcInp.value='';setTimeout(function(){rcInp.focus();},60);}
  else{otpInp.value='';setTimeout(function(){otpInp.focus();},60);}
}
function doVerify(){
  err.textContent='';
  var code;
  if(useRC){
    code=rcInp.value.trim().toUpperCase();
    if(!code){err.textContent='Vui lòng nhập mã khôi phục';return;}
  }else{
    code=otpInp.value.replace(/\\D/g,'');
    if(code.length!==6){err.textContent='Nhập đủ 6 số';return;}
  }
  btn.disabled=true;btn.textContent='⏳ Đang xác minh...';
  fetch('/auth/microsoft/mfa',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({tempToken:T,code:code})})
  .then(function(r){return r.json();})
  .then(function(d){
    if(d.success){
      try{new BroadcastChannel('ms_sso_ch').postMessage('done');}catch(e){}
      try{if(window.opener&&!window.opener.closed){window.opener.postMessage({type:'ms_sso_done'},window.location.origin);}}catch(e){}
      window.close();
      setTimeout(function(){if(!window.closed){window.location.href='/';}},1500);
    }else{
      err.textContent=d.error||(useRC?'Mã khôi phục không đúng hoặc đã dùng':'Sai mã OTP');
      btn.disabled=false;btn.textContent='🔑 Xác minh';
      if(useRC){rcInp.value='';rcInp.focus();}else{otpInp.value='';otpInp.focus();}
    }
  }).catch(function(){
    err.textContent='Lỗi kết nối. Vui lòng thử lại.';
    btn.disabled=false;btn.textContent='🔑 Xác minh';
  });
}
<\/script></body></html>`;
    return new Response(mfaHtml, { status: 200, headers: { 'Content-Type': 'text/html; charset=utf-8' } });
  }

  const sessionTtl    = Math.max(1, cfg.sessionTtlHours ?? 8) * 3600;
  const token         = crypto.randomUUID();
  const canManagePerms = (matchedUser.canManagePerms || []).filter(s => ALL_SERVICES.includes(s));

  await env.DASHBOARD_KV.put(`session:${token}`, JSON.stringify({
    username: matchedUsername, role: matchedUser.role,
    permissions: matchedUser.permissions || {},
    canManagePerms,
    boundIp: ip,
    authMethod: 'microsoft',
    createdAt: Date.now(),
    expires: Date.now() + sessionTtl * 1000,
  }), { expirationTtl: sessionTtl });

  const userInfo = encodeURIComponent(JSON.stringify({
    username: matchedUsername, role: matchedUser.role,
    permissions: matchedUser.permissions || {},
    isAdmin: matchedUser.role === 'admin',
    canManagePerms,
    authMethod: 'microsoft',
    mfaEnabled: false,
  }));

  await logActivity(env, { action: 'login_microsoft', username: matchedUsername, ip, success: true, detail: `SSO via ${msEmail}` });
  notifyEmail(env, ctx, 'login_success', { username: matchedUsername, ip });

  // Trả về HTML — nếu mở từ popup thì postMessage để login page tự navigate, rồi close ngay.
  // KHÔNG navigate popup (window.location.href = '/') vì sẽ gây popup hiện dashboard.
  // NOTE: window.opener bị nullify bởi COOP headers của Microsoft sau khi OAuth redirect.
  // Không thể dùng opener.postMessage() hay check hasOpener để detect popup flow.
  // Dùng BroadcastChannel (same-origin, không phụ thuộc opener) để notify login page.
  const popupHtml = `<!DOCTYPE html><html><head><meta charset="UTF-8">
<title>Đăng nhập thành công</title>
<style>body{font-family:sans-serif;background:#09090b;color:#f4f4f5;display:flex;align-items:center;justify-content:center;height:100vh;margin:0}
.box{text-align:center}.icon{font-size:48px;margin-bottom:12px}.msg{font-size:15px;color:#a1a1aa}
.closebtn{margin-top:18px;padding:8px 20px;background:#3b82f6;color:#fff;border:none;border-radius:6px;cursor:pointer;font-size:14px;display:none}</style>
</head><body><div class="box">
<div class="icon">✅</div>
<div class="msg" id="msg">Đăng nhập thành công. Đang đóng...</div>
<button class="closebtn" id="cbtn" onclick="window.close()">Đóng cửa sổ này</button>
</div>
<script>
(function(){
  // 1. Broadcast to all same-origin windows (login page listener picks this up)
  //    BroadcastChannel works even when window.opener is null (COOP breaks opener but not BC)
  try { new BroadcastChannel('ms_sso_ch').postMessage('done'); } catch(e) {}
  // 2. Also try postMessage directly (fallback if BroadcastChannel not available)
  try { if (window.opener && !window.opener.closed) {
    window.opener.postMessage({ type: 'ms_sso_done' }, window.location.origin);
  }} catch(e) {}
  // 3. Close this popup — works if opened by window.open() regardless of opener status
  window.close();
  // 4. Fallback: if still open after 1.5s, this is likely a full-page redirect (not popup).
  //    Navigate to dashboard directly.
  setTimeout(function(){
    if (!window.closed) {
      // Still open: window.close() was blocked (e.g. full-page redirect, no BroadcastChannel listener closed us)
      // Safe to navigate — if login page already received BC message and navigated, this is the only window
      window.location.href = '/';
    }
  }, 1500);
})();
</script></body></html>`;

  const h = new Headers({ 'Content-Type': 'text/html; charset=utf-8' });
  h.append('Set-Cookie', `${SESSION_COOKIE}=${token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${sessionTtl}`);
  h.append('Set-Cookie', `dh_user=${userInfo}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${sessionTtl}`);
  return new Response(popupHtml, { status: 200, headers: h });
}

/* ── Microsoft SSO — MFA verify (POST /auth/microsoft/mfa) ── */
async function handleMicrosoftMfaVerify(request, env, ctx) {
  if (request.method !== 'POST') return json({ error: 'POST required' }, 405);
  let body; try { body = await request.json(); } catch { return json({ error: 'Invalid JSON' }, 400); }
  const { tempToken, code } = body || {};
  if (!tempToken || !code) return json({ error: 'Thiếu tempToken hoặc code' }, 400);
  const ip = request.headers.get('cf-connecting-ip') || request.headers.get('x-forwarded-for') || 'unknown';

  const temp = await env.DASHBOARD_KV.get(`ms_mfa_temp:${tempToken}`, 'json');
  if (!temp || Date.now() > temp.expires) {
    if (temp) await env.DASHBOARD_KV.delete(`ms_mfa_temp:${tempToken}`).catch(() => {});
    return json({ error: 'Phiên đã hết hạn. Vui lòng đăng nhập lại.' }, 401);
  }

  // Rate limit: max 6 wrong guesses then burn the temp token
  if ((await rlGet(env, `ms_mfa:${tempToken}`)) >= 6) {
    await env.DASHBOARD_KV.delete(`ms_mfa_temp:${tempToken}`).catch(() => {});
    await logActivity(env, { action: 'mfa_blocked', username: temp.username, ip, success: false, detail: 'Too many OTP attempts (SSO)' });
    return json({ error: 'Sai mã quá nhiều lần. Vui lòng đăng nhập lại.' }, 429);
  }

  const user = await env.DASHBOARD_KV.get(`user:${temp.username}`, 'json');
  if (!user || !user.mfaEnabled || !user.mfaSecret) return json({ error: 'Lỗi xác thực MFA' }, 400);

  let mfaOk = await verifyTotp(user.mfaSecret, String(code));
  let usedRecovery = false;
  if (!mfaOk && await tryConsumeRecovery(user, code)) {
    mfaOk = true; usedRecovery = true;
    await env.DASHBOARD_KV.put(`user:${temp.username}`, JSON.stringify(user));
  }
  if (!mfaOk) {
    await rlBump(env, `ms_mfa:${tempToken}`, 360);
    await logActivity(env, { action: 'mfa_fail', username: temp.username, ip, success: false, detail: 'Wrong OTP (SSO)' });
    return json({ error: 'Mã OTP không đúng' }, 400);
  }

  // OTP correct — clean up temp + create full session
  await rlClear(env, `ms_mfa:${tempToken}`);
  await env.DASHBOARD_KV.delete(`ms_mfa_temp:${tempToken}`).catch(() => {});
  if (usedRecovery) await logActivity(env, { action: 'mfa_recovery_used', username: temp.username, ip, success: true, detail: `Recovery code used (SSO) · ${(user.mfaRecovery||[]).length} còn lại` });

  const cfg = await _getCfg(env);
  const sessionTtl = Math.max(1, cfg.sessionTtlHours ?? 8) * 3600;
  const token = crypto.randomUUID();
  const canManagePerms = (user.canManagePerms || []).filter(s => ALL_SERVICES.includes(s));

  await env.DASHBOARD_KV.put(`session:${token}`, JSON.stringify({
    username: temp.username, role: user.role, permissions: user.permissions || {},
    canManagePerms, boundIp: ip, authMethod: 'microsoft',
    createdAt: Date.now(), expires: Date.now() + sessionTtl * 1000,
  }), { expirationTtl: sessionTtl });

  const userInfo = encodeURIComponent(JSON.stringify({
    username: temp.username, role: user.role,
    permissions: user.permissions || {},
    isAdmin: user.role === 'admin',
    canManagePerms, authMethod: 'microsoft', mfaEnabled: true,
  }));

  await logActivity(env, { action: 'login_microsoft', username: temp.username, ip, success: true, detail: 'SSO + MFA verified' });
  notifyEmail(env, ctx, 'login_success', { username: temp.username, ip });

  const h = new Headers({ 'Content-Type': 'application/json' });
  h.append('Set-Cookie', `${SESSION_COOKIE}=${token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${sessionTtl}`);
  h.append('Set-Cookie', `dh_user=${userInfo}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${sessionTtl}`);
  return new Response(JSON.stringify({ success: true }), { status: 200, headers: h });
}

/* ── Setup Flow Handlers (first-login: change password + MFA setup) ── */

async function _createSessionAfterSetup(username, user, env, boundIp, extra) {
  const cfg = await _getCfg(env);
  const sessionTtl = Math.max(1, cfg.sessionTtlHours ?? 8) * 3600;
  const token = crypto.randomUUID();
  await env.DASHBOARD_KV.put(`session:${token}`, JSON.stringify({
    username, role: user.role, permissions: user.permissions || {},
    boundIp: boundIp || '',
    expires: Date.now() + sessionTtl * 1000,
  }), { expirationTtl: sessionTtl });
  const userInfo = encodeURIComponent(JSON.stringify({
    username, role: user.role, permissions: user.permissions || {}, isAdmin: user.role === 'admin',
  }));
  const h = new Headers({ 'Content-Type': 'application/json' });
  h.append('Set-Cookie', `${SESSION_COOKIE}=${token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${sessionTtl}`);
  h.append('Set-Cookie', `dh_user=${userInfo}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${sessionTtl}`);
  return new Response(JSON.stringify({ success: true, role: user.role, ...(extra || {}) }), { status: 200, headers: h });
}

async function _getSetupTemp(env, setupToken) {
  if (!setupToken) return null;
  const temp = await env.DASHBOARD_KV.get(`setup_temp:${setupToken}`, 'json');
  if (!temp || Date.now() > temp.expires) {
    if (temp) await env.DASHBOARD_KV.delete(`setup_temp:${setupToken}`).catch(() => {});
    return null;
  }
  return temp;
}

async function handleSetupChangePassword(request, env) {
  if (request.method !== 'POST') return json({ error: 'POST required' }, 405);
  let body; try { body = await request.json(); } catch { return json({ error: 'Invalid JSON' }, 400); }
  const { setupToken, newPassword } = body || {};
  const ip = request.headers.get('cf-connecting-ip') || 'unknown';
  if (!setupToken || !newPassword) return json({ error: 'Thiếu thông tin' }, 400);
  const temp = await _getSetupTemp(env, setupToken);
  if (!temp) return json({ error: 'Phiên thiết lập đã hết hạn. Vui lòng đăng nhập lại.' }, 401);
  if (!temp.mustChangePassword) return json({ error: 'Không cần đổi mật khẩu' }, 400);
  const setupPwCfg = await _getCfg(env);
  const setupPwMin = Math.max(8, setupPwCfg.pwMinLength ?? 8);
  if (newPassword.length < setupPwMin) return json({ error: `Mật khẩu tối thiểu ${setupPwMin} ký tự` }, 400);
  const user = await env.DASHBOARD_KV.get(`user:${temp.username}`, 'json');
  if (!user) return json({ error: 'User not found' }, 404);
  user.password = await hashPw(newPassword);
  user.mustChangePassword = false;
  await env.DASHBOARD_KV.put(`user:${temp.username}`, JSON.stringify(user));
  // Refresh token state
  const updatedTemp = { ...temp, mustChangePassword: false };
  await env.DASHBOARD_KV.put(`setup_temp:${setupToken}`, JSON.stringify(updatedTemp), { expirationTtl: 600 });
  await logActivity(env, { action: 'setup_password_changed', username: temp.username, ip, success: true });
  if (temp.mustSetupMfa) return json({ success: true, step: 'setupMfa', setupToken });
  return await _createSessionAfterSetup(temp.username, user, env, ip);
}

async function handleSetupMfaInit(request, env) {
  if (request.method !== 'POST') return json({ error: 'POST required' }, 405);
  let body; try { body = await request.json(); } catch { return json({ error: 'Invalid JSON' }, 400); }
  const { setupToken } = body || {};
  const temp = await _getSetupTemp(env, setupToken);
  if (!temp) return json({ error: 'Phiên thiết lập đã hết hạn. Vui lòng đăng nhập lại.' }, 401);
  const raw = crypto.getRandomValues(new Uint8Array(20));
  const secret = b32Encode(raw);
  const label   = encodeURIComponent(`HomeLab:${temp.username}`);
  const issuer  = encodeURIComponent('HomeLab Dashboard');
  const otpauth = `otpauth://totp/${label}?secret=${secret}&issuer=${issuer}&algorithm=SHA1&digits=6&period=30`;
  const qrDataUrl = await _fetchQrDataUrl(otpauth);
  await env.DASHBOARD_KV.put(`setup_mfa_secret:${setupToken}`, secret, { expirationTtl: 600 });
  return json({ secret, otpauth, qrDataUrl });
}

async function handleSetupMfaComplete(request, env) {
  if (request.method !== 'POST') return json({ error: 'POST required' }, 405);
  let body; try { body = await request.json(); } catch { return json({ error: 'Invalid JSON' }, 400); }
  const { setupToken, code } = body || {};
  const ip = request.headers.get('cf-connecting-ip') || 'unknown';
  if (!setupToken || !code) return json({ error: 'Thiếu thông tin' }, 400);

  // [H2] Rate limit: 6 wrong OTP attempts per setupToken → burn token immediately.
  // setupToken TTL is 600s, so rate-limit key shares that same window.
  const rlKey = `setup_mfa_rl:${setupToken}`;
  if ((await rlGet(env, rlKey)) >= 6) {
    await env.DASHBOARD_KV.delete(`setup_temp:${setupToken}`).catch(() => {});
    await env.DASHBOARD_KV.delete(`setup_mfa_secret:${setupToken}`).catch(() => {});
    await logActivity(env, { action: 'setup_mfa_blocked', ip, success: false, detail: 'Too many OTP attempts' });
    return json({ error: 'Sai mã quá nhiều lần. Vui lòng đăng nhập lại từ đầu.' }, 429);
  }

  const temp = await _getSetupTemp(env, setupToken);
  if (!temp) return json({ error: 'Phiên thiết lập đã hết hạn. Vui lòng đăng nhập lại.' }, 401);
  const secret = await env.DASHBOARD_KV.get(`setup_mfa_secret:${setupToken}`);
  if (!secret) return json({ error: 'Chưa khởi tạo MFA hoặc phiên đã hết hạn. Vui lòng thử lại.' }, 400);

  if (!(await verifyTotp(secret, code))) {
    await rlBump(env, rlKey, 600);
    return json({ error: 'Mã OTP không đúng. Kiểm tra đồng hồ thiết bị.' }, 400);
  }

  const user = await env.DASHBOARD_KV.get(`user:${temp.username}`, 'json');
  if (!user) return json({ error: 'User not found' }, 404);
  user.mfaEnabled   = true;
  user.mfaSecret    = secret;
  user.mustSetupMfa = false;
  const recoveryCodes = _genRecoveryCodes(8);
  user.mfaRecovery = await _genRecoveryHashes(recoveryCodes);
  await env.DASHBOARD_KV.put(`user:${temp.username}`, JSON.stringify(user));
  _invalidateEffCache(temp.username);
  await env.DASHBOARD_KV.delete(`setup_temp:${setupToken}`).catch(() => {});
  await env.DASHBOARD_KV.delete(`setup_mfa_secret:${setupToken}`).catch(() => {});
  await env.DASHBOARD_KV.delete(rlKey).catch(() => {});  // clean up on success
  await logActivity(env, { action: 'setup_mfa_complete', username: temp.username, ip, success: true });
  return await _createSessionAfterSetup(temp.username, user, env, ip, { recoveryCodes });
}

/* Shared "Wayfinding" quick-switcher — injected into every authenticated page.
   Lets users jump tool→tool and search without bouncing through the homepage.
   Self-contained, namespaced (wf-), never touches page/map code. */
const WAYFIND_NAV = `<style>
#wf-fab{position:fixed;right:16px;bottom:16px;z-index:2147483000;
 width:34px;height:34px;border-radius:50%;
 display:flex;align-items:center;justify-content:center;
 background:linear-gradient(180deg,#1c2c52,#142037);
 border:1.5px solid rgba(91,140,255,.7);
 cursor:pointer;box-shadow:0 4px 16px rgba(20,40,90,.5),0 0 0 3px rgba(91,140,255,.07);
 transition:all .15s;user-select:none}
#wf-fab:hover{border-color:#8fb3ff;box-shadow:0 6px 20px rgba(30,60,130,.6)}
#wf-fab .wf-dot{width:8px;height:8px;border-radius:50%;background:#5b8cff;box-shadow:0 0 9px #5b8cff}
@keyframes wfpulse{0%{box-shadow:0 4px 16px rgba(20,40,90,.5),0 0 0 0 rgba(91,140,255,.45)}
 70%{box-shadow:0 4px 16px rgba(20,40,90,.5),0 0 0 12px rgba(91,140,255,0)}
 100%{box-shadow:0 4px 16px rgba(20,40,90,.5),0 0 0 0 rgba(91,140,255,0)}}
#wf-fab.wf-pulse{animation:wfpulse 1.8s ease-out 3}
#wf-hint{position:fixed;right:60px;bottom:10px;z-index:2147483000;max-width:260px;
 background:#0c1018;border:1px solid #5b8cff;border-radius:11px;padding:12px 14px;display:none;
 font:13px/1.5 -apple-system,'Segoe UI',sans-serif;color:#cdd6e6;box-shadow:0 10px 30px rgba(0,0,0,.6)}
#wf-hint.on{display:block}
#wf-hint b{color:#8fb3ff}
#wf-hint .wf-x{position:absolute;top:6px;right:9px;color:#5e6f92;cursor:pointer;font-size:14px}
#wf-ov{position:fixed;inset:0;z-index:2147483600;display:none;align-items:flex-start;justify-content:center;
 background:rgba(4,6,11,.72);backdrop-filter:blur(3px)}
#wf-ov.on{display:flex}
#wf-panel{margin-top:11vh;width:min(680px,92vw);background:#0c1018;border:1px solid #283450;
 border-radius:16px;box-shadow:0 24px 70px rgba(0,0,0,.7);overflow:hidden;
 font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif}
#wf-search{width:100%;box-sizing:border-box;background:#0c1018;border:0;border-bottom:1px solid #1d2740;
 color:#eef2fa;font-size:16px;padding:18px 20px;outline:none;font-family:inherit}
#wf-search::placeholder{color:#46587a}
#wf-list{max-height:56vh;overflow-y:auto;padding:8px}
.wf-row{display:flex;align-items:center;gap:14px;padding:11px 14px;border-radius:10px;cursor:pointer;
 color:#cdd6e6;text-decoration:none}
.wf-row .wf-ic{width:30px;height:30px;flex:0 0 30px;display:flex;align-items:center;justify-content:center;
 font-size:16px;background:#121a2c;border:1px solid #243049;border-radius:8px}
.wf-row .wf-nm{font-size:13.5px;font-weight:600}
.wf-row .wf-ds{font-size:11px;color:#5e6f92;margin-top:2px}
.wf-row .wf-tag{margin-left:auto;font-size:10px;color:#5b8cff;font-family:JetBrains Mono,monospace;
 border:1px solid #2b3a5c;border-radius:6px;padding:3px 7px;white-space:nowrap}
.wf-row.sel,.wf-row:hover{background:#16203a}
.wf-row.cur .wf-tag{color:#34d399;border-color:#2c5a44}
#wf-foot{display:flex;gap:18px;padding:10px 18px;border-top:1px solid #1d2740;
 font:11px JetBrains Mono,monospace;color:#46587a}
#wf-foot b{color:#7c8baa;font-weight:600}
</style>
<div id="wf-fab" title="Chuyển trang nhanh (phím tắt: /)" onclick="window.__wfOpen&&window.__wfOpen()">
 <span class="wf-dot"></span></div>
<div id="wf-hint"><span class="wf-x" title="Đóng" onclick="document.getElementById('wf-hint').classList.remove('on')">&#x2715;</span>
 &#x1F449; Bấm nút này (hoặc phím <b>/</b>) để nhảy thẳng giữa các trang — Meraki, FortiGate, ESXi, MOVI…</div>
<div id="wf-ov"><div id="wf-panel">
 <input id="wf-search" placeholder="Tìm dịch vụ… (gõ để lọc, &#x2191;&#x2193; chọn, Enter mở)" autocomplete="off">
 <div id="wf-list"></div>
 <div id="wf-foot"><span><b>&#x2191;&#x2193;</b> di chuyển</span><span><b>Enter</b> mở</span><span><b>Esc</b> đóng</span><span style="margin-left:auto"><b>/</b> hoặc <b>g</b> mở bất kỳ đâu</span></div>
</div></div>
<script>(function(){
 if(window.__wfNav)return; window.__wfNav=1;
 if(location.pathname==='/login.html')return;
 var U=(window.__USER__||{}), adm=!!U.isAdmin, P=U.permissions||{};
 var _TMK=['tool-movi-create-user','tool-movi-block-user','tool-movi-delete-user','tool-movi-asset-search','tool-movi-check-email','tool-movi-azure-group','tool-movi-fg-policy-lan','tool-movi-fg-policy-wifi'];
 function _hp(pk){if(!pk)return true;if(Array.isArray(pk))return pk.some(function(k){return(P[k]||'none')!=='none';});return(P[pk]||'none')!=='none';}
 var _ALL=[
  {i:'\\u2316',n:'Dashboard',d:'Trang chủ · tất cả dịch vụ',h:'/',p:null},
  {i:'\\uD83C\\uDF10',n:'Meraki-Network',d:'Network client monitor · Cisco Meraki',h:'/service-movi/meraki.html',p:'meraki'},
  {i:'\\uD83D\\uDDFA',n:'Movi Map Network',d:'Sơ đồ topology · route · dây switch',h:'/service-movi/topology.html',p:'topology'},
  {i:'\\uD83D\\uDD25',n:'FortiGate Movi',d:'Firewall dashboard · bandwidth · interfaces live',h:'/service-movi/fortigate-movi.html',p:'fortigate-movi'},
  {i:'\\uD83D\\uDCF9',n:'Camera Movi',d:'Camera live · go2rtc · RTSP streams',h:'/service-movi/camera-movi.html',p:'camera-movi'},
  {i:'\\u26A1',n:'n8n Movi',d:'Workflow automation · Movi Finance',h:'/service-movi/n8n-movi.html',p:'n8n-movi'},
  {i:'🛠',n:'Tool Movi',d:'Workflow triggers · n8n automation',h:'/service-movi/tool-movi.html',p:_TMK},
  {i:'\uD83D\uDDA5',n:'VMware01 Movi',d:'ESXi host 01 · Movi Finance datacenter',h:'/service-movi/vmware01-movi.html',p:'vmware01-movi'},
  {i:'\uD83D\uDDA5',n:'VMware02 Movi',d:'ESXi host 02 · Movi Finance datacenter',h:'/service-movi/vmware02-movi.html',p:'vmware02-movi'},
  {i:'\\uD83D\\uDD25',n:'FortiGate',d:'Firewall · security gateway',h:'/service-home/fortigate.html',p:'fortigate'},
  {i:'\\uD83D\\uDDA5',n:'VMware ESXi',d:'Hypervisor · bare metal',h:'/service-home/vmware-home.html',p:'esxi'},
  {i:'\\uD83C\\uDFE0',n:'CasaOS',d:'Home server OS',h:'/service-home/casaos.html',p:'casaos'},
  {i:'\\uD83D\\uDCE1',n:'ASUS Router',d:'Home network router',h:'/service-home/asus.html',p:'asus'},
  {i:'\\uD83D\\uDD00',n:'9Router',d:'Router & network management',h:'/service-home/9router.html',p:'9router'},
  {i:'\\u26A1',n:'n8n Automation',d:'Workflow & bot automation',h:'/service-home/n8n.html',p:'n8n'},
  {i:'\\uD83D\\uDCF7',n:'Camera',d:'Hệ thống camera · go2rtc',h:'/service-home/hikvision.html',p:'camera'},
  {i:'\\uD83D\\uDDA7',n:'SSH Terminal',d:'Web SSH · Termix',h:'/service-home/ssh.html',p:'ssh'},
  {i:'\\uD83D\\uDDA5',n:'RustDesk',d:'Remote desktop · máy nhân viên',h:'/service-home/rustdesk.html',p:'rustdesk'},
  {i:'\\uD83D\\uDDA7',n:'Termix Movi',d:'SSH Movi · token auth',h:'/service-movi/ssh-movi.html',p:'ssh-movi'},
  {i:'\\uD83D\\uDD16',n:'Bookmarks',d:'Liên kết nhanh',h:'/bookmarks.html',p:null}
 ];
 if(adm){_ALL.push({i:'\\u2699',n:'Settings',d:'Cài đặt hệ thống · User · Audit · Role · MFA (admin)',h:'/settings.html',p:null});}
 var S=adm?_ALL:_ALL.filter(function(s){return _hp(s.p);});
 var here=location.pathname.replace(/\\/index\\.html$/,'/')||'/';

 var fab=document.getElementById('wf-fab'),
     ov=document.getElementById('wf-ov'),
     hint=document.getElementById('wf-hint'),
     listEl=document.getElementById('wf-list'),
     inEl=document.getElementById('wf-search'),
     rows=[],sel=0;
 if(!fab||!ov)return;

 function render(q){
  listEl.innerHTML='';
  q=(q||'').trim().toLowerCase();
  var items=S.filter(function(s){return !q||(s.n+' '+s.d).toLowerCase().indexOf(q)>=0;});
  rows=items; sel=0;
  if(!items.length){listEl.innerHTML='<div style="padding:26px;text-align:center;color:#46587a;font-size:13px">Không tìm thấy dịch vụ phù hợp</div>';return;}
  items.forEach(function(s,idx){
   var cur=s.h===here;
   var a=document.createElement('a'); a.className='wf-row'+(idx===0?' sel':'')+(cur?' cur':'');
   a.href=s.h;
   a.innerHTML='<span class="wf-ic">'+s.i+'</span><span><div class="wf-nm">'+s.n+'</div><div class="wf-ds">'+s.d+'</div></span>'+
     '<span class="wf-tag">'+(cur?'\\u25cf đang ở đây':'mở \\u2192')+'</span>';
   a.addEventListener('click',function(e){if(cur){e.preventDefault();closeP();}});
   listEl.appendChild(a);
  });
 }
 function paint(){var r=listEl.querySelectorAll('.wf-row');r.forEach(function(x,i){x.classList.toggle('sel',i===sel);});
  if(r[sel])r[sel].scrollIntoView({block:'nearest'});}
 function openP(){if(hint)hint.classList.remove('on');fab.classList.remove('wf-pulse');ov.classList.add('on');inEl.value='';render('');setTimeout(function(){inEl.focus();},30);}
 function closeP(){ov.classList.remove('on');}
 window.__wfOpen=openP;
 ov.addEventListener('click',function(e){if(e.target===ov)closeP();});
 ov.addEventListener('input',function(e){if(e.target.id==='wf-search')render(e.target.value);});
 document.addEventListener('keydown',function(e){
  var t=e.target,tag=(t&&t.tagName||'').toLowerCase(),typing=tag==='input'||tag==='textarea'||(t&&t.isContentEditable);
  if(!ov.classList.contains('on')){
   if((e.key==='/'||e.key==='g')&&!typing&&!e.ctrlKey&&!e.metaKey&&!e.altKey){e.preventDefault();openP();}
   return;
  }
  if(e.key==='Escape'){e.preventDefault();closeP();return;}
  if(e.key==='ArrowDown'){e.preventDefault();sel=Math.min(sel+1,rows.length-1);paint();return;}
  if(e.key==='ArrowUp'){e.preventDefault();sel=Math.max(sel-1,0);paint();return;}
  if(e.key==='Enter'){var a=listEl.querySelectorAll('.wf-row')[sel];if(a){if(a.classList.contains('cur'))closeP();else location.href=a.getAttribute('href');}}
 });
 try{
  if(!sessionStorage.getItem('wfHinted')){
   sessionStorage.setItem('wfHinted','1');
   fab.classList.add('wf-pulse');
   if(hint){setTimeout(function(){hint.classList.add('on');},800);
            setTimeout(function(){hint.classList.remove('on');},9000);}
  }
 }catch(e){}
})();</script>`;

/* Shared "Reload data" control — small button + progress bar + status text.
   Calls the page's own data-loader so users refresh just the data, not the
   whole page. Injected as static markup before </body>. */
const DATA_REFRESH = `<style>
#wf-bar{position:fixed;top:0;left:0;height:3px;width:0;z-index:2147483647;
 background:linear-gradient(90deg,#5b8cff,#8fb3ff,#5b8cff);box-shadow:0 0 10px #5b8cff;
 opacity:0;transition:opacity .2s}
#wf-bar.on{opacity:1;animation:wfbar 1.1s ease-in-out infinite}
#wf-bar.done{animation:none;width:100%!important;transition:width .25s ease-out}
@keyframes wfbar{0%{width:8%}50%{width:72%}100%{width:92%}}
#wf-toast{position:fixed;left:50%;bottom:26px;transform:translateX(-50%) translateY(20px);
 z-index:2147483600;display:none;opacity:0;transition:all .25s;
 font:600 13px/1.4 -apple-system,'Segoe UI',sans-serif;color:#dfe8f5;
 background:#0c1018;border:1px solid #2b3a5c;border-radius:11px;padding:11px 18px;
 box-shadow:0 12px 34px rgba(0,0,0,.6)}
#wf-toast.on{display:block;opacity:1;transform:translateX(-50%) translateY(0)}
#wf-toast.ok{border-color:#2c8a5c;color:#bff0d4}
#wf-toast.err{border-color:#7a2d2d;color:#ffc4c4}
</style>
<div id="wf-bar"></div>
<div id="wf-toast"></div>
<script>(function(){
 if(window.__wfData)return;
 if(location.pathname==='/login.html')return;
 var MAP={'/':['runChecks'],'/index.html':['runChecks'],
  '/service-movi/meraki.html':['loadAll'],
  '/service-movi/topology.html':['loadData'],
  '/service-movi/fortigate-movi.html':['loadAll'],
  '/service-movi/camera-movi.html':['loadState'],
  '/service-movi/n8n-movi.html':['loadData'],
  '/service-movi/vmware01-movi.html':['loadData'],
  '/service-movi/vmware02-movi.html':['loadData'],
  '/service-movi/tool-movi.html':[],
  '/service-movi/ssh-movi.html':[],
  '/service-home/fortigate.html':['load'],'/service-home/vmware-home.html':['loadData'],'/service-home/casaos.html':['loadData'],
  '/service-home/asus.html':['load'],'/service-home/9router.html':['loadData'],'/service-home/n8n.html':['loadData'],
  '/service-home/hikvision.html':['loadState'],'/service-home/ssh.html':['loadData'],
  '/service-home/rustdesk.html':['loadDevices'],
  '/bookmarks.html':['loadData'],'/settings.html':['loadSettings']};
 var path=location.pathname.replace(/\\/index\\.html$/,'/');
 var fns=MAP[path]||MAP[location.pathname];
 var bar=document.getElementById('wf-bar'),
     toast=document.getElementById('wf-toast');
 if(!fns||!bar)return;
 var busy=false,tHide=null;
 function say(msg,cls,ms){
  clearTimeout(tHide); toast.className=''; toast.textContent=msg;
  if(cls)toast.classList.add(cls); toast.classList.add('on');
  if(ms)tHide=setTimeout(function(){toast.classList.remove('on');},ms);
 }
 function barStart(){bar.classList.remove('done');bar.classList.add('on');}
 function barDone(){bar.classList.remove('on');bar.classList.add('done');
  setTimeout(function(){bar.classList.remove('done');bar.style.width='';},420);}
 function run(){
  if(busy)return; busy=true;
  barStart(); say('\\u27F3 Đang tải lại dữ liệu…','',0);
  var t0=Date.now(), ps=[], called=0;
  fns.forEach(function(fn){
   try{ if(typeof window[fn]==='function'){ called++; var r=window[fn](); if(r&&typeof r.then==='function')ps.push(r); } }catch(e){}
  });
  function finish(ok){
   var wait=Math.max(0,900-(Date.now()-t0));
   setTimeout(function(){
    busy=false; barDone();
    if(ok){var n=new Date();
     say('\\u2713 Dữ liệu đã cập nhật · '+n.toLocaleTimeString('vi-VN',{hour12:false}),'ok',2800);}
    else say('\\u26A0 Tải lại thất bại — thử lại sau','err',3400);
   },wait);
  }
  if(!called){ /* loader not global → soft full reload as fallback */
   say('\\u27F3 Đang tải lại trang…','',0);
   setTimeout(function(){location.reload();},500); return;
  }
  if(ps.length) Promise.allSettled(ps).then(function(rs){
   finish(rs.every(function(x){return x.status==='fulfilled';})||rs.some(function(x){return x.status==='fulfilled';}));
  }); else finish(true);
 }
 window.__wfData=run;
})();</script>`;

/* Per-panel reload — small ⟳ button inside each panel header that reloads
   ONLY that panel's data (its own loader), with a per-panel progress bar. */
const PANEL_REFRESH = `<style>
.wf-pbtn{margin-left:7px;width:23px;height:23px;display:inline-flex;align-items:center;
 justify-content:center;font-size:12px;color:#7fe3b4;border:1px solid #2c8a5c;border-radius:6px;
 background:rgba(52,211,153,.10);cursor:pointer;flex-shrink:0;transition:all .15s;line-height:1}
.wf-pbtn:hover{background:rgba(52,211,153,.22);border-color:#34d399;color:#aef3d2}
.wf-pbtn.spin{animation:wfspin .7s linear infinite;pointer-events:none;opacity:.7}
.wf-host{position:relative}
.wf-pbar{position:absolute;left:0;right:0;bottom:0;height:2px;width:0;border-radius:2px;
 background:linear-gradient(90deg,#34d399,#7fe3b4,#34d399);opacity:0;pointer-events:none}
.wf-pbar.on{opacity:1;animation:wfbar 1.05s ease-in-out infinite}
.wf-pbar.done{animation:none;width:100%!important;opacity:1;transition:width .2s,opacity .35s}
</style>
<script>(function(){
 if(window.__wfPanel)return; window.__wfPanel=1;
 var PMAP={'/service-movi/meraki.html':{
   'panel-clients':'loadClients','panel-devices':'loadDevices','panel-status':'loadStatus',
   'panel-events':'loadEvents','panel-uplinks':'loadUplinks','panel-vlans':'loadVlansRoutes',
   'panel-routes':'loadVlansRoutes','panel-ports':'loadSwitchPorts'}};
 var cfg=PMAP[location.pathname]; if(!cfg)return;
 function wire(){
  Object.keys(cfg).forEach(function(pid){
   var panel=document.getElementById(pid); if(!panel)return;
   var hdr=panel.querySelector('.panel-head,.panel-header'); if(!hdr||hdr.querySelector('.wf-pbtn'))return;
   hdr.classList.add('wf-host');
   var btn=document.createElement('span');
   btn.className='wf-pbtn'; btn.textContent='\\u27F3';
   btn.title='Tải lại riêng bảng này';
   var bar=document.createElement('div'); bar.className='wf-pbar';
   var chev=hdr.querySelector('.panel-chev,.chevron');
   if(chev)hdr.insertBefore(btn,chev); else hdr.appendChild(btn);
   hdr.appendChild(bar);
   var busy=false;
   btn.addEventListener('click',function(e){
    e.stopPropagation(); e.preventDefault();
    if(busy)return; busy=true;
    if(panel.classList.contains('collapsed'))panel.classList.remove('collapsed');
    btn.classList.add('spin'); bar.classList.remove('done'); bar.classList.add('on');
    var fn=cfg[pid], t0=Date.now(), pr=null;
    try{ if(typeof window[fn]==='function'){ var r=window[fn](); if(r&&typeof r.then==='function')pr=r; } }catch(x){}
    function done(){
     var wait=Math.max(0,760-(Date.now()-t0));
     setTimeout(function(){
      btn.classList.remove('spin'); bar.classList.remove('on'); bar.classList.add('done');
      setTimeout(function(){bar.classList.remove('done');bar.style.width='';},360);
      busy=false;
     },wait);
    }
    if(pr&&pr.then)pr.then(done,done); else done();
   });
  });
 }
 if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',wire);
 else wire();
 /* panels can be (re)built late — keep buttons present */
 var n=0,iv=setInterval(function(){wire();if(++n>20)clearInterval(iv);},500);
})();</script>`;

/* ── Mobile responsive: device detect + stylesheet injection ──
   Read-only header check, chỉ toggle CSS attribute — không đụng auth/session.
   CF-Device-Type chỉ có khi Cloudflare bật Cache-by-Device-Type; fallback UA.
   iPad hiện đại báo UA Macintosh → coi như desktop (màn hình lớn, hợp lý). */
function isMobileRequest(request) {
  const cfDev = (request.headers.get('CF-Device-Type') || '').toLowerCase();
  if (cfDev === 'mobile' || cfDev === 'tablet') return true;
  if (cfDev === 'desktop') return false;
  const ua = request.headers.get('User-Agent') || '';
  return /iPhone|iPod|Android.*Mobile|Mobile.*Android|BlackBerry|IEMobile|Opera Mini/i.test(ua);
}

/* Inject <link mobile.css> cuối <head> (sau inline <style> của page để
   thắng specificity tie) + gắn data-mobile="1" vào <html> nếu device mobile */
function applyMobilePatch(html, isMobile) {
  const link = '<link rel="stylesheet" href="/mobile.css">';
  html = /<\/head>/i.test(html)
    ? html.replace(/<\/head>/i, link + '\n</head>')
    : link + html;
  if (isMobile) html = html.replace(/<html(\s|>)/i, '<html data-mobile="1"$1');
  return html;
}

async function injectUser(request, env) {
  const session = await getSession(request, env);
  const url = new URL(request.url);
  const isLoginPage = url.pathname === '/login.html';

  // Login page: redirect if already logged in; otherwise serve with optional banner + inject idle time
  if (isLoginPage) {
    if (session) return Response.redirect(new URL('/', request.url).toString(), 302);
    const cfg = await _getCfg(env);
    const bannerMsg = (cfg.loginBannerMsg || '').trim();
    const idleMin   = Math.max(30, cfg.idleTimeoutMin ?? 60);
    // Background CSS
    let bgCss = '';
    if (cfg.loginBgType === 'color' && cfg.loginBgValue) {
      const safeColor = String(cfg.loginBgValue).replace(/[^a-zA-Z0-9#(),.\s%]/g, '');
      if (/^(#[0-9a-fA-F]{3,8}|rgb|rgba|hsl|hsla|oklch)/i.test(safeColor.trim())) {
        bgCss = `<style>body{background:${safeColor}!important}</style>`;
      }
    } else if (cfg.loginBgType === 'image' && cfg.loginBgValue) {
      const safeUrl = String(cfg.loginBgValue).replace(/[<>"';{}()]/g, '');
      if (/^https:\/\//i.test(safeUrl.trim())) {
        bgCss = `<style>body{background:url('${safeUrl}') center/cover no-repeat fixed!important;background-color:#09090b!important}</style>`;
      }
    }
    const needsPatch = bannerMsg || idleMin !== 60 || bgCss;
    const loginUrl  = new URL(request.url);
    const cleanReq  = new Request(loginUrl.origin + loginUrl.pathname, { method: 'GET', headers: { 'Accept': 'text/html' } });
    const loginRes  = await env.ASSETS.fetch(cleanReq);
    let loginHtml = await loginRes.text();
    loginHtml = applyMobilePatch(loginHtml, isMobileRequest(request));
    if (!needsPatch) {
      return new Response(loginHtml, { headers: {
        'content-type': 'text/html;charset=utf-8',
        'cache-control': 'no-store',
        'x-frame-options': 'DENY',
        'x-content-type-options': 'nosniff',
        'referrer-policy': 'strict-origin-when-cross-origin',
        'content-security-policy': "default-src 'self'; script-src 'self' 'unsafe-inline' https://challenges.cloudflare.com; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-src https://challenges.cloudflare.com; object-src 'none'; frame-ancestors 'none'",
      } });
    }
    // Patch idle notice text with actual configured idle timeout
    loginHtml = loginHtml.replace(
      /không có hoạt động trong <strong>\d+ phút<\/strong>/,
      `không có hoạt động trong <strong>${idleMin} phút</strong>`
    );
    if (bannerMsg) {
      const safe = bannerMsg.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
      const bannerHtml = `<div style="margin-bottom:1.25rem;padding:10px 14px;border-radius:10px;background:rgba(59,130,246,.08);border:1px solid rgba(59,130,246,.25);font-size:13px;color:#93c5fd;text-align:center;line-height:1.5">${safe}</div>`;
      loginHtml = loginHtml.replace('<div class="card">', '<div class="card">'+bannerHtml);
    }
    if (bgCss) loginHtml = loginHtml.replace('</head>', bgCss + '</head>');
    return new Response(loginHtml, { headers: {
      'content-type': 'text/html;charset=utf-8',
      'cache-control': 'no-store',
      'x-frame-options': 'DENY',
      'x-content-type-options': 'nosniff',
      'referrer-policy': 'strict-origin-when-cross-origin',
      'content-security-policy': "default-src 'self'; script-src 'self' 'unsafe-inline' https://challenges.cloudflare.com; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-src https://challenges.cloudflare.com; object-src 'none'; frame-ancestors 'none'",
    } });
  }

  // All other HTML: require auth
  if (!session) {
    return Response.redirect(new URL('/login.html', request.url).toString(), 302);
  }

  // Serve HTML with injected user info (use clean GET request to avoid ASSETS quirks)
  const cleanReq = new Request(request.url, { method: 'GET', headers: { 'Accept': 'text/html' } });
  const res = await env.ASSETS.fetch(cleanReq);
  const ct = res.headers.get('content-type') || '';
  if (!res.ok || (!ct.includes('text/html') && !ct.includes('application/octet-stream'))) return res;
  const html = await res.text();
  // Always compute from KV so role changes + group assignments take effect immediately
  const sysCfgPromise = _getCfg(env);
  let effPerms = { role: session.role || 'user', permissions: {}, panels: {}, cameras: [], groups: [] };
  const computed = await computeEffectivePermissions(env, session.username);
  if (computed) effPerms = computed;
  const isAdmin = effPerms.role === 'admin';
  const sysCfg  = (await sysCfgPromise) || {};

  // Maintenance mode: block non-admin users, show maintenance page
  if (!isAdmin && sysCfg.maintenanceMode) {
    const msg = (sysCfg.maintenanceMsg || 'Hệ thống đang bảo trì. Vui lòng quay lại sau.').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
    const maintHtml = `<!DOCTYPE html><html lang="vi"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Bảo trì hệ thống</title>
<style>*{box-sizing:border-box;margin:0;padding:0}body{font-family:system-ui,sans-serif;background:#0f172a;color:#e2e8f0;min-height:100vh;display:flex;align-items:center;justify-content:center}
.box{text-align:center;padding:3rem 2rem;max-width:480px}
.icon{font-size:4rem;margin-bottom:1.5rem}
h1{font-size:1.5rem;font-weight:700;margin-bottom:.75rem;color:#f8fafc}
p{font-size:1rem;color:#94a3b8;line-height:1.6;margin-bottom:2rem}
a{display:inline-block;padding:.65rem 1.5rem;background:#6366f1;color:#fff;border-radius:.5rem;text-decoration:none;font-weight:600;font-size:.9rem}
a:hover{background:#4f46e5}</style></head>
<body><div class="box"><div class="icon">🚧</div><h1>Hệ thống đang bảo trì</h1><p>${msg}</p>
<a href="/login.html">Đăng xuất</a></div></body></html>`;
    return new Response(maintHtml, { status: 503, headers: { 'content-type':'text/html;charset=utf-8','cache-control':'no-store','retry-after':'3600' } });
  }

  // ── Server-side page permission gate ──
  // Admins bypass all checks. Non-admin users are redirected to home
  // if they try to access a page they don't have permission for.
  if (!isAdmin) {
    const _PAGE_PERM = {
      '/service-movi/meraki.html': 'meraki',
      '/service-movi/topology.html': 'topology',
      '/service-movi/fortigate-movi.html': 'fortigate-movi',
      '/service-movi/camera-movi.html': 'camera-movi',
      '/service-movi/n8n-movi.html': 'n8n-movi',
      '/service-movi/tool-movi.html': ['tool-movi-create-user','tool-movi-block-user','tool-movi-delete-user','tool-movi-asset-search','tool-movi-check-email','tool-movi-azure-group','tool-movi-fg-policy-lan','tool-movi-fg-policy-wifi'],
      '/service-movi/vmware01-movi.html': 'vmware01-movi',
      '/service-movi/vmware02-movi.html': 'vmware02-movi',
      '/service-movi/ssh-movi.html': 'ssh-movi',
      '/service-home/fortigate.html': 'fortigate',
      '/service-home/vmware-home.html': 'esxi',
      '/service-home/casaos.html': 'casaos',
      '/service-home/asus.html': 'asus',
      '/service-home/9router.html': '9router',
      '/service-home/n8n.html': 'n8n',
      '/service-home/hikvision.html': 'camera',
      '/service-home/ssh.html': 'ssh',
      '/service-home/rustdesk.html': 'rustdesk',
      // '/settings.html' intentionally NOT gated — all authenticated users can access own profile/MFA settings
      '/policy.html': '_mgmt',
    };
    const _reqPerm = _PAGE_PERM[url.pathname];
    if (_reqPerm) {
      let _allowed = false;
      if (_reqPerm === '_mgmt') {
        // Admin-area pages: allow if user is a delegated manager
        _allowed = (effPerms.canManagePerms || []).length > 0;
      } else {
        const _perms = effPerms.permissions || {};
        const _keys = Array.isArray(_reqPerm) ? _reqPerm : [_reqPerm];
        _allowed = _keys.some(k => (_perms[k] || 'none') !== 'none');
      }
      if (!_allowed) {
        return Response.redirect(new URL('/', request.url).toString(), 302);
      }
    }
  }

  const idleMin = Math.max(30, sysCfg.idleTimeoutMin ?? 60);
  const idleMs  = idleMin * 60 * 1000;
  const warnMs  = Math.max(60_000, idleMs - 5 * 60 * 1000);
  const dashTitle = (sysCfg.dashboardTitle || '').trim();
  const userScript = `<script>window.__USER__=${JSON.stringify({
    username: session.username,
    role: session.role,
    permissions: isAdmin ? {} : effPerms.permissions,
    panels: isAdmin ? {} : effPerms.panels,
    cameras: isAdmin ? [] : effPerms.cameras,
    groups: isAdmin ? [] : effPerms.groups,
    isAdmin,
    canManagePerms: isAdmin ? [] : (effPerms.canManagePerms || []),
    sysPerms: isAdmin ? { addUser: true, systemConfig: true } : (effPerms.sysPerms || {}),
    dashboardTitle: dashTitle,
    authMethod: session.authMethod || 'local',
    mfaEnabled: !!(effPerms.mfaEnabled),
    isSaml: !!(effPerms.isSaml),
  })};
  /* Auto-inject Settings link + apply custom dashboard title */
  (function(){
    if(!window.__USER__)return;
    document.addEventListener('DOMContentLoaded',function(){
      var sl=document.getElementById('settings-link');
      if(sl){sl.style.display='';} else {
        var nav=document.querySelector('nav.topnav')||document.querySelector('nav.topbar-nav')||document.querySelector('.topnav');
        if(nav){var a=document.createElement('a');a.id='settings-link';a.className='topnav-item';a.href='/settings.html';a.textContent='⚙ Settings';nav.appendChild(a);}
      }
      var dt=window.__USER__.dashboardTitle;
      if(dt){
        document.title=document.title.replace(/Dashboard SYSTEM/g,dt);
        var bn=document.querySelector('.brand-name');
        if(bn&&bn.textContent.trim()==='Dashboard SYSTEM')bn.textContent=dt;
      }
    });
  })();
  </script>` + makeIdleScript(idleMs, warnMs) + `<script>(function(){
  var u=window.__USER__;
  if(!u||!u.isSaml||u.mfaEnabled)return;
  function _showMfaWarn(){
    if(document.getElementById('_mfaw'))return;
    var d=document.createElement('div');
    d.id='_mfaw';
    d.style.cssText='position:fixed;bottom:20px;left:20px;z-index:9998;'
      +'background:#1c1917;border:1px solid #92400e;border-left:3px solid #f59e0b;'
      +'border-radius:8px;padding:12px 14px;display:flex;align-items:flex-start;'
      +'gap:10px;font-family:system-ui,sans-serif;font-size:12px;color:#fde68a;'
      +'max-width:270px;box-shadow:0 4px 16px rgba(0,0,0,.55)';
    /* icon */
    var ic=document.createElement('span');
    ic.textContent='🔐';
    ic.style.cssText='font-size:20px;line-height:1.3;flex-shrink:0';
    /* body */
    var bdy=document.createElement('div');
    bdy.style.flex='1';
    var ttl=document.createElement('b');
    ttl.textContent='Chưa bật MFA';
    ttl.style.cssText='font-size:13px;color:#fbbf24;display:block;margin-bottom:3px';
    var txt=document.createTextNode('Bật xác thực 2 bước để bảo mật tài khoản Microsoft. ');
    var lnk=document.createElement('a');
    lnk.href='/settings.html#mfa';
    lnk.textContent='Bật ngay →';
    lnk.style.cssText='color:#fbbf24;text-decoration:underline;font-weight:600';
    bdy.appendChild(ttl); bdy.appendChild(txt); bdy.appendChild(lnk);
    /* close button */
    var btn=document.createElement('button');
    btn.textContent='×';
    btn.title='Đóng';
    btn.style.cssText='background:none;border:none;color:#78716c;cursor:pointer;'
      +'font-size:18px;padding:0 0 0 4px;line-height:1;flex-shrink:0;align-self:flex-start';
    btn.addEventListener('click',function(){var e=document.getElementById('_mfaw');if(e)e.remove();});
    d.appendChild(ic); d.appendChild(bdy); d.appendChild(btn);
    document.body.appendChild(d);
  }
  if(document.readyState==='loading'){
    document.addEventListener('DOMContentLoaded',_showMfaWarn);
  } else {
    _showMfaWarn();
  }
})();<\/script>`;
  // Head: user + idle scripts.  Body end: the Wayfinding switcher as static
  // markup (DOM-ready, immune to the page's own client-side re-rendering).
  const htmlPatched = applyMobilePatch(html, isMobileRequest(request));
  let newHtml = /<\/head>/i.test(htmlPatched)
    ? htmlPatched.replace(/<\/head>/i, userScript + '\n</head>')
    : htmlPatched.replace(/<body/i, userScript + '\n<body');
  const bodyEnd = WAYFIND_NAV + DATA_REFRESH + PANEL_REFRESH;
  newHtml = /<\/body>/i.test(newHtml)
    ? newHtml.replace(/<\/body>/i, bodyEnd + '\n</body>')
    : newHtml + bodyEnd;
  return new Response(newHtml, {
    status: res.status,
    headers: {
      'content-type': 'text/html; charset=utf-8',
      'cache-control': 'no-store, no-cache',
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
      'Referrer-Policy': 'strict-origin-when-cross-origin',
      // [M1] HSTS: force HTTPS for 1 year, including subdomains
      'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
      // [M2] Permissions-Policy: deny browser features not used by this app
      'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()',
      // App is heavily inline-scripted; 'unsafe-inline' is required to avoid
      // breakage, but external script/object/frame sources are locked down.
      'Content-Security-Policy':
        "default-src 'self'; " +
        "script-src 'self' 'unsafe-inline'; " +
        // Google Fonts stylesheet
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; " +
        "img-src 'self' data: https:; " +
        "media-src 'self' blob:; " +
        // [M4] Whitelist only known domains instead of broad 'https: wss:'
        // Covers: all homelab subdomains + movi-finance API/WebSocket
        "connect-src 'self' https://*.home-server.id.vn wss://*.home-server.id.vn https://*.movi-finance.com wss://*.movi-finance.com https://speed.cloudflare.com; " +
        // Google Fonts files + data URIs
        "font-src 'self' data: https://fonts.gstatic.com; " +
        // Allow camera (go2rtc), SSH terminal (termix) iframes, and Microsoft OIDC silent renewal
        "frame-src 'self' https://camera.home-server.id.vn https://termix.home-server.id.vn https://termix-movi.home-server.id.vn https://cam.movi-finance.com https://termix.movi-finance.com https://login.microsoftonline.com; " +
        "object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
    }
  });
}

/* ═══════════════════════════════════════════════ */

const SERVICES = [
  { id: 'esxi',        name: 'VMware ESXi',    checkUrl: 'https://esxi.home-server.id.vn' },
  { id: 'n8n',         name: 'n8n Automation', checkUrl: 'https://n8n-home.home-server.id.vn' },
  { id: 'casaos',      name: 'CasaOS',         checkUrl: 'https://casaos.home-server.id.vn' },
  { id: '9router',     name: '9Router',        checkUrl: 'https://9router.home-server.id.vn' },
  { id: 'uptime-kuma', name: 'Uptime Kuma',    checkUrl: null },
  { id: 'ssh',         name: 'SSH Terminal',   checkUrl: 'https://termix.home-server.id.vn' },
  { id: 'fortigate',   name: 'FortiGate',      checkUrl: null },
  { id: 'asus',        name: 'ASUS Router',    checkUrl: null },
  { id: 'camera',      name: 'Camera',         checkUrl: 'https://camera.home-server.id.vn' },
  { id: 'rustdesk',    name: 'RustDesk',       checkUrl: 'https://rustdesk.home-server.id.vn' },
];

const N8N_BASE        = 'https://n8n-home.home-server.id.vn/api/v1';
const MOVI_N8N_BASE   = 'https://n8n.movi-finance.com/api/v1';
const NINEROUTER_BASE = 'https://9router.home-server.id.vn';
const RUSTDESK_BASE   = 'https://rustdesk.home-server.id.vn';

/* ── Movi n8n webhook basic-auth (credentials from Cloudflare secrets) ──
   Set via:  wrangler secret put MOVI_N8N_USER  /  MOVI_N8N_PASS
   Never hardcode credentials in source. */
function moviN8nAuth(env) {
  const u = cleanEnv(env.MOVI_N8N_USER);
  const p = cleanEnv(env.MOVI_N8N_PASS);
  if (!u || !p) throw new Error('MOVI_N8N_USER / MOVI_N8N_PASS not configured');
  return 'Basic ' + btoa(unescape(encodeURIComponent(u + ':' + p)));
}

async function checkService(service) {
  if (!service.checkUrl) return { id: service.id, status: 'local', ping: null };
  const t0 = Date.now();
  try {
    const res = await fetch(service.checkUrl, {
      method: 'GET', redirect: 'follow',
      signal: AbortSignal.timeout(6000),
      headers: { 'User-Agent': 'HomeLabDashboard/1.0' },
    });
    return { id: service.id, status: res.status < 500 ? 'online' : 'offline', ping: Date.now() - t0 };
  } catch (e) {
    return { id: service.id, status: 'offline', ping: null };
  }
}

async function handleStatus() {
  const results = await Promise.all(SERVICES.map(checkService));
  const map = {};
  results.forEach(r => { map[r.id] = r; });
  return json({ ts: new Date().toISOString(), services: map });
}

async function handleN8n(env) {
  const key = cleanEnv(env.N8N_API_KEY);
  if (!key) return json({ error: 'N8N_API_KEY not configured' }, 500);

  const h = { 'X-N8N-API-KEY': key, 'Accept': 'application/json' };
  const opts = (extra = {}) => ({ headers: h, signal: AbortSignal.timeout(10000), ...extra });

  try {
    // Fetch running executions separately — n8n default list only returns finished ones
    const [wfRes, exRes, exRunRes, credRes, varRes, tagRes] = await Promise.all([
      fetch(`${N8N_BASE}/workflows?limit=100`, opts()),
      fetch(`${N8N_BASE}/executions?limit=50&includeData=false`, opts()),
      fetch(`${N8N_BASE}/executions?limit=20&includeData=false&status=running`, opts()),
      fetch(`${N8N_BASE}/credentials`, opts()),
      fetch(`${N8N_BASE}/variables`, opts()),
      fetch(`${N8N_BASE}/tags?limit=100`, opts()),
    ]);

    if (!wfRes.ok) {
      const txt = await wfRes.text();
      return json({ error: `n8n server error ${wfRes.status}: ${txt.slice(0, 200)}` }, 502);
    }

    const [wfData, exData, exRunData, credData, varData, tagData] = await Promise.all([
      wfRes.json(),
      exRes.json(),
      exRunRes.ok ? exRunRes.json() : { data: [] },
      credRes.ok  ? credRes.json()  : { data: [] },
      varRes.ok   ? varRes.json()   : { data: [] },
      tagRes.ok   ? tagRes.json()   : { data: [] },
    ]);

    const workflows = (wfData.data || []).map(w => ({
      id: w.id, name: w.name, active: w.active,
      updatedAt: w.updatedAt, createdAt: w.createdAt,
      triggerCount: w.triggerCount || 0,
      tags: (w.tags || []).map(t => t.name || t),
    }));

    const wfNameMap = {};
    workflows.forEach(w => { wfNameMap[w.id] = w.name; });

    // Merge running (first) + finished, deduplicate by ID, sort newest first
    const seenIds = new Set();
    const mergedRaw = [...(exRunData.data || []), ...(exData.data || [])].filter(e => {
      if (seenIds.has(e.id)) return false;
      seenIds.add(e.id);
      return true;
    });
    mergedRaw.sort((a, b) => new Date(b.startedAt) - new Date(a.startedAt));

    const executions = mergedRaw.map(e => ({
      id: e.id,
      workflowName: wfNameMap[e.workflowId] || e.workflowData?.name || '(không rõ)',
      workflowId: e.workflowId,
      status: e.status,
      startedAt: e.startedAt,
      stoppedAt: e.stoppedAt,
      mode: e.mode,
    }));

    const credentials = (credData.data || []).map(c => ({
      id: c.id, name: c.name, type: c.type,
      createdAt: c.createdAt, updatedAt: c.updatedAt,
    }));

    const variables = (varData.data || []).map(v => ({
      id: v.id, key: v.key, value: v.value, type: v.type,
    }));

    const tags = (tagData.data || []).map(t => ({
      id: t.id, name: t.name, usageCount: t.usageCount || 0,
    }));

    const active   = workflows.filter(w => w.active).length;
    const inactive = workflows.length - active;
    const success  = executions.filter(e => e.status === 'success').length;
    const failed   = executions.filter(e => e.status === 'error' || e.status === 'failed').length;
    const running  = executions.filter(e => e.status === 'running').length;

    // last run per workflow
    const lastRun = {};
    executions.forEach(e => {
      if (!lastRun[e.workflowId] || new Date(e.startedAt) > new Date(lastRun[e.workflowId].startedAt)) {
        lastRun[e.workflowId] = { status: e.status, startedAt: e.startedAt, execId: e.id };
      }
    });

    return json({
      workflows, executions, credentials, variables, tags, lastRun,
      stats: { total: workflows.length, active, inactive, success, failed, running,
               totalCreds: credentials.length, totalVars: variables.length },
    });
  } catch (e) {
    return json({ error: e.message }, 502);
  }
}

async function handleExecDetail(request, env) {
  const key = cleanEnv(env.N8N_API_KEY);
  if (!key) return json({ error: 'N8N_API_KEY not configured' }, 500);

  const url = new URL(request.url);
  const execId = url.searchParams.get('id');
  if (!execId) return json({ error: 'Missing id' }, 400);

  try {
    const res = await fetch(`${N8N_BASE}/executions/${execId}?includeData=true`, {
      headers: { 'X-N8N-API-KEY': key, 'Accept': 'application/json' },
      signal: AbortSignal.timeout(12000),
    });
    const data = await res.json();
    const err  = data.data?.resultData?.error || null;
    const last = data.data?.resultData?.lastNodeExecuted || null;
    return json({
      id: data.id, status: data.status,
      startedAt: data.startedAt, stoppedAt: data.stoppedAt,
      mode: data.mode,
      error: err ? { message: err.message, name: err.name, stack: err.stack, description: err.description } : null,
      lastNodeExecuted: last,
    });
  } catch (e) {
    return json({ error: e.message }, 502);
  }
}

/* ── Movi n8n API (direct API key auth) ──
   Set via:  wrangler secret put MOVI_N8N_API_KEY */
async function handleMoviN8n(env) {
  const key = cleanEnv(env.MOVI_N8N_API_KEY);
  if (!key) return json({ error: 'MOVI_N8N_API_KEY not configured' }, 500);

  const h = { 'X-N8N-API-KEY': key, 'Accept': 'application/json' };
  const opts = (extra = {}) => ({ headers: h, signal: AbortSignal.timeout(10000), ...extra });

  try {
    // Fetch running executions separately — n8n default list only returns finished ones
    const [wfRes, exRes, exRunRes, credRes, varRes, tagRes] = await Promise.all([
      fetch(`${MOVI_N8N_BASE}/workflows?limit=100`, opts()),
      fetch(`${MOVI_N8N_BASE}/executions?limit=50&includeData=false`, opts()),
      fetch(`${MOVI_N8N_BASE}/executions?limit=20&includeData=false&status=running`, opts()),
      fetch(`${MOVI_N8N_BASE}/credentials`, opts()),
      fetch(`${MOVI_N8N_BASE}/variables`, opts()),
      fetch(`${MOVI_N8N_BASE}/tags?limit=100`, opts()),
    ]);

    const [wfData, exData, exRunData, credData, varData, tagData] = await Promise.all([
      wfRes.json(),
      exRes.json(),
      exRunRes.ok ? exRunRes.json() : { data: [] },
      credRes.json(),
      varRes.json(),
      tagRes.json(),
    ]);

    const workflows = (wfData.data || []).map(w => ({
      id: w.id, name: w.name, active: w.active,
      updatedAt: w.updatedAt, createdAt: w.createdAt,
      triggerCount: w.triggerCount || 0,
      tags: (w.tags || []).map(t => t.name || t),
    }));

    const wfNameMap = {};
    workflows.forEach(w => { wfNameMap[w.id] = w.name; });

    const seenIds = new Set();
    const mergedRaw = [...(exRunData.data || []), ...(exData.data || [])].filter(e => {
      if (seenIds.has(e.id)) return false;
      seenIds.add(e.id);
      return true;
    });
    mergedRaw.sort((a, b) => new Date(b.startedAt) - new Date(a.startedAt));

    const executions = mergedRaw.map(e => ({
      id: e.id,
      workflowName: wfNameMap[e.workflowId] || e.workflowData?.name || '(không rõ)',
      workflowId: e.workflowId,
      status: e.status,
      startedAt: e.startedAt,
      stoppedAt: e.stoppedAt,
      mode: e.mode,
    }));

    const credentials = (credData.data || []).map(c => ({
      id: c.id, name: c.name, type: c.type,
      createdAt: c.createdAt, updatedAt: c.updatedAt,
    }));

    const variables = (varData.data || []).map(v => ({
      id: v.id, key: v.key, value: v.value, type: v.type,
    }));

    const tags = (tagData.data || []).map(t => ({
      id: t.id, name: t.name, usageCount: t.usageCount || 0,
    }));

    const active   = workflows.filter(w => w.active).length;
    const inactive = workflows.length - active;
    const success  = executions.filter(e => e.status === 'success').length;
    const failed   = executions.filter(e => e.status === 'error' || e.status === 'failed').length;
    const running  = executions.filter(e => e.status === 'running').length;

    const lastRun = {};
    executions.forEach(e => {
      if (!lastRun[e.workflowId] || new Date(e.startedAt) > new Date(lastRun[e.workflowId].startedAt)) {
        lastRun[e.workflowId] = { status: e.status, startedAt: e.startedAt, execId: e.id };
      }
    });

    return json({
      workflows, executions, credentials, variables, tags, lastRun,
      stats: { total: workflows.length, active, inactive, success, failed, running,
               totalCreds: credentials.length, totalVars: variables.length },
    });
  } catch (e) {
    return json({ error: e.message }, 502);
  }
}

async function handleMoviN8nExecDetail(request, env) {
  const key = cleanEnv(env.MOVI_N8N_API_KEY);
  if (!key) return json({ error: 'MOVI_N8N_API_KEY not configured' }, 500);

  const url = new URL(request.url);
  const execId = url.searchParams.get('id');
  if (!execId) return json({ error: 'Missing id' }, 400);

  try {
    const res = await fetch(`${MOVI_N8N_BASE}/executions/${execId}?includeData=true`, {
      headers: { 'X-N8N-API-KEY': key, 'Accept': 'application/json' },
      signal: AbortSignal.timeout(12000),
    });
    const data = await res.json();
    const err  = data.data?.resultData?.error || null;
    const last = data.data?.resultData?.lastNodeExecuted || null;
    return json({
      id: data.id, status: data.status,
      startedAt: data.startedAt, stoppedAt: data.stoppedAt,
      mode: data.mode,
      error: err ? { message: err.message, name: err.name, stack: err.stack, description: err.description } : null,
      lastNodeExecuted: last,
    });
  } catch (e) {
    return json({ error: e.message }, 502);
  }
}

/* ═══════════════════════════════════════════════
   Tool Movi — Workflow triggers via n8n webhook
   Secret: MOVI_TOOL_CREATE_USER_WEBHOOK
   ═══════════════════════════════════════════════ */
async function handleToolMoviCreateUser(request, env, session, ctx) {
  if (request.method !== 'POST') return json({ error: 'POST required' }, 405);
  const webhookUrl = cleanEnv(env.MOVI_TOOL_CREATE_USER_WEBHOOK);
  if (!webhookUrl) return json({ error: 'MOVI_TOOL_CREATE_USER_WEBHOOK not configured. Run: npx wrangler secret put MOVI_TOOL_CREATE_USER_WEBHOOK' }, 500);

  let body;
  try { body = await request.json(); } catch { return json({ error: 'Invalid JSON body' }, 400); }

  // Validate required fields
  const required = ['email','firstName','lastName','personalEmail','group'];
  for (const f of required) {
    if (!body[f] || !String(body[f]).trim()) return json({ error: `Missing required field: ${f}` }, 400);
  }

  // Force createdBy from server-side session (cannot be spoofed by client)
  const createdBy = session.username || session.email || 'unknown';

  // Transform to n8n expected format: flat object, fields accessible as $json['Field Name']
  const n8nPayload = {
    'Email User Movi': body.email         || '',
    'First Name':      body.firstName     || '',
    'Last Name':       body.lastName      || '',
    'JobTitle':        body.jobTitle      || '',
    'Department':      body.department    || '',
    'Personal Email':  body.personalEmail || '',
    'Office':          body.office        || '',
    'MobilePhone':     body.mobilePhone   || '',
    'Manager':         body.manager       || '',
    'Company':         body.company       || '',
    'Phòng Ban':       body.group         || '',
    'Người Tạo user':  createdBy,
  };

  let auth;
  try { auth = moviN8nAuth(env); } catch (e) { return json({ error: e.message }, 500); }

  // Cloudflare Workers HTTP: no wall-clock limit while browser stays connected.
  // Await n8n directly — browser shows spinner, gets result when workflow finishes.
  try {
    const res = await fetch(webhookUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': auth },
      body: JSON.stringify(n8nPayload),
      signal: AbortSignal.timeout(180000), // 3 min safety cap
    });
    const txt = await res.text().catch(() => '');
    let result;
    try { result = JSON.parse(txt); } catch { result = { raw: txt.slice(0, 1000) }; }
    if (!res.ok) return json({ error: `n8n returned ${res.status}`, result }, 502);
    return json({ success: true, result });
  } catch (e) {
    return json({ error: `Webhook error: ${e.message}` }, 502);
  }
}


/* ── Tool Movi: Block User ── */
async function handleToolMoviBlockUser(request, env, session) {
  if (request.method !== 'POST') return json({ error: 'POST required' }, 405);
  const webhookUrl = cleanEnv(env.MOVI_WH_BLOCK_USER);
  let body; try { body = await request.json(); } catch { return json({ error: 'Invalid JSON' }, 400); }
  const email     = (body.email || '').trim();
  const startDate = (body.startDate || '').trim();
  const endDate   = (body.endDate || '').trim();
  const reason    = (body.reason || '').trim();
  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return json({ error: 'Email không hợp lệ' }, 400);
  if (!startDate || !/^\d{4}-\d{2}-\d{2}$/.test(startDate)) return json({ error: 'Ngày bắt đầu không hợp lệ (định dạng: YYYY-MM-DD)' }, 400);
  if (!endDate   || !/^\d{4}-\d{2}-\d{2}$/.test(endDate))   return json({ error: 'Ngày kết thúc không hợp lệ (định dạng: YYYY-MM-DD)' }, 400);
  if (endDate < startDate) return json({ error: 'Ngày kết thúc phải sau hoặc bằng ngày bắt đầu' }, 400);
  if (!reason) return json({ error: 'Lý do block là bắt buộc' }, 400);
  const payload = [
    {
      data: {
        'Tài khoản user block': email,
        'Thời gian bắt đầu':   startDate,
        'thời gian kết thúc':  endDate,
        'ghi chú lý do ':      reason,
      }
    }
  ];
  const ip = request.headers.get('CF-Connecting-IP') || '?';
  try {
    const resp = await fetch(webhookUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': moviN8nAuth(env) },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(180000),
    });
    if (!resp.ok) {
      const txt = await resp.text().catch(() => '');
      return json({ error: `n8n error: HTTP ${resp.status}`, detail: txt.slice(0, 200) }, 502);
    }
    const raw = await resp.json().catch(() => ({}));
    const result = Array.isArray(raw) ? raw : raw;
    await logActivity(env, { action: 'tool-movi-block-user', username: session.username, ip, success: true, detail: `Blocked ${email} (${startDate} → ${endDate})` });
    return json({ success: true, result });
  } catch (e) {
    await logActivity(env, { action: 'tool-movi-block-user', username: session.username, ip, success: false, detail: `Failed: ${e.message}` });
    return json({ error: e.name === 'TimeoutError' ? 'n8n timeout sau 3 phút' : `Lỗi kết nối: ${e.message}` }, 502);
  }
}

/* ── Tool Movi: Asset Search ── */
async function handleToolMoviAssetSearch(request, env, session) {
  if (request.method !== 'POST') return json({ error: 'POST required' }, 405);
  const webhookUrl = cleanEnv(env.MOVI_WH_ASSET_SEARCH);
  let body; try { body = await request.json(); } catch { return json({ error: 'Invalid JSON' }, 400); }
  const params = {
    email:     (body.email     || '').trim(),
    assetTag:  (body.assetTag  || '').trim(),
    model:     (body.model     || '').trim(),
    serial:    (body.serial    || '').trim(),
    location:  (body.location  || '').trim(),
    status:    (body.status    || '').trim(),
    assetType: (body.assetType || '').trim(),
  };
  if (!Object.values(params).some(v => v))
    return json({ error: 'Vui lòng nhập ít nhất 1 tiêu chí tìm kiếm' }, 400);
  try {
    const resp = await fetch(webhookUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': moviN8nAuth(env) },
      body: JSON.stringify(params),
      signal: AbortSignal.timeout(30000),
    });
    if (!resp.ok) {
      const txt = await resp.text().catch(() => '');
      return json({ error: `n8n error: HTTP ${resp.status}`, detail: txt.slice(0, 200) }, 502);
    }
    const raw  = await resp.json().catch(() => []);
    const list = Array.isArray(raw) ? raw : (raw ? [raw] : []);
    return json({ success: true, list, total: list.length });
  } catch(e) {
    return json({ error: e.name === 'TimeoutError' ? 'n8n timeout sau 30 giây' : `Lỗi kết nối: ${e.message}` }, 502);
  }
}

/* ── Tool Movi: Check Email Azure AD ── */
async function handleToolMoviCheckEmail(request, env, session) {
  if (request.method !== 'POST') return json({ error: 'POST required' }, 405);
  const webhookUrl = cleanEnv(env.MOVI_WH_AZURE_CHECK_EMAIL);
  if (!webhookUrl) return json({ error: 'MOVI_WH_AZURE_CHECK_EMAIL chưa được cấu hình' }, 503);
  let body; try { body = await request.json(); } catch { return json({ error: 'Invalid JSON' }, 400); }
  // Accept email OR partial name/keyword — no strict email format check
  const query = (body.query || body.email || '').trim();
  if (!query || query.length < 2)
    return json({ error: 'Nhập ít nhất 2 ký tự để tìm kiếm' }, 400);
  if (query.length > 100)
    return json({ error: 'Từ khoá tìm kiếm quá dài' }, 400);
  try {
    const url = `${webhookUrl}?email=${encodeURIComponent(query)}`;
    const resp = await fetch(url, {
      method: 'GET',
      headers: { 'Authorization': moviN8nAuth(env) },
      signal: AbortSignal.timeout(15000),
    });
    if (!resp.ok) {
      const txt = await resp.text().catch(() => '');
      return json({ error: `n8n error: HTTP ${resp.status}`, detail: txt.slice(0, 200) }, 502);
    }
    // n8n Respond to Webhook returns $json.body (raw Graph API response)
    // Shape: { value: [...users], @odata.context: "..." }
    // OR legacy flat shape: { found, id, displayName, ... }
    const raw = await resp.json().catch(() => ({}));
    // Case 1: n8n returns raw Graph API body { value: [...] }
    if (Array.isArray(raw.value)) {
      const users = raw.value;
      return json({ success: true, found: users.length > 0, users });
    }
    // Case 2: n8n returns flat single-user fields { found, id, displayName, ... }
    if (raw.found !== undefined) {
      const user = (raw.id || raw.displayName) ? {
        id: raw.id, displayName: raw.displayName,
        userPrincipalName: raw.userPrincipalName,
        mail: raw.mail, accountEnabled: raw.accountEnabled,
      } : null;
      return json({ success: true, found: !!raw.found, users: user ? [user] : [] });
    }
    // Case 3: unexpected shape
    return json({ success: true, found: false, users: [] });
  } catch(e) {
    return json({ error: e.name === 'TimeoutError' ? 'n8n timeout sau 15 giây' : `Lỗi kết nối: ${e.message}` }, 502);
  }
}

/* ── Tool Movi: Check Azure Group ── */
async function handleToolMoviCheckAzureGroup(request, env, session) {
  if (request.method !== 'POST') return json({ error: 'POST required' }, 405);
  const webhookUrl = cleanEnv(env.MOVI_WH_AZURE_CHECK_GROUP);
  if (!webhookUrl) return json({ error: 'MOVI_WH_AZURE_CHECK_GROUP chưa được cấu hình' }, 503);
  let body; try { body = await request.json(); } catch { return json({ error: 'Invalid JSON' }, 400); }
  const query = (body.query || '').trim();
  if (!query || query.length < 2)
    return json({ error: 'Nhập ít nhất 2 ký tự để tìm kiếm' }, 400);
  if (query.length > 100)
    return json({ error: 'Từ khoá tìm kiếm quá dài' }, 400);
  try {
    const url = `${webhookUrl}?query=${encodeURIComponent(query)}`;
    const resp = await fetch(url, {
      method: 'GET',
      headers: { 'Authorization': moviN8nAuth(env) },
      signal: AbortSignal.timeout(15000),
    });
    if (!resp.ok) {
      const txt = await resp.text().catch(() => '');
      return json({ error: `n8n error: HTTP ${resp.status}`, detail: txt.slice(0, 200) }, 502);
    }
    const raw = await resp.json().catch(() => ({}));
    if (Array.isArray(raw.value)) {
      return json({ success: true, found: raw.value.length > 0, groups: raw.value });
    }
    return json({ success: true, found: false, groups: [] });
  } catch(e) {
    return json({ error: e.name === 'TimeoutError' ? 'n8n timeout sau 15 giây' : `Lỗi kết nối: ${e.message}` }, 502);
  }
}

/* ── Tool Movi: Delete User List ── */
async function handleToolMoviDeleteUserList(request, env, session) {
  const webhookUrl = cleanEnv(env.MOVI_WH_DELETE_USER_LIST);
  try {
    const resp = await fetch(webhookUrl, {
      method: 'GET',
      headers: { 'Authorization': moviN8nAuth(env) },
      signal: AbortSignal.timeout(30000),
    });
    if (!resp.ok) {
      const txt = await resp.text().catch(() => '');
      return json({ error: `n8n error: HTTP ${resp.status}`, detail: txt.slice(0, 200) }, 502);
    }
    const raw  = await resp.json().catch(() => []);
    const list = Array.isArray(raw) ? raw : (raw ? [raw] : []);
    return json({ success: true, list, total: list.length });
  } catch(e) {
    return json({ error: e.name === 'TimeoutError' ? 'n8n timeout sau 30 giây' : `Lỗi kết nối: ${e.message}` }, 502);
  }
}

/* ── Tool Movi: Delete User Action ── */
async function handleToolMoviDeleteUserAction(request, env, session) {
  if (request.method !== 'POST') return json({ error: 'POST required' }, 405);
  const webhookUrl = cleanEnv(env.MOVI_WH_DELETE_USER);
  let body; try { body = await request.json(); } catch { return json({ error: 'Invalid JSON' }, 400); }
  const email = (body.email || '').trim();
  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return json({ error: 'Email không hợp lệ' }, 400);
  const ip = request.headers.get('CF-Connecting-IP') || '?';
  try {
    const resp = await fetch(webhookUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': moviN8nAuth(env) },
      body: JSON.stringify({ email, 'Người thực hiện': session.username }),
      signal: AbortSignal.timeout(20000),
    });
    if (!resp.ok) {
      const txt = await resp.text().catch(() => '');
      return json({ error: `n8n error: HTTP ${resp.status}`, detail: txt.slice(0, 200) }, 502);
    }
    const raw = await resp.json().catch(() => ({}));
    const result = Array.isArray(raw) ? raw : raw;
    await logActivity(env, { action: 'tool-movi-delete-user', username: session.username, ip, success: true, detail: `Deleted ${email}` });
    return json({ success: true, result });
  } catch(e) {
    await logActivity(env, { action: 'tool-movi-delete-user', username: session.username, ip, success: false, detail: `Failed: ${e.message}` });
    return json({ error: e.name === 'TimeoutError' ? 'TIMEOUT' : `Lỗi kết nối: ${e.message}` }, 502);
  }
}

async function handleToolMoviFgPolicy(request, env, session, policyType, ctx) {
  if (request.method !== 'POST') return json({ error: 'POST required' }, 405);
  const envKey = policyType === 'lan' ? env.MOVI_WH_FG_POLICY_LAN : env.MOVI_WH_FG_POLICY_WIFI;
  const webhookUrl = cleanEnv(envKey);
  if (!webhookUrl) return json({ error: "MOVI_WH_FG_POLICY_" + policyType.toUpperCase() + " chưa được cấu hình" }, 503);
  let body; try { body = await request.json(); } catch { return json({ error: 'Invalid JSON' }, 400); }
  const email = (body.email || '').trim();
  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return json({ error: 'Email user không hợp lệ' }, 400);
  if (!body.date) return json({ error: 'Thiếu ngày' }, 400);
  if (!body.startTime || !body.endTime) return json({ error: 'Thiếu thời gian bắt đầu/kết thúc' }, 400);
  const ip = request.headers.get('CF-Connecting-IP') || '?';

  const policyId = crypto.randomUUID();
  const expiresAt = new Date(`${body.date}T${body.endTime}:00+07:00`).getTime();
  const effectiveTtl = Math.max(60, Math.floor((expiresAt - Date.now()) / 1000));
  // KV TTL = thời gian đến endTime + 15 phút buffer (n8n cần thời gian xóa rule rồi mới callback)
  const kvTtl = effectiveTtl + 900;
  const policyData = {
    id: policyId, type: policyType,
    email, allowApp: (body.allowApp || '').trim(),
    department: (body.department || '').trim(),
    date: body.date, startTime: body.startTime, endTime: body.endTime,
    location: (body.location || '').trim(),
    reason: (body.reason || '').trim(),
    createdBy: session.username,
    createdAt: Date.now(), expiresAt,
  };
  // Generate a single-use callback token — n8n sends this back when deleting rule
  const callbackToken = crypto.randomUUID();
  // Store token → policyId mapping (TTL same as policy)
  await env.DASHBOARD_KV.put(`fgcb:${callbackToken}`, policyId, { expirationTtl: kvTtl }).catch(() => {});

  const payload = [{ data: {
    'policyId':            policyId,       // for reference
    'callbackToken':       callbackToken,  // n8n sends this back to mark done
    'Email user':          email,
    'cho phép sử dụng':   policyData.allowApp,
    'phòng Ban':           policyData.department,
    'Ngày':                body.date,
    'thời gian bắt đầu ': body.startTime,
    'thời gian kết thúc': body.endTime,
    'vị trí máy':         policyData.location,
    'Lý do':              policyData.reason,
    'Người Tạo':          session.username,
  }}];

  try {
    // Wait for n8n Respond to Webhook #1 (policy created confirmation)
    const resp = await fetch(webhookUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': moviN8nAuth(env) },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(120000), // 2 min — wait for FortiGate + Teams
    });
    if (!resp.ok) {
      const txt = await resp.text().catch(() => '');
      return json({ error: "n8n error: HTTP " + resp.status, detail: txt.slice(0, 200) }, 502);
    }
    // Parse n8n response — trích xuất Rule ID + Rule Name từ Teams message HTML
    let ruleId = null, ruleName = null;
    try {
      const respData = await resp.json();
      // n8n trả về Teams message JSON, body.content là HTML
      const html = respData?.body?.content || respData?.content || '';
      // Extract Rule ID: <td>ID Rule</td><td>174</td>
      const mId = html.match(/ID Rule<\/td>\s*<td[^>]*>(\d+)<\/td>/i);
      if (mId) ruleId = mId[1];
      // Extract Rule Name: <td>Name</td><td>N8N-xxx-...</td>
      const mName = html.match(/>\s*Name\s*<\/td>\s*<td[^>]*>([^<]+)<\/td>/i);
      if (mName) ruleName = mName[1].trim();
    } catch (_) {}
    if (ruleId)   policyData.ruleId   = ruleId;
    if (ruleName) policyData.ruleName = ruleName;
    // Policy confirmed created — now save to KV
    try {
      await env.DASHBOARD_KV.put(`fgpolicy:${policyId}`, JSON.stringify(policyData), { expirationTtl: kvTtl });
    } catch (kvErr) { console.error('fgpolicy KV save error:', kvErr); }
    await logActivity(env, { action: "tool-movi-fg-policy-" + policyType, username: session.username, ip, success: true, detail: "Policy " + policyType.toUpperCase() + " [" + policyId.slice(0,8) + "] cho " + email + " " + body.date + (ruleId ? " Rule#" + ruleId : '') });
    // Lưu vào lịch sử ngay khi tạo xong (không đợi callback)
    try {
      const hist = await env.DASHBOARD_KV.get('tool_movi_history', 'json') || [];
      hist.unshift({
        id:          policyId,
        tool:        'fg-policy-' + policyType,
        toolLabel:   'Policy ' + policyType.toUpperCase() + ' — Đang hoạt động',
        email:       policyData.email,
        displayName: policyData.email,
        createdBy:   policyData.createdBy,
        status:      'active',   // phân biệt với "done" khi xóa xong
        expiresAt:   policyData.expiresAt,
        result: {
          type:       policyData.type,
          ruleName:   policyData.ruleName || null,
          ruleId:     policyData.ruleId   || null,
          date:       policyData.date,
          startTime:  policyData.startTime,
          endTime:    policyData.endTime,
          location:   policyData.location,
          allowApp:   policyData.allowApp,
          department: policyData.department,
          reason:     policyData.reason,
        },
        error:   null,
        input:   null,
        savedAt: Date.now(),
      });
      if (hist.length > 1000) hist.length = 1000;
      await env.DASHBOARD_KV.put('tool_movi_history', JSON.stringify(hist));
    } catch (_) {}
    return json({ success: true, policy: policyData });
  } catch(e) {
    await logActivity(env, { action: "tool-movi-fg-policy-" + policyType, username: session.username, ip, success: false, detail: "Failed: " + e.message });
    return json({ error: e.name === 'TimeoutError' ? 'n8n timeout sau 2 phút — kiểm tra FortiGate/Teams' : "Lỗi kết nối: " + e.message }, 502);
  }
}

/* ── Tool Movi: FG Policy Done callback (n8n gọi về khi xóa rule xong) ── */
/* Bảo mật 3 lớp: CF Access Service Token → Basic Auth → callbackToken UUID */
async function handleFgPolicyDone(request, env) {
  if (request.method !== 'POST') return json({ error: 'POST required' }, 405);
  // Lớp 2: Verify Basic Auth từ n8n (Lớp 1 là CF Access Service Token ở edge)
  const authH = request.headers.get('Authorization') || '';
  try {
    if (authH !== moviN8nAuth(env)) return json({ error: 'Unauthorized' }, 401);
  } catch { return json({ error: 'Auth config error' }, 500); }
  let body; try { body = await request.json(); } catch { return json({ error: 'Invalid JSON' }, 400); }
  const callbackToken = (body.callbackToken || '').trim();
  if (!callbackToken) return json({ error: 'Missing callbackToken' }, 400);
  // Lookup token → policyId (token is single-use, TTL same as policy)
  const policyId = await env.DASHBOARD_KV.get(`fgcb:${callbackToken}`).catch(() => null);
  if (!policyId) return json({ error: 'Invalid or expired token' }, 403);
  // Load policy data before deleting (for history)
  const policyData = await env.DASHBOARD_KV.get(`fgpolicy:${policyId}`, 'json').catch(() => null);
  // Delete both the policy and the token
  await Promise.all([
    env.DASHBOARD_KV.delete(`fgpolicy:${policyId}`).catch(() => {}),
    env.DASHBOARD_KV.delete(`fgcb:${callbackToken}`).catch(() => {}),
  ]);
  // Update tool_movi_history: đổi label từ "Đã tạo rule" → "Đã xóa rule" (tìm theo policyId)
  if (policyData) {
    try {
      const history = await env.DASHBOARD_KV.get('tool_movi_history', 'json') || [];
      const existIdx = history.findIndex(h => h.id === policyId);
      if (existIdx >= 0) {
        // Cập nhật entry cũ: đổi sang "Đã xóa rule", xóa expiresAt, đổi status
        history[existIdx].toolLabel  = 'Policy ' + policyData.type.toUpperCase() + ' — Đã xóa rule';
        history[existIdx].status     = 'done';
        history[existIdx].expiresAt  = null;
        history[existIdx].doneAt     = Date.now();
        history[existIdx].savedAt    = Date.now();
      } else {
        // Không tìm thấy entry cũ → thêm mới
        history.unshift({
          id:          policyId,
          tool:        'fg-policy-' + policyData.type,
          toolLabel:   'Policy ' + policyData.type.toUpperCase() + ' — Đã xóa rule',
          email:       policyData.email,
          displayName: policyData.email,
          createdBy:   policyData.createdBy,
          status:      'done',
          expiresAt:   null,
          doneAt:      Date.now(),
          result: {
            type:       policyData.type,
            ruleName:   policyData.ruleName  || null,
            ruleId:     policyData.ruleId    || null,
            date:       policyData.date,
            startTime:  policyData.startTime,
            endTime:    policyData.endTime,
            location:   policyData.location,
            allowApp:   policyData.allowApp,
            department: policyData.department,
            reason:     policyData.reason,
          },
          error:   null,
          input:   null,
          savedAt: Date.now(),
        });
      }
      if (history.length > 1000) history.length = 1000;
      await env.DASHBOARD_KV.put('tool_movi_history', JSON.stringify(history));
    } catch (_) {}
  }
  return json({
    success: true,
    policyId,
    message: 'Policy đã được xóa và ghi vào lịch sử',
    policy: policyData || { id: policyId },
  });
}

/* ── Tool Movi: List active FG policies ── */
async function handleListFgPolicies(request, env, session) {
  if (request.method !== 'GET') return json({ error: 'GET required' }, 405);
  try {
    const listed = await env.DASHBOARD_KV.list({ prefix: 'fgpolicy:' });
    const now = Date.now();
    const all = await Promise.all(listed.keys.map(k => env.DASHBOARD_KV.get(k.name, 'json')));
    const policies = all
      .filter(p => p != null)          // KV already handles TTL expiry
      .filter(p => !p.expiresAt || p.expiresAt > now - 60000) // 1 min grace
      .sort((a, b) => (a.expiresAt || 0) - (b.expiresAt || 0));
    return json({ success: true, policies });
  } catch(e) {
    return json({ error: e.message }, 502);
  }
}

/* ── Tool Movi History (KV-backed) ── */
async function hasAnyToolMoviPerm(env, session) {
  if (session.role === 'admin') return true;
  for (const key of ['tool-movi-create-user','tool-movi-block-user','tool-movi-delete-user','tool-movi-asset-search','tool-movi-check-email','tool-movi-azure-group','tool-movi-fg-policy-lan','tool-movi-fg-policy-wifi']) {
    if (await hasPerm(env, session, key)) return true;
  }
  return false;
}

async function handleGetToolMoviHistory(request, env) {
  const session = await getSession(request, env);
  if (!session) return json({ error: 'Unauthorized' }, 401);
  if (!(await hasAnyToolMoviPerm(env, session))) return json({ error: 'Không có quyền truy cập Tool Movi' }, 403);
  const history = await env.DASHBOARD_KV.get('tool_movi_history', 'json') || [];
  const isAdmin = await isAdminUser(env, session);
  const visible = isAdmin ? history : history.filter(h => h.createdBy === session.username);
  return json({ history: visible, total: visible.length, isAdmin });
}

async function handleSaveToolMoviHistory(request, env) {
  const session = await getSession(request, env);
  if (!session) return json({ error: 'Unauthorized' }, 401);
  if (!(await hasAnyToolMoviPerm(env, session))) return json({ error: 'Không có quyền truy cập Tool Movi' }, 403);
  if (request.method !== 'POST') return json({ error: 'POST required' }, 405);
  let body; try { body = await request.json(); } catch { return json({ error: 'Invalid JSON' }, 400); }
  const history = await env.DASHBOARD_KV.get('tool_movi_history', 'json') || [];
  const entry = {
    id:          crypto.randomUUID(),
    tool:        String(body.tool || 'create-user').slice(0, 50),
    toolLabel:   String(body.toolLabel || '').slice(0, 100),
    email:       String(body.email || '').slice(0, 200),
    displayName: String(body.displayName || '').slice(0, 200),
    createdBy:   session.username,
    status:      ['done', 'error'].includes(body.status) ? body.status : 'error',
    result:      body.result ? _truncateJson(body.result, 8000)  : null,
    error:       body.error  ? String(body.error).slice(0, 500)   : null,
    input:       body.input  ? _truncateJson(body.input, 4000)   : null,
    savedAt:     Date.now(),
  };
  history.unshift(entry);
  if (history.length > 1000) history.length = 1000;
  await env.DASHBOARD_KV.put('tool_movi_history', JSON.stringify(history));
  return json({ success: true, id: entry.id, total: history.length });
}

async function handleClearToolMoviHistory(request, env) {
  const session = await getSession(request, env);
  if (!session || !(await isAdminUser(env, session))) return json({ error: 'Admin required' }, 403);
  await env.DASHBOARD_KV.delete('tool_movi_history');
  return json({ success: true });
}

async function handle9Router(request, env) {
  // 9Router dashboard auth: password-only login → session cookie (auth_token)
  // Set via: npx wrangler secret put NINEROUTER_PASSWORD
  const password = env && env.NINEROUTER_PASSWORD;
  if (!password) {
    return json({ error: 'Chưa cấu hình NINEROUTER_PASSWORD. Chạy: npx wrangler secret put NINEROUTER_PASSWORD' }, 502);
  }

  // Step 1: Login to get session cookie
  let authCookie = '';
  try {
    const loginRes = await fetch(`${NINEROUTER_BASE}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
      body: JSON.stringify({ password }),
      signal: AbortSignal.timeout(10000),
    });
    if (loginRes.status === 401) return json({ error: '9Router login thất bại — mật khẩu NINEROUTER_PASSWORD không đúng' }, 502);
    if (!loginRes.ok) return json({ error: `9Router login lỗi HTTP ${loginRes.status}` }, 502);

    // Extract auth_token cookie from Set-Cookie header
    const setCookie = loginRes.headers.get('set-cookie') || '';
    const match = setCookie.match(/(?:^|,\s*)auth_token=([^;,]+)/i);
    if (!match) return json({ error: '9Router login OK nhưng không nhận được auth_token cookie' }, 502);
    authCookie = `auth_token=${match[1]}`;
  } catch (e) {
    return json({ error: `Không kết nối được 9Router (${NINEROUTER_BASE}): ${e.message}` }, 502);
  }

  const opts = {
    signal: AbortSignal.timeout(12000),
    headers: { 'Accept': 'application/json', 'Cookie': authCookie },
  };

  // safeFetch with session cookie
  const safeFetch = async (url) => {
    try {
      const res = await fetch(url, opts);
      const ct = res.headers.get('content-type') || '';
      if (ct.includes('text/html')) return { data: null, error: `Nhận HTML — session cookie không hợp lệ` };
      if (res.status === 401) return { data: null, error: `401 — session hết hạn` };
      if (!res.ok) return { data: null, error: `HTTP ${res.status}` };
      const d = await res.json();
      if (d && d.error) return { data: null, error: d.error };
      return { data: d, error: null };
    } catch (e) {
      return { data: null, error: `${e.name}: ${e.message}` };
    }
  };

  try {
    const [connResult, comboResult, usageResult] = await Promise.all([
      safeFetch(`${NINEROUTER_BASE}/api/providers`),
      safeFetch(`${NINEROUTER_BASE}/api/combos`),
      safeFetch(`${NINEROUTER_BASE}/api/usage/stats`),
    ]);

    // If ALL three endpoints fail → return a meaningful error so the frontend shows the banner
    if (!connResult.data && !comboResult.data && !usageResult.data) {
      const reasons = [
        connResult.error && `providers: ${connResult.error}`,
        comboResult.error && `combos: ${comboResult.error}`,
        usageResult.error && `usage: ${usageResult.error}`,
      ].filter(Boolean).join(' | ');
      return json({ error: `Không kết nối được 9Router backend. ${reasons}` }, 502);
    }

    const connData  = connResult.data;
    const comboData = comboResult.data;
    const usageData = usageResult.data;

    const rawConns = (connData && connData.connections) ? connData.connections : [];
    const combos   = (comboData && comboData.combos)    ? comboData.combos    : [];
    const usage    = usageData || {};

    // Extract modelLock fields from each connection
    const connections = rawConns.map(c => {
      const modelLocks = {};
      Object.keys(c).forEach(k => {
        if (k.startsWith('modelLock_')) modelLocks[k.slice(10)] = c[k];
      });
      return {
        id: c.id, provider: c.provider, authType: c.authType,
        name: c.name, email: c.email || null,
        priority: c.priority, isActive: c.isActive,
        testStatus: c.testStatus, errorCode: c.errorCode || null,
        backoffLevel: c.backoffLevel || 0,
        expiresAt: c.expiresAt, expiresIn: c.expiresIn,
        lastUsedAt: c.lastUsedAt,
        lastError: c.lastError ? c.lastError.slice(0, 120) : null,
        consecutiveUseCount: c.consecutiveUseCount || 0,
        modelLocks,
        lockedModels: Object.entries(modelLocks).filter(([,v]) => v !== null).map(([m, until]) => ({ model: m, until })),
      };
    });

    // byProvider usage → sorted array
    const usageByProvider = Object.entries(usage.byProvider || {})
      .map(([name, d]) => ({ provider: name, requests: d.requests||0, promptTokens: d.promptTokens||0, completionTokens: d.completionTokens||0, cost: d.cost||0 }))
      .sort((a, b) => b.requests - a.requests);

    // byModel → top 30
    const usageByModel = Object.entries(usage.byModel || {})
      .map(([, d]) => ({ model: d.rawModel, provider: d.provider, requests: d.requests||0, promptTokens: d.promptTokens||0, completionTokens: d.completionTokens||0, cost: d.cost||0, lastUsed: d.lastUsed }))
      .sort((a, b) => b.requests - a.requests)
      .slice(0, 30);

    const activeConns = connections.filter(c => c.isActive).length;
    const errorConns  = connections.filter(c => c.errorCode && c.errorCode >= 400).length;

    return json({
      connections,
      combos,
      usage: {
        totalRequests:         usage.totalRequests         || 0,
        totalPromptTokens:     usage.totalPromptTokens     || 0,
        totalCompletionTokens: usage.totalCompletionTokens || 0,
        totalCost:             usage.totalCost             || 0,
        byProvider:    usageByProvider,
        byModel:       usageByModel,
        recentRequests: (usage.recentRequests || []).slice(0, 25),
        activeRequests: usage.activeRequests || [],
      },
      stats: {
        totalConnections: connections.length,
        activeConnections: activeConns,
        errorConnections:  errorConns,
        totalCombos: combos.length,
      },
    });
  } catch (e) {
    return json({ error: e.message }, 502);
  }
}

/* ═══════════════════════════════════════════════
   Bookmarks — per-user, stored in KV
   ═══════════════════════════════════════════════ */

async function handleGetBookmarks(request, env) {
  const session = await getSession(request, env);
  if (!session) return json({ error: 'Not authenticated' }, 401);
  const list = await env.DASHBOARD_KV.get(`bookmarks:${session.username}`, 'json') || [];
  return json({ bookmarks: list });
}

async function handleSaveBookmarks(request, env) {
  const session = await getSession(request, env);
  if (!session) return json({ error: 'Not authenticated' }, 401);
  if (request.method !== 'PUT') return json({ error: 'PUT required' }, 405);
  let body; try { body = await request.json(); } catch { return json({ error: 'Invalid JSON' }, 400); }
  const raw = body.bookmarks;
  // Accept both v2 object { v:2, folders:[...] } and legacy array
  if (!raw) return json({ error: 'Missing bookmarks field' }, 400);
  // Size guard: max 100 KB to prevent KV abuse
  const serialized = JSON.stringify(raw);
  if (serialized.length > 100_000) return json({ error: 'Bookmarks quá lớn (giới hạn 100 KB)' }, 413);
  await env.DASHBOARD_KV.put(`bookmarks:${session.username}`, serialized);
  const count = Array.isArray(raw) ? raw.length
    : (raw.folders ? raw.folders.reduce((s,f) => s + (f.items||[]).length, 0) : 0);
  return json({ success: true, count });
}


/* ── Activity Log ── */
async function logActivity(env, { action, username, ip, success, detail }) {
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

/* ── Meraki Devices Proxy ── */
async function handleMerakiDevices(request, env) {
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
async function handleMerakiClients(request, env) {
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
async function handleMerakiClientPolicy(request, env) {
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
async function handleMerakiBlockedClients(request, env) {
  const session = await getSession(request, env);
  if (!session) return json({ error: 'Unauthorized' }, 401);
  if (!(await hasWritePerm(env, session, 'meraki'))) return json({ error: 'Cần quyền meraki:write để xem danh sách chặn' }, 403);
  const list = await env.DASHBOARD_KV.get('meraki_blocked_clients', 'json') || [];
  return json({ blocked: list });
}

/* ── Meraki Device Status Proxy ── */
async function handleMerakiDeviceStatus(request, env) {
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
async function handleMerakiSwitchPorts(request, env) {
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
async function handleMerakiSwitchPortConfigs(request, env) {
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
async function handleMerakiLinkAggregations(request, env) {
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
async function handleMerakiUplinks(request, env) {
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
async function handleMerakiL3Routing(request, env) {
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
async function handleMerakiEvents(request, env) {
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
async function handleMoviSdwanRules(request, env) {
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
async function handleMoviSdwan(request, env) {
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
async function handleGetCameraAliases(request, env) {
  const session = await getSession(request, env);
  if (!session) return json({ error: 'Unauthorized' }, 401);
  if (!(await isAdminUser(env, session))) return json({ error: 'Admin required' }, 403);
  const aliases = await env.DASHBOARD_KV.get('camera_aliases_movi', 'json') || {};
  return json({ aliases });
}
async function handleSaveCameraAlias(request, env) {
  const session = await getSession(request, env);
  if (!session) return json({ error: 'Unauthorized' }, 401);
  if (!(await isAdminUser(env, session))) return json({ error: 'Admin required' }, 403);
  const body = await request.json().catch(() => ({}));
  const { camId, name } = body;
  if (!camId) return json({ error: 'camId required' }, 400);
  const aliases = await env.DASHBOARD_KV.get('camera_aliases_movi', 'json') || {};
  const trimmed = (name || '').trim();
  if (trimmed) aliases[camId] = trimmed;
  else delete aliases[camId];
  await env.DASHBOARD_KV.put('camera_aliases_movi', JSON.stringify(aliases));
  await logActivity(env, { action: 'camera_alias_save', user: session.username,
    detail: `cam=${camId} → ${trimmed || '(reset)'}`,
    ip: request.headers.get('cf-connecting-ip') || '', success: true });
  return json({ ok: true, aliases });
}

/* ── Camera Movi — Token ── */
async function handleCameraToken(request, env) {
  const session = await getSession(request, env);
  if (!session) return json({ error: 'Unauthorized' }, 401);
  const url = env.MOVI_CAM_URL || '';
  if (!url) return json({ error: 'Camera not configured' }, 503);

  // Read actual camera list from KV (fallback to defaults)
  let camList = await env.DASHBOARD_KV.get('camera_list_movi', 'json');
  if (!camList || !camList.length) camList = DEFAULT_CAMERAS_MOVI;
  const allCams = camList.filter(c => c.stream);
  const allStreams = allCams.map(c => c.stream);
  // Build labels: default names first, then overlay admin aliases
  const labels = Object.fromEntries(allCams.map(c => [c.stream, c.name || c.id]));
  // Stream → camId map (used by client for alias editing)
  const streamToCamId = Object.fromEntries(allCams.map(c => [c.stream, c.id]));
  // Apply admin-defined aliases
  const aliases = await env.DASHBOARD_KV.get('camera_aliases_movi', 'json') || {};
  allCams.forEach(c => { if (aliases[c.id]) labels[c.stream] = aliases[c.id]; });

  // Permission check + camera filtering for non-admin users
  // Re-check role from KV (handles promoted/demoted users whose session may be stale)
  const sessionRole = session.role;
  const effForRole  = sessionRole !== 'admin' ? await computeEffectivePermissions(env, session.username) : null;
  const effectiveAdmin = sessionRole === 'admin' || (effForRole && effForRole.role === 'admin');

  if (!effectiveAdmin) {
    const eff = effForRole;
    const perm = (eff && eff.permissions['camera-movi']) || 'none';
    if (perm === 'none') return json({ error: 'Không có quyền truy cập Camera Movi' }, 403);

    // Filter by assigned camera IDs (eff.cameras).
    // Normalize IDs to handle legacy 'movi-camXX' → 'camX' migration.
    const normalize = id => {
      if (!id) return id;
      const m = id.match(/^movi-cam(\d+)$/i);
      return m ? 'cam' + parseInt(m[1], 10) : id;
    };
    const allowedIds = eff && Array.isArray(eff.cameras) && eff.cameras.length > 0 ? eff.cameras : null;
    let streams;
    if (allowedIds) {
      const normalizedAllowed = allowedIds.map(normalize);
      streams = allCams.filter(c => normalizedAllowed.includes(normalize(c.id))).map(c => c.stream);
      // Graceful fallback: if stale/unknown IDs produced 0 results, show all cameras
      if (streams.length === 0) streams = allStreams;
    } else {
      streams = allStreams;
    }
    return json({ url, streams, labels, streamToCamId, isAdmin: false });
  }
  return json({ url, streams: allStreams, labels, streamToCamId, isAdmin: true });
}

/* ── Camera Home — Full Reverse Proxy (HTTP + WebSocket) with CF Access Token ── */
async function handleCamHomeEmbed(request, env) {
  const session = await getSession(request, env);
  if (!session) return new Response('Unauthorized', { status: 401 });
  if (!(await hasPerm(env, session, 'camera'))) return new Response('Forbidden', { status: 403 });

  const camUrl    = 'https://camera.home-server.id.vn';
  const cfId      = cleanEnv(env.HOME_CAM_CF_CLIENT_ID);
  const cfSecret  = cleanEnv(env.HOME_CAM_CF_CLIENT_SECRET);
  const g2User    = cleanEnv(env.HOME_GO2RTC_USER);
  const g2Pass    = cleanEnv(env.HOME_GO2RTC_PASS);

  const authHeaders = {
    'CF-Access-Client-Id':     cfId,
    'CF-Access-Client-Secret': cfSecret,
    ...(g2User ? { 'Authorization': 'Basic ' + btoa(unescape(encodeURIComponent(`${g2User}:${g2Pass}`))) } : {}),
  };

  const reqUrl  = new URL(request.url);
  const subPath = reqUrl.pathname.replace('/cam-home', '') || '/';
  const target  = `${camUrl}${subPath}${reqUrl.search}`;

  // ── Granular camera permission checks ──
  // Recordings = python API paths + nginx-vod HLS paths (/vod/... serves master.m3u8/segments)
  const isRecPath = /^\/(?:api\/(?:[^/]+\/(?:recordings|start\/|clip\.mp4)|vod\/)|vod\/)/.test(subPath);
  const isDownload = reqUrl.searchParams.get('dl') === '1';
  const isLatestJpg = request.method === 'GET' && /^\/api\/[^/]+\/latest\.jpg$/.test(subPath);
  if (isDownload) {
    if (!(await hasPerm(env, session, 'camera_download')))
      return new Response('Forbidden', { status: 403 });
  } else if (isRecPath) {
    if (!(await hasPerm(env, session, 'camera_playback')))
      return new Response('Forbidden', { status: 403 });
  }

  // ── JPEG cache: serve cached frame if within TTL (collapses N-worker burst) ──
  if (isLatestJpg) {
    const _hit = _snapJpgCache.get(subPath);
    if (_hit && _hit.exp > Date.now()) {
      return new Response(_hit.bytes, { status: 200, headers: { 'Content-Type': _hit.ct, 'Cache-Control': 'no-cache' } });
    }
  }

  // ── WebSocket proxy (MSE streaming) ──
  // CF Workers: pass only Upgrade header — Connection/Sec-WebSocket-* are managed internally.
  // Do NOT call upstream.accept() — fetch().webSocket is already established.
  if (request.headers.get('Upgrade')?.toLowerCase() === 'websocket') {
    let upstreamResp;
    try {
      upstreamResp = await fetch(target, {
        headers: { ...authHeaders, 'Upgrade': 'websocket' },
      });
    } catch(e) {
      return new Response('WebSocket upstream error: ' + e.message, { status: 502 });
    }
    const upstream = upstreamResp.webSocket;
    if (!upstream) return new Response('WebSocket upstream failed (status ' + upstreamResp.status + ')', { status: 502 });

    const { 0: client, 1: server } = new WebSocketPair();
    server.accept();
    // upstream from fetch() is already established — do NOT call upstream.accept()
    server.addEventListener('message',   ({ data }) => { try { upstream.send(data); } catch(_) {} });
    upstream.addEventListener('message', ({ data }) => { try { server.send(data);   } catch(_) {} });
    server.addEventListener('close',   ({ code, reason }) => { try { upstream.close(code, reason); } catch(_) {} });
    upstream.addEventListener('close', ({ code, reason }) => { try { server.close(code, reason);   } catch(_) {} });
    return new Response(null, { status: 101, webSocket: client });
  }

  // ── HTTP proxy ──
  const fwdHeaders = { ...authHeaders };
  const rangeHdr = request.headers.get('Range');
  if (rangeHdr) fwdHeaders['Range'] = rangeHdr;
  const upstream = await fetch(target, {
    method:  request.method,
    headers: fwdHeaders,
    ...(request.method !== 'GET' && request.method !== 'HEAD' ? { body: request.body } : {}),
  });

  const ct = upstream.headers.get('Content-Type') || 'application/octet-stream';

  // For binary/video responses, pass through with relevant headers preserved
  if (!ct.includes('text/html')) {
    if (isLatestJpg && upstream.status === 200) {
      const bytes = new Uint8Array(await upstream.arrayBuffer());
      _snapJpgCache.set(subPath, { bytes, ct, exp: Date.now() + SNAP_JPG_TTL_MS });
      if (_snapJpgCache.size > 64) for (const [k, v] of _snapJpgCache) if (v.exp < Date.now()) _snapJpgCache.delete(k);
      return new Response(bytes, { status: 200, headers: { 'Content-Type': ct, 'Cache-Control': 'no-cache' } });
    }
    const respHeaders = { 'Content-Type': ct, 'Cache-Control': 'no-cache' };
    const contentRange = upstream.headers.get('Content-Range');
    const contentLength = upstream.headers.get('Content-Length');
    const acceptRanges = upstream.headers.get('Accept-Ranges');
    if (contentRange) respHeaders['Content-Range'] = contentRange;
    if (contentLength) respHeaders['Content-Length'] = contentLength;
    if (acceptRanges) respHeaders['Accept-Ranges'] = acceptRanges;
    return new Response(upstream.body, { status: upstream.status, headers: respHeaders });
  }

  // Patch go2rtc's HTML: redirect all API/WS calls through /cam-home/
  // Frigate embeds go2rtc under /live/ (nginx strips prefix before proxying to go2rtc:1984).
  // go2rtc's stream.html uses /api/ws for WebSocket — when served from Frigate that must
  // be /live/api/ws. We detect /api/* paths and prepend /live/ automatically.
  if (ct.includes('text/html')) {
    let html = await upstream.text();

    // ── Server-side: rewrite absolute paths in HTML attributes ──
    // go2rtc (Vite build) embeds <script src="/assets/..."> and <link href="/assets/...">
    // which the browser resolves against OUR Worker origin → 404.
    // We must rewrite them to /cam-home/live/assets/... so the Worker proxies to Frigate → go2rtc.
    html = html.replace(/(\s(?:src|href|action)=["'])(\/(?!cam-home\/)[^"']*)(["'])/gi,
      (_, attr, path, q) => `${attr}/cam-home/live${path}${q}`
    );

    const patch = `<script>
(function(){
  var PRX='/cam-home';
  var CAM='camera.home-server.id.vn';
  function _rw(u){return(u.indexOf('/api/')===0)?'/live'+u:u;}
  function rwHTTP(u){
    if(typeof u!=='string'||!u)return u;
    if(u.indexOf('https://'+CAM)===0)return PRX+u.slice(('https://'+CAM).length);
    if(u.indexOf('http://'+CAM)===0)return PRX+u.slice(('http://'+CAM).length);
    if(u.charAt(0)==='/'&&u.indexOf(PRX)!==0)return PRX+_rw(u);
    return u;
  }
  function rwWS(u){
    if(typeof u!=='string'||!u)return u;
    var h=window.location.host;
    if(u.indexOf('wss://'+CAM)===0)return 'wss://'+h+PRX+u.slice(('wss://'+CAM).length);
    if(u.indexOf('ws://'+CAM)===0)return 'wss://'+h+PRX+u.slice(('ws://'+CAM).length);
    if(u.charAt(0)==='/'&&u.indexOf(PRX)!==0)return 'wss://'+h+PRX+_rw(u);
    return u;
  }
  var _W=window.WebSocket;
  window.WebSocket=function(u,p){
    u=rwWS(u);
    return p!=null?new _W(u,p):new _W(u);
  };
  window.WebSocket.prototype=_W.prototype;
  for(var k in _W)try{window.WebSocket[k]=_W[k];}catch(e){}
  var _f=window.fetch;
  window.fetch=function(){
    var a=[].slice.call(arguments);
    if(typeof a[0]==='string')a[0]=rwHTTP(a[0]);
    return _f.apply(this,a);
  };
  var _xo=XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open=function(){
    var a=[].slice.call(arguments);
    if(typeof a[1]==='string')a[1]=rwHTTP(a[1]);
    return _xo.apply(this,a);
  };
})();
<\/script>`;
    html = html.includes('</head>') ? html.replace('</head>', patch + '</head>') : patch + html;
    return new Response(html, {
      status: upstream.status,
      headers: { 'Content-Type': 'text/html', 'Cache-Control': 'no-cache' },
    });
  }
}

/* ── Camera Home Live — go2rtc Reverse Proxy (WebSocket MSE + HTTP) ── */
async function handleCamLiveEmbed(request, env) {
  const session = await getSession(request, env);
  if (!session) return new Response('Unauthorized', { status: 401 });
  if (!(await hasPerm(env, session, 'camera'))) return new Response('Forbidden', { status: 403 });

  const camLiveUrl = 'https://camera-home-live.home-server.id.vn';
  const cfId       = cleanEnv(env.HOME_CAM_CF_CLIENT_ID);
  const cfSecret   = cleanEnv(env.HOME_CAM_CF_CLIENT_SECRET);
  const g2User     = cleanEnv(env.HOME_GO2RTC_USER);
  const g2Pass     = cleanEnv(env.HOME_GO2RTC_PASS);
  const authHeaders = {
    'CF-Access-Client-Id':     cfId,
    'CF-Access-Client-Secret': cfSecret,
    ...(g2User ? { 'Authorization': 'Basic ' + btoa(unescape(encodeURIComponent(`${g2User}:${g2Pass}`))) } : {}),
  };

  const reqUrl  = new URL(request.url);
  const subPath = reqUrl.pathname.replace('/cam-live', '') || '/';
  const target  = `${camLiveUrl}${subPath}${reqUrl.search}`;

  // WebSocket proxy for go2rtc MSE streaming — match camera-movi's proven header set
  if (request.headers.get('Upgrade')?.toLowerCase() === 'websocket') {
    let upstreamResp;
    try {
      upstreamResp = await fetch(target, {
        headers: {
          ...authHeaders,
          'Upgrade':               'websocket',
          'Connection':            'Upgrade',
          'Sec-WebSocket-Version': '13',
          'Sec-WebSocket-Key':     'dGhlIHNhbXBsZSBub25jZQ==',
        },
      });
    } catch(e) {
      return new Response('WebSocket upstream error: ' + e.message, { status: 502 });
    }
    const upstream = upstreamResp.webSocket;
    if (!upstream) return new Response('WebSocket upstream failed (status ' + upstreamResp.status + ')', { status: 502 });

    const { 0: client, 1: server } = new WebSocketPair();
    server.accept();
    upstream.accept();
    server.addEventListener('message',   ({ data }) => { try { upstream.send(data); } catch(_) {} });
    upstream.addEventListener('message', ({ data }) => { try { server.send(data);   } catch(_) {} });
    server.addEventListener('close',   ({ code, reason }) => { try { upstream.close(code, reason); } catch(_) {} });
    upstream.addEventListener('close', ({ code, reason }) => { try { server.close(code, reason);   } catch(_) {} });
    return new Response(null, { status: 101, webSocket: client });
  }

  // HTTP proxy — for HTML (go2rtc stream.html + Vite shell), inject URL-rewriting JS
  const upstream = await fetch(target, {
    method:  request.method,
    headers: authHeaders,
    ...(request.method !== 'GET' && request.method !== 'HEAD' ? { body: request.body } : {}),
  });
  const ct = upstream.headers.get('Content-Type') || 'application/octet-stream';

  if (ct.includes('text/html')) {
    let html = await upstream.text();
    // Rewrite absolute Vite asset paths so browser fetches them through /cam-live/
    html = html.replace(/(\s(?:src|href|action)=["'])(\/(?!cam-live\/)[^"']*)(["'])/gi,
      (_, attr, path, q) => `${attr}/cam-live${path}${q}`
    );
    const patch = `<script>
(function(){
  var PRX='/cam-live';
  var CAM='camera-home-live.home-server.id.vn';
  function rwHTTP(u){
    if(typeof u!=='string'||!u)return u;
    if(u.indexOf('https://'+CAM)===0)return PRX+u.slice(('https://'+CAM).length);
    if(u.indexOf('http://'+CAM)===0)return PRX+u.slice(('http://'+CAM).length);
    if(u.charAt(0)==='/'&&u.indexOf(PRX)!==0)return PRX+u;
    return u;
  }
  function rwWS(u){
    if(typeof u!=='string'||!u)return u;
    var h=window.location.host;
    if(u.indexOf('wss://'+CAM)===0)return 'wss://'+h+PRX+u.slice(('wss://'+CAM).length);
    if(u.indexOf('ws://'+CAM)===0)return 'wss://'+h+PRX+u.slice(('ws://'+CAM).length);
    if(u.charAt(0)==='/'&&u.indexOf(PRX)!==0)return 'wss://'+h+PRX+u;
    return u;
  }
  var _W=window.WebSocket;
  window.WebSocket=function(u,p){u=rwWS(u);return p?new _W(u,p):new _W(u);};
  window.WebSocket.prototype=_W.prototype;
  window.WebSocket.CONNECTING=_W.CONNECTING;window.WebSocket.OPEN=_W.OPEN;
  window.WebSocket.CLOSING=_W.CLOSING;window.WebSocket.CLOSED=_W.CLOSED;
  var _F=window.fetch;
  window.fetch=function(u,o){
    if(typeof u==='string')u=rwHTTP(u);
    else if(u instanceof Request)u=new Request(rwHTTP(u.url),u);
    return _F.call(this,u,o);
  };
  var _xo=window.XMLHttpRequest.prototype.open;
  window.XMLHttpRequest.prototype.open=function(m,u){
    var a=[].slice.call(arguments);
    if(typeof a[1]==='string')a[1]=rwHTTP(a[1]);
    return _xo.apply(this,a);
  };
})();
<\/script>`;
    html = html.includes('</head>') ? html.replace('</head>', patch + '</head>') : patch + html;
    return new Response(html, {
      status: upstream.status,
      headers: { 'Content-Type': 'text/html', 'Cache-Control': 'no-cache' },
    });
  }

  return new Response(upstream.body, {
    status: upstream.status,
    headers: { 'Content-Type': ct, 'Cache-Control': 'no-cache' },
  });
}

/* ── Camera Movi — Full Reverse Proxy (HTTP + WebSocket) ── */
async function handleCamEmbed(request, env) {
  const session = await getSession(request, env);
  if (!session) return new Response('Unauthorized', { status: 401 });
  if (!(await hasPerm(env, session, 'camera-movi'))) return new Response('Forbidden', { status: 403 });

  const user   = cleanEnv(env.MOVI_CAM_USER);
  const pass   = cleanEnv(env.MOVI_CAM_PASS);
  const camUrl = cleanEnv(env.MOVI_CAM_URL);
  if (!camUrl) return new Response('Camera not configured', { status: 503 });

  const auth    = 'Basic ' + btoa(unescape(encodeURIComponent(`${user}:${pass}`)));
  const reqUrl  = new URL(request.url);
  const subPath = reqUrl.pathname.replace('/cam-embed', '') || '/';
  const target  = `${camUrl}${subPath}${reqUrl.search}`;

  // WebSocket proxy (for go2rtc MSE video stream)
  // CF Workers fetch does NOT support wss:// — keep target as https://, Workers handles the upgrade
  if (request.headers.get('Upgrade')?.toLowerCase() === 'websocket') {
    let upstreamResp;
    try {
      upstreamResp = await fetch(target, {
        headers: {
          'Authorization':         auth,
          'Upgrade':               'websocket',
          'Connection':            'Upgrade',
          'Sec-WebSocket-Version': '13',
          'Sec-WebSocket-Key':     'dGhlIHNhbXBsZSBub25jZQ==',
        },
      });
    } catch(e) {
      return new Response('WebSocket upstream error: ' + e.message, { status: 502 });
    }

    const upstream = upstreamResp.webSocket;
    if (!upstream) return new Response('WebSocket upstream failed (status ' + upstreamResp.status + ')', { status: 502 });

    // Create browser-facing WebSocket pair
    const { 0: client, 1: server } = new WebSocketPair();
    server.accept();
    upstream.accept();

    // Bridge bidirectionally
    server.addEventListener('message',   ({ data }) => { try { upstream.send(data); } catch(_) {} });
    upstream.addEventListener('message', ({ data }) => { try { server.send(data);   } catch(_) {} });
    server.addEventListener('close',   ({ code, reason }) => { try { upstream.close(code, reason); } catch(_) {} });
    upstream.addEventListener('close', ({ code, reason }) => { try { server.close(code, reason);   } catch(_) {} });

    return new Response(null, { status: 101, webSocket: client });
  }

  const isBodyMethod = request.method !== 'GET' && request.method !== 'HEAD';
  const fwdHeaders = { 'Authorization': auth };
  if (isBodyMethod) {
    const clientCt = request.headers.get('Content-Type');
    if (clientCt) fwdHeaders['Content-Type'] = clientCt;
  }
  const upstream = await fetch(target, {
    method:  request.method,
    headers: fwdHeaders,
    ...(isBodyMethod ? { body: request.body } : {}),
  });

  const ct = upstream.headers.get('Content-Type') || 'application/octet-stream';

  // Inject JS patch into HTML so go2rtc's stream.html routes API calls through proxy
  if (ct.includes('text/html')) {
    let html = await upstream.text();
    const patch = `<script>
(function(){
  var PRX='/cam-embed';
  var CAM='cam.movi-finance.com';
  function rwHTTP(u){
    if(typeof u!=='string'||!u)return u;
    if(u.indexOf('https://'+CAM)===0)return PRX+u.slice(('https://'+CAM).length);
    if(u.indexOf('http://'+CAM)===0)return PRX+u.slice(('http://'+CAM).length);
    if(u.charAt(0)==='/'&&u.indexOf('/cam-embed')!==0)return PRX+u;
    return u;
  }
  function rwWS(u){
    if(typeof u!=='string'||!u)return u;
    var h=window.location.host;
    if(u.indexOf('wss://'+CAM)===0)return 'wss://'+h+PRX+u.slice(('wss://'+CAM).length);
    if(u.indexOf('ws://'+CAM)===0)return 'wss://'+h+PRX+u.slice(('ws://'+CAM).length);
    if(u.charAt(0)==='/'&&u.indexOf('/cam-embed')!==0)return 'wss://'+h+PRX+u;
    return u;
  }
  var _W=window.WebSocket;
  window.WebSocket=function(u,p){
    u=rwWS(u);
    return p!=null?new _W(u,p):new _W(u);
  };
  window.WebSocket.prototype=_W.prototype;
  for(var k in _W)try{window.WebSocket[k]=_W[k];}catch(e){}
  var _f=window.fetch;
  window.fetch=function(){
    var a=[].slice.call(arguments);
    if(typeof a[0]==='string')a[0]=rwHTTP(a[0]);
    return _f.apply(this,a);
  };
  var _xo=XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open=function(){
    var a=[].slice.call(arguments);
    if(typeof a[1]==='string')a[1]=rwHTTP(a[1]);
    return _xo.apply(this,a);
  };
})();
<\/script>`;
    html = html.includes('</head>') ? html.replace('</head>', patch + '</head>') : patch + html;
    return new Response(html, {
      status: upstream.status,
      headers: { 'Content-Type': 'text/html', 'Cache-Control': 'no-cache' },
    });
  }

  return new Response(upstream.body, {
    status: upstream.status,
    headers: { 'Content-Type': ct, 'Cache-Control': 'no-cache' },
  });
}

/* ── FortiGate Movi — Interfaces & Bandwidth ── */
async function handleMoviInterfaces(request, env) {
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
async function handleMoviPolicy(request, env) {
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
async function handleMoviDhcp(request, env) {
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
async function handleMoviSslVpn(request, env) {
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
async function handleMoviVpn(request, env) {
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
async function handleMoviLicense(request, env) {
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
async function handleMoviSystem(request, env) {
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

async function handleMoviFirewallUsers(request, env) {
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

async function handleMoviFortiviewSource(request, env) {
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

async function handleMoviFirewallDeauth(request, env) {
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

async function handleGetActivity(request, env) {
  const session = await getSession(request, env);
  if (!session) return json({ error: 'Unauthorized' }, 401);
  const [log, cfg, eff] = await Promise.all([
    env.DASHBOARD_KV.get('activity_log', 'json').then(v => v || []),
    _getCfg(env),
    session.role !== 'admin' ? computeEffectivePermissions(env, session.username) : Promise.resolve(null),
  ]);
  const retDays = Math.max(7, cfg.auditRetentionDays ?? 30);
  const cutoff  = Date.now() - retDays * 24 * 60 * 60 * 1000;
  const byTime  = log.filter(l => l.ts >= cutoff);
  const isAdmin = session.role === 'admin' || (eff && eff.role === 'admin');
  const filtered = isAdmin ? byTime : byTime.filter(l => l.username === session.username);
  return json({ log: filtered.slice(0, 500), total: filtered.length, cutoffDays: retDays, isAdmin });
}

async function handlePurgeAuditLog(request, env) {
  const session = await getSession(request, env);
  if (!session || !(await isAdminUser(env, session))) return json({ error: 'Admin required' }, 403);
  const purgeCfg = await _getCfg(env);
  const retentionDays = Math.max(1, purgeCfg.auditRetentionDays ?? 30);
  const log = await env.DASHBOARD_KV.get('activity_log', 'json') || [];
  const cutoff = Date.now() - retentionDays * 24 * 60 * 60 * 1000;
  const kept = log.filter(l => l.ts >= cutoff);
  const purged = log.length - kept.length;
  await env.DASHBOARD_KV.put('activity_log', JSON.stringify(kept), { expirationTtl: 60 * 60 * 24 * retentionDays });
  await logActivity(env, { action: 'audit-purge', username: session.username, ip: request.headers.get('CF-Connecting-IP') || '?', success: true, detail: `Purged ${purged} entries older than ${retentionDays} days` });
  return json({ success: true, purged, kept: kept.length });
}

async function handleGetSystemConfig(request, env) {
  const session = await getSession(request, env);
  if (!session) return json({ error: 'Session expired' }, 401);
  if (!(await isAdminUser(env, session))) {
    const callerRaw = await env.DASHBOARD_KV.get(`user:${session.username}`, 'json');
    if (!callerRaw?.sysPerms?.systemConfig) return json({ error: 'Admin required' }, 403);
  }
  const cfg = await env.DASHBOARD_KV.get('system_config', 'json') || {};
  return json({
    // ── Existing ──
    sessionTtlHours:      cfg.sessionTtlHours ?? 8,
    idleTimeoutMin:       cfg.idleTimeoutMin ?? 60,
    maxUsers:             cfg.maxUsers ?? 50,
    defaultRole:          cfg.defaultRole ?? 'user',
    loginBannerMsg:       cfg.loginBannerMsg ?? '',
    auditRetentionDays:   cfg.auditRetentionDays ?? 30,
    dashboardTitle:       cfg.dashboardTitle ?? '',
    pwMinLength:          cfg.pwMinLength ?? 6,
    maxLoginAttempts:     cfg.maxLoginAttempts ?? 8,
    maintenanceMode:      cfg.maintenanceMode ?? false,
    maintenanceMsg:       cfg.maintenanceMsg ?? '',
    // ── Security / Login ──
    lockoutDurationMin:   cfg.lockoutDurationMin ?? 15,
    ipWhitelist:          cfg.ipWhitelist ?? [],
    loginTimeEnabled:     cfg.loginTimeEnabled ?? false,
    loginTimeStart:       cfg.loginTimeStart ?? '06:00',
    loginTimeEnd:         cfg.loginTimeEnd ?? '23:00',
    loginTimeZone:        cfg.loginTimeZone ?? 'Asia/Ho_Chi_Minh',
    pwExpiryDays:         cfg.pwExpiryDays ?? 0,
    // ── Session / Device ──
    maxConcurrentSessions:cfg.maxConcurrentSessions ?? 0,
    // ── Branding ──
    loginBgType:          cfg.loginBgType ?? 'none',
    loginBgValue:         cfg.loginBgValue ?? '',
    // ── Email Notifications ──
    emailEnabled:         cfg.emailEnabled ?? false,
    emailWebhook:         cfg.emailWebhook ?? '',
    emailAdminAddress:    cfg.emailAdminAddress ?? '',
    emailEvents: cfg.emailEvents ?? {
      login_success:    false,
      login_fail:       true,
      account_locked:   true,
      force_logout_all: true,
      maintenance_toggle: false,
      password_changed: false,
      password_expired: true,
    },
    updatedAt: cfg.updatedAt ?? null,
    updatedBy: cfg.updatedBy ?? null,
  });
}

async function handleSaveSystemConfig(request, env, ctx) {
  const session = await getSession(request, env);
  if (!session) return json({ error: 'Session expired' }, 401);
  if (!(await isAdminUser(env, session))) {
    const callerRaw = await env.DASHBOARD_KV.get(`user:${session.username}`, 'json');
    if (!callerRaw?.sysPerms?.systemConfig) return json({ error: 'Admin required' }, 403);
  }
  if (request.method !== 'POST') return json({ error: 'POST required' }, 405);
  let body; try { body = await request.json(); } catch { return json({ error: 'Invalid JSON' }, 400); }
  const cfg = await env.DASHBOARD_KV.get('system_config', 'json') || {};
  // ── Existing fields ──
  if (body.sessionTtlHours !== undefined)   cfg.sessionTtlHours   = Math.min(24, Math.max(1, Number(body.sessionTtlHours) || 8));
  if (body.idleTimeoutMin !== undefined)    cfg.idleTimeoutMin    = Math.min(720, Math.max(30, Number(body.idleTimeoutMin) || 60));
  if (body.maxUsers !== undefined)          cfg.maxUsers          = Math.min(200, Math.max(1, Number(body.maxUsers) || 50));
  if (body.defaultRole !== undefined && ['user', 'admin'].includes(body.defaultRole)) cfg.defaultRole = body.defaultRole;
  if (body.loginBannerMsg !== undefined)    cfg.loginBannerMsg    = String(body.loginBannerMsg).slice(0, 200);
  if (body.auditRetentionDays !== undefined)cfg.auditRetentionDays= Math.min(90, Math.max(7, Number(body.auditRetentionDays) || 30));
  if (body.dashboardTitle !== undefined)    cfg.dashboardTitle    = String(body.dashboardTitle).slice(0, 60);
  if (body.pwMinLength !== undefined)       cfg.pwMinLength       = Math.min(32, Math.max(4, Number(body.pwMinLength) || 6));
  if (body.maxLoginAttempts !== undefined)  cfg.maxLoginAttempts  = Math.min(20, Math.max(3, Number(body.maxLoginAttempts) || 8));
  if (body.maintenanceMode !== undefined) {
    const prev = cfg.maintenanceMode;
    cfg.maintenanceMode = !!body.maintenanceMode;
    if (prev !== cfg.maintenanceMode) notifyEmail(env, ctx, 'maintenance_toggle', { enabled: cfg.maintenanceMode, admin: session.username });
  }
  if (body.maintenanceMsg !== undefined)    cfg.maintenanceMsg    = String(body.maintenanceMsg).slice(0, 300);
  // ── Security / Login ──
  if (body.lockoutDurationMin !== undefined) cfg.lockoutDurationMin = Math.min(1440, Math.max(0, Number(body.lockoutDurationMin) || 0));
  if (body.ipWhitelist !== undefined)        cfg.ipWhitelist        = Array.isArray(body.ipWhitelist)
    ? body.ipWhitelist.map(s => String(s).trim()).filter(Boolean).slice(0, 50) : [];
  if (body.loginTimeEnabled !== undefined)   cfg.loginTimeEnabled   = !!body.loginTimeEnabled;
  if (body.loginTimeStart !== undefined && /^\d{2}:\d{2}$/.test(body.loginTimeStart)) cfg.loginTimeStart = body.loginTimeStart;
  if (body.loginTimeEnd !== undefined   && /^\d{2}:\d{2}$/.test(body.loginTimeEnd))   cfg.loginTimeEnd   = body.loginTimeEnd;
  if (body.loginTimeZone !== undefined) {
    const allowedTz = ['Asia/Ho_Chi_Minh','Asia/Bangkok','Asia/Singapore','UTC','Asia/Tokyo'];
    if (allowedTz.includes(body.loginTimeZone)) cfg.loginTimeZone = body.loginTimeZone;
  }
  if (body.pwExpiryDays !== undefined)       cfg.pwExpiryDays       = Math.min(365, Math.max(0, Number(body.pwExpiryDays) || 0));
  // ── Session / Device ──
  if (body.maxConcurrentSessions !== undefined) cfg.maxConcurrentSessions = Math.min(10, Math.max(0, Number(body.maxConcurrentSessions) || 0));
  // ── Branding ──
  if (body.loginBgType !== undefined && ['none','color','image'].includes(body.loginBgType)) cfg.loginBgType = body.loginBgType;
  if (body.loginBgValue !== undefined) cfg.loginBgValue = String(body.loginBgValue).slice(0, 500);
  // ── Email ──
  if (body.emailEnabled !== undefined)       cfg.emailEnabled       = !!body.emailEnabled;
  if (body.emailWebhook !== undefined)       cfg.emailWebhook       = String(body.emailWebhook).slice(0, 500);
  if (body.emailAdminAddress !== undefined)  cfg.emailAdminAddress  = String(body.emailAdminAddress).slice(0, 200);
  if (body.emailEvents !== undefined && typeof body.emailEvents === 'object' && !Array.isArray(body.emailEvents)) {
    cfg.emailEvents = { ...(cfg.emailEvents || {}) };
    for (const [k, v] of Object.entries(body.emailEvents)) cfg.emailEvents[k] = !!v;
  }
  cfg.updatedAt = Date.now();
  cfg.updatedBy = session.username;
  await env.DASHBOARD_KV.put('system_config', JSON.stringify(cfg));
  _invalidateCfgCache();  // drop cached config so the change applies immediately
  await logActivity(env, { action: 'system-config-update', username: session.username, ip: request.headers.get('CF-Connecting-IP') || '?', success: true, detail: 'System config updated' });
  return json({ success: true, config: cfg });
}


/* ═══════════════════════════════════════════════
   ESXi — SOAP-based (works on free ESXi 8.0)
   ═══════════════════════════════════════════════ */

function escXml(s) {
  return String(s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

// Extract first match of <tag>...</tag> (non-greedy) — handle namespace prefixes
function x1(text, tag) {
  const m = text.match(new RegExp('<(?:[a-zA-Z0-9_]+:)?' + tag + '[^>]*>([\\s\\S]*?)</(?:[a-zA-Z0-9_]+:)?' + tag + '>'));
  return m ? m[1].trim() : '';
}

// Extract ALL matches of <tag>...</tag> — handle namespace prefixes
function xAll(text, tag) {
  const re = new RegExp('<(?:[a-zA-Z0-9_]+:)?' + tag + '[^>]*>([\\s\\S]*?)</(?:[a-zA-Z0-9_]+:)?' + tag + '>', 'g');
  const out = []; let m;
  while ((m = re.exec(text)) !== null) out.push(m[1]);
  return out;
}

// Build key→value map from <propSet> blocks inside one <objects> block
function parsePropSets(objXml) {
  const props = {};
  for (const ps of xAll(objXml, 'propSet')) {
    const name = x1(ps, 'name');
    const val  = x1(ps, 'val');
    if (name) props[name] = val;
  }
  return props;
}


// SOAP variant for Movi ESXi — configurable URL + CF ZT headers
async function esxiSoapEx(bodyXml, sdkUrl, cfId, cfSec, cookie = '') {
  const headers = {
    'Content-Type': 'text/xml; charset=UTF-8',
    'SOAPAction': '"urn:vim25/8.0"',
  };
  if (cookie) headers['Cookie'] = cookie;
  if (cfId && cfSec) {
    headers['CF-Access-Client-Id']     = cfId;
    headers['CF-Access-Client-Secret'] = cfSec;
  }
  const envelope = [
    '<?xml version="1.0" encoding="UTF-8"?>',
    '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"',
    ' xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">',
    '<soapenv:Body>', bodyXml, '</soapenv:Body></soapenv:Envelope>',
  ].join('');
  const res  = await fetch(sdkUrl, { method: 'POST', headers, body: envelope, signal: AbortSignal.timeout(15000) });
  const text = await res.text();
  const sc   = res.headers.get('set-cookie') || '';
  const ck   = (sc.match(/vmware_soap_session[^;]+/) || [''])[0];
  return { text, cookie: ck, ok: res.ok };
}


/* ═══════════════════════════════════════════════
   CasaOS — REST API (v0.4.x)
   Auth: POST /v1/users/login → token (raw, no "Bearer" prefix!)
   ═══════════════════════════════════════════════ */
const CASAOS_BASE = 'https://casaos.home-server.id.vn';

async function handleCasaOS(env) {
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
async function rustdeskToken(env) {
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

async function handleRustdesk(env) {
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
async function handleVmwareHome(env) {
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

async function handleVmwareHomePower(request, env) {
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
async function handleMoviVmwareData(env, hostNum) {
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

async function handleMoviVmwarePower(request, env, hostNum) {
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
async function handleFortigateWebhook(env) {
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

async function handleFortigateBW(env) {
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

async function handleFortigateReboot(env) {
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
   FortiGate — REST API v2 (kept for reference / fallback)
   Via Cloudflare Tunnel + CF Access Service Token
   ═══════════════════════════════════════════════ */
async function handleFortigate(env, debug = false) {
  const base  = env.FORTIGATE_URL;
  const key   = env.FORTIGATE_API_KEY;
  const cfId  = env.CF_ACCESS_CLIENT_ID;
  const cfSec = env.CF_ACCESS_CLIENT_SECRET;

  if (!base || !key) return json({ error: 'FORTIGATE_URL / FORTIGATE_API_KEY not configured' }, 500);

  const headers = {
    'Authorization': `Bearer ${key}`,
    'Accept': 'application/json',
  };
  // Bypass Cloudflare Access for Worker→Fortigate tunnel calls
  if (cfId && cfSec) {
    headers['CF-Access-Client-Id']     = cfId;
    headers['CF-Access-Client-Secret'] = cfSec;
  }

  const opts = { headers, signal: AbortSignal.timeout(12000) };

  const _debug = {
    cfIdPresent:  !!(cfId  && cfId.length  > 0),
    cfSecPresent: !!(cfSec && cfSec.length > 0),
    baseUrl: base,
  };
  const safeGet = async (path) => {
    let status = null;
    try {
      const r = await fetch(`${base}${path}`, opts);
      status = r.status;
      const bodyText = await r.text();
      const isHtml = bodyText.trimStart().startsWith('<');
      _debug[path] = { status, ok: r.ok, isHtml };
      if (!r.ok || isHtml) return null;
      const parsed = JSON.parse(bodyText);
      return (parsed?.results !== undefined) ? parsed.results : parsed;
    } catch(e) {
      _debug[path] = { status, error: e.message };
      return null;
    }
  };

  // safeGetFull: returns the full response body (not just .results)
  // needed for system/status where serial/version/build are at top level
  const safeGetFull = async (path) => {
    let status = null;
    try {
      const r = await fetch(`${base}${path}`, opts);
      status = r.status;
      const bodyText = await r.text();
      _debug[path + '_full'] = { status, ok: r.ok };
      if (!r.ok) return null;
      return JSON.parse(bodyText);
    } catch(e) {
      _debug[path + '_full'] = { status, error: e.message };
      return null;
    }
  };

  // Fetch all endpoints in parallel (all read-only)
  const [sysRaw, resUsage, ifaceRaw2, vpnIpsec, sslVpnRaw, sslVpnStats, policiesRaw] = await Promise.all([
    safeGetFull('/api/v2/monitor/system/status'),
    safeGet('/api/v2/monitor/system/resource/usage'),
    safeGet('/api/v2/monitor/system/interface'),
    safeGet('/api/v2/monitor/vpn/ipsec'),
    safeGet('/api/v2/monitor/vpn/ssl'),
    safeGet('/api/v2/monitor/vpn/ssl/stats'),
    safeGet('/api/v2/cmdb/firewall/policy?count=100'),
  ]);

  // Merge top-level (serial, version, build) + results (hostname, model) for system status
  const sysStatus = sysRaw ? { ...(sysRaw.results || {}), ...sysRaw } : null;

  // ── System info ──
  const sys = sysStatus || {};

  // ── Resource usage — FortiOS may return array of datapoints or single object ──
  const lastVal = (v) => {
    if (v === null || v === undefined) return null;
    if (Array.isArray(v)) return v[v.length - 1]?.current ?? null;
    if (typeof v === 'object') return v.current ?? v.value ?? null;
    if (typeof v === 'number') return v;
    return null;
  };
  const res = resUsage || {};
  const cpuPct   = lastVal(res.cpu);
  const memPct   = lastVal(res.mem);
  // Sessions: FortiOS 7.4 uses "session" key (not "netsession") in resource/usage
  const sessions = lastVal(res.session) ?? lastVal(res.netsession) ?? null;
  const diskPct  = lastVal(res.disk);
  // Uptime: from system/status results (field may be beyond 200-char snippet)
  // sysRaw.results.uptime is in seconds on FortiOS 7.x
  const upSec = sysRaw?.results?.uptime
    ?? sysRaw?.uptime
    ?? lastVal(res.uptime)
    ?? 0;

  // ── Uptime string ──
  const uptimeDays  = Math.floor(upSec / 86400);
  const uptimeHours = Math.floor((upSec % 86400) / 3600);
  const uptimeMins  = Math.floor((upSec % 3600)  / 60);
  const uptimeStr   = uptimeDays > 0
    ? `${uptimeDays}d ${uptimeHours}h ${uptimeMins}m`
    : `${uptimeHours}h ${uptimeMins}m`;

  // ── Interfaces ── FortiOS returns object {wan1:{...}, lan:{...}} not array
  const ifaceRaw = ifaceRaw2
    ? (Array.isArray(ifaceRaw2) ? ifaceRaw2 : Object.values(ifaceRaw2))
    : [];
  const ifaces = ifaceRaw
    .filter(i => i.name && !i.name.startsWith('naf.') && !i.name.startsWith('ssl.'))
    .map(i => ({
      name:     i.name,
      alias:    i.alias  || '',
      status:   (i.link === true || i.status === 'up') ? 'up' : 'down',
      ip:       i.ip    || '',
      mask:     i.mask  || '',
      speed:    i.speed || 0,
      txBytes:  i.tx_bytes  || 0,
      rxBytes:  i.rx_bytes  || 0,
      txPkts:   i.tx_packets || 0,
      rxPkts:   i.rx_packets || 0,
      mac:      i.mac   || '',
      type:     i.type  || '',
    }))
    .sort((a, b) => {
      // WAN first, then up interfaces, then alpha
      const priority = (n) => {
        if (/wan/i.test(n)) return 0;
        if (/lan|internal|port1/i.test(n)) return 1;
        return 2;
      };
      const pd = priority(a.name) - priority(b.name);
      if (pd !== 0) return pd;
      if (a.status !== b.status) return a.status === 'up' ? -1 : 1;
      return a.name.localeCompare(b.name);
    });

  // ── VPN IPSec ──
  const vpnRaw = Array.isArray(vpnIpsec) ? vpnIpsec : [];
  const vpns = vpnRaw.map(v => {
    const tunnels = (v.proxyid || []).map(p => ({
      name:     p.p2name    || p.name || '',
      status:   p.status   || 'down',
      inBytes:  p.inbytes  || 0,
      outBytes: p.outbytes || 0,
    }));
    const anyUp = tunnels.some(t => t.status === 'up') || v.tun_stat?.includes('up');
    return {
      name:    v.name || v.rgwy || '',
      status:  anyUp ? 'up' : 'down',
      rgwy:    v.rgwy || '',
      tunnels,
    };
  });

  const vpnUp   = vpns.filter(v => v.status === 'up').length;
  const vpnDown = vpns.length - vpnUp;

  // ── SSL VPN ──
  const sslUsers = Array.isArray(sslVpnRaw) ? sslVpnRaw : [];
  const sslStats = sslVpnStats?.statistics || sslVpnStats || {};
  const ssl = {
    activeUsers: sslUsers.length,
    maxTunnels:  sslStats.max_num_tunnels  ?? sslStats.max_tunnels  ?? null,
    numTunnels:  sslStats.num_tunnels      ?? sslUsers.length,
    users: sslUsers.map(u => ({
      user:       u.user_name    || u.username || '',
      remoteHost: u.remote_host  || '',
      tunnelIp:   u.tunnel_ip    || '',
      duration:   u.duration     || 0,
      inBytes:    u.incoming_bytes  || 0,
      outBytes:   u.outgoing_bytes  || 0,
    })),
  };

  // ── Firewall Policies ──
  const policyArr = Array.isArray(policiesRaw) ? policiesRaw : [];
  const policies = policyArr.map(p => ({
    id:       p.policyid  || p.q_origin_key,
    name:     p.name      || `Policy ${p.policyid}`,
    srcIntf:  (p.srcintf  || []).map(i => i.name || i).join(', '),
    dstIntf:  (p.dstintf  || []).map(i => i.name || i).join(', '),
    srcAddr:  (p.srcaddr  || []).map(i => i.name || i).join(', '),
    dstAddr:  (p.dstaddr  || []).map(i => i.name || i).join(', '),
    service:  (p.service  || []).map(i => i.name || i).join(', '),
    action:   p.action    || 'accept',
    status:   p.status    || 'enable',
    nat:      p.nat       || 'disable',
    comments: p.comments  || '',
  }));

  return json({
    system: {
      hostname:  sys.hostname   || '',
      model:     sys.model_name || sys.model || sys.model_number || '',
      serial:    sys.serial     || '',
      version:   sys.version    || '',
      build:     sys.build      || '',
      uptime:    uptimeStr,
      uptimeSec: upSec,
      sysTime:   sys.system_time || sys.current_time || '',
    },
    resources: { cpuPct, memPct, sessions, diskPct },
    interfaces: ifaces,
    vpn: vpns,
    ssl,
    policies,
    stats: {
      ifaceUp:   ifaces.filter(i => i.status === 'up').length,
      ifaceDown: ifaces.filter(i => i.status === 'down').length,
      ifaceTotal: ifaces.length,
      vpnUp,
      vpnDown,
      vpnTotal: vpns.length,
      sessions,
      sslUsers: ssl.activeUsers,
      totalPolicies: policies.length,
      enabledPolicies: policies.filter(p => p.status === 'enable').length,
    },
    ...(debug ? { _debug } : {}),
  });
}

/* ═══════════════════════════════════════════════
   ASUS Router — via n8n webhooks (local IP)
   ═══════════════════════════════════════════════ */


async function handleAsusWebhook(env) {
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

async function handleAsusBw(env) {
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

async function handleAsusReboot(request, env) {
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

function json(data, status = 200) {
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

/* ═══════════════════════════════════════════════
   Web Proxy — fetch any HTTPS URL, strip frame-blocking headers
   so it can be embedded in an iframe on the dashboard
   ═══════════════════════════════════════════════ */
function _escHtml(s) { return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }
function proxyErr(msg, url) {
  return new Response(
    `<html><head><meta charset="UTF-8"></head><body style="font-family:system-ui;padding:2rem;background:#0b0d14;color:#e2e8f0">
      <h2 style="color:#f87171;margin-bottom:1rem">⚠ Không thể kết nối</h2>
      <p style="white-space:pre-line;line-height:1.7;color:#cbd5e1">${_escHtml(msg)}</p>
      ${url ? `<p style="margin-top:1rem;font-size:12px;color:#64748b">URL: ${_escHtml(url)}</p>` : ''}
    </body></html>`,
    { status: 502, headers: { 'content-type': 'text/html;charset=utf-8' } }
  );
}

async function handleProxy(request, env) {
  // Require an authenticated session — this endpoint can carry CF-Access
  // service credentials, so it must never be reachable anonymously (SSRF).
  const session = await getSession(request, env);
  if (!session) return proxyErr('Bạn cần đăng nhập để dùng tính năng này.', '');

  const reqUrl = new URL(request.url);
  const target = reqUrl.searchParams.get('url');
  if (!target) return new Response('Missing ?url= parameter', { status: 400 });

  let targetUrl;
  try { targetUrl = new URL(target); } catch {
    return new Response('Invalid URL', { status: 400 });
  }
  if (targetUrl.protocol !== 'https:')
    return proxyErr('Chỉ hỗ trợ URL HTTPS.', target);

  // Block private/local/link-local/loopback hosts (defence-in-depth vs SSRF)
  const h = targetUrl.hostname.replace(/^\[|\]$/g, '');
  const isPrivate =
    /^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|169\.254\.|127\.|0\.)/.test(h) ||
    /^(localhost|.*\.local|.*\.internal)$/i.test(h) ||
    /^(::1?$|fc|fd|fe80:)/i.test(h) ||
    h === '0.0.0.0';
  if (isPrivate) return proxyErr(
    `"${h}" là địa chỉ IP nội bộ — Cloudflare Worker không thể kết nối tới LAN của anh.\n\n` +
    `Để dùng tính năng này, anh cần tạo Cloudflare Tunnel cho dịch vụ này trước,\n` +
    `rồi dùng URL tunnel (VD: https://fortigate-ui.home-server.id.vn) thay vì IP local.`, target);

  // Whitelist: only allow proxying to our own trusted domains
  const isTrustedDomain = h === 'home-server.id.vn' || h.endsWith('.home-server.id.vn')
    || h === 'movi-finance.com' || h.endsWith('.movi-finance.com');
  if (!isTrustedDomain) return proxyErr(
    `Proxy chỉ hỗ trợ các domain nội bộ (*.home-server.id.vn, *.movi-finance.com).\n` +
    `Domain "${h}" không được phép.`, target);

  // Forward CF Access credentials ONLY to our own trusted domain
  // (exact host or *.home-server.id.vn — note the leading dot to prevent
  // an attacker-controlled "evilhome-server.id.vn" from matching).
  const cfId  = env.CF_ACCESS_CLIENT_ID;
  const cfSec = env.CF_ACCESS_CLIENT_SECRET;
  const trusted = h === 'home-server.id.vn' || h.endsWith('.home-server.id.vn');
  const headers = { 'User-Agent': 'Mozilla/5.0 (HomeLabDashboard Proxy)' };
  if (cfId && cfSec && trusted) {
    headers['CF-Access-Client-Id']     = cfId;
    headers['CF-Access-Client-Secret'] = cfSec;
  }

  try {
    const res = await fetch(targetUrl.toString(), {
      method: 'GET', headers,
      redirect: 'follow',
      signal: AbortSignal.timeout(20000),
    });

    // Build new headers, stripping frame-blocking ones
    const out = new Headers();
    for (const [k, v] of res.headers) {
      const kl = k.toLowerCase();
      if (kl === 'x-frame-options') continue;         // allow iframe
      if (kl === 'content-security-policy') {
        // Strip frame-ancestors directive only
        const stripped = v.replace(/frame-ancestors[^;]*(;|$)/gi, '').trim().replace(/;$/, '');
        if (stripped) out.set(k, stripped);
        continue;
      }
      out.set(k, v);
    }
    out.set('X-Proxy-By', 'HomeLabDashboard');

    const ct = res.headers.get('content-type') || '';
    if (ct.includes('text/html')) {
      let html = await res.text();
      // Inject <base> so relative URLs resolve back to the original origin
      const baseTag = `<base href="${targetUrl.origin}/">`;
      if (/<head[\s>]/i.test(html)) {
        html = html.replace(/(<head[^>]*>)/i, `$1\n  ${baseTag}`);
      } else {
        html = baseTag + html;
      }
      out.set('content-type', 'text/html; charset=utf-8');
      return new Response(html, { status: res.status, headers: out });
    }

    return new Response(res.body, { status: res.status, headers: out });
  } catch (e) {
    return proxyErr(`Lỗi kết nối: ${e.message}\n\nKiểm tra lại URL và đảm bảo dịch vụ đang chạy và có Cloudflare Tunnel.`, target);
  }
}

/* ═══════════════════════════════════════════════
   SSH Movi — Secure Terminal Token Flow
   Bảo vệ bằng short-lived single-use token (KV)
   Nginx trên Movi server gọi /api/ssh-movi/verify
   để validate trước khi cho browser qua ttyd
   ═══════════════════════════════════════════════ */

/**
 * POST /api/ssh-movi/token
 * Requires: session + ssh-movi permission
 * Returns: { token, url, expiresIn }
 * Token TTL = 10 phút, single-use (bị xoá ngay sau verify)
 */
async function handleSshMoviToken(request, env) {
  const session = await getSession(request, env);
  if (!session) return json({ error: 'Unauthorized' }, 401);
  if (!(await hasPerm(env, session, 'ssh-movi'))) return json({ error: 'Không có quyền truy cập SSH Movi' }, 403);

  const termixUrl = env.TERMIX_MOVI_URL;
  if (!termixUrl) return json({ error: 'TERMIX_MOVI_URL chưa được cấu hình. Chạy: npx wrangler secret put TERMIX_MOVI_URL' }, 502);

  // Generate a cryptographically random single-use token
  const token = crypto.randomUUID().replace(/-/g, '') + crypto.randomUUID().replace(/-/g, '');
  const ip    = request.headers.get('cf-connecting-ip') || 'unknown';
  const ttl   = 600; // 10 minutes

  await env.DASHBOARD_KV.put(
    `ssh_movi_token:${token}`,
    JSON.stringify({ username: session.username, ip, createdAt: Date.now() }),
    { expirationTtl: ttl }
  );

  await logActivity(env, {
    action: 'ssh-movi-token-issued',
    username: session.username,
    ip,
    success: true,
    detail: `Token issued for SSH Movi terminal`,
  });

  // Append token as query param — nginx on Movi server validates via auth_request
  const iframeUrl = termixUrl.replace(/\/$/, '') + '/?t=' + token;
  return json({ token, url: iframeUrl, expiresIn: ttl });
}

/**
 * GET /api/ssh-movi/verify?t=TOKEN
 * Called by nginx auth_request on Movi server — NO dashboard session required.
 * Validates token, deletes it (single-use), returns 200 or 403.
 * IMPORTANT: This endpoint is intentionally public but token is 64-char random hex
 * (2× UUID = 128-bit entropy each → brute-force infeasible within 10-min window).
 */
async function handleSshMoviVerify(request, env) {
  // 1. Check session cookie first (subsequent requests)
  const cookieHeader = request.headers.get('cookie') || '';
  const sessionMatch = cookieHeader.match(/ts_movi=([a-f0-9]{64})/);
  if (sessionMatch) {
    const sessionKey = `ssh_movi_session:${sessionMatch[1]}`;
    const sessionData = await env.DASHBOARD_KV.get(sessionKey, 'json');
    if (sessionData) {
      // Refresh session TTL
      await env.DASHBOARD_KV.put(sessionKey, JSON.stringify(sessionData), { expirationTtl: 3600 });
      return new Response('OK', {
        status: 200,
        headers: {
          'X-Session-Cookie': `ts_movi=${sessionMatch[1]}; Path=/; Max-Age=3600; HttpOnly; Secure; SameSite=None`,
          'Cache-Control': 'no-store',
        },
      });
    }
  }

  // 2. No valid session — check URL token (initial request)
  const url   = new URL(request.url);
  const token = (url.searchParams.get('t') || '').replace(/[^a-f0-9]/gi, '');
  if (!token || token.length < 32) return new Response('Forbidden', { status: 403 });

  const kvKey = `ssh_movi_token:${token}`;
  const data  = await env.DASHBOARD_KV.get(kvKey, 'json');
  if (!data) return new Response('Forbidden', { status: 403 });

  // Single-use: xóa token ngay để chống replay attack
  await env.DASHBOARD_KV.delete(kvKey).catch(() => {});

  // 3. Token valid — create a session
  const sessionBytes = new Uint8Array(32);
  crypto.getRandomValues(sessionBytes);
  const sessionId = Array.from(sessionBytes).map(b => b.toString(16).padStart(2, '0')).join('');
  await env.DASHBOARD_KV.put(`ssh_movi_session:${sessionId}`, JSON.stringify({ username: data.username }), { expirationTtl: 3600 });

  await logActivity(env, {
    action: 'ssh-movi-token-verified',
    username: data.username,
    ip: request.headers.get('cf-connecting-ip') || data.ip,
    success: true,
    detail: `SSH Movi session started`,
  });

  return new Response('OK', {
    status: 200,
    headers: {
      'X-Session-Cookie': `ts_movi=${sessionId}; Path=/; Max-Age=3600; HttpOnly; Secure; SameSite=None`,
      'Cache-Control': 'no-store',
    },
  });
}

/* ═══════════════════════════════════════════════
   Termix Movi — Worker Reverse Proxy
   Proxies termix-movi.home-server.id.vn qua Worker,
   thêm CF Service Token headers để bypass CF Access.
   Yêu cầu: dashboard session + quyền ssh-movi.
   ═══════════════════════════════════════════════ */

async function handleTermixProxy(request, env, opts) {
  // Auth check
  const session = await getSession(request, env);
  if (!session) return new Response('Chưa đăng nhập — vui lòng đăng nhập lại', { status: 401 });
  if (!(await hasPerm(env, session, opts.perm)))
    return new Response('Không có quyền truy cập ' + opts.label, { status: 403 });

  const termixOrigin = opts.origin.replace(/\/$/, '');
  const originHost   = new URL(termixOrigin).hostname;
  const BASE         = opts.base;
  const clientId     = opts.cfId;
  const clientSecret = opts.cfSecret;

  // Build target URL (strip proxy prefix)
  const reqUrl  = new URL(request.url);
  const subPath = reqUrl.pathname.slice(BASE.length) || '/';
  const target  = `${termixOrigin}${subPath}${reqUrl.search}`;

  // Upstream auth headers
  const upHeaders = new Headers();
  // CF Service Token (nếu có — bypass CF Access)
  if (clientId && clientSecret) {
    upHeaders.set('CF-Access-Client-Id',     clientId);
    upHeaders.set('CF-Access-Client-Secret', clientSecret);
  }
  // Shared secret header — nginx validates này để block direct browser access
  if (opts.secret) upHeaders.set('X-Proxy-Token', opts.secret);

  // X-Forwarded-Host: needed so Termix generates + stores redirect_uri = https://<dashboard>/users/oidc/callback
  // for BOTH the authorization URL AND the code→token exchange (both must use the same redirect_uri).
  // Without this, Termix stores redirect_uri=termix-movi.../callback but Microsoft issues code for
  // dashboard.../callback → mismatch → 400 on token exchange.
  // Post-login redirect (Termix → dashboard URL) is handled in the redirect handler below.
  const _dashFwdOrigin = new URL(request.url);
  upHeaders.set('X-Forwarded-Host',  _dashFwdOrigin.hostname);
  upHeaders.set('X-Forwarded-Proto', 'https');

  // Forward Termix session cookies, strip dashboard cookies
  const rawCookie = request.headers.get('cookie') || '';
  const fwdCookie = rawCookie.split(';')
    .map(c => c.trim())
    .filter(c => c && !c.startsWith('dh_session=') && !c.startsWith('ts_movi='))
    .join('; ');
  if (fwdCookie) upHeaders.set('Cookie', fwdCookie);
  // Forward Authorization header — Termix API uses Bearer token auth for protected endpoints
  const authHeader = request.headers.get('Authorization');
  if (authHeader) upHeaders.set('Authorization', authHeader);

  // ── WebSocket proxy ──
  if (request.headers.get('Upgrade')?.toLowerCase() === 'websocket') {
    const wsTarget = target.replace(/^https/, 'wss').replace(/^http(?!s)/, 'ws');
    upHeaders.set('Upgrade',               'websocket');
    upHeaders.set('Connection',            'Upgrade');
    upHeaders.set('Sec-WebSocket-Version', request.headers.get('Sec-WebSocket-Version') || '13');
    // Set Origin to the Termix origin so Guacamole accepts the connection
    upHeaders.set('Origin', termixOrigin);
    // Forward subprotocol (required for Guacamole: 'guacamole')
    const swp = request.headers.get('Sec-WebSocket-Protocol');
    if (swp) upHeaders.set('Sec-WebSocket-Protocol', swp);

    let upResp;
    try {
      upResp = await fetch(wsTarget, { headers: upHeaders });
    } catch (wsErr) {
      return new Response(
        JSON.stringify({ error: 'WS fetch error', msg: wsErr.message, target: wsTarget }),
        { status: 502, headers: { 'Content-Type': 'application/json' } }
      );
    }
    const upstream = upResp.webSocket;
    if (!upstream) {
      // Verbose error so user can diagnose in Network tab
      const upStatus = upResp.status;
      const upBody   = await upResp.text().catch(() => '(no body)');
      return new Response(
        JSON.stringify({ error: 'WS upstream did not upgrade', status: upStatus, body: upBody.slice(0, 800), target: wsTarget }),
        { status: 502, headers: { 'Content-Type': 'application/json' } }
      );
    }

    const { 0: client, 1: server } = new WebSocketPair();
    server.accept();
    upstream.accept();

    server.addEventListener('message',   ({ data }) => { try { upstream.send(data); } catch(_) {} });
    upstream.addEventListener('message', ({ data }) => { try { server.send(data);   } catch(_) {} });
    server.addEventListener('close',   ({ code, reason }) => { try { upstream.close(code, reason); } catch(_) {} });
    upstream.addEventListener('close', ({ code, reason }) => { try { server.close(code, reason);   } catch(_) {} });

    // Pass Sec-WebSocket-Protocol back — Guacamole requires server to echo the subprotocol
    const wsRespHeaders = new Headers();
    const echoSwp = upResp.headers.get('Sec-WebSocket-Protocol');
    if (echoSwp) wsRespHeaders.set('Sec-WebSocket-Protocol', echoSwp);
    else if (swp) wsRespHeaders.set('Sec-WebSocket-Protocol', swp);

    return new Response(null, { status: 101, webSocket: client, headers: wsRespHeaders });
  }

  // ── HTTP proxy ──
  if (!['GET', 'HEAD'].includes(request.method)) {
    const ct = request.headers.get('Content-Type');
    if (ct) upHeaders.set('Content-Type', ct);
  }
  let upstream;
  try {
    upstream = await fetch(target, {
      method:   request.method,
      headers:  upHeaders,
      body:     ['GET', 'HEAD'].includes(request.method) ? undefined : request.body,
      redirect: 'manual', // Don't follow redirects — rewrite Location headers ourselves
    });
  } catch (fetchErr) {
    return new Response(
      `<html><body style="font:14px system-ui;padding:2rem;background:#1a1a2e;color:#e0e0e0">
        <h2 style="color:#ff6b6b">⚠ Termix Proxy — Fetch Error</h2>
        <p><b>Target:</b> <code>${_escHtml(target)}</code></p>
        <p><b>Error:</b> <code>${_escHtml(fetchErr.message)}</code></p>
        <p style="color:#888">Kiểm tra: CF Access Bypass, nginx đang chạy, Termix port 8081</p>
      </body></html>`,
      { status: 502, headers: { 'Content-Type': 'text/html; charset=utf-8' } }
    );
  }

  // Handle 3xx redirects from Termix — rewrite Location headers before forwarding to browser.
  // Without this, Termix's Location headers point to termix-movi.home-server.id.vn (blocked by CF Access).
  if (upstream.status >= 300 && upstream.status < 400) {
    const _loc    = upstream.headers.get('Location') || '';
    const _reqOri = new URL(request.url).origin;
    let   _newLoc = _loc;

    if (_loc.startsWith(termixOrigin)) {
      // Absolute Termix URL → proxy path
      _newLoc = BASE + _loc.slice(termixOrigin.length);
    } else if (_loc === _reqOri + '/' || _loc === _reqOri) {
      // Termix redirected to our dashboard root — redirect to Termix app root through proxy
      _newLoc = BASE + '/';
    } else if (_loc.startsWith(_reqOri + '/') && !_loc.startsWith(_reqOri + '/proxy/')) {
      // Termix redirected to our dashboard domain for a non-proxy path — redirect to proxy root
      _newLoc = BASE + '/';
    } else if (_loc.startsWith('/') && !_loc.startsWith(BASE) && !_loc.startsWith('//')) {
      // Root-relative → prefix with proxy path
      _newLoc = BASE + _loc;
    }
    // else: already absolute external URL — pass through as-is

    const _rhRedir = new Headers({ 'Location': _newLoc, 'Cache-Control': 'no-cache' });
    const _setSCR  = typeof upstream.headers.getAll === 'function'
      ? upstream.headers.getAll('set-cookie')
      : (upstream.headers.get('set-cookie') ? [upstream.headers.get('set-cookie')] : []);
    for (const _sc of _setSCR) _rhRedir.append('Set-Cookie', _rewriteTermixCookie(_sc, BASE));
    return new Response(null, { status: upstream.status, headers: _rhRedir });
  }

  // Non-2xx: pass through 4xx as-is so Termix frontend can handle auth errors (401, 403, etc.)
  // Only replace with visible error HTML for 5xx upstream failures
  if (!upstream.ok) {
    if (upstream.status < 500) {
      const upCt4 = upstream.headers.get('Content-Type') || 'application/octet-stream';
      const rh4   = new Headers({ 'Content-Type': upCt4, 'Cache-Control': 'no-cache' });
      const setSC4 = typeof upstream.headers.getAll === 'function'
        ? upstream.headers.getAll('set-cookie')
        : (upstream.headers.get('set-cookie') ? [upstream.headers.get('set-cookie')] : []);
      for (const sc of setSC4) rh4.append('Set-Cookie', _rewriteTermixCookie(sc, BASE));
      return new Response(upstream.body, { status: upstream.status, headers: rh4 });
    }
    // 5xx: show visible error page for diagnosability
    const errBody = await upstream.text().catch(() => '(no body)');
    return new Response(
      `<html><body style="font:14px system-ui;padding:2rem;background:#1a1a2e;color:#e0e0e0">
        <h2 style="color:#ff6b6b">⚠ Termix Proxy — Upstream Error</h2>
        <p><b>Target:</b> <code>${_escHtml(target)}</code></p>
        <p><b>Status:</b> <code>${upstream.status} ${_escHtml(upstream.statusText)}</code></p>
        <p><b>Content-Type:</b> <code>${_escHtml(upstream.headers.get('content-type') || 'none')}</code></p>
        <pre style="background:#111;padding:1rem;border-radius:8px;overflow:auto;color:#ffa;font-size:12px">${_escHtml(errBody.slice(0,500))}</pre>
        <p style="color:#888">Nếu 403: X-Proxy-Token không khớp với nginx. Nếu 502/504: Termix chưa chạy.</p>
      </body></html>`,
      { status: 502, headers: { 'Content-Type': 'text/html; charset=utf-8' } }
    );
  }

  // Build response headers
  const ct  = upstream.headers.get('Content-Type') || 'application/octet-stream';
  const rh  = new Headers({ 'Content-Type': ct, 'Cache-Control': 'no-cache' });
  const setSC = typeof upstream.headers.getAll === 'function'
    ? upstream.headers.getAll('set-cookie')
    : (upstream.headers.get('set-cookie') ? [upstream.headers.get('set-cookie')] : []);
  for (const sc of setSC) rh.append('Set-Cookie', _rewriteTermixCookie(sc, BASE));

  // HTML — inject JS to rewrite WebSocket/fetch/XHR URLs to proxy path
  if (ct.includes('text/html')) {
    let html = await upstream.text();
    // [Termix subpath] Termix hỗ trợ chạy dưới subpath qua window.__TERMIX_BASE_PATH__.
    // Set nó = BASE để Termix tự gọi mọi API/route đúng path proxy (same-origin → cookie chạy).
    // Đây là cơ chế chính thức của Termix-SSH, robust hơn rewrite URL.
    if (opts.baseInject !== false) {
      html = html.replace(/window\.__TERMIX_BASE_PATH__\s*=\s*["'][^"']*["']/,
        'window.__TERMIX_BASE_PATH__ = "' + BASE + '"');
    }
    // [H2 fix] Extract JWT from HttpOnly cookie for safe server-side injection.
    // The JWT cookie is HttpOnly so JS cannot read it via document.cookie.
    // Instead we extract it here and inject as a scoped JS variable.
    const _reqCookies = request.headers.get('cookie') || '';
    const _jwtMatch = _reqCookies.split(';').map(c=>c.trim()).find(c=>c.startsWith('jwt='));
    const _jwtVal = _jwtMatch ? _jwtMatch.slice(4) : '';
    // Patcher must run BEFORE Termix's Vue bundle — inject at very start of <head>
    // NOTE: NO new RegExp() here — use indexOf/slice only to avoid escaping issues
    const patch = `<script>
(function(){
  var B='${BASE}';
  var O='${originHost}';
  var __JWT='${_jwtVal.replace(/'/g, "\\'")}'; // server-injected, HttpOnly safe
  // [Termix webview fix] Termix coi MỌI iframe (window.self!==window.top) là Electron webview
  // → dùng auth model native + kẹt "Redirecting to app...". Ép window.top===window.self để
  // Termix nghĩ nó chạy top-level → dùng auth web cookie bình thường. PHẢI chạy trước bundle Termix.
  try{
    Object.defineProperty(window,'top',{get:function(){return window.self;},configurable:true});
    console.log('[proxy-patcher] window.top override OK (self===top)');
  }catch(e){ console.warn('[proxy-patcher] window.top override failed',e); }
  try{ window.IS_ELECTRON_WEBVIEW=false; }catch(e){}
  var WSMODE='${opts.wsMode || 'direct'}';
  console.log('[proxy-patcher] loaded B='+B);
  function _stripB(p){ return (p.indexOf(B)===0)?(p.slice(B.length)||'/'):p; }
  function rw(u,isWS){
    if(typeof u!=='string'||!u)return u;
    // http(s)://<origin>... -> /proxy/.../...  (HTTP only, not WS)
    if(u.indexOf('http')===0&&u.indexOf(O)!==-1){
      return u.replace('https://'+O,B).replace('http://'+O,B);
    }
    // WebSocket. WSMODE='proxy' → giữ WS tới dashboard/proxy (worker proxy + thêm CF token).
    //           WSMODE='direct' → DIRECT tới origin thật (strip base), browser tự nối (Movi).
    if(u.indexOf('wss://')===0||u.indexOf('ws://')===0){
      if(WSMODE==='proxy') return u; // Termix đã dựng URL có base path → tới dashboard/proxy → worker
      if(u.indexOf(O)!==-1)return u;
      var si=u.indexOf('/',u.indexOf('//')+2);
      var path=si===-1?'/':u.slice(si);
      return 'wss://'+O+_stripB(path);
    }
    // Root-relative path
    if(u.charAt(0)==='/'&&u.slice(0,2)!=='//'){
      if(isWS){
        if(WSMODE==='proxy') return (u.slice(0,B.length)===B)?u:(B+u); // đảm bảo có prefix proxy
        return 'wss://'+O+_stripB(u); // direct tới origin
      }
      if(u.slice(0,B.length)!==B) return B+u;
    }
    return u;
  }
  var _W=window.WebSocket;
  window.WebSocket=function(u,p){
    var r=rw(u,true);
    // For SSH websocket: append JWT as ?token= so verifyClient can auth
    // [H2 fix] JWT is injected server-side (__JWT), NOT read from document.cookie (HttpOnly)
    if(r.indexOf('/ssh/websocket')!==-1){
      var _tk=__JWT||(localStorage.getItem('token')||localStorage.getItem('jwt')||localStorage.getItem('authToken')||'');
      if(_tk)r+=(r.indexOf('?')===-1?'?':'&')+'token='+_tk;
      else console.warn('[proxy-patcher] SSH WS: no JWT found');
    }
    if(r!==u)console.log('[proxy-patcher] WS',u,'->',r);
    return p!=null?new _W(r,p):new _W(r);
  };
  window.WebSocket.prototype=_W.prototype;
  for(var k in _W)try{window.WebSocket[k]=_W[k];}catch(e){}
  var _f=window.fetch;
  window.fetch=function(){
    var a=[].slice.call(arguments);
    if(typeof a[0]==='string'){var r=rw(a[0]);if(r!==a[0]){console.log('[proxy-patcher] fetch',a[0],'->',r);a[0]=r;}}
    return _f.apply(this,a);
  };
  var _x=XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open=function(){
    var a=[].slice.call(arguments);
    if(typeof a[1]==='string'){var r=rw(a[1]);if(r!==a[1]){console.log('[proxy-patcher] XHR',a[1],'->',r);a[1]=r;}}
    this._proxyUrl=a[1]||'';
    return _x.apply(this,a);
  };
  // loginRedirect: reload parent iframe sau khi login thanh cong
  // Don gian: sau POST /users/login -> 200 -> fire loginRedirect sau 800ms
  function _fireLoginRedirect(src){
    console.log('[proxy-patcher] loginRedirect from:',src);
    try{window.parent.postMessage({_termixProxy:true,type:'loginRedirect'},'*');}catch(e){}
  }
  try{
    var _xs=XMLHttpRequest.prototype.send;
    XMLHttpRequest.prototype.send=function(){
      var self=this;
      var _u=self._proxyUrl||'';
      // TOTP verify thành công = login HOÀN TẤT (cho cả user bật 2FA)
      if(_u.indexOf('/users/totp/verify-login')!==-1){
        self.addEventListener('load',function(){
          if(self.status>=200&&self.status<300){
            console.log('[proxy-patcher] totp verify 200 -> loginRedirect in 800ms');
            setTimeout(function(){_fireLoginRedirect('totp-ok');},800);
          }
        });
      } else if(_u.indexOf('/users/login')!==-1){
        self.addEventListener('load',function(){
          if(self.status>=200&&self.status<300){
            // Nếu response báo cần 2FA (requires_totp/temp_token) → KHÔNG reload, để user nhập mã
            var _b='';
            try{ _b=self.responseText||''; }catch(e){ try{ _b=JSON.stringify(self.response||''); }catch(e2){} }
            var _needTotp=_b.indexOf('requires_totp')!==-1||_b.indexOf('temp_token')!==-1;
            if(_needTotp){
              console.log('[proxy-patcher] login 200 nhưng cần 2FA -> CHỜ nhập mã, không reload');
            } else {
              console.log('[proxy-patcher] login 200 (no 2FA) -> loginRedirect in 800ms');
              setTimeout(function(){_fireLoginRedirect('login-ok');},800);
            }
          }
        });
      }
      return _xs.apply(this,arguments);
    };
  }catch(e){console.warn('[proxy-patcher] XHR send patch failed',e);}
  // Patch location.assign / location.replace (URL rewriting only)
  try{
    var _la=location.assign.bind(location);
    location.assign=function(u){var r=rw(u);console.log('[proxy-patcher] assign',u,'->',r);return _la(r);};
    var _lr=location.replace.bind(location);
    location.replace=function(u){var r=rw(u);console.log('[proxy-patcher] replace',u,'->',r);return _lr(r);};
  }catch(e){console.warn('[proxy-patcher] location patch failed',e);}
  // Patch location.href setter (URL rewriting only)
  try{
    var _hd=Object.getOwnPropertyDescriptor(Location.prototype,'href');
    if(_hd&&_hd.set){
      Object.defineProperty(Location.prototype,'href',{
        get:_hd.get,
        set:function(u){var r=rw(u);if(r!==u)console.log('[proxy-patcher] href=',u,'->',r);_hd.set.call(this,r);},
        configurable:true
      });
    }
  }catch(e){console.warn('[proxy-patcher] href setter patch failed',e);}
  // Patch history.pushState / replaceState (URL rewriting only)
  try{
    var _hps=history.pushState.bind(history);
    var _hrs=history.replaceState.bind(history);
    history.pushState=function(state,title,url){
      var r=(url!=null)?rw(String(url)):url;
      if(r!==url)console.log('[proxy-patcher] pushState',url,'->',r);
      return _hps(state,title,r);
    };
    history.replaceState=function(state,title,url){
      var r=(url!=null)?rw(String(url)):url;
      if(r!==url)console.log('[proxy-patcher] replaceState',url,'->',r);
      return _hrs(state,title,r);
    };
  }catch(e){console.warn('[proxy-patcher] history patch failed',e);}
  // Global error logger to catch post-load failures
  window.addEventListener('unhandledrejection',function(e){
    console.error('[proxy-patcher] unhandledRejection',e.reason);
  });
  console.log('[proxy-patcher] ready — WS+fetch+XHR+location+history patched');
})();
<\/script>`;
    // Inject at very FIRST position inside <head> so it runs before any other script
    if (/<head(\s[^>]*)?>/i.test(html)) {
      html = html.replace(/<head(\s[^>]*)?>/i, function(m){ return m + patch; });
    } else {
      html = patch + html;
    }
    rh.set('Content-Type', 'text/html; charset=utf-8');
    return new Response(html, { status: upstream.status, headers: rh });
  }

  return new Response(upstream.body, { status: upstream.status, headers: rh });
}

// Rewrite Set-Cookie from Termix backend: remove Domain, set Path to proxy prefix
// KEEP HttpOnly (H2 fix) — JWT is injected server-side for WS auth, not via document.cookie
function _rewriteTermixCookie(sc, base) {
  sc = sc.replace(/;\s*Domain=[^;]*/gi, '');
  // HttpOnly is preserved — prevents XSS from stealing Termix JWT
  if (/;\s*Path=\//i.test(sc)) {
    sc = sc.replace(/;\s*Path=\//i, '; Path=' + base + '/');
  } else if (!/;\s*Path=/i.test(sc)) {
    sc += '; Path=' + base + '/';
  }
  // Iframe embedding: SameSite=Lax KHÔNG được gửi khi reload iframe (sub-frame) bằng script
  // → ép SameSite=None + Secure để cookie session được gửi trong iframe (sau verify 2FA reload)
  if (/;\s*SameSite=/i.test(sc)) {
    sc = sc.replace(/;\s*SameSite=(Lax|Strict|None)/i, '; SameSite=None');
  } else {
    sc += '; SameSite=None';
  }
  if (!/;\s*Secure/i.test(sc)) sc += '; Secure';
  return sc;
}

// Termix Movi — reverse proxy wrapper (CF Access service token + shared secret)
function handleTermixMoviProxy(request, env) {
  return handleTermixProxy(request, env, {
    origin:   cleanEnv(env.TERMIX_MOVI_URL) || 'https://termix-movi.home-server.id.vn',
    base:     '/proxy/termix-movi',
    perm:     'ssh-movi',
    label:    'Termix Movi',
    cfId:     cleanEnv(env.TERMIX_MOVI_CF_CLIENT_ID),
    cfSecret: cleanEnv(env.TERMIX_MOVI_CF_CLIENT_SECRET),
    secret:   cleanEnv(env.TERMIX_MOVI_SECRET),
  });
}

// Termix Home — reverse proxy wrapper (mở top-level tab qua dashboard proxy)
// wsMode='proxy': WS đi QUA worker (worker thêm CF service token) → bật được CF Access cho termix.home
function handleTermixHomeProxy(request, env) {
  return handleTermixProxy(request, env, {
    origin:   cleanEnv(env.TERMIX_HOME_URL) || 'https://termix.home-server.id.vn',
    base:     '/proxy/termix-home',
    perm:     'ssh',
    label:    'Termix Home',
    cfId:     cleanEnv(env.TERMIX_HOME_CF_CLIENT_ID),
    cfSecret: cleanEnv(env.TERMIX_HOME_CF_CLIENT_SECRET),
    secret:   cleanEnv(env.TERMIX_HOME_SECRET),
    wsMode:   'proxy',
  });
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const p   = url.pathname;
    const m   = request.method;
    // Global safety net: API paths always return JSON errors, never HTML
    const isApi = p.startsWith('/api/');
    try {

    // ── SSH Movi verify — fully public, must be FIRST before any session middleware ──
    if (p === '/api/ssh-movi/verify') return handleSshMoviVerify(request, env);

    // ── Auth API (public) ──
    if (p === '/api/auth/login')                   return handleLogin(request, env, ctx);
    if (p === '/api/auth/logout')                  return handleLogout(request, env);
    if (p === '/api/auth/refresh')                 return handleSessionRefresh(request, env);
    if (p === '/api/auth/mfa/verify')              return handleMfaVerify(request, env);

    // ── Microsoft OIDC SSO (public — no session required) ──
    if (p === '/auth/microsoft')          return handleMicrosoftAuth(request, env);
    if (p === '/auth/microsoft/callback') return handleMicrosoftCallback(request, env, ctx);
    if (p === '/auth/microsoft/mfa' && request.method === 'POST') return handleMicrosoftMfaVerify(request, env, ctx);

    // ── First-login setup flow (no session required — use setupToken) ──
    if (p === '/api/auth/setup/change-password')   return handleSetupChangePassword(request, env);
    if (p === '/api/auth/setup/mfa-init')          return handleSetupMfaInit(request, env);
    if (p === '/api/auth/setup/mfa-complete')      return handleSetupMfaComplete(request, env);

    // ── MFA API (require session) ──
    if (p === '/api/auth/mfa/status') return handleMfaStatus(request, env);
    if (p === '/api/auth/mfa/setup')  return handleMfaSetup(request, env);
    if (p === '/api/auth/mfa/enable') return handleMfaEnable(request, env);
    if (p === '/api/auth/mfa/disable')return handleMfaDisable(request, env);

    // ── Admin API ──
    if (p === '/api/admin/users') {
      if (request.method === 'GET')  return handleListUsers(request, env);
      if (request.method === 'POST') return handleCreateUser(request, env);
    }
    const userPerm = p.match(/^\/api\/admin\/users\/([^/]+)\/permissions$/);
    if (userPerm) return handleUpdatePermissions(request, env, decodeURIComponent(userPerm[1]));
    const userManagePerms = p.match(/^\/api\/admin\/users\/([^/]+)\/manage-perms$/);
    if (userManagePerms) return handleSetManagePerms(request, env, decodeURIComponent(userManagePerms[1]));
    const userSysPerms = p.match(/^\/api\/admin\/users\/([^/]+)\/sys-perms$/);
    if (userSysPerms && request.method === 'PUT') return handleSetSysPerms(request, env, decodeURIComponent(userSysPerms[1]));
    const userGrp = p.match(/^\/api\/admin\/users\/([^/]+)\/groups$/);
    if (userGrp) return handleUpdateUserGroups(request, env, decodeURIComponent(userGrp[1]));
    const userPnl = p.match(/^\/api\/admin\/users\/([^/]+)\/panels$/);
    if (userPnl) return handleUpdateUserPanels(request, env, decodeURIComponent(userPnl[1]));
    const userMsLink = p.match(/^\/api\/admin\/users\/([^/]+)\/microsoft-email$/);
    if (userMsLink && request.method === 'PUT') return handleLinkMicrosoftEmail(request, env, decodeURIComponent(userMsLink[1]));
    const userUnlock = p.match(/^\/api\/admin\/users\/([^/]+)\/unlock$/);
    if (userUnlock && request.method === 'POST') return handleUnlockUser(request, env, decodeURIComponent(userUnlock[1]));
    const userResetMfa = p.match(/^\/api\/admin\/users\/([^/]+)\/reset-mfa$/);
    if (userResetMfa && request.method === 'POST') return handleAdminResetMfa(request, env, decodeURIComponent(userResetMfa[1]));
    const userBlock = p.match(/^\/api\/admin\/users\/([^/]+)\/block$/);
    if (userBlock && request.method === 'POST') return handleBlockUser(request, env, decodeURIComponent(userBlock[1]));
    const userLoginTime = p.match(/^\/api\/admin\/users\/([^/]+)\/login-time$/);
    if (userLoginTime && request.method === 'PUT') return handleSaveUserLoginTime(request, env, decodeURIComponent(userLoginTime[1]));
    const userDel  = p.match(/^\/api\/admin\/users\/([^/]+)$/);
    if (userDel) {
      if (request.method === 'DELETE') return handleDeleteUser(request, env, decodeURIComponent(userDel[1]));
      if (request.method === 'PUT')    return handleChangePw(request, env, decodeURIComponent(userDel[1]), ctx);
    }
    if (p === '/api/admin/force-logout-all' && request.method === 'POST') return handleForceLogoutAll(request, env, ctx);
    if (p === '/api/admin/test-email' && request.method === 'POST') return handleTestEmail(request, env);
    if (p === '/api/admin/sessions' && request.method === 'GET') return handleListSessions(request, env);
    const sessKick = p.match(/^\/api\/admin\/sessions\/([a-f0-9]{16})$/);
    if (sessKick && request.method === 'DELETE') return handleKickSession(request, env, sessKick[1]);
    if (p === '/api/admin/backup' && request.method === 'GET') return handleBackup(request, env);
    if (p === '/api/admin/restore' && request.method === 'POST') return handleRestore(request, env);

    // ── Policy Groups API ──
    if (p === '/api/admin/groups') {
      if (request.method === 'GET')  return handleListGroups(request, env);
      if (request.method === 'POST') return handleCreateGroup(request, env);
    }
    const grpMatch = p.match(/^\/api\/admin\/groups\/([^/]+)$/);
    if (grpMatch) {
      if (request.method === 'PUT')    return handleUpdateGroup(request, env, grpMatch[1]);
      if (request.method === 'DELETE') return handleDeleteGroup(request, env, grpMatch[1]);
    }

    // ── User Groups API ──
    if (p === '/api/admin/user-groups') {
      if (request.method === 'GET')  return handleListUserGroups(request, env);
      if (request.method === 'POST') return handleCreateUserGroup(request, env);
    }
    const ugMatch = p.match(/^\/api\/admin\/user-groups\/([^/]+)$/);
    if (ugMatch) {
      const ugid = decodeURIComponent(ugMatch[1]);
      if (request.method === 'PUT')    return handleUpdateUserGroup(request, env, ugid);
      if (request.method === 'DELETE') return handleDeleteUserGroup(request, env, ugid);
    }

    // ── Camera list API ──
    if (p === '/api/admin/cameras') return handleCameraList(request, env);
    if (p === '/api/admin/cameras/movi') return handleMoviCameraList(request, env);

    // ── Policy Groups API alias (settings.html uses /api/policy/groups) ──
    if (p === '/api/policy/groups') {
      if (request.method === 'GET')  return handleListGroups(request, env);
      if (request.method === 'POST') return handleCreateGroup(request, env);
    }
    const polGrpMatch = p.match(/^\/api\/policy\/groups\/([^/]+)$/);
    if (polGrpMatch) {
      if (request.method === 'PUT')    return handleUpdateGroup(request, env, polGrpMatch[1]);
      if (request.method === 'DELETE') return handleDeleteGroup(request, env, polGrpMatch[1]);
    }

    // ── Data API (require valid session) ──
    if (p === '/api/bookmarks') {
      if (request.method === 'GET') return handleGetBookmarks(request, env);
      if (request.method === 'PUT') return handleSaveBookmarks(request, env);
    }
    if (p === '/api/activity') return handleGetActivity(request, env);
    if (p === '/api/audit-log/purge') return handlePurgeAuditLog(request, env);
    if (p === '/api/system-config') {
      if (request.method === 'GET') return handleGetSystemConfig(request, env);
      if (request.method === 'POST') return handleSaveSystemConfig(request, env, ctx);
    }
    if (p === '/api/meraki-clients')       return handleMerakiClients(request, env);
    if (p === '/api/meraki-client-policy')    return handleMerakiClientPolicy(request, env);
    if (p === '/api/meraki-blocked-clients')  return handleMerakiBlockedClients(request, env);
    if (p === '/api/meraki-devices')       return handleMerakiDevices(request, env);
    if (p === '/api/meraki-device-status') return handleMerakiDeviceStatus(request, env);
    if (p === '/api/meraki-events')        return handleMerakiEvents(request, env);
    if (p === '/api/meraki-switch-ports')       return handleMerakiSwitchPorts(request, env);
    if (p === '/api/meraki-port-configs')       return handleMerakiSwitchPortConfigs(request, env);
    if (p === '/api/meraki-link-aggregations')  return handleMerakiLinkAggregations(request, env);
    if (p === '/api/meraki-uplinks')            return handleMerakiUplinks(request, env);
    if (p === '/api/meraki-l3-routing')          return handleMerakiL3Routing(request, env);
    if (p === '/api/movi-sdwan')                return handleMoviSdwan(request, env);
    if (p === '/api/movi-sdwan-rules')          return handleMoviSdwanRules(request, env);
    if (p === '/api/camera-token')               return handleCameraToken(request, env);
    if (p === '/api/admin/camera-aliases-movi' && m === 'GET')  return handleGetCameraAliases(request, env);
    if (p === '/api/admin/camera-aliases-movi' && m === 'PUT')  return handleSaveCameraAlias(request, env);
    if (p.startsWith('/cam-home/'))              return handleCamHomeEmbed(request, env);
    if (p.startsWith('/cam-live/'))              return handleCamLiveEmbed(request, env);
    if (p.startsWith('/cam-embed/'))             return handleCamEmbed(request, env);
    // ── Termix Movi proxy ──
    if (p.startsWith('/proxy/termix-movi'))      return handleTermixMoviProxy(request, env);
    // ── Termix Home proxy (same-origin → OIDC login works in iframe) ──
    if (p.startsWith('/proxy/termix-home'))      return handleTermixHomeProxy(request, env);
    // ── SSH Movi token endpoint ──
    if (p === '/api/ssh-movi/token')  return handleSshMoviToken(request, env);
    // Note: /api/ssh-movi/verify is handled at the top of the router (before session middleware)
    if (p === '/api/movi-interfaces')            return handleMoviInterfaces(request, env);
    if (p === '/api/movi-system')               return handleMoviSystem(request, env);
    if (p === '/api/movi-license')              return handleMoviLicense(request, env);
    if (p === '/api/movi-vpn')                  return handleMoviVpn(request, env);
    if (p === '/api/movi-ssl-vpn')              return handleMoviSslVpn(request, env);
    if (p === '/api/movi-policy')               return handleMoviPolicy(request, env);
    if (p === '/api/movi-dhcp')                 return handleMoviDhcp(request, env);
    if (p === '/api/fortigate-movi/firewall-users') {
      const _s = await getSession(request, env);
      if (!_s) return json({ error: 'Unauthorized' }, 401);
      return handleMoviFirewallUsers(request, env);
    }
    if (p === '/api/fortigate-movi/fortiview-source') {
      const _s = await getSession(request, env);
      if (!_s) return json({ error: 'Unauthorized' }, 401);
      return handleMoviFortiviewSource(request, env);
    }
    if (p === '/api/fortigate-movi/firewall-deauth' && request.method === 'POST') {
      return handleMoviFirewallDeauth(request, env);
    }

    // ── Service endpoints — require session + permission ──
    if (p === '/api/status') {
      const _s = await getSession(request, env);
      if (!_s) return json({ error: 'Unauthorized' }, 401);
      return handleStatus();
    }
    if (p === '/api/n8n') {
      const _s = await getSession(request, env);
      if (!_s) return json({ error: 'Unauthorized' }, 401);
      if (!(await hasPerm(env, _s, 'n8n'))) return json({ error: 'Không có quyền truy cập n8n' }, 403);
      return handleN8n(env);
    }
    if (p === '/api/n8n/exec') {
      const _s = await getSession(request, env);
      if (!_s) return json({ error: 'Unauthorized' }, 401);
      if (!(await hasPerm(env, _s, 'n8n'))) return json({ error: 'Không có quyền truy cập n8n' }, 403);
      return handleExecDetail(request, env);
    }
    if (p === '/api/n8n-movi') {
      const _s = await getSession(request, env);
      if (!_s) return json({ error: 'Unauthorized' }, 401);
      if (!(await hasPerm(env, _s, 'n8n-movi'))) return json({ error: 'Không có quyền truy cập n8n Movi' }, 403);
      return handleMoviN8n(env);
    }
    if (p === '/api/n8n-movi/exec') {
      const _s = await getSession(request, env);
      if (!_s) return json({ error: 'Unauthorized' }, 401);
      if (!(await hasPerm(env, _s, 'n8n-movi'))) return json({ error: 'Không có quyền truy cập n8n Movi' }, 403);
      return handleMoviN8nExecDetail(request, env);
    }
    if (p === '/api/tool-movi/create-user') {
      const _s = await getSession(request, env);
      if (!_s) return json({ error: 'Unauthorized' }, 401);
      if (!(await hasPerm(env, _s, 'tool-movi-create-user'))) return json({ error: 'Không có quyền sử dụng Tạo User Movi' }, 403);
      return handleToolMoviCreateUser(request, env, _s, ctx);
    }
    if (p === '/api/tool-movi/block-user') {
      const _s = await getSession(request, env);
      if (!_s) return json({ error: 'Unauthorized' }, 401);
      if (!(await hasPerm(env, _s, 'tool-movi-block-user'))) return json({ error: 'Không có quyền sử dụng Block User Movi' }, 403);
      return handleToolMoviBlockUser(request, env, _s);
    }
    if (p === '/api/tool-movi/asset-search') {
      const _s = await getSession(request, env);
      if (!_s) return json({ error: 'Unauthorized' }, 401);
      if (!(await hasPerm(env, _s, 'tool-movi-asset-search'))) return json({ error: 'Không có quyền sử dụng Tra Cứu Tài Sản' }, 403);
      return handleToolMoviAssetSearch(request, env, _s);
    }
    if (p === '/api/tool-movi/check-email') {
      const _s = await getSession(request, env);
      if (!_s) return json({ error: 'Unauthorized' }, 401);
      if (!(await hasPerm(env, _s, 'tool-movi-check-email'))) return json({ error: 'Không có quyền sử dụng Kiểm Tra Email Azure' }, 403);
      return handleToolMoviCheckEmail(request, env, _s);
    }
    if (p === '/api/tool-movi/check-azure-group') {
      const _s = await getSession(request, env);
      if (!_s) return json({ error: 'Unauthorized' }, 401);
      if (!(await hasPerm(env, _s, 'tool-movi-azure-group'))) return json({ error: 'Không có quyền sử dụng Tra Cứu Group Azure' }, 403);
      return handleToolMoviCheckAzureGroup(request, env, _s);
    }
    if (p === '/api/tool-movi/fg-policy-lan') {
      const _s = await getSession(request, env);
      if (!_s) return json({ error: 'Unauthorized' }, 401);
      if (!(await hasPerm(env, _s, 'tool-movi-fg-policy-lan'))) return json({ error: 'Không có quyền tạo Policy LAN' }, 403);
      return handleToolMoviFgPolicy(request, env, _s, 'lan', ctx);
    }
    if (p === '/api/tool-movi/fg-policy-wifi') {
      const _s = await getSession(request, env);
      if (!_s) return json({ error: 'Unauthorized' }, 401);
      if (!(await hasPerm(env, _s, 'tool-movi-fg-policy-wifi'))) return json({ error: 'Không có quyền tạo Policy WiFi' }, 403);
      return handleToolMoviFgPolicy(request, env, _s, 'wifi', ctx);
    }
    if (p === '/api/tool-movi/fg-policies') {
      const _s = await getSession(request, env);
      if (!_s) return json({ error: 'Unauthorized' }, 401);
      if (!(await hasPerm(env, _s, 'tool-movi-fg-policy-lan')) && !(await hasPerm(env, _s, 'tool-movi-fg-policy-wifi')))
        return json({ error: 'Không có quyền' }, 403);
      return handleListFgPolicies(request, env, _s);
    }
    if (p === '/api/tool-movi/fg-policy-done') {
      // n8n callback — no session required, verified by Basic auth
      return handleFgPolicyDone(request, env);
    }
    if (p === '/api/tool-movi/delete-user') {
      const _s = await getSession(request, env);
      if (!_s) return json({ error: 'Unauthorized' }, 401);
      if (!(await hasPerm(env, _s, 'tool-movi-delete-user'))) return json({ error: 'Không có quyền sử dụng Xóa User Movi' }, 403);
      return handleToolMoviDeleteUserList(request, env, _s);
    }
    if (p === '/api/tool-movi/delete-user-action') {
      const _s = await getSession(request, env);
      if (!_s) return json({ error: 'Unauthorized' }, 401);
      if (!(await hasPerm(env, _s, 'tool-movi-delete-user'))) return json({ error: 'Không có quyền sử dụng Xóa User Movi' }, 403);
      return handleToolMoviDeleteUserAction(request, env, _s);
    }
    if (p === '/api/tool-movi/history') {
      if (request.method === 'GET')    return handleGetToolMoviHistory(request, env);
      if (request.method === 'POST')   return handleSaveToolMoviHistory(request, env);
      if (request.method === 'DELETE') return handleClearToolMoviHistory(request, env);
    }

    if (p === '/api/vmware01-movi') {
      const _s = await getSession(request, env);
      if (!_s) return json({ error: 'Unauthorized' }, 401);
      if (!(await hasPerm(env, _s, 'vmware01-movi'))) return json({ error: 'Không có quyền truy cập VMware01 Movi' }, 403);
      return handleMoviVmwareData(env, '1');
    }
    if (p === '/api/vmware02-movi') {
      const _s = await getSession(request, env);
      if (!_s) return json({ error: 'Unauthorized' }, 401);
      if (!(await hasPerm(env, _s, 'vmware02-movi'))) return json({ error: 'Không có quyền truy cập VMware02 Movi' }, 403);
      return handleMoviVmwareData(env, '2');
    }
    if (p === '/api/vmware01-movi/power') {
      const _s = await getSession(request, env);
      if (!_s) return json({ error: 'Unauthorized' }, 401);
      if (!(await isAdminUser(env, _s))) return json({ error: 'Admin required để thực hiện power action VMware01 Movi' }, 403);
      return handleMoviVmwarePower(request, env, '1');
    }
    if (p === '/api/vmware02-movi/power') {
      const _s = await getSession(request, env);
      if (!_s) return json({ error: 'Unauthorized' }, 401);
      if (!(await isAdminUser(env, _s))) return json({ error: 'Admin required để thực hiện power action VMware02 Movi' }, 403);
      return handleMoviVmwarePower(request, env, '2');
    }
    if (p === '/api/9router') {
      const _s = await getSession(request, env);
      if (!_s) return json({ error: 'Unauthorized' }, 401);
      if (!(await hasPerm(env, _s, '9router'))) return json({ error: 'Không có quyền truy cập 9Router' }, 403);
      return handle9Router(request, env);
    }
    if (p === '/api/casaos') {
      const _s = await getSession(request, env);
      if (!_s) return json({ error: 'Unauthorized' }, 401);
      if (!(await hasPerm(env, _s, 'casaos'))) return json({ error: 'Không có quyền truy cập CasaOS' }, 403);
      return handleCasaOS(env);
    }
    if (p === '/api/rustdesk') {
      const _s = await getSession(request, env);
      if (!_s) return json({ error: 'Unauthorized' }, 401);
      if (!(await hasPerm(env, _s, 'rustdesk'))) return json({ error: 'Không có quyền truy cập RustDesk' }, 403);
      return handleRustdesk(env);
    }
    if (p === '/api/fortigate') {
      const _s = await getSession(request, env);
      if (!_s) return json({ error: 'Unauthorized' }, 401);
      if (!(await hasPerm(env, _s, 'fortigate'))) return json({ error: 'Không có quyền truy cập FortiGate' }, 403);
      return handleFortigateWebhook(env);
    }
    if (p === '/api/fortigate-bw') {
      const _s = await getSession(request, env);
      if (!_s) return json({ error: 'Unauthorized' }, 401);
      if (!(await hasPerm(env, _s, 'fortigate'))) return json({ error: 'Không có quyền truy cập FortiGate' }, 403);
      return handleFortigateBW(env);
    }
    if (p === '/api/fortigate-reboot') {
      const _s = await getSession(request, env);
      if (!_s) return json({ error: 'Unauthorized' }, 401);
      if (!(await isAdminUser(env, _s))) return json({ error: 'Admin required' }, 403);
      return handleFortigateReboot(env);
    }
    if (p === '/api/asus') {
      const _s = await getSession(request, env);
      if (!_s) return json({ error: 'Unauthorized' }, 401);
      if (!(await hasPerm(env, _s, 'asus'))) return json({ error: 'Không có quyền truy cập ASUS Router' }, 403);
      return handleAsusWebhook(env);
    }
    if (p === '/api/asus/bw') {
      const _s = await getSession(request, env);
      if (!_s) return json({ error: 'Unauthorized' }, 401);
      if (!(await hasPerm(env, _s, 'asus'))) return json({ error: 'Không có quyền truy cập ASUS Router' }, 403);
      return handleAsusBw(env);
    }
    if (p === '/api/asus/reboot') {
      const _s = await getSession(request, env);
      if (!_s) return json({ error: 'Unauthorized' }, 401);
      if (!(await isAdminUser(env, _s))) return json({ error: 'Admin required' }, 403);
      return handleAsusReboot(request, env);
    }
    if (p === '/api/vmware-home') {
      const _s = await getSession(request, env);
      if (!_s) return json({ error: 'Unauthorized' }, 401);
      if (!(await hasPerm(env, _s, 'esxi'))) return json({ error: 'Không có quyền truy cập VMware Home' }, 403);
      return handleVmwareHome(env);
    }
    if (p === '/api/vmware-home/power') {
      const _s = await getSession(request, env);
      if (!_s) return json({ error: 'Unauthorized' }, 401);
      if (!(await isAdminUser(env, _s))) return json({ error: 'Admin required' }, 403);
      return handleVmwareHomePower(request, env);
    }
    if (p === '/proxy')           return handleProxy(request, env);

    // ── HTML pages: inject user or redirect to login ──
    if (p === '/' || p.endsWith('.html')) return injectUser(request, env);

    return env.ASSETS.fetch(request);
    } catch (e) {
      if (isApi) return json({ error: 'Internal server error', detail: e.message }, 500);
      return new Response('Internal Server Error', { status: 500 });
    }
  },
};
