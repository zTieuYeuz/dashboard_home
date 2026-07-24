import {
  ALL_SERVICES,
  DEFAULT_CAMERAS,
  DEFAULT_CAMERAS_MOVI,
  MOVI_N8N_BASE,
  N8N_BASE,
  SESSION_COOKIE,
  _constEq,
  _effCache,
  _getCfg,
  _invalidateCfgCache,
  _invalidateEffCache,
  _invalidateSessionCache,
  _sessionCache,
  _sha256Hex,
  checkIpWhitelist,
  cleanEnv,
  computeEffectivePermissions,
  ensureAdmin,
  getSession,
  getSessionDelegateServices,
  getSessionToken,
  hasPerm,
  hashPw,
  isAdminUser,
  json,
  logActivity,
  notifyEmail,
  rlBump,
  rlClear,
  rlGet,
  sanitizeCameraIds,
  sanitizeName,
  sanitizePanels,
  sanitizePermissions,
  sanitizeSysPerms,
  verifyPw
} from './src/core.js';
import {
  handleClearToolMoviHistory,
  handleFgPolicyDone,
  handleGetToolMoviHistory,
  handleListFgPolicies,
  handleSaveToolMoviHistory,
  handleToolMoviAssetSearch,
  handleToolMoviBlockUser,
  handleToolMoviCheckAzureGroup,
  handleToolMoviCheckEmail,
  handleToolMoviCreateUser,
  handleToolMoviDeleteUserAction,
  handleToolMoviDeleteUserList,
  handleToolMoviFgPolicy
} from './src/tool-movi.js';
import {
  handleMerakiBlockedClients,
  handleMerakiClientPolicy,
  handleMerakiClients,
  handleMerakiDeviceStatus,
  handleMerakiDevices,
  handleMerakiEvents,
  handleMerakiL3Routing,
  handleMerakiLinkAggregations,
  handleMerakiSwitchPortConfigs,
  handleMerakiSwitchPorts,
  handleMerakiUplinks,
  handleMoviSdwan,
  handleMoviSdwanRules
} from './src/meraki.js';
import {
  handleMoviDhcp,
  handleMoviFirewallDeauth,
  handleMoviFirewallUsers,
  handleMoviFortiviewSource,
  handleMoviInterfaces,
  handleMoviLicense,
  handleMoviPolicy,
  handleMoviSslVpn,
  handleMoviSystem,
  handleMoviVpn
} from './src/movi-fortigate.js';
import {
  handleAsusBw,
  handleAsusClients,
  handleAsusReboot,
  handleAsusWebhook,
  handleCasaOS,
  handleFortigateBW,
  handleFortigateReboot,
  handleFortigateWebhook,
  handleMoviVmwareData,
  handleMoviVmwarePower,
  handleRustdesk,
  handleVmwareHome,
  handleVmwareHomePower
} from './src/home-services.js';
import {
  handleFgtPoolAllocate,
  handleFgtPoolOpen,
  handleFgtPoolRelease,
  handleOpenclawApp,
  handleOpenclawToken,
  handleProxy
} from './src/proxy.js';
import {
  handleSshMoviToken,
  handleSshMoviVerify,
  handleTermixHomeProxy,
  handleTermixMoviProxy
} from './src/termix.js';
import {
  handleMcp,
  handleAdminAiConfig,
  handleAdminMcp,
  handleAiAction,
  handleAiGuide,
  handleAiKnowledge,
} from './src/ai/mcp.js';
import {
  handleAiExec,
  handleAiActionsList,
} from './src/ai/actions.js';
import {
  handleAiRead,
  handleAiReadsList,
} from './src/ai/reads.js';
import {
  handleAiFormsList,
  handleAdminAiForms,
} from './src/ai/movi.js';
import {
  handleCameraList,
  handleCameraRename,
  handleCamTestLiveEmbed,
  handleCamTestApiEmbed,
  handleCpaiEmbed,
} from './src/camera-home.js';
import { runDailySelfReview } from './src/ai/review.js';
import { handlePnetLlm, handlePnetConsole } from './src/pnetlab.js';

/* ═══════════════════════════════════════════════
   Auth & User Management System
   ═══════════════════════════════════════════════ */

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


async function handleLogin(request, env, ctx) {
  if (request.method !== 'POST') return json({ error: 'POST required' }, 405);
  await ensureAdmin(env);
  let body; try { body = await request.json(); } catch { return json({ error: 'Invalid JSON' }, 400); }
  const { password } = body || {};
  // Username is case-insensitive — always normalize to lowercase (mobile keyboards
  // auto-capitalize the first letter, which would otherwise break login).
  const username = (body && body.username ? String(body.username) : '').toLowerCase().trim();
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

  const sessionTtl = Math.max(1, (user.sessionTtlHours || cfg.sessionTtlHours || 8)) * 3600;

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
  // Re-read role from KV so role changes take effect without full re-login
  const refreshUser = await env.DASHBOARD_KV.get(`user:${session.username}`, 'json');
  const freshRole = (refreshUser && refreshUser.role) || session.role;
  const refreshTtl = Math.max(1, ((refreshUser && refreshUser.sessionTtlHours) || refreshCfg.sessionTtlHours || 8)) * 3600;
  const newExpires = Date.now() + refreshTtl * 1000;
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

async function handleAuthMe(request, env) {
  const session = await getSession(request, env);
  if (!session) return json({ error: 'No session' }, 401);
  // Use computeEffectivePermissions so policy-group permissions (Role Manager) are included,
  // not just the direct user.permissions stored in the session at login time.
  const eff = await computeEffectivePermissions(env, session.username);
  return json({
    username: session.username,
    role: eff ? eff.role : session.role,
    permissions: eff ? eff.permissions : (session.permissions || {}),
  });
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
      sessionTtlHours:  d.sessionTtlHours || 0,
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

  // Return filtered list: basic info + only the managed service permissions.
  // Dùng EFFECTIVE permissions (gộp cả quyền user nhận từ policy group) — nếu chỉ đọc
  // d.permissions trực tiếp thì user lấy quyền qua nhóm sẽ hiện "none" (bug: không thấy quyền thật).
  const users = [];
  for (const u of list) {
    if (u === session.username) continue; // skip self
    const d = await env.DASHBOARD_KV.get(`user:${u}`, 'json');
    if (!d) continue;
    const eff = await computeEffectivePermissions(env, u);
    const effPerms = (eff && eff.permissions) || d.permissions || {};
    const filteredPerms = {};
    for (const svc of canManage) filteredPerms[svc] = effPerms[svc] || 'none';
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
      createdBy:   d.createdBy || null,   // để frontend hiện nút Xóa cho user do CHÍNH delegate tạo
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
    const { password } = body || {};
    // Usernames are always stored lowercase so login is case-insensitive.
    const username = (body && body.username ? String(body.username) : '').toLowerCase().trim();
    if (!username || !password) return json({ error: 'Thiếu username hoặc password' }, 400);
    if (!/^[a-z0-9_.@-]{3,64}$/.test(username)) return json({ error: 'Username không hợp lệ (3-64 ký tự, a-z 0-9 . @ _ -)' }, 400);
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
    const requireMfa = body?.requireMfa !== false; // mặc định true, false chỉ khi truyền rõ requireMfa:false
    await env.DASHBOARD_KV.put(`user:${username}`, JSON.stringify({
      password: hashed, role, groups, userGroups: [], permissions: {}, panels: {}, cameras: [], created: Date.now(),
      createdBy: session.username, // ai tạo user này → delegate chỉ được xóa/sửa user do MÌNH tạo
      mustChangePassword: true,   // Force password change on first login
      mustSetupMfa: requireMfa,   // Admin có thể tắt MFA khi tạo viewer accounts
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
  if (!session) return json({ error: 'Unauthorized' }, 401);
  if (username === 'admin') return json({ error: 'Không thể xoá admin' }, 400);
  const isAdmin = await isAdminUser(env, session);
  if (!isAdmin) {
    // Delegate: phải có quyền tạo user (sysPerms.addUser) VÀ chỉ xóa được user do CHÍNH MÌNH tạo.
    const callerRaw = await env.DASHBOARD_KV.get(`user:${session.username}`, 'json');
    if (!callerRaw?.sysPerms?.addUser) return json({ error: 'Admin required' }, 403);
    const target = await env.DASHBOARD_KV.get(`user:${username}`, 'json');
    if (!target) return json({ error: 'User not found' }, 404);
    if (target.createdBy !== session.username) return json({ error: 'Bạn chỉ xóa được user do chính mình tạo' }, 403);
  }
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

async function handleSaveUserSessionTtl(request, env, username) {
  const session = await getSession(request, env);
  if (!session || !(await isAdminUser(env, session))) return json({ error: 'Admin required' }, 403);
  let body; try { body = await request.json(); } catch { return json({ error: 'Invalid JSON' }, 400); }
  const user = await env.DASHBOARD_KV.get(`user:${username}`, 'json');
  if (!user) return json({ error: 'User not found' }, 404);
  const hours = Number(body.sessionTtlHours);
  if (isNaN(hours) || hours < 0) return json({ error: 'Giá trị không hợp lệ' }, 400);
  if (hours === 0) {
    delete user.sessionTtlHours; // 0 = dùng global default
  } else {
    user.sessionTtlHours = Math.min(Math.floor(hours), 720); // tối đa 30 ngày
  }
  await env.DASHBOARD_KV.put(`user:${username}`, JSON.stringify(user));
  await logActivity(env, { action: 'user-update-session-ttl', username: session.username,
    ip: request.headers.get('CF-Connecting-IP') || '?', success: true,
    detail: `Session TTL = ${hours || 'global'} for: ${username}` });
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


async function handleListGroups(request, env) {
  const session = await getSession(request, env);
  if (!session) return json({ error: 'Unauthorized' }, 401);
  // Allow admin, delegated managers, or users with sysPerms.addUser (read-only for group assignment during user creation)
  const isAdmin = await isAdminUser(env, session);
  if (!isAdmin) {
    const callerRaw = await env.DASHBOARD_KV.get(`user:${session.username}`, 'json');
    const delegateSvcs = await getSessionDelegateServices(env, session);
    if (!delegateSvcs.length && !callerRaw?.sysPerms?.addUser) return json({ error: 'Admin required' }, 403);
  }
  const ids = await env.DASHBOARD_KV.get('policy_groups', 'json') || [];
  const groups = [];
  for (const id of ids) {
    const g = await env.DASHBOARD_KV.get(`policy_group:${id}`, 'json');
    // Delegate/non-admin CHỈ thấy nhóm quyền do chính mình tạo — không thấy nhóm của admin/người khác.
    if (g && (isAdmin || g.createdBy === session.username)) groups.push(g);
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
  // Delegate chỉ được sửa nhóm quyền do CHÍNH MÌNH tạo (chống sửa nhóm của admin).
  if (!isAdmin && group.createdBy !== session.username) return json({ error: 'Bạn chỉ sửa được nhóm quyền do mình tạo' }, 403);
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
  if (!session) return json({ error: 'Unauthorized' }, 401);
  const isAdmin = await isAdminUser(env, session);
  if (!isAdmin) {
    const delegateSvcs = await getSessionDelegateServices(env, session);
    if (!delegateSvcs.length) return json({ error: 'Admin required' }, 403);
    // Delegate chỉ xóa được Role Group do CHÍNH MÌNH tạo (đồ của admin → chỉ view).
    const grp = await env.DASHBOARD_KV.get(`policy_group:${groupId}`, 'json');
    if (!grp) return json({ error: 'Group not found' }, 404);
    if (grp.createdBy !== session.username) return json({ error: 'Bạn chỉ xóa được Role Group do mình tạo' }, 403);
  }
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
  const isAdmin = await isAdminUser(env, session);
  if (!isAdmin) {
    const callerRaw = await env.DASHBOARD_KV.get(`user:${session.username}`, 'json');
    const delegateSvcs = await getSessionDelegateServices(env, session);
    if (!delegateSvcs.length && !callerRaw?.sysPerms?.addUser) return json({ error: 'Admin required' }, 403);
  }
  const ids = await env.DASHBOARD_KV.get('user_groups', 'json') || [];
  const groups = [];
  for (const id of ids) {
    const g = await env.DASHBOARD_KV.get(`user_group:${id}`, 'json');
    // Delegate/non-admin CHỈ thấy User Group do chính mình tạo.
    if (g && (isAdmin || g.createdBy === session.username)) groups.push(g);
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
    createdBy: session.username,
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
  const isAdmin = await isAdminUser(env, session);
  if (!isAdmin) {
    const delegateSvcs = await getSessionDelegateServices(env, session);
    if (!delegateSvcs.length) return json({ error: 'Admin required' }, 403);
  }
  const group = await env.DASHBOARD_KV.get(`user_group:${groupId}`, 'json');
  if (!group) return json({ error: 'User Group not found' }, 404);
  // Delegate chỉ được sửa User Group do chính mình tạo.
  if (!isAdmin && group.createdBy !== session.username) return json({ error: 'Bạn chỉ sửa được User Group do mình tạo' }, 403);
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
  if (!session) return json({ error: 'Unauthorized' }, 401);
  const isAdmin = await isAdminUser(env, session);
  if (!isAdmin) {
    const delegateSvcs = await getSessionDelegateServices(env, session);
    if (!delegateSvcs.length) return json({ error: 'Admin required' }, 403);
  }
  const group = await env.DASHBOARD_KV.get(`user_group:${groupId}`, 'json');
  if (!group) return json({ error: 'User Group not found' }, 404);
  // Delegate chỉ xóa được User Group do CHÍNH MÌNH tạo (đồ của admin → chỉ view).
  if (!isAdmin && group.createdBy !== session.username) return json({ error: 'Bạn chỉ xóa được User Group do mình tạo' }, 403);
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

/* ── Translate proxy (VI→EN) for AI semantic search ──
   Frigate's jinav1 embedding model only understands English, so Vietnamese
   queries are translated first. Uses Google's keyless gtx endpoint (fixed
   host → no SSRF). Session-gated. Falls back to the original text on error. */
async function handleTranslate(request, env) {
  const session = await getSession(request, env);
  if (!session) return json({ error: 'Unauthorized' }, 401);
  const u  = new URL(request.url);
  const q  = (u.searchParams.get('q') || '').slice(0, 500);
  const tl = (u.searchParams.get('tl') || 'en').replace(/[^a-zA-Z-]/g, '') || 'en';
  let   sl = (u.searchParams.get('sl') || 'vi').replace(/[^a-zA-Z-]/g, '') || 'vi';
  if (sl === 'auto') sl = 'vi';
  if (!q.trim()) return json({ text: '', src: q });

  // 0) KV cache — avoids re-hitting rate-limited free APIs for repeat queries
  const cacheKey = `xlate:${sl}:${tl}:${q.toLowerCase().trim()}`;
  try {
    const cached = await env.DASHBOARD_KV.get(cacheKey);
    if (cached) return json({ text: cached, src: q, via: 'cache' });
  } catch (_) { /* ignore */ }
  const _store = async (t) => { try { await env.DASHBOARD_KV.put(cacheKey, t, { expirationTtl: 2592000 }); } catch (_) {} };

  // 1) MyMemory — keyless translation API, reliable from Worker egress IPs
  try {
    const mm = `https://api.mymemory.translated.net/get?q=${encodeURIComponent(q)}&langpair=${encodeURIComponent(sl + '|' + tl)}`;
    const r = await fetch(mm, { headers: { 'User-Agent': 'Mozilla/5.0' }, signal: AbortSignal.timeout(8000) });
    if (r.ok) {
      const d = await r.json();
      const t = d && d.responseData && d.responseData.translatedText;
      if (t && typeof t === 'string') { await _store(t); return json({ text: t, src: q, via: 'mymemory' }); }
    }
  } catch (_) { /* fall through */ }

  // 2) Google gtx fallback
  try {
    const g = `https://translate.googleapis.com/translate_a/single?client=gtx&sl=${sl}&tl=${tl}&dt=t&q=${encodeURIComponent(q)}`;
    const r = await fetch(g, { headers: { 'User-Agent': 'Mozilla/5.0' }, signal: AbortSignal.timeout(8000) });
    if (r.ok) {
      const data = await r.json();
      const text = (Array.isArray(data) && Array.isArray(data[0]))
        ? data[0].map(seg => (seg && seg[0]) || '').join('')
        : '';
      if (text) { await _store(text); return json({ text, src: q, via: 'google' }); }
    }
  } catch (_) { /* fall through */ }

  return json({ text: q, src: q, fallback: true });
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
  const mfaSessionTtl = Math.max(1, (user.sessionTtlHours || mfaCfg.sessionTtlHours || 8)) * 3600;
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

  const sessionTtl    = Math.max(1, (matchedUser.sessionTtlHours || cfg.sessionTtlHours || 8)) * 3600;
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
  const sessionTtl = Math.max(1, (user.sessionTtlHours || cfg.sessionTtlHours || 8)) * 3600;
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
  const sessionTtl = Math.max(1, (user.sessionTtlHours || cfg.sessionTtlHours || 8)) * 3600;
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

/* Shared dark/light theme toggle — injected into EVERY authenticated page so the
   control is consistent everywhere. Hides any per-page #themeToggle (topbars vary
   between pages) and shows one uniform floating button instead. Theme is stored in
   localStorage 'dh_theme' and applied early (in <head>) to avoid flash. */
const THEME_TOGGLE = `<style>
#themeToggle{display:none!important}
#__themeFab{position:fixed;left:16px;bottom:16px;z-index:2147483000;width:34px;height:34px;border-radius:50%;
 border:1px solid rgba(255,255,255,.18);background:rgba(20,20,30,.72);color:#fff;font-size:16px;cursor:pointer;
 display:grid;place-items:center;-webkit-backdrop-filter:blur(6px);backdrop-filter:blur(6px);box-shadow:0 4px 16px rgba(0,0,0,.4);transition:all .15s;padding:0;line-height:1}
#__themeFab:hover{border-color:#8fb3ff;box-shadow:0 6px 20px rgba(30,60,130,.5)}
html[data-theme=light] #__themeFab{background:rgba(255,255,255,.88);color:#1a1a1a;border-color:rgba(0,0,0,.15)}
@media(max-width:768px){#__themeFab{width:40px;height:40px;font-size:18px}}
</style>
<button id="__themeFab" type="button" title="Chế độ Sáng / Tối" aria-label="Chuyển Sáng/Tối"></button>
<script>(function(){
 if(window.__themeFabInit)return;window.__themeFabInit=1;
 function cur(){return document.documentElement.dataset.theme==='light'?'light':'dark';}
 function icon(){return cur()==='light'?'🌙':'☀️';}
 var b=document.getElementById('__themeFab');
 function paint(){if(b)b.textContent=icon();}
 function toggle(){var n=cur()==='light'?'dark':'light';document.documentElement.dataset.theme=n;try{localStorage.setItem('dh_theme',n);}catch(e){}paint();}
 if(b)b.addEventListener('click',toggle);
 paint();
})();<\/script>`;

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
  {i:'\\u26A1',n:'n8n Automation',d:'Workflow & bot automation',h:'/service-home/n8n.html',p:'n8n'},
  {i:'\\uD83D\\uDCF7',n:'Camera',d:'Hệ thống camera · Frigate NVR',h:'/service-home/camera-home.html',p:'camera'},
  {i:'\\uD83D\\uDDA7',n:'SSH Terminal',d:'Web SSH · Termix',h:'/service-home/ssh.html',p:'ssh'},
  {i:'\\uD83D\\uDDA5',n:'RustDesk',d:'Remote desktop · máy nhân viên',h:'/service-home/rustdesk.html',p:'rustdesk'},
  {i:'\\uD83D\\uDDA7',n:'Termix Movi',d:'SSH Movi · token auth',h:'/service-movi/ssh-movi.html',p:'ssh-movi'},
  {i:'\\uD83C\\uDFE0',n:'ALL Service Home',d:'Chrome Pool · FortiGate · ESXi · NAS · n8n · Frigate…',h:'/service-home/services-embed.html',p:null},
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
   var _ic=document.createElement('span');_ic.className='wf-ic';_ic.textContent=s.i;
   var _nm=document.createElement('div');_nm.className='wf-nm';_nm.textContent=s.n;
   var _ds=document.createElement('div');_ds.className='wf-ds';_ds.textContent=s.d;
   var _sp=document.createElement('span');_sp.appendChild(_nm);_sp.appendChild(_ds);
   var _tg=document.createElement('span');_tg.className='wf-tag';_tg.textContent=cur?'● đang ở đây':'mở →';
   a.appendChild(_ic);a.appendChild(_sp);a.appendChild(_tg);
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
  '/service-home/asus.html':['load'],'/service-home/n8n.html':['loadData'],
  '/service-home/camera-home.html':[],'/service-home/ssh.html':['loadData'],
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
  // mobile.css + PWA meta: cho phép mở từ "Add to Home Screen" ở chế độ standalone
  // (toàn màn hình, KHÔNG có thanh địa chỉ Safari). Thiếu các thẻ này thì iOS mở
  // shortcut như một tab Safari bình thường (có thanh URL + toolbar dưới).
  const head = '<link rel="stylesheet" href="/mobile.css">'
    + '<meta name="apple-mobile-web-app-capable" content="yes">'
    + '<meta name="mobile-web-app-capable" content="yes">'
    + '<meta name="apple-mobile-web-app-status-bar-style" content="black">'
    // Apply saved theme ASAP (before first paint) so there is no light/dark flash.
    + '<script>try{var _t=localStorage.getItem("dh_theme");if(_t==="light"||_t==="dark")document.documentElement.dataset.theme=_t;}catch(e){}</' + 'script>';
  html = /<\/head>/i.test(html)
    ? html.replace(/<\/head>/i, head + '\n</head>')
    : head + html;
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

  // ── App Camera: auto-redirect to camera page on dashboard root ──
  // Users granted the 'app_camera' permission land directly on the camera home
  // page instead of the main dashboard. Server-side so it works regardless of
  // which login path was used (password, MFA, Microsoft SSO).
  if (!isAdmin && (url.pathname === '/' || url.pathname === '/index.html')) {
    if ((effPerms.permissions['app_camera'] || 'none') !== 'none') {
      return Response.redirect(new URL('/service-home/camera-home.html', request.url).toString(), 302);
    }
  }

  // ── Server-side page permission gate ──
  // Admins bypass all checks. Non-admin users are redirected to home
  // if they try to access a page they don't have permission for.
  if (!isAdmin) {
    // ── Admin-only pages: non-admin KHÔNG bao giờ được vào (kể cả gõ thẳng URL) ──
    // Thêm trang admin mới vào đây để tự động chặn server-side (nav chỉ ẩn link là chưa đủ).
    const _ADMIN_ONLY_PAGES = new Set(['/noc.html']);
    if (_ADMIN_ONLY_PAGES.has(url.pathname)) {
      return Response.redirect(new URL('/', request.url).toString(), 302);
    }
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
      '/service-home/n8n.html': 'n8n',
      '/service-home/camera-home.html': ['camera','camera_playback','camera_download','app_camera','camera_autoopen'],
      '/service-home/ssh.html': 'ssh',
      '/service-home/rustdesk.html': 'rustdesk',
      '/service-home/services-embed.html': 'services-hub',
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
  // Nhắc bật MFA cho MỌI user chưa bật (cả local lẫn Microsoft) — trước đây chỉ
  // nhắc user Microsoft nên user local tạo với "không yêu cầu MFA" không thấy nhắc.
  if(!u||u.mfaEnabled)return;
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
    var txt=document.createTextNode('Bật xác thực 2 bước (MFA) để bảo mật tài khoản của bạn. ');
    var lnk=document.createElement('a');
    lnk.href='/settings.html#setup-mfa';
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
  const bodyEnd = WAYFIND_NAV + THEME_TOGGLE + DATA_REFRESH + PANEL_REFRESH
    + '<script src="/service-home/_shared/chat.js" defer></script>';
  newHtml = /<\/body>/i.test(newHtml)
    ? newHtml.replace(/<\/body>/i, bodyEnd + '\n</body>')
    : newHtml + bodyEnd;
  return new Response(newHtml, {
    status: res.status,
    headers: {
      'content-type': 'text/html; charset=utf-8',
      'cache-control': 'no-store, no-cache',
      'X-Content-Type-Options': 'nosniff',
      // SAMEORIGIN (not DENY) so the Services Hub can embed dashboard pages (FortiGate, VMware,
      // CasaOS…) in same-origin iframes. External/cross-origin framing stays blocked → clickjacking
      // protection preserved. (frame-ancestors 'self' below enforces the same in modern browsers.)
      'X-Frame-Options': 'SAMEORIGIN',
      'Referrer-Policy': 'strict-origin-when-cross-origin',
      // [M1] HSTS: force HTTPS for 1 year, including subdomains
      'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
      // [M2] Permissions-Policy: deny browser features not used by this app.
      // Exception: trang Services Hub nhúng Kasm (docker Ubuntu) cần webcam+mic → chỉ trang đó
      // cho phép camera/microphone (giới hạn theo origin Kasm). KHÔNG đụng sandbox/referrer của iframe
      // (những thứ đó làm hư CF Access session — xem services_embed_hub memory 2026-06-29).
      'Permissions-Policy': (url.pathname === '/service-home/services-embed.html'
        ? 'camera=(self "https://kasm-service.home-server.id.vn"), microphone=(self "https://kasm-service.home-server.id.vn")'
        : 'camera=(), microphone=()') + ', geolocation=(), payment=(), usb=(), interest-cohort=()',
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
        "frame-src 'self' https://*.home-server.id.vn https://cam.movi-finance.com https://termix.movi-finance.com https://login.microsoftonline.com; " +
        "object-src 'none'; base-uri 'self'; frame-ancestors 'self'",
    }
  });
}

/* ═══════════════════════════════════════════════ */

const SERVICES = [
  { id: 'esxi',        name: 'VMware ESXi',    checkUrl: 'https://esxi.home-server.id.vn' },
  { id: 'n8n',         name: 'n8n Automation', checkUrl: 'https://n8n-home.home-server.id.vn' },
  { id: 'casaos',      name: 'CasaOS',         checkUrl: 'https://casaos.home-server.id.vn' },
  { id: 'ssh',         name: 'SSH Terminal',   checkUrl: 'https://termix.home-server.id.vn' },
  { id: 'fortigate',   name: 'FortiGate',      checkUrl: null },
  { id: 'asus',        name: 'ASUS Router',    checkUrl: null },
  { id: 'camera',      name: 'Camera',         checkUrl: 'https://camera.home-server.id.vn' },
  { id: 'rustdesk',    name: 'RustDesk',       checkUrl: 'https://rustdesk.home-server.id.vn' },
];


/* ── Services Hub internal site tree (server-authoritative) ──
   perm: permission key mỗi site cần; admin bypass tất cả.
   API /api/services-embed-config trả về chỉ sites user có quyền (bỏ trường perm). */
const SERVICES_EMBED_TREE = [
  { folder:'Network', icon:'🌐', sites:[
    { name:'FortiGate',   icon:'🛡️', url:'https://192.168.110.1/',        perm:'hub-fortigate' },
    { name:'Router Asus', icon:'📡', url:'https://192.168.10.1:8443/',    perm:'hub-asus' },
    { name:'Router Acer', icon:'📶', url:'http://192.168.110.100/',       perm:'hub-asus' },
  ]},
  { folder:'Server', icon:'🖥️', sites:[
    { name:'VMware ESXi', icon:'💾', url:'https://192.168.110.125/',      perm:'hub-esxi' },
    { name:'NAS',         icon:'🗄️', url:'https://192.168.110.126:5001/', perm:'hub-nas' },
    { name:'CasaOS',      icon:'🏠', url:'http://192.168.110.21:4434/',   perm:'hub-casaos' },
    { name:'Kasm',        icon:'🖥️', url:'https://kasm-service.home-server.id.vn/', embedUrl:'https://kasm-service.home-server.id.vn/?fps=24&quality=6&compression=9', cfAccess:true, perm:'hub-kasm' },
  ]},
  { folder:'Automation', icon:'⚡', sites:[
    { name:'n8n', icon:'⚡', url:'https://n8n-home.home-server.id.vn/', embedUrl:'/n8n-proxy/home', perm:'hub-n8n' },
  ]},
  { folder:'Lab', icon:'🧪', sites:[
    // Nhúng iframe qua tunnel. PNETLab KHÔNG gửi X-Frame-Options và không có code framebust
    // (comment cũ ghi "framebust" là từ hồi còn chế độ ONLINE — authen.pnetlab.com mới là thứ đá ra).
    // ⚠ app.js của PNETLab đã phải vá lỗi statusText (chết dưới HTTP/2 của Cloudflare) — xem memory
    //   pnetlab_cloudflare_http2. Update PNETLab sẽ ghi đè bản vá → trắng trang trở lại.
    { name:'Pnetlab-network', icon:'🧪', url:'https://pnetlab.home-server.id.vn/',
      embedUrl:'https://pnetlab.home-server.id.vn/store/public/admin/main/view', perm:'hub-pnetlab' },
  ]},
  { folder:'Monitor', icon:'📊', sites:[
    { name:'Frigate NVR', icon:'📷', url:'http://192.168.110.5:5000/', perm:'hub-frigate' },
    { name:'Camera NVR',  icon:'📹', url:'http://192.168.130.3:8088/',  perm:'hub-camera-nvr' },
  ]},
];

async function handleServicesEmbedConfig(env, session) {
  const eff = await computeEffectivePermissions(env, session.username);
  const isAdmin = !!(eff && (eff.role === 'admin' || session.role === 'admin'));
  const userPerms = (eff && eff.permissions) || {};
  const tree = SERVICES_EMBED_TREE.map(function(folder) {
    const sites = folder.sites
      .filter(function(s) { return isAdmin || (userPerms[s.perm] || 'none') !== 'none'; })
      .map(function(s) {
        const out = { name: s.name, icon: s.icon, url: s.url };
        if (s.embedUrl) out.embedUrl = s.embedUrl;
        if (s.cfAccess) out.cfAccess = true;   // site sau Cloudflare Access → cần vòng xác thực trước khi nhúng
        return out;
      });
    return { folder: folder.folder, icon: folder.icon, sites: sites };
  }).filter(function(f) { return f.sites.length > 0; });
  return json({ tree: tree });
}

/* ── Movi n8n webhook basic-auth (credentials from Cloudflare secrets) ──
   Set via:  wrangler secret put MOVI_N8N_USER  /  MOVI_N8N_PASS
   Never hardcode credentials in source. */
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



/* ── Meraki Devices Proxy ── */
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

/* ── n8n Home — Reverse Proxy (HTTP + WebSocket) ── */
// Proxies https://n8n-home.home-server.id.vn through /n8n-proxy/* so that n8n auth
// cookies are first-party on the dashboard origin (bypasses third-party cookie block in iframe).
async function handleN8nHomeProxy(request, env) {
  const session = await getSession(request, env);
  if (!session) return new Response('Unauthorized', { status: 401 });
  if (!(await hasPerm(env, session, 'n8n'))) return new Response('Forbidden', { status: 403 });

  const N8N_ORIGIN = 'https://n8n-home.home-server.id.vn';
  const reqUrl  = new URL(request.url);

  // Defense for double-prefix URLs (n8n folder cards build /n8n-proxy/n8n-proxy/...). For a real
  // navigation (middle-click, bookmark) redirect the browser to the collapsed single-prefix URL so
  // the SPA router sees a valid route. (Normal left-clicks are fixed client-side before this.)
  if (/^\/n8n-proxy(?:\/n8n-proxy)+/.test(reqUrl.pathname)) {
    const fixed = reqUrl.pathname.replace(/^(?:\/n8n-proxy)+/, '/n8n-proxy');
    return Response.redirect(`${reqUrl.origin}${fixed}${reqUrl.search}`, 302);
  }

  const subPath = reqUrl.pathname.replace(/^(?:\/n8n-proxy)+/, '') || '/';
  const target  = `${N8N_ORIGIN}${subPath}${reqUrl.search}`;

  // ── WebSocket proxy (n8n push notifications) ──
  if (request.headers.get('Upgrade')?.toLowerCase() === 'websocket') {
    let upstreamResp;
    try {
      upstreamResp = await fetch(target, { headers: { 'Upgrade': 'websocket' } });
    } catch(e) {
      return new Response('n8n WS upstream error: ' + e.message, { status: 502 });
    }
    const upstream = upstreamResp.webSocket;
    if (!upstream) return new Response('n8n WS upstream failed (status ' + upstreamResp.status + ')', { status: 502 });
    const { 0: client, 1: server } = new WebSocketPair();
    server.accept();
    server.addEventListener('message',   ({ data }) => { try { upstream.send(data); } catch(_) {} });
    upstream.addEventListener('message', ({ data }) => { try { server.send(data);   } catch(_) {} });
    server.addEventListener('close',   ({ code, reason }) => { try { upstream.close(code, reason); } catch(_) {} });
    upstream.addEventListener('close', ({ code, reason }) => { try { server.close(code, reason);   } catch(_) {} });
    return new Response(null, { status: 101, webSocket: client });
  }

  // ── HTTP proxy ──
  // Forward request headers, but override Host so upstream knows who it is
  const fwdHeaders = {};
  for (const [k, v] of request.headers) {
    const kl = k.toLowerCase();
    if (['host','cf-connecting-ip','x-forwarded-for','cookie'].includes(kl)) continue;
    fwdHeaders[k] = v;
  }
  fwdHeaders['Host'] = 'n8n-home.home-server.id.vn';
  // Lọc cookie phiên dashboard (dh_session/dh_user) — n8n KHÔNG cần và KHÔNG được nhận token này
  // (giống cách proxy Termix làm). Tránh rò token nếu n8n bị xâm nhập hoặc log header.
  // Vẫn giữ các cookie riêng của n8n (n8n-auth…) để n8n hoạt động bình thường.
  const _n8nRawCookie = request.headers.get('cookie') || '';
  const _n8nCleanCookie = _n8nRawCookie.split(';').map(c => c.trim())
    .filter(c => c && !c.startsWith('dh_session=') && !c.startsWith('dh_user='))
    .join('; ');
  if (_n8nCleanCookie) fwdHeaders['Cookie'] = _n8nCleanCookie;

  let upstream;
  try {
    upstream = await fetch(target, {
      method:   request.method,
      headers:  fwdHeaders,
      redirect: 'manual',
      ...(request.method !== 'GET' && request.method !== 'HEAD' ? { body: request.body } : {}),
    });
  } catch(e) {
    return new Response('n8n proxy error: ' + e.message, { status: 502 });
  }

  // Build response headers — strip framing restrictions, rewrite cookies & redirects
  const rh = new Headers();
  for (const [k, v] of upstream.headers) {
    const kl = k.toLowerCase();
    // Strip headers that block iframe embedding
    if (kl === 'x-frame-options') continue;
    if (kl === 'content-security-policy') continue;
    // CF Workers decode gzip — don't forward encoding/length claims
    if (kl === 'content-encoding') continue;
    if (kl === 'content-length') continue;
    // Cache-control / ETag handled below — we force no-store
    if (kl === 'cache-control' || kl === 'etag' || kl === 'last-modified') continue;
    // Set-Cookie handled separately below
    if (kl === 'set-cookie') continue;
    rh.set(k, v);
  }
  // Asset Vite có content-hash trong tên (/assets/xxx-HASH.js) → bất biến. Cho browser cache
  // lâu để n8n KHÔNG phải tải + rewrite lại bundle lớn mỗi lần mở (nhanh hơn nhiều lần sau).
  // Còn lại (HTML, REST, push…) giữ no-store để rewrite/auth luôn đúng.
  const _immutableAsset = /\/assets\//.test(subPath)
    && /\.(js|css|woff2?|ttf|otf|png|jpe?g|svg|gif|webp|ico|map)$/i.test(subPath);
  rh.set('Cache-Control', _immutableAsset
    ? 'private, max-age=31536000, immutable'
    : 'no-store, no-cache, must-revalidate');

  // Rewrite Set-Cookie: strip Domain so cookie lands on dashboard origin
  const rawCookies = upstream.headers.getAll ? upstream.headers.getAll('set-cookie') : [];
  for (const c of rawCookies) {
    const rewritten = c
      .replace(/;\s*Domain=[^;,]*/gi, '')
      .replace(/;\s*SameSite=\w+/gi, '; SameSite=Lax');
    rh.append('Set-Cookie', rewritten);
  }

  // Rewrite Location for redirects so browser follows through proxy
  const loc = upstream.headers.get('Location');
  if (loc) rh.set('Location', loc.replace(N8N_ORIGIN, '/n8n-proxy'));

  const ct = upstream.headers.get('Content-Type') || '';

  // ── JS response: rewrite absolute /assets/ & /static/ paths inside JS bundles ──
  // n8n's SPA uses dynamic import('/assets/en-xxx.js') for locale files — these absolute paths
  // bypass the HTML attribute rewriting and hit the dashboard origin → 404.
  if (ct.includes('javascript')) {
    let js = await upstream.text();
    js = js.replace(/(['"`])\/assets\//g, '$1/n8n-proxy/assets/');
    js = js.replace(/(['"`])\/static\//g,  '$1/n8n-proxy/static/');
    // ── base-path.js: set Vue Router base to /n8n-proxy/ (native n8n sub-path hosting) ──
    // n8n's base-path.js is `window.BASE_PATH="/"`. Rewriting it to "/n8n-proxy/" makes the
    // Vue Router (createWebHistory(BASE_PATH)) strip the proxy prefix natively → no 404,
    // and n8n builds REST/push/asset URLs under /n8n-proxy/ on its own.
    js = js.replace(/(window\.BASE_PATH\s*=\s*)["']\/["']/, '$1"/n8n-proxy/"');
    rh.set('Content-Type', ct);
    return new Response(js, { status: upstream.status, headers: rh });
  }

  if (!ct.includes('text/html')) {
    return new Response(upstream.body, { status: upstream.status, headers: rh });
  }

  // ── HTML response: rewrite absolute paths + fix n8n API endpoint config ──
  let html = await upstream.text();

  // With window.BASE_PATH="/n8n-proxy/" (set in base-path.js), Vue Router natively handles the
  // proxy prefix — so no Location/history/pathname patching is needed. This shim only:
  //  • rewrites any absolute n8n-origin (or stray root /rest) URLs back through the proxy
  //  • collapses double-prefix links (folder cards) and keeps target="_blank" links in-frame
  //  • hides the brief boot flash and nudges a resize once loaded
  const interceptScript = `<script>
(function(){
var B='/n8n-proxy';
var N8N='https://n8n-home.home-server.id.vn';

/* fetch/XHR: route absolute n8n origin (and any stray root /rest|/push|/webhook) through proxy. */
/* n8n already emits /n8n-proxy/rest itself now (starts with B → returned unchanged).            */
function _rw(u){
  if(typeof u!=='string')return u;
  if(u.startsWith(B))return u;
  if(u.startsWith('/rest')||u.startsWith('/push')||u.startsWith('/webhook'))return B+u;
  if(u.startsWith(N8N+'/'))return B+u.slice(N8N.length);
  if(u===N8N)return B+'/';
  return u;
}
var _F=window.fetch;
window.fetch=function(u,o){return _F.call(this,_rw(u),o);};
var _X=XMLHttpRequest.prototype.open;
XMLHttpRequest.prototype.open=function(m,u){return _X.apply(this,[m,_rw(u)].concat([].slice.call(arguments,2)));};

/* Click fixer (capture phase, runs before vue-router's handler). Handles two n8n quirks         */
/* that appear only when n8n runs under a sub-path:                                              */
/*  A) Folder cards render <a href="/n8n-proxy/n8n-proxy/...">  (n8n prepends BASE_PATH to an     */
/*     already-based path). Router strips one prefix → still /n8n-proxy/... → 404. Collapse the   */
/*     repeated prefix and hard-navigate the (correct) URL in-frame.                              */
/*  B) Execution/workflow links use target="_blank" → opens a jarring new tab in the embed.       */
/*     Strip target so vue-router navigates in-place inside the iframe instead.                   */
document.addEventListener('click',function(e){
  var a=e.target&&e.target.closest?e.target.closest('a[href]'):null;
  if(!a)return;
  var href=a.getAttribute('href')||'';
  if(href.indexOf(B)!==0)return;                 /* only our internal proxy links */
  var plainClick=e.button===0&&!e.metaKey&&!e.ctrlKey&&!e.shiftKey&&!e.altKey;
  if(href.indexOf(B+B+'/')>-1){                  /* A: double prefix → fix + in-frame nav */
    if(!plainClick)return;                        /* let ctrl/middle-click fall through (server redirects) */
    e.preventDefault();e.stopImmediatePropagation();
    window.location.assign(href.replace(/^(\\/n8n-proxy)+/,'/n8n-proxy'));
    return;
  }
  var tg=(a.getAttribute('target')||'').toLowerCase();
  if(tg.indexOf('_blank')>-1&&plainClick){       /* B: keep it in-frame → let router take over */
    a.removeAttribute('target');
  }
},true);

/* Hide brief boot flash, reveal once loaded; nudge resize so any list re-measures its height */
document.documentElement.style.opacity='0';
var _shown=false;
function _show(){
  if(_shown)return;_shown=true;
  document.documentElement.style.opacity='';
  function _rsz(){try{window.dispatchEvent(new Event('resize'));}catch(_e){}}
  setTimeout(_rsz,100);setTimeout(_rsz,500);setTimeout(_rsz,1200);
}
window.addEventListener('load',function(){setTimeout(_show,150);});
setTimeout(_show,6000);

})();
</script>`;
  html = html.replace('<head>', '<head>' + interceptScript);

  // Rewrite absolute src/href in HTML attributes so assets load via proxy
  html = html.replace(/(\s(?:src|href|action)=["'])(\/(?!n8n-proxy\/)[^"']*)(["'])/gi,
    (_, attr, path, q) => `${attr}/n8n-proxy${path}${q}`
  );

  // NOTE: rest-endpoint meta stays plain "rest" (cmVzdA==). With window.BASE_PATH="/n8n-proxy/"
  // (set in base-path.js above), n8n builds restUrl = BASE_PATH + "rest" = /n8n-proxy/rest itself.
  // Rewriting the meta too would double-prefix it (/n8n-proxy/n8n-proxy/rest) → 404.

  // ── Fix collapsed app height ──
  // Through the proxy, n8n's #app ends up with no full-height rule → it sizes to content (~337px),
  // which collapses the inner CSS-grid `1fr` rows to 0 → the workflow list (50 cards ARE in the DOM)
  // gets clipped to height 0 and shows blank. Force the canonical full-viewport height on #app.
  html = html.replace('</head>',
    '<style id="n8n-proxy-fix">html,body{height:100%;margin:0}#app{height:100vh}</style></head>');

  rh.set('Content-Type', ct);
  return new Response(html, { status: upstream.status, headers: rh });
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
    enforceIpBinding:     cfg.enforceIpBinding ?? false,
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
  if (body.enforceIpBinding !== undefined)      cfg.enforceIpBinding      = !!body.enforceIpBinding;
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
   CasaOS — REST API (v0.4.x)
   Auth: POST /v1/users/login → token (raw, no "Bearer" prefix!)
   ═══════════════════════════════════════════════ */
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

    // ── PNETLab AI proxy → 9Router: PUBLIC (gọi từ browser PNETLab, không có cookie dashboard).
    //    Tự bảo vệ bằng Origin allowlist + rate-limit trong handlePnetLlm. ──
    if (p === '/api/pnet-llm') return handlePnetLlm(request, env);
    if (p === '/api/pnet-console') return handlePnetConsole(request, env);

    // ── MCP server for external agents (OpenClaw) — token-authed, no session ──
    if (p === '/mcp') return handleMcp(request, env);
    // ── AI action bridge (Phase 1): audit (session) + knowledge guide (token/admin) ──
    if (p === '/api/ai/action' && m === 'POST') return handleAiAction(request, env);
    if (p === '/api/ai/guide') return handleAiGuide(request, env);
    if (p === '/api/ai/knowledge') return handleAiKnowledge(request, env);
    if (p === '/api/ai/actions' && m === 'GET') return handleAiActionsList(request, env);
    if (p === '/api/ai/exec' && m === 'POST') return handleAiExec(request, env);
    if (p === '/api/ai/reads' && m === 'GET') return handleAiReadsList(request, env);
    if (p === '/api/ai/read' && m === 'POST') return handleAiRead(request, env);
    if (p === '/api/ai/forms' && m === 'GET') return handleAiFormsList(request, env);

    // ── Auth API (public) ──
    if (p === '/api/auth/login')                   return handleLogin(request, env, ctx);
    if (p === '/api/auth/logout')                  return handleLogout(request, env);
    if (p === '/api/auth/refresh')                 return handleSessionRefresh(request, env);
    if (p === '/api/auth/me')                      return handleAuthMe(request, env);
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
    // ── AI / MCP admin (admin only) ──
    if (p === '/api/admin/ai-config' || p === '/api/admin/ai-forms' || p.startsWith('/api/admin/mcp')) {
      const _mcpSess = await getSession(request, env);
      if (!(await isAdminUser(env, _mcpSess))) return json({ error: 'Admin required' }, 403);
      if (p === '/api/admin/ai-config') return handleAdminAiConfig(request, env);
      if (p === '/api/admin/ai-forms') return handleAdminAiForms(request, env);
      return handleAdminMcp(request, env);
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
    const userSessionTtl = p.match(/^\/api\/admin\/users\/([^/]+)\/session-ttl$/);
    if (userSessionTtl && request.method === 'PUT') return handleSaveUserSessionTtl(request, env, decodeURIComponent(userSessionTtl[1]));
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
    const camRename = p.match(/^\/api\/admin\/cameras\/([^/]+)\/rename$/);
    if (camRename && request.method === 'PATCH') return handleCameraRename(request, env, decodeURIComponent(camRename[1]));

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
    if (p.startsWith('/cpai/'))                  return handleCpaiEmbed(request, env);
    if (p.startsWith('/n8n-proxy'))               return handleN8nHomeProxy(request, env);
    if (p === '/oc' || p.startsWith('/oc/'))     return handleOpenclawApp(request, env);
    if (p === '/api/openclaw-token')             return handleOpenclawToken(request, env);
    if (p === '/api/translate')                  return handleTranslate(request, env);
    if (p === '/api/fgt-pool/allocate')          return handleFgtPoolAllocate(request, env);
    if (p === '/api/fgt-pool/open')              return handleFgtPoolOpen(request, env);
    if (p === '/api/fgt-pool/release')           return handleFgtPoolRelease(request, env);
    if (p.startsWith('/cam-test-live/'))         return handleCamTestLiveEmbed(request, env);
    if (p.startsWith('/cam-test-api/'))          return handleCamTestApiEmbed(request, env);
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
    if (p === '/api/services-embed-config') {
      const _s = await getSession(request, env);
      if (!_s) return json({ error: 'Unauthorized' }, 401);
      if (!(await hasPerm(env, _s, 'services-hub'))) return json({ error: 'Không có quyền truy cập Services Hub' }, 403);
      return handleServicesEmbedConfig(env, _s);
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
    if (p === '/api/asus/clients') {
      const _s = await getSession(request, env);
      if (!_s) return json({ error: 'Unauthorized' }, 401);
      if (!(await hasPerm(env, _s, 'asus'))) return json({ error: 'Không có quyền truy cập ASUS Router' }, 403);
      return handleAsusClients(env);
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

    // ── n8n asset fallback: dynamic import('/assets/...') from n8n iframe bypasses JS rewriting ──
    // These requests arrive without /n8n-proxy/ prefix; catch them here and proxy to n8n.
    if (p.startsWith('/assets/') || p.startsWith('/static/') || p.startsWith('/icons/') || p.startsWith('/fonts/') || p.startsWith('/rest/') || p.startsWith('/push/') || p.startsWith('/webhook/') || p.startsWith('/types/') || p === '/healthz' || p.startsWith('/templates/')) {
      const assetRes = await env.ASSETS.fetch(request);
      if (assetRes.status === 404) {
        const _s = await getSession(request, env);
        if (_s && await hasPerm(env, _s, 'n8n')) return handleN8nHomeProxy(request, env);
      }
      return assetRes;
    }

    {
      const assetRes = await env.ASSETS.fetch(request);
      // Static assets (JS/CSS/SVG/font/ảnh) — cho browser cache 5 phút + dùng bản cũ
      // trong lúc revalidate: bớt hẳn round-trip mỗi lần chuyển trang, nhưng deploy
      // bản mới vẫn tới user trong ≤5 phút. HTML KHÔNG qua nhánh này (đã injectUser + no-store).
      if (assetRes.ok && /\.(js|css|svg|png|jpg|jpeg|webp|ico|woff2?)$/i.test(p)) {
        const r = new Response(assetRes.body, assetRes);
        r.headers.set('Cache-Control', 'public, max-age=300, stale-while-revalidate=600');
        return r;
      }
      return assetRes;
    }
    } catch (e) {
      if (isApi) return json({ error: 'Internal server error', detail: e.message }, 500);
      return new Response('Internal Server Error', { status: 500 });
    }
  },

  // ── Cron: tự rà soát hệ thống hằng ngày (Mechanism B) ──
  // Lịch chạy khai trong wrangler.toml [triggers] crons (06:00 giờ VN = 23:00 UTC).
  async scheduled(event, env, ctx) {
    ctx.waitUntil(
      runDailySelfReview(env).catch(e => console.error('daily self-review failed:', e && e.message))
    );
  },
};
