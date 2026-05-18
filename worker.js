/* ═══════════════════════════════════════════════
   Auth & User Management System
   ═══════════════════════════════════════════════ */
const SESSION_COOKIE    = 'dh_session';
const SESSION_TTL       = 60 * 60 * 24 * 7; // 7 days
const ALL_SERVICES      = ['esxi','n8n','casaos','9router','fortigate','asus','ssh','uptime-kuma'];
const IDLE_TIMEOUT_MS   = 8 * 60 * 60 * 1000;  // auto-logout after 8h inactivity
const IDLE_WARN_MS      = (8 * 60 - 5) * 60 * 1000; // show warning 5 min before logout

/* Idle-timer script injected into every authenticated HTML page */
const IDLE_SCRIPT = `<script>(function(){
  var T=${IDLE_TIMEOUT_MS},W=${IDLE_WARN_MS},last=Date.now(),bn=null,tk=null;

  /* Reset timer on any user interaction */
  window._idleReset = function() {
    last = Date.now();
    if (bn) { bn.style.display = 'none'; clearInterval(tk); tk = null; }
  };
  ['mousemove','mousedown','keydown','scroll','touchstart','click','pointerdown'].forEach(function(e) {
    document.addEventListener(e, window._idleReset, { passive: true, capture: true });
  });
  /* Reset timer when user switches back to this tab + refresh session */
  document.addEventListener('visibilitychange', function() {
    if (!document.hidden) { window._idleReset(); _refreshSession(); }
  });
  /* Refresh session on page load and every 30 min of activity */
  function _refreshSession() { fetch('/api/auth/refresh', { method: 'POST' }).catch(function(){}); }
  _refreshSession();
  setInterval(function() { if (Date.now() - last < 30 * 60 * 1000) _refreshSession(); }, 30 * 60 * 1000);

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

/* ── Password hashing ──
   New format (string): "pbkdf2$<iter>$<saltHex>$<hashHex>"
   Legacy format: bare 64-hex SHA-256(pw + ':dh-salt-2024'). Verified for
   backward-compat, then transparently re-hashed to PBKDF2 on next login. */
const PW_PBKDF2_ITER = 210000;

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
  const session = await env.DASHBOARD_KV.get(`session:${token}`, 'json');
  if (!session || Date.now() > session.expires) {
    if (session) await env.DASHBOARD_KV.delete(`session:${token}`).catch(() => {});
    return null;
  }
  return { ...session, token };
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

async function handleLogin(request, env) {
  if (request.method !== 'POST') return json({ error: 'POST required' }, 405);
  await ensureAdmin(env);
  let body; try { body = await request.json(); } catch { return json({ error: 'Invalid JSON' }, 400); }
  const { username, password } = body || {};
  if (!username || !password) return json({ error: 'Thiếu username hoặc password' }, 400);
  const ip = request.headers.get('cf-connecting-ip') || request.headers.get('x-forwarded-for') || 'unknown';

  // Rate limit: per-IP (20 / 15min) and per-IP+user (8 / 15min)
  const WIN = 900;
  if ((await rlGet(env, `ip:${ip}`)) >= 20 || (await rlGet(env, `u:${ip}:${username}`)) >= 8) {
    await logActivity(env, { action: 'login_blocked', username, ip, success: false, detail: 'Rate limited' });
    return json({ error: 'Quá nhiều lần thử. Vui lòng chờ ~15 phút rồi thử lại.' }, 429);
  }

  const user = await env.DASHBOARD_KV.get(`user:${username}`, 'json');
  if (!user || !(await verifyPw(password, user.password))) {
    await rlBump(env, `ip:${ip}`, WIN);
    await rlBump(env, `u:${ip}:${username}`, WIN);
    await logActivity(env, { action: 'login_fail', username, ip, success: false, detail: 'Wrong credentials' });
    return json({ error: 'Sai tên đăng nhập hoặc mật khẩu' }, 401);
  }
  // Transparently migrate legacy SHA-256 hashes to PBKDF2 on successful login
  if (!String(user.password || '').startsWith('pbkdf2$')) {
    try { user.password = await hashPw(password);
      await env.DASHBOARD_KV.put(`user:${username}`, JSON.stringify(user)); } catch {}
  }
  await rlClear(env, `ip:${ip}`);
  await rlClear(env, `u:${ip}:${username}`);

  // If MFA is enabled for this user, don't create session yet — return temp token
  if (user.mfaEnabled && user.mfaSecret) {
    const tempToken = crypto.randomUUID();
    await env.DASHBOARD_KV.put(`mfa_temp:${tempToken}`, JSON.stringify({
      username, expires: Date.now() + 300_000 // 5 minutes
    }), { expirationTtl: 300 });
    await logActivity(env, { action: 'login_mfa', username, ip, success: true, detail: 'MFA required' });
    return json({ mfaRequired: true, tempToken });
  }

  const token = crypto.randomUUID();
  await env.DASHBOARD_KV.put(`session:${token}`, JSON.stringify({
    username, role: user.role, permissions: user.permissions || {},
    expires: Date.now() + SESSION_TTL * 1000
  }), { expirationTtl: SESSION_TTL });

  // Set both: HttpOnly session cookie + readable user-info cookie for client JS
  const userInfo = encodeURIComponent(JSON.stringify({
    username, role: user.role,
    permissions: user.permissions || {},
    isAdmin: user.role === 'admin'
  }));
  const h = new Headers({ 'Content-Type': 'application/json' });
  h.append('Set-Cookie', `${SESSION_COOKIE}=${token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${SESSION_TTL}`);
  h.append('Set-Cookie', `dh_user=${userInfo}; Secure; SameSite=Lax; Path=/; Max-Age=${SESSION_TTL}`);
  await logActivity(env, { action: 'login_success', username, ip, success: true });
  return new Response(JSON.stringify({ success: true, role: user.role }), { status: 200, headers: h });
}

async function handleSessionRefresh(request, env) {
  const session = await getSession(request, env);
  if (!session) return json({ error: 'No session' }, 401);
  const token = session.token;
  const newExpires = Date.now() + SESSION_TTL * 1000;
  await env.DASHBOARD_KV.put(`session:${token}`, JSON.stringify({
    username: session.username, role: session.role,
    permissions: session.permissions || {},
    expires: newExpires,
  }), { expirationTtl: SESSION_TTL });
  const h = new Headers({ 'Content-Type': 'application/json' });
  h.append('Set-Cookie', `${SESSION_COOKIE}=${token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${SESSION_TTL}`);
  return new Response(JSON.stringify({ ok: true }), { status: 200, headers: h });
}

async function handleLogout(request, env) {
  const session = await getSession(request, env);
  const logUser = session?.username || 'unknown';
  const ip = request.headers.get('cf-connecting-ip') || request.headers.get('x-forwarded-for') || 'unknown';
  const token = getSessionToken(request);
  if (token) await env.DASHBOARD_KV.delete(`session:${token}`).catch(() => {});
  await logActivity(env, { action: 'logout', username: logUser, ip, success: true });
  const h = new Headers({ 'Content-Type': 'application/json' });
  h.append('Set-Cookie', `${SESSION_COOKIE}=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0`);
  h.append('Set-Cookie', `dh_user=; Secure; SameSite=Lax; Path=/; Max-Age=0`);
  return new Response(JSON.stringify({ success: true }), { status: 200, headers: h });
}

async function handleListUsers(request, env) {
  const session = await getSession(request, env);
  if (!session || session.role !== 'admin') return json({ error: 'Admin required' }, 403);
  const list = await env.DASHBOARD_KV.get('userlist', 'json') || ['admin'];
  const users = [];
  for (const u of list) {
    const d = await env.DASHBOARD_KV.get(`user:${u}`, 'json');
    if (d) users.push({
      username: u, role: d.role,
      permissions: d.permissions || {},
      panels: d.panels || {},
      cameras: d.cameras || [],
      groups: d.groups || []
    });
  }
  return json({ users });
}

async function handleCreateUser(request, env) {
  const session = await getSession(request, env);
  if (!session || session.role !== 'admin') return json({ error: 'Admin required' }, 403);
  if (request.method !== 'POST') return json({ error: 'POST required' }, 405);
  let body; try { body = await request.json(); } catch { return json({ error: 'Invalid JSON' }, 400); }
  const { username, password } = body || {};
  if (!username || !password) return json({ error: 'Thiếu username hoặc password' }, 400);
  if (!/^[a-zA-Z0-9_-]{3,32}$/.test(username)) return json({ error: 'Username không hợp lệ (3-32 ký tự, a-z 0-9 _ -)' }, 400);
  if (await env.DASHBOARD_KV.get(`user:${username}`)) return json({ error: 'User đã tồn tại' }, 409);
  await env.DASHBOARD_KV.put(`user:${username}`, JSON.stringify({
    password: await hashPw(password), role: 'user', permissions: {}, created: Date.now()
  }));
  const list = await env.DASHBOARD_KV.get('userlist', 'json') || ['admin'];
  if (!list.includes(username)) { list.push(username); await env.DASHBOARD_KV.put('userlist', JSON.stringify(list)); }
  return json({ success: true, username });
}

async function handleUpdatePermissions(request, env, username) {
  const session = await getSession(request, env);
  if (!session || session.role !== 'admin') return json({ error: 'Admin required' }, 403);
  if (username === 'admin') return json({ error: 'Không thể sửa quyền admin' }, 400);
  let body; try { body = await request.json(); } catch { return json({ error: 'Invalid JSON' }, 400); }
  const user = await env.DASHBOARD_KV.get(`user:${username}`, 'json');
  if (!user) return json({ error: 'User not found' }, 404);
  user.permissions = body.permissions || {};
  await env.DASHBOARD_KV.put(`user:${username}`, JSON.stringify(user));
  return json({ success: true, username, permissions: user.permissions });
}

async function handleDeleteUser(request, env, username) {
  const session = await getSession(request, env);
  if (!session || session.role !== 'admin') return json({ error: 'Admin required' }, 403);
  if (username === 'admin') return json({ error: 'Không thể xoá admin' }, 400);
  await env.DASHBOARD_KV.delete(`user:${username}`);
  const list = (await env.DASHBOARD_KV.get('userlist', 'json') || []).filter(u => u !== username);
  await env.DASHBOARD_KV.put('userlist', JSON.stringify(list));
  return json({ success: true });
}

async function handleChangePw(request, env, username) {
  const session = await getSession(request, env);
  if (!session) return json({ error: 'Not authenticated' }, 401);
  if (session.role !== 'admin' && session.username !== username) return json({ error: 'Forbidden' }, 403);
  let body; try { body = await request.json(); } catch { return json({ error: 'Invalid JSON' }, 400); }
  if (!body?.password || body.password.length < 4) return json({ error: 'Password quá ngắn (tối thiểu 4 ký tự)' }, 400);
  const user = await env.DASHBOARD_KV.get(`user:${username}`, 'json');
  if (!user) return json({ error: 'User not found' }, 404);
  user.password = await hashPw(body.password);
  await env.DASHBOARD_KV.put(`user:${username}`, JSON.stringify(user));
  return json({ success: true });
}

/* ═══════════════════════════════════════════════
   Policy Groups & Granular Permissions
   ═══════════════════════════════════════════════ */

async function computeEffectivePermissions(env, username) {
  const user = await env.DASHBOARD_KV.get(`user:${username}`, 'json');
  if (!user) return null;
  const eff = {
    permissions: { ...(user.permissions || {}) },
    panels: { ...(user.panels || {}) },
    cameras: [...(user.cameras || [])],
    groups: [...(user.groups || [])]
  };
  for (const gid of eff.groups) {
    const g = await env.DASHBOARD_KV.get(`policy_group:${gid}`, 'json');
    if (!g) continue;
    for (const [k, v] of Object.entries(g.permissions || {})) {
      const cur = eff.permissions[k];
      if (!cur || cur === 'none') eff.permissions[k] = v;
      else if (cur === 'read' && v === 'write') eff.permissions[k] = 'write';
    }
    for (const [k, v] of Object.entries(g.panels || {})) { if (v) eff.panels[k] = true; }
    for (const c of (g.cameras || [])) { if (!eff.cameras.includes(c)) eff.cameras.push(c); }
  }
  return eff;
}

async function handleListGroups(request, env) {
  const session = await getSession(request, env);
  if (!session || session.role !== 'admin') return json({ error: 'Admin required' }, 403);
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
  if (!session || session.role !== 'admin') return json({ error: 'Admin required' }, 403);
  if (request.method !== 'POST') return json({ error: 'POST required' }, 405);
  let body; try { body = await request.json(); } catch { return json({ error: 'Invalid JSON' }, 400); }
  const name = String(body?.name || '').trim();
  if (!name || name.length > 64) return json({ error: 'Tên group không hợp lệ' }, 400);
  const id = name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '') || ('g-' + Date.now());
  if (await env.DASHBOARD_KV.get(`policy_group:${id}`)) return json({ error: 'Group đã tồn tại' }, 409);
  const group = {
    id, name,
    description: String(body?.description || ''),
    permissions: body?.permissions || {},
    panels: body?.panels || {},
    cameras: body?.cameras || [],
    created: Date.now()
  };
  await env.DASHBOARD_KV.put(`policy_group:${id}`, JSON.stringify(group));
  const ids = await env.DASHBOARD_KV.get('policy_groups', 'json') || [];
  if (!ids.includes(id)) { ids.push(id); await env.DASHBOARD_KV.put('policy_groups', JSON.stringify(ids)); }
  return json({ success: true, group });
}

async function handleUpdateGroup(request, env, groupId) {
  const session = await getSession(request, env);
  if (!session || session.role !== 'admin') return json({ error: 'Admin required' }, 403);
  const group = await env.DASHBOARD_KV.get(`policy_group:${groupId}`, 'json');
  if (!group) return json({ error: 'Group not found' }, 404);
  let body; try { body = await request.json(); } catch { return json({ error: 'Invalid JSON' }, 400); }
  if (body.name !== undefined) group.name = String(body.name).trim();
  if (body.description !== undefined) group.description = String(body.description);
  if (body.permissions !== undefined) group.permissions = body.permissions;
  if (body.panels !== undefined) group.panels = body.panels;
  if (body.cameras !== undefined) group.cameras = body.cameras;
  await env.DASHBOARD_KV.put(`policy_group:${groupId}`, JSON.stringify(group));
  return json({ success: true, group });
}

async function handleDeleteGroup(request, env, groupId) {
  const session = await getSession(request, env);
  if (!session || session.role !== 'admin') return json({ error: 'Admin required' }, 403);
  await env.DASHBOARD_KV.delete(`policy_group:${groupId}`);
  const ids = (await env.DASHBOARD_KV.get('policy_groups', 'json') || []).filter(id => id !== groupId);
  await env.DASHBOARD_KV.put('policy_groups', JSON.stringify(ids));
  const userlist = await env.DASHBOARD_KV.get('userlist', 'json') || [];
  for (const u of userlist) {
    const user = await env.DASHBOARD_KV.get(`user:${u}`, 'json');
    if (user && user.groups && user.groups.includes(groupId)) {
      user.groups = user.groups.filter(g => g !== groupId);
      await env.DASHBOARD_KV.put(`user:${u}`, JSON.stringify(user));
    }
  }
  return json({ success: true });
}

async function handleUpdateUserGroups(request, env, username) {
  const session = await getSession(request, env);
  if (!session || session.role !== 'admin') return json({ error: 'Admin required' }, 403);
  if (username === 'admin') return json({ error: 'Không thể sửa admin' }, 400);
  const user = await env.DASHBOARD_KV.get(`user:${username}`, 'json');
  if (!user) return json({ error: 'User not found' }, 404);
  let body; try { body = await request.json(); } catch { return json({ error: 'Invalid JSON' }, 400); }
  user.groups = Array.isArray(body.groups) ? body.groups : [];
  await env.DASHBOARD_KV.put(`user:${username}`, JSON.stringify(user));
  return json({ success: true, username, groups: user.groups });
}

async function handleUpdateUserPanels(request, env, username) {
  const session = await getSession(request, env);
  if (!session || session.role !== 'admin') return json({ error: 'Admin required' }, 403);
  if (username === 'admin') return json({ error: 'Không thể sửa admin' }, 400);
  const user = await env.DASHBOARD_KV.get(`user:${username}`, 'json');
  if (!user) return json({ error: 'User not found' }, 404);
  let body; try { body = await request.json(); } catch { return json({ error: 'Invalid JSON' }, 400); }
  user.panels = body.panels || {};
  user.cameras = Array.isArray(body.cameras) ? body.cameras : (user.cameras || []);
  await env.DASHBOARD_KV.put(`user:${username}`, JSON.stringify(user));
  return json({ success: true, username, panels: user.panels, cameras: user.cameras });
}

const DEFAULT_CAMERAS = [
  { id: 'cam01', name: 'Camera 01',          type: 'analog',  stream: 'cam01' },
  { id: 'cam03', name: 'Camera 03',          type: 'analog',  stream: 'cam03' },
  { id: 'cam04', name: 'Camera 04',          type: 'ip',      stream: 'cam04' },
  { id: 'cam05', name: 'Camera 05',          type: 'ip',      stream: 'cam05' },
  { id: 'cam06', name: 'Camera 06',          type: 'ip',      stream: 'cam06' },
  { id: 'cam07', name: 'Camera Phòng Khách', type: 'unknown', stream: null    },
];

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
    if (session.role !== 'admin') return json({ error: 'Admin required' }, 403);
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

/* ── MFA API handlers ── */

async function handleMfaSetup(request, env) {
  const session = await getSession(request, env);
  if (!session) return json({ error: 'Not authenticated' }, 401);
  const raw = crypto.getRandomValues(new Uint8Array(20));
  const secret = b32Encode(raw);
  const label   = encodeURIComponent(`HomeLab:${session.username}`);
  const issuer  = encodeURIComponent('HomeLab Dashboard');
  const otpauth = `otpauth://totp/${label}?secret=${secret}&issuer=${issuer}&algorithm=SHA1&digits=6&period=30`;
  return json({ secret, otpauth });
}

async function handleMfaEnable(request, env) {
  const session = await getSession(request, env);
  if (!session) return json({ error: 'Not authenticated' }, 401);
  if (request.method !== 'POST') return json({ error: 'POST required' }, 405);
  let body; try { body = await request.json(); } catch { return json({ error: 'Invalid JSON' }, 400); }
  const { secret, code } = body || {};
  if (!secret || !code) return json({ error: 'Thiếu secret hoặc code' }, 400);
  if (!(await verifyTotp(secret, code)))
    return json({ error: 'Mã OTP không đúng. Kiểm tra đồng hồ thiết bị.' }, 400);
  const user = await env.DASHBOARD_KV.get(`user:${session.username}`, 'json');
  if (!user) return json({ error: 'User not found' }, 404);
  user.mfaEnabled = true;
  user.mfaSecret  = secret;
  await env.DASHBOARD_KV.put(`user:${session.username}`, JSON.stringify(user));
  return json({ success: true });
}

async function handleMfaDisable(request, env) {
  const session = await getSession(request, env);
  if (!session) return json({ error: 'Not authenticated' }, 401);
  if (request.method !== 'POST') return json({ error: 'POST required' }, 405);
  let body; try { body = await request.json(); } catch { return json({ error: 'Invalid JSON' }, 400); }
  const { code } = body || {};
  if (!code) return json({ error: 'Vui lòng nhập mã OTP để xác nhận' }, 400);
  const user = await env.DASHBOARD_KV.get(`user:${session.username}`, 'json');
  if (!user) return json({ error: 'User not found' }, 404);
  if (!user.mfaEnabled) return json({ error: 'MFA chưa được bật' }, 400);
  if (!(await verifyTotp(user.mfaSecret, code))) return json({ error: 'Mã OTP không đúng' }, 400);
  user.mfaEnabled = false;
  user.mfaSecret  = null;
  await env.DASHBOARD_KV.put(`user:${session.username}`, JSON.stringify(user));
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
  if (!(await verifyTotp(user.mfaSecret, code))) {
    await rlBump(env, `mfa:${tempToken}`, 360);
    await logActivity(env, { action: 'mfa_fail', username: temp?.username, ip, success: false, detail: 'Wrong OTP' });
    return json({ error: 'Mã OTP không đúng' }, 400);
  }
  await rlClear(env, `mfa:${tempToken}`);
  await env.DASHBOARD_KV.delete(`mfa_temp:${tempToken}`).catch(() => {});
  // Create full session
  const token = crypto.randomUUID();
  await env.DASHBOARD_KV.put(`session:${token}`, JSON.stringify({
    username: temp.username, role: user.role, permissions: user.permissions || {},
    expires: Date.now() + SESSION_TTL * 1000
  }), { expirationTtl: SESSION_TTL });
  const userInfo = encodeURIComponent(JSON.stringify({
    username: temp.username, role: user.role,
    permissions: user.permissions || {},
    isAdmin: user.role === 'admin'
  }));
  const h = new Headers({ 'Content-Type': 'application/json' });
  h.append('Set-Cookie', `${SESSION_COOKIE}=${token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${SESSION_TTL}`);
  h.append('Set-Cookie', `dh_user=${userInfo}; Secure; SameSite=Lax; Path=/; Max-Age=${SESSION_TTL}`);
  await logActivity(env, { action: 'mfa_success', username: temp.username, ip, success: true });
  return new Response(JSON.stringify({ success: true, role: user.role }), { status: 200, headers: h });
}

/* Shared "Wayfinding" quick-switcher — injected into every authenticated page.
   Lets users jump tool→tool and search without bouncing through the homepage.
   Self-contained, namespaced (wf-), never touches page/map code. */
const WAYFIND_NAV = `<style>
#wf-fab{position:fixed;right:22px;bottom:22px;z-index:2147483000;display:flex;align-items:center;gap:9px;
 font:700 13px/1 -apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;color:#eaf0fb;
 background:linear-gradient(180deg,#1c2c52,#142037);border:1.5px solid #5b8cff;border-radius:13px;
 padding:12px 17px;cursor:pointer;box-shadow:0 8px 26px rgba(20,40,90,.55),0 0 0 4px rgba(91,140,255,.08);
 transition:all .15s;user-select:none}
#wf-fab:hover{border-color:#8fb3ff;transform:translateY(-2px);box-shadow:0 12px 32px rgba(30,60,130,.65)}
#wf-fab .wf-dot{width:8px;height:8px;border-radius:50%;background:#5b8cff;box-shadow:0 0 9px #5b8cff}
#wf-fab .wf-k{font-family:JetBrains Mono,ui-monospace,monospace;font-size:11px;color:#bcd0ff;
 border:1px solid #5b8cff;border-radius:6px;padding:3px 8px;background:rgba(91,140,255,.16)}
@keyframes wfpulse{0%{box-shadow:0 8px 26px rgba(20,40,90,.55),0 0 0 0 rgba(91,140,255,.45)}
 70%{box-shadow:0 8px 26px rgba(20,40,90,.55),0 0 0 16px rgba(91,140,255,0)}
 100%{box-shadow:0 8px 26px rgba(20,40,90,.55),0 0 0 0 rgba(91,140,255,0)}}
#wf-fab.wf-pulse{animation:wfpulse 1.8s ease-out 3}
#wf-hint{position:fixed;right:22px;bottom:78px;z-index:2147483000;max-width:280px;
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
@media(max-width:520px){#wf-fab .wf-lbl{display:none}}
</style>
</style>
<div id="wf-fab" title="Chuyển nhanh giữa các trang (phím tắt: / )" onclick="window.__wfOpen&&window.__wfOpen()">
 <span class="wf-dot"></span><span>Chuyển trang nhanh</span><span class="wf-k">/</span></div>
<div id="wf-hint"><span class="wf-x" title="Đóng" onclick="document.getElementById('wf-hint').classList.remove('on')">&#x2715;</span>
 &#x1F449; Bấm nút xanh này (hoặc phím <b>/</b>) để nhảy thẳng giữa các trang — Meraki, FortiGate, ESXi, MOVI… mà không cần quay về trang chủ.</div>
<div id="wf-ov"><div id="wf-panel">
 <input id="wf-search" placeholder="Tìm dịch vụ… (gõ để lọc, &#x2191;&#x2193; chọn, Enter mở)" autocomplete="off">
 <div id="wf-list"></div>
 <div id="wf-foot"><span><b>&#x2191;&#x2193;</b> di chuyển</span><span><b>Enter</b> mở</span><span><b>Esc</b> đóng</span><span style="margin-left:auto"><b>/</b> hoặc <b>g</b> mở bất kỳ đâu</span></div>
</div></div>
<script>(function(){
 if(window.__wfNav)return; window.__wfNav=1;
 if(location.pathname==='/login.html')return;
 var U=(window.__USER__||{}), adm=!!U.isAdmin;
 var S=[
  {i:'\\u2316',n:'Dashboard',d:'Trang chủ · tất cả dịch vụ',h:'/'},
  {i:'\\uD83C\\uDF10',n:'Meraki-Network',d:'Network client monitor · Cisco Meraki',h:'/meraki.html'},
  {i:'\\uD83D\\uDDFA',n:'Movi Map Network',d:'Sơ đồ topology · route · dây switch',h:'/topology.html'},
  {i:'\\uD83D\\uDD25',n:'FortiGate',d:'Firewall · security gateway',h:'/fortigate.html'},
  {i:'\\uD83D\\uDDA5',n:'VMware ESXi',d:'Hypervisor · bare metal',h:'/esxi.html'},
  {i:'\\uD83C\\uDFE0',n:'CasaOS',d:'Home server OS',h:'/casaos.html'},
  {i:'\\uD83D\\uDCE1',n:'ASUS Router',d:'Home network router',h:'/asus.html'},
  {i:'\\uD83D\\uDD00',n:'9Router',d:'Router & network management',h:'/9router.html'},
  {i:'\\u26A1',n:'n8n Automation',d:'Workflow & bot automation',h:'/n8n.html'},
  {i:'\\uD83D\\uDCF7',n:'Camera',d:'Hệ thống camera · go2rtc',h:'/hikvision.html'},
  {i:'\\uD83D\\uDDA7',n:'SSH Terminal',d:'Web SSH · Termix',h:'/ssh.html'},
  {i:'\\uD83D\\uDD16',n:'Bookmarks',d:'Liên kết nhanh',h:'/bookmarks.html'}
 ];
 if(adm){S.push({i:'\\uD83D\\uDC65',n:'Users',d:'Quản lý người dùng (admin)',h:'/users.html'});S.push({i:'\\uD83D\\uDEE1',n:'Policy',d:'Quyền hạn · nhóm · camera (admin)',h:'/policy.html'});}
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
#wf-rfab{position:fixed;right:22px;bottom:74px;z-index:2147483000;display:none;align-items:center;gap:9px;
 font:700 13px/1 -apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;color:#cfe0d6;
 background:linear-gradient(180deg,#143526,#0f261c);border:1.5px solid #2c8a5c;border-radius:13px;
 padding:12px 16px;cursor:pointer;box-shadow:0 8px 24px rgba(10,50,30,.5);transition:all .15s;user-select:none}
#wf-rfab:hover{border-color:#34d399;transform:translateY(-2px)}
#wf-rfab.busy{opacity:.65;cursor:progress}
#wf-rfab .wf-rk{font-family:JetBrains Mono,ui-monospace,monospace;font-size:11px;color:#7fe3b4;
 border:1px solid #2c8a5c;border-radius:6px;padding:3px 8px;background:rgba(52,211,153,.14)}
#wf-rspin{width:13px;height:13px;border:2px solid rgba(127,227,180,.3);border-top-color:#34d399;
 border-radius:50%;display:none}
#wf-rfab.busy #wf-rspin{display:inline-block;animation:wfspin .7s linear infinite}
#wf-rfab.busy .wf-rdot{display:none}
.wf-rdot{width:8px;height:8px;border-radius:50%;background:#34d399;box-shadow:0 0 9px #34d399}
@keyframes wfspin{to{transform:rotate(360deg)}}
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
<div id="wf-rfab" title="Tải lại dữ liệu của trang này (phím tắt: r)" onclick="window.__wfData&&window.__wfData()">
 <span class="wf-rdot"></span><span id="wf-rspin"></span><span>Tải lại dữ liệu</span><span class="wf-rk">r</span></div>
<script>(function(){
 if(window.__wfData)return;
 if(location.pathname==='/login.html')return;
 var MAP={'/':['runChecks'],'/index.html':['runChecks'],'/meraki.html':['loadAll'],
  '/fortigate.html':['load'],'/esxi.html':['loadData'],'/casaos.html':['loadData'],
  '/asus.html':['load'],'/9router.html':['loadData'],'/n8n.html':['loadData'],
  '/hikvision.html':['loadState'],'/users.html':['loadUsers','loadMfaStatus'],
  '/bookmarks.html':['loadData']};
 var path=location.pathname.replace(/\\/index\\.html$/,'/');
 var fns=MAP[path]||MAP[location.pathname];
 var rfab=document.getElementById('wf-rfab'),bar=document.getElementById('wf-bar'),
     toast=document.getElementById('wf-toast');
 if(!fns||!rfab)return;
 rfab.style.display='flex';
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
  if(busy)return; busy=true; rfab.classList.add('busy');
  barStart(); say('\\u27F3 Đang tải lại dữ liệu…','',0);
  var t0=Date.now(), ps=[], called=0;
  fns.forEach(function(fn){
   try{ if(typeof window[fn]==='function'){ called++; var r=window[fn](); if(r&&typeof r.then==='function')ps.push(r); } }catch(e){}
  });
  function finish(ok){
   var wait=Math.max(0,900-(Date.now()-t0));
   setTimeout(function(){
    busy=false; rfab.classList.remove('busy'); barDone();
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
 document.addEventListener('keydown',function(e){
  var t=e.target,tg=(t&&t.tagName||'').toLowerCase(),
      typing=tg==='input'||tg==='textarea'||(t&&t.isContentEditable);
  var ovOpen=(document.getElementById('wf-ov')||{}).classList&&document.getElementById('wf-ov').classList.contains('on');
  if(e.key==='r'&&!typing&&!ovOpen&&!e.ctrlKey&&!e.metaKey&&!e.altKey){e.preventDefault();run();}
 });
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
 var PMAP={'/meraki.html':{
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

async function injectUser(request, env) {
  const session = await getSession(request, env);
  const url = new URL(request.url);
  const isLoginPage = url.pathname === '/login.html';

  // Login page: redirect to / if already logged in
  if (isLoginPage) {
    if (session) return Response.redirect(new URL('/', request.url).toString(), 302);
    return env.ASSETS.fetch(request);
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
  const isAdmin = session.role === 'admin';
  let effPerms = { permissions: {}, panels: {}, cameras: [], groups: [] };
  if (!isAdmin) {
    const computed = await computeEffectivePermissions(env, session.username);
    if (computed) effPerms = computed;
  }
  const userScript = `<script>window.__USER__=${JSON.stringify({
    username: session.username,
    role: session.role,
    permissions: isAdmin ? {} : effPerms.permissions,
    panels: isAdmin ? {} : effPerms.panels,
    cameras: isAdmin ? [] : effPerms.cameras,
    groups: isAdmin ? [] : effPerms.groups,
    isAdmin
  })};</script>` + IDLE_SCRIPT;
  // Head: user + idle scripts.  Body end: the Wayfinding switcher as static
  // markup (DOM-ready, immune to the page's own client-side re-rendering).
  let newHtml = /<\/head>/i.test(html)
    ? html.replace(/<\/head>/i, userScript + '\n</head>')
    : html.replace(/<body/i, userScript + '\n<body');
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
      // App is heavily inline-scripted; 'unsafe-inline' is required to avoid
      // breakage, but external script/object/frame sources are locked down.
      'Content-Security-Policy':
        "default-src 'self'; " +
        "script-src 'self' 'unsafe-inline'; " +
        // Google Fonts stylesheet
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; " +
        "img-src 'self' data: https:; " +
        // Allow same-origin + HTTPS APIs + WebSocket for camera streaming
        "connect-src 'self' https: wss:; " +
        // Google Fonts files + data URIs
        "font-src 'self' data: https://fonts.gstatic.com; " +
        // Allow camera (go2rtc) and SSH terminal (termix) iframes
        "frame-src 'self' https://camera.home-server.id.vn https://termix.home-server.id.vn https://cam.movi-finance.com; " +
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
];

const N8N_BASE        = 'https://n8n-home.home-server.id.vn/api/v1';
const NINEROUTER_BASE = 'https://9router.home-server.id.vn';
const ESXI_SDK        = 'https://esxi.home-server.id.vn/sdk';

/* ── Movi n8n webhook basic-auth (credentials from Cloudflare secrets) ──
   Set via:  wrangler secret put MOVI_N8N_USER  /  MOVI_N8N_PASS
   Never hardcode credentials in source. */
function moviN8nAuth(env) {
  const u = env && env.MOVI_N8N_USER;
  const p = env && env.MOVI_N8N_PASS;
  if (!u || !p) throw new Error('MOVI_N8N_USER / MOVI_N8N_PASS not configured');
  return 'Basic ' + btoa(u + ':' + p);
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
  const key = env.N8N_API_KEY;
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
  const key = env.N8N_API_KEY;
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

async function handle9Router() {
  const opts = { signal: AbortSignal.timeout(10000), headers: { 'Accept': 'application/json' } };
  const safeFetch = async (url) => {
    try {
      const res = await fetch(url, opts);
      if (!res.ok) return null;
      const d = await res.json();
      return (d && d.error) ? null : d;
    } catch { return null; }
  };

  try {
    const [connData, comboData, usageData] = await Promise.all([
      safeFetch(`${NINEROUTER_BASE}/api/providers`),
      safeFetch(`${NINEROUTER_BASE}/api/combos`),
      safeFetch(`${NINEROUTER_BASE}/api/usage/stats`),
    ]);

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
  await env.DASHBOARD_KV.put(`bookmarks:${session.username}`, JSON.stringify(raw));
  const count = Array.isArray(raw) ? raw.length
    : (raw.folders ? raw.folders.reduce((s,f) => s + (f.items||[]).length, 0) : 0);
  return json({ success: true, count });
}


/* ── Activity Log ── */
async function logActivity(env, { action, username, ip, success, detail }) {
  try {
    const log = await env.DASHBOARD_KV.get('activity_log', 'json') || [];
    log.unshift({ ts: Date.now(), action, username: username||'?', ip: ip||'?', success: !!success, detail: detail||'' });
    if (log.length > 200) log.length = 200;
    await env.DASHBOARD_KV.put('activity_log', JSON.stringify(log), { expirationTtl: 60*60*24*30 });
  } catch(e) { /* non-critical */ }
}

/* ── Meraki Devices Proxy ── */
async function handleMerakiDevices(request, env) {
  const session = await getSession(request, env);
  if (!session) return json({ error: 'Unauthorized' }, 401);

  const N8N_URL  = 'https://n8n.movi-finance.com/webhook/c65756f7-f228-4668-8d47-79efd543f234';
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

  const N8N_URL  = 'https://n8n.movi-finance.com/webhook/8e83df3c-d3ad-48ae-ae1c-11fd5733d147';
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

/* ── Meraki Client Policy: block / unblock — ADMIN ONLY ── */
async function handleMerakiClientPolicy(request, env) {
  const session = await getSession(request, env);
  if (!session) return json({ error: 'Unauthorized' }, 401);
  if (session.role !== 'admin') return json({ error: 'Admin required' }, 403);
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

  const N8N_URL  = 'https://n8n.movi-finance.com/webhook/meraki-client-policy';
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
    try {
      const lg = await env.DASHBOARD_KV.get('activity_log', 'json') || [];
      lg.unshift({ ts: Date.now(), user: session.username, action: 'meraki-client-policy', mac, policy });
      await env.DASHBOARD_KV.put('activity_log', JSON.stringify(lg.slice(0, 200)));
    } catch (e) {}
    return json({ success: true, mac, policy, result: payload });
  } catch (e) {
    return json({ error: 'Failed to reach n8n', detail: e.message }, 502);
  }
}

/* ── Meraki Blocked Clients list (GET) — admin only ── */
async function handleMerakiBlockedClients(request, env) {
  const session = await getSession(request, env);
  if (!session) return json({ error: 'Unauthorized' }, 401);
  if (session.role !== 'admin') return json({ error: 'Admin required' }, 403);
  const list = await env.DASHBOARD_KV.get('meraki_blocked_clients', 'json') || [];
  return json({ blocked: list });
}

/* ── Meraki Device Status Proxy ── */
async function handleMerakiDeviceStatus(request, env) {
  const session = await getSession(request, env);
  if (!session) return json({ error: 'Unauthorized' }, 401);

  const N8N_URL  = 'https://n8n.movi-finance.com/webhook/105904c4-2578-4bd7-98c9-bc226bf8f655';
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
  const N8N_URL  = 'https://n8n.movi-finance.com/webhook/35e2fe08-836e-49de-b029-3d6f4f59ff78';
  const N8N_AUTH = moviN8nAuth(env);
  try {
    const resp = await fetch(N8N_URL, { headers: { 'Authorization': N8N_AUTH }, signal: AbortSignal.timeout(50000) });
    if (!resp.ok) return json({ error: 'n8n upstream error', status: resp.status }, 502);
    const raw = await resp.json();
    const switches = Array.isArray(raw) ? raw : [raw];
    const totalPorts     = switches.reduce((s, sw) => s + (sw.totalPorts || 0), 0);
    const connectedPorts = switches.reduce((s, sw) => s + (sw.connectedPorts || 0), 0);
    const errorPorts     = switches.reduce((s, sw) => s + (sw.errorPorts || 0), 0);
    const deadSwitches   = switches.filter(sw => sw.connectedPorts === 0).length;
    return json({ switches, totalSwitches: switches.length, totalPorts, connectedPorts, errorPorts, deadSwitches, fetchedAt: new Date().toISOString() });
  } catch (e) {
    return json({ error: 'Failed to reach n8n', detail: e.message }, 502);
  }
}

/* ── Meraki Switch Port Configs (W5b) ── */
async function handleMerakiSwitchPortConfigs(request, env) {
  const session = await getSession(request, env);
  if (!session) return json({ error: 'Unauthorized' }, 401);
  const N8N_URL  = 'https://n8n.movi-finance.com/webhook/aa72618f-47a8-44cb-a58b-d77be06ee3d7';
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
  const N8N_URL  = 'https://n8n.movi-finance.com/webhook/b1405e23-8260-433b-b295-8218fc22c024';
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
  const N8N_URL  = 'https://n8n.movi-finance.com/webhook/3f478f32-1d89-4724-a052-e43da70ed922';
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
  const N8N_URL  = 'https://n8n.movi-finance.com/webhook/03771442-1f75-4c8a-9c94-8c601796f79b';
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

  const N8N_URL  = 'https://n8n.movi-finance.com/webhook/3019c3e2-5725-40b5-95e4-f4a8d5a3d326';
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
  const N8N_URL  = 'https://n8n.movi-finance.com/webhook/79b39d3c-debd-4e25-ad1f-21aa7d9b3908';
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
  const N8N_URL  = 'https://n8n.movi-finance.com/webhook/635ec656-db89-48b5-9d57-66d8b154958b';
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

/* ── Camera Movi — Token ── */
async function handleCameraToken(request, env) {
  const session = await getSession(request, env);
  if (!session) return json({ error: 'Unauthorized' }, 401);
  const url = env.MOVI_CAM_URL || '';
  if (!url) return json({ error: 'Camera not configured' }, 503);
  const streams = [];
  for (let i = 1; i <= 16; i++) streams.push('cam' + i);
  return json({ url, streams });
}

/* ── Camera Movi — Full Reverse Proxy (HTTP + WebSocket) ── */
async function handleCamEmbed(request, env) {
  const session = await getSession(request, env);
  if (!session) return new Response('Unauthorized', { status: 401 });

  const user   = env.MOVI_CAM_USER || '';
  const pass   = env.MOVI_CAM_PASS || '';
  const camUrl = env.MOVI_CAM_URL  || '';
  if (!camUrl) return new Response('Camera not configured', { status: 503 });

  const auth    = 'Basic ' + btoa(`${user}:${pass}`);
  const reqUrl  = new URL(request.url);
  const subPath = reqUrl.pathname.replace('/cam-embed', '') || '/';
  const target  = `${camUrl}${subPath}${reqUrl.search}`;

  // WebSocket proxy (for go2rtc MSE video stream)
  if (request.headers.get('Upgrade')?.toLowerCase() === 'websocket') {
    const wsTarget = target.replace(/^https/, 'wss').replace(/^http(?!s)/, 'ws');

    // Connect to upstream go2rtc WebSocket with auth
    const upstreamResp = await fetch(wsTarget, {
      headers: {
        'Authorization':        auth,
        'Upgrade':              'websocket',
        'Connection':           'Upgrade',
        'Sec-WebSocket-Version': request.headers.get('Sec-WebSocket-Version') || '13',
        'Sec-WebSocket-Key':     request.headers.get('Sec-WebSocket-Key')     || '',
      },
    });

    const upstream = upstreamResp.webSocket;
    if (!upstream) return new Response('WebSocket upstream failed', { status: 502 });

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

  const upstream = await fetch(target, {
    method:  request.method,
    headers: { 'Authorization': auth },
  });

  const ct = upstream.headers.get('Content-Type') || 'application/octet-stream';

  // Inject JS patch into HTML so go2rtc's stream.html routes API calls through proxy
  if (ct.includes('text/html')) {
    let html = await upstream.text();
    const patch = `<script>
(function(){
  var _W=window.WebSocket;
  window.WebSocket=function(u,p){
    if(typeof u==='string') u=u.replace(/(wss?:\\/\\/[^\\/]+)\\/api\\//,'$1/cam-embed/api/');
    return p!=null?new _W(u,p):new _W(u);
  };
  var _f=window.fetch;
  window.fetch=function(u){
    var a=Array.prototype.slice.call(arguments);
    if(typeof u==='string') a[0]=u.replace(/https?:\\/\\/[^\\/]+\\/api\\//,'/cam-embed/api/');
    return _f.apply(this,a);
  };
  var _xo=XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open=function(m,u){
    var a=Array.prototype.slice.call(arguments);
    if(typeof u==='string') a[1]=u.replace(/https?:\\/\\/[^\\/]+\\/api\\//,'/cam-embed/api/');
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
  const N8N_URL  = 'https://n8n.movi-finance.com/webhook/ccd8b0a9-730e-4767-aa29-6f99ba8d9a4b';
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
  const N8N_URL  = 'https://n8n.movi-finance.com/webhook/fed29e7e-aa06-483c-9709-1e7bcaf79c3b';
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
  const N8N_URL  = 'https://n8n.movi-finance.com/webhook/ea8d7f9b-903b-4855-abdf-b73aa02ba1e8';
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
  const N8N_URL  = 'https://n8n.movi-finance.com/webhook/30b5ff6d-0065-4150-8c7f-0d25f2b6bc76';
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
  const N8N_URL  = 'https://n8n.movi-finance.com/webhook/2d3b9660-b99a-4bd3-92ba-165efb23c741';
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
  const N8N_URL  = 'https://n8n.movi-finance.com/webhook/8bd446f5-d1d4-4de6-a679-a26fcb0f5f60';
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
  const N8N_URL  = 'https://n8n.movi-finance.com/webhook/52d4503a-66ec-49cc-b4c2-f4605349b17b';
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

async function handleGetActivity(request, env) {
  const session = await getSession(request, env);
  if (!session || session.role !== 'admin') return json({ error: 'Admin required' }, 403);
  const log = await env.DASHBOARD_KV.get('activity_log', 'json') || [];
  return json({ log: log.slice(0, 100) });
}

/* ── User Shortcuts ── */
async function handleGetShortcuts(request, env) {
  const session = await getSession(request, env);
  if (!session) return json({ error: 'Not authenticated' }, 401);
  const list = await env.DASHBOARD_KV.get(`shortcuts:${session.username}`, 'json') || [];
  return json({ shortcuts: list });
}

async function handleSaveShortcuts(request, env) {
  const session = await getSession(request, env);
  if (!session) return json({ error: 'Not authenticated' }, 401);
  if (request.method !== 'PUT') return json({ error: 'PUT required' }, 405);
  let body; try { body = await request.json(); } catch { return json({ error: 'Invalid JSON' }, 400); }
  const list = (Array.isArray(body.shortcuts) ? body.shortcuts : []).slice(0, 24);
  await env.DASHBOARD_KV.put(`shortcuts:${session.username}`, JSON.stringify(list));
  return json({ success: true, count: list.length });
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

// Wrap body in SOAP Envelope and POST to /sdk
async function esxiSoap(bodyXml, cookie = '') {
  const headers = {
    'Content-Type': 'text/xml; charset=UTF-8',
    'SOAPAction': '"urn:vim25/8.0"',
  };
  if (cookie) headers['Cookie'] = cookie;

  const envelope = [
    '<?xml version="1.0" encoding="UTF-8"?>',
    '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"',
    ' xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">',
    '<soapenv:Body>', bodyXml, '</soapenv:Body></soapenv:Envelope>',
  ].join('');

  const res = await fetch(ESXI_SDK, {
    method: 'POST', headers, body: envelope,
    signal: AbortSignal.timeout(15000),
  });
  const text = await res.text();
  const sc   = res.headers.get('set-cookie') || '';
  const ck   = (sc.match(/vmware_soap_session[^;]+/) || [''])[0];
  return { text, cookie: ck, ok: res.ok };
}

async function handleESXi(env) {
  const user = env.ESXI_USER;
  const pass = env.ESXI_PASSWORD;

  // ── Step 1: basic info, no auth ──
  const { text: svcText } = await esxiSoap(
    '<RetrieveServiceContent xmlns="urn:vim25">' +
    '<_this type="ServiceInstance">ServiceInstance</_this>' +
    '</RetrieveServiceContent>'
  );
  const about = {
    fullName:   x1(svcText, 'fullName'),
    version:    x1(svcText, 'version'),
    build:      x1(svcText, 'build'),
    apiVersion: x1(svcText, 'apiVersion'),
  };

  if (!user || !pass) {
    return json({ about, host: null, vms: [], datastores: [], stats: {}, error: 'ESXI_USER / ESXI_PASSWORD not configured' });
  }

  // ── Step 2: login ──
  const smRef = x1(svcText, 'sessionManager') || 'ha-sessionmanager';

  const loginBody =
    '<Login xmlns="urn:vim25">' +
    '<_this type="SessionManager">' + escXml(smRef) + '</_this>' +
    '<userName>' + escXml(user) + '</userName>' +
    '<password>' + escXml(pass) + '</password>' +
    '</Login>';

  const { text: loginText, cookie, ok: loginOk } = await esxiSoap(loginBody);

  let sessionToken = null;
  if (!cookie || loginText.includes('Fault>')) {
    try {
      const b64 = btoa(user + ':' + pass);
      const restRes = await fetch('https://esxi.home-server.id.vn/api/session', {
        method: 'POST',
        headers: { 'Authorization': 'Basic ' + b64, 'Content-Type': 'application/json', 'Accept': 'application/json' },
        signal: AbortSignal.timeout(10000),
      });
      if (restRes.ok) {
        const tok = await restRes.json();
        sessionToken = typeof tok === 'string' ? tok : null;
      }
    } catch (_) {}
  }

  if (!cookie && !sessionToken) {
    const msg = x1(loginText, 'localizedMessage') || x1(loginText, 'faultstring') || 'Login failed';
    return json({
      about, host: null, vms: [], datastores: [], stats: {},
      error: msg || 'Login failed',
      _debug: { loginOk, hasCookie: !!cookie, loginSnippet: loginText.slice(0, 600) }
    });
  }

  // ── Step 3: fetch host, VMs, datastores in parallel ──
  const hostBody = `<RetrievePropertiesEx xmlns="urn:vim25">
<_this type="PropertyCollector">ha-property-collector</_this>
<specSet>
  <propSet><type>HostSystem</type>
    <pathSet>summary.config.name</pathSet>
    <pathSet>summary.hardware.memorySize</pathSet>
    <pathSet>summary.hardware.cpuModel</pathSet>
    <pathSet>summary.hardware.numCpuCores</pathSet>
    <pathSet>summary.hardware.numCpuThreads</pathSet>
    <pathSet>summary.hardware.cpuMhz</pathSet>
    <pathSet>summary.quickStats.overallCpuUsage</pathSet>
    <pathSet>summary.quickStats.overallMemoryUsage</pathSet>
    <pathSet>summary.runtime.connectionState</pathSet>
    <pathSet>summary.overallStatus</pathSet>
  </propSet>
  <objectSet><obj type="HostSystem">ha-host</obj></objectSet>
</specSet><options/></RetrievePropertiesEx>`;

  const vmBody = `<RetrievePropertiesEx xmlns="urn:vim25">
<_this type="PropertyCollector">ha-property-collector</_this>
<specSet>
  <propSet><type>VirtualMachine</type>
    <pathSet>name</pathSet>
    <pathSet>runtime.powerState</pathSet>
    <pathSet>config.hardware.numCPU</pathSet>
    <pathSet>config.hardware.memoryMB</pathSet>
    <pathSet>guest.ipAddress</pathSet>
    <pathSet>guest.hostName</pathSet>
    <pathSet>guest.guestFullName</pathSet>
    <pathSet>summary.quickStats.overallCpuUsage</pathSet>
    <pathSet>summary.quickStats.guestMemoryUsage</pathSet>
    <pathSet>summary.storage.committed</pathSet>
    <pathSet>summary.runtime.bootTime</pathSet>
    <pathSet>config.annotation</pathSet>
  </propSet>
  <objectSet>
    <obj type="HostSystem">ha-host</obj>
    <selectSet xsi:type="TraversalSpec">
      <type>HostSystem</type><path>vm</path><skip>false</skip>
    </selectSet>
  </objectSet>
</specSet><options><maxObjects>100</maxObjects></options></RetrievePropertiesEx>`;

  const dsBody = `<RetrievePropertiesEx xmlns="urn:vim25">
<_this type="PropertyCollector">ha-property-collector</_this>
<specSet>
  <propSet><type>Datastore</type>
    <pathSet>name</pathSet>
    <pathSet>summary.capacity</pathSet>
    <pathSet>summary.freeSpace</pathSet>
    <pathSet>summary.type</pathSet>
    <pathSet>summary.accessible</pathSet>
    <pathSet>summary.url</pathSet>
  </propSet>
  <objectSet>
    <obj type="HostSystem">ha-host</obj>
    <selectSet xsi:type="TraversalSpec">
      <type>HostSystem</type><path>datastore</path><skip>false</skip>
    </selectSet>
  </objectSet>
</specSet><options/></RetrievePropertiesEx>`;

  try {
    const [hostRes, vmRes, dsRes] = await Promise.all([
      esxiSoap(hostBody, cookie),
      esxiSoap(vmBody,   cookie),
      esxiSoap(dsBody,   cookie),
    ]);

    // ── Parse host ──
    let host = null;
    for (const obj of xAll(hostRes.text, 'objects')) {
      const p = parsePropSets(obj);
      const totalMhz = parseInt(p['summary.hardware.numCpuCores'] || 0)
                     * parseInt(p['summary.hardware.cpuMhz'] || 0);
      const cpuUsed  = parseInt(p['summary.quickStats.overallCpuUsage'] || 0);
      const memTotal = parseInt(p['summary.hardware.memorySize'] || 0);
      const memUsed  = parseInt(p['summary.quickStats.overallMemoryUsage'] || 0);
      host = {
        name: p['summary.config.name'],
        cpuModel: p['summary.hardware.cpuModel'],
        numCpuCores: parseInt(p['summary.hardware.numCpuCores'] || 0),
        numCpuThreads: parseInt(p['summary.hardware.numCpuThreads'] || 0),
        cpuMhz: parseInt(p['summary.hardware.cpuMhz'] || 0),
        totalCpuMhz: totalMhz,
        usedCpuMhz: cpuUsed,
        cpuPct: totalMhz > 0 ? Math.round(cpuUsed / totalMhz * 100) : 0,
        memTotalMB: Math.round(memTotal / 1048576),
        memUsedMB: memUsed,
        memPct: memTotal > 0 ? Math.round(memUsed / (memTotal / 1048576) * 100) : 0,
        connectionState: p['summary.runtime.connectionState'],
        overallStatus: p['summary.overallStatus'],
      };
    }

    // ── Parse VMs ──
    const vms = [];
    for (const obj of xAll(vmRes.text, 'objects')) {
      if (!obj.includes('type="VirtualMachine"')) continue;
      const moId = x1(obj, 'obj');
      const p    = parsePropSets(obj);
      const cpuMhz = parseInt(p['summary.quickStats.overallCpuUsage'] || 0);
      const cpuPct = host && host.cpuMhz > 0
        ? Math.round(cpuMhz / host.cpuMhz * 100) : 0;
      const memMB  = parseInt(p['config.hardware.memoryMB'] || 0);
      const memUsed= parseInt(p['summary.quickStats.guestMemoryUsage'] || 0);
      vms.push({
        id: moId,
        name: p['name'] || '(unnamed)',
        powerState: p['runtime.powerState'],
        numCPU: parseInt(p['config.hardware.numCPU'] || 0),
        memoryMB: memMB,
        ipAddress: p['guest.ipAddress'] || null,
        hostName: p['guest.hostName'] || null,
        guestOS: p['guest.guestFullName'] || null,
        cpuUsageMhz: cpuMhz,
        cpuPct: Math.min(cpuPct, 100),
        memUsedMB: memUsed,
        memPct: memMB > 0 ? Math.round(memUsed / memMB * 100) : 0,
        storageGB: Math.round(parseInt(p['summary.storage.committed'] || 0) / 1073741824 * 10) / 10,
        bootTime: p['summary.runtime.bootTime'] || null,
        annotation: p['config.annotation'] || null,
      });
    }
    vms.sort((a, b) => {
      if (a.powerState !== b.powerState)
        return a.powerState === 'poweredOn' ? -1 : 1;
      return (a.name || '').localeCompare(b.name || '');
    });

    // ── Parse Datastores ──
    const datastores = [];
    for (const obj of xAll(dsRes.text, 'objects')) {
      const p = parsePropSets(obj);
      const cap  = parseInt(p['summary.capacity']  || 0);
      const free = parseInt(p['summary.freeSpace'] || 0);
      datastores.push({
        name: p['name'],
        type: p['summary.type'],
        accessible: p['summary.accessible'] === 'true',
        capacityGB: Math.round(cap  / 1073741824 * 10) / 10,
        freeGB:     Math.round(free / 1073741824 * 10) / 10,
        usedGB:     Math.round((cap - free) / 1073741824 * 10) / 10,
        usedPct: cap > 0 ? Math.round((cap - free) / cap * 100) : 0,
      });
    }

    const poweredOn  = vms.filter(v => v.powerState === 'poweredOn').length;
    const poweredOff = vms.filter(v => v.powerState === 'poweredOff').length;
    const suspended  = vms.filter(v => v.powerState === 'suspended').length;

    return json({ about, host, vms, datastores, stats: { totalVMs: vms.length, poweredOn, poweredOff, suspended } });
  } finally {
    esxiSoap('<Logout xmlns="urn:vim25"><_this type="SessionManager">ha-sessionmanager</_this></Logout>', cookie).catch(() => {});
  }
}

/* ═══════════════════════════════════════════════
   ESXi — VM Power Actions (SOAP)
   ═══════════════════════════════════════════════ */
async function handleESXiPower(request, env) {
  if (request.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
    }});
  }
  if (request.method !== 'POST') return json({ error: 'POST required' }, 405);

  const user = env.ESXI_USER;
  const pass = env.ESXI_PASSWORD;
  if (!user || !pass) return json({ error: 'ESXi credentials not configured' }, 500);

  let body;
  try { body = await request.json(); } catch { return json({ error: 'Invalid JSON body' }, 400); }

  const { vmId, action } = body;
  if (!vmId || !action) return json({ error: 'Missing vmId or action' }, 400);

  const actionMap = {
    'powerOn':       'PowerOnVM_Task',
    'powerOff':      'PowerOffVM_Task',
    'suspend':       'SuspendVM_Task',
    'reset':         'ResetVM_Task',
    'shutdownGuest': 'ShutdownGuest',
    'rebootGuest':   'RebootGuest',
  };
  const soapMethod = actionMap[action];
  if (!soapMethod) return json({ error: 'Invalid action. Allowed: ' + Object.keys(actionMap).join(', ') }, 400);

  try {
    const { text: svcText } = await esxiSoap(
      '<RetrieveServiceContent xmlns="urn:vim25"><_this type="ServiceInstance">ServiceInstance</_this></RetrieveServiceContent>'
    );
    const smRef = x1(svcText, 'sessionManager') || 'ha-sessionmanager';
    const { cookie } = await esxiSoap(
      '<Login xmlns="urn:vim25">' +
      '<_this type="SessionManager">' + escXml(smRef) + '</_this>' +
      '<userName>' + escXml(user) + '</userName>' +
      '<password>' + escXml(pass) + '</password>' +
      '</Login>'
    );
    if (!cookie) return json({ error: 'ESXi login failed' }, 502);

    const powerBody =
      '<' + soapMethod + ' xmlns="urn:vim25">' +
      '<_this type="VirtualMachine">' + escXml(vmId) + '</_this>' +
      '</' + soapMethod + '>';

    const { text: resultText } = await esxiSoap(powerBody, cookie);

    esxiSoap('<Logout xmlns="urn:vim25"><_this type="SessionManager">ha-sessionmanager</_this></Logout>', cookie).catch(() => {});

    if (resultText.includes('Fault>')) {
      const faultMsg = x1(resultText, 'localizedMessage') || x1(resultText, 'faultstring') || 'Unknown fault';
      return json({ success: false, error: faultMsg });
    }

    return json({ success: true, action, vmId });
  } catch (e) {
    return json({ error: e.message }, 502);
  }
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
   FortiGate — REST API v2 (read-only token)
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
   ASUS Router — HTTP API (asusrouter protocol)
   Via Cloudflare Tunnel + CF Access Service Token
   ═══════════════════════════════════════════════ */
const ASUS_BASE = 'https://asus-api.home-server.id.vn';

async function asusRequest(path, method, body, token, env) {
  const cfId  = env.CF_ACCESS_CLIENT_ID;
  const cfSec = env.CF_ACCESS_CLIENT_SECRET;
  const headers = { 'User-Agent': 'asusrouter--DUTUtil-' };
  if (cfId && cfSec) {
    headers['CF-Access-Client-Id']     = cfId;
    headers['CF-Access-Client-Secret'] = cfSec;
  }
  if (token) headers['Cookie'] = `asus_token=${token}`;
  if (body)  headers['Content-Type'] = 'application/x-www-form-urlencoded';
  const opts = { method: method || 'GET', headers, signal: AbortSignal.timeout(12000) };
  if (body) opts.body = body;
  try {
    const r = await fetch(`${ASUS_BASE}${path}`, opts);
    const text = await r.text();
    return { ok: r.ok, text };
  } catch (e) {
    return { ok: false, text: '', error: e.message };
  }
}

async function asusLogin(env) {
  const user = env.ASUS_USER;
  const pass = env.ASUS_PASS;
  if (!user || !pass) return null;
  const auth = btoa(`${user}:${pass}`);
  const { ok, text } = await asusRequest(
    '/login.cgi', 'POST', `login_authorization=${encodeURIComponent(auth)}`, null, env
  );
  if (!ok) return null;
  try { return JSON.parse(text).asus_token || null; } catch { return null; }
}

async function handleAsus(env) {
  if (!env.ASUS_USER || !env.ASUS_PASS)
    return json({ error: 'ASUS_USER / ASUS_PASS not configured' }, 500);

  const token = await asusLogin(env);
  if (!token) return json({ error: 'ASUS router login failed — check credentials' }, 502);

  // Main hook: only nvram_get + appobj — NO get_clientlist() here
  // (some firmware breaks the entire response if get_clientlist() is mixed in)
  const hookVars = [
    'cpu_usage(appobj)', 'memory_usage(appobj)', 'netdev(appobj)',
    'nvram_get(wan_ipaddr)', 'nvram_get(wan_gateway)', 'nvram_get(wan_dns)',
    'nvram_get(wan_proto)', 'nvram_get(link_internet)',
    'nvram_get(ddns_enable_x)', 'nvram_get(ddns_hostname_x)',
    'nvram_get(ddns_server_x)', 'nvram_get(ddns_ipaddr)', 'nvram_get(ddns_updated)',
    'nvram_get(wl0_ssid)', 'nvram_get(wl0_channel)', 'nvram_get(wl0_radio)',
    'nvram_get(wl1_ssid)', 'nvram_get(wl1_channel)', 'nvram_get(wl1_radio)',
    'nvram_get(productid)', 'nvram_get(firmver)', 'nvram_get(buildno)',
    'nvram_get(lan_ipaddr)', 'nvram_get(uptime)', 'nvram_get(label_mac)',
  ].join(';');

  // Fetch main data + client list in parallel (isolated so client list failure doesn't break main data)
  const [appRes, clRes] = await Promise.all([
    asusRequest('/appGet.cgi', 'POST', `hook=${encodeURIComponent(hookVars)}`, token, env),
    asusRequest('/appGet.cgi', 'POST', `hook=${encodeURIComponent('get_clientlist()')}`, token, env),
  ]);

  let app = {};
  try { app = JSON.parse(appRes.text || '{}'); } catch {}

  // Client list from separate fetch
  let clRaw = null;
  try {
    const clJson = JSON.parse(clRes.text || '{}');
    clRaw = clJson.get_clientlist ?? null;
  } catch {}

  // ── Parse client list ──────────────────────────────────────────────────
  // get_clientlist() returns either a string "<MAC>><name>><ip>><isWL>><rssi>><online>><ssid>>"
  // or a JSON object { MAC: { mac, name, ip, isWL, rssi, online, ... } }
  function connLabel(wl) {
    const n = parseInt(wl || 0);
    return n === 0 ? 'Wired' : n === 1 ? '2.4G' : n === 2 ? '5G' : n === 3 ? '5G-2' : 'Unknown';
  }

  function parseClientList(raw) {
    if (!raw) return [];
    // Format A: plain object { MAC: {...} }
    if (typeof raw === 'object' && !Array.isArray(raw)) {
      return Object.values(raw).map(c => ({
        mac:    (c.mac   || c.MAC   || '').toUpperCase(),
        name:   c.name   || c.nickName || c.NickName || '',
        ip:     c.ip     || c.ipAddr   || '',
        type:   connLabel(c.isWL ?? c.type ?? 0),
        rssi:   parseInt(c.rssi  || 0),
        online: c.online === true || c.online === '1' || c.online === 1,
      })).filter(c => c.mac && c.mac.length >= 12);
    }
    // Format B: string "<MAC>><name>><ip>><isWL>><rssi>><online>><ssid>>"
    if (typeof raw === 'string' && raw.trim()) {
      return raw.replace(/^</, '').split('<').filter(Boolean).map(entry => {
        const p = entry.split('>');
        const mac = (p[0] || '').trim().toUpperCase();
        if (!mac || mac.length < 12) return null;
        return {
          mac,
          name:   (p[1] || '').trim(),
          ip:     (p[2] || '').trim(),
          type:   connLabel(p[3]),
          rssi:   parseInt(p[4] || 0),
          online: p[5] === '1',
        };
      }).filter(Boolean);
    }
    return [];
  }

  const clients = parseClientList(clRaw).filter(c => c.online || c.ip);

  // ── CPU ──
  const cpuObj = app.cpu_usage || {};
  let cpuPct = 0;
  const cores = Object.values(cpuObj).filter(c => c && typeof c === 'object' && c.total);
  if (cores.length) {
    const totSum = cores.reduce((s, c) => s + (parseInt(c.total) || 0), 0);
    const useSum = cores.reduce((s, c) => s + (parseInt(c.usage) || 0), 0);
    cpuPct = totSum > 0 ? Math.round(useSum / totSum * 100) : 0;
  }

  // ── Memory ──
  const memObj   = app.memory_usage || {};
  const memTotal = parseInt(memObj.mem_total || 0);
  const memFree  = parseInt(memObj.mem_free  || 0);
  const memUsed  = memTotal - memFree;
  const memPct   = memTotal > 0 ? Math.round(memUsed / memTotal * 100) : 0;

  // ── Network ──
  const netObj  = app.netdev || {};
  const wanNet  = netObj.INTERNET || netObj.wan || {};
  const rxBytes = parseInt(wanNet.rx_bytes || 0);
  const txBytes = parseInt(wanNet.tx_bytes || 0);

  // ── WAN ──
  const wanIp    = app.wan_ipaddr || '';
  const wanOnline = app.link_internet === '1' || (wanIp && wanIp !== '0.0.0.0' && wanIp !== '');

  // ── DDNS ──
  const ddnsEnabled  = app.ddns_enable_x === '1';
  const ddnsHostname = app.ddns_hostname_x || '';
  const ddnsServer   = app.ddns_server_x   || '';
  const ddnsIp       = app.ddns_ipaddr     || '';
  const ddnsUpdated  = app.ddns_updated    || '';
  // Working = enabled + has a valid registered IP + last update didn't fail
  // Note: ddns_updated is often a timestamp like "2025/04/12 08:30:00", not "success"
  const ddnsHasIp    = ddnsIp && ddnsIp !== '' && ddnsIp !== '0.0.0.0';
  const ddnsNotFailed = !ddnsUpdated.toLowerCase().match(/fail|error|n\/a|none/);
  const ddnsWorking  = ddnsEnabled && ddnsHasIp && ddnsNotFailed;

  // ── WiFi client counts from parsed client list ──
  const wifi24Clients = clients.filter(c => c.type === '2.4G').length;
  const wifi5Clients  = clients.filter(c => c.type === '5G' || c.type === '5G-2').length;
  const wiredClients  = clients.filter(c => c.type === 'Wired').length;
  const totalClients  = clients.length;

  // ── Uptime ──
  const uptimeSec  = parseInt(app.uptime || 0);
  const uptimeDays = Math.floor(uptimeSec / 86400);
  const uptimeHrs  = Math.floor((uptimeSec % 86400) / 3600);
  const uptimeMins = Math.floor((uptimeSec % 3600) / 60);
  const uptimeStr  = uptimeDays > 0 ? `${uptimeDays}d ${uptimeHrs}h ${uptimeMins}m`
                   : uptimeHrs  > 0 ? `${uptimeHrs}h ${uptimeMins}m`
                   : `${uptimeMins}m`;

  // Logout fire-and-forget
  asusRequest('/Logout.asp', 'GET', null, token, env).catch(() => {});

  return json({
    system: {
      model:     app.productid  || '',
      firmware:  `${app.firmver || ''}.${app.buildno || ''}`.replace(/^\./,''),
      lanIp:     app.lan_ipaddr || '',
      mac:       app.label_mac  || '',
      uptime:    uptimeStr,
      uptimeSec,
    },
    resources: { cpuPct, memPct, memTotalKB: memTotal, memFreeKB: memFree },
    wan: {
      ip:      wanIp,
      gateway: app.wan_gateway || '',
      dns:     app.wan_dns     || '',
      proto:   (app.wan_proto  || '').toUpperCase(),
      online:  wanOnline,
      rxBytes, txBytes,
    },
    ddns: {
      enabled:  ddnsEnabled,
      hostname: ddnsHostname,
      server:   ddnsServer,
      ip:       ddnsIp,
      updated:  ddnsUpdated,
      working:  ddnsWorking,
    },
    wifi: {
      band24: {
        ssid:    app.wl0_ssid    || '',
        channel: app.wl0_channel || '',
        enabled: app.wl0_radio   !== '0',
        clients: wifi24Clients,
      },
      band5: {
        ssid:    app.wl1_ssid    || '',
        channel: app.wl1_channel || '',
        enabled: app.wl1_radio   !== '0',
        clients: wifi5Clients,
      },
    },
    stats: {
      wanOnline, ddnsWorking, cpuPct, memPct,
      totalClients, wifi24Clients, wifi5Clients, wiredClients,
    },
    clients,
  });
}

async function handleAsusReboot(request, env) {
  if (request.method !== 'POST') return json({ error: 'POST required' }, 405);
  if (!env.ASUS_USER || !env.ASUS_PASS)
    return json({ error: 'ASUS_USER / ASUS_PASS not configured' }, 500);

  const token = await asusLogin(env);
  if (!token) return json({ error: 'Login failed — cannot reboot' }, 502);

  // Send reboot command
  const { ok, text } = await asusRequest(
    '/applyapp.cgi', 'POST', 'action_mode=reboot', token, env
  );
  // Router may close connection immediately on reboot — treat as success
  return json({ success: true, message: 'Reboot command sent to ASUS router' });
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
function proxyErr(msg, url) {
  return new Response(
    `<html><head><meta charset="UTF-8"></head><body style="font-family:system-ui;padding:2rem;background:#0b0d14;color:#e2e8f0">
      <h2 style="color:#f87171;margin-bottom:1rem">⚠ Không thể kết nối</h2>
      <p style="white-space:pre-line;line-height:1.7;color:#cbd5e1">${msg}</p>
      ${url ? `<p style="margin-top:1rem;font-size:12px;color:#64748b">URL: ${url}</p>` : ''}
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

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const p   = url.pathname;

    // ── Auth API (public) ──
    if (p === '/api/auth/login')      return handleLogin(request, env);
    if (p === '/api/auth/logout')     return handleLogout(request, env);
    if (p === '/api/auth/refresh')    return handleSessionRefresh(request, env);
    if (p === '/api/auth/mfa/verify') return handleMfaVerify(request, env);

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
    if (userPerm) return handleUpdatePermissions(request, env, userPerm[1]);
    const userGrp = p.match(/^\/api\/admin\/users\/([^/]+)\/groups$/);
    if (userGrp) return handleUpdateUserGroups(request, env, userGrp[1]);
    const userPnl = p.match(/^\/api\/admin\/users\/([^/]+)\/panels$/);
    if (userPnl) return handleUpdateUserPanels(request, env, userPnl[1]);
    const userDel  = p.match(/^\/api\/admin\/users\/([^/]+)$/);
    if (userDel) {
      if (request.method === 'DELETE') return handleDeleteUser(request, env, userDel[1]);
      if (request.method === 'PUT')    return handleChangePw(request, env, userDel[1]);
    }

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

    // ── Camera list API ──
    if (p === '/api/admin/cameras') return handleCameraList(request, env);

    // ── Data API (require valid session) ──
    if (p === '/api/bookmarks') {
      if (request.method === 'GET') return handleGetBookmarks(request, env);
      if (request.method === 'PUT') return handleSaveBookmarks(request, env);
    }
    if (p === '/api/shortcuts') {
      if (request.method === 'GET') return handleGetShortcuts(request, env);
      if (request.method === 'PUT') return handleSaveShortcuts(request, env);
    }
    if (p === '/api/activity') return handleGetActivity(request, env);
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
    if (p.startsWith('/cam-embed/'))             return handleCamEmbed(request, env);
    if (p === '/api/movi-interfaces')            return handleMoviInterfaces(request, env);
    if (p === '/api/movi-system')               return handleMoviSystem(request, env);
    if (p === '/api/movi-license')              return handleMoviLicense(request, env);
    if (p === '/api/movi-vpn')                  return handleMoviVpn(request, env);
    if (p === '/api/movi-ssl-vpn')              return handleMoviSslVpn(request, env);
    if (p === '/api/movi-policy')               return handleMoviPolicy(request, env);
    if (p === '/api/movi-dhcp')                 return handleMoviDhcp(request, env);

    if (p === '/api/status')      return handleStatus();
    if (p === '/api/n8n')         return handleN8n(env);
    if (p === '/api/n8n/exec')    return handleExecDetail(request, env);
    if (p === '/api/9router')     return handle9Router();
    if (p === '/api/esxi')        return handleESXi(env);
    if (p === '/api/esxi/power')  return handleESXiPower(request, env);
    if (p === '/api/casaos')      return handleCasaOS(env);
    if (p === '/api/fortigate')   return handleFortigate(env, url.searchParams.has('debug'));
    if (p === '/api/asus')        return handleAsus(env);
    if (p === '/api/asus/reboot') return handleAsusReboot(request, env);
    if (p === '/proxy')           return handleProxy(request, env);

    // ── HTML pages: inject user or redirect to login ──
    if (p === '/' || p.endsWith('.html')) return injectUser(request, env);

    return env.ASSETS.fetch(request);
  },
};
