/* ═══════════════════════════════════════════════════════════════════════════
   webauthn.js — Đăng nhập bằng Passkey (vân tay/FaceID/Windows Hello), 2026-07-27
   ───────────────────────────────────────────────────────────────────────────
   Phương thức đăng nhập THỨ 2, song song với mật khẩu — KHÔNG thay thế, KHÔNG
   đụng gì vào handleLogin/mật khẩu hiện có. User tự chọn 1 trong 2 lúc đăng nhập.

   AN TOÀN: verify chữ ký/attestation dùng thư viện đã kiểm chứng
   `@simplewebauthn/server` (không tự viết CBOR decode/verify tay) — WebAuthn có
   nhiều bước xác minh tinh vi (RP ID hash, flags, signature counter, challenge,
   origin...), viết tay dễ có lỗ hổng tinh vi mà không nhận ra ngay. Thư viện chỉ
   dùng Web Crypto API (crypto.subtle) — CHẠY ĐƯỢC trên Cloudflare Workers thuần,
   KHÔNG cần bật nodejs_compat (đã tự test: dry-run bundle wrangler xác nhận
   bundle không chứa require('crypto')/require('buffer') nào).

   Đăng nhập bằng passkey KHÔNG cần thêm OTP (chốt cùng anh Thoại 2026-07-27) —
   passkey tự nó đã là 2 yếu tố (thiết bị + sinh trắc), đúng chuẩn ngành.

   Session/cookie: TÁI DÙNG nguyên xi cơ chế có sẵn (session KHÔNG phải JWT, chỉ
   là crypto.randomUUID() tra KV) — xem _createSession() bên dưới, sao chép từ
   handleMfaVerify (worker.js) để không đổi gì ở tầng session.

   Dữ liệu mới trong user:${username}:
     user.webauthnCredentials = [
       { id, publicKey, counter, transports, deviceName, createdAt }
     ]
   userID cho WebAuthn (khác username, theo yêu cầu chuẩn) = SHA-256(username)
   — deterministic, không cần field mới.

   RP ID/Origin lấy ĐỘNG từ request.url — KHÔNG hardcode, vì staging
   (*.workers.dev) và production (dashboard.home-server.id.vn) là 2 domain khác
   nhau; passkey đăng ký domain nào chỉ dùng được domain đó (đúng bản chất
   WebAuthn, không phải bug).
   ═══════════════════════════════════════════════════════════════════════════ */
import {
  generateRegistrationOptions, verifyRegistrationResponse,
  generateAuthenticationOptions, verifyAuthenticationResponse,
} from '@simplewebauthn/server';
import { getSession, rlGet, rlBump, rlClear, logActivity, _getCfg, _sha256Hex, _hexToBytes, json, SESSION_COOKIE } from './core.js';

const REG_CHALLENGE_TTL = 300;    // 5 phút để hoàn thành đăng ký passkey
const LOGIN_CHALLENGE_TTL = 120;  // 2 phút để chạm vân tay/FaceID
const LOGIN_RL_MAX = 20;          // lần thử / 5 phút / IP — chống dò credential

function rpFromRequest(request) {
  const u = new URL(request.url);
  return { rpID: u.hostname, origin: u.origin };
}

async function userIdBytes(username) {
  const hex = await _sha256Hex('webauthn-uid:' + username);
  return _hexToBytes(hex); // 32 byte, ổn định theo username, không cần lưu field mới
}

function b64urlToBytes(b64url) {
  const b64 = b64url.replace(/-/g, '+').replace(/_/g, '/').padEnd(b64url.length + (4 - b64url.length % 4) % 4, '=');
  const bin = atob(b64);
  return Uint8Array.from(bin, c => c.charCodeAt(0));
}

/* ── 1. Đăng ký passkey mới (cần đã đăng nhập) ─────────────────────────────── */
export async function handleWebauthnRegisterOptions(request, env) {
  if (request.method !== 'POST') return json({ error: 'method' }, 405);
  const session = await getSession(request, env);
  if (!session) return json({ error: 'Chưa đăng nhập' }, 401);

  const user = await env.DASHBOARD_KV.get(`user:${session.username}`, 'json');
  if (!user) return json({ error: 'Không tìm thấy tài khoản' }, 404);

  const { rpID } = rpFromRequest(request);
  const existing = (user.webauthnCredentials || []).map(c => ({
    id: c.id, type: 'public-key', transports: c.transports || undefined,
  }));

  const options = await generateRegistrationOptions({
    rpName: 'Dashboard Homelab',
    rpID,
    userID: await userIdBytes(session.username),
    userName: session.username,
    attestationType: 'none',   // không cần chứng thực nhà sản xuất thiết bị — chỉ cần khoá công khai
    excludeCredentials: existing,
    // 'preferred' — xem giải thích chi tiết ở handleWebauthnLoginOptions (lỗi
    // thật gặp với Bitwarden AutoFill trên iOS Safari). Đồng bộ 2 chiều đăng
    // ký/đăng nhập để không lặp lại đúng lỗi khi ai đăng ký thẳng trên iPhone.
    authenticatorSelection: { residentKey: 'required', userVerification: 'preferred' },
  });

  await env.DASHBOARD_KV.put(`webauthn_reg:${session.username}`, JSON.stringify({ challenge: options.challenge }), { expirationTtl: REG_CHALLENGE_TTL });
  return json({ options });
}

export async function handleWebauthnRegisterVerify(request, env) {
  if (request.method !== 'POST') return json({ error: 'method' }, 405);
  const session = await getSession(request, env);
  if (!session) return json({ error: 'Chưa đăng nhập' }, 401);

  let body; try { body = await request.json(); } catch { return json({ error: 'bad json' }, 400); }
  const deviceName = String(body.deviceName || '').trim().slice(0, 64) || 'Thiết bị không tên';
  const response = body.response;
  if (!response) return json({ error: 'Thiếu response' }, 400);

  const temp = await env.DASHBOARD_KV.get(`webauthn_reg:${session.username}`, 'json');
  if (!temp) return json({ error: 'Phiên đăng ký đã hết hạn, thử lại từ đầu.' }, 400);

  const { rpID, origin } = rpFromRequest(request);
  let verification;
  try {
    verification = await verifyRegistrationResponse({
      response, expectedChallenge: temp.challenge, expectedOrigin: origin, expectedRPID: rpID,
      requireUserVerification: false,   // đồng bộ với login-verify — xem giải thích ở đó
    });
  } catch (e) {
    return json({ error: 'Xác minh thất bại: ' + (e && e.message || e) }, 400);
  }
  if (!verification.verified || !verification.registrationInfo) return json({ error: 'Xác minh thất bại' }, 400);

  await env.DASHBOARD_KV.delete(`webauthn_reg:${session.username}`).catch(() => {});

  const { credential } = verification.registrationInfo;
  const user = await env.DASHBOARD_KV.get(`user:${session.username}`, 'json');
  if (!user) return json({ error: 'Không tìm thấy tài khoản' }, 404);
  const creds = user.webauthnCredentials || [];
  if (creds.some(c => c.id === credential.id)) return json({ error: 'Thiết bị này đã được đăng ký rồi.' }, 400);
  creds.push({
    id: credential.id,
    publicKey: btoa(String.fromCharCode(...credential.publicKey)),
    counter: credential.counter,
    transports: credential.transports || [],
    deviceName,
    createdAt: Date.now(),
  });
  user.webauthnCredentials = creds;
  await env.DASHBOARD_KV.put(`user:${session.username}`, JSON.stringify(user));
  // Chỉ mục tra ngược credentialId → username. BẮT BUỘC — login-verify KHÔNG có
  // session để biết "user:${username}" cần đọc, chỉ có credential.id trả về từ
  // trình duyệt; đây là cách duy nhất khớp lại đúng tài khoản. Không có TTL vì
  // sống cùng vòng đời passkey (xoá đi ở handleWebauthnDelete).
  await env.DASHBOARD_KV.put(`webauthn_owner:${credential.id}`, session.username);

  const ip = request.headers.get('cf-connecting-ip') || '?';
  await logActivity(env, { action: 'webauthn-register', username: session.username, ip, success: true, detail: `Thêm passkey "${deviceName}"` });
  return json({ success: true });
}

/* ── 2. Tự quản lý: xem danh sách + xoá ─────────────────────────────────────── */
export async function handleWebauthnList(request, env) {
  const session = await getSession(request, env);
  if (!session) return json({ error: 'Chưa đăng nhập' }, 401);
  const user = await env.DASHBOARD_KV.get(`user:${session.username}`, 'json');
  const creds = (user && user.webauthnCredentials || []).map(c => ({ id: c.id, deviceName: c.deviceName, createdAt: c.createdAt, transports: c.transports }));
  return json({ credentials: creds });
}

export async function handleWebauthnDelete(request, env, credentialId) {
  if (request.method !== 'DELETE') return json({ error: 'method' }, 405);
  const session = await getSession(request, env);
  if (!session) return json({ error: 'Chưa đăng nhập' }, 401);
  const user = await env.DASHBOARD_KV.get(`user:${session.username}`, 'json');
  if (!user) return json({ error: 'Không tìm thấy tài khoản' }, 404);
  const before = (user.webauthnCredentials || []).length;
  user.webauthnCredentials = (user.webauthnCredentials || []).filter(c => c.id !== credentialId);
  if (user.webauthnCredentials.length === before) return json({ error: 'Không tìm thấy passkey đó.' }, 404);
  await env.DASHBOARD_KV.put(`user:${session.username}`, JSON.stringify(user));
  await env.DASHBOARD_KV.delete(`webauthn_owner:${credentialId}`).catch(() => {});
  const ip = request.headers.get('cf-connecting-ip') || '?';
  await logActivity(env, { action: 'webauthn-delete', username: session.username, ip, success: true, detail: `Xoá passkey ${credentialId.slice(0, 12)}…` });
  return json({ success: true });
}

/* ── 3. Đăng nhập bằng passkey (KHÔNG cần session — như /api/auth/login) ────
   Discoverable credential: KHÔNG cần nhập username trước, trình duyệt tự cho
   chọn thiết bị đã đăng ký; server nhận diện user qua response.userHandle. */
export async function handleWebauthnLoginOptions(request, env) {
  if (request.method !== 'POST') return json({ error: 'method' }, 405);
  const ip = request.headers.get('cf-connecting-ip') || request.headers.get('x-forwarded-for') || 'unknown';
  const cnt = await rlGet(env, `webauthn-login:${ip}`);
  if (cnt >= LOGIN_RL_MAX) return json({ error: 'Quá nhiều yêu cầu, thử lại sau ít phút.' }, 429);
  await rlBump(env, `webauthn-login:${ip}`, 300);

  const { rpID } = rpFromRequest(request);
  // 'preferred' thay vì 'required': một số trình quản lý mật khẩu (đã gặp thật:
  // Bitwarden AutoFill Extension trên iOS Safari) từ chối hoàn tất ceremony
  // (NotAllowedError) khi bị ép "required" dù đã tự xác thực mở vault trước đó
  // — không giảm an toàn thực tế vì Bitwarden/1Password/OS đều đòi mở khoá
  // (vân tay/FaceID/master password) TRƯỚC KHI giao credential, bất kể cờ này.
  const options = await generateAuthenticationOptions({ rpID, userVerification: 'preferred' });
  const token = crypto.randomUUID();
  await env.DASHBOARD_KV.put(`webauthn_login:${token}`, JSON.stringify({ challenge: options.challenge }), { expirationTtl: LOGIN_CHALLENGE_TTL });
  return json({ token, options });
}

export async function handleWebauthnLoginVerify(request, env, ctx) {
  if (request.method !== 'POST') return json({ error: 'method' }, 405);
  const ip = request.headers.get('cf-connecting-ip') || request.headers.get('x-forwarded-for') || 'unknown';
  if ((await rlGet(env, `webauthn-login:${ip}`)) >= LOGIN_RL_MAX) return json({ error: 'Quá nhiều yêu cầu, thử lại sau ít phút.' }, 429);
  await rlBump(env, `webauthn-login:${ip}`, 300);

  let body; try { body = await request.json(); } catch { return json({ error: 'bad json' }, 400); }
  const { token, response } = body || {};
  if (!token || !response) return json({ error: 'Thiếu token hoặc response' }, 400);

  const temp = await env.DASHBOARD_KV.get(`webauthn_login:${token}`, 'json');
  if (!temp) return json({ error: 'Phiên đăng nhập đã hết hạn, thử lại.' }, 401);
  await env.DASHBOARD_KV.delete(`webauthn_login:${token}`).catch(() => {});

  // response.response.userHandle = base64url(userID) mà ta gán lúc đăng ký (SHA-256 username)
  // → phải dò username khớp hash, vì userID không tự giải mã ngược ra username được.
  const userHandleB64 = response.response && response.response.userHandle;
  if (!userHandleB64) return json({ error: 'Thiếu userHandle — thiết bị không hỗ trợ discoverable credential' }, 400);

  const credId = response.id || response.rawId;
  if (!credId) return json({ error: 'Thiếu credential id' }, 400);

  // Tra username: user KV lưu credential.id → tra ngược qua KV index nhỏ (tạo lúc đăng ký).
  const owner = await env.DASHBOARD_KV.get(`webauthn_owner:${credId}`);
  if (!owner) return json({ error: 'Không nhận diện được passkey này (có thể đã bị xoá).' }, 401);

  const user = await env.DASHBOARD_KV.get(`user:${owner}`, 'json');
  if (!user) return json({ error: 'Không tìm thấy tài khoản' }, 404);
  const cred = (user.webauthnCredentials || []).find(c => c.id === credId);
  if (!cred) return json({ error: 'Không tìm thấy passkey này trên tài khoản.' }, 401);

  const { rpID, origin } = rpFromRequest(request);
  let verification;
  try {
    verification = await verifyAuthenticationResponse({
      response, expectedChallenge: temp.challenge, expectedOrigin: origin, expectedRPID: rpID,
      credential: {
        id: cred.id,
        publicKey: Uint8Array.from(atob(cred.publicKey), c => c.charCodeAt(0)),
        counter: cred.counter,
        transports: cred.transports,
      },
      // Mặc định thư viện là true, ĐỘC LẬP với userVerification:'preferred' đã
      // gửi cho client ở login-options — nếu không đồng bộ ở đây, một số trình
      // quản lý mật khẩu (Bitwarden AutoFill trên iOS Safari — lỗi thật đã gặp
      // 2026-07-27) không luôn bật cờ UV trong assertion dù đã tự mở khoá vault
      // trước đó → verify sẽ bị từ chối dù ceremony phía client đã thành công.
      requireUserVerification: false,
    });
  } catch (e) {
    await logActivity(env, { action: 'webauthn-login-fail', username: owner, ip, success: false, detail: String(e && e.message || e) });
    return json({ error: 'Xác minh thất bại: ' + (e && e.message || e) }, 401);
  }
  if (!verification.verified) {
    await logActivity(env, { action: 'webauthn-login-fail', username: owner, ip, success: false, detail: 'verify() trả false' });
    return json({ error: 'Xác minh thất bại' }, 401);
  }

  // Cập nhật counter chống replay (đúng chuẩn WebAuthn: counter phải luôn tăng)
  cred.counter = verification.authenticationInfo.newCounter;
  await env.DASHBOARD_KV.put(`user:${owner}`, JSON.stringify(user));
  await rlClear(env, `webauthn-login:${ip}`);

  // Tạo session ĐẦY ĐỦ ngay — KHÔNG bắt thêm OTP (đã chốt cùng anh Thoại).
  // Sao chép nguyên xi cấu trúc session/cookie từ handleMfaVerify (worker.js).
  const cfg = await _getCfg(env);
  const sessionTtl = Math.max(1, (user.sessionTtlHours || cfg.sessionTtlHours || 8)) * 3600;
  const sessToken = crypto.randomUUID();
  const canManagePerms = user.canManagePerms || [];
  await env.DASHBOARD_KV.put(`session:${sessToken}`, JSON.stringify({
    username: owner, role: user.role, permissions: user.permissions || {},
    canManagePerms, boundIp: ip, createdAt: Date.now(),
    expires: Date.now() + sessionTtl * 1000,
    authMethod: 'webauthn',
  }), { expirationTtl: sessionTtl });

  const userInfo = encodeURIComponent(JSON.stringify({
    username: owner, role: user.role, permissions: user.permissions || {},
    isAdmin: user.role === 'admin', canManagePerms,
  }));
  const h = new Headers({ 'Content-Type': 'application/json' });
  h.append('Set-Cookie', `${SESSION_COOKIE}=${sessToken}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${sessionTtl}`);
  h.append('Set-Cookie', `dh_user=${userInfo}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${sessionTtl}`);
  await logActivity(env, { action: 'webauthn-login-success', username: owner, ip, success: true });
  if (ctx) { /* notifyEmail nếu cần sau này — giữ tối giản cho v1 */ }
  return new Response(JSON.stringify({ success: true, role: user.role }), { status: 200, headers: h });
}
