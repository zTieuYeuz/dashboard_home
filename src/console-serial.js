/* ═══════════════════════════════════════════════════════════════════
   Web Console (Serial) — AI proxy → 9Router
   -------------------------------------------------------------------
   Trang public/service-home/console-serial.html dùng Web Serial API để
   đọc/ghi THẲNG cổng COM (dây console USB-to-Serial) ngay trong trình
   duyệt — không qua Worker, không cần Internet cho phần kết nối gốc.
   Worker CHỈ đóng 2 vai: (1) phục vụ trang HTML (gate bằng session +
   quyền 'console-serial' qua _PAGE_PERM), (2) proxy chat AI ở đây.

   Quyền TÁCH RIÊNG khỏi 'ssh' (đã chốt với anh Thoại 2026-07-25): đây là
   thao tác trên THIẾT BỊ VẬT LÝ tại hiện trường (switch/router qua dây
   console), rủi ro khác hẳn SSH vào server — nên cấp quyền độc lập.

   Cùng pattern CSRF/rate-limit/model-allowlist như handleTermixLlm
   (src/termix.js) — xem file đó để biết lý do từng bước chặn.
   ═══════════════════════════════════════════════════════════════════ */
import { getSession, hasPerm, logActivity } from './core.js';

const CS_NINE_ROUTER = 'https://9router.home-server.id.vn/v1/chat/completions';
const CS_LLM_MODELS  = new Set(['pnetlab', 'AI-Home']);
const CS_LLM_RL_MAX  = 60;   // request / 5 phút / user

export async function handleConsoleSerialLlm(request, env) {
  const j = (obj, status) => new Response(JSON.stringify(obj), { status, headers: { 'Content-Type': 'application/json' } });
  if (request.method !== 'POST') return j({ error: 'method' }, 405);

  // CSRF: chỉ nhận same-origin (giống /api/termix-llm)
  const sfs = request.headers.get('Sec-Fetch-Site');
  if (sfs && sfs !== 'same-origin') return j({ error: 'forbidden: cross-site request bị chặn' }, 403);
  const origin = request.headers.get('Origin');
  if (origin) {
    try { if (new URL(origin).host !== new URL(request.url).host) return j({ error: 'forbidden: origin mismatch' }, 403); }
    catch { return j({ error: 'bad origin' }, 403); }
  }

  const session = await getSession(request, env);
  if (!session) return j({ error: 'Chưa đăng nhập dashboard' }, 401);
  if (!(await hasPerm(env, session, 'console-serial'))) return j({ error: 'Không có quyền Web Console (Serial)' }, 403);

  const key = env.NINE_ROUTER_KEY;
  if (!key) return j({ error: 'Chưa cấu hình NINE_ROUTER_KEY (wrangler secret put NINE_ROUTER_KEY).' }, 503);

  const rlKey = 'conserialllm:rl:' + session.username;
  const cnt = parseInt((await env.DASHBOARD_KV.get(rlKey)) || '0', 10);
  if (cnt >= CS_LLM_RL_MAX) return j({ error: 'Quá nhiều yêu cầu, thử lại sau ít phút.' }, 429);
  await env.DASHBOARD_KV.put(rlKey, String(cnt + 1), { expirationTtl: 300 });

  let body; try { body = await request.json(); } catch { return j({ error: 'bad json' }, 400); }
  const model = CS_LLM_MODELS.has(body.model) ? body.model : 'pnetlab';
  const payload = Object.assign({}, body, { model, stream: true });

  let upstream;
  try {
    upstream = await fetch(CS_NINE_ROUTER, {
      method: 'POST',
      headers: { 'Authorization': 'Bearer ' + key, 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
  } catch (e) { return j({ error: '9Router không phản hồi: ' + ((e && e.message) || e) }, 502); }

  return new Response(upstream.body, {
    status: upstream.status,
    headers: { 'Content-Type': 'text/event-stream; charset=utf-8', 'Cache-Control': 'no-cache' },
  });
}

/* ═══════════════════════════════════════════════════════════════════
   Console Relay — "🙋 Nhờ hỗ trợ" (2026-07-25)
   -------------------------------------------------------------------
   Vì sao cần: người hiện trường có thể là NGƯỜI NGOÀI (chỉ mở link web,
   không có RustDesk/phần mềm cài sẵn). Web Serial là phần cứng LOCAL —
   2 trình duyệt ở 2 nơi không tự "thấy" nhau — nên cần relay qua KV để
   anh Thoại xem output + gõ lệnh từ xa vào ĐÚNG phiên console của họ.

   Kiến trúc: polling qua KV (~1s/lần), KHÔNG dùng Durable Objects (chưa
   bật trên plan hiện tại, tránh phát sinh chi phí) — đủ mượt cho việc
   hướng dẫn từ xa, không cần tức thời như xem màn hình trực tiếp.

   AN TOÀN — người hiện trường LUÔN được ưu tiên tuyệt đối:
   - Field tech chủ động bật chia sẻ (KHÔNG ai xem lén được), có nút tắt
     bất cứ lúc nào, luôn thấy banner đang chia sẻ.
   - "Khoá lượt" một chiều: nếu field tech vừa gõ trong CS_FIELD_BUSY_MS
     gần nhất, lệnh remote của helper bị TỪ CHỐI (409) — không bao giờ
     2 nguồn cùng ghi đè vào 1 thiết bị vật lý cùng lúc.
   - token (32 hex, bí mật) tách biệt với code (6 số, đọc qua điện thoại)
     — code dùng để JOIN (qua session dashboard), token dùng để field
     tech tự xác thực các API push/pull tần suất cao mà không cần session
     check nặng mỗi lần (đã qua session-gate 1 lần lúc create()).
   - Mọi endpoint đều yêu cầu session dashboard + quyền 'console-serial'
     hợp lệ (không riêng gì token) — chặn người ngoài dò mã suông.

   ⚠️ KHÔNG RACE CONDITION — bài học thực tế (2026-07-25): bản đầu dùng 1
   object sess DUY NHẤT cho cả output/command, và field's loop gọi 2 API
   riêng (push-output + pull-command) GẦN NHƯ ĐỒNG THỜI mỗi giây. Workers
   KV KHÔNG có giao dịch/khoá — 2 request cùng đọc-sửa-ghi 1 key sẽ RACE:
   request ghi SAU đè mất thay đổi của request ghi TRƯỚC (mỗi request chỉ
   biết bản nó đọc được, không biết request kia vừa đổi gì) → gây trộn
   lẫn/lặp/mất chữ (đã xảy ra thật: output hiện lẫn lộn, lặp header).
   FIX: tách 3 khối dữ liệu, MỖI KHỐI CHỈ DUY NHẤT 1 BÊN ĐƯỢC GHI:
   - `consrelay:out:<sid>`  → CHỈ field-sync ghi (helper chỉ ĐỌC, tự tính
     phần mới bằng con trỏ độ dài phía client, không có bên thứ 2 ghi).
   - `consrelay:cmd:<sid>`  → CHỈ push-command (helper) ghi (field-sync
     chỉ ĐỌC, so `ts` với con trỏ cục bộ để biết lệnh mới hay đã xử lý).
   - `consrelay:sess:<sid>` → metadata ít đổi (token/owner/helperJoined/
     lastFieldActivity) — tần suất ghi thấp hơn NHIỀU so với output/lệnh
     nên rủi ro race chấp nhận được (không còn là đường dẫn dữ liệu chính).
   ═══════════════════════════════════════════════════════════════════ */
const CS_RELAY_TTL       = 3600;   // phiên tự dọn sau 1 giờ không dùng
const CS_RELAY_MAXBUF    = 200000; // giới hạn buffer output (ký tự) — cắt bớt đầu nếu vượt
const CS_FIELD_BUSY_MS   = 3000;   // field tech vừa gõ trong X ms gần nhất → khoá lệnh remote
const CS_JOIN_RL_MAX     = 20;     // số lần thử mã / 5 phút / user — chống dò mã 6 số

function _csRandCode() {
  return String(Math.floor(100000 + (crypto.getRandomValues(new Uint32Array(1))[0] % 900000)));
}
function _csRandToken() {
  const b = crypto.getRandomValues(new Uint8Array(20));
  return Array.from(b).map(x => x.toString(16).padStart(2, '0')).join('');
}

async function _csAuth(request, env) {
  const session = await getSession(request, env);
  if (!session) return { err: new Response(JSON.stringify({ error: 'Chưa đăng nhập dashboard' }), { status: 401, headers: { 'Content-Type': 'application/json' } }) };
  if (!(await hasPerm(env, session, 'console-serial'))) {
    return { err: new Response(JSON.stringify({ error: 'Không có quyền Web Console (Serial)' }), { status: 403, headers: { 'Content-Type': 'application/json' } }) };
  }
  return { session };
}

function _csJson(obj, status) { return new Response(JSON.stringify(obj), { status: status || 200, headers: { 'Content-Type': 'application/json' } }); }

// POST /api/console-relay/create — người hiện trường bấm "🙋 Nhờ hỗ trợ"
export async function handleConsoleRelayCreate(request, env) {
  if (request.method !== 'POST') return _csJson({ error: 'method' }, 405);
  const { session, err } = await _csAuth(request, env);
  if (err) return err;

  let code, tries = 0;
  do {
    code = _csRandCode();
    tries++;
  } while (tries < 5 && await env.DASHBOARD_KV.get('consrelay:code:' + code));

  const sid = crypto.randomUUID();
  const token = _csRandToken();
  const sess = {
    code, token, owner: session.username,
    createdAt: Date.now(), lastFieldActivity: Date.now(),
    helperJoined: false, helperUsername: null,
  };
  await env.DASHBOARD_KV.put('consrelay:code:' + code, sid, { expirationTtl: CS_RELAY_TTL });
  await env.DASHBOARD_KV.put('consrelay:sess:' + sid, JSON.stringify(sess), { expirationTtl: CS_RELAY_TTL });

  await logActivity(env, { action: 'console-relay-create', username: session.username, ip: request.headers.get('cf-connecting-ip') || '?', success: true, detail: `Tạo phiên nhờ hỗ trợ, mã ${code}` });
  return _csJson({ ok: true, sid, token, code });
}

// POST /api/console-relay/join {code} — anh Thoại nhập mã để vào hỗ trợ
export async function handleConsoleRelayJoin(request, env) {
  if (request.method !== 'POST') return _csJson({ error: 'method' }, 405);
  const { session, err } = await _csAuth(request, env);
  if (err) return err;

  const rlKey = 'consrelay:joinrl:' + session.username;
  const cnt = parseInt((await env.DASHBOARD_KV.get(rlKey)) || '0', 10);
  if (cnt >= CS_JOIN_RL_MAX) return _csJson({ error: 'Thử quá nhiều lần, đợi vài phút rồi thử lại.' }, 429);
  await env.DASHBOARD_KV.put(rlKey, String(cnt + 1), { expirationTtl: 300 });

  let body; try { body = await request.json(); } catch { return _csJson({ error: 'bad json' }, 400); }
  const code = String(body.code || '').replace(/\D/g, '');
  if (code.length !== 6) return _csJson({ error: 'Mã phải gồm 6 chữ số.' }, 400);

  const sid = await env.DASHBOARD_KV.get('consrelay:code:' + code);
  if (!sid) return _csJson({ error: 'Mã không đúng hoặc đã hết hạn.' }, 404);
  const raw = await env.DASHBOARD_KV.get('consrelay:sess:' + sid);
  if (!raw) return _csJson({ error: 'Phiên không còn tồn tại.' }, 404);
  const sess = JSON.parse(raw);

  sess.helperJoined = true;
  sess.helperUsername = session.username;
  await env.DASHBOARD_KV.put('consrelay:sess:' + sid, JSON.stringify(sess), { expirationTtl: CS_RELAY_TTL });

  await logActivity(env, { action: 'console-relay-join', username: session.username, ip: request.headers.get('cf-connecting-ip') || '?', success: true, detail: `Vào hỗ trợ phiên của ${sess.owner}, mã ${code}` });
  return _csJson({ ok: true, sid, owner: sess.owner });
}

// POST /api/console-relay/field-sync {sid, token, text} — field tech: đẩy output mới (nếu có)
// + đọc lệnh helper gửi (read-only) TRONG CÙNG 1 lượt gọi. Gộp 2 việc lại để field's loop
// chỉ còn 1 request/giây thay vì 2 request riêng chạy gần như đồng thời (nguồn gây race cũ).
export async function handleConsoleRelayFieldSync(request, env) {
  if (request.method !== 'POST') return _csJson({ error: 'method' }, 405);
  const { err } = await _csAuth(request, env);
  if (err) return err;

  let body; try { body = await request.json(); } catch { return _csJson({ error: 'bad json' }, 400); }
  const { sid, token, text } = body || {};
  if (!sid || !token) return _csJson({ error: 'Thiếu sid/token' }, 400);

  const raw = await env.DASHBOARD_KV.get('consrelay:sess:' + sid);
  if (!raw) return _csJson({ error: 'Phiên không còn tồn tại.' }, 404);
  const sess = JSON.parse(raw);
  if (sess.token !== token) return _csJson({ error: 'Token sai — không phải chủ phiên.' }, 403);

  // Ghi output — CHỈ handler này (field-sync) từng ghi key này → không có ai tranh ghi cùng lúc.
  if (typeof text === 'string' && text) {
    const cur = (await env.DASHBOARD_KV.get('consrelay:out:' + sid)) || '';
    await env.DASHBOARD_KV.put('consrelay:out:' + sid, (cur + text).slice(-CS_RELAY_MAXBUF), { expirationTtl: CS_RELAY_TTL });
  }

  // Đọc lệnh helper gửi — CHỈ ĐỌC (push-command mới là bên ghi), field tự so `ts` phía
  // client để biết lệnh mới hay đã xử lý rồi, nên không cần "xoá" ở đây (không ghi = không race).
  const cmdRaw = await env.DASHBOARD_KV.get('consrelay:cmd:' + sid);
  const cmd = cmdRaw ? JSON.parse(cmdRaw) : null;

  // helperJoined/helperUsername: TIỆN THỂ trả kèm từ chính `sess` đã đọc ở trên (không tốn
  // thêm lượt đọc KV nào) — để field tech's UI biết ngay khi có người vào hỗ trợ.
  return _csJson({
    ok: true, command: cmd ? cmd.command : null, ts: cmd ? cmd.ts : 0,
    helperJoined: !!sess.helperJoined, helperUsername: sess.helperUsername || null,
  });
}

// GET /api/console-relay/pull-output?sid= — helper: ĐỌC toàn bộ buffer hiện có (read-only,
// KHÔNG xoá/ghi gì) — client tự tính phần MỚI bằng con trỏ độ dài đã thấy trước đó.
export async function handleConsoleRelayPullOutput(request, env) {
  const { session, err } = await _csAuth(request, env);
  if (err) return err;

  const url = new URL(request.url);
  const sid = url.searchParams.get('sid') || '';
  const raw = await env.DASHBOARD_KV.get('consrelay:sess:' + sid);
  if (!raw) return _csJson({ error: 'Phiên không còn tồn tại (có thể đã bị dừng).' }, 404);
  const sess = JSON.parse(raw);
  if (sess.helperUsername !== session.username) return _csJson({ error: 'Bạn chưa vào phiên này.' }, 403);

  const text = (await env.DASHBOARD_KV.get('consrelay:out:' + sid)) || '';
  return _csJson({ ok: true, text });
}

// POST /api/console-relay/field-activity {sid, token} — field tech tự gõ (cập nhật mốc "đang bận")
export async function handleConsoleRelayFieldActivity(request, env) {
  if (request.method !== 'POST') return _csJson({ error: 'method' }, 405);
  const { err } = await _csAuth(request, env);
  if (err) return err;

  let body; try { body = await request.json(); } catch { return _csJson({ error: 'bad json' }, 400); }
  const { sid, token } = body || {};
  const raw = await env.DASHBOARD_KV.get('consrelay:sess:' + sid);
  if (!raw) return _csJson({ error: 'Phiên không còn tồn tại.' }, 404);
  const sess = JSON.parse(raw);
  if (sess.token !== token) return _csJson({ error: 'Token sai.' }, 403);

  sess.lastFieldActivity = Date.now();
  await env.DASHBOARD_KV.put('consrelay:sess:' + sid, JSON.stringify(sess), { expirationTtl: CS_RELAY_TTL });
  return _csJson({ ok: true });
}

// POST /api/console-relay/push-command {sid, command} — helper (anh) gửi lệnh muốn chèn
export async function handleConsoleRelayPushCommand(request, env) {
  if (request.method !== 'POST') return _csJson({ error: 'method' }, 405);
  const { session, err } = await _csAuth(request, env);
  if (err) return err;

  let body; try { body = await request.json(); } catch { return _csJson({ error: 'bad json' }, 400); }
  const { sid, command } = body || {};
  if (typeof command !== 'string' || !command) return _csJson({ error: 'Thiếu command.' }, 400);

  const raw = await env.DASHBOARD_KV.get('consrelay:sess:' + sid);
  if (!raw) return _csJson({ error: 'Phiên không còn tồn tại.' }, 404);
  const sess = JSON.parse(raw);
  if (sess.helperUsername !== session.username) return _csJson({ error: 'Bạn chưa vào phiên này.' }, 403);

  // Khoá lượt: người hiện trường vừa gõ gần đây → từ chối, KHÔNG bao giờ chèn đè lên họ
  if (Date.now() - sess.lastFieldActivity < CS_FIELD_BUSY_MS) {
    return _csJson({ error: 'field_busy', message: 'Người hiện trường đang thao tác — đợi vài giây rồi thử lại.' }, 409);
  }

  // Ghi vào key RIÊNG (chỉ push-command từng ghi key này) — field-sync chỉ ĐỌC, dùng `ts`
  // (mili-giây tăng dần tự nhiên) để tự biết lệnh nào MỚI, không cần "xoá" nên không race.
  await env.DASHBOARD_KV.put('consrelay:cmd:' + sid, JSON.stringify({ command, ts: Date.now() }), { expirationTtl: CS_RELAY_TTL });
  await logActivity(env, { action: 'console-relay-command', username: session.username, ip: request.headers.get('cf-connecting-ip') || '?', success: true, detail: `Gửi lệnh từ xa vào phiên của ${sess.owner}: ${command.slice(0, 200)}` });
  return _csJson({ ok: true });
}

// POST /api/console-relay/stop {sid, token} — field tech chủ động dừng chia sẻ
export async function handleConsoleRelayStop(request, env) {
  if (request.method !== 'POST') return _csJson({ error: 'method' }, 405);
  const { session, err } = await _csAuth(request, env);
  if (err) return err;

  let body; try { body = await request.json(); } catch { return _csJson({ error: 'bad json' }, 400); }
  const { sid, token } = body || {};
  const raw = await env.DASHBOARD_KV.get('consrelay:sess:' + sid);
  if (raw) {
    const sess = JSON.parse(raw);
    if (sess.token !== token) return _csJson({ error: 'Token sai.' }, 403);
    await env.DASHBOARD_KV.delete('consrelay:code:' + sess.code);
    await env.DASHBOARD_KV.delete('consrelay:sess:' + sid);
    await env.DASHBOARD_KV.delete('consrelay:out:' + sid);
    await env.DASHBOARD_KV.delete('consrelay:cmd:' + sid);
    await logActivity(env, { action: 'console-relay-stop', username: session.username, ip: request.headers.get('cf-connecting-ip') || '?', success: true, detail: `Dừng chia sẻ phiên ${sess.code}` });
  }
  return _csJson({ ok: true });
}
