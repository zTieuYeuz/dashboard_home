/* ── Proxy ConsolePi ────────────────────────────────────────────────────────
   Đưa https://consolepi.home-server.id.vn về dưới /consolepi-proxy/* của chính
   dashboard, để nhúng iframe được.

   VÌ SAO PHẢI PROXY (đo thật 2026-08-31): nhúng thẳng thì gõ đúng user/pass vẫn
   không vào được — ConsolePi cấp cookie phiên bình thường, nhưng dashboard và
   ConsolePi là HAI SITE KHÁC NHAU, nên cookie đó là "cookie bên thứ ba" trong
   iframe và bị Chrome/Edge vứt đi. ConsolePi hỏi lại "anh là ai?" → quay về trang
   đăng nhập. Anh Thoại xác nhận mở tab riêng thì đăng nhập được — đúng dấu hiệu.
   Đi qua đường này thì với trình duyệt cookie thành CÙNG SITE nên không bị chặn.
   Cùng loại bệnh và cùng cách chữa như /n8n-proxy (xem handleN8nHomeProxy).

   ⚠️ BÀI HỌC ĐÃ TRẢ GIÁ Ở n8n — KHÔNG ĐƯỢC LẶP LẠI:
   TUYỆT ĐỐI không đọc-rồi-regex mọi file JS. Bản n8n cũ làm vậy, gặp bundle vài MB
   là đốt sạch hạn mức CPU của một request → 502 → app kẹt nửa chừng, triệu chứng
   trông y hệt lỗi mạng nên rất lâu mới lần ra. Ở đây CHỈ viết lại HTML (trang
   ConsolePi rất nhỏ — trang đăng nhập chỉ 1.900 byte), còn JS/CSS/ảnh chuyển
   thẳng dạng luồng, không đệm, không regex. */

import { getSession, hasPerm, bridgeWebSocket, cleanEnv } from './core.js';

const CP_ORIGIN = 'https://consolepi.home-server.id.vn';
const CP_PREFIX = '/consolepi-proxy';

/* ── Vé vào cửa cho Worker (Cloudflare Access Service Token) ─────────────────
   Dùng khi anh Thoại khoá consolepi.home-server.id.vn bằng Cloudflare Access
   với chính sách Service Auth, để CHỈ vào được qua dashboard:
     • Worker gọi kèm cặp mã này  → Cloudflare cho qua
     • Người ngoài mở thẳng địa chỉ → không có mã → Cloudflare chặn ngay ở biên,
       chưa từng chạm tới thiết bị

   Cùng khuôn với 6 dịch vụ khác trong dự án (TERMIX_HOME_CF_*, HOME_CAM_CF_*,
   PNETLAB_HOME_CF_*, FGT_POOL_CF_*…) — mỗi dịch vụ một cặp riêng, để lộ cặp nào
   thì thu hồi cặp đó, không kéo sập mọi thứ.

   CHƯA khai mã thì bỏ qua, proxy chạy y như cũ — nên đặt sẵn phần này TRƯỚC lúc
   bật khoá là an toàn: bật xong dashboard vào được ngay, không có khoảng đứt.
   `cleanEnv` cắt dấu BOM và khoảng trắng thừa — secret dán từ Cloudflare hay
   dính, mà dính thì Access từ chối với thông báo rất khó hiểu. */
function veVaoCua(env) {
  const id  = cleanEnv(env.CONSOLEPI_CF_CLIENT_ID);
  const sec = cleanEnv(env.CONSOLEPI_CF_CLIENT_SECRET);
  return (id && sec) ? { id, sec } : null;
}

/* Đường dẫn tuyệt đối trong HTML (vd src="/vkeyboard.js") sẽ trỏ về GỐC dashboard
   chứ không phải vào proxy — đúng cái bẫy đã làm trắng trang PNETLab. Nên phải
   gắn tiền tố vào. Chỉ đụng src/href/action, và CHỪA các đường đã có tiền tố,
   đường dẫn giao thức (//), dữ liệu nhúng (data:) và neo trong trang (#). */
function themTienTo(html) {
  return html.replace(
    /(\s(?:src|href|action)\s*=\s*["'])\/(?!\/|consolepi-proxy\/)/gi,
    '$1' + CP_PREFIX + '/'
  );
}

export async function handleConsolePiProxy(request, env) {
  /* Gác quyền NGAY ĐẦU: đường này mở thẳng vào console của thiết bị mạng, để hở
     là người ngoài chạm được cổng console. Kiểm cả phiên lẫn quyền 'consolepi'
     — cùng khoá mà trang /service-home/consolepi.html dùng, khớp với registry. */
  const session = await getSession(request, env);
  if (!session) return new Response('Unauthorized', { status: 401 });
  if (!(await hasPerm(env, session, 'consolepi'))) return new Response('Forbidden', { status: 403 });

  const reqUrl = new URL(request.url);
  /* Gộp tiền tố lặp (/consolepi-proxy/consolepi-proxy/...) — sinh ra khi trang con
     dựng URL từ đường đã có sẵn tiền tố. Cùng lớp phòng thủ như bên n8n. */
  const subPath = reqUrl.pathname.replace(/^(?:\/consolepi-proxy)+/, '') || '/';
  const target = CP_ORIGIN + subPath + reqUrl.search;

  /* ── WebSocket ────────────────────────────────────────────────────────────
     Màn hình console thường chạy trên WebSocket. Theo đúng khuôn đã ổn định ở
     termix.js/pnetlab.js: fetch tới https:// (KHÔNG dùng wss://) và CHỈ set
     Upgrade — Connection/Sec-WebSocket-Version do Workers tự quản, tự set tay là
     `response.webSocket` thành null. */
  if ((request.headers.get('Upgrade') || '').toLowerCase() === 'websocket') {
    const wsHeaders = new Headers();
    wsHeaders.set('Upgrade', 'websocket');
    wsHeaders.set('Host', new URL(CP_ORIGIN).hostname);
    wsHeaders.set('Origin', CP_ORIGIN);
    const ckWs = (request.headers.get('cookie') || '').split(';').map(c => c.trim())
      .filter(c => c && !c.startsWith('dh_session=') && !c.startsWith('dh_user='))
      .join('; ');
    if (ckWs) wsHeaders.set('Cookie', ckWs);
    const swp = request.headers.get('Sec-WebSocket-Protocol');
    if (swp) wsHeaders.set('Sec-WebSocket-Protocol', swp);
    const veWs = veVaoCua(env);
    if (veWs) {
      wsHeaders.set('CF-Access-Client-Id',     veWs.id);
      wsHeaders.set('CF-Access-Client-Secret', veWs.sec);
    }

    let upResp;
    try { upResp = await fetch(target, { headers: wsHeaders }); }
    catch (e) { return new Response('ConsolePi WS error: ' + e.message, { status: 502 }); }

    const upSock = upResp.webSocket;
    if (!upSock) {
      const body = await upResp.text().catch(() => '(no body)');
      return new Response(
        'ConsolePi WS: upstream không nâng cấp được (HTTP ' + upResp.status + ') — ' + body.slice(0, 300),
        { status: 502 });
    }

    const { 0: client, 1: server } = new WebSocketPair();
    server.accept();
    upSock.accept();
    bridgeWebSocket(server, upSock, { tag: 'consolepi-ws' });

    const rhWs = new Headers();
    const proto = upResp.headers.get('Sec-WebSocket-Protocol');
    if (proto) rhWs.set('Sec-WebSocket-Protocol', proto);
    return new Response(null, { status: 101, webSocket: client, headers: rhWs });
  }

  /* ── HTTP thường ─────────────────────────────────────────────────────────── */
  const fwd = new Headers(request.headers);
  fwd.set('Host', new URL(CP_ORIGIN).hostname);
  /* Ép Origin/Referer về chính ConsolePi: form đăng nhập thường kiểm hai thứ này
     để chống giả mạo, thấy tên miền dashboard là từ chối. */
  fwd.set('Origin', CP_ORIGIN);
  const ref = request.headers.get('Referer');
  if (ref) fwd.set('Referer', ref.split(reqUrl.origin + CP_PREFIX).join(CP_ORIGIN).split(reqUrl.origin).join(CP_ORIGIN));
  /* Bỏ cookie phiên của dashboard — ConsolePi không cần, gửi sang là rò thông tin. */
  const sach = (request.headers.get('cookie') || '').split(';').map(c => c.trim())
    .filter(c => c && !c.startsWith('dh_session=') && !c.startsWith('dh_user='))
    .join('; ');
  if (sach) fwd.set('Cookie', sach); else fwd.delete('Cookie');
  const ve = veVaoCua(env);
  if (ve) {
    fwd.set('CF-Access-Client-Id',     ve.id);
    fwd.set('CF-Access-Client-Secret', ve.sec);
  }

  let upstream;
  try {
    upstream = await fetch(target, {
      method: request.method,
      headers: fwd,
      body: (request.method === 'GET' || request.method === 'HEAD') ? undefined : request.body,
      redirect: 'manual',
      signal: AbortSignal.timeout(20000),
    });
  } catch (e) {
    return new Response('ConsolePi không phản hồi: ' + e.message, { status: 502 });
  }

  const rh = new Headers(upstream.headers);
  /* Gỡ hai header chặn nhúng nếu ConsolePi có ngày nào đó thêm vào — giờ chưa có,
     nhưng thêm rồi thì khung trắng mà không báo gì cả. */
  rh.delete('X-Frame-Options');
  rh.delete('Content-Security-Policy');
  rh.delete('Content-Length');       // sửa HTML xong là độ dài đổi

  /* ⚠️ PHẢI dùng getSetCookie(): Headers gộp nhiều Set-Cookie thành MỘT chuỗi,
     lấy bằng .get() là mất hết cookie phiên trừ cái đầu. Đúng lỗi đã làm proxy
     PNETLab "đăng nhập OK nhưng trang trắng" ngày 2026-07-27. */
  rh.delete('Set-Cookie');
  let rawCookies = [];
  try { rawCookies = upstream.headers.getSetCookie(); }
  catch (e) { const h = upstream.headers.get('set-cookie'); if (h) rawCookies = [h]; }
  for (const c of rawCookies) {
    rh.append('Set-Cookie', String(c)
      .replace(/;\s*Domain=[^;,]*/gi, '')          // bỏ Domain của ConsolePi → cookie thuộc dashboard
      .replace(/;\s*SameSite=\w+/gi, '')
      + '; SameSite=Lax');
  }

  /* Chuyển hướng: kéo về trong proxy, nếu không trình duyệt nhảy thẳng ra ngoài
     và lại rơi đúng vào cảnh cookie bên thứ ba. */
  const loc = upstream.headers.get('Location');
  if (loc) {
    if (loc.indexOf(CP_ORIGIN) === 0) rh.set('Location', CP_PREFIX + loc.slice(CP_ORIGIN.length));
    else if (loc.charAt(0) === '/' && loc.indexOf(CP_PREFIX) !== 0) rh.set('Location', CP_PREFIX + loc);
  }

  const ct = upstream.headers.get('Content-Type') || '';
  if (ct.includes('text/html')) {
    const html = await upstream.text();
    return new Response(themTienTo(html), { status: upstream.status, headers: rh });
  }
  /* Mọi thứ còn lại (JS, CSS, ảnh, JSON) — CHUYỂN THẲNG dạng luồng.
     Không đọc vào bộ nhớ, không regex. Xem lý do ở đầu file. */
  return new Response(upstream.body, { status: upstream.status, headers: rh });
}
