/* ═══════════════════════════════════════════════
   termix.js — split out of worker.js (2026-07-01). Logic UNCHANGED.
   ═══════════════════════════════════════════════ */
import {
  _escHtml,
  cleanEnv,
  getSession,
  hasPerm,
  json,
  logActivity
} from './core.js';

export async function handleSshMoviToken(request, env) {
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
export async function handleSshMoviVerify(request, env) {
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

export async function handleTermixProxy(request, env, opts) {
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
    // CF Workers: fetch the https:// target with only Upgrade header — Connection/Sec-WebSocket-*
    // are managed internally by Workers (giống camera proxy đã chạy ổn). KHÔNG dùng wss:// scheme
    // và KHÔNG tự set Connection/Sec-WebSocket-Version → nếu không, response.webSocket = null.
    const wsTarget = target;
    upHeaders.set('Upgrade', 'websocket');
    // Set Origin to the Termix origin so Guacamole accepts the connection (chống cross-origin reject)
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

    // [Defensive] Nếu upstream redirect tới CF Access login (cloudflareaccess.com) → service token
    // KHÔNG hợp lệ/thiếu. KHÔNG đẩy redirect này về browser (sẽ lạc sang CF Access của upstream).
    // Báo lỗi rõ để dễ sửa (thường do thiếu secret service token trên worker).
    if (/cloudflareaccess\.com/i.test(_loc)) {
      return new Response(
        `<html><body style="font:14px system-ui;padding:2rem;background:#1a1a2e;color:#e0e0e0">
          <h2 style="color:#ff6b6b">⚠ ${_escHtml(opts.label)} — Service token không hợp lệ</h2>
          <p>Worker proxy tới <code>${_escHtml(originHost)}</code> nhưng bị CF Access chặn (thiếu/sai service token).</p>
          <p style="color:#888">Kiểm tra secret CF Access service token của worker (vd: TERMIX_HOME_CF_CLIENT_ID / _SECRET) đã set đúng trên môi trường này chưa.</p>
        </body></html>`,
        { status: 502, headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-cache' } }
      );
    }

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
    // [CF Access fix] Vite thêm crossorigin vào <script>/<link> asset → trình duyệt tải KHÔNG kèm cookie
    // → CF Access (trên domain dashboard) chặn asset → CORS fail. Strip crossorigin để asset tải
    // same-origin CÓ cookie → CF Access cho qua. (asset cùng origin nên không cần crossorigin)
    html = html.replace(/\s+crossorigin(=("[^"]*"|'[^']*'|\S+))?/gi, '');
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
      var si=u.indexOf('/',u.indexOf('//')+2);
      var path=si===-1?'/':u.slice(si);
      // guac WS PHẢI đi qua proxy (bất kể WSMODE): guacamole-lite check Origin → worker set
      // Origin=termix.home (+ CF token) thì guac mới accept. Direct sẽ bị reject vì cross-origin.
      if(_stripB(path).indexOf('/guacamole/websocket')===0) return u.slice(0,si)+B+_stripB(path);
      if(WSMODE==='proxy') return u; // Termix đã dựng URL có base path → tới dashboard/proxy → worker
      if(u.indexOf(O)!==-1)return u;
      return 'wss://'+O+_stripB(path);
    }
    // Root-relative path
    if(u.charAt(0)==='/'&&u.slice(0,2)!=='//'){
      if(isWS){
        if(_stripB(u).indexOf('/guacamole/websocket')===0) return B+_stripB(u); // guac → qua proxy
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
    r=r.replace(/[?&]undefined$/,''); // strip ?undefined appended by Termix new version bug
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
    try{
      if(window.parent && window.parent!==window){
        // chạy trong iframe → báo parent reload iframe
        window.parent.postMessage({_termixProxy:true,type:'loginRedirect'},'*');
      } else {
        // chạy top-level (tab riêng) → tự reload để lấy jwt cookie mới (cần cho __JWT inject + token WS)
        setTimeout(function(){location.reload();},250);
      }
    }catch(e){ try{location.reload();}catch(e2){} }
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
export function _rewriteTermixCookie(sc, base) {
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
export function handleTermixMoviProxy(request, env) {
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
export function handleTermixHomeProxy(request, env) {
  return handleTermixProxy(request, env, {
    origin:   cleanEnv(env.TERMIX_HOME_URL) || 'https://termix.home-server.id.vn',
    base:     '/proxy/termix-home',
    perm:     'ssh',
    label:    'Termix Home',
    cfId:     cleanEnv(env.TERMIX_HOME_CF_CLIENT_ID),
    cfSecret: cleanEnv(env.TERMIX_HOME_CF_CLIENT_SECRET),
    secret:   cleanEnv(env.TERMIX_HOME_SECRET),
    wsMode:   'direct',  // WS đi thẳng tới termix.home (+?token=jwt) — CF Worker không proxy WS qua CF Tunnel được
  });
}

