/* ═══════════════════════════════════════════════
   camera-home.js — Camera Home (Frigate) handlers split out of worker.js
   (2026-07-11). Logic UNCHANGED — pure verbatim move, same as other
   src/ modules. Camera Movi handlers (handleCameraToken, handleCamEmbed,
   aliases) intentionally STAY in worker.js.
   ═══════════════════════════════════════════════ */
import {
  getSession, hasPerm, isAdminUser, cleanEnv, json, logActivity, DEFAULT_CAMERAS,
} from './core.js';

export async function handleCameraList(request, env) {
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

export async function handleCameraRename(request, env, camId) {
  const session = await getSession(request, env);
  if (!session || !(await isAdminUser(env, session))) return json({ error: 'Admin required' }, 403);
  let body; try { body = await request.json(); } catch { return json({ error: 'Invalid JSON' }, 400); }
  const name = (body.name || '').trim();
  if (!name || name.length > 40) return json({ error: 'Tên không hợp lệ (tối đa 40 ký tự)' }, 400);
  const list = await env.DASHBOARD_KV.get('camera_list', 'json') || DEFAULT_CAMERAS;
  const cam = list.find(c => c.id === camId);
  if (!cam) return json({ error: 'Camera not found' }, 404);
  cam.name = name;
  await env.DASHBOARD_KV.put('camera_list', JSON.stringify(list));
  await logActivity(env, { action: 'camera-rename', username: session.username,
    ip: request.headers.get('CF-Connecting-IP') || '?', success: true, detail: `Camera "${camId}" → "${name}"` });
  return json({ success: true });
}

/* ── Camera Test (Linux PC Frigate) — go2rtc Live Proxy (port 1984) ── */
export async function handleCamTestLiveEmbed(request, env) {
  const session = await getSession(request, env);
  if (!session) return new Response('Unauthorized', { status: 401 });
  if (!(await hasPerm(env, session, 'camera'))) return new Response('Forbidden', { status: 403 });

  const baseUrl  = cleanEnv(env.HOME_FRIGATE_TEST_LIVE_URL);
  if (!baseUrl) return new Response('HOME_FRIGATE_TEST_LIVE_URL chưa được cấu hình', { status: 503 });
  const cfId     = cleanEnv(env.HOME_CAM_CF_CLIENT_ID);
  const cfSecret = cleanEnv(env.HOME_CAM_CF_CLIENT_SECRET);

  const reqUrl  = new URL(request.url);
  const subPath = reqUrl.pathname.replace('/cam-test-live', '') || '/';
  const target  = `${baseUrl}${subPath}${reqUrl.search}`;

  if (request.headers.get('Upgrade')?.toLowerCase() === 'websocket') {
    let upstreamResp;
    try {
      upstreamResp = await fetch(target, {
        headers: {
          'Upgrade':               'websocket',
          'Connection':            'Upgrade',
          'Sec-WebSocket-Version': '13',
          'Sec-WebSocket-Key':     'dGhlIHNhbXBsZSBub25jZQ==',
          ...(cfId ? { 'CF-Access-Client-Id': cfId, 'CF-Access-Client-Secret': cfSecret } : {}),
        },
      });
    } catch(e) {
      return new Response('WebSocket upstream error: ' + e.message, { status: 502 });
    }
    const upstream = upstreamResp.webSocket;
    if (!upstream) return new Response('WebSocket upstream failed (' + upstreamResp.status + ')', { status: 502 });

    const { 0: client, 1: server } = new WebSocketPair();
    server.accept();
    upstream.accept();
    server.addEventListener('message',   ({ data }) => { try { upstream.send(data); } catch(_) {} });
    upstream.addEventListener('message', ({ data }) => { try { server.send(data);   } catch(_) {} });
    server.addEventListener('close',   ({ code, reason }) => { try { upstream.close(code, reason); } catch(_) {} });
    upstream.addEventListener('close', ({ code, reason }) => { try { server.close(code, reason);   } catch(_) {} });
    return new Response(null, { status: 101, webSocket: client });
  }

  const upstream = await fetch(target, {
    method:  request.method,
    headers: { ...(cfId ? { 'CF-Access-Client-Id': cfId, 'CF-Access-Client-Secret': cfSecret } : {}) },
    ...(request.method !== 'GET' && request.method !== 'HEAD' ? { body: request.body } : {}),
  });
  const ct = upstream.headers.get('Content-Type') || 'application/octet-stream';

  if (ct.includes('text/html')) {
    let html = await upstream.text();
    html = html.replace(/(\s(?:src|href|action)=["'])(\/(?!cam-test-live\/)[^"']*)(["'])/gi,
      (_, attr, path, q) => `${attr}/cam-test-live${path}${q}`
    );
    let camHost;
    try { camHost = new URL(baseUrl).host; } catch(_) { camHost = baseUrl; }
    const patch = `<script>
(function(){
  var PRX='/cam-test-live';
  var CAM='${camHost.replace(/'/g,"\\'")}';
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
    var a=[].slice.call(arguments);if(typeof a[1]==='string')a[1]=rwHTTP(a[1]);
    return _xo.apply(this,a);
  };
  try{if(new URLSearchParams(window.location.search).get('cam_audio')==='1')window.CAM_AUDIO=true;}catch(e){}
  function _fixVid(v){
    try{if(!window.CAM_AUDIO){v.muted=true;v.defaultMuted=true;v.setAttribute('muted','');}
    else{v.muted=false;v.defaultMuted=false;v.removeAttribute('muted');v.volume=1;}
    v.playsInline=true;v.setAttribute('playsinline','');v.setAttribute('webkit-playsinline','');
    v.autoplay=true;v.setAttribute('autoplay','');v.controls=false;
    var p=v.play();if(p&&p.catch)p.catch(function(){});}catch(e){}
  }
  function _scan(){try{document.querySelectorAll('video').forEach(_fixVid);}catch(e){}}
  try{new MutationObserver(_scan).observe(document.documentElement,{childList:true,subtree:true});}catch(e){}
  document.addEventListener('DOMContentLoaded',_scan);
  window.addEventListener('load',_scan);
  setInterval(_scan,1000);
})();
<\/script>`;
    html = html.includes('</head>') ? html.replace('</head>', patch + '</head>') : patch + html;
    return new Response(html, {
      status: upstream.status,
      headers: { 'Content-Type': 'text/html', 'Cache-Control': 'no-cache' },
    });
  }

  // HLS m3u8: rewrite absolute segment paths to go through /cam-test-live/ proxy
  if (ct.includes('mpegurl') || ct.includes('m3u8') || reqUrl.pathname.endsWith('.m3u8')) {
    let m3u8 = await upstream.text();
    m3u8 = m3u8.replace(/^(\/(?!cam-test-live\/)[^\s].*)$/gm, '/cam-test-live$1');
    return new Response(m3u8, { status: upstream.status, headers: { 'Content-Type': ct, 'Cache-Control': 'no-cache' } });
  }

  return new Response(upstream.body, {
    status: upstream.status,
    headers: { 'Content-Type': ct, 'Cache-Control': 'no-cache' },
  });
}

/* ── Camera Test (Linux PC Frigate) — Frigate API Proxy (port 5000) ── */
export async function handleCamTestApiEmbed(request, env) {
  const session = await getSession(request, env);
  if (!session) return new Response('Unauthorized', { status: 401 });
  if (!(await hasPerm(env, session, 'camera'))) return new Response('Forbidden', { status: 403 });

  const baseUrl  = cleanEnv(env.HOME_FRIGATE_TEST_URL);
  if (!baseUrl) return new Response('HOME_FRIGATE_TEST_URL chưa được cấu hình', { status: 503 });
  const cfId     = cleanEnv(env.HOME_CAM_CF_CLIENT_ID);
  const cfSecret = cleanEnv(env.HOME_CAM_CF_CLIENT_SECRET);

  const isDownload = new URL(request.url).searchParams.get('dl') === '1';
  const subPath = new URL(request.url).pathname.replace('/cam-test-api', '') || '/';
  const isRecPath = /^\/(api\/[^/]+\/start\/|vod\/)/.test(subPath);
  if (isDownload) {
    if (!(await hasPerm(env, session, 'camera_download')))
      return new Response('Forbidden', { status: 403 });
  } else if (isRecPath) {
    if (!(await hasPerm(env, session, 'camera_playback')))
      return new Response('Forbidden', { status: 403 });
  }

  const reqUrl = new URL(request.url);
  const target = `${baseUrl}${subPath}${reqUrl.search}`;

  try {
    const fetchOpts = {
      method:  request.method,
      headers: {
        ...(cfId ? { 'CF-Access-Client-Id': cfId, 'CF-Access-Client-Secret': cfSecret } : {}),
      },
    };
    const ct = request.headers.get('Content-Type');
    if (ct) fetchOpts.headers['Content-Type'] = ct;
    if (request.method !== 'GET' && request.method !== 'HEAD') fetchOpts.body = request.body;

    const upstream = await fetch(target, fetchOpts);
    const resCt = upstream.headers.get('Content-Type') || 'application/octet-stream';

    const resHeaders = { 'Content-Type': resCt, 'Cache-Control': 'no-cache' };
    const cd = upstream.headers.get('Content-Disposition');
    if (cd) resHeaders['Content-Disposition'] = cd;

    return new Response(upstream.body, { status: upstream.status, headers: resHeaders });
  } catch(e) {
    return new Response('Frigate upstream error: ' + e.message, { status: 502 });
  }
}

/* ── CodeProject.AI — Simple REST Reverse Proxy ── */
export async function handleCpaiEmbed(request, env) {
  const session = await getSession(request, env);
  if (!session) return new Response('Unauthorized', { status: 401 });
  if (!(await hasPerm(env, session, 'camera'))) return new Response('Forbidden', { status: 403 });

  const cpaiUrl  = 'https://cpai.home-server.id.vn';
  const cfId     = cleanEnv(env.HOME_CAM_CF_CLIENT_ID);
  const cfSecret = cleanEnv(env.HOME_CAM_CF_CLIENT_SECRET);

  const reqUrl  = new URL(request.url);
  const subPath = reqUrl.pathname.replace('/cpai', '') || '/';
  const target  = `${cpaiUrl}${subPath}${reqUrl.search}`;

  const headers = new Headers(request.headers);
  headers.set('CF-Access-Client-Id', cfId);
  headers.set('CF-Access-Client-Secret', cfSecret);
  headers.delete('host');

  const upstream = await fetch(target, {
    method:  request.method,
    headers,
    body:    ['GET','HEAD'].includes(request.method) ? undefined : request.body,
  });

  const respHeaders = new Headers(upstream.headers);
  respHeaders.set('Access-Control-Allow-Origin', new URL(request.url).origin);
  respHeaders.delete('content-encoding');
  return new Response(upstream.body, { status: upstream.status, headers: respHeaders });
}

