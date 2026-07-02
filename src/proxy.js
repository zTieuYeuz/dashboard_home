/* ═══════════════════════════════════════════════
   proxy.js — split out of worker.js (2026-07-01). Logic UNCHANGED.
   ═══════════════════════════════════════════════ */
import {
  _escHtml,
  cleanEnv,
  computeEffectivePermissions,
  getSession,
  isAdminUser,
  json
} from './core.js';

export const FGT_POOL_SLOTS = [
  { id:'a1', role:'admin', kasm:'https://kasm-a1.home-server.id.vn', nav:'https://nav-a1.home-server.id.vn' },
  // Chỉ 1 người dùng → chạy 1 slot để dồn CPU/RAM, đỡ lag. Bật lại khi cần 2 người đồng thời:
  // { id:'a2', role:'admin', kasm:'https://kasm-a2.home-server.id.vn', nav:'https://nav-a2.home-server.id.vn' },
  // { id:'a3', role:'admin', kasm:'https://kasm-a3.home-server.id.vn', nav:'https://nav-a3.home-server.id.vn' },
  // { id:'v1', role:'view',  kasm:'https://kasm-v1.home-server.id.vn', nav:'https://nav-v1.home-server.id.vn' },
  // { id:'v2', role:'view',  kasm:'https://kasm-v2.home-server.id.vn', nav:'https://nav-v2.home-server.id.vn' },
];
export const FGT_POOL_TTL_SEC = 1200; // giữ slot 20 phút, trang heartbeat sẽ gia hạn

export async function _fgtPoolRole(env, username) {
  const eff = await computeEffectivePermissions(env, username);
  if (eff && eff.role === 'admin') return 'admin';
  const hubLvl = (eff && eff.permissions && eff.permissions['services-hub']) || 'none';
  if (hubLvl !== 'none') return 'admin';
  return null;
}

export async function _fgtPoolClaim(env, username, role) {
  // Đang giữ slot hợp lệ? → gia hạn & dùng lại
  const cur = await env.DASHBOARD_KV.get(`fgtpool:user:${username}`);
  if (cur) {
    const rec = await env.DASHBOARD_KV.get(`fgtpool:slot:${cur}`, 'json');
    const slot = FGT_POOL_SLOTS.find(s => s.id === cur);
    if (slot && slot.role === role && rec && rec.username === username) {
      await env.DASHBOARD_KV.put(`fgtpool:slot:${cur}`, JSON.stringify({ username, ts: Date.now() }), { expirationTtl: FGT_POOL_TTL_SEC });
      await env.DASHBOARD_KV.put(`fgtpool:user:${username}`, cur, { expirationTtl: FGT_POOL_TTL_SEC });
      return slot;
    }
  }
  // Tìm slot rảnh cùng role
  for (const slot of FGT_POOL_SLOTS.filter(s => s.role === role)) {
    const rec = await env.DASHBOARD_KV.get(`fgtpool:slot:${slot.id}`, 'json');
    if (!rec || rec.username === username) {
      await env.DASHBOARD_KV.put(`fgtpool:slot:${slot.id}`, JSON.stringify({ username, ts: Date.now() }), { expirationTtl: FGT_POOL_TTL_SEC });
      await env.DASHBOARD_KV.put(`fgtpool:user:${username}`, slot.id, { expirationTtl: FGT_POOL_TTL_SEC });
      return slot;
    }
  }
  return null;
}

export async function handleFgtPoolAllocate(request, env) {
  const session = await getSession(request, env);
  if (!session) return json({ error: 'Unauthorized' }, 401);
  const role = await _fgtPoolRole(env, session.username);
  if (!role) return json({ error: 'forbidden' }, 403);
  const slot = await _fgtPoolClaim(env, session.username, role);
  if (!slot) return json({ busy: true, role }, 200);
  return json({ ok: true, role, slot: { id: slot.id, kasm: slot.kasm } }, 200);
}

export async function handleFgtPoolOpen(request, env) {
  if (request.method !== 'POST') return json({ error: 'POST required' }, 405);
  const session = await getSession(request, env);
  if (!session) return json({ error: 'Unauthorized' }, 401);
  const role = await _fgtPoolRole(env, session.username);
  if (!role) return json({ error: 'forbidden' }, 403);
  let body; try { body = await request.json(); } catch { body = {}; }
  const url = (body && body.url) || '';
  if (!/^https?:\/\//.test(url)) return json({ error: 'URL không hợp lệ' }, 400);
  const slotId = await env.DASHBOARD_KV.get(`fgtpool:user:${session.username}`);
  const slot = FGT_POOL_SLOTS.find(s => s.id === slotId);
  if (!slot) return json({ error: 'Chưa được cấp slot — tải lại trang' }, 409);
  const headers = { 'Content-Type': 'application/json' };
  // Khi bật Access cho nav-*, đính Service Token để Worker qua được Access.
  // Dùng chung token với home-cam (HOME_CAM_CF_*); fallback FGT_POOL_CF_* nếu đặt riêng.
  const cfId  = env.FGT_POOL_CF_CLIENT_ID     || env.HOME_CAM_CF_CLIENT_ID;
  const cfSec = env.FGT_POOL_CF_CLIENT_SECRET || env.HOME_CAM_CF_CLIENT_SECRET;
  if (cfId && cfSec) {
    headers['CF-Access-Client-Id']     = cleanEnv(cfId);
    headers['CF-Access-Client-Secret'] = cleanEnv(cfSec);
  }
  try {
    const r = await fetch(`${slot.nav}/open`, { method: 'POST', headers, body: JSON.stringify({ url }), signal: AbortSignal.timeout(10000) });
    const data = await r.json().catch(() => ({}));
    return json(data, r.status);
  } catch (e) {
    return json({ error: 'Không gọi được navigator: ' + e.message }, 502);
  }
}

export async function handleFgtPoolRelease(request, env) {
  const session = await getSession(request, env);
  if (!session) return json({ error: 'Unauthorized' }, 401);
  const slotId = await env.DASHBOARD_KV.get(`fgtpool:user:${session.username}`);
  if (slotId) {
    await env.DASHBOARD_KV.delete(`fgtpool:slot:${slotId}`).catch(() => {});
    await env.DASHBOARD_KV.delete(`fgtpool:user:${session.username}`).catch(() => {});
  }
  return json({ ok: true });
}

export function proxyErr(msg, url) {
  return new Response(
    `<html><head><meta charset="UTF-8"></head><body style="font-family:system-ui;padding:2rem;background:#0b0d14;color:#e2e8f0">
      <h2 style="color:#f87171;margin-bottom:1rem">⚠ Không thể kết nối</h2>
      <p style="white-space:pre-line;line-height:1.7;color:#cbd5e1">${_escHtml(msg)}</p>
      ${url ? `<p style="margin-top:1rem;font-size:12px;color:#64748b">URL: ${_escHtml(url)}</p>` : ''}
    </body></html>`,
    { status: 502, headers: { 'content-type': 'text/html;charset=utf-8' } }
  );
}

export async function handleProxy(request, env) {
  // Require an authenticated session — this endpoint can carry CF-Access
  // service credentials, so it must never be reachable anonymously (SSRF).
  const session = await getSession(request, env);
  if (!session) return proxyErr('Bạn cần đăng nhập để dùng tính năng này.', '');
  // Proxy chung này đính kèm CF-Access service credentials → có thể bypass Cloudflare Access
  // để chạm tới mọi dịch vụ nội bộ. Chỉ admin được dùng (không UI nào gọi route này).
  if (!(await isAdminUser(env, session))) return proxyErr('Tính năng proxy chỉ dành cho admin.', '');

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
   OpenClaw Chat — same-origin reverse proxy under /oc/*
   OpenClaw's Control UI SPA is built with RELATIVE asset paths (./assets/,
   import.meta.url), so it can be served under any base path. We proxy it under
   /oc/ on the dashboard origin so all HTTP (html, assets, config, avatar) is
   SAME-ORIGIN (no CORS — a plain <base>/cross-origin approach fails because
   openclaw-service sends no CORS headers and X-Frame-Options: DENY).
   The WebSocket goes DIRECT to wss://openclaw-service (cross-origin WS is not
   CORS-gated; gateway.controlUi.allowedOrigins must list the dashboard origin).
   Gateway token is injected as a Bearer header so config.json/avatar authorize.
   ═══════════════════════════════════════════════ */

const OC_ORIGIN = 'https://openclaw-service.home-server.id.vn';
const OC_WS_URL = 'wss://openclaw-service.home-server.id.vn/';

export async function handleOpenclawToken(request, env) {
  const session = await getSession(request, env);
  if (!session) return json({ error: 'Unauthorized' }, 401);
  const token = env.OPENCLAW_GATEWAY_TOKEN ? cleanEnv(env.OPENCLAW_GATEWAY_TOKEN) : '';
  return json({ ok: !!token, token, wsUrl: OC_WS_URL });
}

export async function handleOpenclawApp(request, env) {
  const reqUrl = new URL(request.url);
  // /oc → /oc/ ; /oc/<rest> → openclaw-service/<rest>
  let sub = reqUrl.pathname.replace(/^\/oc(?=\/|$)/, '');

  // ── WebSocket upgrade: the SPA connects same-origin to wss://<dash>/oc,
  //    proxy it straight through to the gateway. Auth rides inside the WS
  //    connect frame (token from the iframe #hash), so no header injection. ──
  if ((request.headers.get('Upgrade') || '').toLowerCase() === 'websocket') {
    const wsTarget = OC_ORIGIN + (sub || '/') + reqUrl.search;
    return fetch(new Request(wsTarget, request));
  }

  const session = await getSession(request, env);
  if (!session) return new Response('Unauthorized', { status: 401 });
  if (sub === '') return Response.redirect(`${reqUrl.origin}/oc/${reqUrl.search}`, 302);
  const target = OC_ORIGIN + sub + reqUrl.search;

  const token = env.OPENCLAW_GATEWAY_TOKEN ? cleanEnv(env.OPENCLAW_GATEWAY_TOKEN) : '';
  // Minimal, clean forward headers — never leak the dashboard session cookie.
  const fwd = new Headers();
  for (const h of ['accept', 'accept-language', 'user-agent', 'range', 'content-type']) {
    const v = request.headers.get(h);
    if (v) fwd.set(h, v);
  }
  if (token) fwd.set('Authorization', `Bearer ${token}`);

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
    return new Response(`OpenClaw upstream error: ${e.message}`, { status: 502 });
  }

  const rh = new Headers(upstream.headers);
  rh.delete('x-frame-options');
  const csp = rh.get('content-security-policy');
  if (csp) {
    const stripped = csp.replace(/frame-ancestors[^;]*(;|$)/gi, '').trim().replace(/;$/, '');
    if (stripped) rh.set('content-security-policy', stripped); else rh.delete('content-security-policy');
  }
  // Rewrite any redirect Location back through the /oc prefix.
  const loc = rh.get('location');
  if (loc && loc.startsWith(OC_ORIGIN)) rh.set('location', '/oc' + loc.slice(OC_ORIGIN.length));

  return new Response(upstream.body, { status: upstream.status, headers: rh });
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
