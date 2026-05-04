const SERVICES = [
  {
    id: 'esxi',
    name: 'VMware ESXi',
    checkUrl: null,
  },
  {
    id: 'n8n',
    name: 'n8n Automation',
    checkUrl: 'https://n8n-home.home-server.id.vn',
  },
  {
    id: 'casaos',
    name: 'CasaOS',
    checkUrl: null,
  },
  {
    id: '9router',
    name: '9Router',
    checkUrl: 'https://9router.home-server.id.vn',
  },
  {
    id: 'uptime-kuma',
    name: 'Uptime Kuma',
    checkUrl: null,
  },
];

async function checkService(service) {
  if (!service.checkUrl) {
    return { id: service.id, status: 'local', ping: null };
  }
  const t0 = Date.now();
  try {
    const res = await fetch(service.checkUrl, {
      method: 'GET',
      redirect: 'follow',
      signal: AbortSignal.timeout(6000),
      headers: { 'User-Agent': 'HomeLabDashboard/1.0' },
    });
    const ping = Date.now() - t0;
    return { id: service.id, status: res.status < 500 ? 'online' : 'offline', ping, httpStatus: res.status };
  } catch (e) {
    return { id: service.id, status: 'offline', ping: null, error: e.message };
  }
}

async function handleStatus() {
  const results = await Promise.all(SERVICES.map(checkService));
  const map = {};
  results.forEach(r => { map[r.id] = r; });
  return new Response(JSON.stringify({ ts: new Date().toISOString(), services: map }), {
    headers: {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
      'Cache-Control': 'no-store',
    },
  });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname === '/api/status') {
      return handleStatus();
    }
    return env.ASSETS.fetch(request);
  },
};
