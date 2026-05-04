const SERVICES = [
  { id: 'esxi',        name: 'VMware ESXi',    checkUrl: null },
  { id: 'n8n',         name: 'n8n Automation', checkUrl: 'https://n8n-home.home-server.id.vn' },
  { id: 'casaos',      name: 'CasaOS',         checkUrl: null },
  { id: '9router',     name: '9Router',        checkUrl: 'https://9router.home-server.id.vn' },
  { id: 'uptime-kuma', name: 'Uptime Kuma',    checkUrl: null },
];

const N8N_BASE = 'https://n8n-home.home-server.id.vn/api/v1';

async function checkService(service) {
  if (!service.checkUrl) return { id: service.id, status: 'local', ping: null };
  const t0 = Date.now();
  try {
    const res = await fetch(service.checkUrl, {
      method: 'GET',
      redirect: 'follow',
      signal: AbortSignal.timeout(6000),
      headers: { 'User-Agent': 'HomeLabDashboard/1.0' },
    });
    return { id: service.id, status: res.status < 500 ? 'online' : 'offline', ping: Date.now() - t0, httpStatus: res.status };
  } catch (e) {
    return { id: service.id, status: 'offline', ping: null, error: e.message };
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

  const headers = { 'X-N8N-API-KEY': key, 'Accept': 'application/json' };
  const opts = { headers, signal: AbortSignal.timeout(10000) };

  try {
    const [wfRes, exRes] = await Promise.all([
      fetch(`${N8N_BASE}/workflows?limit=100`, opts),
      fetch(`${N8N_BASE}/executions?limit=30&includeData=false`, opts),
    ]);

    const [wfData, exData] = await Promise.all([wfRes.json(), exRes.json()]);

    const workflows = (wfData.data || []).map(w => ({
      id: w.id,
      name: w.name,
      active: w.active,
      updatedAt: w.updatedAt,
      createdAt: w.createdAt,
      tags: (w.tags || []).map(t => t.name || t),
    }));

    const executions = (exData.data || []).map(e => ({
      id: e.id,
      workflowName: e.workflowData?.name || '—',
      status: e.status,
      startedAt: e.startedAt,
      stoppedAt: e.stoppedAt,
      mode: e.mode,
    }));

    const active   = workflows.filter(w => w.active).length;
    const inactive = workflows.length - active;
    const success  = executions.filter(e => e.status === 'success').length;
    const failed   = executions.filter(e => e.status === 'error' || e.status === 'failed').length;
    const running  = executions.filter(e => e.status === 'running').length;

    return json({ workflows, executions, stats: { total: workflows.length, active, inactive, success, failed, running } });
  } catch (e) {
    return json({ error: e.message }, 502);
  }
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*', 'Cache-Control': 'no-store' },
  });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname === '/api/status') return handleStatus();
    if (url.pathname === '/api/n8n')    return handleN8n(env);
    return env.ASSETS.fetch(request);
  },
};
