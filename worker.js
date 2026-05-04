const SERVICES = [
  { id: 'esxi',        name: 'VMware ESXi',    checkUrl: 'https://esxi.home-server.id.vn' },
  { id: 'n8n',         name: 'n8n Automation', checkUrl: 'https://n8n-home.home-server.id.vn' },
  { id: 'casaos',      name: 'CasaOS',         checkUrl: null },
  { id: '9router',     name: '9Router',        checkUrl: 'https://9router.home-server.id.vn' },
  { id: 'uptime-kuma', name: 'Uptime Kuma',    checkUrl: null },
];

const N8N_BASE        = 'https://n8n-home.home-server.id.vn/api/v1';
const NINEROUTER_BASE = 'https://9router.home-server.id.vn';
const ESXI_SDK        = 'https://esxi.home-server.id.vn/sdk';

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
    const [wfRes, exRes, credRes, varRes, tagRes] = await Promise.all([
      fetch(`${N8N_BASE}/workflows?limit=100`, opts()),
      fetch(`${N8N_BASE}/executions?limit=50&includeData=false`, opts()),
      fetch(`${N8N_BASE}/credentials`, opts()),
      fetch(`${N8N_BASE}/variables`, opts()),
      fetch(`${N8N_BASE}/tags?limit=100`, opts()),
    ]);

    const [wfData, exData, credData, varData, tagData] = await Promise.all([
      wfRes.json(), exRes.json(), credRes.json(), varRes.json(), tagRes.json(),
    ]);

    const workflows = (wfData.data || []).map(w => ({
      id: w.id, name: w.name, active: w.active,
      updatedAt: w.updatedAt, createdAt: w.createdAt,
      triggerCount: w.triggerCount || 0,
      tags: (w.tags || []).map(t => t.name || t),
    }));

    const wfNameMap = {};
    workflows.forEach(w => { wfNameMap[w.id] = w.name; });

    const executions = (exData.data || []).map(e => ({
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

  // Map action → SOAP method
  const actionMap = {
    'powerOn':       'PowerOnVM_Task',
    'powerOff':      'PowerOffVM_Task',
    'suspend':       'SuspendVM_Task',
    'reset':         'ResetVM_Task',
    'shutdownGuest': 'ShutdownGuest',
  };
  const soapMethod = actionMap[action];
  if (!soapMethod) return json({ error: 'Invalid action. Allowed: ' + Object.keys(actionMap).join(', ') }, 400);

  try {
    // Login
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

    // Execute power action
    const powerBody =
      '<' + soapMethod + ' xmlns="urn:vim25">' +
      '<_this type="VirtualMachine">' + escXml(vmId) + '</_this>' +
      '</' + soapMethod + '>';

    const { text: resultText, ok } = await esxiSoap(powerBody, cookie);

    // Logout
    esxiSoap('<Logout xmlns="urn:vim25"><_this type="SessionManager">ha-sessionmanager</_this></Logout>', cookie).catch(() => {});

    // Check for fault
    if (resultText.includes('Fault>')) {
      const faultMsg = x1(resultText, 'localizedMessage') || x1(resultText, 'faultstring') || 'Unknown fault';
      return json({ success: false, error: faultMsg });
    }

    return json({ success: true, action, vmId });
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
    if (url.pathname === '/api/status')      return handleStatus();
    if (url.pathname === '/api/n8n')         return handleN8n(env);
    if (url.pathname === '/api/n8n/exec')    return handleExecDetail(request, env);
    if (url.pathname === '/api/9router')     return handle9Router();
    if (url.pathname === '/api/esxi')        return handleESXi(env);
    if (url.pathname === '/api/esxi/power')  return handleESXiPower(request, env);
    return env.ASSETS.fetch(request);
  },
};
