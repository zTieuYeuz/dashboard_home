const SERVICES = [
  { id: 'esxi',        name: 'VMware ESXi',    checkUrl: 'https://esxi.home-server.id.vn' },
  { id: 'n8n',         name: 'n8n Automation', checkUrl: 'https://n8n-home.home-server.id.vn' },
  { id: 'casaos',      name: 'CasaOS',         checkUrl: 'https://casaos.home-server.id.vn' },
  { id: '9router',     name: '9Router',        checkUrl: 'https://9router.home-server.id.vn' },
  { id: 'uptime-kuma', name: 'Uptime Kuma',    checkUrl: null },
  { id: 'ssh',         name: 'SSH Terminal',   checkUrl: 'https://termix.home-server.id.vn' },
  { id: 'fortigate',   name: 'FortiGate',      checkUrl: null },
  { id: 'asus',        name: 'ASUS Router',    checkUrl: null },
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
      signal: AbortSignal.timeout(10000),
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
    signal: AbortSignal.timeout(10000),
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

  // Build hook query: nvram_get() + appobj calls
  const hookVars = [
    'cpu_usage(appobj)', 'memory_usage(appobj)', 'netdev(appobj)',
    'nvram_get(wan_ipaddr)', 'nvram_get(wan_gateway)', 'nvram_get(wan_dns)',
    'nvram_get(wan_proto)', 'nvram_get(link_internet)',
    'nvram_get(ddns_enable_x)', 'nvram_get(ddns_hostname_x)',
    'nvram_get(ddns_server_x)', 'nvram_get(ddns_ipaddr)', 'nvram_get(ddns_updated)',
    'nvram_get(wl0_ssid)', 'nvram_get(wl0_channel)', 'nvram_get(wl0_radio)', 'nvram_get(wl0_sta_list)',
    'nvram_get(wl1_ssid)', 'nvram_get(wl1_channel)', 'nvram_get(wl1_radio)', 'nvram_get(wl1_sta_list)',
    'nvram_get(productid)', 'nvram_get(firmver)', 'nvram_get(buildno)',
    'nvram_get(lan_ipaddr)', 'nvram_get(uptime)', 'nvram_get(label_mac)',
  ].join(';');

  const [appRes, sysinfoRes, clientRes] = await Promise.all([
    asusRequest('/appGet.cgi', 'POST', `hook=${encodeURIComponent(hookVars)}`, token, env),
    asusRequest('/ajax_sysinfo.asp', 'GET', null, token, env),
    asusRequest('/update_clients.asp', 'GET', null, token, env),
  ]);

  let app = {};
  try { app = JSON.parse(appRes.text || '{}'); } catch {}

  let sysinfo = {};
  try { sysinfo = JSON.parse(sysinfoRes.text || '{}'); } catch {}

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

  // ── WiFi client counts (wl0_sta_list / wl1_sta_list are MAC lists) ──
  const countMacs = (s) => s ? s.split(' ').filter(m => m.trim().length > 0).length : 0;
  const wifi24Clients = countMacs(app.wl0_sta_list);
  const wifi5Clients  = countMacs(app.wl1_sta_list);

  // ── Uptime ──
  const uptimeSec  = parseInt(app.uptime || sysinfo.uptime || 0);
  const uptimeDays = Math.floor(uptimeSec / 86400);
  const uptimeHrs  = Math.floor((uptimeSec % 86400) / 3600);
  const uptimeMins = Math.floor((uptimeSec % 3600) / 60);
  const uptimeStr  = uptimeDays > 0 ? `${uptimeDays}d ${uptimeHrs}h ${uptimeMins}m`
                   : uptimeHrs  > 0 ? `${uptimeHrs}h ${uptimeMins}m`
                   : `${uptimeMins}m`;

  // ── Total clients (sysinfo may have count) ──
  let totalClients = wifi24Clients + wifi5Clients;
  // Also try from sysinfo
  if (sysinfo.client_count) totalClients = Math.max(totalClients, parseInt(sysinfo.client_count));

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
      totalClients, wifi24Clients, wifi5Clients,
    },
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
    if (url.pathname === '/api/casaos')        return handleCasaOS(env);
    if (url.pathname === '/api/fortigate')     return handleFortigate(env, url.searchParams.has('debug'));
    if (url.pathname === '/api/asus')          return handleAsus(env);
    if (url.pathname === '/api/asus/reboot')   return handleAsusReboot(request, env);
    return env.ASSETS.fetch(request);
  },
};
