/* ═══════════════════════════════════════════════
   tool-movi.js — split out of worker.js (2026-07-01). Logic UNCHANGED.
   ═══════════════════════════════════════════════ */
import {
  _truncateJson,
  cleanEnv,
  getSession,
  hasPerm,
  isAdminUser,
  json,
  logActivity,
  moviN8nAuth
} from './core.js';

export async function handleToolMoviCreateUser(request, env, session, ctx) {
  if (request.method !== 'POST') return json({ error: 'POST required' }, 405);
  const webhookUrl = cleanEnv(env.MOVI_TOOL_CREATE_USER_WEBHOOK);
  if (!webhookUrl) return json({ error: 'MOVI_TOOL_CREATE_USER_WEBHOOK not configured. Run: npx wrangler secret put MOVI_TOOL_CREATE_USER_WEBHOOK' }, 500);

  let body;
  try { body = await request.json(); } catch { return json({ error: 'Invalid JSON body' }, 400); }

  // Validate required fields
  const required = ['email','firstName','lastName','personalEmail','group'];
  for (const f of required) {
    if (!body[f] || !String(body[f]).trim()) return json({ error: `Missing required field: ${f}` }, 400);
  }

  // Force createdBy from server-side session (cannot be spoofed by client)
  const createdBy = session.username || session.email || 'unknown';

  // Transform to n8n expected format: flat object, fields accessible as $json['Field Name']
  const n8nPayload = {
    'Email User Movi': body.email         || '',
    'First Name':      body.firstName     || '',
    'Last Name':       body.lastName      || '',
    'JobTitle':        body.jobTitle      || '',
    'Department':      body.department    || '',
    'Personal Email':  body.personalEmail || '',
    'Office':          body.office        || '',
    'MobilePhone':     body.mobilePhone   || '',
    'Manager':         body.manager       || '',
    'Company':         body.company       || '',
    'Phòng Ban':       body.group         || '',
    'Người Tạo user':  createdBy,
  };

  let auth;
  try { auth = moviN8nAuth(env); } catch (e) { return json({ error: e.message }, 500); }

  // Cloudflare Workers HTTP: no wall-clock limit while browser stays connected.
  // Await n8n directly — browser shows spinner, gets result when workflow finishes.
  try {
    const res = await fetch(webhookUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': auth },
      body: JSON.stringify(n8nPayload),
      signal: AbortSignal.timeout(180000), // 3 min safety cap
    });
    const txt = await res.text().catch(() => '');
    let result;
    try { result = JSON.parse(txt); } catch { result = { raw: txt.slice(0, 1000) }; }
    if (!res.ok) return json({ error: `n8n returned ${res.status}`, result }, 502);
    return json({ success: true, result });
  } catch (e) {
    return json({ error: `Webhook error: ${e.message}` }, 502);
  }
}


/* ── Tool Movi: Block User ── */
export async function handleToolMoviBlockUser(request, env, session) {
  if (request.method !== 'POST') return json({ error: 'POST required' }, 405);
  const webhookUrl = cleanEnv(env.MOVI_WH_BLOCK_USER);
  let body; try { body = await request.json(); } catch { return json({ error: 'Invalid JSON' }, 400); }
  const email     = (body.email || '').trim();
  const startDate = (body.startDate || '').trim();
  const endDate   = (body.endDate || '').trim();
  const reason    = (body.reason || '').trim();
  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return json({ error: 'Email không hợp lệ' }, 400);
  if (!startDate || !/^\d{4}-\d{2}-\d{2}$/.test(startDate)) return json({ error: 'Ngày bắt đầu không hợp lệ (định dạng: YYYY-MM-DD)' }, 400);
  if (!endDate   || !/^\d{4}-\d{2}-\d{2}$/.test(endDate))   return json({ error: 'Ngày kết thúc không hợp lệ (định dạng: YYYY-MM-DD)' }, 400);
  if (endDate < startDate) return json({ error: 'Ngày kết thúc phải sau hoặc bằng ngày bắt đầu' }, 400);
  if (!reason) return json({ error: 'Lý do block là bắt buộc' }, 400);
  const payload = [
    {
      data: {
        'Tài khoản user block': email,
        'Thời gian bắt đầu':   startDate,
        'thời gian kết thúc':  endDate,
        'ghi chú lý do ':      reason,
      }
    }
  ];
  const ip = request.headers.get('CF-Connecting-IP') || '?';
  try {
    const resp = await fetch(webhookUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': moviN8nAuth(env) },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(180000),
    });
    if (!resp.ok) {
      const txt = await resp.text().catch(() => '');
      return json({ error: `n8n error: HTTP ${resp.status}`, detail: txt.slice(0, 200) }, 502);
    }
    const raw = await resp.json().catch(() => ({}));
    const result = Array.isArray(raw) ? raw : raw;
    await logActivity(env, { action: 'tool-movi-block-user', username: session.username, ip, success: true, detail: `Blocked ${email} (${startDate} → ${endDate})` });
    return json({ success: true, result });
  } catch (e) {
    await logActivity(env, { action: 'tool-movi-block-user', username: session.username, ip, success: false, detail: `Failed: ${e.message}` });
    return json({ error: e.name === 'TimeoutError' ? 'n8n timeout sau 3 phút' : `Lỗi kết nối: ${e.message}` }, 502);
  }
}

/* ── Tool Movi: Asset Search ── */
export async function handleToolMoviAssetSearch(request, env, session) {
  if (request.method !== 'POST') return json({ error: 'POST required' }, 405);
  const webhookUrl = cleanEnv(env.MOVI_WH_ASSET_SEARCH);
  let body; try { body = await request.json(); } catch { return json({ error: 'Invalid JSON' }, 400); }
  const params = {
    email:     (body.email     || '').trim(),
    assetTag:  (body.assetTag  || '').trim(),
    model:     (body.model     || '').trim(),
    serial:    (body.serial    || '').trim(),
    location:  (body.location  || '').trim(),
    status:    (body.status    || '').trim(),
    assetType: (body.assetType || '').trim(),
  };
  if (!Object.values(params).some(v => v))
    return json({ error: 'Vui lòng nhập ít nhất 1 tiêu chí tìm kiếm' }, 400);
  try {
    const resp = await fetch(webhookUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': moviN8nAuth(env) },
      body: JSON.stringify(params),
      signal: AbortSignal.timeout(30000),
    });
    if (!resp.ok) {
      const txt = await resp.text().catch(() => '');
      return json({ error: `n8n error: HTTP ${resp.status}`, detail: txt.slice(0, 200) }, 502);
    }
    const raw  = await resp.json().catch(() => []);
    const list = Array.isArray(raw) ? raw : (raw ? [raw] : []);
    return json({ success: true, list, total: list.length });
  } catch(e) {
    return json({ error: e.name === 'TimeoutError' ? 'n8n timeout sau 30 giây' : `Lỗi kết nối: ${e.message}` }, 502);
  }
}

/* ── Tool Movi: Check Email Azure AD ── */
export async function handleToolMoviCheckEmail(request, env, session) {
  if (request.method !== 'POST') return json({ error: 'POST required' }, 405);
  const webhookUrl = cleanEnv(env.MOVI_WH_AZURE_CHECK_EMAIL);
  if (!webhookUrl) return json({ error: 'MOVI_WH_AZURE_CHECK_EMAIL chưa được cấu hình' }, 503);
  let body; try { body = await request.json(); } catch { return json({ error: 'Invalid JSON' }, 400); }
  // Accept email OR partial name/keyword — no strict email format check
  const query = (body.query || body.email || '').trim();
  if (!query || query.length < 2)
    return json({ error: 'Nhập ít nhất 2 ký tự để tìm kiếm' }, 400);
  if (query.length > 100)
    return json({ error: 'Từ khoá tìm kiếm quá dài' }, 400);
  try {
    const url = `${webhookUrl}?email=${encodeURIComponent(query)}`;
    const resp = await fetch(url, {
      method: 'GET',
      headers: { 'Authorization': moviN8nAuth(env) },
      signal: AbortSignal.timeout(15000),
    });
    if (!resp.ok) {
      const txt = await resp.text().catch(() => '');
      return json({ error: `n8n error: HTTP ${resp.status}`, detail: txt.slice(0, 200) }, 502);
    }
    // n8n Respond to Webhook returns $json.body (raw Graph API response)
    // Shape: { value: [...users], @odata.context: "..." }
    // OR legacy flat shape: { found, id, displayName, ... }
    const raw = await resp.json().catch(() => ({}));
    // Case 1: n8n returns raw Graph API body { value: [...] }
    if (Array.isArray(raw.value)) {
      const users = raw.value;
      return json({ success: true, found: users.length > 0, users });
    }
    // Case 2: n8n returns flat single-user fields { found, id, displayName, ... }
    if (raw.found !== undefined) {
      const user = (raw.id || raw.displayName) ? {
        id: raw.id, displayName: raw.displayName,
        userPrincipalName: raw.userPrincipalName,
        mail: raw.mail, accountEnabled: raw.accountEnabled,
      } : null;
      return json({ success: true, found: !!raw.found, users: user ? [user] : [] });
    }
    // Case 3: unexpected shape
    return json({ success: true, found: false, users: [] });
  } catch(e) {
    return json({ error: e.name === 'TimeoutError' ? 'n8n timeout sau 15 giây' : `Lỗi kết nối: ${e.message}` }, 502);
  }
}

/* ── Tool Movi: Check Azure Group ── */
export async function handleToolMoviCheckAzureGroup(request, env, session) {
  if (request.method !== 'POST') return json({ error: 'POST required' }, 405);
  const webhookUrl = cleanEnv(env.MOVI_WH_AZURE_CHECK_GROUP);
  if (!webhookUrl) return json({ error: 'MOVI_WH_AZURE_CHECK_GROUP chưa được cấu hình' }, 503);
  let body; try { body = await request.json(); } catch { return json({ error: 'Invalid JSON' }, 400); }
  const query = (body.query || '').trim();
  if (!query || query.length < 2)
    return json({ error: 'Nhập ít nhất 2 ký tự để tìm kiếm' }, 400);
  if (query.length > 100)
    return json({ error: 'Từ khoá tìm kiếm quá dài' }, 400);
  try {
    const url = `${webhookUrl}?query=${encodeURIComponent(query)}`;
    const resp = await fetch(url, {
      method: 'GET',
      headers: { 'Authorization': moviN8nAuth(env) },
      signal: AbortSignal.timeout(15000),
    });
    if (!resp.ok) {
      const txt = await resp.text().catch(() => '');
      return json({ error: `n8n error: HTTP ${resp.status}`, detail: txt.slice(0, 200) }, 502);
    }
    const raw = await resp.json().catch(() => ({}));
    if (Array.isArray(raw.value)) {
      return json({ success: true, found: raw.value.length > 0, groups: raw.value });
    }
    return json({ success: true, found: false, groups: [] });
  } catch(e) {
    return json({ error: e.name === 'TimeoutError' ? 'n8n timeout sau 15 giây' : `Lỗi kết nối: ${e.message}` }, 502);
  }
}

/* ── Tool Movi: Delete User List ── */
export async function handleToolMoviDeleteUserList(request, env, session) {
  const webhookUrl = cleanEnv(env.MOVI_WH_DELETE_USER_LIST);
  try {
    const resp = await fetch(webhookUrl, {
      method: 'GET',
      headers: { 'Authorization': moviN8nAuth(env) },
      signal: AbortSignal.timeout(30000),
    });
    if (!resp.ok) {
      const txt = await resp.text().catch(() => '');
      return json({ error: `n8n error: HTTP ${resp.status}`, detail: txt.slice(0, 200) }, 502);
    }
    const raw  = await resp.json().catch(() => []);
    const list = Array.isArray(raw) ? raw : (raw ? [raw] : []);
    return json({ success: true, list, total: list.length });
  } catch(e) {
    return json({ error: e.name === 'TimeoutError' ? 'n8n timeout sau 30 giây' : `Lỗi kết nối: ${e.message}` }, 502);
  }
}

/* ── Tool Movi: Delete User Action ── */
export async function handleToolMoviDeleteUserAction(request, env, session) {
  if (request.method !== 'POST') return json({ error: 'POST required' }, 405);
  const webhookUrl = cleanEnv(env.MOVI_WH_DELETE_USER);
  let body; try { body = await request.json(); } catch { return json({ error: 'Invalid JSON' }, 400); }
  const email = (body.email || '').trim();
  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return json({ error: 'Email không hợp lệ' }, 400);
  const ip = request.headers.get('CF-Connecting-IP') || '?';
  try {
    const resp = await fetch(webhookUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': moviN8nAuth(env) },
      body: JSON.stringify({ email, 'Người thực hiện': session.username }),
      signal: AbortSignal.timeout(20000),
    });
    if (!resp.ok) {
      const txt = await resp.text().catch(() => '');
      return json({ error: `n8n error: HTTP ${resp.status}`, detail: txt.slice(0, 200) }, 502);
    }
    const raw = await resp.json().catch(() => ({}));
    const result = Array.isArray(raw) ? raw : raw;
    await logActivity(env, { action: 'tool-movi-delete-user', username: session.username, ip, success: true, detail: `Deleted ${email}` });
    return json({ success: true, result });
  } catch(e) {
    await logActivity(env, { action: 'tool-movi-delete-user', username: session.username, ip, success: false, detail: `Failed: ${e.message}` });
    return json({ error: e.name === 'TimeoutError' ? 'TIMEOUT' : `Lỗi kết nối: ${e.message}` }, 502);
  }
}

export async function handleToolMoviFgPolicy(request, env, session, policyType, ctx) {
  if (request.method !== 'POST') return json({ error: 'POST required' }, 405);
  const envKey = policyType === 'lan' ? env.MOVI_WH_FG_POLICY_LAN : env.MOVI_WH_FG_POLICY_WIFI;
  const webhookUrl = cleanEnv(envKey);
  if (!webhookUrl) return json({ error: "MOVI_WH_FG_POLICY_" + policyType.toUpperCase() + " chưa được cấu hình" }, 503);
  let body; try { body = await request.json(); } catch { return json({ error: 'Invalid JSON' }, 400); }
  const email = (body.email || '').trim();
  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return json({ error: 'Email user không hợp lệ' }, 400);
  if (!body.date) return json({ error: 'Thiếu ngày' }, 400);
  if (!body.startTime || !body.endTime) return json({ error: 'Thiếu thời gian bắt đầu/kết thúc' }, 400);
  const ip = request.headers.get('CF-Connecting-IP') || '?';

  const policyId = crypto.randomUUID();
  const expiresAt = new Date(`${body.date}T${body.endTime}:00+07:00`).getTime();
  const effectiveTtl = Math.max(60, Math.floor((expiresAt - Date.now()) / 1000));
  // KV TTL = thời gian đến endTime + 15 phút buffer (n8n cần thời gian xóa rule rồi mới callback)
  const kvTtl = effectiveTtl + 900;
  const policyData = {
    id: policyId, type: policyType,
    email, allowApp: (body.allowApp || '').trim(),
    department: (body.department || '').trim(),
    date: body.date, startTime: body.startTime, endTime: body.endTime,
    location: (body.location || '').trim(),
    reason: (body.reason || '').trim(),
    createdBy: session.username,
    createdAt: Date.now(), expiresAt,
  };
  // Generate a single-use callback token — n8n sends this back when deleting rule
  const callbackToken = crypto.randomUUID();
  // Store token → policyId mapping (TTL same as policy)
  await env.DASHBOARD_KV.put(`fgcb:${callbackToken}`, policyId, { expirationTtl: kvTtl }).catch(() => {});

  const payload = [{ data: {
    'policyId':            policyId,       // for reference
    'callbackToken':       callbackToken,  // n8n sends this back to mark done
    'Email user':          email,
    'cho phép sử dụng':   policyData.allowApp,
    'phòng Ban':           policyData.department,
    'Ngày':                body.date,
    'thời gian bắt đầu ': body.startTime,
    'thời gian kết thúc': body.endTime,
    'vị trí máy':         policyData.location,
    'Lý do':              policyData.reason,
    'Người Tạo':          session.username,
  }}];

  try {
    // Wait for n8n Respond to Webhook #1 (policy created confirmation)
    const resp = await fetch(webhookUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': moviN8nAuth(env) },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(120000), // 2 min — wait for FortiGate + Teams
    });
    if (!resp.ok) {
      const txt = await resp.text().catch(() => '');
      return json({ error: "n8n error: HTTP " + resp.status, detail: txt.slice(0, 200) }, 502);
    }
    // Parse n8n response — trích xuất Rule ID + Rule Name từ Teams message HTML
    let ruleId = null, ruleName = null;
    try {
      const respData = await resp.json();
      // n8n trả về Teams message JSON, body.content là HTML
      const html = respData?.body?.content || respData?.content || '';
      // Extract Rule ID: <td>ID Rule</td><td>174</td>
      const mId = html.match(/ID Rule<\/td>\s*<td[^>]*>(\d+)<\/td>/i);
      if (mId) ruleId = mId[1];
      // Extract Rule Name: <td>Name</td><td>N8N-xxx-...</td>
      const mName = html.match(/>\s*Name\s*<\/td>\s*<td[^>]*>([^<]+)<\/td>/i);
      if (mName) ruleName = mName[1].trim();
    } catch (_) {}
    if (ruleId)   policyData.ruleId   = ruleId;
    if (ruleName) policyData.ruleName = ruleName;
    // Policy confirmed created — now save to KV
    try {
      await env.DASHBOARD_KV.put(`fgpolicy:${policyId}`, JSON.stringify(policyData), { expirationTtl: kvTtl });
    } catch (kvErr) { console.error('fgpolicy KV save error:', kvErr); }
    await logActivity(env, { action: "tool-movi-fg-policy-" + policyType, username: session.username, ip, success: true, detail: "Policy " + policyType.toUpperCase() + " [" + policyId.slice(0,8) + "] cho " + email + " " + body.date + (ruleId ? " Rule#" + ruleId : '') });
    // Lưu vào lịch sử ngay khi tạo xong (không đợi callback)
    try {
      const hist = await env.DASHBOARD_KV.get('tool_movi_history', 'json') || [];
      hist.unshift({
        id:          policyId,
        tool:        'fg-policy-' + policyType,
        toolLabel:   'Policy ' + policyType.toUpperCase() + ' — Đang hoạt động',
        email:       policyData.email,
        displayName: policyData.email,
        createdBy:   policyData.createdBy,
        status:      'active',   // phân biệt với "done" khi xóa xong
        expiresAt:   policyData.expiresAt,
        result: {
          type:       policyData.type,
          ruleName:   policyData.ruleName || null,
          ruleId:     policyData.ruleId   || null,
          date:       policyData.date,
          startTime:  policyData.startTime,
          endTime:    policyData.endTime,
          location:   policyData.location,
          allowApp:   policyData.allowApp,
          department: policyData.department,
          reason:     policyData.reason,
        },
        error:   null,
        input:   null,
        savedAt: Date.now(),
      });
      if (hist.length > 1000) hist.length = 1000;
      await env.DASHBOARD_KV.put('tool_movi_history', JSON.stringify(hist));
    } catch (_) {}
    return json({ success: true, policy: policyData });
  } catch(e) {
    await logActivity(env, { action: "tool-movi-fg-policy-" + policyType, username: session.username, ip, success: false, detail: "Failed: " + e.message });
    return json({ error: e.name === 'TimeoutError' ? 'n8n timeout sau 2 phút — kiểm tra FortiGate/Teams' : "Lỗi kết nối: " + e.message }, 502);
  }
}

/* ── Tool Movi: FG Policy Done callback (n8n gọi về khi xóa rule xong) ── */
/* Bảo mật 3 lớp: CF Access Service Token → Basic Auth → callbackToken UUID */
export async function handleFgPolicyDone(request, env) {
  if (request.method !== 'POST') return json({ error: 'POST required' }, 405);
  // Lớp 2: Verify Basic Auth từ n8n (Lớp 1 là CF Access Service Token ở edge)
  const authH = request.headers.get('Authorization') || '';
  try {
    if (authH !== moviN8nAuth(env)) return json({ error: 'Unauthorized' }, 401);
  } catch { return json({ error: 'Auth config error' }, 500); }
  let body; try { body = await request.json(); } catch { return json({ error: 'Invalid JSON' }, 400); }
  const callbackToken = (body.callbackToken || '').trim();
  if (!callbackToken) return json({ error: 'Missing callbackToken' }, 400);
  // Lookup token → policyId (token is single-use, TTL same as policy)
  const policyId = await env.DASHBOARD_KV.get(`fgcb:${callbackToken}`).catch(() => null);
  if (!policyId) return json({ error: 'Invalid or expired token' }, 403);
  // Load policy data before deleting (for history)
  const policyData = await env.DASHBOARD_KV.get(`fgpolicy:${policyId}`, 'json').catch(() => null);
  // Delete both the policy and the token
  await Promise.all([
    env.DASHBOARD_KV.delete(`fgpolicy:${policyId}`).catch(() => {}),
    env.DASHBOARD_KV.delete(`fgcb:${callbackToken}`).catch(() => {}),
  ]);
  // Update tool_movi_history: đổi label từ "Đã tạo rule" → "Đã xóa rule" (tìm theo policyId)
  if (policyData) {
    try {
      const history = await env.DASHBOARD_KV.get('tool_movi_history', 'json') || [];
      const existIdx = history.findIndex(h => h.id === policyId);
      if (existIdx >= 0) {
        // Cập nhật entry cũ: đổi sang "Đã xóa rule", xóa expiresAt, đổi status
        history[existIdx].toolLabel  = 'Policy ' + policyData.type.toUpperCase() + ' — Đã xóa rule';
        history[existIdx].status     = 'done';
        history[existIdx].expiresAt  = null;
        history[existIdx].doneAt     = Date.now();
        history[existIdx].savedAt    = Date.now();
      } else {
        // Không tìm thấy entry cũ → thêm mới
        history.unshift({
          id:          policyId,
          tool:        'fg-policy-' + policyData.type,
          toolLabel:   'Policy ' + policyData.type.toUpperCase() + ' — Đã xóa rule',
          email:       policyData.email,
          displayName: policyData.email,
          createdBy:   policyData.createdBy,
          status:      'done',
          expiresAt:   null,
          doneAt:      Date.now(),
          result: {
            type:       policyData.type,
            ruleName:   policyData.ruleName  || null,
            ruleId:     policyData.ruleId    || null,
            date:       policyData.date,
            startTime:  policyData.startTime,
            endTime:    policyData.endTime,
            location:   policyData.location,
            allowApp:   policyData.allowApp,
            department: policyData.department,
            reason:     policyData.reason,
          },
          error:   null,
          input:   null,
          savedAt: Date.now(),
        });
      }
      if (history.length > 1000) history.length = 1000;
      await env.DASHBOARD_KV.put('tool_movi_history', JSON.stringify(history));
    } catch (_) {}
  }
  return json({
    success: true,
    policyId,
    message: 'Policy đã được xóa và ghi vào lịch sử',
    policy: policyData || { id: policyId },
  });
}

/* ── Tool Movi: List active FG policies ── */
export async function handleListFgPolicies(request, env, session) {
  if (request.method !== 'GET') return json({ error: 'GET required' }, 405);
  try {
    const listed = await env.DASHBOARD_KV.list({ prefix: 'fgpolicy:' });
    const now = Date.now();
    const all = await Promise.all(listed.keys.map(k => env.DASHBOARD_KV.get(k.name, 'json')));
    const policies = all
      .filter(p => p != null)          // KV already handles TTL expiry
      .filter(p => !p.expiresAt || p.expiresAt > now - 60000) // 1 min grace
      .sort((a, b) => (a.expiresAt || 0) - (b.expiresAt || 0));
    return json({ success: true, policies });
  } catch(e) {
    return json({ error: e.message }, 502);
  }
}

/* ── Tool Movi History (KV-backed) ── */
export async function hasAnyToolMoviPerm(env, session) {
  if (session.role === 'admin') return true;
  for (const key of ['tool-movi-create-user','tool-movi-block-user','tool-movi-delete-user','tool-movi-asset-search','tool-movi-check-email','tool-movi-azure-group','tool-movi-fg-policy-lan','tool-movi-fg-policy-wifi']) {
    if (await hasPerm(env, session, key)) return true;
  }
  return false;
}

export async function handleGetToolMoviHistory(request, env) {
  const session = await getSession(request, env);
  if (!session) return json({ error: 'Unauthorized' }, 401);
  if (!(await hasAnyToolMoviPerm(env, session))) return json({ error: 'Không có quyền truy cập Tool Movi' }, 403);
  const history = await env.DASHBOARD_KV.get('tool_movi_history', 'json') || [];
  const isAdmin = await isAdminUser(env, session);
  const visible = isAdmin ? history : history.filter(h => h.createdBy === session.username);
  return json({ history: visible, total: visible.length, isAdmin });
}

export async function handleSaveToolMoviHistory(request, env) {
  const session = await getSession(request, env);
  if (!session) return json({ error: 'Unauthorized' }, 401);
  if (!(await hasAnyToolMoviPerm(env, session))) return json({ error: 'Không có quyền truy cập Tool Movi' }, 403);
  if (request.method !== 'POST') return json({ error: 'POST required' }, 405);
  let body; try { body = await request.json(); } catch { return json({ error: 'Invalid JSON' }, 400); }
  const history = await env.DASHBOARD_KV.get('tool_movi_history', 'json') || [];
  const entry = {
    id:          crypto.randomUUID(),
    tool:        String(body.tool || 'create-user').slice(0, 50),
    toolLabel:   String(body.toolLabel || '').slice(0, 100),
    email:       String(body.email || '').slice(0, 200),
    displayName: String(body.displayName || '').slice(0, 200),
    createdBy:   session.username,
    status:      ['done', 'error'].includes(body.status) ? body.status : 'error',
    result:      body.result ? _truncateJson(body.result, 8000)  : null,
    error:       body.error  ? String(body.error).slice(0, 500)   : null,
    input:       body.input  ? _truncateJson(body.input, 4000)   : null,
    savedAt:     Date.now(),
  };
  history.unshift(entry);
  if (history.length > 1000) history.length = 1000;
  await env.DASHBOARD_KV.put('tool_movi_history', JSON.stringify(history));
  return json({ success: true, id: entry.id, total: history.length });
}

export async function handleClearToolMoviHistory(request, env) {
  const session = await getSession(request, env);
  if (!session || !(await isAdminUser(env, session))) return json({ error: 'Admin required' }, 403);
  await env.DASHBOARD_KV.delete('tool_movi_history');
  return json({ success: true });
}

/* ═══════════════════════════════════════════════
   Bookmarks — per-user, stored in KV
   ═══════════════════════════════════════════════ */

