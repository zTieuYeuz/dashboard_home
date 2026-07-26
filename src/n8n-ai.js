/* ═══════════════════════════════════════════════════════════════════
   n8n AI assistant (2026-07-25) — nút 🤖 nhúng thẳng vào n8n qua proxy
   -------------------------------------------------------------------
   Khác Termix/PNETLab/Console-Serial: KHÔNG dùng lại session n8n của
   user để đọc/ghi workflow — dùng n8n PUBLIC API chính thức (có tài
   liệu, ổn định) thay vì API nội bộ /rest/* (không tài liệu, có thể
   đổi giữa các bản n8n). Xác thực bằng header `X-N8N-API-KEY`
   (docs.n8n.io/api/authentication) — anh Thoại tự tạo key tại
   Settings → n8n API → Create an API key trong n8n, lưu server-side
   (Cloudflare secret N8N_API_KEY), KHÔNG lộ ra browser.

   Quyền: dùng CHUNG quyền 'n8n' đã có (anh Thoại chốt 2026-07-25) —
   ai vào được n8n thì tự động thấy nút AI, không cần quyền riêng.

   AN TOÀN GHI: mọi thao tác SỬA/THÊM node đều qua bước GET workflow
   hiện tại trước → sửa bản sao trong bộ nhớ → PUT lại (n8n Public API
   KHÔNG có PATCH cho /workflows/:id — chỉ PUT full-replace, đòi đủ
   name+nodes+connections+settings mỗi lần, xem handleN8nAiUpdateWorkflow) —
   không bao giờ "đoán mò" cấu trúc, luôn dựa trên dữ liệu THẬT vừa đọc.
   Ghi có audit log (logActivity) vì đây là thay đổi automation thật.
   ═══════════════════════════════════════════════════════════════════ */
import { getSession, hasPerm, logActivity } from './core.js';

const N8N_ORIGIN = 'https://n8n-home.home-server.id.vn';
const N8N_9ROUTER = 'https://9router.home-server.id.vn/v1/chat/completions';
// MCP tài liệu CHÍNH CHỦ n8n (GitBook) — KHÔNG cần API key (bản kapa.ai anh Thoại gửi thì cần key).
// Đã tự test bằng curl 2026-07-26: initialize + tools/list + tools/call đều 200, transport là
// streamable-HTTP trả SSE, stateless (không cần session id giữa các lần gọi).
const N8N_DOCS_MCP = 'https://docs.n8n.io/~gitbook/mcp';
// CHỈ 2 tool ĐỌC. Server còn expose "sendFeedback" (gửi báo cáo lên team n8n) — CỐ Ý KHÔNG cho AI
// dùng: đó là ghi dữ liệu ra dịch vụ ngoài, không phục vụ việc sửa workflow của anh Thoại.
const N8N_DOCS_TOOLS = new Set(['searchDocumentation', 'getPage']);
const N8N_LLM_MODELS = new Set(['N8N']);   // 9Router phân biệt HOA/THƯỜNG — đúng phải là "N8N" viết hoa (đã test xác nhận)
const N8N_LLM_RL_MAX = 60;      // request / 5 phút / user
const N8N_API_RL_MAX = 60;      // request đọc/ghi workflow / 5 phút / user

function _n8nJson(obj, status) { return new Response(JSON.stringify(obj), { status: status || 200, headers: { 'Content-Type': 'application/json' } }); }

async function _n8nAiAuth(request, env) {
  const sfs = request.headers.get('Sec-Fetch-Site');
  if (sfs && sfs !== 'same-origin') return { err: _n8nJson({ error: 'forbidden: cross-site request bị chặn' }, 403) };
  const origin = request.headers.get('Origin');
  if (origin) {
    try { if (new URL(origin).host !== new URL(request.url).host) return { err: _n8nJson({ error: 'forbidden: origin mismatch' }, 403) }; }
    catch { return { err: _n8nJson({ error: 'bad origin' }, 403) }; }
  }
  const session = await getSession(request, env);
  if (!session) return { err: _n8nJson({ error: 'Chưa đăng nhập dashboard' }, 401) };
  if (!(await hasPerm(env, session, 'n8n'))) return { err: _n8nJson({ error: 'Không có quyền n8n' }, 403) };
  return { session };
}

// POST /api/n8n-ai-llm — proxy 9Router (giống pattern termix-llm/console-serial-llm)
export async function handleN8nAiLlm(request, env) {
  if (request.method !== 'POST') return _n8nJson({ error: 'method' }, 405);
  const { session, err } = await _n8nAiAuth(request, env);
  if (err) return err;

  const key = env.N8N_9ROUTER_KEY;
  if (!key) return _n8nJson({ error: 'Chưa cấu hình N8N_9ROUTER_KEY (wrangler secret put N8N_9ROUTER_KEY).' }, 503);

  const rlKey = 'n8naillm:rl:' + session.username;
  const cnt = parseInt((await env.DASHBOARD_KV.get(rlKey)) || '0', 10);
  if (cnt >= N8N_LLM_RL_MAX) return _n8nJson({ error: 'Quá nhiều yêu cầu, thử lại sau ít phút.' }, 429);
  await env.DASHBOARD_KV.put(rlKey, String(cnt + 1), { expirationTtl: 300 });

  let body; try { body = await request.json(); } catch { return _n8nJson({ error: 'bad json' }, 400); }
  const model = N8N_LLM_MODELS.has(body.model) ? body.model : 'N8N';
  // reasoning_effort: alias N8N chạy trên gpt-5, mặc định nó "suy nghĩ" khá nặng cả với việc vặt
  // (đo thật 2026-07-26: mặc định 128–192 reasoning token & 3,4–4,0s; low 64 token & 2,2s;
  // minimal 0 token & 1,4s). Cho client chọn để đổi lấy tốc độ + token, nhưng chỉ nhận giá trị hợp lệ.
  const REASONING = new Set(['minimal', 'low', 'medium', 'high']);
  const payload = Object.assign({}, body, { model, stream: true });
  if (!REASONING.has(payload.reasoning_effort)) delete payload.reasoning_effort;
  // Xin usage kèm trong stream để hiện chi phí token thật cho anh Thoại (đã test: 9Router có chuyển tiếp).
  payload.stream_options = { include_usage: true };

  let upstream;
  try {
    upstream = await fetch(N8N_9ROUTER, {
      method: 'POST',
      headers: { 'Authorization': 'Bearer ' + key, 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
  } catch (e) { return _n8nJson({ error: '9Router không phản hồi: ' + ((e && e.message) || e) }, 502); }

  return new Response(upstream.body, {
    status: upstream.status,
    headers: { 'Content-Type': 'text/event-stream; charset=utf-8', 'Cache-Control': 'no-cache' },
  });
}

function _n8nRl(env, session) {
  const rlKey = 'n8naiapi:rl:' + session.username;
  return (async () => {
    const cnt = parseInt((await env.DASHBOARD_KV.get(rlKey)) || '0', 10);
    if (cnt >= N8N_API_RL_MAX) return false;
    await env.DASHBOARD_KV.put(rlKey, String(cnt + 1), { expirationTtl: 300 });
    return true;
  })();
}

/* POST /api/n8n-ai/docs {tool:'searchDocumentation'|'getPage', query?, url?}
   ─────────────────────────────────────────────────────────────────────────
   Cầu nối tới MCP tài liệu chính chủ n8n. Lý do có handler này: trợ lý trước
   đây phải ĐOÁN cú pháp node (type, tên tham số) từ mỗi những node đã có sẵn
   trong workflow đang mở — nên hay sai với node lạ. Giờ nó tra được tài liệu
   thật trước khi tạo/sửa.

   ⚠️ ĐÂY LÀ DỊCH VỤ NGOÀI (docs.n8n.io): câu truy vấn RỜI KHỎI hệ thống anh
   Thoại. Vì vậy chỉ gửi ĐÚNG chuỗi query/url do AI soạn để tra cứu kỹ thuật —
   KHÔNG bao giờ gửi kèm nội dung workflow, credentials hay dữ liệu chạy thật
   (client cũng được dặn trong system prompt). Gọi từ Worker (không phải từ
   browser) để không lộ cấu trúc nội bộ và để áp được rate-limit theo user. */
export async function handleN8nAiDocs(request, env) {
  if (request.method !== 'POST') return _n8nJson({ error: 'method' }, 405);
  const { session, err } = await _n8nAiAuth(request, env);
  if (err) return err;
  if (!(await _n8nRl(env, session))) return _n8nJson({ error: 'Quá nhiều yêu cầu, thử lại sau ít phút.' }, 429);

  let body; try { body = await request.json(); } catch { return _n8nJson({ error: 'bad json' }, 400); }
  const tool = String(body.tool || '');
  if (!N8N_DOCS_TOOLS.has(tool)) return _n8nJson({ error: 'Tool không hợp lệ (chỉ searchDocumentation / getPage).' }, 400);

  const args = {};
  if (tool === 'searchDocumentation') {
    const q = String(body.query || '').trim();
    if (!q) return _n8nJson({ error: 'Thiếu query.' }, 400);
    args.query = q.slice(0, 500);
  } else {
    const u = String(body.url || '').trim();
    // Chỉ cho đọc trang trên chính docs.n8n.io — chặn biến handler thành proxy đọc URL bất kỳ.
    let parsed; try { parsed = new URL(u); } catch { return _n8nJson({ error: 'URL không hợp lệ.' }, 400); }
    if (parsed.protocol !== 'https:' || parsed.hostname !== 'docs.n8n.io') return _n8nJson({ error: 'Chỉ đọc được trang trên https://docs.n8n.io.' }, 400);
    args.url = parsed.href;
  }

  let upstream;
  try {
    upstream = await fetch(N8N_DOCS_MCP, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Accept': 'application/json, text/event-stream' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: tool, arguments: args } }),
    });
  } catch (e) { return _n8nJson({ error: 'Không gọi được MCP tài liệu n8n: ' + ((e && e.message) || e) }, 502); }

  const raw = await upstream.text().catch(() => '');
  if (!upstream.ok) return _n8nJson({ error: `MCP tài liệu lỗi ${upstream.status}.` }, 502);

  // Transport trả SSE ("event: message\ndata: {...}") chứ không phải JSON thuần — gom các dòng data:.
  let payload = null;
  for (const line of raw.split('\n')) {
    const t = line.trim();
    if (t.indexOf('data:') !== 0) continue;
    try { const j = JSON.parse(t.slice(5).trim()); if (j && (j.result || j.error)) payload = j; } catch { /* chunk lẻ */ }
  }
  if (!payload) { try { payload = JSON.parse(raw); } catch { return _n8nJson({ error: 'MCP trả dữ liệu không đọc được.' }, 502); } }
  if (payload.error) return _n8nJson({ error: 'MCP báo lỗi: ' + (payload.error.message || 'không rõ') }, 502);

  // Rút gọn về text thuần cho LLM; cắt ngắn để 1 lần tra không nuốt hết cửa sổ ngữ cảnh.
  const parts = ((payload.result && payload.result.content) || [])
    .filter(c => c && c.type === 'text').map(c => c.text);
  // 5.000 ký tự (~1.500 token) là đủ để trả lời đúng mà không nuốt hết ngữ cảnh — kết quả tra cứu
  // còn nằm lại trong lịch sử chat các vòng sau, nên cắt sớm ở đây tiết kiệm token dồn cả lượt.
  const text = parts.join('\n\n---\n\n').slice(0, 5000);
  return _n8nJson({ ok: true, tool, text: text || '(không tìm thấy nội dung)' });
}

// GET /api/n8n-ai/workflow?id=<workflowId> — đọc TOÀN BỘ workflow (nodes/connections/settings)
export async function handleN8nAiReadWorkflow(request, env) {
  const { session, err } = await _n8nAiAuth(request, env);
  if (err) return err;
  if (!(await _n8nRl(env, session))) return _n8nJson({ error: 'Quá nhiều yêu cầu, thử lại sau ít phút.' }, 429);

  const apiKey = env.N8N_API_KEY;
  if (!apiKey) return _n8nJson({ error: 'Chưa cấu hình N8N_API_KEY (anh tạo tại n8n Settings → n8n API, rồi wrangler secret put N8N_API_KEY).' }, 503);

  const url = new URL(request.url);
  const wfId = (url.searchParams.get('id') || '').trim();
  if (!wfId) return _n8nJson({ error: 'Thiếu id workflow.' }, 400);

  let upstream;
  try {
    upstream = await fetch(`${N8N_ORIGIN}/api/v1/workflows/${encodeURIComponent(wfId)}`, {
      headers: { 'X-N8N-API-KEY': apiKey },
    });
  } catch (e) { return _n8nJson({ error: 'Không gọi được n8n: ' + ((e && e.message) || e) }, 502); }

  const text = await upstream.text().catch(() => '');
  if (!upstream.ok) return _n8nJson({ error: `n8n API lỗi ${upstream.status}: ${text.slice(0, 300)}` }, 502);
  let data; try { data = JSON.parse(text); } catch { return _n8nJson({ error: 'n8n trả dữ liệu không hợp lệ.' }, 502); }
  return _n8nJson({ ok: true, workflow: data });
}

// GET /api/n8n-ai/executions?workflowId=<id> — lịch sử chạy gần đây + CHI TIẾT NODE LỖI (nếu có).
// Đã tự test thật (curl) trước khi viết: n8n Public API /executions/:id?includeData=true trả đủ
// runData từng node trên bản n8n hiện tại của anh (một số bản cộng đồng báo chỉ trả tóm tắt —
// ĐÃ XÁC NHẬN bản này KHÔNG bị vậy). Chỉ ĐỌC, không trigger chạy gì (n8n không có API chính thức
// để tự "bấm chạy thử" — chỉ có route nội bộ không tài liệu và nó THỰC THI THẬT, không dùng ở đây).
export async function handleN8nAiCheckExecutions(request, env) {
  const { session, err } = await _n8nAiAuth(request, env);
  if (err) return err;
  if (!(await _n8nRl(env, session))) return _n8nJson({ error: 'Quá nhiều yêu cầu, thử lại sau ít phút.' }, 429);

  const apiKey = env.N8N_API_KEY;
  if (!apiKey) return _n8nJson({ error: 'Chưa cấu hình N8N_API_KEY.' }, 503);

  const url = new URL(request.url);
  const wfId = (url.searchParams.get('workflowId') || '').trim();
  if (!wfId) return _n8nJson({ error: 'Thiếu workflowId.' }, 400);

  let listResp;
  try {
    listResp = await fetch(`${N8N_ORIGIN}/api/v1/executions?workflowId=${encodeURIComponent(wfId)}&limit=5`, {
      headers: { 'X-N8N-API-KEY': apiKey },
    });
  } catch (e) { return _n8nJson({ error: 'Không gọi được n8n: ' + ((e && e.message) || e) }, 502); }
  const listText = await listResp.text().catch(() => '');
  if (!listResp.ok) return _n8nJson({ error: `n8n API lỗi ${listResp.status}: ${listText.slice(0, 300)}` }, 502);
  let list; try { list = JSON.parse(listText); } catch { return _n8nJson({ error: 'n8n trả dữ liệu không hợp lệ.' }, 502); }
  const runs = (list.data || []).map(r => ({ id: r.id, status: r.status, mode: r.mode, startedAt: r.startedAt, stoppedAt: r.stoppedAt }));

  if (!runs.length) return _n8nJson({ ok: true, recent_runs: [], detail: null, note: 'Workflow này chưa có lần chạy nào được ghi lại.' });

  // Ưu tiên soi CHI TIẾT lần lỗi gần nhất; nếu không có lỗi thì soi lần gần nhất (để xác nhận chạy OK thật).
  const target = runs.find(r => r.status === 'error') || runs[0];

  let detailResp;
  try {
    detailResp = await fetch(`${N8N_ORIGIN}/api/v1/executions/${encodeURIComponent(target.id)}?includeData=true`, {
      headers: { 'X-N8N-API-KEY': apiKey },
    });
  } catch (e) { return _n8nJson({ ok: true, recent_runs: runs, detail: null, detail_error: 'Không lấy được chi tiết: ' + e.message }); }
  const detailText = await detailResp.text().catch(() => '');
  if (!detailResp.ok) return _n8nJson({ ok: true, recent_runs: runs, detail: null, detail_error: `n8n API lỗi ${detailResp.status}` });
  let full; try { full = JSON.parse(detailText); } catch { return _n8nJson({ ok: true, recent_runs: runs, detail: null }); }

  // Rút gọn: CHỈ trả node LỖI (kèm error message) + tên các node đã chạy thành công (không kèm data
  // đầy đủ, tránh đổ hàng chục KB input/output thật không cần thiết cho AI, và giảm rủi ro lộ dữ liệu).
  const runData = (full.data && full.data.resultData && full.data.resultData.runData) || {};
  const nodesReport = Object.keys(runData).map(nodeName => {
    const runs2 = runData[nodeName] || [];
    const last = runs2[runs2.length - 1] || {};
    const ok = last.executionStatus !== 'error';
    return {
      node: nodeName,
      status: last.executionStatus || 'unknown',
      error: ok ? undefined : (last.error && (last.error.message || last.error.description || JSON.stringify(last.error).slice(0, 500))),
    };
  });

  return _n8nJson({
    ok: true,
    recent_runs: runs,
    detail: {
      execution_id: target.id,
      status: target.status,
      nodes: nodesReport,
    },
  });
}

// POST /api/n8n-ai/workflow  {workflowId, patch:{name,nodes,connections,settings}} — GHI (PUT full-replace,
// n8n Public API không có PATCH cho endpoint này — client phải gửi đủ cả 4 field, xem ghi chú bên dưới)
export async function handleN8nAiUpdateWorkflow(request, env) {
  if (request.method !== 'POST') return _n8nJson({ error: 'method' }, 405);
  const { session, err } = await _n8nAiAuth(request, env);
  if (err) return err;
  if (!(await _n8nRl(env, session))) return _n8nJson({ error: 'Quá nhiều yêu cầu, thử lại sau ít phút.' }, 429);

  const apiKey = env.N8N_API_KEY;
  if (!apiKey) return _n8nJson({ error: 'Chưa cấu hình N8N_API_KEY.' }, 503);

  let body; try { body = await request.json(); } catch { return _n8nJson({ error: 'bad json' }, 400); }
  const wfId = (body.workflowId || '').trim();
  const patch = body.patch;
  if (!wfId) return _n8nJson({ error: 'Thiếu workflowId.' }, 400);
  if (!patch || typeof patch !== 'object' || Array.isArray(patch)) return _n8nJson({ error: 'Thiếu patch (object).' }, 400);
  // n8n Public API KHÔNG hỗ trợ PATCH (partial) cho /workflows/:id — chỉ có PUT (full replace).
  // Xác nhận qua tài liệu chính thức + cộng đồng (2026-07-26, sau khi anh Thoại gặp lỗi thật
  // "PATCH method not allowed"): endpoint là PUT, và validator của n8n đòi ĐỦ CẢ 4 field gốc
  // name/nodes/connections/settings trong 1 lần gửi — thiếu "settings" là lỗi 400 "must NOT have
  // additional properties". Vì vậy bắt buộc client phải đọc workflow hiện tại trước rồi gửi lại
  // ĐỦ 4 field (không phải chỉ field muốn đổi) — không còn "cập nhật từng phần" thật sự.
  const REQUIRED = ['name', 'nodes', 'connections', 'settings'];
  const missing = REQUIRED.filter(k => !(k in patch));
  if (missing.length) return _n8nJson({ error: `Thiếu field bắt buộc: ${missing.join(', ')}. n8n yêu cầu gửi ĐỦ name+nodes+connections+settings mỗi lần ghi (không hỗ trợ patch từng phần).` }, 400);
  const cleanPatch = {};
  for (const k of REQUIRED) cleanPatch[k] = patch[k];
  // GET /workflows/:id trả cả field nội bộ trong "settings" (vd binaryMode, availableInMCP) mà PUT
  // KHÔNG chấp nhận — validator n8n báo "settings must NOT have additional properties" (đã tự test
  // curl xác nhận 2026-07-26). Client thường gửi thẳng lại settings vừa đọc được → phải lọc ở đây
  // theo đúng field n8n Public API hỗ trợ, để client khỏi phải tự biết whitelist này.
  const ALLOWED_SETTINGS = ['saveExecutionProgress', 'saveManualExecutions', 'saveDataErrorExecution', 'saveDataSuccessExecution', 'executionTimeout', 'timezone', 'errorWorkflow', 'executionOrder'];
  if (cleanPatch.settings && typeof cleanPatch.settings === 'object') {
    const s = {};
    for (const k of ALLOWED_SETTINGS) if (k in cleanPatch.settings) s[k] = cleanPatch.settings[k];
    cleanPatch.settings = s;
  }

  let upstream;
  try {
    upstream = await fetch(`${N8N_ORIGIN}/api/v1/workflows/${encodeURIComponent(wfId)}`, {
      method: 'PUT',
      headers: { 'X-N8N-API-KEY': apiKey, 'Content-Type': 'application/json' },
      body: JSON.stringify(cleanPatch),
    });
  } catch (e) { return _n8nJson({ error: 'Không gọi được n8n: ' + ((e && e.message) || e) }, 502); }

  const text = await upstream.text().catch(() => '');
  const ip = request.headers.get('cf-connecting-ip') || '?';
  if (!upstream.ok) {
    await logActivity(env, { action: 'n8n-ai-update-fail', username: session.username, ip, success: false, detail: `workflow ${wfId}: n8n API ${upstream.status} — ${text.slice(0, 200)}` });
    return _n8nJson({ error: `n8n API lỗi ${upstream.status}: ${text.slice(0, 300)}` }, 502);
  }
  await logActivity(env, { action: 'n8n-ai-update', username: session.username, ip, success: true, detail: `Sửa workflow ${wfId} qua AI — field: ${Object.keys(cleanPatch).join(',')}` });
  let data; try { data = JSON.parse(text); } catch { data = null; }
  return _n8nJson({ ok: true, workflow: data });
}
