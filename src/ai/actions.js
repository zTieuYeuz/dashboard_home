/* ═══════════════════════════════════════════════════════════════════
   AI action registry + executor (Phase 2)
   -------------------------------------------------------------------
   Triết lý: AI hành động THAY MẶT user, KHÔNG có quyền riêng.
   Luồng: AI in khối ```dash-action {json}``` → chat.js (chạy trong trình
   duyệt của user) kiểm quyền + hỏi xác nhận → gọi POST /api/ai/exec bằng
   COOKIE của user → server kiểm quyền LẦN NỮA (defense-in-depth) rồi chạy.
   → user bị giới hạn gì thì AI cũng bị chặn (403 kèm lý do), và ghi audit.
   ═══════════════════════════════════════════════════════════════════ */
import { json, getSession, logActivity, isAdminUser, computeEffectivePermissions } from '../core.js';
import { handleFortigateReboot, handleVmwareHomePower, handleAsusReboot, handleCasaosAppState, handleMoviVmwarePower } from '../home-services.js';
import { submitForm } from './movi.js';

/* danger: 'safe' = làm ngay | 'confirm' = phải xác nhận trong dashboard
   perm: khoá quyền dịch vụ user cần | adminOnly: chỉ admin */
export const ACTION_REGISTRY = [
  {
    id: 'test_ping',
    label: 'Kiểm tra điều khiển (test — vô hại)',
    perm: null, adminOnly: false, danger: 'confirm',
    desc: 'Hành động thử: KHÔNG tác động gì tới hệ thống, chỉ để kiểm tra AI có điều khiển được dashboard không.',
    params: [],
  },
  {
    id: 'fortigate_reboot',
    label: 'Khởi động lại FortiGate Home',
    perm: 'fortigate', adminOnly: true, danger: 'confirm',
    desc: 'Khởi động lại firewall FortiGate Home. Mạng sẽ gián đoạn vài phút.',
    params: [],
  },
  {
    id: 'vmware_vm_power',
    label: 'Điều khiển nguồn máy ảo (ESXi)',
    perm: 'esxi', adminOnly: false, danger: 'confirm',
    desc: 'Bật/tắt/khởi động lại/tạm dừng một máy ảo trên ESXi Home.',
    params: [
      { name: 'vmId',   desc: 'ID máy ảo', required: true },
      { name: 'action', desc: 'powerOn | powerOff | reset | suspend | shutdownGuest | rebootGuest', required: true },
    ],
  },
  {
    id: 'asus_reboot',
    label: 'Khởi động lại ASUS Router',
    perm: 'asus', adminOnly: true, danger: 'confirm',
    desc: 'Khởi động lại router ASUS. Mạng nhà sẽ gián đoạn 1-2 phút.',
    params: [],
  },
  {
    id: 'casaos_app_state',
    label: 'Bật/tắt container CasaOS',
    perm: 'casaos', adminOnly: false, danger: 'confirm',
    // TẠM TẮT (2026-07-05): bản CasaOS này lỗi round-trip GET→PUT compose (types.External).
    // Chờ anh Thoai bắt payload thật từ CasaOS UI (F12) để chốt endpoint → bật lại disabled:false.
    disabled: true,
    desc: 'Start / stop / restart một app (container) trên CasaOS home server. (TẠM TẮT — chờ chốt API CasaOS.)',
    params: [
      { name: 'id',     desc: 'Tên app/container (theo danh sách CasaOS, vd: jellyfin)', required: true },
      { name: 'action', desc: 'start | stop | restart', required: true },
    ],
  },
  {
    id: 'movi_vm_power',
    label: 'Điều khiển nguồn máy ảo (ESXi Movi)',
    perm: 'esxi', adminOnly: false, danger: 'confirm',
    desc: 'Bật/tắt/khởi động lại một máy ảo trên host ESXi của Movi (host 1 hoặc 2).',
    params: [
      { name: 'host',   desc: 'Số host Movi: 1 hoặc 2', required: true },
      { name: 'vmId',   desc: 'ID máy ảo', required: true },
      { name: 'action', desc: 'powerOn | powerOff | reset | suspend | shutdownGuest | rebootGuest', required: true },
    ],
  },
  {
    id: 'form_submit',
    label: 'Gửi biểu mẫu tới n8n (theo quy tắc định sẵn)',
    // perm null: quyền/adminOnly được kiểm THEO TỪNG FORM ở server (submitForm) —
    // vì mỗi biểu mẫu có yêu cầu quyền riêng.
    perm: null, adminOnly: false, danger: 'confirm',
    desc: 'Gửi 1 biểu mẫu nghiệp vụ (vd tạo user Movi) tới n8n. Dashboard validate đủ trường + đúng quy tắc rồi mới gửi. Lấy danh sách biểu mẫu + trường + quy tắc bằng tool list_dashboard_forms (hoặc GET /api/ai/forms).',
    params: [
      { name: 'form', desc: 'ID biểu mẫu (vd movi_create_user)', required: true },
      { name: 'data', desc: 'Object dữ liệu các trường đã thu thập đủ theo quy tắc', required: true },
    ],
  },
];

const _byId = {};
for (const a of ACTION_REGISTRY) _byId[a.id] = a;

async function _hasPerm(env, session, action) {
  if (await isAdminUser(env, session)) return true;
  if (action.adminOnly) return false;
  if (!action.perm) return true;
  const eff = await computeEffectivePermissions(env, session.username);
  const lvl = (eff && eff.permissions && eff.permissions[action.perm]) || 'none';
  return lvl !== 'none';
}

/* GET /api/ai/actions — client (chat.js) lấy registry để kiểm quyền + xác nhận UI */
export async function handleAiActionsList(request, env) {
  const session = await getSession(request, env);
  if (!session) return json({ error: 'Unauthorized' }, 401);
  return json({
    actions: ACTION_REGISTRY.filter(a => !a.disabled).map(a => ({
      id: a.id, label: a.label, perm: a.perm || null, adminOnly: !!a.adminOnly,
      danger: a.danger, desc: a.desc, params: a.params || [],
    })),
  });
}

/* POST /api/ai/exec — thực thi 1 hành động THAY MẶT user (session cookie). */
export async function handleAiExec(request, env) {
  const session = await getSession(request, env);
  if (!session) return json({ ok: false, error: 'Unauthorized' }, 401);
  let b; try { b = await request.json(); } catch { return json({ ok: false, error: 'Invalid JSON' }, 400); }
  const action = _byId[(b.action || '').toString()];
  const params = (b.params && typeof b.params === 'object') ? b.params : {};
  const ip = request.headers.get('CF-Connecting-IP') || '?';
  if (!action) return json({ ok: false, error: 'Hành động không tồn tại' }, 404);
  if (action.disabled) return json({ ok: false, error: 'Hành động "' + action.label + '" đang tạm tắt (chờ hoàn thiện). Hãy báo người dùng và ghi log_unresolved.' }, 503);

  // ── Enforce: AI bị chặn đúng như user ──
  if (!(await _hasPerm(env, session, action))) {
    await logActivity(env, { action: 'ai-denied:' + action.id, username: session.username, ip, success: false,
      detail: 'Thiếu quyền ' + (action.perm || 'admin') });
    return json({ ok: false, denied: true,
      error: 'Bạn không có quyền thực hiện "' + action.label + '" (cần quyền ' + (action.perm || 'admin') + '). Vì AI hành động thay mặt bạn nên cũng không làm được.' }, 403);
  }

  // ── Execute (server-side, nhưng chỉ SAU khi đã kiểm quyền theo user) ──
  let resp;
  try {
    if (action.id === 'test_ping') {
      resp = json({ ok: true, message: 'pong — AI điều khiển dashboard thành công (không tác động gì).' });
    } else if (action.id === 'fortigate_reboot') {
      resp = await handleFortigateReboot(env);
    } else if (action.id === 'vmware_vm_power') {
      const req = new Request('https://internal/ai-exec', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ vmId: params.vmId, action: params.action }),
      });
      resp = await handleVmwareHomePower(req, env);
    } else if (action.id === 'asus_reboot') {
      const req = new Request('https://internal/ai-exec', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' });
      resp = await handleAsusReboot(req, env);
    } else if (action.id === 'casaos_app_state') {
      const req = new Request('https://internal/ai-exec', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id: params.id, action: params.action }),
      });
      resp = await handleCasaosAppState(req, env);
    } else if (action.id === 'movi_vm_power') {
      const host = String(params.host) === '2' ? 2 : 1;
      const req = new Request('https://internal/ai-exec', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ vmId: params.vmId, action: params.action }),
      });
      resp = await handleMoviVmwarePower(req, env, host);
    } else if (action.id === 'form_submit') {
      // submitForm tự kiểm quyền theo form + validate + audit riêng (ai-form:*)
      return await submitForm(env, session, params, ip);
    } else {
      return json({ ok: false, error: 'Hành động chưa được hỗ trợ thực thi' }, 501);
    }
  } catch (e) {
    return json({ ok: false, error: 'Lỗi thực thi: ' + ((e && e.message) || e) }, 500);
  }

  const okStatus = resp.status < 400;
  let data = null; try { data = await resp.clone().json(); } catch { /* non-json */ }
  await logActivity(env, { action: 'ai:' + action.id, username: session.username, ip, success: okStatus,
    detail: (action.label + ' ' + JSON.stringify(params)).slice(0, 160) });
  return json({ ok: okStatus, action: action.id, label: action.label, result: data });
}
