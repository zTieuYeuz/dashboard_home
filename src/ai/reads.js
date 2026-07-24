/* ═══════════════════════════════════════════════════════════════════
   AI read bridge — ĐỌC dữ liệu THAY MẶT user (giới hạn theo quyền)
   -------------------------------------------------------------------
   Khác MCP tool (server-side, không biết user): các nguồn ở đây chạy
   bằng PHIÊN của user. AI in khối ```dash-read {"source":"..."}``` →
   chat.js gọi POST /api/ai/read bằng COOKIE user → handler tự kiểm quyền
   (getSession + hasPerm) → user không có quyền thì bị 403, AI cũng KHÔNG
   đọc được và phải báo user bị giới hạn. Không rò rỉ dữ liệu qua quyền.
   Dùng cho dữ liệu nhạy cảm/đa-user (Movi/Meraki, FortiGate Movi…).
   ═══════════════════════════════════════════════════════════════════ */
import { json, getSession, logActivity, isAdminUser, computeEffectivePermissions } from '../core.js';
import {
  handleMerakiClients, handleMerakiDevices, handleMerakiUplinks,
  handleMerakiEvents, handleMerakiBlockedClients,
} from '../meraki.js';
import { handleMoviSystem } from '../movi-fortigate.js';
import {
  handleFortigateWebhook, handleVmwareHome, handleAsusWebhook,
  handleAsusClients, handleCasaOS, handleRustdesk,
} from '../home-services.js';
import { MOVI_READS, summarizeMerakiClients, summarizeMerakiDevices, summarizeMerakiEvents } from './movi.js';
import { pnetReadLabs, pnetReadTopology, pnetReadNodeConfig } from '../pnetlab.js';

/* 2 loại nguồn:
   - `handler(request,env)`  : TỰ kiểm quyền bên trong (Meraki/Movi — getSession+hasPerm).
   - `homeHandler(env)`      : KHÔNG tự kiểm → bridge phải kiểm quyền `perm` theo user
                               TRƯỚC khi gọi (dịch vụ nhà). Nhờ vậy MỌI read đều
                               giới hạn theo quyền user, không còn đường coarse rò rỉ. */
export const READ_REGISTRY = [
  // ── Nhà (Home) — bridge tự kiểm quyền theo user ──
  { id: 'fortigate_home', perm: 'fortigate', label: 'FortiGate Home (firewall nhà)',      homeHandler: handleFortigateWebhook,
    desc: 'Firewall nhà: hostname, phiên bản, CPU/RAM, session, interfaces (WAN IP), VPN, policy.' },
  { id: 'vmware_home',    perm: 'esxi',      label: 'VMware ESXi Home (máy ảo)',          homeHandler: handleVmwareHome,
    desc: 'Host ESXi + danh sách máy ảo (tên, vmId, poweredOn/Off), datastore.' },
  { id: 'asus_router',    perm: 'asus',      label: 'ASUS Router (mạng nhà)',             homeHandler: handleAsusWebhook,
    desc: 'Router nhà: model, firmware, uptime, WAN, CPU/RAM, băng thông.' },
  { id: 'asus_clients',   perm: 'asus',      label: 'Thiết bị nối ASUS Router',           homeHandler: handleAsusClients,
    desc: 'Danh sách thiết bị đang kết nối router nhà (tên, IP, MAC, 2.4G/5G, online).' },
  { id: 'casaos',         perm: 'casaos',    label: 'CasaOS (home server)',               homeHandler: handleCasaOS,
    desc: 'Home server: CPU/RAM/ổ đĩa, danh sách app/container Docker (running/stopped).' },
  { id: 'rustdesk',       perm: 'rustdesk',  label: 'RustDesk (máy remote)',              homeHandler: handleRustdesk,
    desc: 'Danh sách máy RustDesk remote desktop: ID, tên, OS, online/offline.' },

  // ── Văn phòng Movi — handler TỰ kiểm quyền ──
  { id: 'meraki_clients',  perm: 'meraki',         label: 'Thiết bị đang kết nối mạng Meraki (Movi)', handler: handleMerakiClients, aiTransform: summarizeMerakiClients,
    desc: 'Client đang kết nối Meraki, ĐÃ GOM SẴN: byAp (số client theo từng AP, vd byAp["F2-02"]), bySsid, tổng online/wired/wireless. Dùng cho câu "AP X có bao nhiêu client", "bao nhiêu người đang kết nối".' },
  { id: 'meraki_devices',  perm: 'meraki',         label: 'Thiết bị hạ tầng Meraki (AP/Switch)',       handler: handleMerakiDevices, aiTransform: summarizeMerakiDevices,
    desc: 'AP/Switch/Appliance Meraki (đã gom byType + tách thiết bị lỗi): model, serial, IP, firmware, trạng thái.' },
  { id: 'meraki_uplinks',  perm: 'meraki',         label: 'WAN uplinks Meraki',                        handler: handleMerakiUplinks,
    desc: 'Trạng thái các đường WAN uplink của Meraki (Movi).' },
  { id: 'meraki_events',   perm: 'meraki',         label: 'Sự kiện mạng Meraki',                       handler: handleMerakiEvents, aiTransform: summarizeMerakiEvents,
    desc: 'Sự kiện mạng gần đây trên Meraki (40 dòng gần nhất).' },
  { id: 'meraki_blocked',  perm: 'meraki',         label: 'Thiết bị bị chặn (Meraki)',                 handler: handleMerakiBlockedClients,
    desc: 'Danh sách client đang bị chặn trên Meraki.' },
  { id: 'movi_fortigate',  perm: 'fortigate-movi', label: 'Trạng thái FortiGate Movi',                 handler: handleMoviSystem,
    desc: 'Trạng thái FortiGate văn phòng Movi: CPU/RAM, phiên bản, uptime…' },

  // ── PNETLab (lab mạng) — homeHandler(env, params); bridge tự kiểm quyền hub-pnetlab ──
  { id: 'pnetlab_labs',    perm: 'hub-pnetlab', label: 'Danh sách lab PNETLab',           homeHandler: pnetReadLabs,
    desc: 'Cây folder + danh sách lab trên PNETLab (mỗi lab có "path"). Dùng path này cho các nguồn/hành động PNETLab khác.' },
  { id: 'pnetlab_topology', perm: 'hub-pnetlab', label: 'Topology 1 lab PNETLab',          homeHandler: pnetReadTopology, needsParams: true,
    desc: 'Nodes (id, tên, template, trạng thái running/stopped) + kết nối mạng của 1 lab. THAM SỐ: lab (path lab, vd /CCNA/lab1.unl).' },
  { id: 'pnetlab_config',  perm: 'hub-pnetlab', label: 'Startup config 1 node PNETLab',   homeHandler: pnetReadNodeConfig, needsParams: true,
    desc: 'Startup config của 1 node router/switch. THAM SỐ: lab (path lab) + node_id (số, lấy từ pnetlab_topology).' },

  // ── Movi network mở rộng + chẩn đoán + ESXi Movi (module riêng src/ai/movi.js) ──
  ...MOVI_READS,
];

const _byId = {};
for (const r of READ_REGISTRY) _byId[r.id] = r;

/* Quyền ĐỌC = có bất kỳ mức nào ngoài 'none' (read hoặc write). Admin: luôn được. */
async function _hasReadPerm(env, session, perm) {
  if (await isAdminUser(env, session)) return true;
  if (!perm) return true;
  const eff = await computeEffectivePermissions(env, session.username);
  const lvl = (eff && eff.permissions && eff.permissions[perm]) || 'none';
  return lvl !== 'none';
}

/* GET /api/ai/reads — client (chat.js) lấy danh sách nguồn để nhắc quyền + UI. */
export async function handleAiReadsList(request, env) {
  const session = await getSession(request, env);
  if (!session) return json({ error: 'Unauthorized' }, 401);
  return json({
    reads: READ_REGISTRY.map(r => ({ id: r.id, perm: r.perm, label: r.label, desc: r.desc, needsParams: !!r.needsParams })),
  });
}

/* POST /api/ai/read — đọc 1 nguồn THAY MẶT user (session cookie). */
export async function handleAiRead(request, env) {
  const session = await getSession(request, env);
  if (!session) return json({ ok: false, error: 'Unauthorized' }, 401);
  let b; try { b = await request.json(); } catch { return json({ ok: false, error: 'Invalid JSON' }, 400); }
  const src = _byId[(b.source || '').toString()];
  const params = (b.params && typeof b.params === 'object') ? b.params : {};
  const ip = request.headers.get('CF-Connecting-IP') || '?';
  if (!src) return json({ ok: false, error: 'Nguồn dữ liệu không tồn tại' }, 404);

  // Request giữ nguyên cookie user — dùng cho handler tự-gate + aiTransform
  const proxied = new Request('https://internal/ai-read', { method: 'GET', headers: request.headers });
  let resp;
  try {
    if (src.homeHandler) {
      // Dịch vụ nhà: bridge KIỂM QUYỀN theo user trước (handler không tự gate)
      if (!(await _hasReadPerm(env, session, src.perm))) {
        await logActivity(env, { action: 'ai-read-denied:' + src.id, username: session.username, ip, success: false, detail: 'Thiếu quyền ' + src.perm });
        return json({ ok: false, denied: true, source: src.id,
          error: 'Bạn không có quyền xem "' + src.label + '" (cần quyền ' + src.perm + '). Vì AI đọc thay bạn nên cũng không xem được — hãy báo người dùng họ bị giới hạn quyền này.' }, 403);
      }
      // homeHandler(env) hoặc homeHandler(env, params) — handler cũ bỏ qua tham số 2 (tương thích ngược)
      resp = await src.homeHandler(env, params);
    } else {
      // Movi/Meraki: handler tự-gate bằng request giữ nguyên cookie user
      resp = await src.handler(proxied, env);
    }
  } catch (e) { return json({ ok: false, error: 'Lỗi đọc: ' + ((e && e.message) || e) }, 500); }

  const ok = resp.status < 400;
  let data = null; try { data = await resp.clone().json(); } catch { /* non-json */ }
  await logActivity(env, { action: 'ai-read:' + src.id, username: session.username, ip, success: ok, detail: src.label });

  if (!ok) {
    if (resp.status === 403) {
      return json({ ok: false, denied: true, source: src.id,
        error: 'Bạn không có quyền xem "' + src.label + '". Vì AI đọc thay bạn nên cũng không xem được — hãy báo người dùng họ bị giới hạn quyền này.' }, 403);
    }
    return json({ ok: false, source: src.id, error: (data && data.error) || ('Lỗi ' + resp.status) }, 502);
  }

  // Gom gọn cho AI (nếu nguồn có aiTransform): trả về dữ liệu ĐÃ TỔNG HỢP
  // (byAp/bySsid/counts…) để AI đọc chính xác, không phải tự đếm trong đống thô,
  // và không bị cắt cụt. Lỗi transform → fallback dữ liệu gốc.
  if (src.aiTransform) {
    try { data = await src.aiTransform(data, env, proxied); }
    catch (e) { /* giữ data gốc nếu transform lỗi */ }
  }
  return json({ ok: true, source: src.id, label: src.label, data });
}
