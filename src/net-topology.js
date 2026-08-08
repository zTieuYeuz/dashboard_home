/* ═══════════════════════════════════════════════════════════════════════════
   net-topology.js — SƠ ĐỒ HỆ THỐNG MẠNG (dữ liệu riêng của công ty)
   ───────────────────────────────────────────────────────────────────────────
   VÌ SAO TÁCH KHỎI KHO KIẾN THỨC

   Kho kiến thức (ai_knowledge, nhóm network/) là KIẾN THỨC CHUNG và là asset
   công khai của trang. Sơ đồ hệ thống thì ngược lại: IP thật, tên thiết bị thật,
   ai nối với ai — đây là DỮ LIỆU CÔNG TY. Anh Thoại đã chốt rõ hai thứ này không
   được lẫn vào nhau.

   Nên sơ đồ nằm ở khoá KV riêng, chỉ ra vào qua API có gác quyền, KHÔNG bao giờ
   là file tĩnh ai cũng tải được.

   VÌ SAO CẦN SƠ ĐỒ

   AI kém về network chủ yếu vì mỗi cuộc hội thoại nó bắt đầu từ số không: nhìn
   vài dòng output rồi phải đoán cả hệ thống. Người kỹ sư giỏi thì ngược lại —
   họ mang sẵn bản đồ trong đầu, nên chỉ cần một hai lệnh là khoanh được vùng.
   Sơ đồ ở đây chính là bản đồ đó, viết ra để AI dùng lại giữa các phiên.

   Sơ đồ do AI TỰ KHẢO SÁT rồi ĐỀ XUẤT (đọc CDP/LLDP, interface, route, VLAN),
   anh Thoại duyệt thì mới lưu. Không tự ghi — dữ liệu sai còn tệ hơn không có.
   ═══════════════════════════════════════════════════════════════════════════ */
import { getSession, hasPerm, logActivity } from './core.js';

const KEY = 'net_topology';
const QUYEN = ['ssh-field', 'console-serial', 'ssh'];

const json = (o, s = 200) => new Response(JSON.stringify(o), {
  status: s, headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' },
});

async function duocDoc(env, session) {
  for (const q of QUYEN) if (await hasPerm(env, session, q)) return true;
  return false;
}

/* GET  /api/net-topology  → đọc sơ đồ
   PUT  /api/net-topology  → ghi đè (chỉ khi anh Thoại đã bấm duyệt ở khung chat)
   Lưu cả LỊCH SỬ 10 bản gần nhất: sơ đồ sai làm AI chẩn đoán lệch, phải quay lui được. */
export async function handleNetTopology(request, env) {
  const session = await getSession(request, env);
  if (!session) return json({ error: 'Chưa đăng nhập' }, 401);
  if (!(await duocDoc(env, session))) return json({ error: 'Không có quyền' }, 403);

  if (request.method === 'GET') {
    let d = null;
    try { d = JSON.parse(await env.DASHBOARD_KV.get(KEY) || 'null'); } catch { d = null; }
    if (!d) {
      return json({
        ok: true, co_so_do: false,
        goi_y: 'Chưa có sơ đồ hệ thống. Hãy chạy pha KHẢO SÁT: đọc CDP/LLDP neighbor, '
             + 'interface, VLAN, route trên các thiết bị đang mở, rồi đề xuất sơ đồ để anh Thoại duyệt.',
      });
    }
    return json({ ok: true, co_so_do: true, so_do: d.so_do, cap_nhat: d.cap_nhat, boi: d.boi });
  }

  if (request.method === 'PUT') {
    let b; try { b = await request.json(); } catch { return json({ error: 'JSON hỏng' }, 400); }
    const so_do = b && b.so_do;
    if (!so_do || typeof so_do !== 'object') return json({ error: 'Thiếu so_do' }, 400);

    /* Chặn kích thước: sơ đồ là bản tóm tắt có chọn lọc, không phải nơi đổ nguyên
       running-config vào (vừa phình, vừa dễ lọt mật khẩu trong config). */
    const raw = JSON.stringify(so_do);
    if (raw.length > 60000) return json({ error: 'Sơ đồ quá lớn (>60KB). Tóm tắt lại, đừng dán nguyên config.' }, 400);
    if (/-----BEGIN [^-\n]*PRIVATE KEY-----/.test(raw) ||
        /(password|psksecret|secret)[ \t]*[:=][ \t]*\S{4,}/i.test(raw)) {
      return json({ error: 'Sơ đồ chứa thứ trông như mật khẩu/khoá. Bỏ ra rồi lưu lại — sơ đồ chỉ để mô tả cấu trúc.' }, 400);
    }

    let cu = null;
    try { cu = JSON.parse(await env.DASHBOARD_KV.get(KEY) || 'null'); } catch { cu = null; }
    const lich_su = (cu && Array.isArray(cu.lich_su) ? cu.lich_su : []);
    if (cu && cu.so_do) lich_su.unshift({ so_do: cu.so_do, cap_nhat: cu.cap_nhat, boi: cu.boi });

    const moi = {
      so_do,
      cap_nhat: Date.now(),
      boi: session.username || '?',
      lich_su: lich_su.slice(0, 9),
    };
    await env.DASHBOARD_KV.put(KEY, JSON.stringify(moi));
    await logActivity(env, {
      action: 'net-topology:save',
      username: session.username || '?',
      ip: request.headers.get('CF-Connecting-IP') || '?',
      success: true,
      detail: 'Cập nhật sơ đồ hệ thống mạng (' + Math.round(raw.length / 1024) + ' KB)',
    });
    return json({ ok: true, cap_nhat: moi.cap_nhat });
  }

  return json({ error: 'method' }, 405);
}
