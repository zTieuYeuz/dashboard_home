/* ═══════════════════════════════════════════════════════════════════════════
   kb-network.js — cấp kho kiến thức cho các trợ lý TERMINAL
   ───────────────────────────────────────────────────────────────────────────
   VÌ SAO CÓ FILE NÀY

   Dashboard vốn đã có kho kiến thức "Dạy AI" (Settings → AI → 🎓 Dạy AI), lưu ở
   KV khoá `ai_knowledge` dạng [{path, content}]. Nhưng kho đó chỉ phục vụ AI TỔNG
   của trang (OpenClaw đồng bộ về máy). Các trợ lý terminal — Web Console (Serial),
   SSH Hiện trường, Termix — không đọc được gì từ đó.

   Anh Thoại muốn chia làm HAI NHÓM, phân biệt bằng TIỀN TỐ ĐƯỜNG DẪN:

       dashboard/...   → kiến thức về dashboard, quy trình nội bộ (AI tổng dùng)
       network/...     → kiến thức mạng & server, DÙNG CHUNG cho cả 3 trợ lý terminal

   File này cấp nhóm `network/` cho các trang terminal. Một chỗ sửa, ba trợ lý
   cùng hưởng — không phải dạy lại từng cái.

   ⚠️ KHO NÀY BỊ GỬI LÊN LLM khi AI tra cứu → chỉ để kiến thức chung, đừng để dữ
   liệu công ty (IP thật, mật khẩu, tên máy). Có kiểm tự động ở hàm quetBiMat().
   ═══════════════════════════════════════════════════════════════════════════ */
import { getSession, hasPerm } from './core.js';

const json = (o, s = 200) => new Response(JSON.stringify(o), {
  status: s, headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' },
});

/* Quyền: ai dùng được trợ lý terminal nào thì đọc được kho network.
   Không mở cho mọi người đăng nhập — kho có thể chứa quy trình vận hành nội bộ. */
const QUYEN_DOC = ['ssh-field', 'console-serial', 'ssh'];

/* Đổi đường dẫn file thành tên mục cho AI tra:
     network/gop-cong.md      → gop-cong
     network/cisco/trunk.md   → cisco-trunk
   Bỏ tiền tố nhóm và đuôi .md để AI gọi kb_lookup cho gọn. */
function tenMuc(path) {
  return String(path)
    .replace(/^network\//, '')
    .replace(/\.(md|txt)$/i, '')
    .replace(/\//g, '-')
    .toLowerCase();
}

/* Mô tả một dòng cho mục lục: lấy tiêu đề markdown đầu tiên, hoặc dòng có chữ đầu tiên. */
function moTa(content) {
  const lines = String(content || '').split('\n');
  const h = lines.find(l => /^#{1,3}\s+\S/.test(l));
  if (h) return h.replace(/^#+\s*/, '').slice(0, 90);
  const l = lines.find(l => l.trim());
  return (l || '').slice(0, 90);
}

/* Quét dấu hiệu dữ liệu công ty — CẢNH BÁO chứ không chặn đọc: kho đã lỡ có thì
   vẫn phải dùng được, nhưng phải nói cho người quản trị biết mà dọn. */
export function quetBiMat(content) {
  const c = String(content || '');
  const canh = [];
  if (/(pass(word|wd)?|secret|token|api[_-]?key)\s*[:=]\s*\S{4,}/i.test(c)) canh.push('có thể chứa mật khẩu/token');
  if (/-----BEGIN [^-\n]*PRIVATE KEY-----/.test(c)) canh.push('có khoá riêng');
  if (/\b(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\b/i.test(c)) canh.push('có địa chỉ MAC cụ thể');
  return canh;
}

/* GET /api/kb/network — trả các mục dạng {id, mo_ta, noi_dung} cho trang terminal.
   Trang tự trộn với kho dựng sẵn trong file tĩnh (ssh-field-kb*.js). */
export async function handleKbNetwork(request, env) {
  const session = await getSession(request, env);
  if (!session) return json({ error: 'Chưa đăng nhập' }, 401);

  let duoc = false;
  for (const q of QUYEN_DOC) { if (await hasPerm(env, session, q)) { duoc = true; break; } }
  if (!duoc) return json({ error: 'Không có quyền đọc kho kiến thức mạng' }, 403);

  let files = [];
  try { files = JSON.parse(await env.DASHBOARD_KV.get('ai_knowledge') || '[]'); } catch { files = []; }

  const muc = files
    .filter(f => f && typeof f.path === 'string' && f.path.toLowerCase().startsWith('network/'))
    .map(f => ({
      id: tenMuc(f.path),
      duong_dan: f.path,
      mo_ta: moTa(f.content),
      noi_dung: String(f.content || ''),
      canh_bao: quetBiMat(f.content),
    }))
    .filter(m => m.id && m.noi_dung.trim());

  return json({ ok: true, so_muc: muc.length, muc });
}
