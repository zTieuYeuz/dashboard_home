/* ═══════════════════════════════════════════════════════════════════════════
   kiem-kho-kien-thuc.mjs — canh cổng cho kho kiến thức của trợ lý SSH
   ───────────────────────────────────────────────────────────────────────────
   CHẠY:  node tools/kiem-kho-kien-thuc.mjs      (nên chạy trước mỗi lần deploy)

   VÌ SAO CẦN: kho kiến thức là asset CÔNG KHAI của trang và được gửi lên LLM khi
   AI tra cứu. Nguyên tắc anh Thoại đặt ra: chỉ chứa KIẾN THỨC CHUNG (giao thức,
   cách đọc output, quy trình chẩn đoán) — TUYỆT ĐỐI không có dữ liệu công ty
   (IP thật, mật khẩu, tên máy chủ, tên khách hàng, sơ đồ mạng thật).

   Người viết dễ vô tình dán một đoạn output thật vào cho "dễ hiểu" — script này
   bắt đúng chuyện đó. Máy kiểm thì không quên, người thì có.

   Cách đọc kết quả:
     ✖ CHẶN   — gần như chắc chắn là dữ liệu thật, phải bỏ trước khi deploy
     ⚠ XEM LẠI — có thể là ví dụ minh hoạ hợp lệ, tự quyết
   ═══════════════════════════════════════════════════════════════════════════ */
import { readFileSync, readdirSync } from 'node:fs';
import path from 'node:path';

const DIR = path.resolve('public/service-home');
const FILES = readdirSync(DIR).filter(f => /^ssh-field-kb.*\.js$/.test(f));

/* IP ví dụ được phép dùng để minh hoạ — dải tài liệu chuẩn (RFC 5737) + vài dải
   quen thuộc trong sách giáo khoa mạng, và DNS công cộng. */
const IP_CHO_PHEP = [
  /^192\.0\.2\./, /^198\.51\.100\./, /^203\.0\.113\./,      // RFC 5737
  /^10\.0\.0\.(1|254)$/, /^192\.168\.1\.(1|10)$/,            // ví dụ kinh điển
  /^1\.1\.1\.1$/, /^8\.8\.8\.8$/,                            // DNS công cộng
  /^255\./, /^0\.0\.0\.0$/, /^127\.0\.0\.1$/,
];

const LUAT = [
  { muc: 'CHẶN', ten: 'Mật khẩu / khoá / token',
    re: /(pass(word|wd)?|secret|token|api[_-]?key)\s*[:=]\s*\S{4,}/gi },
  { muc: 'CHẶN', ten: 'Khoá riêng',
    re: /-----BEGIN [^-\n]*PRIVATE KEY-----/g },
  { muc: 'CHẶN', ten: 'Tên miền nội bộ của công ty',
    re: /\b[a-z0-9-]+\.(home-server\.id\.vn|movi-finance\.com|local|lan|internal)\b/gi },
  { muc: 'CHẶN', ten: 'Địa chỉ MAC cụ thể',
    re: /\b(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b/gi },
  { muc: 'XEM LẠI', ten: 'Tên thiết bị/máy chủ trông như thật',
    re: /\b(SW|SW-|R-|FW-|NVR|ESXi|VM-)[A-Za-z0-9_-]{3,}\b/g },
  { muc: 'XEM LẠI', ten: 'Tên người / khách hàng',
    re: /\b(anh|chị|ông|bà)\s+[A-ZĐ][a-zà-ỹ]+\b/g, boQua: /anh Thoại/ },
];

let chan = 0, xemLai = 0;
console.log('\n═══ KIỂM KHO KIẾN THỨC ═══\n');

for (const f of FILES) {
  const src = readFileSync(path.join(DIR, f), 'utf8');
  const lines = src.split('\n');
  const bao = [];

  lines.forEach((line, i) => {
    /* Bỏ qua dòng chú thích của chính script/cảnh báo — chúng cố tình nhắc tới
       mấy từ khoá này để dặn người viết. */
    if (/^\s*(\/\*|\*|\/\/)/.test(line) && /TUYỆT ĐỐI|không chứa|KHÔNG chứa/i.test(line)) return;

    for (const l of LUAT) {
      l.re.lastIndex = 0;
      let m;
      while ((m = l.re.exec(line))) {
        if (l.boQua && l.boQua.test(m[0])) continue;
        bao.push({ muc: l.muc, ten: l.ten, dong: i + 1, doan: m[0].slice(0, 60) });
      }
    }

    /* IP: bắt riêng để còn lọc dải ví dụ hợp lệ */
    const ips = line.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) || [];
    for (const ip of ips) {
      if (IP_CHO_PHEP.some(re => re.test(ip))) continue;
      bao.push({ muc: 'XEM LẠI', ten: 'IP không nằm trong dải ví dụ chuẩn', dong: i + 1, doan: ip });
    }
  });

  if (!bao.length) { console.log('✔ ' + f + ' — sạch'); continue; }
  console.log('── ' + f);
  bao.forEach(b => {
    const dau = b.muc === 'CHẶN' ? '  ✖ CHẶN   ' : '  ⚠ XEM LẠI ';
    console.log(dau + 'dòng ' + b.dong + ' · ' + b.ten + ' → "' + b.doan + '"');
    b.muc === 'CHẶN' ? chan++ : xemLai++;
  });
  console.log('');
}

console.log('\n═══════════════════════════');
console.log('  Chặn: ' + chan + '   ·   Xem lại: ' + xemLai);
if (chan) {
  console.log('\n✖ CÓ DỮ LIỆU KHÔNG ĐƯỢC PHÉP — bỏ hết rồi mới deploy.');
  console.log('  Kho kiến thức chỉ chứa kiến thức chung, không chứa dữ liệu công ty.\n');
  process.exit(1);
}
console.log('\n✔ Không có dữ liệu công ty trong kho. Deploy được.\n');
