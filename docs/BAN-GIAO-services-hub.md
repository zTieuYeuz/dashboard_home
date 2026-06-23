# BÀN GIAO — Nhúng dịch vụ vào Services Hub (Dashboard)

> Tài liệu tổng hợp cách nhúng các dịch vụ nội bộ (FortiGate, n8n, camera…) vào trang
> Services Hub (`public/service-home/services-embed.html`). Ghi lại **cách làm thành công**,
> **quy tắc quyết định**, và **những cạm bẫy đã gặp** để không phải dò lại từ đầu.
>
> Cập nhật: 2026-06-23

---

## 0. QUY TẮC QUYẾT ĐỊNH (đọc cái này trước)

Khi cần nhúng 1 dịch vụ web mới vào dashboard, theo thứ tự ưu tiên:

```
┌─ Dịch vụ có cho nhúng iframe không? (thử nhúng trực tiếp xem có bị chặn)
│
├─ CÓ, nhưng auth/cookie không chạy trong iframe (cross-origin)
│     → PATTERN A: proxy qua Cloudflare Worker để thành SAME-ORIGIN (kiểu n8n)  ✅ ưu tiên
│
├─ KHÔNG cho nhúng (anti-clickjacking: FortiOS, app check window.self!==window.top)
│     → PATTERN B: chạy Chrome kiosk trong KasmVNC rồi nhúng luồng hình (kiểu FortiGate)
│
└─ Cần thao tác như người dùng thật / app desktop
      → PATTERN B
```

**Tóm tắt:** *Ưu tiên iframe kiểu n8n (Pattern A). Không được thì mới làm kiểu Chrome kiosk (Pattern B).*

---

## 1. PATTERN A — Nhúng iframe qua Worker proxy (vd: n8n)

**Khi nào dùng:** dịch vụ cho phép nhúng iframe nhưng auth bằng cookie bị chặn vì là
*third-party* (iframe cross-origin). Proxy qua Worker biến nó thành **same-origin** với dashboard
→ cookie thành first-party → auth chạy trong iframe.

### Cách làm (n8n là mẫu chuẩn — `handleN8nHomeProxy` trong `worker.js`)

1. **Route Worker** `/n8n-proxy/*` → fetch tới origin thật, inject Host header.
2. **Strip header chặn nhúng:** xóa `X-Frame-Options`, `Content-Security-Policy` của upstream.
3. **Rewrite Set-Cookie:** bỏ `Domain=`, đổi `SameSite=Lax` → cookie rơi về dashboard origin.
4. **Rewrite đường dẫn tuyệt đối trong JS/HTML:** `/assets/` → `/n8n-proxy/assets/` …
   - Với n8n (Vue Router): set `window.BASE_PATH="/n8n-proxy/"` trong `base-path.js`
     → Vue Router tự strip prefix, tự build URL REST/push/asset đúng. **Không cần** patch
     `location`/`history` thủ công.
5. **WebSocket proxy:** n8n dùng push (thực ra là SSE/WS); proxy bằng `WebSocketPair`
   (fetch `https://` + header `Upgrade: websocket`, KHÔNG dùng `wss://`).
6. **embedUrl trong SVCS** = đường dẫn tương đối: `/n8n-proxy/home`.

### Tối ưu tốc độ (đã làm)
- Asset Vite có **content-hash** trong tên (`/assets/xxx-HASH.js|css|woff2…`) là **bất biến**
  → cho browser cache lâu thay vì `no-store`:
  ```js
  const _immutableAsset = /\/assets\//.test(subPath)
    && /\.(js|css|woff2?|ttf|otf|png|jpe?g|svg|gif|webp|ico|map)$/i.test(subPath);
  rh.set('Cache-Control', _immutableAsset
    ? 'private, max-age=31536000, immutable'   // private để shared cache không giữ nội dung sau-auth
    : 'no-store, no-cache, must-revalidate');
  ```
  → lần mở thứ 2 trở đi nhanh hơn nhiều (khỏi tải + rewrite lại bundle lớn).

### Cạm bẫy Pattern A
- ⚠️ **ĐỪNG** set `Cross-Origin-Embedder-Policy` lên trang dashboard để "tối ưu" (xem mục 6).
- n8n folder card hay tạo URL double-prefix `/n8n-proxy/n8n-proxy/…` → cần defense redirect
  collapse về 1 prefix.
- `btoa()` trong CF Worker chỉ nhận Latin1 → encode qua `TextEncoder` nếu chuỗi có ký tự lạ.

---

## 2. PATTERN B — Chrome kiosk trong KasmVNC (vd: FortiGate)

**Khi nào dùng:** dịch vụ TỪ CHỐI nhúng iframe (FortiOS check `window.self !== window.top`,
anti-clickjacking, không sửa được). Giải pháp: chạy **1 trình duyệt Chrome BÊN TRONG container**
mở dịch vụ như tab top-level (app tưởng nó full-screen → render đầy đủ), rồi nhúng **luồng hình
KasmVNC** (vốn thiết kế để nhúng) vào dashboard.

### Thành phần
- Container `kasmweb/chrome:1.16.0` (KasmVNC 1.2.0) trên CasaOS (192.168.110.21).
- Cloudflare Tunnel → `kasm.home-server.id.vn`.
- Thư mục cấu hình: `docker/fortigate-browser/`.

### `custom_startup.sh` — mở Chrome kiosk
```bash
#!/bin/bash
# DÙNG exec (KHÔNG dùng &) — nếu & thì shell thoát → service manager tưởng chết → restart loop.
exec /usr/bin/google-chrome-stable \
  --kiosk \                        # ẩn address bar/tab → chỉ hiện nội dung web
  --no-first-run --no-default-browser-check \
  --disable-session-crashed-bubble --disable-infobars --disable-translate \
  --load-extension=/opt/fortigate-autologin \           # auto-login (mục 4)
  --disable-extensions-except=/opt/fortigate-autologin \
  "https://fortigate.home-server.id.vn/"
```

### Tắt auth nội bộ của KasmVNC (để browser nhúng/connect thẳng không hiện form login)
Trong `docker-compose.yml`, env:
```yaml
VNCOPTIONS: "-DisableBasicAuth 1 -SecurityTypes None"
```
- kasmweb chèn `$VNCOPTIONS` vào lệnh `vncserver` (xem `/dockerstartup/vnc_startup.sh` ~dòng 172).
- `-DisableBasicAuth 1`: bỏ Basic Auth websocket. `-SecurityTypes None`: bỏ mật khẩu VNC.
- Verify: `docker exec fortigate-browser bash -c "ps aux | grep -oE 'DisableBasicAuth [0-9]+|SecurityTypes [A-Za-z]+'"`
- Recreate: `docker compose up -d --force-recreate`

### embedUrl + Cloudflare Transform Rule
- `embedUrl` trong SVCS = **trực tiếp** `https://kasm.home-server.id.vn/?autoconnect=1&resize=remote`
  (KHÔNG qua Worker proxy — lý do ở mục "Cạm bẫy WebSocket").
- CSP `frame-src` của dashboard phải có `https://kasm.home-server.id.vn`.
- **Cloudflare Transform Rule:** strip `X-Frame-Options` trên response của `kasm.home-server.id.vn`
  (để nhúng iframe được).

---

## 3. AUTH CHO PATTERN B (gate ai được xem FortiGate)

KasmVNC nội bộ đã tắt auth → cần gate ở tầng Cloudflare. **Ràng buộc cứng:** VNC stream phải
kết nối WebSocket THẲNG browser→kasm (Worker không proxy được WS — mục 5), mà browser **không
gửi được header trên WebSocket** → mọi cách auth phải dựa trên **cookie browser tự gửi**.

| Cách | Kết quả |
|---|---|
| **Cloudflare Access — Service Token** | ❌ Chỉ qua HTTP, WebSocket bị chặn → "Kết nối thất bại". KHÔNG dùng được. |
| **Cloudflare Access — Identity (Gmail/email)** ✅ | Browser tự gửi cookie `CF_Authorization` → cả HTML lẫn WS qua được. **CHỐT DÙNG CÁI NÀY.** |
| Để mở (không auth) | Chạy nhưng nguy hiểm — ai biết hostname đều vào. |

### Điều kiện để Identity Access chạy: **SAME-SITE**
- `CF_Authorization` (SameSite=Lax) chỉ được gửi vào iframe khi dashboard và kasm **cùng site**.
- **Production:** `dashboard.home-server.id.vn` + `kasm.home-server.id.vn` = cùng `home-server.id.vn`
  → cookie qua được → **CHẠY**. ✅
- **Staging:** `...workers.dev` ≠ `home-server.id.vn` → cross-site → cookie KHÔNG qua → "This content
  is blocked". ⚠️ **Không test được trên staging** (đây là giới hạn staging, không phải lỗi).

### Trải nghiệm người dùng
- Đã đăng nhập Cloudflare Access (Gmail) 1 lần/phiên → vào FortiGate **liền mạch không hỏi gì**.
- Hết phiên Access (chỉnh ở Zero Trust → Settings → Authentication → Session Duration) → đăng nhập
  Gmail lại 1 lần (mở `kasm.home-server.id.vn` tab riêng, vì trang login Gmail không cho nhúng iframe).
- Kiểm chứng Access đang khóa: `curl -sk -D - -o /dev/null 'https://kasm.home-server.id.vn/'`
  → phải thấy `302` → `…cloudflareaccess.com/cdn-cgi/access/login/…` (người lạ bị đá ra login).

---

## 4. AUTO-LOGIN FORTIGATE (Chrome extension trong kiosk)

KasmVNC/Access gate "ai xem được", còn đây là tự đăng nhập **chính FortiOS** để khỏi gõ user/pass.

- Extension MV3 ở `docker/fortigate-browser/fortigate-autologin/` (`manifest.json` + `autologin.js`).
- Nạp qua `--load-extension` trong `custom_startup.sh`.
- **Selector FortiOS (đã xác minh):** user `#username` · pass `#secretkey` · nút `#login_button`
  · (2FA token nếu có: `#token_code`).
- Content script: poll thấy form → set `.value` + dispatch `input` → `setTimeout` → `#login_button.click()`.
- **Điền creds:** sửa 2 dòng `FGT_USER` / `FGT_PASS` trong `autologin.js` **trên server** (đừng để
  trong chat/commit). Recreate container.

### ⚠️ Cảnh báo
- **2FA:** nếu account bật FortiToken/2FA → auto-login kẹt ở bước token. Dùng account **không 2FA**.
- **Bảo mật:** mật khẩu plaintext trong container → tạo **account FortiGate riêng, quyền vừa đủ**,
  không dùng super-admin.

---

## 5. CẠM BẪY LỚN NHẤT — Worker KHÔNG proxy được WebSocket tới origin sau CF Tunnel

**Triệu chứng:** proxy `/kasm-proxy/websockify` qua Worker → upstream luôn trả **404 HTTP thường**,
`resp.webSocket = null`, không bao giờ 101. Browser thì connect thẳng `wss://kasm…/websockify` lại
upgrade bình thường (101).

**Đã thử HẾT và đều fail:**
1. `wss://` → đổi `https://` + header Upgrade
2. Forward nguyên header gốc của browser
3. Header tối thiểu + dummy `Sec-WebSocket-Key` (đúng pattern go2rtc `handleCamEmbed`)
4. `new Request(target, request)` giữ "upgrade intent"
5. Cả Basic Auth lẫn CF Access Service Token

→ **Kết luận:** với KasmVNC qua CF Tunnel, Worker không upgrade được WS subrequest. **VNC stream
bắt buộc browser connect thẳng tới origin.** (Lưu ý: go2rtc/scrypted WS proxy qua Worker thì lại
chạy — khác origin/cấu hình; đừng suy ra là "Worker luôn proxy được WS".)

**Hệ quả:** vì phải connect thẳng + browser không gửi được token trên WS → buộc dùng **Access
Identity (cookie)** chứ không phải Service Token (mục 3).

---

## 6. CẠM BẪY — Fix lag bằng Cross-Origin Isolation: ĐÃ THỬ, THẤT BẠI, ĐÃ GỠ. ĐỪNG LÀM LẠI.

**Hiện tượng lag:** nhúng FortiGate trong dashboard thì lag, mở link `kasm…` trực tiếp thì mượt.

**Nguyên nhân (xác nhận từ bundle KasmVNC):** KasmVNC giải mã hình bằng codec **QOI chạy trong
Web Worker + `SharedArrayBuffer`**. `_enableQOIWorkers()` kiểm tra `typeof SharedArrayBuffer`;
không có thì fallback JPEG/WebP trên luồng chính → lag. `SharedArrayBuffer` **chỉ có khi trang
cross-origin isolated** (COOP `same-origin` + COEP). Link trực tiếp: kasm tự gửi COOP/COEP →
isolated → QOI bật → mượt. Nhúng dashboard: không isolated → QOI tắt → lag.

**Vì sao KHÔNG fix được bằng COEP:** thêm COEP lên trang dashboard để isolated → trên production
iframe kasm **"refused to connect"**. COEP xung đột với việc nhúng iframe **cross-origin được gate
bằng Cloudflare Access** (n8n same-origin thì ok, kasm cross-origin+Access thì vỡ hẳn). Đã gỡ toàn
bộ COOP/COEP.

**Kết luận:** không thể vừa nhúng iframe kasm (cross-origin, Access-gated) vừa cross-origin-isolated
→ hai cái loại trừ nhau. **Chấp nhận lag khi nhúng**, hoặc khi cần xem kỹ thì mở **link trực tiếp**
`kasm.home-server.id.vn` (luôn mượt). Có thể cân nhắc đổi nút FortiGate thành "mở tab mới" khi cần.

---

## 7. CÁC CẠM BẪY KHÁC (ngắn)

- **Secret qua PowerShell `echo "..." | wrangler secret put`** → ra **UTF-16LE** → lưu thành chuỗi
  rác (vd 56 ký tự thay vì 12) → `btoa` lỗi / auth sai. **Fix:** dùng Git Bash `printf '%s' '...' |
  npx wrangler secret put NAME` (ASCII sạch, không BOM, không newline).
- **`custom_startup.sh` dùng `&`** để chạy nền Chrome → shell thoát → "Unknown Service" restart loop.
  **Fix:** `exec` để Chrome thay thế shell (foreground).
- **KasmVNC blacklist IP** khi quá nhiều lần SSL cert bị từ chối → restart container rồi accept cert
  đàng hoàng (`thisisunsafe` trong Chrome khi test LAN).
- **`browser tooling` (Claude-in-Chrome) treo** trên trang stream KasmVNC nặng — không phải lỗi code;
  test bằng tab nhẹ hoặc kiểm tra server-side.

---

## 8. CẢI TIẾN UI/PERF KHÁC ĐÃ LÀM

- **Sidebar nhóm "Chưa làm":** thêm `done:true` vào service đã tích hợp (fortigate, n8n); service
  khác gom vào nhóm `todo` (label "Chưa làm", order 99) qua `effCat(s)`. Xem `services-embed.html`.
- **Camera home (`hikvision.html`) load nhanh hơn:** giảm stagger nạp iframe từ **350ms → 120ms**/cam
  (`_CAM_STAGGER_MS`). 7 cam: cam cuối bắt đầu ~0.7s thay vì 2.1s. Vẫn giãn để không nghẽn băng thông.

---

## 9. CHECKLIST THÊM 1 DỊCH VỤ MỚI

1. Thử nhúng iframe trực tiếp (top-level + iframe) — bị chặn không?
2. Không bị chặn nhưng auth hỏng trong iframe → **Pattern A** (Worker proxy same-origin như n8n).
3. Bị chặn nhúng (anti-clickjacking) → **Pattern B** (KasmVNC Chrome kiosk).
4. Gate truy cập: same-site → Cloudflare Access **Identity**; KHÔNG dùng Service Token nếu có WebSocket.
5. Auto-login app (nếu cần): Chrome extension content-script (Pattern B) hoặc cookie/SSO (Pattern A).
6. Thêm vào `SVCS` (`services-embed.html`) + `done:true` khi xong; CSP `frame-src` + Transform Rule
   nếu nhúng cross-origin.
7. Deploy **staging** trước (`npx wrangler deploy --config wrangler.staging.toml`); **production do
   anh Thoai tự deploy** (`npx wrangler deploy`).
