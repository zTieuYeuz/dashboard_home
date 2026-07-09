# fortigate-browser — nhúng UI thật FortiGate vào dashboard qua trình duyệt container

## Vì sao
FortiGate (FortiOS SPA) **không render khi bị nhúng iframe** — đây là cơ chế
chống-clickjacking build sẵn (`window.self !== window.top`), `main.js` minified
tải từ CDN Fortinet, **không vá được**. (Đã kiểm chứng thực nghiệm bằng Chrome
DevTools: `<fos-root>` rỗng, không `ng-version`, không lỗi JS — app im lặng từ
chối vẽ.)

**Cách vòng qua:** chạy 1 Chrome trong Docker, mở FortiGate **top-level** trong đó.
FortiOS tưởng nó full-screen → render đầy đủ. Dashboard nhúng **luồng KasmVNC**
(được phép nhúng), không nhúng FortiGate trực tiếp.

```
[Dashboard iframe] ──embed──> [KasmVNC web UI] ──stream──> [Chrome trong container] ──tab top-level──> FortiGate
        (HTTPS qua CF Tunnel)         (WebSocket)                  (FortiOS render OK vì self === top)
```

---

## 1. Deploy container (trên CasaOS/Docker @ 192.168.110.21)

```bash
# Sửa VNC_PW trong docker-compose.yml trước
docker compose up -d
docker logs -f fortigate-browser   # chờ tới khi thấy KasmVNC sẵn sàng
```

Test trong LAN: mở `https://192.168.110.21:6901`
- Bỏ qua cảnh báo self-signed
- Login: user `kasm_user`, pass = `VNC_PW`
- Phải thấy Chrome đã mở sẵn trang login FortiGate → đăng nhập FortiGate 1 lần

> CasaOS/Portainer: có thể import file `docker-compose.yml` này qua "Stacks".

---

## 2. Cloudflare Tunnel — tạo hostname HTTPS

Thêm public hostname trong Zero Trust → Tunnels → (tunnel của anh) → Public Hostname:

| Field | Giá trị |
|-------|---------|
| Subdomain | `kasm` |
| Domain | `home-server.id.vn` |
| Service type | **HTTPS** |
| URL | `192.168.110.21:6901` |
| Additional settings → **No TLS Verify** | **BẬT** (origin self-signed) |

(hoặc trong `config.yml` của cloudflared:)
```yaml
ingress:
  - hostname: kasm.home-server.id.vn
    service: https://192.168.110.21:6901
    originRequest:
      noTLSVerify: true
  # ... các rule khác ...
```

Test: `https://kasm.home-server.id.vn` → phải ra KasmVNC như bước 1.

> Nếu iframe báo "refused to connect": KasmVNC gửi `X-Frame-Options`. Thêm
> **Cloudflare Transform Rule** trên `kasm.home-server.id.vn` để **Remove
> `X-Frame-Options`** (giống hệt đã làm cho FortiGate).

---

## 3. Nối vào dashboard (em làm phần này khi anh báo tunnel đã chạy)

Hai thay đổi nhỏ, đều ở thư mục chính `dashboard\`:

**a) `worker.js`** — thêm host vào CSP `frame-src` (chỗ list đã có fortigate…):
```
https://kasm.home-server.id.vn
```

**b) `public/service-home/services-embed.html`** — đổi `embedUrl` của FortiGate:
```js
// từ:
embedUrl:'https://fortigate.home-server.id.vn/',
// thành:
embedUrl:'https://kasm.home-server.id.vn/?autoconnect=1&resize=remote',
```
`?autoconnect=1&resize=remote` = tự kết nối + co giãn theo khung. (KHÔNG nhét
mật khẩu vào URL — gõ pass KasmVNC 1 lần, trình duyệt nhớ session.)

Rồi deploy staging:
```
npx wrangler deploy --config wrangler.staging.toml
```

---

## Bảo mật (quan trọng)
- **Đặt `VNC_PW` mạnh.** Ai vào được luồng này = thao tác được FortiGate đang
  đăng nhập trong container. Coi như 1 phiên admin dùng chung.
- Container chỉ phơi qua tunnel + (khuyến nghị) đặt sau Cloudflare Access nếu
  muốn lớp xác thực thứ 2.
- Phiên FortiGate sống trong container đến khi đăng xuất/khởi động lại container.

## Đánh đổi
- Nặng hơn iframe thường: ~1–2GB RAM cho container, có độ trễ nhập liệu nhẹ
  (là stream video).
- Cần container chạy nền. Đổi lại: UI FortiGate **thật, đầy đủ, ngay trong
  dashboard**, không phụ thuộc/không vỡ theo firmware Fortinet.
