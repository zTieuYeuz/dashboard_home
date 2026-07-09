# FortiGate Pool — nhúng nhiều site, tối đa 2 người, có phân quyền

Mô hình: vài container Chrome điều khiển được (role cố định admin/view). Dashboard
cấp 1 container cho mỗi người, gọi **navigator** để đổi sang site bất kỳ; extension
auto-login điền account theo role của container.

## Vì sao chạy được (mà 200 container thì không)
- Người dùng tối đa 2 → chỉ cần 2–4 container (~1GB RAM mỗi cái), KHÔNG phải 200.
- Account admin/view giống nhau toàn site → chỉ 2 bộ creds.
- Navigator chỉ đổi URL tab (CDP `Page.navigate`) → nhẹ.

## Yêu cầu
- Image `kasmweb/chrome:1.16.0` có sẵn `python3` (navigator dùng thư viện chuẩn,
  không cần pip). Kiểm tra: `docker run --rm kasmweb/chrome:1.16.0 which python3`.
- Thư mục `../fortigate-browser/fortigate-autologin/` (extension) phải tồn tại.

## Phase 1 — test 1 slot
```bash
cd docker/fortigate-pool
cp .env.example .env && nano .env        # điền ADM_USER/ADM_PASS
docker compose up -d
```
Test trên LAN:
```bash
# Đổi tab sang 1 site FortiGate → phải thấy tab nhảy + tự đăng nhập
curl -X POST http://192.168.110.21:8911/open \
     -H 'Content-Type: application/json' \
     -d '{"url":"https://fortigate.home-server.id.vn/"}'

# Health check
curl http://192.168.110.21:8911/health      # → {"status":"ok"}
```
Xem stream: `https://192.168.110.21:6911` (KasmVNC).

Nếu tab nhảy đúng + auto-login chạy → Phase 1 OK. Báo lại để làm **Phase 2**:
- Bỏ comment slot view trong `docker-compose.yml` (người thứ 2 / role view).
- Tạo Cloudflare Tunnel: `kasm-a1` / `nav-a1` (và `kasm-v1` / `nav-v1`) → các cổng tương ứng.
- Tích hợp dashboard: cấp phát container theo người + danh sách 200 site + nút bấm gọi `/open`.

## Bảo mật
- CDP chỉ mở trong container (`--remote-debugging-address=127.0.0.1`), không ra ngoài.
- Navigator chỉ điều hướng tới `*.home-server.id.vn` (`NAV_ALLOW_SUFFIX`).
- Khi đưa lên tunnel, đặt **Cloudflare Access** cho cả `kasm-*` lẫn `nav-*`.
- KasmVNC `DisableBasicAuth` → service OPEN trong LAN, bảo vệ bằng tunnel + Access.
```
