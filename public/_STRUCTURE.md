# Dashboard — Cấu trúc thư mục

```
public/
├── index.html              ← Trang chủ dashboard (danh sách services + status)
├── login.html              ← Trang đăng nhập
├── bookmarks.html          ← Bookmarks / liên kết nhanh
├── viewer.html             ← File viewer
├── policy.html             ← Chính sách & tài liệu phân quyền (chỉ đọc)
│
├── users.html              ← Quản lý users + đổi mật khẩu + MFA (admin)
├── settings.html           ← Cài đặt hệ thống + Role Management + Audit Log (admin)
│
├── service-home/           ← Các trang quản lý hạ tầng nội bộ (home-server)
│   ├── esxi.html           ← VMware ESXi
│   ├── n8n.html            ← n8n Automation
│   ├── casaos.html         ← CasaOS
│   ├── 9router.html        ← 9Router
│   ├── asus.html           ← ASUS Router
│   ├── ssh.html            ← SSH Terminal
│   ├── fortigate.html      ← FortiGate (home)
│   └── hikvision.html      ← Camera Hikvision
│
└── service-movi/           ← Các trang quản lý hạ tầng văn phòng Movi
    ├── meraki.html         ← Meraki Network
    ├── topology.html       ← Network Topology (Movi Map)
    ├── fortigate-movi.html ← FortiGate Movi
    ├── camera-movi.html    ← Camera Movi
    ├── n8n-movi.html       ← n8n Movi Automation
    ├── vmware01-movi.html  ← VMware ESXi 01 (Movi)
    ├── vmware02-movi.html  ← VMware ESXi 02 (Movi)
    └── tool-movi.html      ← Tool Movi (Tạo user email, v.v.)
```

## Nguyên tắc tổ chức

### Mỗi trang là độc lập
- Mỗi `.html` file có inline CSS và JS riêng → chỉnh 1 trang không ảnh hưởng trang khác
- Không có shared global state giữa các trang
- Tất cả data fetch qua `/api/*` endpoints

### Khi thêm service mới
Cần cập nhật **3 chỗ**:

1. **`worker.js`** — `ALL_SERVICES` array (dòng ~6) + API route handler
2. **`settings.html`** — `SERVICE_HOME_PAGES` hoặc `SERVICE_MOVI_PAGES` (dòng ~697-750)  
3. **`users.html`** — `ALL_SERVICES` array (dòng ~272)

### Permission keys
Tất cả permission keys phải trùng với `id` trong `ALL_SERVICES`:
- Service Home: `esxi`, `n8n`, `casaos`, `9router`, `fortigate`, `asus`, `ssh`, `uptime-kuma`, `camera`
- Service Movi: `meraki`, `topology`, `fortigate-movi`, `camera-movi`, `n8n-movi`, `vmware01-movi`, `vmware02-movi`, `tool-movi`

### Phân quyền
- `none` = ẩn service, không thể vào trang
- `read` = xem được data, không thao tác được
- `write` = toàn quyền (xem + thao tác)
- Admin = bypass tất cả permission checks

## Admin pages

| Trang | URL | Ai xem được |
|-------|-----|-------------|
| users.html | `/users.html` | Admin only (phần create/delete) |
| settings.html | `/settings.html` | Admin (tabs User/SysConfig/Roles), User thường (tab Tài khoản, Audit Log) |
| policy.html | `/policy.html` | Tất cả authenticated users |
