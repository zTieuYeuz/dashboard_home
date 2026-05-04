# Home Lab Dashboard

Một dashboard tập trung được host trên Cloudflare Workers dùng để theo dõi tất cả các dịch vụ (services) trong hệ thống mạng gia đình (Home Lab).

## Kiến trúc & Codebase

- **Worker (`worker.js`)**: Backend viết bằng Cloudflare Workers. 
  - Khai báo danh sách các services (`SERVICES` list với URL để ping như ESXi, n8n, 9Router). 
  - Xử lý các API endpoint như `/api/status` (ping check dịch vụ), `/api/n8n/overview`, `/api/n8n/exec`, `/api/9router`, `/api/esxi` bằng cách fetch đến hệ thống backend.
  - Chịu trách nhiệm router các request tĩnh tới thư mục `public/*`.

- **Frontend (`public/` & `index.html`)**: UI HTML/CSS thuần (Vanilla JS) không dùng framework. 
  - Giao diện Dark theme, responsive.
  - Tính năng tự động auto-refresh 60s/lần cập nhật trạng thái Online/Offline của các server (fetch qua `/api/status` từ worker).
  - Có các thẻ summary, danh sách các services, nút chuyển đến trang chi tiết.
  
- **Các trang chi tiết**: Từng service có 1 file html riêng.
  - `n8n.html`: Hiện workflows, executions, status của n8n (qua API Cloudflare worker `/api/n8n/overview`).
  - `9router.html`: Quản lý LoadBalancer API / AI Router.
  - `esxi.html`: Tương tự theo dõi máy chủ VMWare.
  - `casaos.html`: Nhúng dashboard CasaOS qua Cloudflare Tunnel (`https://casaos.home-server.id.vn`). Không còn giới hạn LAN-only.

## Cài đặt cấu hình

Hệ thống được deploy hoàn toàn serverless bằng `wrangler`.
- Sửa các URL đích tại đầu file `worker.js`.
- File Cấu hình: `wrangler.toml`

## Giao diện Home

Trang Home đã được tinh chỉnh UI theo phong cách hiện đại (`Inter` font, bo góc, grid balanced), bỏ bớt Uptime/Logs và tập trung vào:
1. Thống kê số lượng service online.
2. Danh sách service với trạng thái hiển thị rõ ràng.
3. Thông tin IP LAN, Quick Links và trạng thái Worker phản hồi.
4. Đo tốc độ mạng: Kết quả là tốc độ download từ trình duyệt của bạn đến Cloudflare (server gần nhất của Cloudflare, không phải tốc độ nội bộ LAN hay đến từng service riêng lẻ).
