/* ───────────────────────────────────────────────────────────────────────────
 * creds.js — biến user/pass cho auto-login.
 *
 * ⚠️ File này được custom_startup.sh TỰ SINH LẠI lúc container khởi động, lấy
 *    giá trị từ biến môi trường FGT_USER / FGT_PASS (khai trong .env của
 *    docker-compose). Bản nằm trong repo để TRỐNG — KHÔNG chứa mật khẩu.
 *
 * Vì sao tách riêng: nhiều content script của CÙNG extension chạy chung 1
 * "isolated world" → biến var ở đây (FGT_USER, FGT_PASS) autologin.js dùng được.
 * ─────────────────────────────────────────────────────────────────────────── */
var FGT_USER = "", FGT_PASS = "";
