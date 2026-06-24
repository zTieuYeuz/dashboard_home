#!/bin/bash
# ──────────────────────────────────────────────────────────────────────────
# FortiGate kiosk — điền user/pass/url từ BIẾN MÔI TRƯỜNG (docker-compose/.env)
# ──────────────────────────────────────────────────────────────────────────
# Đổi sang site FortiGate khác chỉ cần đổi 3 biến trong .env, KHÔNG sửa file .js:
#   FGT_URL  = trang FortiGate cần mở   (vd https://fortigate2.home-server.id.vn/)
#   FGT_USER = tài khoản đăng nhập
#   FGT_PASS = mật khẩu  (mọi ký tự đặc biệt đều OK — mã hoá base64 bên dưới)
#
# exec thay thế shell = Chrome chạy foreground, service manager track đúng PID.
# ──────────────────────────────────────────────────────────────────────────
set -e

FGT_URL="${FGT_URL:-https://fortigate.home-server.id.vn/}"

# Extension được mount READ-ONLY ở /opt → copy ra nơi ghi được rồi chèn creds.
EXT_SRC=/opt/fortigate-autologin
EXT=/tmp/fgt-ext
rm -rf "$EXT"; mkdir -p "$EXT"
cp -r "$EXT_SRC"/. "$EXT"/

# Sinh creds.js an toàn cho MỌI ký tự: base64-hoá trong shell, atob() giải mã ở
# trình duyệt. base64 chỉ gồm [A-Za-z0-9+/=] nên không vỡ cú pháp JS.
U_B64=$(printf '%s' "${FGT_USER:-}" | base64 | tr -d '\n')
P_B64=$(printf '%s' "${FGT_PASS:-}" | base64 | tr -d '\n')
cat > "$EXT/creds.js" <<EOF
/* Tự sinh lúc khởi động từ biến môi trường — KHÔNG sửa tay. */
var FGT_USER = atob("$U_B64"), FGT_PASS = atob("$P_B64");
EOF

exec /usr/bin/google-chrome-stable \
  --kiosk \
  --no-first-run \
  --no-default-browser-check \
  --disable-session-crashed-bubble \
  --disable-infobars \
  --disable-translate \
  --load-extension="$EXT" \
  --disable-extensions-except="$EXT" \
  "$FGT_URL"
