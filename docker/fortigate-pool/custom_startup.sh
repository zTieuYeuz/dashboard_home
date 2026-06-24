#!/bin/bash
# ──────────────────────────────────────────────────────────────────────────
# Container POOL — Chrome kiosk + navigator (hộp thư) + extension tự đổi site.
# KHÔNG dùng CDP (Chrome 136+ chặn remote-debugging). Extension poll navigator
# để đổi trang. Role cố định theo container qua FGT_USER/FGT_PASS.
# ──────────────────────────────────────────────────────────────────────────
set -e

FGT_URL="${FGT_URL:-https://fortigate.home-server.id.vn/}"

# ── Điền creds vào extension pool ──
EXT_SRC=/opt/pool-ext
EXT=/tmp/fgt-ext
rm -rf "$EXT"; mkdir -p "$EXT"
cp -r "$EXT_SRC"/. "$EXT"/
U_B64=$(printf '%s' "${FGT_USER:-}" | base64 | tr -d '\n')
P_B64=$(printf '%s' "${FGT_PASS:-}" | base64 | tr -d '\n')
cat > "$EXT/creds.js" <<EOF
var FGT_USER = atob("$U_B64"), FGT_PASS = atob("$P_B64");
EOF

# ── Navigator (hộp thư lệnh điều hướng) chạy nền ──
python3 /opt/navigator.py &

# ── Chrome kiosk (không cần remote-debugging nữa) ──
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
