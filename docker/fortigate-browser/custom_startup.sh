#!/bin/bash
# exec thay thế shell process = Chrome chạy foreground, service manager track đúng PID.
exec /usr/bin/google-chrome-stable \
  --kiosk \
  --no-first-run \
  --no-default-browser-check \
  --disable-session-crashed-bubble \
  --disable-infobars \
  --disable-translate \
  "https://fortigate.home-server.id.vn/"
