#!/usr/bin/env python3
# ──────────────────────────────────────────────────────────────────────────
# navigator.py — "hộp thư" lệnh điều hướng (KHÔNG dùng CDP, vì Chrome 136+ chặn
# remote-debugging-port). Dashboard POST /open {url} → lưu lại. Extension trong
# Chrome poll GET /next để lấy url rồi tự đổi trang.
#
# Chỉ dùng thư viện chuẩn Python — KHÔNG cần pip install.
#
# API:
#   POST /open   {"url":"https://fortigate2.home-server.id.vn/"}  → đặt lệnh
#   GET  /next                                                    → {"url": ...|null} (lấy & xoá)
#   GET  /health                                                  → {"status":"ok"}
# ──────────────────────────────────────────────────────────────────────────
import json, os, http.server, socketserver, threading

LISTEN       = int(os.environ.get("NAV_PORT", "8080"))
ALLOW_SUFFIX = os.environ.get("NAV_ALLOW_SUFFIX", ".home-server.id.vn")

_lock = threading.Lock()
_pending = {"url": None}


class Handler(http.server.BaseHTTPRequestHandler):
    def _send(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self._send(200, {})

    def do_GET(self):
        if self.path.startswith("/health"):
            return self._send(200, {"status": "ok"})
        if self.path.startswith("/next"):
            with _lock:
                u = _pending["url"]; _pending["url"] = None
            return self._send(200, {"url": u})
        self._send(404, {"error": "not found"})

    def do_POST(self):
        if not self.path.startswith("/open"):
            return self._send(404, {"error": "not found"})
        try:
            n = int(self.headers.get("Content-Length", "0"))
            data = json.loads(self.rfile.read(n).decode() or "{}")
            url = data["url"]
            if not (url.startswith("https://") or url.startswith("http://")):
                raise ValueError("URL phải bắt đầu bằng http(s)://")
            host = url.split("://", 1)[1].split("/", 1)[0].split(":")[0]
            if ALLOW_SUFFIX and not host.endswith(ALLOW_SUFFIX):
                raise ValueError(f"Domain '{host}' không thuộc {ALLOW_SUFFIX} — từ chối")
            with _lock:
                _pending["url"] = url
            self._send(200, {"status": "ok", "url": url})
        except Exception as e:
            self._send(400, {"error": str(e)})

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    with socketserver.ThreadingTCPServer(("0.0.0.0", LISTEN), Handler) as httpd:
        print(f"[navigator] hộp thư mode, nghe :{LISTEN}", flush=True)
        httpd.serve_forever()
