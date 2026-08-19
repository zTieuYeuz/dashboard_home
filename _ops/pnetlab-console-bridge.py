#!/usr/bin/env python3
"""
console-bridge — cầu nối telnet localhost cho AI gõ console PNETLab.
-------------------------------------------------------------------
CHẠY TRÊN VM PNETLAB (192.168.110.16), KHÔNG đụng file PNETLab gốc.

Vì sao: mỗi node PNETLab (IOL/dynamips) mở 1 cổng TELNET THÔ trên chính
127.0.0.1 của VM này (field "port" trong topology API, vd 30001). Guacamole
chỉ là lớp web bọc ngoài cổng đó để hiện terminal trên trình duyệt — không
liên quan gì tới việc này. Script này bỏ qua Guacamole/WebSocket hoàn toàn,
telnet THẲNG vào cổng đó từ chính server → không dính bug console-qua-tunnel
đã gặp cả ngày hôm nay.

Bind 0.0.0.0 (KHÔNG phải 127.0.0.1) vì tunnel Cloudflare chạy trên MÁY KHÁC
trong LAN, cần với tới qua mạng — bảo vệ bằng secret bắt buộc trên MỌI request.
Chỉ dùng thư viện chuẩn Python (không cần pip install).

Cài đặt:
  sudo cp pnetlab-console-bridge.py /opt/pnetlab-console-bridge.py
  sudo BRIDGE_SECRET="<chuỗi ngẫu nhiên dài>" python3 -c "print('lưu secret này để set vào wrangler secret PNET_CONSOLE_SECRET')"
  # rồi cài systemd service (xem file .service kèm theo)
"""
import http.server
import json
import os
import socket
import socketserver
import time

BIND_HOST = '0.0.0.0'
BIND_PORT = int(os.environ.get('BRIDGE_PORT', '5099'))
SECRET = os.environ.get('BRIDGE_SECRET', '')
READ_IDLE_MS = 400          # hết dữ liệu mới trong bao lâu thì coi là "đã đọc xong 1 lệnh"
MAX_TOTAL_WAIT = 12.0       # trần thời gian đọc cho 1 lệnh (giây)
CONNECT_TIMEOUT = 5.0

if not SECRET:
    raise SystemExit('BRIDGE_SECRET chưa được set (biến môi trường) — không được chạy service này thiếu secret.')


def strip_telnet_iac(data: bytes) -> bytes:
    """Bỏ các chuỗi điều khiển telnet (IAC = 0xFF) khỏi output, giữ lại text thật."""
    out = bytearray()
    i = 0
    n = len(data)
    while i < n:
        b = data[i]
        if b != 0xFF:
            out.append(b)
            i += 1
            continue
        if i + 1 >= n:
            break
        cmd = data[i + 1]
        if cmd == 0xFF:            # 0xFF 0xFF = 1 byte 0xFF thật trong dữ liệu
            out.append(0xFF)
            i += 2
        elif cmd in (251, 252, 253, 254):   # WILL/WONT/DO/DONT — có 1 byte option theo sau
            i += 3
        elif cmd == 250:            # SB ... SE (subnegotiation) — bỏ tới khi gặp SE (240)
            j = i + 2
            while j + 1 < n and not (data[j] == 0xFF and data[j + 1] == 240):
                j += 1
            i = j + 2
        else:
            i += 2
    return bytes(out)


def read_until_idle(sock: socket.socket, idle_ms: int, max_wait: float) -> str:
    sock.settimeout(idle_ms / 1000.0)
    chunks = []
    start = time.time()
    while time.time() - start < max_wait:
        try:
            chunk = sock.recv(65536)
            if not chunk:
                break
            chunks.append(chunk)
        except socket.timeout:
            break
    return strip_telnet_iac(b''.join(chunks)).decode('utf-8', errors='replace')


def run_commands(port: int, commands: list) -> dict:
    try:
        sock = socket.create_connection(('127.0.0.1', port), timeout=CONNECT_TIMEOUT)
    except OSError as e:
        return {'ok': False, 'error': 'Không kết nối được console (port %d): %s — node có đang chạy không?' % (port, e)}

    try:
        banner = read_until_idle(sock, READ_IDLE_MS, 2.0)
        # Enter 1 lần để hiện prompt (IOL console thường im lặng tới khi có input)
        sock.sendall(b'\r\n')
        banner += read_until_idle(sock, READ_IDLE_MS, 1.5)

        results = []
        for cmd in commands:
            sock.sendall(cmd.encode('utf-8') + b'\r\n')
            out = read_until_idle(sock, READ_IDLE_MS, MAX_TOTAL_WAIT)
            # bỏ dòng đầu (echo lại chính lệnh vừa gõ, telnet echo)
            lines = out.split('\r\n')
            if lines and cmd.strip() and lines[0].strip().startswith(cmd.strip()[:20]):
                lines = lines[1:]
            results.append({'command': cmd, 'output': '\r\n'.join(lines).strip()})
        return {'ok': True, 'banner': banner.strip()[:300], 'results': results}
    finally:
        try:
            sock.close()
        except OSError:
            pass


class Handler(http.server.BaseHTTPRequestHandler):
    def _send(self, status: int, obj: dict):
        body = json.dumps(obj, ensure_ascii=False).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        pass  # im lặng — tránh log lộ nội dung lệnh/console ra stdout

    def do_GET(self):
        if self.path == '/health':
            self._send(200, {'ok': True, 'service': 'pnetlab-console-bridge'})
        else:
            self._send(404, {'ok': False, 'error': 'not found'})

    def do_POST(self):
        if self.path != '/exec':
            self._send(404, {'ok': False, 'error': 'not found'})
            return
        if self.headers.get('X-Bridge-Secret', '') != SECRET:
            self._send(401, {'ok': False, 'error': 'unauthorized'})
            return
        try:
            length = int(self.headers.get('Content-Length', '0'))
            body = json.loads(self.rfile.read(length) or b'{}')
        except (ValueError, json.JSONDecodeError):
            self._send(400, {'ok': False, 'error': 'bad json'})
            return

        port = body.get('port')
        commands = body.get('commands')
        if not isinstance(port, int) or not (1 <= port <= 65535):
            self._send(400, {'ok': False, 'error': 'thiếu/sai "port" (số nguyên, port console của node)'})
            return
        if not isinstance(commands, list) or not commands or not all(isinstance(c, str) for c in commands):
            self._send(400, {'ok': False, 'error': 'thiếu "commands" (mảng chuỗi lệnh)'})
            return
        if len(commands) > 40:
            self._send(400, {'ok': False, 'error': 'quá nhiều lệnh trong 1 lần gọi (tối đa 40)'})
            return

        result = run_commands(port, commands)
        self._send(200 if result.get('ok') else 502, result)


class ThreadingHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True   # tương thích Python < 3.7 (chưa có http.server.ThreadingHTTPServer)


def main():
    server = ThreadingHTTPServer((BIND_HOST, BIND_PORT), Handler)
    print('pnetlab-console-bridge listening on %s:%d' % (BIND_HOST, BIND_PORT))
    server.serve_forever()


if __name__ == '__main__':
    main()
