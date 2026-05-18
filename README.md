# Home Lab Dashboard — Tài liệu Kỹ thuật

> **Cập nhật lần cuối:** 2026-05-18  
> Tài liệu này ghi lại toàn bộ kiến trúc, những gì đã làm, những gì đang dở, để AI hoặc người khác có thể tiếp tục ngay lập tức mà không làm hỏng.

---

## ⚡ CHECKLIST CHO SESSION MỚI — ĐỌC TRƯỚC KHI LÀM BẤT CỨ ĐIỀU GÌ

> Session mới thường bị lầm vì không đọc kỹ. Làm đúng thứ tự này:

**Bước 1 — Xác định working directory:**
```powershell
# Thư mục ĐÚNG để làm việc:
C:\Users\Administrator\Documents\dashboard

# KHÔNG làm việc trong:
C:\Users\Administrator\Documents\dashboard\.claude\worktrees\*
# (đây là worktree tạm thời của AI agent, không phải repo chính)
```

**Bước 2 — Kiểm tra file trước khi sửa:**
```powershell
cd "C:\Users\Administrator\Documents\dashboard"
git status          # xem file nào đang bị sửa
grep -n "n8n.movi-finance" worker.js   # xác nhận Meraki dùng n8n webhook (KHÔNG gọi Meraki API trực tiếp)
```

**Bước 3 — Deploy đúng cách:**
```powershell
cd "C:\Users\Administrator\Documents\dashboard"
npx wrangler deploy
# Xong là live ngay, không cần git commit để deploy
```

**Bước 4 — Các file cốt lõi cần biết:**
- `worker.js` — backend (Cloudflare Worker), mọi API route đều ở đây
- `public/meraki.html` — trang Meraki monitor (4 collapsible panels)
- `public/fortigate-movi.html` — ★ MỚI — FortiGate Movi dashboard (system, VPN, policy, routing)
- `public/index.html` — trang chủ dashboard

**⛔ KHÔNG BAO GIỜ:**
- Gọi `https://api.meraki.com` trực tiếp từ Worker/browser (lộ API key, CORS)
- Sửa Meraki API key trong code (key được giữ bí mật trong n8n credential)
- Thêm panel Uplinks vào meraki.html (user đã quyết định bỏ Workflow Uplinks)
- Làm việc trong `.claude/worktrees/` rồi commit vào main

---

## 1. Tổng quan hệ thống

Dashboard quản lý Home Lab chạy hoàn toàn trên **Cloudflare Workers** (serverless), không cần server riêng. Truy cập từ bất kỳ đâu qua internet.

```
Browser → https://dashboard.home-server.id.vn
              ↓ (Cloudflare Worker: dashboard-homelab)
         KV Store (auth/session/bookmarks)
              ↓ fetch nội bộ qua Cloudflare Tunnel
         CasaOS (192.168.110.21) → các service LAN
              ↓ fetch riêng (Meraki)
         n8n (https://n8n.movi-finance.com) → Meraki API
```

**URL chính:** `https://dashboard.home-server.id.vn`  
**URL backup:** `https://dashboard-homelab.tranminhthoai788.workers.dev`  
**Deploy:** `cd C:\Users\Administrator\Documents\dashboard && npx wrangler deploy`

---

## 2. Cấu trúc file

```
dashboard/
├── worker.js            # Toàn bộ backend (Cloudflare Worker) — ~1700+ dòng
├── wrangler.toml        # Config deploy (KV binding, assets, custom domain)
├── public/
│   ├── index.html       # Trang chủ dashboard
│   ├── login.html       # Trang đăng nhập
│   ├── bookmarks.html   # Trang bookmark (start.me-like)
│   ├── users.html       # Quản lý user (admin only)
│   ├── meraki.html      # Meraki Network Monitor (4 panels)
│   ├── fortigate-movi.html  # ★ FortiGate Movi Dashboard (7 panels)
│   ├── esxi.html        # Chi tiết VMware ESXi
│   ├── asus.html        # Chi tiết ASUS Router
│   ├── casaos.html      # Chi tiết CasaOS
│   ├── n8n.html         # Chi tiết n8n
│   ├── 9router.html     # Chi tiết AI Router
│   ├── fortigate.html   # Chi tiết FortiGate (trang cũ)
│   ├── ssh.html         # Web SSH terminal
│   ├── hikvision.html   # Camera page (TRỐNG — chờ cài go2rtc)
│   └── favicon.svg
└── README.md            # File này
```

---

## 3. Cloudflare Resources

| Resource | Tên | ID / Ghi chú |
|----------|-----|--------------|
| Worker | `dashboard-homelab` | deploy bằng `npx wrangler deploy` |
| KV Namespace | `DASHBOARD_KV` | `ebad8682cfe24bbda0a4cf04b3e97210` |
| Custom Domain | `dashboard.home-server.id.vn` | đã set trong wrangler.toml |
| Account email | `tranminhthoai788@gmail.com` | |

### wrangler.toml hiện tại
```toml
name = "dashboard-homelab"
main = "worker.js"
compatibility_date = "2024-01-01"

[assets]
directory = "./public"
binding = "ASSETS"

[[kv_namespaces]]
binding = "DASHBOARD_KV"
id = "ebad8682cfe24bbda0a4cf04b3e97210"

[[routes]]
pattern = "dashboard.home-server.id.vn"
custom_domain = true
```

### Worker Secrets
```
ADMIN_PASSWORD          # password tài khoản admin dashboard
ESXI_USER / ESXI_PASSWORD
CASAOS_USER / CASAOS_PASSWORD
ASUS_USER / ASUS_PASS
FORTIGATE_URL           # https://fortigate-api.home-server.id.vn
FORTIGATE_API_KEY
N8N_API_KEY
CF_ACCESS_CLIENT_ID / CF_ACCESS_CLIENT_SECRET
```

---

## 4. Kiến trúc Backend (worker.js)

### Auth System
- **Login:** `POST /api/auth/login` → set 2 cookies:
  - `dh_session` (HttpOnly, 7 ngày) — xác thực session
  - `dh_user` (readable) — JSON `{username, role, permissions, isAdmin}` cho frontend
- **Session:** lưu KV key `session:{token}`, TTL 7 ngày
- **User data:** lưu KV key `user:{username}`
- **Idle timeout:** 30 phút không tương tác → tự logout, cảnh báo trước 5 phút
- **Admin auto-create:** nếu chưa có user `admin`, tự tạo với `ADMIN_PASSWORD`

### HTML Inject & Redirect
- Chưa login → redirect 302 về `/login.html`
- Đã login → inject `<script>window.__USER__={...}</script>` vào `<head>`
- Login page khi đã login → redirect về `/`

### Permission System
```javascript
// Mỗi user có object permissions:
{ esxi: 'write', asus: 'read', n8n: 'write', ... }

// PHẢI có đoạn này ở ĐẦU SCRIPT trong MỌI trang detail mới:
function _readUserCookie() {
  try { var m = document.cookie.match(/(?:^|;\s*)dh_user=([^;]+)/);
        return m ? JSON.parse(decodeURIComponent(m[1])) : null; }
  catch(e) { return null; }
}
var __USER__ = window.__USER__ || _readUserCookie() || { role:'user', permissions:{}, isAdmin:false };
var __PERM__  = __USER__.isAdmin ? 'write' : (__USER__.permissions['esxi'] || 'read');
```

### API Routes đầy đủ
```
POST /api/auth/login
POST /api/auth/logout
GET  /api/auth/me
GET  /api/bookmarks
PUT  /api/bookmarks
GET  /api/status              # ping check tất cả services (không ping noCheck)
GET  /api/esxi
GET  /api/n8n/overview
GET  /api/n8n/exec
GET  /api/9router
GET  /api/fortigate
GET  /api/asus
     /api/users/*             # CRUD users (admin only)
     /api/proxy               # Generic proxy
GET  /api/meraki-clients      # ★ Meraki: danh sách clients
GET  /api/meraki-devices      # ★ Meraki: inventory thiết bị
GET  /api/meraki-device-status # ★ Meraki: real-time status
GET  /api/meraki-events       # ★ Meraki: network events log
GET  /api/movi-system         # FortiGate Movi: system info + CPU/RAM/sessions
GET  /api/movi-license        # FortiGate Movi: license status (FortiCare, AV, IPS...)
GET  /api/movi-interfaces     # FortiGate Movi: interfaces + bandwidth realtime
GET  /api/movi-vpn            # FortiGate Movi: IPSec tunnels + Phase2 selectors
GET  /api/movi-ssl-vpn        # FortiGate Movi: SSL VPN active sessions
GET  /api/movi-policy         # FortiGate Movi: firewall policies (CMDB + hit stats)
GET  /api/movi-dhcp           # FortiGate Movi: routing table (route `/api/movi-dhcp`)
```

---

## 5. ★ Meraki Network Monitor — Kiến trúc đầy đủ

### Tại sao phải qua n8n? (QUAN TRỌNG — đừng bỏ qua)

Meraki API key phải được giữ bí mật. Không thể:
- Gọi từ browser → lộ key trong Network tab
- Gọi từ Worker → phải lưu key trong Worker secret, phức tạp, khó thay đổi

Giải pháp: **n8n làm proxy trung gian**. Key lưu trong n8n credential, Worker chỉ cần biết webhook URL + basic auth.

### Luồng dữ liệu
```
meraki.html
    ↓ fetch /api/meraki-*
Worker (Cloudflare)
    ↓ fetch webhook URL + Basic Auth (secrets: MOVI_N8N_USER / MOVI_N8N_PASS)
n8n (https://n8n.movi-finance.com)
    ↓ HTTP Request node + Meraki API Key credential
Meraki API v1 (https://api.meraki.com/api/v1)
    ↓ JSON response
n8n Code Node (transform/merge)
    ↓ Respond to Webhook node
Worker (transform format nếu cần)
    ↓ JSON
meraki.html (render UI)
```

### n8n Webhooks (production — dùng trong worker.js)

| Route Worker | n8n Webhook URL | Meraki API gọi |
|---|---|---|
| `/api/meraki-clients` | `https://n8n.movi-finance.com/webhook/8e83df3c-d3ad-48ae-ae1c-11fd5733d147` | `GET /networks/{netId}/clients` |
| `/api/meraki-devices` | `https://n8n.movi-finance.com/webhook/c65756f7-f228-4668-8d47-79efd543f234` | `GET /organizations/{orgId}/devices` |
| `/api/meraki-device-status` | `https://n8n.movi-finance.com/webhook/105904c4-2578-4bd7-98c9-bc226bf8f655` | `GET /organizations/{orgId}/devices/statuses` |
| `/api/meraki-events` | `https://n8n.movi-finance.com/webhook/3019c3e2-5725-40b5-95e4-f4a8d5a3d326` | `GET /networks/{netId}/events` (2 nguồn merged) |

**Auth n8n:** Basic Auth — credentials stored as Cloudflare secrets
`MOVI_N8N_USER` / `MOVI_N8N_PASS` (set via `wrangler secret put`). Never commit credentials.
**n8n URL:** `https://n8n.movi-finance.com`

### n8n Workflow Notes

**Workflow Clients (W1):**
- Webhook → HTTP Request GET clients → Code Node transform → Respond to Webhook
- Response format: `{ clients: [...], total, fetchedAt }`
- Mỗi client: `{ name, ip, mac, ssid, vlan, manufacturer, os, lastSeen }`

**Workflow Devices (W2):**
- n8n trả **raw array** (không phải object) → Worker tự wrap thành `{ devices, total, fetchedAt }`
- Mỗi device: `{ name, model, serial, lanIp, productType, typeIcon, tags, firmware, firmwareOk, status, url }`
- `firmwareOk = !firmware.includes('Not running')` → nếu false thì status = 'alerting'

**Workflow Device Status (W3):**
- n8n trả `[{ devices: [...] }]` (array bọc object) → Worker parse: `const first = Array.isArray(raw) ? raw[0] : raw; const list = first.devices || ...`
- Status values: `online`, `offline`, `alerting`, `dormant`
- Mỗi device: `{ name, serial, model, productType, status, publicIp, lastReportedAt }`

**Workflow Events (W4) — QUAN TRỌNG:**
- Mạng Combined → KHÔNG dùng `productType` filter (lỗi "not applicable")
- Dùng **2 HTTP Request nodes** song song: một lấy wireless events, một lấy appliance/switch events
- Merge bằng **Code Node** sau đó:
```javascript
const all = $input.all().map(i => i.json);
const events = all.flatMap(r => (r.events || []).map(e => ({
  occurredAt: e.occurredAt, type: e.type, description: e.description || e.type,
  deviceName: e.deviceName || '—', ssid: e.ssidName || '—', clientMac: e.clientMac || '—',
  severity: ['dhcp_no_leases','packet_flood','rogue_ap','vpn_connectivity_change'].includes(e.type) ? 'high'
            : ['disassociation','port_status'].includes(e.type) ? 'medium' : 'low',
})));
events.sort((a,b) => new Date(b.occurredAt) - new Date(a.occurredAt));
const high = events.filter(e => e.severity==='high').length;
const medium = events.filter(e => e.severity==='medium').length;
return [{ json: { events: events.slice(0,1000), total: events.length, high, medium, fetchedAt: new Date().toISOString() }}];
```
- **`perPage=1000`** phải set trong mỗi HTTP Request node (Meraki default chỉ 10)
- Response format: `{ events: [...], total, high, medium, fetchedAt }`

### meraki.html — Cấu trúc trang

4 panels (default **collapsed**, toggle bằng `togglePanel(id)`):
1. **👥 Clients** — search + filter SSID buttons + bảng 8 cột, auto-refresh 60s
2. **📡 Devices** — search + bảng 8 cột (inventory, firmware status)
3. **🔴 Device Status** — search + bảng 7 cột (real-time, public IP, dormant/alerting)
4. **📋 Network Events** — search + filter severity (High/Medium/All) + bảng 6 cột, auto-refresh 120s

Stats row (4 cards): Clients Online · Devices Online · Devices Offline · SSIDs Active

### Service Card Meraki trên index.html
```javascript
{ id:'meraki', name:'Meraki-Network', icon:'🌐',
  desc:'Network Client Monitor · Cisco Meraki',
  url:'https://dashboard.meraki.com',
  local:false, detailPage:'/meraki.html',
  noCheck:true }   // ← không ping, không hiện trong Trạng thái nhanh
```
- **`noCheck:true`** → bỏ qua trong `runChecks()` (không ping)
- Lọc `!s.noCheck` trong `updateStatusStrip()` → không hiện trong strip Trạng thái nhanh
- Card hiện badge = số clients từ `/api/meraki-clients` qua `updateMerakiCard()`
- Nằm trong category `movi` (Services Movi)

---

## 5b. ★ FortiGate Movi Dashboard — Kiến trúc đầy đủ

### Cùng pattern với Meraki — qua n8n làm proxy

```
fortigate-movi.html
    ↓ fetch /api/movi-*
Worker (Cloudflare)
    ↓ fetch webhook URL + Basic Auth (MOVI_N8N_USER / MOVI_N8N_PASS)
n8n (https://n8n.movi-finance.com)
    ↓ HTTP Request node + FortiGate access_token
FortiGate REST API (https://192.168.140.254)
    ↓ JSON
n8n Code Node (transform)
    ↓ Respond to Webhook
Worker → JSON → fortigate-movi.html
```

### n8n Webhooks FortiGate Movi

| Worker Route | n8n Webhook URL | FortiGate API |
|---|---|---|
| `/api/movi-system` | `webhook/52d4503a-66ec-49cc-b4c2-f4605349b17b` | `/monitor/system/status` + `/monitor/system/resource/usage?interval=1-min` |
| `/api/movi-license` | `webhook/8bd446f5-d1d4-4de6-a679-a26fcb0f5f60` | `/monitor/license/status` |
| `/api/movi-interfaces` | *(có sẵn từ trước)* | `/monitor/system/interface` |
| `/api/movi-vpn` | `webhook/2d3b9660-b99a-4bd3-92ba-165efb23c741` | `/monitor/vpn/ipsec` |
| `/api/movi-ssl-vpn` | `webhook/30b5ff6d-0065-4150-8c7f-0d25f2b6bc76` | `/monitor/vpn/ssl` |
| `/api/movi-policy` | `webhook/fed29e7e-aa06-483c-9709-1e7bcaf79c3b` | `/monitor/firewall/policy` + `/cmdb/firewall/policy` |
| `/api/movi-dhcp` | `webhook/ea8d7f9b-903b-4855-abdf-b73aa02ba1e8` | `/monitor/router/ipv4` |

**Auth:** `moviN8nAuth(env)` → Basic Auth từ secrets `MOVI_N8N_USER` / `MOVI_N8N_PASS`

### FortiGate API — Quirks quan trọng

```
❗ CPU/RAM không phải số thẳng — FortiGate 7.2 trả ARRAY:
   cpu: [{ current: 12, historical: {...} }]
   → Worker normalize: cpu = Array.isArray(data.cpu) ? data.cpu[0].current : data.cpu

❗ System status: version/serial/uptime ở TOP LEVEL response (KHÔNG phải trong results{})
   hostname, model → trong results{}
   version, serial, build, uptime → ở ngoài top level

❗ DHCP lease KHÔNG có trên FortiGate 7.2.10
   /api/v2/monitor/dhcp/lease → 404 dù thêm bất kỳ param nào
   → Thay bằng /api/v2/monitor/router/ipv4 (routing table), route /api/movi-dhcp

❗ SSL VPN field names:
   user_name (KHÔNG phải user), remote_host (KHÔNG phải source_ip)
   tunnel IP → subsessions[0].aip
   two_factor_auth (KHÔNG phải two_factor)

❗ Firewall Policy CMDB → srcintf/dstintf là ARRAY [{name:'x'}]
   → arr2names(arr) = arr.map(x => x.name).join(', ')

❗ CMDB không có hit_count — Monitor không có name
   → Policy workflow cần 2 nodes: FG CMDB + FG Monitor, merge trong Code
```

### n8n Policy Workflow — cấu trúc chuẩn

```
Webhook → FG Stats (HTTP GET /cmdb/firewall/policy) 
        → FG Monitor (HTTP GET /monitor/firewall/policy)
        → FG CMDB (HTTP GET /cmdb/firewall/policy?fields=policyid,name,status,...)
        → Code in JavaScript
        → Respond to Webhook
```

**Code node — merge pattern:**
```javascript
const cmdbRaw    = $input.all()[0].json;           // direct parent (FG CMDB)
const monitorRaw = $('FG Monitor').all()[0].json;  // named reference
const configs    = Array.isArray(cmdbRaw?.results) ? cmdbRaw.results : [];
const stats      = Array.isArray(monitorRaw?.results) ? monitorRaw.results : [];
const hitMap     = {};
stats.forEach(s => { hitMap[s.policyid] = s; });
// map configs với cfg['av-profile'], cfg['webfilter-profile'], cfg['ips-sensor'],
//   cfg['application-list'], cfg['ssl-ssh-profile'], cfg['dnsfilter-profile']
```

### CMDB fields cần fetch cho Policy

```
/api/v2/cmdb/firewall/policy?fields=policyid,name,status,srcintf,dstintf,
srcaddr,dstaddr,action,service,schedule,nat,logtraffic,comments,
av-profile,webfilter-profile,ips-sensor,application-list,ssl-ssh-profile,dnsfilter-profile
```

### fortigate-movi.html — UI Layout

```
[topbar] ← nav link đến fortigate-movi.html
[sys-bar] hostname | model | FortiOS version | uptime | CPU% | RAM% | Sessions
[lic-warn-banner] ← ẩn, chỉ hiện nếu license sắp hết
[lic-strip] FortiCare chip | AV chip | IPS chip | ... (màu theo trạng thái)
[stats-row] 5 cards: Interfaces Up | SD-WAN | Download | Upload | Top WAN
[body-grid 2 cột]
  Left: UP interface cards (bandwidth bars) | DOWN table (collapsible)
  Right: Bandwidth chart realtime (Chart.js)
[sec-panel] VPN IPSec — Site-to-Site (collapsible, full width)
  → bảng tunnels, click expand thấy Phase2 selectors
[sec-panel] VPN SSL — Active Sessions (collapsible)
  → bảng user/srcIP/tunnelIP/interface/traffic/2FA
[sec-panel] Firewall Policy — Top Hit (collapsible, có search)
  → bảng: ID | Tên | Interface/Address | Security Profiles chips | Hits bar | Traffic | Sessions | Action
  → click row → expand thấy profile names đầy đủ
[sec-panel] Routing Table (collapsible, có search)
  → bảng: Network | Gateway | Interface | Type | Distance | Metric
```

### Security Profile chips trong Policy table

```
AV  = đỏ  (av-profile)
WF  = xanh dương  (webfilter-profile)
IPS = vàng  (ips-sensor)
APP = tím  (application-list)
SSL = xanh lá  (ssl-ssh-profile)
DNS = teal  (dnsfilter-profile)
```
Hover chip → tooltip hiện tên profile. Click row → expand detail row.

### Collapsible panel pattern (dùng lại cho trang mới)

```javascript
function togglePanel(id){
  const body = document.getElementById('body-'+id);
  const hdr  = document.querySelector(`#sp-${id} .sec-panel-hdr`);
  const chev = document.getElementById('chev-'+id);
  const isOpen = !body.classList.contains('hidden');
  body.classList.toggle('hidden', isOpen);
  hdr.classList.toggle('open', !isOpen);
  chev.classList.toggle('closed', isOpen);
}
```

HTML structure:
```html
<div class="sec-panel" id="sp-xxx">
  <div class="sec-panel-hdr open" onclick="togglePanel('xxx')">
    <div class="sec-title" style="margin:0">...</div>
    <span class="panel-chev" id="chev-xxx">▼</span>
  </div>
  <div class="sec-panel-body" id="body-xxx">
    ... content ...
  </div>
</div>
```
CSS: `.sec-panel { grid-column: 1/-1 }` → full width trong body-grid

---

## 6. Frontend — index.html

### Service Cards
- Render bằng `function initUI()` trong `<script>`
- **Dùng thẻ `<a>` (KHÔNG phải `<div>`)** → hỗ trợ Ctrl+click, middle-click
- Service có `detailPage` → `href` = đường dẫn detail
- Service không có `detailPage` → `href` = URL gốc, `target="_blank"`
- Service `noCheck:true` → bỏ qua trong `runChecks()` VÀ `updateStatusStrip()`

### Đã xóa khỏi index.html
- ❌ **My Shortcuts section** — đã xóa hoàn toàn (CSS, HTML div, modal, tất cả JS functions)
- Sau khi xóa phải giữ lại hàm `_esc()` trong activity log IIFE (không được xóa theo)

### Layout fixes đã làm
- **Trạng thái hệ thống** box: xóa `height:100%`, thêm `align-items:start` vào grid container → không còn che text

---

## 7. Infrastructure — Cloudflare Tunnel

**Tunnel chạy trên:** CasaOS (192.168.110.21)  
**Process thật:** cloudflared chạy như **host process** (KHÔNG phải trong container)  
**Restart:** `docker restart 0696322545ea`  
**Kiểm tra:** `ps aux | grep cloudflared`

### Routes đang active
| Subdomain | Đích | Ghi chú |
|-----------|------|---------|
| `n8n-home.home-server.id.vn` | `http://192.168.110.21:56789` | n8n |
| `nashome.home-server.id.vn` | `https://192.168.110.126:5001` | NAS (noTLSVerify) |
| `esxi.home-server.id.vn` | `https://192.168.110.125` | ESXi (noTLSVerify) |
| `casaos.home-server.id.vn` | `http://192.168.110.21:4434` | CasaOS |
| `termix.home-server.id.vn` | `http://192.168.110.21:8080` | Web SSH |
| `openclaw.home-server.id.vn` | `http://192.168.110.5:18789` | OpenClaw |
| `9router.home-server.id.vn` | `http://192.168.110.5:20128` | AI Router |
| `fortigate-api.home-server.id.vn` | `https://192.168.110.1` | FortiGate |
| `asus-api.home-server.id.vn` | `https://192.168.10.1:8443` | ASUS Router |

> ✅ **`dashboard.home-server.id.vn`** — Worker custom domain, KHÔNG qua tunnel.

---

## 8. Services trong Dashboard

| ID | Tên | URL mở | Trang detail | Ghi chú |
|----|-----|--------|--------------|---------|
| `esxi` | VMware ESXi | `https://esxi.home-server.id.vn` | `/esxi.html` | SOAP API |
| `n8n` | n8n Automation | `https://n8n-home.home-server.id.vn` | `/n8n.html` | |
| `casaos` | CasaOS | `https://casaos.home-server.id.vn` | `/casaos.html` | |
| `9router` | 9Router | `https://9router.home-server.id.vn/dashboard` | `/9router.html` | |
| `uptime-kuma` | Uptime Kuma | `http://192.168.110.21:3005/dashboard` | — | LAN only |
| `ssh` | SSH Terminal | `https://termix.home-server.id.vn` | `/ssh.html` | |
| `fortigate` | FortiGate | `http://192.168.110.1` | `/fortigate.html` | LAN only |
| `asus` | ASUS Router | `https://192.168.10.1:8443` | `/asus.html` | LAN only |
| `meraki` | Meraki-Network | `https://dashboard.meraki.com` | `/meraki.html` | `noCheck:true` |

---

## 9. Mạng nội bộ

| Thiết bị | IP | Ghi chú |
|---------|-----|---------|
| FortiGate | `192.168.110.1` | Gateway chính |
| CasaOS | `192.168.110.21` | Docker host, cloudflared, NPM |
| ESXi | `192.168.110.125` | VMware |
| NAS | `192.168.110.126` | Synology |
| OpenClaw | `192.168.110.5` | AI Router host |
| ASUS Router | `192.168.10.1` | Subnet phụ `192.168.10.x` |
| Hikvision DVR | `192.168.130.3` | Camera, subnet `192.168.130.x`, port web 8088, RTSP 554 |
| n8n | `https://n8n.movi-finance.com` | External, dùng làm Meraki API proxy |

---

## 10. Trang Bookmarks (/bookmarks.html)

- Clock giờ VN real-time
- Search bar (Google/DuckDuckGo/Bing), Ctrl+K để focus
- Folder grid với icon picker (70+ IT icons)
- Auto favicon qua `https://www.google.com/s2/favicons?domain=X&sz=64`
- Sync qua KV `/api/bookmarks`, localStorage làm cache offline
- Format v2: `{ v:2, folders:[{ id, name, icon, color, items:[{id,name,url,icon}] }] }`

---

## 11. VIỆC ĐÃ XONG ✅

- [x] Auth system hoàn chỉnh (login, session, role, permissions, idle timeout)
- [x] Multi-user management (users.html)
- [x] Bookmark sync qua KV (bookmarks.html, start.me-like)
- [x] Service cards dùng `<a>` tag → Ctrl+click / middle-click
- [x] Custom domain `dashboard.home-server.id.vn`
- [x] Xóa My Shortcuts section hoàn toàn
- [x] Fix Trạng thái hệ thống box height
- [x] Fix activity log `_esc()` function
- [x] **Meraki integration hoàn chỉnh:**
  - [x] W1 — Clients webhook + `/api/meraki-clients`
  - [x] W2 — Devices webhook + `/api/meraki-devices`
  - [x] W3 — Device Status webhook + `/api/meraki-device-status`
  - [x] W4 — Events webhook (2 nguồn merged) + `/api/meraki-events`
  - [x] meraki.html với 4 collapsible panels
  - [x] Service card Meraki trong category Movi
  - [x] Ẩn Meraki khỏi Trạng thái nhanh (noCheck + filter strip)
- [x] **FortiGate Movi Dashboard (fortigate-movi.html) — 2026-05-18:**
  - [x] System info bar (hostname, model, version, uptime, CPU%, RAM%, sessions)
  - [x] License strip (FortiCare, AV, IPS, WebFilter, AppCtrl... màu theo trạng thái)
  - [x] Interfaces (UP cards + bandwidth bars, DOWN table collapsible)
  - [x] Bandwidth chart realtime (Chart.js, multi-interface tabs)
  - [x] VPN IPSec — tunnels + Phase2 expandable
  - [x] VPN SSL — active sessions với 2FA badge
  - [x] Firewall Policy — CMDB + Monitor stats merged, security profile chips, search, expand
  - [x] Routing Table — thay DHCP (FG 7.2.10 không có DHCP API), có search
  - [x] Tất cả sections là collapsible panels full width

---

## 12. VIỆC CÒN LẠI 🔧

### FortiGate Movi — Uptime hiển thị "0m" — CẦN KIỂM TRA
- `sys-uptime` hiển thị 0 → n8n Code node có thể đang đọc `s.uptime` từ `results{}` thay vì top level
- Sửa trong n8n System Info workflow: đọc `status.uptime` (top level) thay vì `status.results.uptime`

### FortiGate Movi — Thêm vào index.html — CHƯA LÀM
- Thêm service card `fortigate-movi` vào category Movi trong index.html
- Thêm nav link trong topbar của fortigate-movi.html trỏ về dashboard

### Meraki — Workflow AI Diagnosis (W6) — CHƯA LÀM
Ý tưởng: thêm AI vào trang meraki.html để phân tích dữ liệu (clients, devices, events) và đưa ra chuẩn đoán/khuyến nghị.

**Kế hoạch:**
- Tạo n8n workflow W6: nhận data từ các endpoint đã có, gọi AI API (OpenAI/Claude), trả về text phân tích
- Worker route: `GET /api/meraki-ai-diagnosis`
- UI: thêm button "🤖 Phân tích AI" trên meraki.html, hiển thị kết quả trong panel mới

### Camera — go2rtc (chưa làm)
```bash
# Cài go2rtc trên CasaOS
docker run -d --name go2rtc --network=host \
  -v /DATA/AppData/go2rtc:/config ghcr.io/alexxit/go2rtc

# /DATA/AppData/go2rtc/go2rtc.yaml
streams:
  camera01: rtsp://<DVR_USER>:<DVR_PASS>@<DVR_IP>:554/Streaming/Channels/101
  camera03: rtsp://<DVR_USER>:<DVR_PASS>@<DVR_IP>:554/Streaming/Channels/301
  # Chỉ kênh 1 và 3 có camera thật — thay <DVR_*> bằng giá trị thật, KHÔNG commit

# Tunnel route: go2rtc.home-server.id.vn → http://<go2rtc-host>:1984
```
- Hikvision dùng **Digest auth** (không phải Basic)
- Credentials: lưu trong Cloudflare secrets `HIKVISION_USER` / `HIKVISION_PASS` / `HIKVISION_URL` — KHÔNG ghi vào README/source

### Dọn dẹp nhỏ
- [ ] Xóa route `cam.home-server.id.vn` khỏi Cloudflare Zero Trust
- [ ] Xóa 3 secrets `HIKVISION_*`: `npx wrangler secret delete HIKVISION_URL` (và USER, PASS)

---

## 13. ⚠️ NHỮNG ĐIỀU DỄ NHẦM — ĐỌC TRƯỚC KHI LÀM

1. **Service card PHẢI là `<a>` tag, KHÔNG phải `<div>`** — đừng đổi lại.

2. **`_readUserCookie()` phải có ở MỌI trang detail mới** (xem mục 4).

3. **`noCheck:true` trên service** phải đồng thời:
   - Bỏ qua trong `runChecks()` (đã có `if (s.noCheck) return;`)
   - Bỏ qua trong `updateStatusStrip()` (filter `!s.noCheck`)

4. **Meraki Events dùng 2 HTTP Request nodes** (không có `productType` param) vì mạng là Combined type — `productType` sẽ báo lỗi "not applicable".

5. **n8n Response Mode** phải set "Using Respond to Webhook Node" (KHÔNG phải "Immediately") và node Respond to Webhook phải **nối vào** output của node cuối.

6. **n8n Devices trả raw array** — Worker tự wrap: `const list = Array.isArray(raw) ? raw : (raw.devices || [])`.

7. **n8n Device Status trả `[{devices:[...]}]`** — Worker parse: `const first = Array.isArray(raw) ? raw[0] : raw; const list = first.devices || ...`.

8. **n8n Events perPage** phải set = 1000 trong HTTP Request node (default Meraki chỉ trả 10).

9. **Cloudflared là HOST process** — restart: `docker restart 0696322545ea`.

10. **`dashboard.home-server.id.vn` là Worker custom domain** — KHÔNG phải Cloudflare Tunnel.

11. **KV data không xóa khi redeploy** — muốn reset phải xóa thủ công trên Cloudflare KV dashboard.

---

## 14. Cách Deploy

```powershell
cd C:\Users\Administrator\Documents\dashboard
npx wrangler deploy
```

```powershell
# Set secret
npx wrangler secret put TEN_SECRET

# Xóa secret
npx wrangler secret delete TEN_SECRET

# Xem secrets hiện có
npx wrangler secret list
```
