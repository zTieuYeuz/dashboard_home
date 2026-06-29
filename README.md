# Home Lab Dashboard

Dashboard quản lý hạ tầng Home Lab & Văn phòng Movi, chạy trên **Cloudflare Workers**.

## Tính năng

- 🏠 **Service Home** — VMware ESXi, n8n, CasaOS, FortiGate, ASUS Router, SSH, RustDesk, Services Hub
- 🎬 **Service Movi** — Cisco Meraki Network Monitor, FortiGate Movi, Camera Movi, Topology
- 🔐 **Auth System** — Multi-user, role-based permissions, policy groups
- 📑 **Bookmarks** — Trang bookmark cá nhân, sync qua Cloudflare KV
- 📷 **Camera** — go2rtc WebRTC streaming

## Tech Stack

- **Backend:** Cloudflare Workers (serverless)
- **Storage:** Cloudflare KV (session, user data, bookmarks)
- **Proxy:** n8n (Meraki API, FortiGate API)
- **Frontend:** Vanilla HTML/CSS/JS

## Deploy

```powershell
cd C:\Users\Administrator\Documents\dashboard
npx wrangler deploy
```

## Tài liệu kỹ thuật

