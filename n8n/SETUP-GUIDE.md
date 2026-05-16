# n8n Workflow: Meraki Client Policy (Block/Unblock)

## Mục đích
Cho phép dashboard admin block/unblock thiết bị client trên mạng Meraki
thông qua Meraki API `PUT /networks/{networkId}/clients/{clientId}/policy`.

## Cài đặt trên n8n.movi-finance.com

### Bước 1 — Import workflow
1. Mở n8n.movi-finance.com > Workflows > Import from File
2. Chọn file `meraki-client-policy.workflow.json`
3. Workflow sẽ xuất hiện với tên "Meraki Client Policy (Block/Unblock)"

### Bước 2 — Tạo/chọn Credentials

**a) HTTP Basic Auth (cho webhook):**
- Tạo credential "HTTP Basic Auth" mới (hoặc dùng sẵn có nếu đã có)
- Username: `admin` (hoặc giá trị MOVI_N8N_USER đã đặt trên Cloudflare)
- Password: (giá trị MOVI_N8N_PASS trên Cloudflare — đã thay đổi chưa?)
- Gán vào node **Webhook** > Authentication > Credential

**b) HTTP Header Auth (Meraki API Key):**
- Tạo credential "HTTP Header Auth":
  - Header Name: `X-Cisco-Meraki-API-Key`
  - Header Value: `<Meraki Dashboard API Key của anh>`
- Gán vào node **Meraki API - Set Policy** > Credential
- (Nếu đã có credential Meraki từ các workflow read khác, dùng lại nó)

### Bước 3 — Điền Network ID
1. Mở node **"Config & Extract"**
2. Field `networkId` → thay `REPLACE_WITH_YOUR_MERAKI_NETWORK_ID` bằng Meraki Network ID thật
   - Tìm tại: Meraki Dashboard > Organization > Configure > Networks → copy ID từ URL
   - Hoặc Meraki API: `GET /organizations/{orgId}/networks` → lấy `id` field
   - Ví dụ: `L_123456789012345678`

### Bước 4 — Kết nối Error output (tuỳ chọn)
- Node "Meraki API - Set Policy" > Settings > On Error: chọn "Continue on Error Output"
- Kéo error output sang node "Respond Error"
- (Nếu n8n version chưa hỗ trợ, bỏ qua — workflow sẽ trả 502 tự động khi API lỗi)

### Bước 5 — Activate
1. Test thủ công: POST `https://n8n.movi-finance.com/webhook-test/meraki-client-policy`
   ```
   curl -X POST https://n8n.movi-finance.com/webhook-test/meraki-client-policy \
     -u admin:YOUR_PASS \
     -H 'Content-Type: application/json' \
     -d '{"mac":"aa:bb:cc:dd:ee:ff","policy":"Blocked"}'
   ```
2. Kiểm tra response trả `{"success":true,...}`
3. **Activate** workflow (toggle ON)

### Bước 6 — Verify production webhook URL
- URL production (sau khi active): `https://n8n.movi-finance.com/webhook/meraki-client-policy`
- Dashboard worker.js gọi đúng URL này (đã code sẵn)

---

## Payload format (worker.js -> n8n)
```json
{
  "mac": "aa:bb:cc:dd:ee:ff",
  "policy": "Blocked"    // hoặc "Normal"
}
```

## Response format (n8n -> worker.js)
```json
{
  "success": true,
  "mac": "aa:bb:cc:dd:ee:ff",
  "policy": "Blocked",
  "merakiResponse": { ... }   // Meraki API response
}
```

## Lưu ý quan trọng
- **clientId = MAC address**: Meraki chấp nhận MAC (lowercase, có dấu `:`) làm clientId
- **devicePolicy values**: `"Blocked"` (chặn hoàn toàn) hoặc `"Normal"` (cho phép)
- **Rate limit**: Meraki API giới hạn 10 calls/second — không ảnh hưởng vì admin thao tác thủ công
- **Rollback**: Bấm "Mở chặn" trên dashboard = set `Normal`, hiệu lực ngay lập tức
- **Audit log**: Worker ghi log hành động vào KV `activity_log` (admin, mac, policy, timestamp)
