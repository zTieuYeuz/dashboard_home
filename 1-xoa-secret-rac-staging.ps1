# ═══════════════════════════════════════════════════════════════
# BƯỚC 1/2 — Xoá 15 secret RÁC (đã xác nhận 0 nơi nào trong code dùng tới).
# An toàn tuyệt đối, không cần điền gì. Chạy từ: C:\Users\Administrator\Documents\dashboard
# Mỗi lệnh sẽ hỏi "Are you sure...? (y/N)" — gõ y rồi Enter (hoặc để mặc định pipe "y" bên dưới đã tự trả lời).
# ═══════════════════════════════════════════════════════════════

cd C:\Users\Administrator\Documents\dashboard

$racSecrets = @(
  "ASUS_PASS", "ASUS_USER",
  "CONSOLEPI_CF_CLIENT_ID", "CONSOLEPI_CF_CLIENT_SECRET",
  "ESXI_PASSWORD", "ESXI_USER",
  "HIKVISION_PASS", "HIKVISION_URL", "HIKVISION_USER",
  "HOME_GO2RTC_PASS", "HOME_GO2RTC_USER",
  "HOME_WH_FG",
  "KASM_PW",
  "NINEROUTER_KEY", "NINEROUTER_PASSWORD"
)

foreach ($s in $racSecrets) {
  Write-Host "`n=== Xoa $s ===" -ForegroundColor Yellow
  "y" | npx wrangler secret delete $s --config wrangler.staging.toml
}

Write-Host "`nXong. Kiem lai: npx wrangler secret list --config wrangler.staging.toml"
