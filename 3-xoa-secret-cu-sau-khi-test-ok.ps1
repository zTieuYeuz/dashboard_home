# ═══════════════════════════════════════════════════════════════
# BƯỚC 3/3 — CHỈ chạy sau khi đã làm Bước 2 (gộp JSON) VÀ deploy staging
# VÀ xác nhận các trang FortiGate Movi/Home, Meraki, ASUS, VMware, quản lý user
# vẫn chạy đúng. Xoá 41 secret lẻ CŨ (đã có bản JSON gộp thay thế ở Bước 2).
# Nếu bỏ qua bước này cũng KHÔNG sao — code đã tự ưu tiên đọc JSON mới, secret
# cũ chỉ còn là dự phòng không dùng tới, nhưng vẫn TÍNH vào hạn mức 64 nên nên xoá.
# ═══════════════════════════════════════════════════════════════

cd C:\Users\Administrator\Documents\dashboard

$oldSecrets = @(
  # MOVI_WH_FG_JSON thay cho 14 cái:
  "MOVI_WH_FG_INTERFACES","MOVI_WH_FG_POLICY","MOVI_WH_FG_ROUTING","MOVI_WH_FG_SSL_VPN",
  "MOVI_WH_FG_VPN","MOVI_WH_FG_LICENSE","MOVI_WH_FG_SYSTEM","MOVI_WH_FG_FIREWALL_USERS",
  "MOVI_WH_FG_FORTIVIEW_SOURCE","MOVI_WH_FG_FIREWALL_DEAUTH","MOVI_WH_FG_SDWAN_RULES",
  "MOVI_WH_FG_SDWAN_MEMBERS","MOVI_WH_FG_POLICY_LAN","MOVI_WH_FG_POLICY_WIFI",
  # MOVI_WH_MERAKI_JSON thay cho 10 cái:
  "MOVI_WH_MERAKI_DEVICES","MOVI_WH_MERAKI_CLIENTS","MOVI_WH_MERAKI_CLIENT_POLICY",
  "MOVI_WH_MERAKI_DEV_STATUS","MOVI_WH_MERAKI_SW_PORTS","MOVI_WH_MERAKI_PORT_CFG",
  "MOVI_WH_MERAKI_LINK_AGG","MOVI_WH_MERAKI_UPLINKS","MOVI_WH_MERAKI_L3","MOVI_WH_MERAKI_EVENTS",
  # MOVI_WH_USERMGMT_JSON thay cho 7 cái:
  "MOVI_TOOL_CREATE_USER_WEBHOOK","MOVI_WH_BLOCK_USER","MOVI_WH_ASSET_SEARCH",
  "MOVI_WH_AZURE_CHECK_EMAIL","MOVI_WH_AZURE_CHECK_GROUP","MOVI_WH_DELETE_USER_LIST","MOVI_WH_DELETE_USER",
  # HOME_WH_FG_JSON thay cho 8 cái:
  "HOME_WH_FG_SYSTEM","HOME_WH_FG_RESOURCES","HOME_WH_FG_INTERFACES","HOME_WH_FG_VPN",
  "HOME_WH_FG_SSL","HOME_WH_FG_POLICIES","HOME_WH_FG_DDNS","HOME_WH_FG_REBOOT",
  # HOME_WH_ASUS_JSON thay cho 3 cái:
  "HOME_WH_ASUS_MAIN","HOME_WH_ASUS_CLIENTS","HOME_WH_ASUS_REBOOT",
  # MOVI_WH_VMWARE_JSON thay cho 4 cái:
  "MOVI_WH_VMWARE01_DATA","MOVI_WH_VMWARE01_POWER","MOVI_WH_VMWARE02_DATA","MOVI_WH_VMWARE02_POWER",
  # HOME_WH_VMWARE_JSON thay cho 2 cái:
  "HOME_WH_VMWARE_DATA","HOME_WH_VMWARE_POWER"
)

foreach ($s in $oldSecrets) {
  Write-Host "`n=== Xoa $s ===" -ForegroundColor Yellow
  "y" | npx wrangler secret delete $s --config wrangler.staging.toml
}

Write-Host "`nXong. Kiem lai tong so: npx wrangler secret list --config wrangler.staging.toml"
