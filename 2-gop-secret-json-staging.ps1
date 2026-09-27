# ═══════════════════════════════════════════════════════════════
# Gộp 41 secret webhook cũ -> 7 secret JSON (staging).
# Điền URL THẬT của anh vào các chỗ "..." bên dưới rồi chạy cả file.
# Lấy URL từ n8n: mở từng workflow -> node Webhook -> copy "Production URL".
# Chạy từ thư mục: C:\Users\Administrator\Documents\dashboard
# ═══════════════════════════════════════════════════════════════

cd C:\Users\Administrator\Documents\dashboard

# ── 1. MOVI_WH_FG_JSON (14 webhook FortiGate Movi -> 1) ──
$moviFg = @{
  interfaces       = "..."   # cũ: MOVI_WH_FG_INTERFACES
  policy           = "..."   # cũ: MOVI_WH_FG_POLICY
  routing          = "..."   # cũ: MOVI_WH_FG_ROUTING
  sslVpn           = "..."   # cũ: MOVI_WH_FG_SSL_VPN
  vpn              = "..."   # cũ: MOVI_WH_FG_VPN
  license          = "..."   # cũ: MOVI_WH_FG_LICENSE
  system           = "..."   # cũ: MOVI_WH_FG_SYSTEM
  firewallUsers    = "..."   # cũ: MOVI_WH_FG_FIREWALL_USERS
  fortiviewSource  = "..."   # cũ: MOVI_WH_FG_FORTIVIEW_SOURCE
  firewallDeauth   = "..."   # cũ: MOVI_WH_FG_FIREWALL_DEAUTH
  sdwanRules       = "..."   # cũ: MOVI_WH_FG_SDWAN_RULES
  sdwanMembers     = "..."   # cũ: MOVI_WH_FG_SDWAN_MEMBERS
  policyLan        = "..."   # cũ: MOVI_WH_FG_POLICY_LAN
  policyWifi       = "..."   # cũ: MOVI_WH_FG_POLICY_WIFI
} | ConvertTo-Json -Compress
$moviFg | npx wrangler secret put MOVI_WH_FG_JSON --config wrangler.staging.toml

# ── 2. MOVI_WH_MERAKI_JSON (10 webhook Meraki -> 1) ──
$moviMeraki = @{
  devices      = "..."   # cũ: MOVI_WH_MERAKI_DEVICES
  clients      = "..."   # cũ: MOVI_WH_MERAKI_CLIENTS
  clientPolicy = "..."   # cũ: MOVI_WH_MERAKI_CLIENT_POLICY
  devStatus    = "..."   # cũ: MOVI_WH_MERAKI_DEV_STATUS
  swPorts      = "..."   # cũ: MOVI_WH_MERAKI_SW_PORTS
  portCfg      = "..."   # cũ: MOVI_WH_MERAKI_PORT_CFG
  linkAgg      = "..."   # cũ: MOVI_WH_MERAKI_LINK_AGG
  uplinks      = "..."   # cũ: MOVI_WH_MERAKI_UPLINKS
  l3           = "..."   # cũ: MOVI_WH_MERAKI_L3
  events       = "..."   # cũ: MOVI_WH_MERAKI_EVENTS
} | ConvertTo-Json -Compress
$moviMeraki | npx wrangler secret put MOVI_WH_MERAKI_JSON --config wrangler.staging.toml

# ── 3. MOVI_WH_USERMGMT_JSON (7 webhook quản lý user/asset -> 1) ──
$moviUser = @{
  createUser      = "..."   # cũ: MOVI_TOOL_CREATE_USER_WEBHOOK
  blockUser       = "..."   # cũ: MOVI_WH_BLOCK_USER
  assetSearch     = "..."   # cũ: MOVI_WH_ASSET_SEARCH
  azureCheckEmail = "..."   # cũ: MOVI_WH_AZURE_CHECK_EMAIL
  azureCheckGroup = "..."   # cũ: MOVI_WH_AZURE_CHECK_GROUP
  deleteUserList  = "..."   # cũ: MOVI_WH_DELETE_USER_LIST
  deleteUser      = "..."   # cũ: MOVI_WH_DELETE_USER
} | ConvertTo-Json -Compress
$moviUser | npx wrangler secret put MOVI_WH_USERMGMT_JSON --config wrangler.staging.toml

# ── 4. HOME_WH_FG_JSON (8 webhook FortiGate Home -> 1) ──
$homeFg = @{
  system     = "..."   # cũ: HOME_WH_FG_SYSTEM
  resources  = "..."   # cũ: HOME_WH_FG_RESOURCES
  interfaces = "..."   # cũ: HOME_WH_FG_INTERFACES
  vpn        = "..."   # cũ: HOME_WH_FG_VPN
  ssl        = "..."   # cũ: HOME_WH_FG_SSL
  policies   = "..."   # cũ: HOME_WH_FG_POLICIES
  ddns       = "..."   # cũ: HOME_WH_FG_DDNS
  reboot     = "..."   # cũ: HOME_WH_FG_REBOOT
} | ConvertTo-Json -Compress
$homeFg | npx wrangler secret put HOME_WH_FG_JSON --config wrangler.staging.toml

# ── 5. HOME_WH_ASUS_JSON (3 webhook ASUS router -> 1) ──
$homeAsus = @{
  main    = "..."   # cũ: HOME_WH_ASUS_MAIN
  clients = "..."   # cũ: HOME_WH_ASUS_CLIENTS
  reboot  = "..."   # cũ: HOME_WH_ASUS_REBOOT
} | ConvertTo-Json -Compress
$homeAsus | npx wrangler secret put HOME_WH_ASUS_JSON --config wrangler.staging.toml

# ── 6. MOVI_WH_VMWARE_JSON (4 webhook VMware Movi -> 1) ──
$moviVmware = @{
  vmware01Data  = "..."   # cũ: MOVI_WH_VMWARE01_DATA
  vmware01Power = "..."   # cũ: MOVI_WH_VMWARE01_POWER
  vmware02Data  = "..."   # cũ: MOVI_WH_VMWARE02_DATA
  vmware02Power = "..."   # cũ: MOVI_WH_VMWARE02_POWER
} | ConvertTo-Json -Compress
$moviVmware | npx wrangler secret put MOVI_WH_VMWARE_JSON --config wrangler.staging.toml

# ── 7. HOME_WH_VMWARE_JSON (2 webhook VMware Home -> 1) ──
$homeVmware = @{
  data  = "..."   # cũ: HOME_WH_VMWARE_DATA
  power = "..."   # cũ: HOME_WH_VMWARE_POWER
} | ConvertTo-Json -Compress
$homeVmware | npx wrangler secret put HOME_WH_VMWARE_JSON --config wrangler.staging.toml

Write-Host "`nXong 7 secret gop. Kiem tra lai bang: npx wrangler secret list --config wrangler.staging.toml"
