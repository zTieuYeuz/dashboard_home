# =============================================================
# Import tất cả secrets từ file secrets.secret lên Cloudflare
# Chạy: .\import-secrets.ps1
# Chạy staging: .\import-secrets.ps1 -Staging
# =============================================================

param(
    [switch]$Staging
)

$file = "secrets.secret"

if (-not (Test-Path $file)) {
    Write-Host "Khong tim thay file $file" -ForegroundColor Red
    exit 1
}

$config = if ($Staging) { "--config wrangler.staging.toml" } else { "" }
$target = if ($Staging) { "STAGING" } else { "PRODUCTION" }

Write-Host ""
Write-Host "=== Import secrets len $target ===" -ForegroundColor Cyan
Write-Host ""

$total = 0
$skipped = 0
$imported = 0

Get-Content $file | ForEach-Object {
    $line = $_.Trim()

    # Bỏ qua dòng trống và comment
    if ($line -eq "" -or $line.StartsWith("#")) { return }

    # Parse KEY=VALUE
    $idx = $line.IndexOf("=")
    if ($idx -lt 0) { return }

    $key   = $line.Substring(0, $idx).Trim()
    $value = $line.Substring($idx + 1).Trim()

    $total++

    if ($value -eq "") {
        Write-Host "  SKIP  $key (chua co value)" -ForegroundColor Yellow
        $skipped++
        return
    }

    Write-Host "  PUT   $key ..." -ForegroundColor Green
    $value | npx wrangler secret put $key $config 2>&1 | Out-Null
    $imported++
}

Write-Host ""
Write-Host "=== Xong: $imported imported, $skipped skipped (tong $total) ===" -ForegroundColor Cyan
Write-Host ""
