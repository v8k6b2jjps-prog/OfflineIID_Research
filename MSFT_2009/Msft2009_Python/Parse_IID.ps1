Clear-Host
Write-Host

$iid2009   = Join-Path $PSScriptRoot "iid2009.py"
$pythonCmd = Get-Command python -ErrorAction SilentlyContinue

if (-not $pythonCmd) {
    Write-Error "Python is not installed or not found in the system PATH."
    return
}

$ActObj = Get-CimInstance -Query "SELECT PartialProductKey, OfflineInstallationId FROM SoftwareLicensingProduct WHERE PartialProductKey IS NOT NULL AND OfflineInstallationId IS NOT NULL"

foreach ($obj in $ActObj) {
    Write-Host
    Write-Host "Recovering IID for Product Key: $($obj.PartialProductKey) | Installation ID: $($obj.OfflineInstallationId)" -ForegroundColor Cyan
    Write-Host ""
    
    & python $iid2009 recover $obj.OfflineInstallationId $obj.PartialProductKey
    
    Write-Host ("-" * 60)
}