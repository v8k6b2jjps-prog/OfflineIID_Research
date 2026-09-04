
# SecurityID cannot be fully recovered (Lossy / Truncated).
# Parts are checked as boolean flags (e.g., BYTE11 checks if != 0), 
# and the rest is bit-masked and chopped down into a smaller internal 32-bit field.
# BYTE11(v53) = (*(_DWORD *)(a1 + 28) != 0 ? 8 : 0) | ...

Clear-Host
Write-Host

$BaseFolder = "D:\Software\MS Tools Pack\Product Key Tools\MSFT_2009\Testing"
$pidIns = Join-Path $BaseFolder "pidgenxIn.dll"
$MsftHelperDll = Join-Path $BaseFolder "MsftHelperDll.dll"
[Assembly]::LoadFile((Join-Path $BaseFolder "Msft2009.dll"))

Write-Host

$InstallationIdList = gcim -Query "SELECT ID, OfflineInstallationId FROM SoftwareLicensingProduct WHERE PartialProductKey IS NOT NULL AND OfflineInstallationId IS NOT NULL"
if ($InstallationIdList) {
    $generatedIid = $InstallationIdList[0].OfflineInstallationId
    $decodedParams = [Activator]::CreateInstance([Type]'DecodedParameters')
    $readResult = [Msft2009.MSFT]::ReadParametersFromString($generatedIid, [ref]$decodedParams);
    if ($readResult -eq 0) {
        Write-Host "Extract HWID Value :  $($decodedParams.hwid)"
    }
}

$StoreObj = Get-SppStoreLicense -SkuType Windows -IgnoreEsu -Dump | 
    Where-Object Value -match 'current' | 
    Select-Object -First 1
if ($StoreObj -and $StoreObj["raw"]) {
    $StoreHwid = Convert-HWIDToShort -HWIDBytes ($StoreObj["raw"]) -Modern
    Write-Host "Store HWID Value   :  $StoreHwid"
}

$WinrtDll = Join-Path $env:windir "System32\LicensingWinRT.dll"
$Offset = Get-HwidRVA -dllpath $WinrtDll
$params = 0L, 0x0, [ref]0L, [ref]0L, [ref]0L, [ref]0L
$hr = Invoke-UnmanagedMethod `
    -Dll $WinrtDll `
    -Function "Inner" `
    -Values $params `
    -Sub $Offset

if ($hr -ge 0 -and $params[2].Value -ne 0L) {
    $byteArray = New-Object Byte[] 0x118
    [Marshal]::Copy(([IntPtr]::Add($params[2].Value, 0)), $byteArray, 0, 0x118)
    $ShortHWID = Convert-HWIDToShort -HWIDBytes $byteArray
    Write-Host "WinRT HWID Value   :  $ShortHWID"
}

Write-Host

# Allocate space for 64+ characters (plus null terminator)
$bufferSize = 128
$OutStr = New-IntPtr -Size ($bufferSize * 2)
$values = 5150, 80009470, 34969266479148, -7066209111506718658, $OutStr, $bufferSize

Write-Host
Write-Host "--- Encode Values ---" -ForegroundColor Yellow
Write-Host "Group ID:    $($values[0])"
Write-Host "Serial:      $($values[1])"
Write-Host "Security ID: $($values[2])"
Write-Host "HWID:        $($values[3])"
$result = Invoke-UnmanagedMethod -Dll $MsftHelperDll -Function GetInstallationIdString -Values $values

if ($result -eq 0) {
    $generatedIid = [Marshal]::PtrToStringAuto($OutStr)
    Write-Host
    Write-Host "Msft Dll Call results    : $generatedIid" -ForegroundColor Green
} else {
    Write-Error "GetInstallationIdString failed with error code: $result"
}

$generatedIid = ''
$result = [Msft2009.MSFT]::GetInstallationIdString($values[0], $values[1], $values[2], $values[3], [ref]$generatedIid)

if ($result -eq 0) {
    Write-Host
    Write-Host "Msft C# Dll Call results : $generatedIid" -ForegroundColor Green
} else {
    Write-Error "GetInstallationIdString failed with error code: $result"
}

$iidCall = Invoke-IIDRequest `
    -GroupID $values[0] `
    -Serial $values[1] `
    -SecurityID $values[2] `
    -HWID $values[3] `
    -DllPath $pidIns `
    -Mode Insider

Write-Host
Write-Host "Pidgen Dll Call results  : $($iidCall.IID)" -ForegroundColor Green
Free-IntPtr $OutStr

$pDecodedParams = New-IntPtr -Size 24
$Values = $generatedIid, $pDecodedParams
$readResult = Invoke-UnmanagedMethod -Dll $MsftHelperDll -Function ReadParametersFromString -Values $Values

if ($readResult -eq 0) {

    $secId   = [Marshal]::ReadInt32($pDecodedParams, 0)
    $groupId = [Marshal]::ReadInt16($pDecodedParams, 4)
    $serial  = [Marshal]::ReadInt32($pDecodedParams, 8)
    $hwid    = [Marshal]::ReadInt64($pDecodedParams, 16)

    Write-Host
    Write-Host "--- Native DLL Decoded Successfully ---" -ForegroundColor Yellow
    Write-Host "Group ID:    $groupId"
    Write-Host "Serial:      $serial"
    Write-Host "Security ID: $secId"
    Write-Host "HWID:        $hwid"
} else {
    Write-Error "ReadParametersFromString failed with error code: $readResult"
}

# Clean up struct memory
[Marshal]::FreeHGlobal($pDecodedParams)

$decodedParams = [Activator]::CreateInstance([Type]'DecodedParameters')
$readResult = [Msft2009.MSFT]::ReadParametersFromString($generatedIid, [ref]$decodedParams);

if ($readResult -eq 0) {

    Write-Host
    Write-Host "--- .Net C# Decoded Successfully ---" -ForegroundColor Yellow
    Write-Host "Group ID:    $($decodedParams.groupID)"
    Write-Host "Serial:      $($decodedParams.serial)"
    Write-Host "Security ID: $($decodedParams.securityID)"
    Write-Host "HWID:        $($decodedParams.hwid)"
} else {
    Write-Error "ReadParametersFromString failed with error code: $readResult"
}

Write-Host
Write-Host "Read / Validate Test .. . . " -ForegroundColor Magenta

$StoreInfo = Get-SppStoreLicense -SkuType Windows -IgnoreEsu | select -First 1 | select SkuId, ProductKey
$OfflineId = gcim -Query "SELECT ID, OfflineInstallationId FROM SoftwareLicensingProduct WHERE PartialProductKey IS NOT NULL AND OfflineInstallationId IS NOT NULL" | ? ID -Match $StoreInfo.SkuId | select -ExpandProperty OfflineInstallationId

$HWID = 0L
$decodedParams = [Activator]::CreateInstance([Type]'DecodedParameters')
$readResult    = [Msft2009.MSFT]::ReadParametersFromString($OfflineId, [ref]$decodedParams);
if ($readResult -eq 0) {
    $HWID = $decodedParams.hwid
}

$keyPtr    = [marshal]::StringToHGlobalUni($StoreInfo.ProductKey)
$configPtr = [marshal]::StringToHGlobalUni("C:\windows\System32\spp\tokens\pkeyconfig\pkeyconfig.xrm-ms")
$values = $keyPtr, $configPtr, 0L, 0L, $HWID, [ref]0L, [ref]0L, [ref]0L, [ref]0L, 0L
Invoke-UnmanagedMethod -Dll PidgenX -Function GetPKeyData -Values $values | Out-Null
if ($values[5].Value -ge 0L) {
  $IID = [marshal]::PtrToStringAuto($values[5].Value)
  Write-Host ("is IID matching ? {0}" -f ($IID -match $OfflineId))
}
Free-IntPtr $keyPtr    -Method Auto
Free-IntPtr $configPtr -Method Auto

return;