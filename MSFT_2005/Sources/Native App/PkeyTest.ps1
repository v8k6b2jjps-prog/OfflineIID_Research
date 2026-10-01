using namespace System
using namespace System.Runtime.InteropServices
using namespace System.Diagnostics

Clear-Host
Set-Location $PSScriptRoot
[Environment]::CurrentDirectory = $PSScriptRoot

# ------------------------------------------------------------
# Process priority
# ------------------------------------------------------------

try {
    $CurrentProcess.PriorityClass = [ProcessPriorityClass]::High
    [Threading.Thread]::CurrentThread.Priority =
        [Threading.ThreadPriority]::Highest
}
catch {
    # Priority changes are optional; continue if unavailable.
}

# ------------------------------------------------------------
# Native P/Invoke
# ------------------------------------------------------------

Add-Type @"
using System;
using System.Runtime.InteropServices;

public static class PkeyNative
{
    [DllImport(
        "PkeyLib.dll",
        EntryPoint = "VerifyAndExtractKeyByRef",
        CallingConvention = CallingConvention.Cdecl,
        ExactSpelling = true,
        SetLastError = false)]
    [return: MarshalAs(UnmanagedType.I1)]
    public static extern bool VerifyAndExtractKeyByRef(
        [MarshalAs(UnmanagedType.LPStr)] string key,
        [MarshalAs(UnmanagedType.LPStr)] string config,
        [Out] byte[] uid,
        out int group);
}
"@
function Get-PkeyInfo {
    <#
    .SYNOPSIS
        Decodes the PKEY2005 UID returned by PkeyLib.dll, looks up the
        matching configuration in pkeyconfig.xrm-ms, builds the ActString
        and (if Python is available) re-encodes an offline IID using the
        HWID of the installed Windows product.

        UID layout (https://github.com/UMSKT/writeups/blob/main/PKEY2005.md):
            upgrade : 1   | serial : 30   | auth : 10
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][byte[]]$Uid,
        [Parameter(Mandatory)][int]$Group,
        [Parameter(Mandatory)][string]$ConfigPath,
        [string]$ScriptDir = $PSScriptRoot
    )

    # --- Decode UID bit fields ---------------------------------------------
    $raw     = [BitConverter]::ToUInt64($Uid, 0)
    $upgrade = $raw -band 1
    $serial  = ($raw -shr 1)  -band 0x3FFFFFFF
    $auth    = ($raw -shr 31) -band 0x3FF

    # --- Find Configuration + KeyRange for Group/Serial ---------------------
    [xml]$xrm = Get-Content -LiteralPath $ConfigPath -Raw
    $b64 = $xrm.SelectSingleNode("//*[local-name()='infoBin'][@name='pkeyConfigData']").InnerText
    [xml]$pkey = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($b64)).TrimStart([char]0xFEFF)

    $get = { param($Node, $Name) $Node.SelectSingleNode("*[local-name()='$Name']").InnerText }

    $cfg = $null; $range = $null; $actId = $null
    foreach ($c in $pkey.SelectNodes("//*[local-name()='Configuration'][*[local-name()='RefGroupId']='$Group']")) {
        $id = & $get $c 'ActConfigId'
        $range = $pkey.SelectNodes("//*[local-name()='KeyRange'][*[local-name()='RefActConfigId']='$id']") |
            Where-Object { $serial -ge [UInt64](& $get $_ 'Start') -and $serial -le [UInt64](& $get $_ 'End') } |
            Select-Object -First 1
        if ($range) { 
            $cfg = $c; 
            $actId = $id; 
            break 
        }
    }

    # --- ActString: msft2005:<guid>&<base64(upgrade | serial<<1 | auth<<31)> --
    $actString = $null
    if ($actId) {
        $keyData = [byte[]]::new(12)
        [BitConverter]::GetBytes([UInt64]($upgrade -bor ($serial -shl 1) -bor ($auth -shl 31))).CopyTo($keyData, 0)
        $actString = "msft2005:$($actId.Trim('{','}').ToLowerInvariant())&$([Convert]::ToBase64String($keyData))"
    }

    # --- HWID from installed Windows product + new offline IID --------------
    $hwid = '0'; $offlineAct = $null
    if (Get-Command python -ErrorAction SilentlyContinue) {
        $iid = (Get-CimInstance -Query ("SELECT OfflineInstallationId FROM SoftwareLicensingProduct " +
                "WHERE ApplicationID='55c92734-d682-4d71-983e-d6ec3f16059f' " +
                "AND PartialProductKey IS NOT NULL AND OfflineInstallationId IS NOT NULL") |
                Select-Object -First 1).OfflineInstallationId

        if ($iid) {
            # 2009 format = 63 digits (signed decimal HWID), 2005 format = 54 digits (hex HWID)
            $py, $rx = if ($iid.Length -gt 54) { 'iid2009.py', 'HWID\s*:\s*(-?\d+)' }
                       else                    { 'iid2005.py', 'HWID\s*:\s*\[(0x[0-9a-f]+)\]' }
            $m = python (Join-Path $ScriptDir $py) decode $iid | Select-String $rx
            if ($m) { $hwid = $m.Matches[0].Groups[1].Value }
        }

        $offlineAct = python (Join-Path $ScriptDir 'iid2005.py') encode $hwid $auth $Group $serial
    }

    [pscustomobject]@{
        Upgrade     = $upgrade
        Serial      = $serial
        Auth        = $auth
        Group       = $Group
        ActConfigId = $actId
        Edition     = if ($cfg)   { & $get $cfg 'EditionId' } else { $null }
        Description = if ($cfg)   { & $get $cfg 'ProductDescription' } else { $null }
        PartNumber  = if ($range) { & $get $range 'PartNumber' } else { $null }
        EulaType    = if ($range) { & $get $range 'EulaType' } else { $null }
        RangeValid  = if ($range) { (& $get $range 'IsValid') -eq 'true' } else { $null }
        ActString   = $actString
        HWID        = $hwid
        OfflineAct  = $offlineAct
    }
}

# ------------------------------------------------------------
# Configuration
# ------------------------------------------------------------

$CdKey = "RHTBY-VWY6D-QJRJ9-JGQ3X-Q2289"

$Config = Join-Path `
    $PSScriptRoot `
    "pkeyconfig.xrm-ms"

$group = 0
$uidBytes = [byte[]]::new(8)
$success = [PkeyNative]::VerifyAndExtractKeyByRef(
    $CdKey,
    $Config,
    $uidBytes,
    [ref]$group
)
if ($success) {
    Write-Host
    Get-PkeyInfo -Uid $uidBytes -Group $group -ConfigPath $Config | Format-List
} else {
    Write-Host "`n[ X ] Invalid" -ForegroundColor DarkGray
}