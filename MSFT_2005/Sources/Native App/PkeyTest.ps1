using namespace System
using namespace System.Runtime.InteropServices
using namespace System.Diagnostics

Clear-Host

# ------------------------------------------------------------
# Process priority
# ------------------------------------------------------------

Set-Location $PSScriptRoot
$CurrentProcess = [Process]::GetCurrentProcess()

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

$DllPath = Join-Path $PSScriptRoot "PkeyLib.dll"
$DllPathForCSharp = $DllPath.Replace('\', '\\').Replace('"', '\"')

Add-Type @"
using System;
using System.Runtime.InteropServices;

public static class PkeyNative
{
    [DllImport(
        "$DllPathForCSharp",
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

# ------------------------------------------------------------
# Configuration
# ------------------------------------------------------------

$CdKey = "RHTBY-VWY6D-QJRJ9-JGQ3X-Q2289"

$Config = Join-Path `
    $PSScriptRoot `
    "pkeyconfig.xrm-ms"

$DllFile = "PkeyLib.dll"
$DllPath = Join-Path $PSScriptRoot $DllFile

Write-Host "`n=== $DllFile ===" -ForegroundColor Cyan

if (-not (Test-Path -LiteralPath $Config -PathType Leaf)) {
    Write-Host "[-] Config not found: $Config" -ForegroundColor Red
    return
}

if (-not (Test-Path -LiteralPath $DllPath -PathType Leaf)) {
    Write-Host "[-] DLL not found: $DllPath" -ForegroundColor Red
    return
}

# ------------------------------------------------------------
# Make the DLL discoverable by the loader
# ------------------------------------------------------------

$group = 0
$uidBytes = [byte[]]::new(8)

$sw = [Stopwatch]::StartNew()
$success = [PkeyNative]::VerifyAndExtractKeyByRef(
    $CdKey,
    $Config,
    $uidBytes,
    [ref]$group
)
$sw.Stop()

if ($success) {

    <#
    https://github.com/UMSKT/writeups/blob/main/PKEY2005.md
    struct DECODED_PKEY {
        bool upgrade : 1; // presumed to indicate upgrade keys
        uint pid : 30; // middle 9 digits of Product ID
        uint auth : 10; // presumed to be authentication bits
    }
    #>

    $GetBits = {
        param (
            [Parameter(Mandatory = $true, Position = 0)]
            [byte[]]$Bytes,

            [Parameter(Mandatory = $true, Position = 1)]
            [ValidateRange(0, 63)]
            [int]$StartBit,

            [Parameter(Mandatory = $true, Position = 2)]
            [ValidateRange(1, 64)]
            [int]$BitCount
        )

        [UInt64]$Value = 0
        $byteCount = [Math]::Min($Bytes.Length, 8)

        for ($i = 0; $i -lt $byteCount; $i++) {
            $Value = $Value -bor ([UInt64]$Bytes[$i] -shl ($i * 8))
        }

        [UInt64]$Mask = if ($BitCount -eq 64) { 
            [UInt64]::MaxValue 
        } else { 
            ([UInt64]1 -shl $BitCount) - 1 
        }

        return (($Value -shr $StartBit) -band $Mask)
    }

    $Upgrade = & $GetBits $uidBytes 00 01
    $Serial  = & $GetBits $uidBytes 01 30
    $Auth    = & $GetBits $uidBytes 31 10

    Write-Host
    Write-Host "Time     : $($sw.Elapsed.TotalSeconds.ToString('F7'))s"
    Write-Host "Upgrade  : $Upgrade"
    Write-Host "Serial   : $Serial"
    Write-Host "Auth     : $Auth"
    Write-Host "Group    : $group"

}
else {
    Write-Host
    Write-Host "[ X ] Invalid" -ForegroundColor DarkGray
}
