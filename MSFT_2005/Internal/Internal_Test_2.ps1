using namespace System
using namespace System.IO
using namespace System.Runtime.InteropServices

Clear-Host
Set-Location $PSScriptRoot
[Environment]::CurrentDirectory = $PSScriptRoot

# 1. Define native delegates and helpers cleanly in C#
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public static class PKeyNativeInterop {
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    public static extern IntPtr LoadLibrary(string dllToLoad);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate int ParseDelegate(IntPtr header, IntPtr blob, int blobSize, IntPtr workspace);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate int VerifyDelegate(IntPtr header, IntPtr key, IntPtr found, IntPtr m, IntPtr workspace);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate int FreeDelegate(IntPtr header, IntPtr workspace);
}
"@ -ErrorAction Stop

# 2. Load DLL and resolve function pointers relative to base address
$dllPath = Join-Path $PSScriptRoot 'pidgenx.dll'
$hModule = [PKeyNativeInterop]::LoadLibrary($dllPath)
if ($hModule -eq [IntPtr]::Zero) {
    throw "Failed to load library: $dllPath"
}

function Get-SubAddress([string]$hexOffset) {
    return [IntPtr]::Add($hModule, [Convert]::ToInt64($hexOffset, 16) - 0x180000000)
}

$parseFunc  = [Marshal]::GetDelegateForFunctionPointer((Get-SubAddress "0x1800876C8"), [PKeyNativeInterop+ParseDelegate])  #[cite: 1]
$verifyFunc = [Marshal]::GetDelegateForFunctionPointer((Get-SubAddress "0x180087ACC"), [PKeyNativeInterop+VerifyDelegate]) #[cite: 1]
$freeFunc   = [Marshal]::GetDelegateForFunctionPointer((Get-SubAddress "0x18008763C"), [PKeyNativeInterop+FreeDelegate])   #[cite: 1]

# 3. Allocate buffers
$Workspace  = [Marshal]::AllocHGlobal(32); [Marshal]::WriteInt64($Workspace, 0)
$Header     = [Marshal]::AllocHGlobal(32); [Marshal]::WriteInt64($Header, 0)

$KeyBytes   = [File]::ReadAllBytes('KeyData.bin')
$KeyDataPtr = [Marshal]::AllocHGlobal(16)
[Marshal]::Copy($KeyBytes, 0, $KeyDataPtr, 16)

$BinkBytes  = [File]::ReadAllBytes('Bink.bin')
$BinkObj    = [Marshal]::AllocHGlobal($BinkBytes.Length)
[Marshal]::Copy($BinkBytes, 0, $BinkObj, $BinkBytes.Length)

try {
    # 4. Parse Call[cite: 1]
    $parseResult = $parseFunc.Invoke($Header, $BinkObj, $BinkBytes.Length, $Workspace)
    if ($parseResult -ne 1) {
        Write-Host "Blob parsing failed." -ForegroundColor Red
        return
    }

    # Validate header prefix[cite: 1]
    if ([Marshal]::ReadInt64($Header, 0) -ne 0x2900000073) {
        Write-Host "Header prefix validation failed." -ForegroundColor Red
        return
    }

    $FoundPtr = [Marshal]::AllocHGlobal(8); [Marshal]::WriteInt32($FoundPtr, 0)
    $MBuf     = [Marshal]::AllocHGlobal(8); [Marshal]::WriteInt64($MBuf, 0)

    try {
        # 5. Verify Call[cite: 1]
        $verifyResult = $verifyFunc.Invoke($Header, $KeyDataPtr, $FoundPtr, $MBuf, $Workspace)
        $foundVal = [Marshal]::ReadInt32($FoundPtr, 0)

        if ($verifyResult -eq 1 -and $foundVal -eq 1) {
            $m = [Marshal]::ReadInt64($MBuf, 0)
            $upgrade  =  $m -band 1
            $serial   = ($m -shr 1)  -band 0x3FFFFFFF
            $security = ($m -shr 31) -band 0x3FF
            $channel  = [Math]::Floor($serial / 1000000)
            $sequence = $serial % 1000000
            $actData  = [Convert]::ToBase64String([BitConverter]::GetBytes($m) + [byte[]](0,0,0,0))

            Write-Host ''
            Write-Host '=== PKEY2005 result ===' -ForegroundColor Green
            Write-Host "Status       : Valid Key"
            Write-Host ('M            : 0x{0:X12}' -f $m)
            Write-Host "Upgrade Flag : $upgrade"
            Write-Host ("Serial       : $serial (0x{0:X})" -f $serial)
            Write-Host ("  Channel    : $("{0:D3}" -f [int]$channel)")
            Write-Host ("  Sequence   : $("{0:D6}" -f [int]$sequence)")
            Write-Host ("Security ID  : $security (0x{0:X})" -f $security)
            Write-Host "Act Data     : $actData"
        } else {
            Write-Host "Key not found or verification math failed (verifyResult: $verifyResult, found: $foundVal)." -ForegroundColor Yellow
        }
    }
    finally {
        [Marshal]::FreeHGlobal($FoundPtr)
        [Marshal]::FreeHGlobal($MBuf)
    }
}
finally {
    # 6. Free Call (Always executed if parse succeeded)[cite: 1]
    [void]$freeFunc.Invoke($Header, $Workspace)

    # Cleanup unmanaged memory
    [Marshal]::FreeHGlobal($Header)
    [Marshal]::FreeHGlobal($Workspace)
    [Marshal]::FreeHGlobal($KeyDataPtr)
    [Marshal]::FreeHGlobal($BinkObj)
    Write-Host
}