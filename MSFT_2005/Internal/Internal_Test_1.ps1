using namespace System
using namespace System.IO
using namespace System.Runtime.InteropServices

Clear-Host
Set-Location $PSScriptRoot
[Environment]::CurrentDirectory = $PSScriptRoot

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public static class PKeyInnerInterop {
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    public static extern IntPtr LoadLibrary(string dllToLoad);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate int InnerDelegate(IntPtr keyObj, IntPtr blob, int blobSize, IntPtr reserved);
}
"@ -ErrorAction Stop

$dllPath = Join-Path $PSScriptRoot 'pidgenx.dll'
$hModule = [PKeyInnerInterop]::LoadLibrary($dllPath)
if ($hModule -eq [IntPtr]::Zero) {
    throw "Failed to load library: $dllPath"
}

function Get-SubAddress([string]$hexOffset) {
    return [IntPtr]::Add($hModule, [Convert]::ToInt64($hexOffset, 16) - 0x180000000)
}

$innerFunc = [Marshal]::GetDelegateForFunctionPointer((Get-SubAddress "0x18008D85C"), [PKeyInnerInterop+InnerDelegate])

# Key object
$KeyObjBytes       = [byte[]]::new(96)
$KeyObjBytes[0x30] = 1
$KeyBytes          = [File]::ReadAllBytes((Join-Path $PSScriptRoot 'KeyData.bin'))
[Array]::Copy($KeyBytes, 0, $KeyObjBytes, 0x38, 16)

$KeyObj = [Marshal]::AllocHGlobal($KeyObjBytes.Length)
[Marshal]::Copy($KeyObjBytes, 0, $KeyObj, $KeyObjBytes.Length)

# Bink blob
$BinkBytes = [File]::ReadAllBytes((Join-Path $PSScriptRoot 'Bink.bin'))
$BinkObj   = [Marshal]::AllocHGlobal($BinkBytes.Length)
[Marshal]::Copy($BinkBytes, 0, $BinkObj, $BinkBytes.Length)

try {
    $hr = $innerFunc.Invoke($KeyObj, $BinkObj, $BinkBytes.Length, [IntPtr]::Zero)

    if ($hr -eq 0) {
        $m = [Marshal]::ReadInt64($KeyObj, 0x48)
        $upgrade  =  $m -band 1
        $serial   = ($m -shr 1)  -band 0x3FFFFFFF
        $security = ($m -shr 31) -band 0x3FF
        $channel  = [Math]::Floor($serial / 1000000)
        $sequence = $serial % 1000000
        $actData  = [Convert]::ToBase64String([BitConverter]::GetBytes($m) + [byte[]](0,0,0,0))

        Write-Host ''
        Write-Host '=== PKEY2005 result ===' -ForegroundColor Green
        Write-Host ('Status       : Valid Key')
        Write-Host ('M            : 0x{0:X12}' -f $m)
        Write-Host ('Upgrade Flag : {0}' -f $upgrade)
        Write-Host ('Serial       : {0} (0x{0:X})' -f $serial)
        Write-Host ('  Channel    : {0:D3}' -f [int]$channel)
        Write-Host ('  Sequence   : {0:D6}' -f [int]$sequence)
        Write-Host ('Security ID  : {0} (0x{0:X})' -f $security)
        Write-Host ('Act Data     : {0}' -f $actData)
    } else {
        Write-Host ('Inner call failed (hr: 0x{0:X8}).' -f $hr) -ForegroundColor Yellow
    }
}
finally {
    [Marshal]::FreeHGlobal($KeyObj)
    [Marshal]::FreeHGlobal($BinkObj)
    Write-Host
}