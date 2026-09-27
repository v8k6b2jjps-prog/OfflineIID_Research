using namespace System
using namespace System.Runtime.InteropServices
using namespace System.Diagnostics

Clear-Host

Add-Type @"
using System;
using System.Runtime.InteropServices;

public static class Native {
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    public static extern IntPtr LoadLibrary(string path);

    [DllImport("kernel32.dll")]
    public static extern IntPtr GetProcAddress(IntPtr module, string name);

    [DllImport("kernel32.dll")]
    public static extern bool FreeLibrary(IntPtr module);
}

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
public delegate bool VerifyAndExtractKeyDelegate(
    IntPtr key, IntPtr config, IntPtr uid, IntPtr group);
"@

$CdKey = "RHTBY-VWY6D-QJRJ9-JGQ3X-Q2289"
$Config = Join-Path $PSScriptRoot "pkeyconfig.xrm-ms"

if (-not (Test-Path $Config)) {
    Write-Host "[-] Config not found: $Config" -ForegroundColor Red
    return
}

$DllFile = "PkeyLib.dll"
$DllPath = Join-Path $PSScriptRoot $DllFile

Write-Host "`n=== $DllFile ===" -ForegroundColor Cyan

if (-not (Test-Path $DllPath)) {
	Write-Host "[-] DLL not found" -ForegroundColor Red
	continue
}

$hDll = [Native]::LoadLibrary($DllPath)

if (!$hDll) {
	Write-Host "[-] LoadLibrary failed" -ForegroundColor Red
	continue
}

try {
	$fn = [Native]::GetProcAddress($hDll, "VerifyAndExtractKey")

	if (!$fn) {
		Write-Host "[-] Function not found" -ForegroundColor Red
		continue
	}

	$Verify = [Marshal]::GetDelegateForFunctionPointer(
		$fn, [VerifyAndExtractKeyDelegate])

	$cKey = [Marshal]::StringToHGlobalAnsi($CdKey)
	$cCfg = [Marshal]::StringToHGlobalAnsi($Config)
	$uBuf = [Marshal]::AllocHGlobal(8)
	$gPtr = [Marshal]::AllocHGlobal(4)

	try {
		$sw = [Stopwatch]::StartNew()

		$success = $Verify.Invoke($cKey, $cCfg, $uBuf, $gPtr)

		$sw.Stop()

		if ($success) {
			$bytes = [byte[]]::new(8)
			[Marshal]::Copy($uBuf, $bytes, 0, 8)

			$uid = [BitConverter]::ToUInt64($bytes, 0)
			$group = [Marshal]::ReadInt32($gPtr)
			$hex = -join ($bytes | ForEach-Object { $_.ToString("X2") })

			write-host
			Write-Host "Time     : $($sw.Elapsed.TotalSeconds)s"
			Write-Host "Upgrade  : $([int](($uid -band 1) -eq 1))"
			Write-Host "Serial   : $(($uid -shr 1) -band 0x3FFFFFFF)"
			Write-Host "Auth     : $(($uid -shr 31) -band 0x3FF)"
			Write-Host "Group    : $group"
		}
		else {
			Write-Host "[ X ] Invalid" -ForegroundColor DarkGray
		}
	}
	finally {
		[Marshal]::FreeHGlobal($cKey)
		[Marshal]::FreeHGlobal($cCfg)
		[Marshal]::FreeHGlobal($uBuf)
		[Marshal]::FreeHGlobal($gPtr)
	}
}
finally {
	[Native]::FreeLibrary($hDll) | Out-Null
}