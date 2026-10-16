using namespace System
using namespace System.Diagnostics
using namespace System.Management.Automation
using namespace System.Runtime.InteropServices

param(
    [string]$CDKey,
    [string]$Config,
    [string]$ConfigPath = (Join-Path $PSScriptRoot '\PKeyConfigs'),
    [int]$Threads = 0,
    [switch]$FromParent,

    [ValidateSet('PidGenX','PkeyLib')]
    [string]$RunAs = 'PidGenX',

    # File / Xml / Binks = native PkeyLib export, BinksNet = managed C# engine (PidKeyPlugIn), same index, all cores
    [ValidateSet('File','Xml','Binks','BinksNet')]
    [string]$Method = 'Binks'
)

# List of Source, not by order
# TSForge project, ExtPid
# laomms, PKey2005Decoder, C# Source
# massgravel, spp-stuff-main, iid2005.py
# https://github.com/ntriver-org/PKeyMaster/commit/4926123bc7e56882dc13123942c3459728fb562c

# Multi Platform Version
# .\Pkey-ValidateBink.ps1 -CDKey "FJ82H-XT6CR-J8D7P-XQJJ2-GPDD4"

Set-Location $PSScriptRoot
[Environment]::CurrentDirectory = $PSScriptRoot

# ------------------------------------------------------------
# Process priority
# ------------------------------------------------------------

try {
    $CurrentProcess = [Process]::GetCurrentProcess()
    $CurrentProcess.PriorityClass = [ProcessPriorityClass]::High
    [Threading.Thread]::CurrentThread.Priority = [Threading.ThreadPriority]::Highest
}
catch {
    # Priority changes are optional; continue if unavailable.
}

# Architecture of this PowerShell process, without RuntimeInformation (that type needs .NET Framework 4.7.1+).
# PROCESSOR_ARCHITECTURE describes the current process: x86, AMD64 or ARM64.

# ProcessorArchitecture Enum
# https://learn.microsoft.com/en-us/uwp/api/windows.system.processorarchitecture?view=winrt-28000

$Is32Bit = ([IntPtr]::Size -eq 4)
$IsArm   = ($env:PROCESSOR_ARCHITECTURE -eq 'Arm')
$IsArm64 = ($env:PROCESSOR_ARCHITECTURE -eq 'Arm64')

if ($IsArm) {
    throw "32-bit ARM is not supported"
}

#region Shared
function Resolve-SymbolFromPdb {
    param (
        [string]$BinaryPath = "C:\Windows\System32\ntoskrnl.exe",
        [string]$FunctionName = "MiAllocateVirtualMemory",
        [string]$DownloadFolder = "C:\Symbols"
    )

    # 1. Pure Type Generation Reflection
    try {
        $Module = [AppDomain]::CurrentDomain.GetAssemblies() | ? { $_.ManifestModule.ScopeName -eq "PdbRaw" } | select -Last 1
        $PdbRaw = $Module.GetTypes()[0]
    }
    catch {
        $Module = [AppDomain]::CurrentDomain.DefineDynamicAssembly("null", 1).DefineDynamicModule("PdbRaw", $False).DefineType("null")
        @(
            @('SymInitialize',   'dbghelp.dll', [bool],   @([IntPtr], [string], [bool])),
            @('SymCleanup',      'dbghelp.dll', [bool],   @([IntPtr])),
            @('SymLoadModuleEx', 'dbghelp.dll', [uint64], @([IntPtr], [IntPtr], [string], [string], [uint64], [uint32], [IntPtr], [uint32])),
            @('SymFromName',     'dbghelp.dll', [bool],   @([IntPtr], [string], [IntPtr]))
        ) | % {
            $Module.DefinePInvokeMethod(($_[0]), ($_[1]), 22, 1, [Type]($_[2]), [Type[]]($_[3]), 1, 3).SetImplementationFlags(128)
        }
        $PdbRaw = $Module.CreateType()
    }

    $index = -1
    $found = $false
    $bytes = [System.IO.File]::ReadAllBytes($BinaryPath)
    $ms    = [System.IO.MemoryStream]::new($bytes)
    $br    = [System.IO.BinaryReader]::new($ms)

    while(($index = [Array]::IndexOf($bytes, [byte]0x52, $index + 1)) -ge 0)
    {
        # Verify "RSDS"
        if(
            $index + 24 -gt $bytes.Length -or
            $bytes[$index + 1] -ne 0x53 -or
            $bytes[$index + 2] -ne 0x44 -or
            $bytes[$index + 3] -ne 0x53
        ){
            continue
        }

        # Read candidate RSDS record
        $ms.Position = $index + 4      # Skip "RSDS"
        $guid = (New-Object Guid (,$br.ReadBytes(16))).ToString("N").ToUpper()
        $age  = $br.ReadUInt32()
        $sb = [System.Text.StringBuilder]::new()

        while($ms.Position -lt $ms.Length)
        {
            $b = $br.ReadByte()
            if($b -eq 0){ break }
            [void]$sb.Append([char]$b)
        }

        $name = Split-Path $sb.ToString() -Leaf

        if(
            $age -gt 0 -and
            $name.Length -gt 4 -and
            $name.Length -lt 260 -and
            $name -cmatch '^[ -~]+\.pdb$'
        ){
            $pdbName = $name
            $found = $true
            break
        }
    }

    $br.Close()
    $ms.Close()

    if(-not $found){
        throw "Valid RSDS record not found."
    }

    # 3. Handle local cache check or download
    $destination = Join-Path $DownloadFolder "$pdbName\$guid$age\$pdbName"
    if (-not (Test-Path $destination)) {
        Write-warning "PDB missing locally. Downloading..."
        New-Item -ItemType Directory -Path (Split-Path $destination) -Force | Out-Null
        $url = "https://msdl.microsoft.com/download/symbols/$pdbName/$guid$age/$pdbName"
        # Older .NET Framework versions do not offer TLS 1.2 by default, and the symbol server requires it
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $url -OutFile $destination -UserAgent "Microsoft-Symbol-Server/10.0.0.0" -UseBasicParsing
    }

    # 4. Invoke PInvoke APIs via PdbRaw Methods
    # FIX: Use the current process handle instead of a random integer to guarantee initialization context
    $hProcess = [System.Diagnostics.Process]::GetCurrentProcess().Handle
    
    $fs = [System.IO.File]::OpenRead($BinaryPath)
    $br = New-Object System.IO.BinaryReader($fs)

    # 1. Read DOS header offset (e_lfanew is at 0x3C)
    $fs.Position = 0x3C
    $e_lfanew = $br.ReadInt32()

    # 2. Check the Magic to confirm architecture (at offset e_lfanew + 24)
    $fs.Position = $e_lfanew + 24
    $magic = $br.ReadUInt16()

    # 3. Read the clean ImageBase
    if ($magic -eq 0x20B) { 
        # 64-bit (PE32+): ImageBase is a UInt64 at offset e_lfanew + 48
        $fs.Position = $e_lfanew + 48
        $dummyBase = $br.ReadUInt64()
    } else { 
        # 32-bit (PE32): ImageBase is a UInt32 at offset e_lfanew + 52
        $fs.Position = $e_lfanew + 52
        $dummyBase = [uint64]$br.ReadUInt32()
    }

    $br.Close()
    $fs.Close()

    # FIX: Ensure SymInitialize is passed true or the local target directory to register the module context properly
    $PdbDir = Split-Path $destination
    [void]$PdbRaw::SymInitialize($hProcess, $PdbDir, $false)
    
    # Load the module layout cleanly
    $modBase = $PdbRaw::SymLoadModuleEx($hProcess, [IntPtr]::Zero, $destination, $null, $dummyBase, [uint32]0, [IntPtr]::Zero, [uint32]0)

    if ($modBase -eq 0) {
        [void]$PdbRaw::SymCleanup($hProcess)
        throw "Failed to load module inside dbghelp. Ensure the PDB target matches your architecture."
    }

    # FIX: Standardized unmanaged allocation via native Marshal instead of custom commandlets
    $BufferSize = 88 + 2000
    $pSymbolInfo = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($BufferSize)
    [marshal]::Copy((New-Object byte[] $BufferSize),0, $pSymbolInfo, $BufferSize)
    [marshal]::WriteInt32($pSymbolInfo, 0, 88)
    [Marshal]::WriteInt32($pSymbolInfo, 76, 2000)

    # Run the symbol search
    $matched = $PdbRaw::SymFromName($hProcess, $FunctionName, $pSymbolInfo)

    if ($matched) {
        $AbsoluteAddress = [Marshal]::ReadInt64($pSymbolInfo, 56) # Offset 56 = Address
        $offset = [int64]($AbsoluteAddress - $dummyBase)
        $result = $offset
    } else {
        $result = $null
    }

    # Cleanup memory and symbol paths
    [Marshal]::FreeHGlobal($pSymbolInfo)
    [void]$PdbRaw::SymCleanup($hProcess)

    if ($null -ne $result) { return $result } else { throw "Function '$FunctionName' not found." }
}
function Restore-Util {
    $asm = $null
    try { $asm = [Reflection.Assembly]::LoadWithPartialName('Microsoft.PowerShell.Commands.Utility') } catch { }
    if (-not $asm) {
        foreach ($ver in '3.0.0.0', '3.1.0.0') {
            try {
                $asm = [Reflection.Assembly]::Load(
                    "Microsoft.PowerShell.Commands.Utility, Version=$ver, Culture=neutral, PublicKeyToken=31bf3856ad364e35")
                if ($asm) { break }
            } catch { }
        }
    }
    if (-not $asm) {
        $dll = [IO.Path]::Combine($PSHOME, 'Microsoft.PowerShell.Commands.Utility.dll')
        if ([IO.File]::Exists($dll)) { try { $asm = [Reflection.Assembly]::LoadFile($dll) } catch { } }
    }
    if (-not $asm) {
        [Console]::Error.WriteLine('Could not locate Microsoft.PowerShell.Commands.Utility.')
        return
    }
    $token = ($asm.GetName().GetPublicKeyToken() | ForEach-Object { $_.ToString('x2') }) -join ''
    if ($token -ne '31bf3856ad364e35') {
        [Console]::Error.WriteLine("Refusing to import: unexpected publisher token '$token'.")
        return
    }
    Import-Module -Assembly $asm -ErrorAction Stop
}
function Get-WinRTHwid {
    [CmdletBinding()]
    param(
        [string]$WinrtDll = (Join-Path $env:windir "System32\LicensingWinRT.dll"),
        [int64] $Rva = 0,                                  # pass a known RVA to skip the scan
        [byte[]]$Pattern = [byte[]](0x18,0x01,0x00,0x00)
    )

if (!([PSTypeName]'HwidGetCurrentExDelegate').Type) {
    Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

// 2 in-params + 4 out-pointers, returns HRESULT  (mirrors your old 6-value call)
[UnmanagedFunctionPointer(CallingConvention.Winapi)]
public delegate int HwidGetCurrentExDelegate(
    IntPtr context,
    uint   flags,
    out IntPtr buffer,
    out IntPtr out1,
    out IntPtr out2,
    out IntPtr out3);

public static class Native {
    [DllImport("kernel32", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern IntPtr LoadLibraryW(string lpFileName);
}
"@
}

    if (-not (Test-Path $WinrtDll)) { throw "Not found: $WinrtDll" }
    $b = [IO.File]::ReadAllBytes($WinrtDll)

    # ---- resolve RVA of inner HwidGetCurrentEx: scan prologue, then offset->RVA ----
    if ($Rva -le 0) {
      try {
        $Rva = Resolve-SymbolFromPdb -BinaryPath C:\Windows\System32\LicensingWinRT.dll -FunctionName HwidGetCurrentEx
      } 
      catch {
        $Rva = 0
      }
    }
    if ($Rva -le 0 -and !$IsArm64 -and !$Is32Bit) {
        # Stage 1: CMP r32, 0x118
        $cmp = -1
        for ($i = 3; $i -lt $b.Length - 4; $i++) {
            if ($b[$i] -eq $Pattern[0] -and $b[$i+1] -eq $Pattern[1] -and $b[$i+2] -eq $Pattern[2]) {
                if (($b[$i-1] -eq 0x3D) -or
                    ($b[$i-2] -eq 0x81 -and $b[$i-1] -ge 0xF8 -and $b[$i-1] -le 0xFB) -or
                    ($b[$i-3] -eq 0x41 -and $b[$i-2] -eq 0x81 -and $b[$i-1] -ge 0xF8 -and $b[$i-1] -le 0xFB)) {
                    $cmp = $i; break
                }
            }
        }
        if ($cmp -lt 0) { throw "CMP 0x118 not found" }

        # Stage 2: previous 0x118 (alloc size)
        $alloc = -1
        for ($j = $cmp - 1; $j -gt 0; $j--) {
            if ($b[$j] -eq $Pattern[0] -and $b[$j+1] -eq $Pattern[1] -and $b[$j+2] -eq $Pattern[2]) { $alloc = $j; break }
        }
        if ($alloc -lt 0) { throw "Second 0x118 not found before CMP" }

        # Stage 3: function prologue, preceded by CC/90/C3 padding
        $off = -1
        $limit = [Math]::Max(0, $alloc - 0x150)
        for ($k = $alloc; $k -gt $limit; $k--) {
            $hit = ($b[$k] -eq 0x48 -and $b[$k+1] -eq 0x8B -and $b[$k+2] -eq 0xC4) -or   # mov rax,rsp
                   ($b[$k] -eq 0x48 -and $b[$k+1] -eq 0x83 -and $b[$k+2] -eq 0xEC) -or   # sub rsp,XX
                   ($b[$k] -eq 0x55 -and $b[$k+1] -eq 0x48 -and $b[$k+2] -eq 0x89)       # push rbp; mov rbp
            if ($hit) {
                $p = $b[$k-1]
                if ($p -eq 0xCC -or $p -eq 0x90 -or $p -eq 0xC3) { $off = $k; break }
            }
        }
        if ($off -lt 0) { throw "Could not locate function prologue" }

        # file offset -> RVA via section table (no ImageBase needed; we use the live base)
        $pe     = [BitConverter]::ToUInt32($b, 0x3C)
        $nSec   = [BitConverter]::ToUInt16($b, $pe + 6)
        $secTbl = $pe + 0x18 + [BitConverter]::ToUInt16($b, $pe + 0x14)
        for ($s = 0; $s -lt $nSec; $s++) {
            $pt   = $secTbl + ($s * 40)
            $rawP = [BitConverter]::ToUInt32($b, $pt + 0x14)
            $rawS = [BitConverter]::ToUInt32($b, $pt + 0x10)
            $va   = [BitConverter]::ToUInt32($b, $pt + 0x0C)
            if ($off -ge $rawP -and $off -lt ($rawP + $rawS)) { $Rva = [int64](($off - $rawP) + $va); break }
        }
        if ($Rva -le 0) { throw ("Could not map offset 0x{0:X} to an RVA" -f $off) }
    }

    # ---- LoadLibrary + delegate call ----
    $h = [Native]::LoadLibraryW($WinrtDll)
    if ($h -eq [IntPtr]::Zero) { throw "LoadLibrary failed (err $([Marshal]::GetLastWin32Error()))" }
    $call = [Marshal]::GetDelegateForFunctionPointer([IntPtr]([int64]$h + $Rva), [HwidGetCurrentExDelegate])

    $buf=[IntPtr]::Zero; $o1=[IntPtr]::Zero; $o2=[IntPtr]::Zero; $o3=[IntPtr]::Zero
    $hr = $call.Invoke([IntPtr]::Zero, 0, [ref]$buf, [ref]$o1, [ref]$o2, [ref]$o3)
    if ($hr -lt 0)               { throw ("HwidGetCurrentEx hr=0x{0:X8}" -f $hr) }
    if ($buf -eq [IntPtr]::Zero) { throw "HwidGetCurrentEx returned a null buffer" }

    $raw = New-Object Byte[] 0x118
    [Marshal]::Copy($buf, $raw, 0, 0x118)

    # ---- fold the 0x118 block into the short HWID ----
    $S = [PSCustomObject]@{ P=28; L=[int64]0; H=[int64]0; S=0 }
    $Pack = {
        param([int]$idx,[int]$bits,[int]$shift,[int64]$mask,[bool]$isHigh,$sShift)
        $cnt = [BitConverter]::ToUInt16($raw, $idx*2)
        if ($cnt -eq 0) { return }
        $v4 = [BitConverter]::ToUInt16($raw, $S.P)
        for ($i=0; $i -lt $cnt; $i++) {
            $val = [BitConverter]::ToUInt16($raw, $S.P + ($i*2))
            if (($val -band 1) -eq 0) { $v4 = $val; break }
        }
        $S.S = ($v4 -band 1)
        $m = (1 -shl $bits) - 1
        $hash = $m -band ($v4 -shr 1); if ($hash -eq 0) { $hash = $m }
        $xor = ([int64]$hash -shl $shift)
        if ($isHigh) { $S.H = ($S.H -bxor (($S.H -bxor $xor) -band $mask)) -band 0xFFFFFFFF }
        else         { $S.L = ($S.L -bxor (($S.L -bxor $xor) -band $mask)) -band 0xFFFFFFFF }
        if ($null -ne $sShift) {
            $S.L = ($S.L -bxor (($S.L -bxor ($S.L -bor ($S.S -shl $sShift))) -band 0x7C0)) -band 0xFFFFFFFF
        }
        $S.P += (2 * $cnt)
    }
    $v3 = [BitConverter]::ToUInt16($raw, 26); if ($v3) { $v6=(($v3 -shr 1) -band 0x3F); $S.L = if($v6){[int64]$v6}else{[int64]63} }
    $v8 = [BitConverter]::ToUInt16($raw, 24); if ($v8) { $v9=(($v8 -shr 1) -band 7); $v10= if($v9){$v9}else{7}; $S.H=([int64]$v10 -shl 29) -band 0xFFFFFFFF }
    &$Pack 2  7 21 0xFE00000  $false 6
    &$Pack 3  4 28 0xF0000000 $false $null
    &$Pack 4  7 9  0xFE00     $true  7
    &$Pack 5  5 21 0x3E00000  $true  $null
    &$Pack 6  5 16 0x1F0000   $true  8
    &$Pack 7  6 3  0x1F8      $true  9
    $S.P += (2 * [BitConverter]::ToUInt16($raw, 16))
    &$Pack 9  10 11 0x1FF800   $false 10
    &$Pack 10 3  26 0x1C000000 $true  $null

    return ([int64]$S.H -shl 32) -bor ([uint32]$S.L)
}
function Get-IidHwid {
    <#
    .SYNOPSIS
        Returns the HWID from a 54-digit (2005) or 63-digit (2009) Installation ID
        as "0x" + 16 hex digits, or $null if the IID is invalid.
    #>
    param([Parameter(Mandatory, ValueFromPipeline)][AllowEmptyString()][string]$Iid)
    process {
if (!([PSTypeName]'PkeyIid.IidHwid').Type) {
    $IidHwidSource = @'
using System;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;

namespace PkeyIid
{
    /// <summary>
    /// Extracts only the HWID from an MSFT 2005 (54-digit) or 2009 (63-digit) Installation ID.
    /// Decode-only; no other fields are returned. C# 5 compatible (Windows PowerShell 5.1 Add-Type).
    /// </summary>
    public static class IidHwid
    {
        private static readonly byte[] Key = {
            0x6B, 0xC8, 0x5E, 0xD4, 0xF0, 0xF8, 0xD8, 0x84,
            0x77, 0x41, 0x2A, 0x2F, 0x7D, 0x93, 0x13, 0xF4,
            0x1B, 0x8A, 0x66, 0xE6, 0xA2, 0x15, 0x95, 0xBB,
            0x0E, 0x9D, 0xB0, 0x67, 0x83, 0x32, 0x2B, 0x97,
            0x49, 0xFE, 0xD9, 0xCD, 0x7C, 0x7D, 0xDC, 0xEE,
            0xB0, 0x07, 0x12, 0xDF, 0xE7, 0x0B, 0x3B, 0xEB,
            0x56, 0xBD, 0x98, 0xDF, 0xFD, 0x27, 0xA6, 0xCF,
            0x5D, 0x84, 0x36, 0xC2, 0xF8, 0x73, 0x3A, 0x57
        };

        /// <summary>Returns false if the IID is malformed, has a wrong check digit, or is not 54/63 digits.</summary>
        public static bool TryGetHwid(string iid, out ulong hwid)
        {
            hwid = 0;
            string s = Normalize(iid);
            if (s == null) return false;

            if (s.Length == 54)
            {
                // 2005: 9 x (5+1) digits -> 19 bytes -> Feistel 9+9 (+1 passthrough); HWID = bits 64..127
                string d = StripCheckDigits(s, 5);
                if (d == null) return false;
                byte[] enc = ToBytesChecked(BigInteger.Parse(d), 19);
                if (enc == null) return false;
                hwid = (ulong)((ToBig(Feistel(enc)) >> 64) & ulong.MaxValue);
                return true;
            }

            if (s.Length == 63)
            {
                // 2009: 9 x (6+1) digits -> 179 bits, >>3 -> 22 bytes -> Feistel 11+11; HWID = bits 92..155
                string d = StripCheckDigits(s, 6);
                if (d == null) return false;
                BigInteger v = BigInteger.Parse(d);
                if (ToBytesChecked(v, 23) == null) return false;
                hwid = (ulong)((ToBig(Feistel(ToBytes(v >> 3, 22))) >> 92) & ulong.MaxValue);
                return true;
            }

            return false;
        }

        /// <summary>HWID as "0x" + 16 hex digits, or null if the IID is invalid.</summary>
        public static string GetHwidHex(string iid)
        {
            ulong h;
            return TryGetHwid(iid, out h) ? "0x" + h.ToString("x16") : null;
        }

        // ---------------------------------------------------------------- decrypt (16-round SHA-1 Feistel)

        private static byte[] Feistel(byte[] input)
        {
            int half = input.Length / 2;
            byte[] L = new byte[half], R = new byte[half];
            Buffer.BlockCopy(input, 0,    L, 0, half);
            Buffer.BlockCopy(input, half, R, 0, half);

            using (SHA1 sha = SHA1.Create())
            {
                for (int i = 0; i < 16; i++)
                {
                    byte[] f = Round(sha, L, 0x3C - 4 * i);
                    byte[] nL = new byte[half];
                    for (int j = 0; j < half; j++) nL[j] = (byte)(R[j] ^ f[j]);
                    R = L; L = nL;
                }
            }

            byte[] output = (byte[])input.Clone();
            Buffer.BlockCopy(L, 0, output, 0,    half);
            Buffer.BlockCopy(R, 0, output, half, half);
            return output;
        }

        private static byte[] Round(SHA1 sha, byte[] half, int keyOff)
        {
            int n = half.Length;
            byte[] msg = new byte[1 + n + 4];
            msg[0] = 0x79;
            Buffer.BlockCopy(half, 0, msg, 1, n);
            Buffer.BlockCopy(Key, keyOff, msg, 1 + n, 4);

            byte[] h = sha.ComputeHash(msg);
            int dwords = n - (n % 4), tail = n % 4;
            byte[] r = new byte[n];
            Buffer.BlockCopy(h, 0, r, 0, dwords);
            if (tail > 0) Buffer.BlockCopy(h, dwords + 4 - tail, r, dwords, tail);
            return r;
        }

        // ---------------------------------------------------------------- input handling

        private static string Normalize(string iid)
        {
            if (string.IsNullOrEmpty(iid)) return null;
            StringBuilder sb = new StringBuilder(iid.Length);
            foreach (char c in iid)
            {
                if (c >= '0' && c <= '9') sb.Append(c);
                else if (c != '-' && c != ' ') return null;
            }
            return sb.ToString();
        }

        // Check digit = sum(digit * (1,2,1,2,...)) mod 7, one per group.
        private static string StripCheckDigits(string s, int groupLen)
        {
            int step = groupLen + 1;
            if (s.Length % step != 0) return null;
            StringBuilder sb = new StringBuilder(s.Length);
            for (int g = 0; g < s.Length; g += step)
            {
                int sum = 0;
                for (int i = 0; i < groupLen; i++) sum += (s[g + i] - '0') * (i % 2 + 1);
                if (s[g + groupLen] - '0' != sum % 7) return null;
                sb.Append(s, g, groupLen);
            }
            return sb.ToString();
        }

        private static byte[] ToBytes(BigInteger v, int size)
        {
            byte[] b = v.ToByteArray();
            byte[] r = new byte[size];
            Buffer.BlockCopy(b, 0, r, 0, Math.Min(b.Length, size));
            return r;
        }

        private static byte[] ToBytesChecked(BigInteger v, int size)
        {
            byte[] b = v.ToByteArray();
            for (int i = size; i < b.Length; i++) if (b[i] != 0) return null;
            return ToBytes(v, size);
        }

        private static BigInteger ToBig(byte[] le)
        {
            byte[] tmp = new byte[le.Length + 1];
            Buffer.BlockCopy(le, 0, tmp, 0, le.Length);
            return new BigInteger(tmp);
        }
    }
}
'@

    $addTypeArgs = @{ TypeDefinition = $IidHwidSource; Language = 'CSharp' }
    if ($PSVersionTable.PSEdition -ne 'Core') {
        # Windows PowerShell 5.1 needs the BigInteger assembly referenced explicitly
        $addTypeArgs.ReferencedAssemblies = 'System.Numerics'
    }
    Add-Type @addTypeArgs
    Remove-Variable IidHwidSource, addTypeArgs
}
        try   { [PkeyIid.IidHwid]::GetHwidHex($Iid) }
        catch { $null }
    }
}
function New-Iid2005 {
    <#
    .SYNOPSIS
        Builds a 54-digit MSFT 2005 Installation ID. Same argument order as iid2005.py encode.
    .PARAMETER Hwid
        "0x..." hex (from Get-IidHwid), signed decimal, or unsigned decimal.
    .OUTPUTS
        54-digit IID string, or $null if the HWID text is invalid.
    #>
    param(
        [Parameter(Mandatory, Position = 0)][string]$Hwid,
        [Parameter(Mandatory, Position = 1)][uint32]$Security,
        [Parameter(Mandatory, Position = 2)][uint32]$Group,
        [Parameter(Mandatory, Position = 3)][uint32]$Serial,
        [uint32]$Upgrade = 0
    )
    try   { 
if (!([PSTypeName]'PkeyIid.Iid2005Encoder').Type) {
    $Iid2005Source = @'
using System;
using System.Globalization;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;

namespace PkeyIid
{
    /// <summary>
    /// Builds a 54-digit MSFT 2005 Installation ID. Encode-only; same field order as iid2005.py encode.
    /// C# 5 compatible (Windows PowerShell 5.1 Add-Type).
    /// </summary>
    public static class Iid2005Encoder
    {
        private static readonly byte[] Key = {
            0x6B, 0xC8, 0x5E, 0xD4, 0xF0, 0xF8, 0xD8, 0x84,
            0x77, 0x41, 0x2A, 0x2F, 0x7D, 0x93, 0x13, 0xF4,
            0x1B, 0x8A, 0x66, 0xE6, 0xA2, 0x15, 0x95, 0xBB,
            0x0E, 0x9D, 0xB0, 0x67, 0x83, 0x32, 0x2B, 0x97,
            0x49, 0xFE, 0xD9, 0xCD, 0x7C, 0x7D, 0xDC, 0xEE,
            0xB0, 0x07, 0x12, 0xDF, 0xE7, 0x0B, 0x3B, 0xEB,
            0x56, 0xBD, 0x98, 0xDF, 0xFD, 0x27, 0xA6, 0xCF,
            0x5D, 0x84, 0x36, 0xC2, 0xF8, 0x73, 0x3A, 0x57
        };

        /// <summary>HWID as "0x..." hex, signed decimal ("-706...") or unsigned decimal. Null on bad HWID text.</summary>
        public static string Encode(string hwid, uint security, uint group, uint serial, uint upgrade)
        {
            ulong h;
            if (!TryParseHwid(hwid, out h)) return null;
            return Encode(h, security, group, serial, upgrade);
        }

        public static string Encode(ulong hwid, uint security, uint group, uint serial, uint upgrade)
        {
            // bit 0-7 version (=1) | 8 upgrade | 9-38 serial | 39-48 security | 49-58 group | 64-127 hwid
            BigInteger raw = BigInteger.One;
            raw |= (BigInteger)(upgrade  & 1)          << 8;
            raw |= (BigInteger)(serial   & 0x3FFFFFFF) << 9;
            raw |= (BigInteger)(security & 0x3FF)      << 39;
            raw |= (BigInteger)(group    & 0x3FF)      << 49;
            raw |= (BigInteger)hwid                    << 64;

            byte[] b = raw.ToByteArray();
            byte[] block = new byte[19];
            Buffer.BlockCopy(b, 0, block, 0, Math.Min(b.Length, 19));

            byte[] enc = Encrypt(block);
            byte[] tmp = new byte[20];                       // trailing 0x00 keeps it unsigned
            Buffer.BlockCopy(enc, 0, tmp, 0, 19);
            string digits = new BigInteger(tmp).ToString().PadLeft(45, '0');

            // 9 groups of 5 digits + check digit: sum(d * (1,2,1,2,1)) mod 7
            StringBuilder sb = new StringBuilder(54);
            for (int g = 0; g < 45; g += 5)
            {
                int sum = 0;
                for (int i = 0; i < 5; i++) sum += (digits[g + i] - '0') * (i % 2 + 1);
                sb.Append(digits, g, 5).Append((char)('0' + sum % 7));
            }
            return sb.ToString();
        }

        private static bool TryParseHwid(string s, out ulong hwid)
        {
            hwid = 0;
            if (string.IsNullOrWhiteSpace(s)) return false;
            s = s.Trim();

            if (s.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
                return s.Length > 2 && s.Length <= 18 &&
                       ulong.TryParse(s.Substring(2), NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture, out hwid);

            if (s.StartsWith("-"))
            {
                long signed;
                if (!long.TryParse(s, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out signed)) return false;
                hwid = unchecked((ulong)signed);
                return true;
            }

            return ulong.TryParse(s, NumberStyles.None, CultureInfo.InvariantCulture, out hwid);
        }

        // 16-round SHA-1 Feistel, 9+9 bytes, byte 18 passes through. F truncated to h[0..7] + h[11].
        private static byte[] Encrypt(byte[] input)
        {
            byte[] L = new byte[9], R = new byte[9];
            Buffer.BlockCopy(input, 0, L, 0, 9);
            Buffer.BlockCopy(input, 9, R, 0, 9);

            using (SHA1 sha = SHA1.Create())
            {
                byte[] msg = new byte[14];
                msg[0] = 0x79;
                for (int i = 0; i < 16; i++)
                {
                    Buffer.BlockCopy(R, 0, msg, 1, 9);
                    Buffer.BlockCopy(Key, 4 * i, msg, 10, 4);
                    byte[] h = sha.ComputeHash(msg);

                    byte[] nR = new byte[9];
                    for (int j = 0; j < 8; j++) nR[j] = (byte)(L[j] ^ h[j]);
                    nR[8] = (byte)(L[8] ^ h[11]);
                    L = R; R = nR;
                }
            }

            byte[] output = new byte[19];
            Buffer.BlockCopy(L, 0, output, 0, 9);
            Buffer.BlockCopy(R, 0, output, 9, 9);
            output[18] = input[18];
            return output;
        }
    }
}
'@

    $addTypeArgs = @{ TypeDefinition = $Iid2005Source; Language = 'CSharp' }
    if ($PSVersionTable.PSEdition -ne 'Core') {
        # Windows PowerShell 5.1 needs the BigInteger assembly referenced explicitly
        $addTypeArgs.ReferencedAssemblies = 'System.Numerics'
    }
    Add-Type @addTypeArgs
    Remove-Variable Iid2005Source, addTypeArgs
}
        [PkeyIid.Iid2005Encoder]::Encode($Hwid, $Security, $Group, $Serial, $Upgrade) 
    }
    catch { $null }
}
function Get-PkeyInfo {
    <#
    .SYNOPSIS
        Decodes the PKEY2005 UID returned by PkeyLib64.dll, looks up the
        matching configuration in pkeyconfig.xrm-ms, builds the ActString
        and re-encodes an offline IID using the
        HWID of the installed Windows product.

        UID layout (https://github.com/UMSKT/writeups/blob/main/PKEY2005.md):
            upgrade : 1   | serial : 30   | auth : 10
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][byte[]]$Uid,
        [Parameter(Mandatory)][int]$Group,
        [string]$ConfigPath,
        [switch]$Skip,                      # no pkeyconfig lookup: only the fields decoded from the UID are filled
        [string]$ScriptDir = $PSScriptRoot
    )

    # --- Decode UID bit fields ---------------------------------------------
    $raw     = [BitConverter]::ToUInt64($Uid, 0)
    $upgrade = $raw -band 1
    $serial  = ($raw -shr 1)  -band 0x3FFFFFFF
    $auth    = ($raw -shr 31) -band 0x3FF

    # --- Find Configuration + KeyRange for Group/Serial ---------------------
    $get = { param($Node, $Name) $Node.SelectSingleNode("*[local-name()='$Name']").InnerText }

    $cfg = $null; $range = $null; $actId = $null
    if ($ConfigPath -and -not $Skip) {
        [xml]$xrm = Get-Content -LiteralPath $ConfigPath -Raw
        $b64 = $xrm.SelectSingleNode("//*[local-name()='infoBin'][@name='pkeyConfigData']").InnerText
        [xml]$pkey = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($b64)).TrimStart([char]0xFEFF)

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
    }

    # --- ActString: msft2005:<guid>&<base64(upgrade | serial<<1 | auth<<31)> --
    $actString = $null
    if ($actId) {
        $keyData = [byte[]]::new(12)
        [BitConverter]::GetBytes([UInt64]($upgrade -bor ($serial -shl 1) -bor ($auth -shl 31))).CopyTo($keyData, 0)
        $actString = "msft2005:$($actId.Trim('{','}').ToLowerInvariant())&$([Convert]::ToBase64String($keyData))"
    }

    # --- HWID from installed Windows product + new offline IID --------------
    $hwid = $null
    $offlineAct = $null

    if (-not $hwid -and $Global:iid) { 
        try {
          $hwid = Get-IidHwid $iid
        } catch{}
    }
    if (-not $hwid) {
      try {
        $hwid = [String]::Format("0x{0}", [Convert]::ToString((Get-WinRTHwid), 16))
      } catch {}
    }
    if ($hwid -eq $null) {
      $hwid = '0'
    }
    $offlineAct = New-Iid2005 -Hwid $hwid -Security $auth -Group $Group -Serial $serial -Upgrade $upgrade

# Tsforge Project
$GetPid = {
    param (
        [long]$Serial,
        [int]$Group,
        [string]$EulaType = "Retail",
        [string]$Mpc = "00000"
    )

    $groupPart = ($Group -shr 1) % 100
    $high      = [int]([Math]::Floor($Serial / 1000000) % 1000)   # clamped like the real code
    $low       = [int]($Serial % 1000000)

    if ($EulaType -like 'OEM*') {
        $serialHigh = 'OEM'
        $serialLow  = [int]([Math]::Floor($low / 100000) + 10 * ($high + 1000 * $groupPart))
        $lastPart   = [int]($Serial % 100000)
    }
    else {
        $serialHigh = '{0:D3}' -f $high
        $serialLow  = $low
        $lastPart   = [int]($groupPart * 1000 + (Get-Random -Maximum 1000))
    }

    # Digit sum of serialLow, mod-7 check digit (1..7, never 0)
    $sum = 0
    foreach ($ch in $serialLow.ToString().ToCharArray()) { $sum += [int]$ch - 48 }
    $checksum = 7 - ($sum % 7)

    '{0}-{1}-{2:D6}{3}-{4:D5}' -f $Mpc, $serialHigh, $serialLow, $checksum, $lastPart
}
$GetExtendedPid = {
    param (
        [long]$Serial,
        [int]$Group,
        [string]$EulaType = "Retail",
        [string]$Mpc = "00000"
    )

    $now = Get-Date
    $licenseType = switch -Wildcard ($EulaType) { 'OEM*' { 2 } 'Volume*' { 3 } default { 0 } }

    [String]::Format(
        "{0}-{1:D5}-{2:D3}-{3:D6}-{4:D2}-{5:D4}-{6:D4}.0000-{7:D3}{8:D4}",
        $Mpc,
        $Group % 100000,
        [int]([Math]::Floor($Serial / 1000000) % 1000),
        [int]($Serial % 1000000),
        $licenseType,
        [PkeyNative]::GetSystemDefaultLangID(),
        [Environment]::OSVersion.Version.Build,
        $now.DayOfYear,
        $now.Year
    )
}
    $Eula = if ($range) { & $get $range 'EulaType' } else { $null }
    [pscustomobject]@{
        Upgrade     = $upgrade
        Serial      = $serial
        Auth        = $auth
        Group       = $Group
        ActConfigId = $actId
        Edition     = if ($cfg)   { & $get $cfg 'EditionId' } else { $null }
        Description = if ($cfg)   { & $get $cfg 'ProductDescription' } else { $null }
        PartNumber  = if ($range) { & $get $range 'PartNumber' } else { $null }
        EulaType    = $Eula
        RangeValid  = if ($range) { (& $get $range 'IsValid') -eq 'true' } else { $null }
        ActString   = $actString
        BasePid     = & $GetPid -Serial $serial -Group $Group -EulaType $Eula
        ExtendedPID = & $GetExtendedPid -Serial $serial -Group $Group
        HWID        = $hwid
        OfflineAct  = $offlineAct
    }
}
class BinaryKey {
    [uint16]$Group
    [uint32]$Serial
    [uint64]$Security
    [bool]$IsNKey
    [int32]$Checksum
    [byte[]]$BinaryData
    [string]$CdKey

    BinaryKey([string]$ProductKey) {
        $this.BinaryData = [BinaryKey]::EncodeBinaryKey($ProductKey)
        $BinKeyInfo = [BinaryKey]::UnpackBinaryKey($this.BinaryData, $true)
        $this.Group = $BinKeyInfo.Group
        $this.Serial = $BinKeyInfo.Serial
        $this.Security = $BinKeyInfo.Security
        $this.IsNKey = $BinKeyInfo.IsNKey
        $this.CdKey = $ProductKey
        $this.Checksum = [BinaryKey]::GetKeyChecksum($this.BinaryData)
    }

    static $CrcTable = @(
        0x00000000, 0x04C11DB7, 0x09823B6E, 0x0D4326D9, 0x130476DC, 0x17C56B6B, 0x1A864DB2, 0x1E475005,
        0x2608EDB8, 0x22C9F00F, 0x2F8AD6D6, 0x2B4BCB61, 0x350C9B64, 0x31CD86D3, 0x3C8EA00A, 0x384FBDBD,
        0x4C11DB70, 0x48D0C6C7, 0x4593E01E, 0x4152FDA9, 0x5F15ADAC, 0x5BD4B01B, 0x569796C2, 0x52568B75,
        0x6A1936C8, 0x6ED82B7F, 0x639B0DA6, 0x675A1011, 0x791D4014, 0x7DDC5DA3, 0x709F7B7A, 0x745E66CD,
        0x9823B6E0, 0x9CE2AB57, 0x91A18D8E, 0x95609039, 0x8B27C03C, 0x8FE6DD8B, 0x82A5FB52, 0x8664E6E5,
        0xBE2B5B58, 0xBAEA46EF, 0xB7A96036, 0xB3687D81, 0xAD2F2D84, 0xA9EE3033, 0xA4AD16EA, 0xA06C0B5D,
        0xD4326D90, 0xD0F37027, 0xDDB056FE, 0xD9714B49, 0xC7361B4C, 0xC3F706FB, 0xCEB42022, 0xCA753D95,
        0xF23A8028, 0xF6FB9D9F, 0xFBB8BB46, 0xFF79A6F1, 0xE13EF6F4, 0xE5FFEB43, 0xE8BCCD9A, 0xEC7DD02D,
        0x34867077, 0x30476DC0, 0x3D044B19, 0x39C556AE, 0x278206AB, 0x23431B1C, 0x2E003DC5, 0x2AC12072,
        0x128E9DCF, 0x164F8078, 0x1B0CA6A1, 0x1FCDBB16, 0x018AEB13, 0x054BF6A4, 0x0808D07D, 0x0CC9CDCA,
        0x7897AB07, 0x7C56B6B0, 0x71159069, 0x75D48DDE, 0x6B93DDDB, 0x6F52C06C, 0x6211E6B5, 0x66D0FB02,
        0x5E9F46BF, 0x5A5E5B08, 0x571D7DD1, 0x53DC6066, 0x4D9B3063, 0x495A2DD4, 0x44190B0D, 0x40D816BA,
        0xACA5C697, 0xA864DB20, 0xA527FDF9, 0xA1E6E04E, 0xBFA1B04B, 0xBB60ADFC, 0xB6238B25, 0xB2E29692,
        0x8AAD2B2F, 0x8E6C3698, 0x832F1041, 0x87EE0DF6, 0x99A95DF3, 0x9D684044, 0x902B669D, 0x94EA7B2A,
        0xE0B41DE7, 0xE4750050, 0xE9362689, 0xEDF73B3E, 0xF3B06B3B, 0xF771768C, 0xFA325055, 0xFEF34DE2,
        0xC6BCF05F, 0xC27DEDE8, 0xCF3ECB31, 0xCBFFD686, 0xD5B88683, 0xD1799B34, 0xDC3ABDED, 0xD8FBA05A,
        0x690CE0EE, 0x6DCDFD59, 0x608EDB80, 0x644FC637, 0x7A089632, 0x7EC98B85, 0x738AAD5C, 0x774BB0EB,
        0x4F040D56, 0x4BC510E1, 0x46863638, 0x42472B8F, 0x5C007B8A, 0x58C1663D, 0x558240E4, 0x51435D53,
        0x251D3B9E, 0x21DC2629, 0x2C9F00F0, 0x285E1D47, 0x36194D42, 0x32D850F5, 0x3F9B762C, 0x3B5A6B9B,
        0x0315D626, 0x07D4CB91, 0x0A97ED48, 0x0E56F0FF, 0x1011A0FA, 0x14D0BD4D, 0x19939B94, 0x1D528623,
        0xF12F560E, 0xF5EE4BB9, 0xF8AD6D60, 0xFC6C70D7, 0xE22B20D2, 0xE6EA3D65, 0xEBA91BBC, 0xEF68060B,
        0xD727BBB6, 0xD3E6A601, 0xDEA580D8, 0xDA649D6F, 0xC423CD6A, 0xC0E2D0DD, 0xCDA1F604, 0xC960EBB3,
        0xBD3E8D7E, 0xB9FF90C9, 0xB4BCB610, 0xB07DABA7, 0xAE3AFBA2, 0xAAFBE615, 0xA7B8C0CC, 0xA379DD7B,
        0x9B3660C6, 0x9FF77D71, 0x92B45BA8, 0x9675461F, 0x8832161A, 0x8CF30BAD, 0x81B02D74, 0x857130C3,
        0x5D8A9099, 0x594B8D2E, 0x5408ABF7, 0x50C9B640, 0x4E8EE645, 0x4A4FFBF2, 0x470CDD2B, 0x43CDC09C,
        0x7B827D21, 0x7F436096, 0x7200464F, 0x76C15BF8, 0x68860BFD, 0x6C47164A, 0x61043093, 0x65C52D24,
        0x119B4BE9, 0x155A565E, 0x18197087, 0x1CD86D30, 0x029F3D35, 0x065E2082, 0x0B1D065B, 0x0FDC1BEC,
        0x3793A651, 0x3352BBE6, 0x3E119D3F, 0x3AD08088, 0x2497D08D, 0x2056CD3A, 0x2D15EBE3, 0x29D4F654,
        0xC5A92679, 0xC1683BCE, 0xCC2B1D17, 0xC8EA00A0, 0xD6AD50A5, 0xD26C4D12, 0xDF2F6BCB, 0xDBEE767C,
        0xE3A1CBC1, 0xE760D676, 0xEA23F0AF, 0xEEE2ED18, 0xF0A5BD1D, 0xF464A0AA, 0xF9278673, 0xFDE69BC4,
        0x89B8FD09, 0x8D79E0BE, 0x803AC667, 0x84FBDBD0, 0x9ABC8BD5, 0x9E7D9662, 0x933EB0BB, 0x97FFAD0C,
        0xAFB010B1, 0xAB710D06, 0xA6322BDF, 0xA2F33668, 0xBCB4666D, 0xB8757BDA, 0xB5365D03, 0xB1F740B4
    )

    static [int] GetKeyChecksum([byte[]]$Data) {
        $v35 = $Data.Clone()
        $v11 = [int]$v35[14]
        $isNKeySet = ($v11 -band 8) -ne 0
        $v14 = $v11 -bxor (($v11 -bxor (4 * [int]$isNKeySet)) -band 8)
        $v35[12] = [byte]($v35[12] -band 0x7F)
        $v35[14] = [byte]($v14 -band 0xFE)
        $v35[13] = 0

        $v20 = [uint32]"0xFFFFFFFF"
        foreach ($b in $v35) {
            $idx = ([int]$b -bxor [int]($v20 -shr 24)) -band 0xFF
            $v20 = [uint32]((($v20 -shl 8) -bxor [BinaryKey]::CrcTable[$idx]) -band 0xFFFFFFFF)
        }
        return [int]((-bnot $v20) -band 0x3FF)
    }

    static [byte[]] EncodeBinaryKey([string]$CdKey) {
        $Alphabet = "BCDFGHJKMPQRTVWXY2346789"
        $RawKey = $CdKey.Replace("-", "").ToUpper()
        if ($RawKey.Length -ne 25) { throw "Key must be 25 characters." }

        $Digits = New-Object byte[] 25
        $isNKey_ = $false
        $digitCount = 0

        foreach ($char in $RawKey.ToCharArray()) {
            if ($char -eq 'N' -and -not $isNKey_) {
                $isNKey_ = $true
                for ($i = $digitCount; $i -gt 0; $i--) { $Digits[$i] = $Digits[$i-1] }
                $Digits[0] = [byte]$digitCount
                $digitCount++
                continue
            }
            $val = $Alphabet.IndexOf($char)
            if ($val -lt 0) { throw "Invalid character in key: $char" }
            $Digits[$digitCount] = [byte]$val
            $digitCount++
        }

        $Binary = New-Object byte[] 16
        foreach ($digit in $Digits) {
            $carry = [uint32]$digit
            for ($i = 0; $i -lt 16; $i++) {
                $res = ($Binary[$i] * 24) + $carry
                $Binary[$i] = [byte]($res -band 0xFF)
                $carry = $res -shr 8
            }
        }
        if ($isNKey_) { $Binary[14] = $Binary[14] -bor 0x08 }
        return $Binary
    }

    static [PSCustomObject] UnpackBinaryKey([byte[]]$BinaryData, [bool]$Stream = $true) {
        $TempBytes = $BinaryData[0..15] + [byte]0
        $Value = [bigint]::new($TempBytes)
        return [PSCustomObject][Ordered]@{
            Group    = [uint16]($Value -band 0xFFFF)
            Serial   = [uint32](($Value -shr 20) -band 0x3FFFFFFF)
            Security = [uint64](($Value -shr 50) -band 0x1FFFFFFFFFFFFF)
            IsNKey   = (($Value -shr 115) -band 1) -eq 1
            Checksum = [BinaryKey]::GetKeyChecksum($BinaryData)
        }
    }
}
#endregion
#region Helpers
function New-PkeyIndex {
    <#
    .SYNOPSIS
        Scans a folder of pkeyconfig files and writes an index.
        Defaults to JSON format (calls New-PkeyIndex-JS), but supports CSV via -Format.
    .EXAMPLE
        New-PkeyIndex C:\PKeyConfigs                     # -> defaults to JSON
        New-PkeyIndex C:\PKeyConfigs -Format CSV         # -> calls CSV function
        New-PkeyIndex C:\PKeyConfigs -Gzip               # -> JSON with Gzip
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)][string]$Path,
        [switch]$NoRecurse,
        [string[]]$Include = @('*.xrm-ms', '*.xml'),
        [ValidateSet('JSON', 'CSV')]
        [string]$Format = 'JSON',
        [string]$Out,
        [string]$BinksOut,
        [string]$RangesOut,
        [switch]$Gzip
    )

    if ($Format -eq 'CSV') {
        # Forward parameters to your CSV function
        $csvParams = @{ Path = $Path }
        if ($NoRecurse) { $csvParams['NoRecurse'] = $true }
        if ($PSBoundParameters.ContainsKey('Include')) { $csvParams['Include'] = $Include }
        if ($BinksOut) { $csvParams['BinksOut'] = $BinksOut }
        if ($RangesOut) { $csvParams['RangesOut'] = $RangesOut }

        New-PkeyIndex-CSV @csvParams
    } 
    else {
        # Forward parameters to your JSON function (Default)
        $jsParams = @{ Path = $Path }
        if ($NoRecurse) { $jsParams['NoRecurse'] = $true }
        if ($PSBoundParameters.ContainsKey('Include')) { $jsParams['Include'] = $Include }
        if ($Out) { $jsParams['Out'] = $Out }
        if ($Gzip) { $jsParams['Gzip'] = $true }

        New-PkeyIndex-JS @jsParams
    }
}
function New-PkeyIndex-CSV {
    <#
    .SYNOPSIS
        Scans a folder of pkeyconfig files and writes TWO csv files into it:
          binks.csv   GroupId, Bink, Files      (file(s) holding bink + range)
          ranges.csv  Group, Start, End, File    (ONE ROW PER KEY RANGE)
        One pass: each file is parsed once. Self-contained.
        Windows PowerShell 5.1+ (Windows 7 SP1+).
    .EXAMPLE
        New-PkeyIndex C:\PKeyConfigs                 # -> binks.csv + ranges.csv
        New-PkeyIndex C:\PKeyConfigs -NoRecurse
        New-PkeyIndex C:\PKeyConfigs -BinksOut D:\b.csv -RangesOut D:\r.csv
    .DESCRIPTION
        binks.csv: a group is written only when ONE file holds its Bink, a
        configuration pointing to it and a key range for that configuration.
        Each GroupId appears once (first file wins). Lets Get-PkeyBinkLists
        build the batched lists for VerifyBinks.

        ranges.csv: every msft2005 key range, with its serial bounds and the
        file it lives in. Resolve a validated key with ONE lookup, no loop:
            Group = g AND Start <= serial <= End  ->  row.File
        Ranges may live in files that don't hold the bink, so a group can have
        range rows across several files. Identical (Group,Start,End) ranges are
        written once (first file kept).

        Paths are relative to each csv's folder, so the folder can be moved.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)][string]$Path,
        [switch]$NoRecurse,
        [string[]]$Include = @('*.xrm-ms', '*.xml'),
        [string]$BinksOut,
        [string]$RangesOut
    )
    $ErrorActionPreference = 'Stop'
    Set-StrictMode -Version 2.0
    $Algo2005 = 'msft:rm/algorithm/pkey/2005'

    # ------------------------------------------------------------ helpers ---
    function Get-ChildText($Node, [string]$Name) {
        $n = $Node.SelectSingleNode("*[local-name()='$Name']")
        if ($null -eq $n) { return $null }
        $n.InnerText.Trim()
    }
    function ConvertFrom-ConfigBytes([byte[]]$Bytes) {
        if ($Bytes.Length -ge 2 -and $Bytes[0] -eq 0xFF -and $Bytes[1] -eq 0xFE) { return [Text.Encoding]::Unicode.GetString($Bytes, 2, $Bytes.Length - 2) }
        if ($Bytes.Length -ge 3 -and $Bytes[0] -eq 0xEF -and $Bytes[1] -eq 0xBB -and $Bytes[2] -eq 0xBF) { return [Text.Encoding]::UTF8.GetString($Bytes, 3, $Bytes.Length - 3) }
        if ($Bytes.Length -ge 2 -and $Bytes[1] -eq 0) { return [Text.Encoding]::Unicode.GetString($Bytes) }
        [Text.Encoding]::UTF8.GetString($Bytes)
    }
    function New-XmlDoc { $d = New-Object System.Xml.XmlDocument; $d.XmlResolver = $null; ,$d }
    function Read-PkeyDoc([string]$File) {
        $doc = New-XmlDoc
        try { $doc.Load($File) } catch { Write-Verbose "Skip (not XML): $File"; return $null }
        if ($doc.DocumentElement.LocalName -eq 'ProductKeyConfiguration') { return ,$doc }
        $bin = $doc.SelectSingleNode("//*[local-name()='infoBin' and @name='pkeyConfigData']")
        if ($null -eq $bin) { Write-Verbose "Skip (no pkeyConfigData): $File"; return $null }
        try {
            $bytes = [Convert]::FromBase64String(($bin.InnerText -replace '\s', ''))
            $text  = (ConvertFrom-ConfigBytes $bytes).TrimStart([char]0xFEFF)
            $inner = New-XmlDoc; $inner.LoadXml($text)
        } catch { Write-Warning "Cannot decode pkeyConfigData in $File : $($_.Exception.Message)"; return $null }
        if ($inner.DocumentElement.LocalName -ne 'ProductKeyConfiguration') { Write-Verbose "Skip (unexpected root): $File"; return $null }
        ,$inner
    }

    # one file -> { Binks = @{group=base64}; Ranges = @( {Group;Start;End} ) }
    function Get-FileData($Doc) {
        $binks = @{}
        foreach ($pk in $Doc.SelectNodes("//*[local-name()='PublicKeys']/*[local-name()='PublicKey']")) {
            if ((Get-ChildText $pk 'AlgorithmId') -ne $Algo2005) { continue }
            $gid = 0
            if (-not [int]::TryParse((Get-ChildText $pk 'GroupId'), [ref]$gid)) { continue }
            if (-not $binks.ContainsKey($gid)) { $binks[$gid] = (Get-ChildText $pk 'PublicKeyValue') -replace '\s', '' }
        }
        # config id -> group id
        $cfgGroup = @{}
        foreach ($c in $Doc.SelectNodes("//*[local-name()='Configurations']/*[local-name()='Configuration']")) {
            $id = Get-ChildText $c 'ActConfigId'
            if ([string]::IsNullOrEmpty($id)) { continue }
            $gid = 0
            if ([int]::TryParse((Get-ChildText $c 'RefGroupId'), [ref]$gid)) { $cfgGroup[$id] = $gid }
        }
        # one record per KeyRange
        $ranges = New-Object System.Collections.ArrayList
        foreach ($r in $Doc.SelectNodes("//*[local-name()='KeyRanges']/*[local-name()='KeyRange']")) {
            $id = Get-ChildText $r 'RefActConfigId'
            if (-not $id -or -not $cfgGroup.ContainsKey($id)) { continue }
            $s = [long]0; $e = [long]0
            if (-not [long]::TryParse((Get-ChildText $r 'Start'), [ref]$s)) { continue }
            if (-not [long]::TryParse((Get-ChildText $r 'End'),   [ref]$e)) { continue }
            [void]$ranges.Add([pscustomobject]@{ Group = $cfgGroup[$id]; Start = $s; End = $e })
        }
        [pscustomobject]@{ Binks = $binks; Ranges = $ranges }
    }

    function ConvertTo-RelPath([string]$FullPath, [string]$BaseDir) {
        $base = $BaseDir.TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
        if ($FullPath.StartsWith($base, [StringComparison]::OrdinalIgnoreCase)) { return $FullPath.Substring($base.Length) }
        $FullPath
    }

    # -------------------------------------------------------------- scan ---
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) { throw "Folder not found: $Path" }
    $files = @(Get-ChildItem -LiteralPath $Path -Recurse:(-not $NoRecurse) -Force |
               Where-Object { if ($_.PSIsContainer) { return $false }; foreach ($p in $Include) { if ($_.Name -like $p) { return $true } }; $false } |
               Sort-Object FullName)

    if (-not $BinksOut)  { $BinksOut  = Join-Path $Path 'binks.csv' }
    if (-not $RangesOut) { $RangesOut = Join-Path $Path 'ranges.csv' }
    $binksFull  = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($BinksOut)
    $rangesFull = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($RangesOut)
    $binksDir   = [IO.Path]::GetDirectoryName($binksFull)
    $rangesDir  = [IO.Path]::GetDirectoryName($rangesFull)

    $binkIndex = @{}                          # group -> @{ Bink; Files(ArrayList) }
    $rangeRows = New-Object System.Collections.ArrayList
    $seenRange = @{}                          # "group|start|end" -> $true
    $used = 0; $ignored = 0

    foreach ($f in $files) {
        $doc = Read-PkeyDoc $f.FullName
        if ($null -eq $doc) { $ignored++; continue }
        $data = Get-FileData $doc
        $relRange = ConvertTo-RelPath $f.FullName $rangesDir

        # ranges: one row per unique (group,start,end), remembering the file
        $groupsWithRange = @{}
        foreach ($r in $data.Ranges) {
            $groupsWithRange[$r.Group] = $true
            $key = '{0}|{1}|{2}' -f $r.Group, $r.Start, $r.End
            if ($seenRange.ContainsKey($key)) { continue }
            $seenRange[$key] = $true
            [void]$rangeRows.Add([pscustomobject]@{ Group = $r.Group; Start = $r.Start; End = $r.End; File = $relRange })
        }

        # binks: a group counts only when its bink AND a range are both here
        $complete = @($data.Binks.Keys | Where-Object { $groupsWithRange.ContainsKey($_) } | Sort-Object)
        if ($complete.Count -eq 0) { Write-Verbose "No complete group (bink + range) in: $($f.FullName)"; $ignored++; continue }
        $used++
        foreach ($gid in $complete) {
            if (-not $binkIndex.ContainsKey($gid)) { $binkIndex[$gid] = @{ Bink = $data.Binks[$gid]; Files = (New-Object System.Collections.ArrayList) } }
            elseif ($binkIndex[$gid].Bink -ne $data.Binks[$gid]) { Write-Warning "Group $gid : different Bink in $($f.FullName); keeping the first, file not listed"; continue }
            [void]$binkIndex[$gid].Files.Add((ConvertTo-RelPath $f.FullName $binksDir))
        }
    }

    # -------------------------------------------------------------- binks.csv ---
    $groups = @($binkIndex.Keys | Sort-Object)
    $binkRows = @(foreach ($gid in $groups) { [pscustomobject]@{ GroupId = $gid; Bink = $binkIndex[$gid].Bink; Files = ($binkIndex[$gid].Files -join '|') } })
    if ($binkRows.Count -gt 0) { $binkRows | Export-Csv -LiteralPath $binksFull -NoTypeInformation -Encoding UTF8 }
    else { [IO.File]::WriteAllText($binksFull, '"GroupId","Bink","Files"' + [Environment]::NewLine, (New-Object System.Text.UTF8Encoding($true))); Write-Warning "No complete msft2005 group found in $Path (empty binks.csv written)" }
    Write-Host "Binks index written:  $binksFull ($($binkRows.Count) groups)"

    # -------------------------------------------------------------- ranges.csv ---
    $outRanges = @($rangeRows | Sort-Object Group, Start)
    if ($outRanges.Count -gt 0) { $outRanges | Export-Csv -LiteralPath $rangesFull -NoTypeInformation -Encoding UTF8 }
    else { [IO.File]::WriteAllText($rangesFull, '"Group","Start","End","File"' + [Environment]::NewLine, (New-Object System.Text.UTF8Encoding($true))); Write-Warning "No msft2005 ranges found in $Path" }
    $groupsCovered = @($outRanges | Group-Object Group).Count
    Write-Host "Range index written:  $rangesFull ($($outRanges.Count) ranges over $groupsCovered groups)"
}
function New-PkeyIndex-JS {
    <#
    .SYNOPSIS
        Scans a folder of pkeyconfig files and writes ONE json index into it
        (replaces binks.csv + ranges.csv). One pass: each file is parsed once.
        Self-contained. Windows PowerShell 5.1+ (Windows 7 SP1+).
    .EXAMPLE
        New-PkeyIndex C:\PKeyConfigs                 # -> pkeyindex.json
        New-PkeyIndex C:\PKeyConfigs -Gzip           # -> pkeyindex.json.gz
        New-PkeyIndex C:\PKeyConfigs -NoRecurse -Out D:\index.json
    .DESCRIPTION
        Layout (one line per group):
          { "version": 1,
            "files":  [ "rel\path\a.xrm-ms", ... ],          <- every path once
            "groups": {
              "140": { "bink": "<base64>",                   <- only if complete
                       "binkFiles": [3,7],                   <- indexes into files
                       "ranges": [[start,end,fileIndex], ...] } } }

        bink / binkFiles: same rule as the old binks.csv. A group gets them only
        when ONE file holds its Bink, a configuration pointing to it and a key
        range for that configuration. First Bink wins; a file with a different
        Bink for the same group is warned about and not listed.

        ranges: same rows as the old ranges.csv. Every key range with its
        serial bounds and the file it lives in, sorted by Start. Identical
        (group,start,end) ranges are written once (first file kept). A group
        with ranges but no complete Bink has only "ranges".

        Paths are relative to the json's folder, so the folder can be moved.
        Load with Import-PkeyIndex, resolve a key with Find-PkeyFile.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)][string]$Path,
        [switch]$NoRecurse,
        [string[]]$Include = @('*.xrm-ms', '*.xml'),
        [string]$Out,
        [switch]$Gzip
    )
    $ErrorActionPreference = 'Stop'
    Set-StrictMode -Version 2.0
    $Algo2005 = 'msft:rm/algorithm/pkey/2005'

    # ------------------------------------------------------------ helpers ---
    function Get-ChildText($Node, [string]$Name) {
        $n = $Node.SelectSingleNode("*[local-name()='$Name']")
        if ($null -eq $n) { return $null }
        $n.InnerText.Trim()
    }
    function ConvertFrom-ConfigBytes([byte[]]$Bytes) {
        if ($Bytes.Length -ge 2 -and $Bytes[0] -eq 0xFF -and $Bytes[1] -eq 0xFE) { return [Text.Encoding]::Unicode.GetString($Bytes, 2, $Bytes.Length - 2) }
        if ($Bytes.Length -ge 3 -and $Bytes[0] -eq 0xEF -and $Bytes[1] -eq 0xBB -and $Bytes[2] -eq 0xBF) { return [Text.Encoding]::UTF8.GetString($Bytes, 3, $Bytes.Length - 3) }
        if ($Bytes.Length -ge 2 -and $Bytes[1] -eq 0) { return [Text.Encoding]::Unicode.GetString($Bytes) }
        [Text.Encoding]::UTF8.GetString($Bytes)
    }
    function New-XmlDoc { $d = New-Object System.Xml.XmlDocument; $d.XmlResolver = $null; ,$d }
    function Read-PkeyDoc([string]$File) {
        $doc = New-XmlDoc
        try { $doc.Load($File) } catch { Write-Verbose "Skip (not XML): $File"; return $null }
        if ($doc.DocumentElement.LocalName -eq 'ProductKeyConfiguration') { return ,$doc }
        $bin = $doc.SelectSingleNode("//*[local-name()='infoBin' and @name='pkeyConfigData']")
        if ($null -eq $bin) { Write-Verbose "Skip (no pkeyConfigData): $File"; return $null }
        try {
            $bytes = [Convert]::FromBase64String(($bin.InnerText -replace '\s', ''))
            $text  = (ConvertFrom-ConfigBytes $bytes).TrimStart([char]0xFEFF)
            $inner = New-XmlDoc; $inner.LoadXml($text)
        } catch { Write-Warning "Cannot decode pkeyConfigData in $File : $($_.Exception.Message)"; return $null }
        if ($inner.DocumentElement.LocalName -ne 'ProductKeyConfiguration') { Write-Verbose "Skip (unexpected root): $File"; return $null }
        ,$inner
    }

    # one file -> { Binks = @{group=base64}; Ranges = @( {Group;Start;End} ) }
    function Get-FileData($Doc) {
        $binks = @{}
        foreach ($pk in $Doc.SelectNodes("//*[local-name()='PublicKeys']/*[local-name()='PublicKey']")) {
            if ((Get-ChildText $pk 'AlgorithmId') -ne $Algo2005) { continue }
            $gid = 0
            if (-not [int]::TryParse((Get-ChildText $pk 'GroupId'), [ref]$gid)) { continue }
            if (-not $binks.ContainsKey($gid)) { $binks[$gid] = (Get-ChildText $pk 'PublicKeyValue') -replace '\s', '' }
        }
        # config id -> group id
        $cfgGroup = @{}
        foreach ($c in $Doc.SelectNodes("//*[local-name()='Configurations']/*[local-name()='Configuration']")) {
            $id = Get-ChildText $c 'ActConfigId'
            if ([string]::IsNullOrEmpty($id)) { continue }
            $gid = 0
            if ([int]::TryParse((Get-ChildText $c 'RefGroupId'), [ref]$gid)) { $cfgGroup[$id] = $gid }
        }
        # one record per KeyRange
        $ranges = New-Object System.Collections.ArrayList
        foreach ($r in $Doc.SelectNodes("//*[local-name()='KeyRanges']/*[local-name()='KeyRange']")) {
            $id = Get-ChildText $r 'RefActConfigId'
            if (-not $id -or -not $cfgGroup.ContainsKey($id)) { continue }
            $s = [long]0; $e = [long]0
            if (-not [long]::TryParse((Get-ChildText $r 'Start'), [ref]$s)) { continue }
            if (-not [long]::TryParse((Get-ChildText $r 'End'),   [ref]$e)) { continue }
            [void]$ranges.Add([pscustomobject]@{ Group = $cfgGroup[$id]; Start = $s; End = $e })
        }
        [pscustomobject]@{ Binks = $binks; Ranges = $ranges }
    }

    function ConvertTo-RelPath([string]$FullPath, [string]$BaseDir) {
        $base = $BaseDir.TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
        if ($FullPath.StartsWith($base, [StringComparison]::OrdinalIgnoreCase)) { return $FullPath.Substring($base.Length) }
        $FullPath
    }

    # json string literal: quotes, backslashes and control characters escaped
    function ConvertTo-JsonText([string]$Text) {
        $sb = New-Object System.Text.StringBuilder
        [void]$sb.Append('"')
        foreach ($ch in $Text.ToCharArray()) {
            if     ($ch -eq [char]'"')  { [void]$sb.Append('\"') }
            elseif ($ch -eq [char]'\')  { [void]$sb.Append('\\') }
            elseif ([int]$ch -lt 0x20)  { [void]$sb.Append('\u' + ([int]$ch).ToString('x4')) }
            else                        { [void]$sb.Append($ch) }
        }
        [void]$sb.Append('"')
        $sb.ToString()
    }

    # -------------------------------------------------------------- scan ---
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) { throw "Folder not found: $Path" }
    $files = @(Get-ChildItem -LiteralPath $Path -Recurse:(-not $NoRecurse) -Force |
               Where-Object { if ($_.PSIsContainer) { return $false }; foreach ($p in $Include) { if ($_.Name -like $p) { return $true } }; $false } |
               Sort-Object FullName)

    if (-not $Out) { $Out = Join-Path $Path $(if ($Gzip) { 'pkeyindex.json.gz' } else { 'pkeyindex.json' }) }
    $outFull = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Out)
    $outDir  = [IO.Path]::GetDirectoryName($outFull)

    $fileList  = New-Object System.Collections.ArrayList   # index -> relative path
    $fileIds   = @{}                                        # relative path -> index
    $groups    = @{}                                        # group -> @{ Bink; BinkFiles; Ranges }
    $seenRange = @{}                                        # "group|start|end" -> $true
    $used = 0; $ignored = 0; $rangeCount = 0

    foreach ($f in $files) {
        $doc = Read-PkeyDoc $f.FullName
        if ($null -eq $doc) { $ignored++; continue }
        $data = Get-FileData $doc
        $rel  = ConvertTo-RelPath $f.FullName $outDir
        $fid  = -1                                          # assigned on first use

        # ranges: one entry per unique (group,start,end), remembering the file
        $groupsWithRange = @{}
        foreach ($r in $data.Ranges) {
            $groupsWithRange[$r.Group] = $true
            $key = '{0}|{1}|{2}' -f $r.Group, $r.Start, $r.End
            if ($seenRange.ContainsKey($key)) { continue }
            $seenRange[$key] = $true
            if ($fid -lt 0) { if (-not $fileIds.ContainsKey($rel)) { $fileIds[$rel] = $fileList.Add($rel) }; $fid = $fileIds[$rel] }
            if (-not $groups.ContainsKey($r.Group)) { $groups[$r.Group] = @{ Bink = $null; BinkFiles = (New-Object System.Collections.ArrayList); Ranges = (New-Object System.Collections.ArrayList) } }
            [void]$groups[$r.Group].Ranges.Add([pscustomobject]@{ Start = $r.Start; End = $r.End; File = $fid })
            $rangeCount++
        }

        # binks: a group counts only when its bink AND a range are both here
        $complete = @($data.Binks.Keys | Where-Object { $groupsWithRange.ContainsKey($_) } | Sort-Object)
        if ($complete.Count -eq 0) { Write-Verbose "No complete group (bink + range) in: $($f.FullName)"; $ignored++; continue }
        $used++
        foreach ($gid in $complete) {
            $g = $groups[$gid]                              # exists: the group has a range in this run
            if ($null -eq $g.Bink) { $g.Bink = $data.Binks[$gid] }
            elseif ($g.Bink -ne $data.Binks[$gid]) { Write-Warning "Group $gid : different Bink in $($f.FullName); keeping the first, file not listed"; continue }
            if ($fid -lt 0) { if (-not $fileIds.ContainsKey($rel)) { $fileIds[$rel] = $fileList.Add($rel) }; $fid = $fileIds[$rel] }
            [void]$g.BinkFiles.Add($fid)
        }
    }

    # -------------------------------------------------------------- write ---
    $nl = "`n"
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('{"version":1,').Append($nl).Append('"files":[')
    for ($i = 0; $i -lt $fileList.Count; $i++) {
        if ($i) { [void]$sb.Append(',') }
        [void]$sb.Append($nl).Append((ConvertTo-JsonText $fileList[$i]))
    }
    [void]$sb.Append($nl).Append('],').Append($nl).Append('"groups":{')
    $first = $true; $binkCount = 0
    foreach ($gid in @($groups.Keys | Sort-Object)) {
        $g = $groups[$gid]
        if (-not $first) { [void]$sb.Append(',') }
        $first = $false
        [void]$sb.Append($nl).Append('"').Append($gid).Append('":{')
        if ($null -ne $g.Bink) {
            $binkCount++
            [void]$sb.Append('"bink":').Append((ConvertTo-JsonText $g.Bink)).Append(',"binkFiles":[').Append(($g.BinkFiles -join ',')).Append('],')
        }
        [void]$sb.Append('"ranges":[')
        $sep = ''
        foreach ($r in @($g.Ranges | Sort-Object Start, End)) {
            [void]$sb.Append($sep).Append('[').Append($r.Start).Append(',').Append($r.End).Append(',').Append($r.File).Append(']')
            $sep = ','
        }
        [void]$sb.Append(']}')
    }
    [void]$sb.Append($nl).Append('}}').Append($nl)

    $bytes = (New-Object System.Text.UTF8Encoding($false)).GetBytes($sb.ToString())
    if ($Gzip) {
        $ms = New-Object System.IO.MemoryStream
        $gz = New-Object System.IO.Compression.GZipStream($ms, [System.IO.Compression.CompressionMode]::Compress)
        $gz.Write($bytes, 0, $bytes.Length); $gz.Close()
        $bytes = $ms.ToArray()
    }
    [IO.File]::WriteAllBytes($outFull, $bytes)

    if ($binkCount -eq 0) { Write-Warning "No complete msft2005 group found in $Path" }
    if ($rangeCount -eq 0) { Write-Warning "No key ranges found in $Path" }
    Write-Host "Index written: $outFull ($binkCount groups with Bink, $rangeCount ranges over $($groups.Count) groups, $($fileList.Count) files, $($bytes.Length) bytes)"
}
function Import-PkeyIndex {
    <#
    .SYNOPSIS
        Loads pkeyindex.json (or .json.gz, detected by content) once per session.
    .EXAMPLE
        $db = Import-PkeyIndex C:\PKeyConfigs\pkeyindex.json
        $db.groups['140'].bink                    # base64 Bink ($null if none)
        $db.groups['140'].ranges.Count
        Find-PkeyFile $db 140 123456789           # full path(s) of the file
    .DESCRIPTION
        Returns nested dictionaries/arrays exactly as stored, plus 'baseDir'
        (the json's folder) so relative paths can be resolved.
        Uses JavaScriptSerializer directly: no 2 MB limit, no PSCustomObjects.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true, Position = 0)][string]$Path)
    $full  = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
    $bytes = [IO.File]::ReadAllBytes($full)
    if ($bytes.Length -ge 2 -and $bytes[0] -eq 0x1F -and $bytes[1] -eq 0x8B) {
        $in  = New-Object System.IO.MemoryStream(, $bytes)
        $gz  = New-Object System.IO.Compression.GZipStream($in, [System.IO.Compression.CompressionMode]::Decompress)
        $out = New-Object System.IO.MemoryStream
        $buf = New-Object byte[] 65536
        while (($n = $gz.Read($buf, 0, $buf.Length)) -gt 0) { $out.Write($buf, 0, $n) }
        $gz.Close()
        $bytes = $out.ToArray()
    }
    $text = [Text.Encoding]::UTF8.GetString($bytes).TrimStart([char]0xFEFF)
    if ($PSVersionTable.PSVersion.Major -ge 6) {
        $db = ConvertFrom-Json -InputObject $text -AsHashtable        # PowerShell 7
    } else {
        Add-Type -AssemblyName System.Web.Extensions                  # Windows PowerShell
        $ser = New-Object System.Web.Script.Serialization.JavaScriptSerializer
        $ser.MaxJsonLength = [int]::MaxValue
        $db = $ser.DeserializeObject($text)
    }
    $db['baseDir'] = [IO.Path]::GetDirectoryName($full)
    , $db
}
function Find-PkeyFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]$Index,
        [Parameter(Mandatory = $true, Position = 1)][int]$Group,
        [Parameter(Mandatory = $true, Position = 2)][long]$Serial
    )
    $g = [string]$Group
    if (-not $Index['groups'].ContainsKey($g)) { return }
    foreach ($r in $Index['groups'][$g]['ranges']) {
        if ($r[0] -gt $Serial) { break }                    # sorted by Start
        if ($Serial -gt $r[1]) { continue }
        $rel = $Index['files'][$r[2]]
        [pscustomobject][ordered]@{
            Group = $Group
            Start = [long]$r[0]
            End   = [long]$r[1]
            File  = $rel
            Path  = Join-Path $Index['baseDir'] $rel
        }
    }
}
function Get-PkeyBinkLists {
    <#
    .SYNOPSIS
        Packs msft:rm/algorithm/pkey/2005 public keys into the two lists that
        VerifyBinks takes.
 
    .DESCRIPTION
        -ConfigPath can be:
          * pkeyindex.json / pkeyindex.json.gz written by New-PkeyIndex
          * a folder: its pkeyindex.json is used, else pkeyindex.json.gz,
            else the old binks.csv
          * a .csv with a Group (or GroupId) column and a Bink column (base64),
            e.g. the old binks.csv
          * a pkeyconfig .xrm-ms licence (or a decoded pkeyconfig .xml)
 
        -Index takes an index already loaded with Import-PkeyIndex, so the
        json is not read again.
 
        Both lists share one 8-byte header, followed by the items:
            uint32 Type         1 = group ids, 2 = binks
            uint32 TotalLength  whole list in bytes, header included
            items               Type 1: int32 group ids
                                Type 2: the binks back to back, all one size
 
        Each group is packed once (first one wins), sorted by group id.
        Binks whose size differs from the first are skipped with a warning,
        because the bink list carries no per-item length.
 
        Needs Import-PkeyIndex (same file) for the json sources.
 
    .PARAMETER GroupId
        Optional: pack only these groups.
 
    .EXAMPLE
        $l = Get-PkeyBinkLists C:\PKeyConfigs                 # folder -> pkeyindex.json
        $l = Get-PkeyBinkLists C:\PKeyConfigs\pkeyindex.json.gz
        $l = Get-PkeyBinkLists -Index $db                     # already loaded
        $l = Get-PkeyBinkLists -Index $db -GroupId 172,176
        $l = Get-PkeyBinkLists C:\PKeyConfigs\binks.csv       # old format still works
        $l = Get-PkeyBinkLists C:\...\pkeyconfig.xrm-ms
        # $l.GroupList, $l.BinkList -> byte[] for VerifyBinks
    #>
    [CmdletBinding(DefaultParameterSetName = 'Path')]
    param(
        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = 'Path')][string]$ConfigPath,
        [Parameter(Mandatory = $true, ParameterSetName = 'Index')]$Index,
        [int[]]$GroupId
    )
    $ErrorActionPreference = 'Stop'
 
    $full = $null
    if ($PSCmdlet.ParameterSetName -eq 'Path') {
        $full = $PSCmdlet.GetUnresolvedProviderPathFromPSPath($ConfigPath)
        if (Test-Path -LiteralPath $full -PathType Container) {
            $dir = $full
            $full = Join-Path $dir 'binks.csv'
            foreach ($name in 'pkeyindex.json', 'pkeyindex.json.gz', 'binks.csv') {
                $candidate = Join-Path $dir $name
                if (Test-Path -LiteralPath $candidate -PathType Leaf) { $full = $candidate; break }
            }
            if (-not (Test-Path -LiteralPath $full -PathType Leaf)) {
                throw "No pkeyindex.json, pkeyindex.json.gz or binks.csv in: $dir"
            }
        }
        if (-not (Test-Path -LiteralPath $full -PathType Leaf)) {
            throw "File not found: $full"
        }
        if ($full -match '\.json(\.gz)?$') { $Index = Import-PkeyIndex $full }
    }
    $source = if ($full) { $full } else { 'the loaded index' }
 
    # --- 1. read (Group, Bink-bytes) pairs from the source ------------------
    $entries = New-Object System.Collections.ArrayList
 
    if ($null -ne $Index) {
        # json index: groups without a complete Bink have no 'bink' key
        $all = $Index['groups']
        foreach ($k in $all.Keys) {
            $g = $all[$k]
            if (-not $g.ContainsKey('bink')) { continue }
            [void]$entries.Add([pscustomobject]@{
                Group = [int]$k
                Bink  = [Convert]::FromBase64String($g['bink'])
            })
        }
    }
    elseif ([IO.Path]::GetExtension($full) -ieq '.csv') {
        $rows = [IO.File]::ReadAllText($full, [Text.Encoding]::UTF8) | ConvertFrom-Csv
        foreach ($row in $rows) {
            $names = $row.PSObject.Properties.Name
            $g = if ($names -contains 'Group') { $row.Group } else { $row.GroupId }
            if ([string]::IsNullOrEmpty($g) -or [string]::IsNullOrEmpty($row.Bink)) {
                Write-Warning "CSV row skipped: missing Group/GroupId or Bink"; continue
            }
            [void]$entries.Add([pscustomobject]@{
                Group = [int]$g
                Bink  = [Convert]::FromBase64String(($row.Bink -replace '\s', ''))
            })
        }
    }
    else {
        # outer licence XML -> inner pkeyconfig XML, or an already-decoded XML
        $outer = New-Object System.Xml.XmlDocument
        $outer.XmlResolver = $null
        $outer.Load($full)
 
        if ($outer.DocumentElement.LocalName -eq 'ProductKeyConfiguration') {
            $pkey = $outer
        }
        else {
            $bin = $outer.SelectSingleNode("//*[local-name()='infoBin'][@name='pkeyConfigData']")
            if ($null -eq $bin) { throw "No pkeyConfigData in $full" }
            $innerBytes = [Convert]::FromBase64String(($bin.InnerText -replace '\s', ''))
            $isUtf16 = $innerBytes.Length -gt 2 -and (
                $innerBytes[1] -eq 0 -or ($innerBytes[0] -eq 0xFF -and $innerBytes[1] -eq 0xFE))
            $innerText = if ($isUtf16) { [Text.Encoding]::Unicode.GetString($innerBytes) }
                         else          { [Text.Encoding]::UTF8.GetString($innerBytes) }
            $pkey = New-Object System.Xml.XmlDocument
            $pkey.XmlResolver = $null
            $pkey.LoadXml($innerText.TrimStart([char]0xFEFF))
        }
 
        foreach ($pk in $pkey.SelectNodes("//*[local-name()='PublicKeys']/*[local-name()='PublicKey']")) {
            $alg = $pk.SelectSingleNode("*[local-name()='AlgorithmId']").InnerText
            if ($alg -notlike '*pkey/2005') { continue }
            $gid  = [int]$pk.SelectSingleNode("*[local-name()='GroupId']").InnerText
            $bink = [Convert]::FromBase64String(
                        ($pk.SelectSingleNode("*[local-name()='PublicKeyValue']").InnerText -replace '\s', ''))
            [void]$entries.Add([pscustomobject]@{ Group = $gid; Bink = $bink })
        }
    }
 
    # --- 2. filter, de-duplicate, sort --------------------------------------
    $seen   = @{}
    $picked = New-Object System.Collections.ArrayList
    $filter = $PSBoundParameters.ContainsKey('GroupId')     # not "if ($GroupId)": -GroupId 0 is falsy
    foreach ($e in ($entries | Sort-Object Group)) {
        if ($filter -and ($GroupId -notcontains $e.Group)) { continue }
        if ($seen.ContainsKey($e.Group)) { continue }
        $seen[$e.Group] = $true
        [void]$picked.Add($e)
    }
 
    # keep only binks that match the first one's size
    $binkSize = 0
    $final = New-Object System.Collections.ArrayList
    foreach ($e in $picked) {
        if ($final.Count -eq 0) { $binkSize = $e.Bink.Length }
        if ($e.Bink.Length -ne $binkSize) {
            Write-Warning "Group $($e.Group) skipped: bink is $($e.Bink.Length) bytes, expected $binkSize."
            continue
        }
        [void]$final.Add($e)
    }
    if ($final.Count -eq 0) { throw "No usable msft2005 binks found in $source" }
 
    # --- 3. build the two byte lists ----------------------------------------
    $groupItems = New-Object System.IO.MemoryStream
    $binkItems  = New-Object System.IO.MemoryStream
    foreach ($e in $final) {
        $gb = [BitConverter]::GetBytes([int32]$e.Group)
        $groupItems.Write($gb, 0, 4)
        $binkItems.Write($e.Bink, 0, $e.Bink.Length)
    }
 
    $NewList = {
        param([uint32]$Type, [byte[]]$data)
        $list = New-Object byte[] (8 + $data.Length)
        [BitConverter]::GetBytes([uint32]$Type).CopyTo($list, 0)
        [BitConverter]::GetBytes([uint32]$list.Length).CopyTo($list, 4)
        [Array]::Copy($data, 0, $list, 8, $data.Length)
        , $list
    }
 
    [pscustomobject]@{
        GroupList = [byte[]](& $NewList 1 $groupItems.ToArray())
        BinkList  = [byte[]](& $NewList 2 $binkItems.ToArray())
        Count     = $final.Count
        BinkSize  = $binkSize
    }
}
function ConvertTo-PkeyBinkArrays {
    param([Parameter(Mandatory)]$Lists)   # output of Get-PkeyBinkLists
    $n = [int]$Lists.Count; $size = [int]$Lists.BinkSize
    $ids  = New-Object 'int[]' $n
    $keys = New-Object 'byte[][]' $n
    for ($i = 0; $i -lt $n; $i++) {
        $ids[$i] = [BitConverter]::ToInt32($Lists.GroupList, 8 + 4 * $i)      # 8 = list header
        $k = New-Object 'byte[]' $size
        [Buffer]::BlockCopy($Lists.BinkList, 8 + $i * $size, $k, 0, $size)
        $keys[$i] = $k
    }
    [pscustomobject]@{ Ids = $ids; Keys = $keys }
}
function Get-PkeyBinkArrays {
    param([Parameter(Mandatory)][string]$ConfigPath)   # .xrm-ms, .xml, pkeyindex.json(.gz) or binks.csv
    ConvertTo-PkeyBinkArrays (Get-PkeyBinkLists -ConfigPath $ConfigPath)
}
#endregion
#region Lammos DLL
<#
# 32-bit execution path (PkeyLib32.dll)[cite: 5]
$key16   = [BinaryKey]::EncodeBinaryKey($CDKey)
$entries = Get-PublicKeys $Config
if ($entries.Count -eq 0) { throw 'No public keys found in the config.' }

$Fn = Connect-PidKeyData
if ($Threads -le 0) { $Threads = [Environment]::ProcessorCount }

$out = Search-Keys $Fn $entries $key16 $Threads
$success = $out.Valid
#>
function Connect-PidKeyData {
    param([string]$DllPath)
    if ([IntPtr]::Size -ne 4) { throw 'PkeyLib32.dll is 32-bit: use 32-bit PowerShell.' }
    if (-not $DllPath) { $DllPath = [IO.Path]::Combine($PSScriptRoot, 'PkeyLib32.dll') }
    if (-not [IO.Path]::IsPathRooted($DllPath)) { $DllPath = [IO.Path]::Combine($PSScriptRoot, $DllPath) }
    if (-not [IO.File]::Exists($DllPath)) { throw "DLL not found: $DllPath" }

    $dll = [Pk.K32]::LoadLibraryW($DllPath)
    if ($dll -eq [IntPtr]::Zero) { throw "LoadLibrary failed: $DllPath" }

    $mem = [Pk.K32]::VirtualAlloc([IntPtr]::Zero, [uint32]64, [uint32]0x3000, [uint32]0x40)
    if ($mem -eq [IntPtr]::Zero) { throw 'VirtualAlloc failed.' }

    $exports = @(
        @{ Name = 'PubkeyParser'; Type = [Pk.Fn4] }
        @{ Name = 'CalculateH1';  Type = [Pk.Fn6] }
        @{ Name = 'ExtractM';     Type = [Pk.Fn4] }
    )
    $fn = @{}
    for ($i = 0; $i -lt $exports.Count; $i++) {
        $target = [Pk.K32]::GetProcAddress($dll, $exports[$i].Name)
        if ($target -eq [IntPtr]::Zero) { throw "$($exports[$i].Name) is not exported." }
        [byte[]]$stub = (0x58, 0x59, 0x5A, 0x50, 0xB8) + [BitConverter]::GetBytes($target.ToInt32()) + (0xFF, 0xE0)
        $addr = [IntPtr]::Add($mem, 16 * $i)
        [Marshal]::Copy($stub, 0, $addr, $stub.Length)
        $fn[$exports[$i].Name] = [Marshal]::GetDelegateForFunctionPointer($addr, $exports[$i].Type)
    }
    $fn
}
function Get-PublicKeys([string]$configPath) {
    $outer = [IO.File]::ReadAllText($configPath)
    $i = $outer.IndexOf('pkeyConfigData'); if ($i -lt 0) { throw 'pkeyConfigData not found in config.' }
    $cs = $outer.IndexOf('>', $i) + 1
    $ce = $outer.IndexOf('</', $cs)
    $b64 = ($outer.Substring($cs, $ce - $cs) -replace '\s', '')
    $innerBytes = [Convert]::FromBase64String($b64)

    $xml = [System.Xml.XmlDocument]::new()
    $xml.Load([System.IO.MemoryStream]::new($innerBytes))

    $list = [System.Collections.Generic.List[object]]::new()
    foreach ($pk in $xml.GetElementsByTagName('PublicKey', '*')) {
        $kv = $pk.GetElementsByTagName('PublicKeyValue', '*')
        if ($kv.Count -eq 0) { continue }
        $gid = $pk.GetElementsByTagName('GroupId', '*')
        $groupId = if ($gid.Count) { $gid[0].InnerText } else { '' }
        $bytes = [Convert]::FromBase64String(($kv[0].InnerText -replace '\s', ''))
        if ($bytes.Length -eq 1579) { $list.Add([pscustomobject]@{ GroupId = $groupId; Bytes = $bytes }) }
    }
    $list
}
function Search-Keys($Fn, $entries, [byte[]]$key16, [int]$threads) {
    $total = $entries.Count
    if ($threads -lt 1) { $threads = 1 }
    if ($threads -gt $total) { $threads = $total }
    $sync = [hashtable]::Synchronized(@{ Found = $false; Result = $null })

    $worker = {
        param($Fn, $entries, $key16, $start, $end, $sync)
        $M = [Runtime.InteropServices.Marshal]
        $pMem = $M::AllocHGlobal(32); $pRet = $M::AllocHGlobal(20); $pValid = $M::AllocHGlobal(4)
        $pH1 = $M::AllocHGlobal(16); $pM = $M::AllocHGlobal(8); $pKey = $M::AllocHGlobal(16); $blob = $M::AllocHGlobal(1579)
        try {
            $M::Copy($key16, 0, $pKey, 16)
            for ($i = $start; $i -lt $end; $i++) {
                if ($sync.Found) { break }
                $e = $entries[$i]; $b = $e.Bytes
                $M::Copy([byte[]]::new(32), 0, $pMem, 32)
                $M::Copy([byte[]]::new(20), 0, $pRet, 20)
                $M::Copy([byte[]]::new(4), 0, $pValid, 4)
                $M::Copy($b, 0, $blob, $b.Length)

                if ($Fn.PubkeyParser.Invoke($pMem, $blob, [IntPtr]$b.Length, $pRet) -eq 0) { continue }
                $pData = $M::ReadIntPtr($pMem, 24)
                if ($pData -eq [IntPtr]::Zero) { continue }
                $bytes1 = [IntPtr]::Add($pData, 44); $bytes2 = [IntPtr]::Add($pData, 88)

                [void]$Fn.CalculateH1.Invoke($bytes1, $bytes2, $pKey, $pValid, $pH1, $pRet)
                if ($M::ReadByte($pValid, 0) -ne 1) { continue }

                $M::WriteInt32($pRet, 16, 1)
                [void]$Fn.ExtractM.Invoke($bytes1, $pH1, $pM, $pRet)
                $v = $M::ReadInt64($pM, 0)

                [System.Threading.Monitor]::Enter($sync)
                try {
                    if (-not $sync.Found) {
                        $sync.Found = $true
                        $sync.Result = [pscustomobject]@{
                            Valid    = $true
                            Upgrade  = [bool]($v -band 1)
                            Serial   = [uint32](($v -shr 1)  -band 0x3FFFFFFF)
                            Security = [uint32](($v -shr 31) -band 0x3FF)
                            GroupId  = $e.GroupId
                            Data     = [BitConverter]::GetBytes($v)
                        }
                    }
                } finally { [System.Threading.Monitor]::Exit($sync) }
                break
            }
        }
        finally {
            foreach ($p in $pMem, $pRet, $pValid, $pH1, $pM, $pKey, $blob) { $M::FreeHGlobal($p) }
        }
    }

    $iss  = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault2()
    $pool = [RunspaceFactory]::CreateRunspacePool(1, $threads, $iss, $Host)
    $pool.Open()
    try {
        $chunk = [Math]::Ceiling($total / $threads)
        $jobs = @()
        for ($t = 0; $t -lt $threads; $t++) {
            $s = $t * $chunk; $en = [Math]::Min($s + $chunk, $total)
            if ($s -ge $en) { continue }
            $ps = [PowerShell]::Create(); $ps.RunspacePool = $pool
            [void]$ps.AddScript($worker).
                AddArgument($Fn).AddArgument($entries).AddArgument($key16).
                AddArgument($s).AddArgument($en).AddArgument($sync)
            $jobs += [pscustomobject]@{ PS = $ps; Handle = $ps.BeginInvoke() }
        }
        foreach ($j in $jobs) { $j.PS.EndInvoke($j.Handle); $j.PS.Dispose() }
    }
    finally { $pool.Close(); $pool.Dispose() }

    if ($sync.Result) { $sync.Result }
    else { [pscustomobject]@{ Valid = $false; Upgrade = $null; Serial = $null; Security = $null; GroupId = $null } }
}
#endregion
#region Add-Type
# x86, x64, Arm x64 Block's
if ($Is32Bit) {
  Restore-Util
}
if (!([PSTypeName]'PkeyNative').Type) {
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

namespace Pk {
    public static class K32 {
        [DllImport("kernel32", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern IntPtr LoadLibraryW(string path);
        [DllImport("kernel32", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
        public static extern IntPtr GetProcAddress(IntPtr module, string name);
        [DllImport("kernel32", SetLastError = true)]
        public static extern IntPtr VirtualAlloc(IntPtr address, uint size, uint type, uint protect);
    }
    [UnmanagedFunctionPointer(CallingConvention.StdCall)] public delegate int Fn4(IntPtr a, IntPtr b, IntPtr c, IntPtr d);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)] public delegate int Fn6(IntPtr a, IntPtr b, IntPtr c, IntPtr d, IntPtr e, IntPtr f);
}

// Not tied to a PkeyLib build
public static class PkeyNative
{
    [DllImport("kernel32.dll")]
    public static extern ushort GetSystemDefaultLangID();
}

// One wrapper per DLL, the same three exports in each:
//   VerifyKey        key text + config path, always scans every group
//   VerifyBinaryKey  raw key + config bytes
//   VerifyBinks      raw key + group list + bink list
//                    Both lists start with: uint32 Type (1 = groups, 2 = binks),
//                    uint32 TotalLength (whole list, header included), then the items.
//                    Returns 1 = valid, 0 = no match, negative = error (see $PkeyErrors).

// x32 Native Wrapper
public static class PkeyNativeX32 {
    [DllImport("PkeyLib32.dll", EntryPoint = "VerifyKey", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.I1)]
    public static extern bool VerifyKey(string key, string config, [Out] byte[] uid, out int group);

    [DllImport("PkeyLib32.dll", EntryPoint = "VerifyBinaryKey", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.I1)]
    public static extern bool VerifyBinaryKey([In] byte[] rawKey, int rawKeySize, [In] byte[] xmlData, int xmlSize, [Out] byte[] uid, out int group, int targetGroupId);

    [DllImport("PkeyLib32.dll", EntryPoint = "VerifyBinks", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    public static extern int VerifyBinks([In] byte[] rawKey, int rawKeySize, [In] byte[] groupList, [In] byte[] binkList, [Out] byte[] uid, out int group, out int index, int targetGroupId);
}

// x64 Native Wrapper
public static class PkeyNativeX64 {
    [DllImport("PkeyLib64.dll", EntryPoint = "VerifyKey", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.I1)]
    public static extern bool VerifyKey(string key, string config, [Out] byte[] uid, out int group);

    [DllImport("PkeyLib64.dll", EntryPoint = "VerifyBinaryKey", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.I1)]
    public static extern bool VerifyBinaryKey([In] byte[] rawKey, int rawKeySize, [In] byte[] xmlData, int xmlSize, [Out] byte[] uid, out int group, int targetGroupId);

    [DllImport("PkeyLib64.dll", EntryPoint = "VerifyBinks", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    public static extern int VerifyBinks([In] byte[] rawKey, int rawKeySize, [In] byte[] groupList, [In] byte[] binkList, [Out] byte[] uid, out int group, out int index, int targetGroupId);
}

// ARM64 Native Wrapper
public static class PkeyNativeArm64 {
    [DllImport("PkeyLibA64.dll", EntryPoint = "VerifyKey", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.I1)]
    public static extern bool VerifyKey(string key, string config, [Out] byte[] uid, out int group);

    [DllImport("PkeyLibA64.dll", EntryPoint = "VerifyBinaryKey", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.I1)]
    public static extern bool VerifyBinaryKey([In] byte[] rawKey, int rawKeySize, [In] byte[] xmlData, int xmlSize, [Out] byte[] uid, out int group, int targetGroupId);

    [DllImport("PkeyLibA64.dll", EntryPoint = "VerifyBinks", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    public static extern int VerifyBinks([In] byte[] rawKey, int rawKeySize, [In] byte[] groupList, [In] byte[] binkList, [Out] byte[] uid, out int group, out int index, int targetGroupId);
}
'@
}
if (!([PSTypeName]'PKeyInnerInterop').Type) {
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
using System.Runtime.ExceptionServices;
using System.Security;

public static class PKeyInnerInterop {
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    public static extern IntPtr LoadLibrary(string dllToLoad);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate int InnerDelegate(IntPtr keyObj, IntPtr blob, int blobSize, IntPtr reserved);

    [HandleProcessCorruptedStateExceptions]
    [SecurityCritical]
    public static int SafeInvoke(IntPtr fn, IntPtr keyObj, IntPtr blob, int blobSize, out int status) {
        status = 0;
        try {
            var f = (InnerDelegate)Marshal.GetDelegateForFunctionPointer(fn, typeof(InnerDelegate));
            return f(keyObj, blob, blobSize, IntPtr.Zero);
        }
        catch (AccessViolationException) { status = 1; return unchecked((int)0xC0000005); }
        catch (SEHException)             { status = 2; return unchecked((int)0xC0000006); }
        catch (Exception)                { status = 3; return unchecked((int)0xDEAD0003); }
    }
}
"@ -ErrorAction Stop -IgnoreWarnings
}
if (-not ([PSTypeName]'PidKeyPlugIn.PubKeyParser').Type) {
    
    # Dot Net 8.0 & Up, And PS 7.x, Env-Test.
    $isNetCoreOr8Plus = $PSVersionTable.PSVersion.Major -ge 7 -and [System.Environment]::Version.Major -ge 8

    if ($isNetCoreOr8Plus) {

        # To make it Fully work Good, it need to Run 4/5 Times
        # Dot Net 8 is just crazy

        $env:COMPlus_TieredCompilation = "0"    
        $b = [Convert]::FromBase64String(((@'
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
'@) -replace '\s',''))
        $s = (New-Object IO.StreamReader((New-Object IO.Compression.GZipStream((New-Object IO.MemoryStream(,$b)), [IO.Compression.CompressionMode]::Decompress)), [Text.Encoding]::UTF8)).ReadToEnd()
        $dllPath = Join-Path $PSScriptRoot "PidKeyPlugIn.dll"
        Add-Type -TypeDefinition $s -CompilerOptions "/optimize+" -ReferencedAssemblies @(
            "System.Runtime",
            "System.Runtime.Extensions",
            "System.Runtime.Numerics",
            "System.Numerics",
            "System.Collections",
            "System.Console",
            "System.Threading",
            "System.Threading.Tasks",
            "System.Threading.Tasks.Parallel",
            "netstandard"
        ) -ErrorAction Stop

	} else {
        
        $b = [Convert]::FromBase64String(((@'
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
==
'@) -replace '\s',''))
        $s = (New-Object IO.StreamReader((New-Object IO.Compression.GZipStream((New-Object IO.MemoryStream(,$b)), [IO.Compression.CompressionMode]::Decompress)), [Text.Encoding]::UTF8)).ReadToEnd()
        $cp = New-Object System.CodeDom.Compiler.CompilerParameters
        Add-Type -AssemblyName System.Numerics
        [void]$cp.ReferencedAssemblies.AddRange([string[]]@(
            [uri].Assembly.Location, 
            [System.Linq.Enumerable].Assembly.Location, 
            [System.Numerics.BigInteger].Assembly.Location
        ))
        $cp.CompilerOptions = '/optimize+'
        
        $a = @{ IgnoreWarnings = $true }
        if ($PSVersionTable.PSEdition -ne 'Core') { 
            $a = @{ CompilerParameters = $cp } 
        }
        Add-Type -TypeDefinition $s @a -ErrorAction Stop
    }
}
function Invoke-PkeyInner {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][byte[]]$KeyData,   # 16 key bytes
        [Parameter(Mandatory)][byte[]]$Bink,      # raw bink blob
        [string]$DllPath   = (Join-Path $PSScriptRoot 'pidgenx64.dll'),
        [string]$FnOffset  = '0x18008D85C',
        [string]$ImageBase = '0x180000000'
    )

    $hModule = [PKeyInnerInterop]::LoadLibrary($DllPath)
    if ($hModule -eq [IntPtr]::Zero) { throw "Failed to load library: $DllPath" }
    $fnPtr = [IntPtr]::Add($hModule,
                [Convert]::ToInt64($FnOffset,16) - [Convert]::ToInt64($ImageBase,16))

    $KeyObjBytes       = [byte[]]::new(96)
    $KeyObjBytes[0x30] = 1
    [Array]::Copy($KeyData, 0, $KeyObjBytes, 0x38, 16)

    $KeyObj  = [Marshal]::AllocHGlobal(96)
    $BinkObj = [Marshal]::AllocHGlobal($Bink.Length)
    try {
        [Marshal]::Copy($KeyObjBytes, 0, $KeyObj, 96)
        [Marshal]::Copy($Bink, 0, $BinkObj, $Bink.Length)

        $status = 0
        $hr = [PKeyInnerInterop]::SafeInvoke($fnPtr, $KeyObj, $BinkObj, $Bink.Length, [ref]$status)

        [pscustomobject]@{
            Ok      = ($status -eq 0 -and $hr -eq 0)
            Faulted = ($status -ne 0)
            Status  = $status
            Hr      = $hr
            M       = if ($status -eq 0 -and $hr -eq 0) { [Marshal]::ReadInt64($KeyObj, 0x48) } else { $null }
        }
    }
    finally {
        [Marshal]::FreeHGlobal($KeyObj)
        [Marshal]::FreeHGlobal($BinkObj)
    }
}
#endregion

# Wrapper for this process: x86 -> PkeyLib32.dll, x64 -> PkeyLib64.dll, ARM64 -> PkeyLibA64.dll.
# Every native call below goes through $PkeyLib, so all three share one code path.
if     ($Is32Bit) { $PkeyLib = [PkeyNativeX32]   }
elseif ($IsArm64) { $PkeyLib = [PkeyNativeArm64] }
else              { $PkeyLib = [PkeyNativeX64]   }

# Types cannot be redefined inside a session: one that already ran the older script still holds the old wrappers.
if (-not $PkeyLib.GetMethod('VerifyBinks')) {
    throw 'Older PkeyNative types are loaded in this session. Open a new PowerShell window and run again.'
}

if(-not $Global:iid) {
  $Global:iid = (Get-CimInstance -Query ("SELECT OfflineInstallationId FROM SoftwareLicensingProduct " +
            "WHERE PartialProductKey IS NOT NULL AND OfflineInstallationId IS NOT NULL") |
            Select-Object -First 1).OfflineInstallationId
}

# ------------------------------------------------------------
# Configuration
# ------------------------------------------------------------

# Which export to call
#   'File'  = VerifyKey        (key text + config path, always scans every group)   needs -Config
#   'Xml'   = VerifyBinaryKey  (raw key + config bytes)                             needs -Config
#   'Binks' = VerifyBinks      (raw key + group list + bink list)                   uses the index in $ConfigPath
#   'BinksNet' =               Managed C# TryBinks (PidKeyPlugIn, Parallel.For over all groups)   uses the same index, no DLL needed
# (choose with -Method; default 'Binks')

# Group to test, 0 = every group ('Xml' and 'Binks')
$TargetGroup = 0

if ($Method -in 'Binks','BinksNet') {
    if (-not [System.Io.File]::Exists((Join-Path $ConfigPath "pkeyindex.json"))) {
      New-PkeyIndex -Path $ConfigPath -Format JSON | Out-Null
    }
}

# ------------------------------------------------------------
# --- Execution Flow ---
# ------------------------------------------------------------

if ('File', 'Xml', 'Binks', 'BinksNet' -notcontains $Method) { throw "Unknown `$Method '$Method' (use File, Xml, Binks or BinksNet)" }
if (-not $CDKey) { throw 'Provide -CDKey (25 characters).' }
if ($Method -notin 'Binks','BinksNet') {
    if (-not $Config) { throw "Provide -Config (path to pkeyconfig.xrm-ms) for the '$Method' method." }
    if (-not [IO.Path]::IsPathRooted($Config)) { $Config = [IO.Path]::Combine($PWD.Path, $Config) }
    if (-not [IO.File]::Exists($Config)) { throw "Config not found: $Config" }
}

if ($Method -ne 'File') {
  $rawKey = [BinaryKey]::EncodeBinaryKey($CdKey)
}

if ($Method -eq 'Xml') {
  $xml = [System.IO.File]::ReadAllBytes($Config)
}

if ($Method -in 'Binks','BinksNet') {
    if (-not $Global:ConfigDB) { 
      $Global:ConfigDB = Import-PkeyIndex -Path "$ConfigPath\pkeyindex.json" 
    }
}
if ($Method -eq 'Binks' -and -not $Global:BinkDB) {
    $Global:BinkDB = Get-PkeyBinkLists -Index $Global:ConfigDB 
}

if ($Method -eq 'BinksNet' -and -not [PidKeyPlugIn.PKeyCalc].GetMethod('TryBinks')) {
    throw 'Older PidKeyPlugIn is loaded in this session. Open a new PowerShell window and run again.'
}

# VerifyBinks return codes (1 = valid, 0 = no match)
$PkeyErrors = @{
    -1 = 'Null pointer or raw key is not 16 bytes'
    -2 = 'Group list: wrong type, bad length, or empty'
    -3 = 'Bink list: wrong type, or length does not fit the group count'
    -4 = 'No entry passed the bink checks'
    -5 = 'Target group is not in the group list'
    -9 = 'Unexpected exception inside the DLL'
}

# Output
$group    = 0
$index    = -1
$code     = $null
$lastHr   = $null
$success  = $false
$uidBytes = [byte[]]::new(8)

$Dtimer   = [System.Diagnostics.Stopwatch]::StartNew()
$Ctimer   = [System.Diagnostics.Stopwatch]::StartNew()

try {
    switch ($Method) {
        'File' {
            # VerifyKey Call
            $success = $PkeyLib::VerifyKey(
                $CdKey,
                $Config,
                $uidBytes,
                [ref]$group
            )
        }
        'Xml' {
            # VerifyBinaryKey Call
            $success = $PkeyLib::VerifyBinaryKey(
                $rawKey, $rawKey.Length,
                $xml,    $xml.Length,
                $uidBytes, [ref]$group,
                $TargetGroup
            )
        }
        'Binks' {
            
            # VerifyBinks Call
            $code = $PkeyLib::VerifyBinks(
                $rawKey, $rawKey.Length,
                $BinkDB.GroupList,
                $BinkDB.BinkList,
                $uidBytes, [ref]$group, [ref]$index,
                $TargetGroup
            )
            $success = ($code -eq 1)
        }

        'BinksNet' {

            # Managed engine (PidKeyPlugIn.PKeyCalc, ported C#). ONE call, all groups, all cores:
            # Parallel.For inside TryBinks, lowest group index wins (same result as the DLL's scan).
            # The byte[][] / int[] arrays are built once per session and cached in $Global:NetBinks.
            if (-not $Global:NetBinks) {
                $groups = $Global:ConfigDB['groups']
                $ids = New-Object System.Collections.Generic.List[int]
                $pks = New-Object System.Collections.Generic.List[byte[]]
                foreach ($gidStr in @($groups.Keys | Sort-Object { [int]$_ })) {
                    $node = $groups[$gidStr]
                    if (-not $node.ContainsKey('bink')) { continue }
                    $ids.Add([int]$gidStr)
                    $pks.Add([Convert]::FromBase64String($node['bink']))     # PublicKeyPart1 + Part2
                }
                $Global:NetBinks = [pscustomobject]@{ Ids = $ids.ToArray(); Keys = $pks.ToArray() }
            }
            $ids = $Global:NetBinks.Ids; $pks = $Global:NetBinks.Keys
            if ($TargetGroup -ne 0) {
                $at = [Array]::IndexOf($ids, [int]$TargetGroup)
                if ($at -lt 0) { $ids = [int[]]@(); $pks = [byte[][]]@() }
                else           { $ids = [int[]]@($ids[$at]); $pks = [byte[][]]@(,$pks[$at]) }
            }
            $g = 0; $h1 = $null; $u = $null
            $code = [PidKeyPlugIn.PKeyCalc]::TryBinks($pks, $ids, $rawKey, $Threads, [ref]$g, [ref]$h1, [ref]$u)
            if ($code -eq 1) {
                $uidBytes = [byte[]]$u[0..7]
                $group    = $g
                $success  = $true
            }
        }
    }
} finally {
    $Dtimer.Stop()
}

if ($success) {
    if ($Method -in 'Binks','BinksNet') {
        # The index knows which pkeyconfig holds this group + serial; 'File' and 'Xml' already have -Config
        $serial = (([BitConverter]::ToUInt64($uidBytes, 0)) -shr 1) -band 0x3FFFFFFF
        $Config = Find-PkeyFile $Global:ConfigDB $group $serial | Select-Object -First 1 -ExpandProperty Path
    }
    if ($Config) {
        Get-PkeyInfo -Uid $uidBytes -Group $group -ConfigPath $Config
    } else {
        Get-PkeyInfo -Uid $uidBytes -Group $group -Skip
    }
} elseif ($null -ne $code -and $code -lt 0) {
    Write-Host ("`n[ ! ] VerifyBinks error {0}: {1}" -f $code, $PkeyErrors[$code]) -ForegroundColor Red
} else {
    Write-Host "`n[ X ] Invalid" -ForegroundColor DarkGray
}

$Ctimer.Stop()
[String]::Format("Native Call Took {1:N3} s ({2} ms)", $Method, $Dtimer.Elapsed.TotalSeconds, $Dtimer.ElapsedMilliseconds)
[String]::Format("Total  Time Took {1:N3} s ({2} ms)", $Method, $Ctimer.Elapsed.TotalSeconds, $Ctimer.ElapsedMilliseconds)