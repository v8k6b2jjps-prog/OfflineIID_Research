using namespace System
using namespace System.Diagnostics
using namespace System.Management.Automation
using namespace System.Runtime.InteropServices

param(
    [string]$CDKey,
    [string]$Config,
    [int]$Threads = 0,
    [switch]$FromParent
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
#   'Xml'   = VerifyBinaryKey  (raw key + config bytes)                              needs -Config
#   'Binks' = VerifyBinks      (raw key + group list + bink list)                    uses the index in $ConfigPath
$Method = 'Binks'

# Group to test, 0 = every group ('Xml' and 'Binks')
$TargetGroup = 0

# Base Input
$ConfigPath  = '.\PKeyConfigs'
#$ConfigPath = 'C:\Windows\System32\spp'

# TO create new List
#New-PkeyIndex -Path $ConfigPath | Out-Null


# --- Execution Flow ---
if ('File', 'Xml', 'Binks' -notcontains $Method) { throw "Unknown `$Method '$Method' (use File, Xml or Binks)" }
if (-not $CDKey) { throw 'Provide -CDKey (25 characters).' }
if ($Method -ne 'Binks') {
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

if ($Method -eq 'Binks') {
    if (-not $Global:ConfigDB) { 
      $Global:ConfigDB = Import-PkeyIndex -Path "$ConfigPath\pkeyindex.json" 
    }
    if (-not $Global:BinkDB) {
      $Global:BinkDB = Get-PkeyBinkLists -Index $Global:ConfigDB 
    }
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
    }
} finally {
    $Dtimer.Stop()
}

if ($success) {
    if ($Method -eq 'Binks') {
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