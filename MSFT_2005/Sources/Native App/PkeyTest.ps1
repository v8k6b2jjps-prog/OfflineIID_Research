using namespace System
using namespace System.Diagnostics
using namespace System.Management.Automation
using namespace System.Runtime.InteropServices

# Source I use
# TSForge project, ExtPid
# laomms, PKey2005Decoder, C# Source
# massgravel, spp-stuff-main, iid2005.py
# https://github.com/ntriver-org/PKeyMaster/commit/4926123bc7e56882dc13123942c3459728fb562c

Clear-Host
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

# ------------------------------------------------------------
# Native P/Invoke
# ------------------------------------------------------------

Add-Type @"
using System;
using System.Runtime.InteropServices;

public static class PkeyNative
{
    [DllImport("kernel32.dll")]
    public static extern ushort GetSystemDefaultLangID();

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
        Decodes the PKEY2005 UID returned by PkeyLib.dll, looks up the
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
    $hwid = $null
    $offlineAct = $null
    $iid = (Get-CimInstance -Query ("SELECT OfflineInstallationId FROM SoftwareLicensingProduct " +
            "WHERE PartialProductKey IS NOT NULL AND OfflineInstallationId IS NOT NULL") |
            Select-Object -First 1).OfflineInstallationId

    if (-not $hwid -and $iid) { 
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
        BasePid     = & $GetPid -Serial $serial -Group $Group -EulaType $eula
        ExtendedPID = & $GetExtendedPid -Serial $serial -Group $Group
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
    Get-PkeyInfo -Uid $uidBytes -Group $group -ConfigPath $Config | Format-List
} else {
    Write-Host "`n[ X ] Invalid" -ForegroundColor DarkGray
}