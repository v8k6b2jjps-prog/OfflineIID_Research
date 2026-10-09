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

#region Setup
if (!([PSTypeName]'PkeyNative').Type) {
Add-Type @"
using System;
using System.Runtime.InteropServices;

public static class PkeyNative
{
    [DllImport("kernel32.dll")]
    public static extern ushort GetSystemDefaultLangID();

    [DllImport(
        "PkeyLib64.dll",
        EntryPoint = "VerifyKey",
        CallingConvention = CallingConvention.Cdecl,
        ExactSpelling = true,
        SetLastError = false)]
    [return: MarshalAs(UnmanagedType.I1)]
    public static extern bool VerifyKey(
        [MarshalAs(UnmanagedType.LPStr)] string key,
        [MarshalAs(UnmanagedType.LPStr)] string config,
        [Out] byte[] uid,
        out int group);

    [DllImport(
        "PkeyLib64.dll",
        EntryPoint = "VerifyBinaryKey",
        CallingConvention = CallingConvention.Cdecl,
        ExactSpelling = true,
        SetLastError = false)]
    [return: MarshalAs(UnmanagedType.I1)]
    public static extern bool VerifyBinaryKey(
        [In] byte[] rawKey,
        int rawKeySize,
        [In] byte[] xmlData,
        int xmlSize,
        [Out] byte[] uid,
        out int group,
        int targetGroupId);

    // Group / bink lists both start with: uint32 Type (1 = groups, 2 = binks),
    // uint32 TotalLength (whole list, header included), then the items.
    // Returns 1 = valid, 0 = no match, negative = error (see $PkeyErrors).
    [DllImport(
        "PkeyLib64.dll",
        EntryPoint = "VerifyBinks",
        CallingConvention = CallingConvention.Cdecl,
        ExactSpelling = true,
        SetLastError = false)]
    public static extern int VerifyBinks(
        [In] byte[] rawKey,
        int rawKeySize,
        [In] byte[] groupList,
        [In] byte[] binkList,
        [Out] byte[] uid,
        out int group,
        out int index,
        int targetGroupId);
}
"@
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
    BinaryKey([byte[]]$BinaryData, [bool]$Stream = $true) {
        $this.BinaryData = $BinaryData.Clone()
        $BinKeyInfo = [BinaryKey]::UnpackBinaryKey($this.BinaryData, $true)
        $this.Group = $BinKeyInfo.Group
        $this.Serial = $BinKeyInfo.Serial
        $this.Security = $BinKeyInfo.Security
        $this.IsNKey = $BinKeyInfo.IsNKey
        $this.CdKey = [BinaryKey]::DecodeBinaryKey($this.BinaryData)
        $this.Checksum = [BinaryKey]::GetKeyChecksum($this.BinaryData)
    }
    BinaryKey([uint16]$Group, [uint32]$Serial, [uint64]$Security, [bool]$IsNKey = $true, [bool]$Stream = $true) {
        $this.BinaryData = [BinaryKey]::FormatBinaryKey($Group, $Serial, $Security, $IsNKey, $Stream)
        $this.Group = $Group
        $this.Serial = $Serial
        $this.Security = $Security
        $this.IsNKey = $IsNKey
        $this.CdKey = [BinaryKey]::DecodeBinaryKey($this.BinaryData)
        $this.Checksum = [BinaryKey]::GetKeyChecksum($this.BinaryData)
    }

    # --- Static Key Checksum method ---
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

        # Replicate the sanitization/manipulation seen in sub_180020A1C
        # The code works on a copy (v35)
        $v35 = $Data.Clone()

        # ASM: v11 = HIWORD(_mm_srli_si128(v7, 8).m128i_u64[0]); (This is Byte 14)
        $v11 = [int]$v35[14]
    
        # ASM: v14 = v11 ^ (v11 ^ (4 * ((v11 & 8) != 0))) & 8;
        # This effectively isolates/toggles the NKey bit (Bit 3)
        $isNKeySet = ($v11 -band 8) -ne 0
        $v14 = $v11 -bxor (($v11 -bxor (4 * [int]$isNKeySet)) -band 8)

        # ASM: v35.m128i_i16[6] = v12 & 0x7F; (Byte 12)
        $v35[12] = [byte]($v35[12] -band 0x7F)

        # ASM: v17 = v14 & 0xFE; v35.m128i_i8[14] = v17; (Byte 14)
        $v17 = [byte]($v14 -band 0xFE)
        $v35[14] = $v17

        # Byte 13 is included in the CRC but is usually zeroed in the 'clean' version
        # The ASM doesn't explicitly zero it in the v35 copy before the loop, 
        # but the extractor implies it's a dedicated CRC byte.
        $v35[13] = 0

        # --- CRC-32 LOOP ---
        $v20 = [uint32]"0xFFFFFFFF"
        foreach ($b in $v35) {
            $idx = ([int]$b -bxor [int]($v20 -shr 24)) -band 0xFF
            $v20 = [uint32]((($v20 -shl 8) -bxor [BinaryKey]::CrcTable[$idx]) -band 0xFFFFFFFF)
        }

        # ASM: if ( v31 == (~(_WORD)v20 & 0x3FF) )
        $FinalCRC = [int]((-bnot $v20) -band 0x3FF)
    
        return $FinalCRC
    }

    # Static method version of New-BinaryKey
    static [byte[]] FormatBinaryKey(
        [uint16]$Group,
        [uint32]$Serial,
        [uint64]$Security,
        [bool]$IsNKey = $true,
        [bool]$Stream = $true ) {

        # Internal helper function for setting bits
        function Set-Bits {
            param(
                [byte[]]$Data,
                [int]$StartBit,
                [uint64]$Value,
                [int]$Count
            )
            $byteOffset = $StartBit -shr 3
            $bitOffset  = $StartBit -band 7

            $chunkBytes = [byte[]]::new(8)
            $bytesToCopy = [Math]::Min(8, $Data.Length - $byteOffset)
            [Array]::Copy($Data, $byteOffset, $chunkBytes, 0, $bytesToCopy)
            [uint64]$currentData = [BitConverter]::ToUInt64($chunkBytes, 0)

            $mask = ([uint64]1 -shl $Count) - 1
            if ($Count -eq 64) { $mask = [uint64]::MaxValue }
            $clearedMask = -bnot ($mask -shl $bitOffset)

            $newData = ($currentData -band $clearedMask) -bor (($Value -band $mask) -shl $bitOffset)

            $modifiedBytes = [BitConverter]::GetBytes($newData)
            [Array]::Copy($modifiedBytes, 0, $Data, $byteOffset, $bytesToCopy)
        }

        # Stream / BigInteger packing
        if ($Stream) {
            [bigint]$Key = 0
            $Key = $Key -bor [bigint]$Group
            $Key = $Key -bor ([bigint]($Serial -band 0x3FFFFFFF) -shl 20)
            $Key = $Key -bor ([bigint]($Security -band 0x1FFFFFFFFFFFFF) -shl 50)

            if ($IsNKey) { $Key = $Key -bor ([bigint]1 -shl 115) }

            $BinaryData_ = $Key.ToByteArray()
            if ($BinaryData_.Length -lt 16) { $BinaryData_ += ,0 * (16 - $BinaryData_.Length) }
            $BinaryData_ = $BinaryData_[0..15]

            $crc = [BinaryKey]::GetKeyChecksum($BinaryData_)
            if ($crc -band 0x01) { $BinaryData_[12] = $BinaryData_[12] -bor 0x80 }
            $BinaryData_[13] = [byte](($crc -shr 1) -band 0xFF)
            if ($crc -band 0x200) { $BinaryData_[14] = $BinaryData_[14] -bor 0x01 }
        } else {
            $GROUP_OFFSET    = 0
            $SERIAL_OFFSET   = 20
            $SERIAL_BITS     = 30
            $SECURITY_OFFSET = 50
            $SECURITY_BITS   = 53

            $BinaryData_ = [byte[]]::new(16)
            [BitConverter]::GetBytes($Group).CopyTo($BinaryData_, 0)
            Set-Bits $BinaryData_ $SERIAL_OFFSET   ([uint64]$Serial)   $SERIAL_BITS
            Set-Bits $BinaryData_ $SECURITY_OFFSET ([uint64]$Security) $SECURITY_BITS

            if ($IsNKey) { $BinaryData_[14] = $BinaryData_[14] -bor 0x08 }

            $crc = [BinaryKey]::GetKeyChecksum($BinaryData_)
            if ($crc -band 0x001) { $BinaryData_[12] = $BinaryData_[12] -bor 0x80 }
            $BinaryData_[13] = [byte](($crc -shr 1) -band 0xFF)
            if ($crc -band 0x200) { $BinaryData_[14] = $BinaryData_[14] -bor 0x01 }
        }

        return $BinaryData_
    }

    # Static method version of Unpack-BinaryKey
    static [PSCustomObject] UnpackBinaryKey(
        [byte[]]$BinaryData,
        [bool]$Stream = $true ) {

        # Internal helper function
        function Get-Bits {
            param(
                [byte[]]$Data,
                [int]$StartBit,
                [int]$Count
            )

            $byteOffset = $StartBit -shr 3
            $bitOffset  = $StartBit -band 7

            $chunkBytes = [byte[]]::new(8)
            [Array]::Copy($Data, $byteOffset, $chunkBytes, 0, [Math]::Min(8, $Data.Length - $byteOffset))
            [uint64]$u64 = [BitConverter]::ToUInt64($chunkBytes, 0)

            $mask = ([uint64]1 -shl $Count) - 1
            if ($Count -eq 64) { $mask = [uint64]::MaxValue }

            return ($u64 -shr $bitOffset) -band $mask
        }

        if ($Stream) {
            $TempBytes = $BinaryData[0..15] + [byte]0
            $Value = [bigint]::new($TempBytes)

            return [PSCustomObject][Ordered]@{
                Group    = [uint16]($Value -band 0xFFFF)
                Serial   = [uint32](($Value -shr 20) -band 0x3FFFFFFF)
                Security = [uint64](($Value -shr 50) -band 0x1FFFFFFFFFFFFF)
                IsNKey   = (($Value -shr 115) -band 1) -eq 1
                Checksum = [BinaryKey]::GetKeyChecksum($BinaryData)
            }
        } else {
            $GROUP_OFFSET    = 0
            $SERIAL_OFFSET   = 20
            $SERIAL_BITS     = 30
            $SECURITY_OFFSET = 50
            $SECURITY_BITS   = 53

            return [PSCustomObject][Ordered]@{
                Group    = [BitConverter]::ToUInt16($BinaryData, 0)
                Serial   = [uint32](Get-Bits $BinaryData $SERIAL_OFFSET $SERIAL_BITS)
                Security = Get-Bits $BinaryData $SECURITY_OFFSET $SECURITY_BITS
                IsNKey   = (($BinaryData[14] -band 0x08) -ne 0)
            }
        }
    }

    # Static Encoder method
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
                for ($i = $digitCount; $i -gt 0; $i--) {
                    $Digits[$i] = $Digits[$i-1]
                }
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

    # Static decoder method
    static [string] DecodeBinaryKey([byte[]]$bCDKeyArray) {
        $last = 0

        # Clone input like C++ __m128i
        $keyData = $bCDKeyArray.Clone()

        # +2 for N` Logic Shift right [else fail]
        $Src = New-Object char[] 27

        # Base-24 character set
        $charset = "BCDFGHJKMPQRTVWXY2346789"

        if ($keyData.Length -lt 15 -or $keyData.Length -gt 16) {
            throw "Input data must be a 15 or 16 byte array."
        }

        # Win 8 key check
        if (($keyData[14] -band 0xF0) -ne 0) {
            throw "Failed to decode key!"
        }

        # N-flag detection
        $BYTE14 = [byte]$keyData[14]
        $flag = (($BYTE14 -band 0x08) -ne 0)

        # Adjust BYTE14 per original algorithm
        $keyData[14] = (4 * (([int](($BYTE14 -band 8) -ne 0)) -band 2)) -bor ($BYTE14 -band 0xF7)

        # Base-24 decoding loop
        for ($idx = 24; $idx -ge 0; $idx--) {
            $last = 0
            for ($j = 14; $j -ge 0; $j--) {
                $val = $keyData[$j] + ($last -shl 8)
                $keyData[$j] = [math]::Floor($val / 0x18)
                $last = $val % 0x18
            }
            $Src[$idx] = $charset[$last]
        }

        if ($keyData[0] -ne 0) {
            throw "Invalid product key data"
        }

        # Handle N-flag
        $rev = $last -gt 13
        $pos = if ($rev) { 25 } else { -1 }
        $T = 0

        if ($flag -and ($last -le 0)) {
            $Src[0] = [char]78 # 'N'
        } elseif ($flag -and $rev) {
            while ($pos-- -gt $last) { $Src[$pos + 1] = $Src[$pos] }
            $T = 1
            $Src[$last + 1] = [char]78
        } elseif ($flag -and !$rev) {
            while (++$pos -lt $last) { $Src[$pos] = $Src[$pos + 1] }
            $Src[$last] = [char]78
        }

        # Format as 5x5 key with dashes
        $Output = (0..4 | ForEach-Object { -join $Src[((5*$_)+$T)..((5*$_)+4+$T)] }) -join '-'

        return $Output
    }
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
        Decodes the PKEY2005 UID returned by PkeyLib, finds the matching
        configuration + key range across ONE OR MORE pkeyconfig files, builds
        the ActString and re-encodes an offline IID from the machine HWID.

        UID layout (https://github.com/UMSKT/writeups/blob/main/PKEY2005.md):
            upgrade : 1   | serial : 30   | auth : 10

        -ConfigPath now takes a LIST of candidate files (e.g. every file
        binks.csv lists for the group). The files are tried in order and the
        first one whose <Configuration RefGroupId=Group> has a <KeyRange>
        containing the serial wins. The chosen file is reported as ConfigFile.
    #>
    [CmdletBinding()]
    param(
        [byte[]]$Uid,
        [int]$Group,
        [string]$ConfigPath,
        [string]$ScriptDir = $PSScriptRoot,
        [switch]$Skip
    )

    # --- Decode UID bit fields ---------------------------------------------
    $raw     = [BitConverter]::ToUInt64($Uid, 0)
    $upgrade = $raw -band 1
    $serial  = ($raw -shr 1)  -band 0x3FFFFFFF
    $auth    = ($raw -shr 31) -band 0x3FF

    $get = { param($Node, $Name) $n = $Node.SelectSingleNode("*[local-name()='$Name']"); if ($n) { $n.InnerText.Trim() } else { $null } }

    # inner pkeyConfigData bytes -> text, by BOM (UTF-16 LE / UTF-8)
    $decode = {
        param([byte[]]$b)
        if ($b.Length -ge 2 -and $b[0] -eq 0xFF -and $b[1] -eq 0xFE) { return [Text.Encoding]::Unicode.GetString($b, 2, $b.Length - 2) }
        if ($b.Length -ge 3 -and $b[0] -eq 0xEF -and $b[1] -eq 0xBB -and $b[2] -eq 0xBF) { return [Text.Encoding]::UTF8.GetString($b, 3, $b.Length - 3) }
        if ($b.Length -ge 2 -and $b[1] -eq 0) { return [Text.Encoding]::Unicode.GetString($b) }
        return [Text.Encoding]::UTF8.GetString($b)
    }

    if (-not $Skip.IsPresent) {

        # --- Find Configuration + KeyRange for Group/Serial, across the files ---
        $cfg = $null; $range = $null; $actId = $null; $usedConfig = $null

        if (-not [string]::IsNullOrWhiteSpace($ConfigPath) -and (Test-Path -LiteralPath $ConfigPath)) {
            try {
                [xml]$xrm = Get-Content -LiteralPath $ConfigPath -Raw
                $bin = $xrm.SelectSingleNode("//*[local-name()='infoBin'][@name='pkeyConfigData']")
                if (-not $bin) { $pkey = $null }
                else {
                    $bytes = [Convert]::FromBase64String(($bin.InnerText -replace '\s',''))
                    [xml]$pkey = (& $decode $bytes).TrimStart([char]0xFEFF)
                }
            } catch { Write-Verbose "skip $ConfigPath : $($_.Exception.Message)"; continue }

            if ($pkey) {
                foreach ($c in $pkey.SelectNodes("//*[local-name()='Configuration'][*[local-name()='RefGroupId']='$Group']")) {
                    $id = & $get $c 'ActConfigId'
                    if (-not $id) { continue }
                    foreach ($r in $pkey.SelectNodes("//*[local-name()='KeyRange'][*[local-name()='RefActConfigId']='$id']")) {
                        $s = [uint64]0; $e = [uint64]0
                        if (-not [uint64]::TryParse((& $get $r 'Start'), [ref]$s)) { continue }
                        if (-not [uint64]::TryParse((& $get $r 'End'),   [ref]$e)) { continue }
                        if ($serial -ge $s -and $serial -le $e) { $range = $r; break }
                    }
                    if ($range) { 
                        $cfg = $c; 
                        $actId = $id; 
                        break 
                    }
                }
            }
        }
        if ($range) { $usedConfig = $ConfigPath; }
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

    if (-not $hwid -and $iid) {
        try { $hwid = Get-IidHwid $iid } catch {}
    }
    if (-not $hwid) {
        try { $hwid = [String]::Format("0x{0}", [Convert]::ToString((Get-WinRTHwid), 16)) } catch {}
    }
    if ($hwid -eq $null) { $hwid = '0' }
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

    $eula = if ($range) { & $get $range 'EulaType' } else { 'Retail' }

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
        ExtendedPID = & $GetExtendedPid -Serial $serial -Group $Group -EulaType $eula
        HWID        = $hwid
        OfflineAct  = $offlineAct
        ConfigFile  = $usedConfig
    }
}
function Get-PkeyBinkLists {
    <#
    .SYNOPSIS
        Packs msft:rm/algorithm/pkey/2005 public keys into the two lists that
        VerifyBinks takes.

    .DESCRIPTION
        -ConfigPath can be:
          * a pkeyconfig .xrm-ms licence (or a decoded pkeyconfig .xml)
          * a .csv with a Group (or GroupId) column and a Bink column (base64),
            e.g. the binks.csv written by the index script
          * a folder: its binks.csv is used

        Both lists share one 8-byte header, followed by the items:
            uint32 Type         1 = group ids, 2 = binks
            uint32 TotalLength  whole list in bytes, header included
            items               Type 1: int32 group ids
                                Type 2: the binks back to back, all one size

        Each group is packed once (first one wins), sorted by group id.
        Binks whose size differs from the first are skipped with a warning,
        because the bink list carries no per-item length.

    .PARAMETER GroupId
        Optional: pack only these groups.

    .EXAMPLE
        $l = Get-PkeyBinkLists C:\PKeyConfigs\binks.csv
        $l = Get-PkeyBinkLists C:\PKeyConfigs                 # folder -> binks.csv
        $l = Get-PkeyBinkLists C:\...\pkeyconfig.xrm-ms
        $l = Get-PkeyBinkLists C:\PKeyConfigs -GroupId 172,176
        # $l.GroupList, $l.BinkList -> byte[] for VerifyBinks
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)][string]$ConfigPath,
        [int[]]$GroupId
    )
    $ErrorActionPreference = 'Stop'

    $full = $PSCmdlet.GetUnresolvedProviderPathFromPSPath($ConfigPath)
    if (Test-Path -LiteralPath $full -PathType Container) {
        $full = Join-Path $full 'binks.csv'
    }
    if (-not (Test-Path -LiteralPath $full -PathType Leaf)) {
        throw "File not found: $full"
    }

    # --- 1. read (Group, Bink-bytes) pairs from the source ------------------
    $entries = New-Object System.Collections.ArrayList

    if ([IO.Path]::GetExtension($full) -ieq '.csv') {
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
    foreach ($e in ($entries | Sort-Object Group)) {
        if ($GroupId -and ($GroupId -notcontains $e.Group)) { continue }
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
    if ($final.Count -eq 0) { throw "No usable msft2005 binks found in $full" }

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
function New-PkeyIndex {
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
#endregion

# ------------------------------------------------------------
# Configuration
# ------------------------------------------------------------

# Which export to call
#   'File'  = VerifyKey        (key text + config path, always scans every group)
#   'Xml'   = VerifyBinaryKey  (raw key + config bytes)
#   'Binks' = VerifyBinks      (raw key + group list + bink list)
$Method = 'Binks'

# Base Input
$Group  = 0 #172
$CdKey  = "GT63C-RJFQ3-4GMB6-BRFB9-CB83V"
$Config = Join-Path $PSScriptRoot "pkeyconfig.xrm-ms"

if ($Method -ne 'File') {
  $rawKey = [BinaryKey]::EncodeBinaryKey($CdKey)
}

if ($Method -eq 'Xml') {
  $xml = [System.IO.File]::ReadAllBytes($Config)
}

$ConfigPath  = '.\PKeyConfigs'
#$ConfigPath = 'C:\Windows\System32\spp'

# TO create new List
#New-PkeyIndex -Path $ConfigPath | Out-Null


if(-not $Global:lists) {
  $Global:lists  = Get-PkeyBinkLists -ConfigPath "$ConfigPath\binks.csv"
}
if(-not $Global:ranges) {
  $Global:ranges = [System.IO.File]::ReadAllText("$ConfigPath\ranges.csv", [System.Text.Encoding]::UTF8) | ConvertFrom-Csv
}

if(-not $Global:iid) {
  $Global:iid = (Get-CimInstance -Query ("SELECT OfflineInstallationId FROM SoftwareLicensingProduct " +
            "WHERE PartialProductKey IS NOT NULL AND OfflineInstallationId IS NOT NULL") |
            Select-Object -First 1).OfflineInstallationId
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
            $success = [PkeyNative]::VerifyKey(
                $CdKey,
                $Config,
                $uidBytes,
                [ref]$group
            )
        }
        'Xml' {
            # VerifyBinaryKey Call
            $success = [PkeyNative]::VerifyBinaryKey(
                $rawKey, $rawKey.Length,
                $xml,    $xml.Length,
                $uidBytes, [ref]$group,
                $Group
            )
        }
        'Binks' {
            # VerifyBinks Call
            $code = [PkeyNative]::VerifyBinks(
                $rawKey, $rawKey.Length,
                $lists.GroupList,
                $lists.BinkList,
                $uidBytes, [ref]$group, [ref]$index,
                $Group
            )
            $success = ($code -eq 1)
        }
        default { 
          throw "Unknown `$Method '$Method' (use File, Xml or Binks)"
        }
    }

} finally {
    $Dtimer.Stop()
}

if ($success) {
    $serial = (([BitConverter]::ToUInt64($uidBytes, 0)) -shr 1) -band 0x3FFFFFFF
    $Config = $ranges | Where-Object { [int]$_.Group -eq $group -and $serial -ge [int64]$_.Start -and $serial -le [int64]$_.End } | Select-Object -First 1
    if ($Config) {
        Get-PkeyInfo -Uid $uidBytes -Group $group -ConfigPath (Join-Path $ConfigPath $Config.File)
    } else {
        Get-PkeyInfo -Uid $uidBytes -Group $group -Skip
    }
} elseif ($null -ne $code -and $code -lt 0) {
    Write-Host ("`n[ ! ] VerifyBinks error {0}: {1}" -f $code, $PkeyErrors[$code]) -ForegroundColor Red
} else {
    Write-Host "`n[ X ] Invalid" -ForegroundColor DarkGray
}
$Ctimer.Stop()
[String]::Format("native call took {1:N3} s ({2} ms)", $Method, $Dtimer.Elapsed.TotalSeconds, $Dtimer.ElapsedMilliseconds)
[String]::Format("Total  Time took {1:N3} s ({2} ms)", $Method, $Ctimer.Elapsed.TotalSeconds, $Ctimer.ElapsedMilliseconds)