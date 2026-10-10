using namespace System
using namespace System.IO
using namespace System.Runtime.InteropServices

# ---------------------------------------------------------------------------
# Direct call into pidgenx.dll ONE LEVEL BELOW the public validator.
#
#   Old path : ctor -> validate-wrapper -> [core] -> Release
#   New path : [core] only
#
# The wrapper (sub_18008CFF0 / sub_18008D200) is a thin shell around the real
# worker sub_18009CA30. That worker is a PLAIN function (not a vtable method):
# it allocates its own ~0x9F0 scratch context via GetProcessHeap/HeapAlloc,
# verifies the key against the BINK, and returns 0 on success. Because it owns
# its context, no constructed object / vtable / Release is required.
#
# What the wrapper does around the core, replicated below in PowerShell:
#   PRE  : build a 16-byte "key struct" + a 10-byte reconstructed payload
#          from the 16 raw key bytes (strips the embedded CRC/N bits).
#   CALL : sub_18009CA30(pubKey, keyStruct, 4, recon10, &outA, &outB) -> 0 = ok
#   POST : Channel/Sequence/Upgrade are derived from keyStruct[0..3] (no object).
#          The M / "Act Data" field is NOT produced here - in the wrapper it
#          comes from a separate vtable method on the constructed object, so a
#          pure core call cannot return it without also replicating that method.
#
# Offsets are valid only for this exact DLL build (x64, 10.0.26040.1000).
# Run in 64-bit PowerShell.
# ---------------------------------------------------------------------------

#region Helpers
function Test-BinkIntegrity([byte[]]$BinkBytes) {
    if ($null -eq $BinkBytes -or $BinkBytes.Length -lt 24) {
        return [PSCustomObject]@{ IsValid = $false; Reason = "Buffer too short" }
    }

    # Helper for UInt32
    $U32 = { param($off) [BitConverter]::ToUInt32($BinkBytes, $off) }
    # Helper for UInt16
    $U16 = { param($off) [BitConverter]::ToUInt16($BinkBytes, $off) }

    # 1. Verify declared size matches actual buffer length
    $declaredSize = &$U32 0
    if ($declaredSize -ne $BinkBytes.Length) {
        return [PSCustomObject]@{ IsValid = $false; Reason = "Declared size mismatch" }
    }

    # 2. Extract version / structural metrics
    $versionId    = &$U32 4
    $modulusBytes = $BinkBytes[21]
    $orderBytes   = $BinkBytes[22]
    $extDeg1      = &$U32 23

    return [PSCustomObject]@{
        IsValid        = $true
        VersionId      = $versionId
        ModulusBytes   = $modulusBytes
        OrderBytes     = $orderBytes
        ExtDeg1        = $ExtDeg1
        DeclaredSize   = $declaredSize
        ActualSize     = $BinkBytes.Length
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
#endregion

Clear-Host
Set-Location $PSScriptRoot
[Environment]::CurrentDirectory = $PSScriptRoot

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public static class PKeyCoreInterop {
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    public static extern IntPtr LoadLibrary(string dllToLoad);

    // int sub_18009CA30(void* pubKey, void* keyStruct16, int mode,
    //                   void* recon10, void* outA, void* outB)   -> 0 = valid
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate int CoreValidateDelegate(
        IntPtr pubKey, IntPtr keyStruct, int mode,
        IntPtr recon10, IntPtr outA, IntPtr outB);
}
"@ -ErrorAction Stop

$dllPath = Join-Path $PSScriptRoot 'pidgenx.dll'
$hModule = [PKeyCoreInterop]::LoadLibrary($dllPath)
if ($hModule -eq [IntPtr]::Zero) { throw "Failed to load library: $dllPath" }

function Get-SubAddress([string]$hexOffset) {
    return [IntPtr]::Add($hModule, [Convert]::ToInt64($hexOffset, 16) - 0x180000000)
}

# The core worker is shared by all three algorithms (980 / 985 / 986);
# the algorithm is selected by which BINK you feed it, not by the entry point.
$CORE_OFFSET = '0x18009CA30'
$coreFunc = [Marshal]::GetDelegateForFunctionPointer(
    (Get-SubAddress $CORE_OFFSET), [PKeyCoreInterop+CoreValidateDelegate])

# --- Raw key bytes (base-24 -> 16 bytes), exactly as before --------------------
$CDKEy = 'XJFG6-2GH83-87QQJ-33F4K-K7HBB'
$raw = [BinaryKey]::EncodeBinaryKey($CDKEy)
if ($raw.Length -lt 16) { throw 'Encoded key must hold 16 bytes.' }

# --- PRE: reshape raw bytes the way the wrapper does (D06B..D0BB) --------------
#   keyStruct[0..3] = raw[0], raw[1], raw[2], raw[3] & 0x7F   (CRC top bit cleared)
#   recon[i]        = (raw[4+i] << 1) | (raw[3+i] >> 7)  for i = 0..9   (loop D0A1..D0BB)
#   recon[10]       = ((raw[14] << 1) | (raw[13] >> 7)) & 7             (D0BD..D0DE)
#                     -> the payload is 11 bytes, NOT 10; the 11th byte (the top
#                        3 bits that spill past the loop) is written separately at
#                        [rbp-0x16]. Omitting it makes the core reject with 1.

$keyStruct = [byte[]]::new(16)
$keyStruct[0] = $raw[0]
$keyStruct[1] = $raw[1]
$keyStruct[2] = $raw[2]
$keyStruct[3] = [byte]($raw[3] -band 0x7F)

$recon = [byte[]]::new(16)
for ($i = 0; $i -lt 10; $i++) {
    $recon[$i] = [byte]( (($raw[4 + $i] -shl 1) -band 0xFF) -bor ($raw[3 + $i] -shr 7) )
}
$recon[10] = [byte]( ( (($raw[14] -shl 1) -band 0xFF) -bor ($raw[13] -shr 7) ) -band 7 )

# --- Public key (BINK) for the selected algorithm ------------------------------
[xml]$xmlContent = Get-Content -Path "Legacy_License.xml"
$BinkList = foreach ($pubKey in $xmlContent.ProductKeyConfiguration.PublicKeys.PublicKey) {
    [PSCustomObject]@{ GroupId = $pubKey.GroupId; AlgorithmId = $pubKey.AlgorithmId; PublicKeyValue = $pubKey.PublicKeyValue }
}

$BinkList | % {

    $BinkBytes = [System.Convert]::FromBase64String($_.PublicKeyValue)
    $declared  = [BitConverter]::ToUInt32($BinkBytes, 0)
    if ($declared -ne $BinkBytes.Length) {
        Write-Host ("Warning: blob says {0} bytes, file is {1}; core will reject with 0x80041053 upstream." -f $declared, $BinkBytes.Length) -ForegroundColor Yellow
    }

    $pKey   = [Marshal]::AllocHGlobal($BinkBytes.Length)
    $pKS    = [Marshal]::AllocHGlobal($keyStruct.Length)
    $pRec   = [Marshal]::AllocHGlobal($recon.Length)
    $pOutA  = [Marshal]::AllocHGlobal(8)
    $pOutB  = [Marshal]::AllocHGlobal(8)
    [Marshal]::Copy($BinkBytes, 0, $pKey, $BinkBytes.Length)
    [Marshal]::Copy($keyStruct, 0, $pKS,  $keyStruct.Length)
    [Marshal]::Copy($recon,     0, $pRec, $recon.Length)
    [Marshal]::WriteInt64($pOutA, 0)
    [Marshal]::WriteInt64($pOutB, 0)

    try {
        # mode = 4  (wrapper passes r8d = 4)
        $hr = $coreFunc.Invoke($pKey, $pKS, 4, $pRec, $pOutA, $pOutB)

        if ($hr -eq 0) {
            
            # POST: replicate wrapper field decode (D149..D192), object not needed.
            # v = little-endian uint32 of keyStruct[0..3]
            [uint32]$v = [BitConverter]::ToUInt32($keyStruct, 0)
            $upgrade  = [int]($v -band 1)
            $value    = $v -shr 1
            $channel  = [int]([math]::Floor($value / 1000000))
            $sequence = [int]($value % 1000000)
            $outA     = [Marshal]::ReadInt32($pOutA)
            $outB     = [Marshal]::ReadInt32($pOutB)

            Write-Host ''
            Write-Host ("=== PKEY{0} core result (one level below) ===" -f $Algo) -ForegroundColor Green
            Write-Host  'Status       : Valid Key (core returned 0)'
            Write-Host ('Group        : {0}' -f $_.GroupID)
            Write-Host ('Upgrade Flag : {0}' -f $upgrade)
            Write-Host ('Channel      : {0:D3}' -f $channel)
            Write-Host ('Sequence     : {0:D6}' -f $sequence)
            Write-Host ('out A / out B: 0x{0:X8} / 0x{1:X8}' -f $outA, $outB)

            break

        } else {

            $why = switch ([int32]$hr) {
                0x80041051 { 'key does not belong to this public key' }
                0x0000000A { 'HeapAlloc failed inside core (0xA)' }
                default    { 'core rejected key' }
            }
            Write-Warning ('Core returned 0x{0:X8} - {1}.' -f $hr, $why)
        }
    }
    finally {
        [Marshal]::FreeHGlobal($pKey)
        [Marshal]::FreeHGlobal($pKS)
        [Marshal]::FreeHGlobal($pRec)
        [Marshal]::FreeHGlobal($pOutA)
        [Marshal]::FreeHGlobal($pOutB)
    }
}

Write-Host