
# =====================================================================
#  Pkey2009 validator
#    [BinaryKey]          - decodes a product key (group / serial / security / checksum)
#    New-PKeyConfigIndex  - scans *.xrm-ms files in a folder, writes the index into that folder
#    Get-PKeyConfigGroup  - returns the Configurations (with KeyRanges) of RefGroupIds
#    Test-PKey            - validates product keys against the index
#  Two ways to point at the index (both work on every function):
#    -Path <folder>      index is <folder>\pkey2009-index.json, built automatically on
#                        first use (or when it's an old format)
#    -IndexFile <json>   use that JSON directly (no xrm-ms folder needed, never rebuilt)
#  Edit the values in the "RUN" section at the bottom, then run the script.
# =====================================================================

#region Helpers
class BinaryKey {
    
    [uint32]$Group            # 20 bits (groups like 100055 do not fit in uint16)
    [uint32]$Serial
    [uint64]$Security
    [bool]$IsNKey
    [bool]$IsUpgrade          # bit 113
    [int32]$Checksum          # CRC computed from the key data
    [int32]$StoredChecksum    # CRC stored inside the key (bits 103..112)
    [bool]$IsChecksumValid
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
        $this.FillCheckInfo()
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
        $this.FillCheckInfo()
    }
    BinaryKey([uint16]$Group, [uint32]$Serial, [uint64]$Security, [bool]$IsNKey = $true, [bool]$Stream = $true) {
        $this.BinaryData = [BinaryKey]::FormatBinaryKey($Group, $Serial, $Security, $IsNKey, $Stream)
        $this.Group = $Group
        $this.Serial = $Serial
        $this.Security = $Security
        $this.IsNKey = $IsNKey
        $this.CdKey = [BinaryKey]::DecodeBinaryKey($this.BinaryData)
        $this.Checksum = [BinaryKey]::GetKeyChecksum($this.BinaryData)
        $this.FillCheckInfo()
    }

    hidden [void] FillCheckInfo() {
        $b = $this.BinaryData
        $this.StoredChecksum  = [BinaryKey]::GetStoredChecksum($b)
        $this.IsChecksumValid = ($this.StoredChecksum -eq $this.Checksum)
        $this.IsUpgrade       = (($b[14] -band 0x02) -ne 0)
    }

    # CRC-10 stored in the key: bit 103 (byte12 b7), bits 104..111 (byte13), bit 112 (byte14 b0)
    static [int] GetStoredChecksum([byte[]]$Data) {
        return [int]((($Data[12] -shr 7) -band 1) -bor ([int]$Data[13] -shl 1) -bor (([int]$Data[14] -band 1) -shl 9))
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
                Group    = [uint32]($Value -band 0xFFFFF)
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
                Group    = [uint32](Get-Bits $BinaryData 0 20)
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
function New-PKeyConfigIndex {
    <#
    .SYNOPSIS
        Builds a JSON index of pkey/2009 Configurations + KeyRanges from pkeyconfig *.xrm-ms files.
        Keyed by RefGroupId. Every Configuration of a group is kept (a group can hold several,
        the serial's KeyRange decides which one applies). Identical Configurations / KeyRanges
        found in several files are merged.
    .OUTPUTS
        Hashtable of stats. The index is written to -IndexFile, or by default into the
        -Path folder as pkey2009-index.json.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [string]$IndexFile,
        [switch]$Recurse,
        [string]$Filter    = '*.xrm-ms',
        [string]$Algorithm = 'msft:rm/algorithm/pkey/2009'
    )

    if (-not $IndexFile) { $IndexFile = Join-Path $Path 'pkey2009-index.json' }

    # --- local helpers (kept inside so the function is self-contained) ---
    $decode = {
        param([byte[]]$b)
        if ($b.Length -ge 3 -and $b[0] -eq 0xEF -and $b[1] -eq 0xBB -and $b[2] -eq 0xBF) { return [Text.Encoding]::UTF8.GetString($b, 3, $b.Length - 3) }
        if ($b.Length -ge 2 -and $b[0] -eq 0xFF -and $b[1] -eq 0xFE) { return [Text.Encoding]::Unicode.GetString($b, 2, $b.Length - 2) }
        if ($b.Length -ge 2 -and $b[0] -eq 0xFE -and $b[1] -eq 0xFF) { return [Text.Encoding]::BigEndianUnicode.GetString($b, 2, $b.Length - 2) }
        if ($b.Length -ge 2 -and $b[1] -eq 0) { return [Text.Encoding]::Unicode.GetString($b) }
        return [Text.Encoding]::UTF8.GetString($b)
    }
    $text = {
        param($node, [string]$name)
        $n = $node.SelectSingleNode("*[local-name()='$name']")
        if ($n) { $n.InnerText.Trim() } else { $null }
    }

    $infoBinRx = [regex]'<(?:\w+:)?infoBin\s+name="pkeyConfigData"\s*>\s*([A-Za-z0-9+/=\s]+?)\s*</(?:\w+:)?infoBin>'

    $gci = @{ Path = $Path; Filter = $Filter; File = $true; ErrorAction = 'Stop' }
    if ($Recurse) { $gci.Recurse = $true }
    $files = @(Get-ChildItem @gci | Sort-Object FullName)

    $groupsIdx = @{}   # RefGroupId -> @{ ActConfigId -> config }
    $rangeSeen = @{}   # "act|start|end|part" -> $true
    $stats = [ordered]@{
        FilesScanned      = 0
        FilesWithPkey2009 = 0
        FilesSkipped      = 0
        FilesFailed       = 0
        Groups            = 0
        Configurations    = 0
        KeyRanges         = 0
    }

    $i = 0
    foreach ($f in $files) {
        $i++
        if ($i % 200 -eq 0) {
            Write-Progress -Activity 'Indexing pkey/2009 configurations' -Status "$i / $($files.Count)" -PercentComplete (100 * $i / $files.Count)
        }
        $stats.FilesScanned++
        try {
            $m = $infoBinRx.Match([IO.File]::ReadAllText($f.FullName))
            if (-not $m.Success) { $stats.FilesSkipped++; continue }

            $xml = New-Object Xml.XmlDocument
            $xml.XmlResolver = $null
            $xml.LoadXml((& $decode ([Convert]::FromBase64String(($m.Groups[1].Value -replace '\s', '')))))

            # GroupIds that use the requested algorithm
            $groups = @{}
            foreach ($pk in $xml.SelectNodes("//*[local-name()='PublicKey']")) {
                if ((& $text $pk 'AlgorithmId') -eq $Algorithm) {
                    $g = & $text $pk 'GroupId'
                    if ($g) { $groups[$g] = $true }
                }
            }
            if ($groups.Count -eq 0) { $stats.FilesSkipped++; continue }
            $stats.FilesWithPkey2009++

            # Configurations of those groups (this file)
            $fileCfg = @{}   # ActConfigId -> config object (merged one)
            foreach ($cfg in $xml.SelectNodes("//*[local-name()='Configuration']")) {
                $ref = & $text $cfg 'RefGroupId'
                if (-not $ref -or -not $groups.ContainsKey($ref)) { continue }
                $act = (& $text $cfg 'ActConfigId').ToLowerInvariant()

                if (-not $groupsIdx.ContainsKey($ref)) { $groupsIdx[$ref] = [ordered]@{}; $stats.Groups++ }
                if (-not $groupsIdx[$ref].Contains($act)) {
                    $groupsIdx[$ref][$act] = [ordered]@{
                        RefGroupId         = [int]$ref
                        ActConfigId        = $act
                        EditionId          = & $text $cfg 'EditionId'
                        ProductDescription = & $text $cfg 'ProductDescription'
                        ProductKeyType     = & $text $cfg 'ProductKeyType'
                        IsRandomized       = ((& $text $cfg 'IsRandomized') -eq 'true')
                        SourceFile         = $f.FullName
                        KeyRanges          = New-Object 'System.Collections.Generic.List[object]'
                    }
                    $stats.Configurations++
                }
                $fileCfg[$act] = $groupsIdx[$ref][$act]
            }

            # KeyRanges of those configurations
            foreach ($kr in $xml.SelectNodes("//*[local-name()='KeyRange']")) {
                $act = & $text $kr 'RefActConfigId'
                if (-not $act) { continue }
                $act = $act.ToLowerInvariant()
                if (-not $fileCfg.ContainsKey($act)) { continue }

                $start = [uint32](& $text $kr 'Start')
                $end   = [uint32](& $text $kr 'End')
                $part  = & $text $kr 'PartNumber'
                $rk    = "$act|$start|$end|$part"
                if ($rangeSeen.ContainsKey($rk)) { continue }
                $rangeSeen[$rk] = $true

                $fileCfg[$act].KeyRanges.Add([ordered]@{
                    Start      = $start
                    End        = $end
                    PartNumber = $part
                    EulaType   = & $text $kr 'EulaType'
                    IsValid    = ((& $text $kr 'IsValid') -eq 'true')
                })
                $stats.KeyRanges++
            }
        }
        catch {
            $stats.FilesFailed++
            Write-Warning "$($f.FullName): $($_.Exception.Message)"
        }
    }
    Write-Progress -Activity 'Indexing pkey/2009 configurations' -Completed

    $outGroups = [ordered]@{}
    foreach ($g in ($groupsIdx.Keys | Sort-Object { [int]$_ })) {
        $outGroups[$g] = @($groupsIdx[$g].Values)
    }
    $out = [ordered]@{ Format = 2; Algorithm = $Algorithm; Groups = $outGroups }

    [IO.File]::WriteAllText($IndexFile, ($out | ConvertTo-Json -Depth 8 -Compress), (New-Object Text.UTF8Encoding $false))
    $stats
}
function Get-PKeyConfigGroup {
    <#
    .SYNOPSIS
        Returns every Configuration (with its KeyRanges) for each RefGroupId.
          -Path <folder>     uses <folder>\pkey2009-index.json; builds it first if it is
                             missing or in an old format (needs New-PKeyConfigIndex).
          -IndexFile <json>  uses that JSON directly; never rebuilt.
        Missing ids produce a warning. Delete pkey2009-index.json to force a rebuild.
    #>
    [CmdletBinding(DefaultParameterSetName = 'Folder')]
    param(
        [Parameter(Mandatory, ParameterSetName = 'Folder')]
        [string]$Path,

        [Parameter(Mandatory, ParameterSetName = 'File')]
        [string]$IndexFile,

        [Parameter(Mandatory)]
        [int[]]$RefGroupId
    )

    $fromFolder = ($PSCmdlet.ParameterSetName -eq 'Folder')
    if ($fromFolder) {
        $IndexFile = Join-Path $Path 'pkey2009-index.json'
    }
    elseif (-not (Test-Path -LiteralPath $IndexFile -PathType Leaf)) {
        throw "Index file not found: $IndexFile"
    }

    # Cache the parsed index per session (reloaded if the file changes)
    if (-not (Get-Variable -Name PKeyIndexCache -Scope Script -ErrorAction SilentlyContinue)) { $script:PKeyIndexCache = @{} }
    $load = {
        $fi = Get-Item -LiteralPath $IndexFile
        $c  = $script:PKeyIndexCache[$fi.FullName]
        if ($c -and $c.Stamp -eq $fi.LastWriteTimeUtc) { return $c.Data }
        $d = Get-Content -LiteralPath $IndexFile -Raw | ConvertFrom-Json
        $script:PKeyIndexCache[$fi.FullName] = @{ Stamp = $fi.LastWriteTimeUtc; Data = $d }
        $d
    }

    $idx = $null
    if (Test-Path -LiteralPath $IndexFile) {
        $idx = & $load
        if (-not $idx.PSObject.Properties['Format'] -or $idx.Format -lt 2) {
            if (-not $fromFolder) {
                throw "Old index format in $IndexFile - rebuild it with New-PKeyConfigIndex (or use -Path <folder>)"
            }
            Write-Host "Old index format in $Path - rebuilding..." -ForegroundColor Yellow
            $idx = $null
        }
    }
    else {
        Write-Host "No index in $Path - building..." -ForegroundColor Yellow
    }
    if (-not $idx) {
        New-PKeyConfigIndex -Path $Path -Recurse | Out-Null
        $idx = & $load
    }

    foreach ($id in $RefGroupId) {
        $p = $idx.Groups.PSObject.Properties["$id"]
        if ($p) { $p.Value }
        else    { Write-Warning "RefGroupId $id not found in index" }
    }
}
function Test-PKey {
    <#
    .SYNOPSIS
        Validates pkey/2009 product keys offline against the pkeyconfig index.
          -Path <folder>     index in that folder (built automatically if missing)
          -IndexFile <json>  that JSON directly
    .DESCRIPTION
        Checks, in order:
          1. Format    - 25 chars, valid alphabet, decodes to 16 bytes
          2. NKey      - pkey/2009 keys carry the N flag
          3. Checksum  - CRC-10 stored in the key == CRC computed from the key data
          4. Group     - key's group exists as a pkey/2009 RefGroupId in the index
          5. Range     - key's serial falls inside a KeyRange of one of that group's
                         Configurations, and that range is IsValid=true
        The first failing check sets Status and stops. The Security field cannot be
        verified offline (that check is done by the activation server).
        Needs the BinaryKey class and Get-PKeyConfigGroup / New-PKeyConfigIndex.
    #>
    [CmdletBinding(DefaultParameterSetName = 'Folder')]
    param(
        [Parameter(Mandatory, ParameterSetName = 'Folder')]
        [string]$Path,

        [Parameter(Mandatory, ParameterSetName = 'File')]
        [string]$IndexFile,

        [Parameter(Mandatory, ValueFromPipeline)]
        [string[]]$ProductKey
    )

    begin {
        # Where Get-PKeyConfigGroup should look (same parameter set as this call)
        $src = if ($PSCmdlet.ParameterSetName -eq 'Folder') { @{ Path = $Path } } else { @{ IndexFile = $IndexFile } }
    }

    process {
        foreach ($key in $ProductKey) {
            $r = [ordered]@{
                ProductKey         = $key
                IsValid            = $false
                Status             = $null
                Group              = $null
                Serial             = $null
                Security           = $null
                IsUpgrade          = $null
                Checksum           = $null
                ActConfigId        = $null
                EditionId          = $null
                ProductDescription = $null
                ProductKeyType     = $null
                PartNumber         = $null
                EulaType           = $null
                SourceFile         = $null
            }

            # 1. Format
            try { $bk = [BinaryKey]::new([string]$key.Trim()) }
            catch {
                $r.Status = "Invalid format: $($_.Exception.InnerException.Message)"
                if (-not $_.Exception.InnerException) { $r.Status = "Invalid format: $($_.Exception.Message)" }
                [pscustomobject]$r; continue
            }
            $r.ProductKey = $bk.CdKey.ToUpperInvariant()
            $r.Group      = $bk.Group
            $r.Serial     = $bk.Serial
            $r.Security   = ('0x{0:X}' -f $bk.Security)
            $r.IsUpgrade  = $bk.IsUpgrade
            $r.Checksum   = ('{0} / {1}' -f $bk.StoredChecksum, $bk.Checksum)   # stored / computed

            # 2. NKey
            if (-not $bk.IsNKey) { $r.Status = 'Not a pkey/2009 key (no N flag)'; [pscustomobject]$r; continue }

            # 3. Checksum
            if (-not $bk.IsChecksumValid) { $r.Status = 'Checksum mismatch'; [pscustomobject]$r; continue }

            # 4. Group
            $configs = @(Get-PKeyConfigGroup @src -RefGroupId $bk.Group -WarningAction SilentlyContinue)
            if ($configs.Count -eq 0) { $r.Status = "Group $($bk.Group) not found in index"; [pscustomobject]$r; continue }

            # 5. Range
            $hitCfg = $null; $hitRange = $null
            foreach ($c in $configs) {
                foreach ($kr in @($c.KeyRanges)) {
                    if ($bk.Serial -ge [uint32]$kr.Start -and $bk.Serial -le [uint32]$kr.End) {
                        $hitCfg = $c; $hitRange = $kr
                        if ($kr.IsValid) { break }
                    }
                }
                if ($hitRange -and $hitRange.IsValid) { break }
            }

            if (-not $hitCfg) {
                # Group is known but serial is outside every range: still report the edition if unambiguous
                if ($configs.Count -eq 1) {
                    $r.ActConfigId = $configs[0].ActConfigId; $r.EditionId = $configs[0].EditionId
                    $r.ProductDescription = $configs[0].ProductDescription; $r.ProductKeyType = $configs[0].ProductKeyType
                }
                $r.Status = "Serial $($bk.Serial) outside all KeyRanges of group $($bk.Group)"
                [pscustomobject]$r; continue
            }

            $r.ActConfigId        = $hitCfg.ActConfigId
            $r.EditionId          = $hitCfg.EditionId
            $r.ProductDescription = $hitCfg.ProductDescription
            $r.ProductKeyType     = $hitCfg.ProductKeyType
            $r.PartNumber         = $hitRange.PartNumber
            $r.EulaType           = $hitRange.EulaType
            $r.SourceFile         = $hitCfg.SourceFile

            if ($hitRange.IsValid) { $r.IsValid = $true; $r.Status = 'Valid' }
            else                   { $r.Status = 'KeyRange is marked IsValid=false (blocked range)' }

            [pscustomobject]$r
        }
    }
}
#endregion

# =====================================================================
#  RUN - edit these values (use ONE of the two sources)
# =====================================================================

$ProductKeys = '33CY4-NPKCC-V98JP-42G8W-VH636', 'NH7W7-BMC3R-4W9XT-94B6D-TCQG3', 'NTRHT-XTHTG-GBWCG-4MTMP-HH64C'
$IndexJson   = Join-Path $PSScriptRoot 'pkey2009-index.json'
Test-PKey -IndexFile $IndexJson -ProductKey $ProductKeys | Format-List

<#
$ProductKeys   = '33CY4-NPKCC-V98JP-42G8W-VH636', 'NH7W7-BMC3R-4W9XT-94B6D-TCQG3', 'NTRHT-XTHTG-GBWCG-4MTMP-HH64C'
$LicenseFolder = Join-Path $PSScriptRoot 'PKeyConfigs'
Test-PKey -Path $LicenseFolder -ProductKey $ProductKeys | Format-List
#>

return