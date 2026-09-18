using namespace System
using namespace System.IO
using namespace System.Text
using namespace System.Numerics
using namespace System.Reflection
using namespace System.IO.Compression
using namespace System.Collections.Generic
using namespace System.Management.Automation
using namespace System.Runtime.InteropServices

<#
 Etc, How it find the key.
 sub_18000E8E8, >> 

 ECC, Group, Here:
 </pkc:PublicKey><pkc:PublicKey>
	<pkc:GroupId>??</pkc:GroupId>
	<pkc:AlgorithmId>msft:rm/algorithm/pkey/2005</pkc:AlgorithmId>
	<pkc:PublicKeyValue>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</pkc:PublicKeyValue>
</pkc:PublicKey><pkc:PublicKey>

SO, it compare our info Raw msft 2005 info to << PublicKeyValue 

--- Raw v75 Buffer Extraction Results ---
--- Total: 96 bytes | Alignment: 16x ---
0000 : 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0010 : 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0020 : 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0030 : 01 00 00 00 00 00 00 00 67 DE 1C 56 9C 03 AE E2
0040 : B7 87 63 E4 69 E2 02 00 00 00 00 00 00 00 00 00
0050 : 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00

Same ????, now you can decrypt the binary, and you also have the << <pkc:GroupId
#>

<#
typedef struct _MSFT_PKEY_DATA {
    uint64_t Reserved;             // 0x00 (0x20 relative to PID_OBJ)
    wchar_t* ProductIdStr;         // 0x08 -> Points to "msft2005:[GUID]&[Base64->MatrixAddress-0x68]"
    void*    UnknownPtr1;          // 0x10 -> Int64 Address Pointer
    uint32_t GroupID;              // 0x18 (0x38) - e.g., 189
    uint32_t Serial_A;             // 0x1C (0x3C) - Serial Part, Partial
    uint32_t Serial_B;             // 0x20 (0x40) - Serial Part, Partial
    uint32_t LicenseFlags;         // 0x24 (0x44) - Upgrade flag & lower bits
    uint64_t Security              // 0x28 (0x48) - Security Value
    uint32_t StatusFlag1;          // 0x30 (0x50) - Status/Mode value 1
    uint32_t StatusFlag2;          // 0x34 (0x54) - Status/Mode value 2
    uint8_t  RawKeyMaterial[16];   // 0x38 (0x58) - RAW CD KEY Bytes  
} MSFT_PKEY_DATA;                  // Total Size: 0x48 bytes (72 decimal)                   // Total Size: 0x48 bytes

typedef struct _PID_OBJ {
    uint64_t        RefCount;          // 0x00
    wchar_t*        ProductIdStr;      // 0x08
    FILETIME        ValidationTime;    // 0x10
    uint32_t        DataIdSequence;    // 0x18, Serial Part, Full, As INT32
    uint32_t        AlignmentPadding;  // 0x1C
    MSFT_PKEY_DATA  Data;              // 0x20 - 0x68
    void*    pPKeyConfig;              // 0x68 - XRM-MS matrix row
    void*    pKeyBits;                 // 0x70
    void*    pMetadata;                // 0x78
    uint64_t UnknownTail;              // 0x80
} PID_OBJ;
#>

function Format-HexView {
    [CmdletBinding(DefaultParameterSetName = "ByteArray")]
    param (
        # Parameter Set 1: Standard Byte Array Input
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ParameterSetName = "ByteArray")]
        [byte[]]$Data,

        # Parameter Set 2: Direct Unmanaged Pointer Input
        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = "Pointer")]
        [IntPtr]$Address,

        [Parameter(Mandatory = $true, Position = 1, ParameterSetName = "Pointer")]
        [int]$Size,

        [ValidateSet("4x", "8x", "16x")]
        [string]$Mode = "8x"
    )

    begin {
        $fullBuffer = [System.Collections.Generic.List[byte]]::new()
        $Count = [int]($Mode.Replace("x", ""))
        
        if ($PsCmdlet.ParameterSetName -eq "Pointer") {
            if ($Address -eq [IntPtr]::Zero -or $Size -le 0) {
                Write-Error "Invalid memory pointer address or size requested."
                return
            }
            $tempArray = [byte[]]::new($Size)
            [System.Runtime.InteropServices.Marshal]::Copy($Address, $tempArray, 0, $Size)
            $fullBuffer.AddRange($tempArray)
        }
    }
    process {
        # Validated: Null check keeps 0x00 bytes intact through pipeline unrolling
        if ($PsCmdlet.ParameterSetName -eq "ByteArray" -and $null -ne $Data) {
            $fullBuffer.AddRange($Data)
        }
    }
    end {
        if ($fullBuffer.Count -eq 0) {
            Write-Warning "Hex view buffer is empty."
            return
        }

        Write-Host "--- Total: $($fullBuffer.Count) bytes | Alignment: $Mode ---" -ForegroundColor Cyan
        
        for ($i = 0; $i -lt $fullBuffer.Count; $i += $Count) {
            $remaining = [Math]::Min($Count, $fullBuffer.Count - $i)
            
            $hexElements = [string[]]::new($remaining)
            for ($j = 0; $j -lt $remaining; $j++) {
                $hexElements[$j] = "{0:X2}" -f $fullBuffer[$i + $j]
            }
            
            $hexPart = $hexElements -join " "
            "{0:X4} : {1}" -f $i, $hexPart
        }
    }
}
Function Install-NativeModule {
    try {
        $repoUrl = "https://github.com/v8k6b2jjps-prog/Unmanaged.PS1.Library/archive/refs/heads/main.zip"
        $moduleFolder = "C:\Windows\System32\WindowsPowerShell\v1.0\Modules\NativeInteropLib"
        $tempFolder = "$env:TEMP\Unmanaged.PS1.Library"
        $zipFile = "$tempFolder.zip"

        Invoke-WebRequest -Uri $repoUrl -OutFile $zipFile
        Expand-Archive -Path $zipFile -DestinationPath $tempFolder -Force
        if (-not (Test-Path $moduleFolder)) { New-Item -Path $moduleFolder -ItemType Directory }
        Copy-Item -Path "$tempFolder\Unmanaged.PS1.Library-main\*" -Destination $moduleFolder -Recurse -Force | Out-Null
        Remove-Item -Path $zipFile -Force | Out-Null
        Remove-Item -Path $tempFolder -Recurse -Force | Out-Null
    } catch {
    }
}

if (!([PSTypeName]'NativeInterop').Type) {
  Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public class NativeInterop {

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate int Delegate4Args(long p1, IntPtr p2, long p3, long p4);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate int Delegate8Args(long p1, long p2, IntPtr p3, long p4, long p5, long p6, long p7, IntPtr p8);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate int Delegate2PtrArgs(IntPtr p1, IntPtr p2);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate int DelegateGenArgs(IntPtr p1, long p2, long p3, out IntPtr p4);

    public static IntPtr GetTargetAddress(IntPtr hModule, long rva) {
        long offset = rva >= 0x180000000 ? rva - 0x180000000 : rva;
        return new IntPtr(hModule.ToInt64() + offset);
    }

    public static int Call(IntPtr funcAddress, long p1, IntPtr p2, long p3, long p4) {
        return Marshal.GetDelegateForFunctionPointer<Delegate4Args>(funcAddress)(p1, p2, p3, p4);
    }

    public static int Call(IntPtr funcAddress, long p1, long p2, IntPtr p3, long p4, long p5, long p6, long p7, IntPtr p8) {
        return Marshal.GetDelegateForFunctionPointer<Delegate8Args>(funcAddress)(p1, p2, p3, p4, p5, p6, p7, p8);
    }

    public static int Call(IntPtr funcAddress, IntPtr p1, IntPtr p2) {
        return Marshal.GetDelegateForFunctionPointer<Delegate2PtrArgs>(funcAddress)(p1, p2);
    }

    public static int Call(IntPtr funcAddress, IntPtr p1, long p2, long p3, out IntPtr p4) {
        return Marshal.GetDelegateForFunctionPointer<DelegateGenArgs>(funcAddress)(p1, p2, p3, out p4);
    }
}
"@
}

try {
    Import-Module NativeInteropLib -ErrorAction Stop
} catch {
    Install-NativeModule
    Import-Module NativeInteropLib -ErrorAction Stop
}

Clear-Host
Write-Host

$CdKey   = 'RHTBY-VWY6D-QJRJ9-JGQ3X-Q2289'
$DllPath = Join-Path $PSScriptRoot "pidgenx64.dll"
$CfgPath = Join-Path $PSScriptRoot "pkeyconfig.xrm-ms"
$iid2005 = Join-Path $PSScriptRoot "iid2005.py"
$valPath = Join-Path $PSScriptRoot "Validator"
$valExe  = Join-Path $PSScriptRoot "Validator\Validator.exe"
$hModule = Ldr-LoadDll -dwFlags ALTERED_SEARCH -dll $DllPath

$tmpPtr  = New-IntPtr -Size 8
$func1 = [NativeInterop]::GetTargetAddress($hModule, 0x180015270)
[NativeInterop]::Call($func1, $tmpPtr, [IntPtr]::Zero) | Out-Null
$Address = [Marshal]::ReadIntPtr($tmpPtr)
[Marshal]::FreeHGlobal($tmpPtr)

$CfgPtr = [Marshal]::StringToHGlobalUni($CfgPath)
$func2  = [NativeInterop]::GetTargetAddress($hModule, 0x18000C970)
[Marshal]::FreeHGlobal($CfgPtr)

Write-Host "Loading 7601 Configuration Rules..." -ForegroundColor Cyan
$hr = [NativeInterop]::Call($func2, $Address.ToInt64(), $CfgPtr, 0L, 0L)
Write-Host "Loader Return HRESULT: 0x$($hr.ToString('X'))`n"

# ==========================================
# STEP 2 & 3: ALLOCATE INPUT & EXECUTE DISPATCHER
# ==========================================
$KeyPtr    = [Marshal]::StringToHGlobalUni($CdKey)
$OutObjPtr = [Marshal]::AllocHGlobal(8)
[Marshal]::WriteInt64($OutObjPtr, 0)

$func3 = [NativeInterop]::GetTargetAddress($hModule, 0x180009338)

Write-Host "Invoking sub_180009338 Directly..." -ForegroundColor Cyan
$hr = [NativeInterop]::Call($func3, ([Int64]$Address + 0x10), 0L, $KeyPtr, 0L, 0L, 0L, 0L, $OutObjPtr)
Write-Host "Direct Subroutine HRESULT: 0x$($hr.ToString('X'))"

$HeapPtr = [Marshal]::ReadIntPtr($OutObjPtr)
[Marshal]::FreeHGlobal($OutObjPtr)
if ([long]$HeapPtr -le 0) { return }

# Parse and Extract Struct Metadata Fields
$KeyIDValue    = [Marshal]::ReadInt32($HeapPtr, 0x18) # Serial
$GroupIDValue  = [Marshal]::ReadByte($HeapPtr,  0x38) # Group
$SecurityValue = [Marshal]::ReadInt64($HeapPtr, 0x48) # Security
$LicenseFlags  = [Marshal]::ReadInt32($HeapPtr, 0x44) # Flags
$UpgradeText   = if (($LicenseFlags -band 0x1) -eq 1) { "Yes" } else { "No" }

# NEW: Read the nested pointer at offset +8, then decode the Wide String
$StringPtr        = [Marshal]::ReadIntPtr($HeapPtr, 8)
$FinalString      = "NULL"
if ($StringPtr -ne [IntPtr]::Zero) {
    $FinalString = [Marshal]::PtrToStringUni($StringPtr)
}

Write-Host "`n--- Decoded Fields ---" -ForegroundColor Green
Write-Host "IsUpgrade    : $UpgradeText"
Write-Host "Group ID     : $GroupIDValue (0x$($GroupIDValue.ToString('X')))"
Write-Host "Serial       : $KeyIDValue (0x$($KeyIDValue.ToString('X')))"
Write-Host "Security     : $SecurityValue (0x$($SecurityValue.ToString('X')))" -ForegroundColor Cyan
Write-Host "Final String : $FinalString" -ForegroundColor Yellow
Write-Host

$SerialA = [Marshal]::ReadInt32($HeapPtr, 0x3C)
$SerialB = [Marshal]::ReadInt32($HeapPtr, 0x40)
Write-Host "Serial A (0x3C)  : $SerialA (0x$($SerialA.ToString('X')))"
Write-Host "Serial B (0x40)  : $SerialB (0x$($SerialB.ToString('X')))"
Write-Host ("Serial Full      : {0}" -f ($SerialA.ToString() + $SerialB.ToString()))
Write-Host

Format-HexView -Address $HeapPtr -Size 128 -Mode 16x

# STEP 4: EXECUTE BASE MATH LAYER PARSER BLOCK (sub_1800090B0)
$v75Buffer  = New-IntPtr -Size 96
$func4     = [NativeInterop]::GetTargetAddress($hModule, 0x1800090B0)

Write-Host "`nInvoking Base Math Parser (sub_1800090B0)..." -ForegroundColor Cyan
$hr = [NativeInterop]::Call($func4, $KeyPtr, $v75Buffer)
Write-Host "Math Layer HRESULT: 0x$($hr.ToString('X'))"

if ($hr -eq 0) {
    Write-Host "`n--- Raw v75 Buffer Extraction Results ---" -ForegroundColor Green
    Format-HexView -Address $v75Buffer -Size 96 -Mode 16x
}
Free-IntPtr $v75Buffer -Method Auto

# =====================================================================
# NEW STEP: MANUALLY MANUFACTURE AND BASE64 ENCODE THE MATERIAL 
# =====================================================================
Write-Host
Write-Host "Re-manufacturing the 12-Byte Material Block..." -ForegroundColor Cyan

# 1. Grab the live pointer sitting at row 0060, offset 0x68 (104 decimal)
$ConfigRowPtr = [Marshal]::ReadIntPtr($HeapPtr, 104)

if ($ConfigRowPtr -ne [IntPtr]::Zero) {

    $RawMaterialBuffer = New-IntPtr -Size 12
    [Marshal]::WriteInt64($RawMaterialBuffer, 0, $ConfigRowPtr.ToInt64())
    [Marshal]::WriteInt32($RawMaterialBuffer, 8, 0)
    Write-Host "`n--- Raw Material Structure (Before Base64) ---" -ForegroundColor Green
    Format-HexView -Address $RawMaterialBuffer -Size 12 -Mode 4x

    $managedBytes = New-Object Byte[] 12
    [Marshal]::Copy($RawMaterialBuffer, $managedBytes, 0, 12)
    $base64String = [Convert]::ToBase64String($managedBytes)

    Write-Host
    Write-Host "--- Base64 Encoded Result ---" -ForegroundColor Cyan
    Write-Host $base64String

} else {
    Write-Warning "Could not extract a valid Config Row Pointer from offset 104."
}

# MSFT2005 Pkey Generator
# https://github.com/ntriver-org/PKeyMaster/commit/4926123bc7e56882dc13123942c3459728fb562c

[long]$serial   = $KeyIDValue
[long]$security = $SecurityValue
[int32]$upgrade = [Int](($LicenseFlags -band 0x1) -eq 1)

[BigInteger]$act_hash = [BigInteger]$upgrade -band 1
$act_hash = $act_hash -bor (([BigInteger]$serial -band ((1L -shl 30) - 1)) -shl 1)
$act_hash = $act_hash -bor (([BigInteger]$security -band ((1L -shl 20) - 1)) -shl 31)
$bytes = $act_hash.ToByteArray()
$KeyData = New-Object 'Byte[]' 12
[Array]::Copy($bytes, 0, $KeyData, 0, [Math]::Min(12, $bytes.Length))
$act_data = [Convert]::ToBase64String($KeyData)

Write-Host
Write-Host "--- Base64 Encoded Result ---" -ForegroundColor Cyan
$act_data

# ==========================================
# RE-ENCODE / GENERATE IID (sub_1800065DC)
# ==========================================

Write-Host "`n--- Re-Encoding Fields into IID String ---" -ForegroundColor Cyan

$bufSizeGen = 0x58
$bufferGen  = [byte[]]::new($bufSizeGen)
[Array]::Clear($bufferGen, 0,$bufferGen.Length)

#$SerialA = [Math]::Floor($Serial / 1000000)
#$SerialB = $Serial % 1000000

# Populate structure fields for generation
[BitConverter]::GetBytes([Int32]$GroupIDValue).CopyTo($bufferGen, 0x18) 
[BitConverter]::GetBytes([Int32]$SerialA).CopyTo($bufferGen, 0x1C) 
[BitConverter]::GetBytes([Int32]$SerialB).CopyTo($bufferGen, 0x20) 
[BitConverter]::GetBytes([Int32]0).CopyTo($bufferGen, 0x24)
[BitConverter]::GetBytes([Int32]$SecurityValue).CopyTo($bufferGen, 0x28)

$hBufferGen = New-IntPtr -Size $bufSizeGen
[Marshal]::Copy($bufferGen, 0, $hBufferGen,$bufSizeGen)

$hwidVal       = 0L
$pOutString    = ''
$outStrPtr     = [IntPtr]::Zero
$signatureBase = [IntPtr]::Add($hBufferGen, 0x8)

$funcGen = [NativeInterop]::GetTargetAddress($hModule, 0x1800065DC)
$hrGen = [NativeInterop]::Call($funcGen, $signatureBase, $hwidVal, 0L, [ref]$outStrPtr)
$pOutString = if ($outStrPtr -ne [IntPtr]::Zero) {
  [Marshal]::PtrToStringUni($outStrPtr) 
}
Free-IntPtr $hBufferGen -Method Auto
Write-Host "Generated IID String : $pOutString" -ForegroundColor Green

Write-Host
Write-Host "=== DEBUG: Running Python Decoder ===" -ForegroundColor Cyan

$pythonCmd = Get-Command python -ErrorAction SilentlyContinue
if ($pythonCmd) {

    $decodedData = @{}    
    $results = & python $iid2005 decode $pOutString
    
    foreach ($line in $results) {
        if ($line -match '^\s*([A-Za-z]+)\s*:\s*\[(.*?)\]') {
            $key = $Matches[1]
            $val = $Matches[2]
        
            if ($val -match '^0x[0-9a-fA-F]+$') {
                $decodedData[$key] = [Convert]::ToInt64($val, 16)
            } else {
                $decodedData[$key] = $val
            }
        }
    }
    
    # Extract specific values into clean variables
    $group    = $decodedData['Group']
    $serial   = $decodedData['Serial']
    $security = $decodedData['Security']

    # Print them to verify
    Write-Host "Group    : $group" -ForegroundColor Green
    Write-Host "Serial   : $serial" -ForegroundColor Green
    Write-Host "Security : $security" -ForegroundColor Green

} else {
    Write-Host "Python executable not found in PATH. Skipping automated validation step." -ForegroundColor Yellow
    Write-Host "Generated IID can still be verified manually." -ForegroundColor DarkGray
}

Write-Host
Write-Host "=== Invoke-Validator App ===" -ForegroundColor Green
Set-Location $valPath
& $valExe

Write-Host
return