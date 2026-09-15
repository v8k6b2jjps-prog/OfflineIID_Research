# MSFT 2009 Format + Offline IID Research Library
Include Source + Test Results

## Legal Notice & Disclaimer
This project is an independent research initiative intended solely for educational, archival, and software interoperability analysis. 
- **Proprietary Software & Trademarks:** All product names, trademarks, and proprietary binary formats referenced herein are the property of Microsoft Corporation. 
- **No Authorization for Bypass:** This repository does not provide tools, keys, or mechanisms designed to bypass software activation controls, violate licensing terms, or infringe upon Microsoft intellectual property. 
- **Limitation of Liability:** The author assumes no liability for any misuse of the information provided. Users are strictly required to ensure that their actions comply with all applicable local laws and Microsoft's terms of service.

## Security Value
````
Security ID Value cannot be fully recovered (Lossy / Truncated).
Parts are checked as boolean flags (e.g., BYTE11 checks if != 0), 
and the rest is bit-masked and chopped down into a smaller internal 32-bit field.
BYTE11(v53) = (*(_DWORD *)(a1 + 28) != 0 ? 8 : 0) | ...
````

## How to use
````
Group - 11
Serial - 22
Security - 33
HwidShort - 44

# - Native Dll

$bufferSize = 128
$OutStr = New-IntPtr -Size ($bufferSize * 2)
$values = 11, 22, 33, 44, $OutStr, $bufferSize
$result = Invoke-UnmanagedMethod -Dll $MsftHelperDll -Function GetInstallationIdString -Values $values

# 0..3, 4..7, 8..15, 16..23 # Sec, Group, Serial, ShortIID
$pDecodedParams = New-IntPtr -Size 24
$Values = $generatedIid, $pDecodedParams
$readResult = Invoke-UnmanagedMethod -Dll $MsftHelperDll -Function ReadParametersFromString -Values $Values

# - C# DLL

$generatedIid = ''
[Msft2009.MSFT]::GetInstallationIdString(11, 22, 33, 44, [ref]$generatedIid)

$decodedParams = [Activator]::CreateInstance([Type]'DecodedParameters')
$readResult = [Msft2009.MSFT]::ReadParametersFromString($generatedIid, [ref]$decodedParams);
````
## Test Results
````
GAC    Version        Location                                                                                                                                                                                                                  
---    -------        --------                                                                                                                                                                                                                  
False  v4.0.30319     D:\Software\MS Tools Pack\Product Key Tools\MSFT_2009\Testing\Msft2009.dll                                                                                                                                                

Extract HWID Value :  -7066209111506718658
Store HWID Value   :  -7066209111506718658
WinRT HWID Value   :  -7066209111506718658


--- Encode Values ---
Group ID:    5150
Serial:      80009470
Security ID: 34969266479148
HWID:        -7066209111506718658

Msft Dll Call results    : 631267238851209650325063288122616649605340181386226574961832720

Msft C# Dll Call results : 631267238851209650325063288122616649605340181386226574961832720

Pidgen Dll Call results  : 631267238851209650325063288122616649605340181386226574961832720

--- Native DLL Decoded Successfully ---
Group ID:    5150
Serial:      80009470
Security ID: 179626028
HWID:        -7066209111506718658

--- .Net C# Decoded Successfully ---
Group ID:    5150
Serial:      80009470
Security ID: 179626028
HWID:        -7066209111506718658

Read / Validate Test .. . . 
is IID matching ? True



PS C:\Users\Administrator> 
````
# MSFT 2005 Test 
Extra part, MSFT 2005 Test script
````powershell

Loading 7601 Configuration Rules...
Loader Return HRESULT: 0x0

Invoking sub_180009338 Directly...
Direct Subroutine HRESULT: 0x0

--- Decoded Fields ---
IsUpgrade    : No
Group ID     : 189 (0xBD)
Serial       : 69673552 (0x4272250)
Security     : 847 (0x34F)
Final String : msft2005:a0cde89c-3304-4157-b61c-c8ad785d1fad&oEROiKcBAAAAAAAA

Serial A (0x3C)  : 69 (0x45)
Serial B (0x40)  : 673552 (0xA4710)
Serial Full      : 69673552

--- Total: 128 bytes | Alignment: 16x ---
0000 : 01 00 00 00 00 00 00 00 64 F4 0B 1B A2 02 00 00
0010 : B0 CE 73 03 59 45 DD 01 50 22 27 04 00 00 00 00
0020 : 00 00 00 00 00 00 00 00 95 15 73 B8 F6 A2 0B 43
0030 : A7 99 FB FF B8 1A 8D 73 BD 00 00 00 45 00 00 00
0040 : 10 47 0A 00 00 00 00 00 4F 03 00 00 00 00 00 00
0050 : 01 00 00 00 01 00 00 00 67 DE 1C 56 9C 03 AE E2
0060 : B7 87 63 E4 69 E2 02 00 A0 44 4E 88 A7 01 00 00
0070 : 00 00 00 00 00 00 00 00 10 36 45 1B A2 02 00 00

Invoking Base Math Parser (sub_1800090B0)...
Math Layer HRESULT: 0x0

--- Raw v75 Buffer Extraction Results ---
--- Total: 96 bytes | Alignment: 16x ---
0000 : 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0010 : 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0020 : 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0030 : 01 00 00 00 00 00 00 00 67 DE 1C 56 9C 03 AE E2
0040 : B7 87 63 E4 69 E2 02 00 00 00 00 00 00 00 00 00
0050 : 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00

Re-manufacturing the 12-Byte Material Block...

--- Raw Material Structure (Before Base64) ---
--- Total: 12 bytes | Alignment: 4x ---
0000 : A0 44 4E 88
0004 : A7 01 00 00
0008 : 00 00 00 00

--- Base64 Encoded Result ---
oEROiKcBAAAAAAAA

--- Base64 Encoded Result ---
oEROiKcBAAAAAAAA


PS C:\Users\Administrator> 
````
