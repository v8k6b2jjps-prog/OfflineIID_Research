# MSFT 2009 Format + Offline IID Research Library
Include Source + Test Results

## Legal Notice & Disclaimer
This project documents independent research and analysis of proprietary Microsoft formats for educational and interoperability purposes only. 
- All trademarks and proprietary formats belong to Microsoft Corporation. 
- This material is not intended to bypass security controls or facilitate unauthorized activation. 
- Users are solely responsible for ensuring compliance with applicable laws.

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
