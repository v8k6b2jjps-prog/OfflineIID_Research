$Info = Unpack-BinaryKey `
    -BinaryData $EncResult.Data
$Req = Invoke-IIDRequest `
    -GroupID $Info.Group `
    -Serial $Info.Serial `
    -SecurityID $Info.Security `
    -HWID $hwid.ShortHWID `
    -DllPath $pidIns `
    -Mode Insider
	
function Invoke-IIDRequest {
    [CmdletBinding(DefaultParameterSetName = "FromFields")]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = "FromStruct")]
        [byte[]]$RawStruct,

        [Parameter(Mandatory = $true, ParameterSetName = "FromForge")]
        [int]$GroupID,
        [Parameter(Mandatory = $true, ParameterSetName = "FromForge")]
        [int]$Serial,
        [Parameter(Mandatory = $true, ParameterSetName = "FromForge")]
        [long]$SecurityID,

        [Parameter(Mandatory = $false)]
        [long]$HWID = 0,

        [Parameter(Mandatory = $false)]
        [string]$DllPath = "pidgenx.dll",

        [ValidateSet("Retail", "Insider")]
        [Parameter(Mandatory = $false)]
        [string]$Mode = "Retail",

        [String]$Key,
        [String]$ConfigPath,
        [Nullable[Guid]]$SkuID
    )

    try {
        $Module = [AppDomain]::CurrentDomain.GetAssemblies() | ? { $_.ManifestModule.ScopeName -eq "OFF" } | select -Last 1
        $Global:OFF = $Module.GetTypes()[0]
    }
    catch {
        $Module = [AppDomain]::CurrentDomain.DefineDynamicAssembly("null", 1).DefineDynamicModule("OFF", $False).DefineType("null")
        @(
            @('null', 'null', [int], @()), # place holder
            @('GetPKeyData',                        'pidgenx.dll', [Int32], @([string], [string], [IntPtr], [IntPtr], [Int64], [String].MakeByRefType(), [Int64].MakeByRefType(), [Int64].MakeByRefType(), [Int64].MakeByRefType(), [IntPtr])),
            @('SLOpen',                             'sppc.dll', [Int32], @([IntPtr].MakeByRefType())),
            @('SLClose',                            'sppc.dll', [Int32], @([IntPtr])),
            @('SLGenerateOfflineInstallationIdEx',  'sppc.dll', [Int32], @([IntPtr], [Guid].MakeByRefType(), [Int32], [String].MakeByRefType())),
            @('SLDepositOfflineConfirmationId',     'sppc.dll', [Int32], @([IntPtr], [Guid].MakeByRefType(), [IntPtr], [IntPtr]))

        ) | % {
            $Module.DefinePInvokeMethod(($_[0]), ($_[1]), 22, 1, [Type]($_[2]), [Type[]]($_[3]), 1, 3).SetImplementationFlags(128)
        }
        $Global:OFF = $Module.CreateType()
    }

    $bufSize = 0x58
    $buffer = New-Object byte[] $bufSize
    [Array]::Clear($buffer, 0, $buffer.Length)

    $PidDll = $DllPath
    if (-not [System.IO.Path]::IsPathRooted($PidDll)) {
        $PidDll = Join-Path $env:windir "System32\pidgenx.dll"
    }
    #[Int64]$offset = Get-PidGenRVA -dllpath $PidDll
    [Int64]$offset = Get-PKey2009EngineRVA -dllpath $PidDll

    $param = $PSCmdlet.ParameterSetName
    if ($param -match "FromStruct|FromForge") {
        if ($param -eq "FromStruct") {
        
            # Copy the whole thing 1:1
            [Array]::Copy($RawStruct, 0, $buffer, 0, [Math]::Min($RawStruct.Length, $bufSize))
    
        } elseif (($param -eq "FromForge")) {

            # FORGERY MODE: Start at Offset 8 to leave the header space
            
            <#
            msft:rm/algorithm/pkey/2009
            .text:000000018000A050 CLSID_IProductKeyAlgorithm2009 dd 660672EFh            ; Data1
            .text:000000018000A050                                         ; DATA XREF: CAlgorithmsFactoryClient::CreateInstance(_GUID const &,_GUID const &,void * *)+79ג†“r
            .text:000000018000A050                                         ; CConfigCacheUtil::CreatePkeyAlgorithmObject<CAlgorithmsFactoryClient>(ushort const *,IProductKeyAlgorithm * *,_GUID *)+3Eג†“r ...
            .text:000000018000A050                 dw 7809h                ; Data2
            .text:000000018000A050                 dw 4CFDh                ; Data3
            .text:000000018000A050                 db 8Dh, 54h, 41h, 0B7h, 0FBh, 73h, 89h, 88h; Data4
            #>

            # This part only In use, if you use selector Function
            #$IProductKeyAlgorithm2009 = [Guid]'660672EF-7809-4CFD-8D54-41B7FB738988'
            #$IProductKeyAlgorithm2009.ToByteArray().CopyTo($buffer, 0x08)

            # Copy Settings
            [BitConverter]::GetBytes([Int32]$GroupID).CopyTo($buffer, 0x18)
            [BitConverter]::GetBytes([Int32]$Serial).CopyTo($buffer, 0x20)
            [BitConverter]::GetBytes([Int64]$SecurityID).CopyTo($buffer, 0x28)

        }

        $hBuffer = [Marshal]::AllocHGlobal($bufSize)

        try {
            # v25 = sub_180006A94((__int64)v12 + 8
            [Marshal]::Copy($buffer, 0, $hBuffer, $bufSize)

            $pOutString = ''
            $signatureBase = [IntPtr]::Add($hBuffer, 0x8)
            
            $params = $signatureBase, [int64]$HWID, 0L, [ref]$pOutString             # RVA2009 Direct Params
            $hr = Invoke-UnmanagedMethod `
                -Dll $DllPath `
                -Function "InnerCall" `
                -Values $params `
                -Sub $offset

            if ($hr -ge 0) {
                return [PSCustomObject]@{
                    Success = $true
                    IID     = $pOutString
                    HResult = "0x$($hr.ToString('X8'))"
                }
            }
            return [PSCustomObject]@{ Success = $false; HResult = "0x$($hr.ToString('X8'))" }
        }
        finally {
            [Marshal]::FreeHGlobal($hBuffer)
        }

    }
}

// Main Code
__int64 __fastcall sub_180006738(__int64 a1, __int64 a2, __int64 a3, _QWORD *a4)
{
  __int16 v9;
  __int64 v10;
  __int64 v11;
  int v17;
  int v18;
  __int64 v21;
  _BYTE *v22;
  __int64 v23;
  unsigned __int8 v24;
  char v25;
  _BYTE *v26;
  __int64 v27;
  __int64 v28;
  unsigned __int8 v29;
  char v30;
  __int16 *v31;
  __int64 v32;
  unsigned __int8 v33;
  char v34;
  __int64 v35;
  int v36;
  _BYTE *v38;
  __int64 v39;
  unsigned __int8 v40;
  char v41;
  int v42;
  HLOCAL v43;
  int v46;
  __int64 v50;
  int v51[2];
  HLOCAL hMem;

  __int64 v60 = a2;
  v51[0] = 0;
  int v57 = 0;
  __int16 v58 = 0;
  char v59 = 0;
  int v54 = 0;
  unsigned int v5 = 0;
  __int8 v6 = *(_BYTE *)(a1 + 37);
  __int64 v7 = a1 + 16;
  __int16 v55 = 0;
  v9 = *(_WORD *)(a1 + 32);
  __int128 v53 = 0i64;
  LOWORD(v53) = v9;
  v10 = 2i64;
  v11 = 2i64;
  BYTE2(v53) = *(_BYTE *)(a1 + 34);
  LOBYTE(v9) = *(_BYTE *)(a1 + 35) & 0xF;
  LODWORD(v50) = 0;
  BYTE3(v53) = (16 * v6) | v9 & 0xF;
  __int64 v12 = (unsigned __int64)&v53 + 6;
  char v13 = *(_BYTE *)(a1 + 38) >> 4;
  BYTE4(v53) = (v6 >> 4) | (16 * *(_BYTE *)(a1 + 38));
  __int64 v14 = (unsigned __int64)&v53 + 5;
  BYTE5(v53) = v13 & 1;
  __int64 v15 = v7 - ((_QWORD)&v53 + 5);
  __int128 Src = 0i64;

  // Unpack and shuffle bits from structure context
  do
  {
    __int8 v16 = *(_BYTE *)(v15 + v14);
    *(_BYTE *)v14 &= 1u;
    *(_BYTE *)v12 &= ~1u;
    *(_BYTE *)v14++ |= 2 * v16;
    *(_BYTE *)v12++ |= v16 >> 7;
    --v11;
  }
  while ( v11 );

  v17 = 0;
  v18 = *(_DWORD *)(a1 + 20);
  BYTE7(v53) ^= (BYTE7(v53) ^ (2 * *(_BYTE *)(a1 + 18))) & 0x1E;
  
  if ( v18 )
  {
    v12 = (unsigned int)(1000000 * v18);
    v14 = (unsigned int)v12 / 0xF4240;
    if ( (_DWORD)v14 == v18 )
    {
      v5 = 1000000 * v18;
      LODWORD(v50) = 1000000 * v18;
    }
    else
    {
      v17 = -2147024362;
    }
  }

  if ( v17 < 0 )
    return (unsigned int)v17;

  if ( v5 + *(_DWORD *)(a1 + 24) < v5 )
  {
    v17 = -2147024362;
  }
  else
  {
    LODWORD(v50) = v5 + *(_DWORD *)(a1 + 24);
    v17 = 0;
  }

  if ( v17 < 0 )
    return (unsigned int)v17;

  v21 = 0i64;
  v22 = (char *)&v53 + 8;
  v23 = 3i64;
  do
  {
    v24 = *((_BYTE *)&v51[-2] + v21);
    v25 = *((_BYTE *)&v53 + v21 + 7);
    *v22 &= 0xE0u;
    *v22++ |= v24 >> 3;
    *((_BYTE *)&v53 + v21++ + 7) = v25 & 0x1F | (32 * v24);
    --v23;
  }
  while ( v23 );

  v26 = (char *)&v53 + 12;
  BYTE10(v53) = (32 * BYTE3(v50)) | BYTE10(v53) & 0x1F;
  v27 = 8i64;
  BYTE11(v53) = (*(_DWORD *)(a1 + 28) != 0 ? 8 : 0) | BYTE11(v53) & 0xF0 ^ (BYTE3(v50) >> 3) & 7;
  v28 = 0i64;
  
  // Mix source data block into state buffer
  do
  {
    v29 = *((_BYTE *)&v60 + v28);
    v30 = *((_BYTE *)&v53 + v28 + 11);
    *v26 &= 0xF0u;
    *v26++ |= v29 >> 4;
    *((_BYTE *)&v53 + v28++ + 11) = v30 & 0xF | (16 * v29);
    --v27;
  }
  while ( v27 );

  v31 = &v55;
  v32 = 0i64;
  do
  {
    v33 = *((_BYTE *)v51 + v32);
    v34 = *((_BYTE *)&v54 + v32 + 3);
    *(_BYTE *)v31 &= 0xF0u;
    *(_BYTE *)v31 |= v33 >> 4;
    v31 = (__int16 *)((char *)v31 + 1);
    *((_BYTE *)&v54 + v32++ + 3) = v34 & 0xF | (16 * v33);
    --v10;
  }
  while ( v10 );

  HIBYTE(v55) &= 0xFu;
  v35 = 22i64;
  
  // Execute core Feistel cipher transformation
  v36 = ProcessEncryptionContext(22i64, &v53, v31, v32, v50, v51[0]);
  v17 = v36;
  if ( v36 < 0 )
    return (unsigned int)v17;

  v38 = (char *)&Src + 1;
  v39 = 0i64;
  do
  {
    v40 = *((_BYTE *)&v53 + v39);
    v41 = *((_BYTE *)&Src + v39);
    *v38 &= 0xF8u;
    *v38++ |= v40 >> 5;
    *((_BYTE *)&Src + v39++) = v41 & 7 | (8 * v40);
    --v35;
  }
  while ( v35 );

  hMem = 0i64;
  v50 = 0i64;
  v42 = sub_1800060F4(&Src);
  v43 = hMem;
  v17 = v42;
  
  if ( v42 >= 0 )
  {
    v46 = sub_180005D58(hMem, &v50);
    v17 = v46;
    if ( v46 >= 0 )
    {
      *a4 = v50;
    }
    else
    {
      v35 = v50;
    }
  }

  // Safe memory cleanup
  if ( v35 )
    LocalFree((HLOCAL)v35);
  if ( v43 )
    LocalFree(v43);

  return (unsigned int)v17;
}

// Sub code
__int64 __fastcall ProcessEncryptionContext(__int64 a1, __int64 a2)
{
  unsigned int v3; // edi
  int v4; // eax
  __int64 v5; // r8
  unsigned int v6; // ebx
  char v8[64]; // [rsp+20h] [rbp-58h] BYREF

  v3 = a1;
  v4 = sub_180006E78(a1, v8);
  v6 = v4;
  if ( v4 < 0 || (v4 = sub_180006394(v3, a2, v5, v8), v6 = v4, v4 < 0) )
    sub_1800038E8((unsigned int)v4);
  memset(v8, 0, sizeof(v8));
  sub_180003B30(v6);
  return v6;
}

// called from ProcessEncryptionContext
__int64 __fastcall sub_180006E78(__int64 a1, _OWORD *a2)
{
  __int128 v3; // [rsp+20h] [rbp-40h]
  __int128 v4; // [rsp+30h] [rbp-30h]
  __int128 v5; // [rsp+40h] [rbp-20h]
  __int128 v6; // [rsp+50h] [rbp-10h]

  *(_QWORD *)&v3 = 0x84D8F8F0D45EC86Bui64;
  *((_QWORD *)&v3 + 1) = 0xF413937D2F2A4177ui64;
  *a2 = v3;
  *(_QWORD *)&v4 = 0xBB9515A2E6668A1Bui64;
  *((_QWORD *)&v4 + 1) = 0x972B328367B09D0Eui64;
  a2[1] = v4;
  *(_QWORD *)&v5 = 0xEEDC7D7CCDD9FE49ui64;
  *((_QWORD *)&v5 + 1) = 0xEB3B0BE7DF1207B0ui64;
  *(_QWORD *)&v6 = 0xCFA627FDDF98BD56ui64;
  *((_QWORD *)&v6 + 1) = 0x573A73F8C236845Di64;
  a2[2] = v5;
  a2[3] = v6;
  sub_180003B30(0);
  return 0i64;
}

// called from ProcessEncryptionContext
__int64 __fastcall sub_180006394(unsigned int a1, _BYTE *a2, __int64 a3, int *a4)
{
  _BYTE *v4; // rbx
  unsigned int v5; // r14d
  _BYTE *v6; // rsi
  HLOCAL v7; // rbp
  SIZE_T v8; // r12
  _BYTE *v9; // rdi
  int v10; // ecx
  unsigned int v11; // r15d
  _BYTE *v12; // r15
  __int64 v13; // rcx
  SIZE_T v14; // rdx
  unsigned int v15; // edx
  _BYTE *v16; // r8
  __int64 v17; // rax
  unsigned int v18; // r13d
  int v19; // eax
  int v20; // eax
  signed __int64 v21; // rdx
  signed __int64 v22; // r8
  SIZE_T v23; // r10
  _BYTE *v24; // rcx
  unsigned int v25; // edx
  _BYTE *v26; // r8
  __int64 v27; // rcx
  int v29; // [rsp+20h] [rbp-68h]

  v4 = 0i64;
  v5 = a1 >> 1;
  v6 = 0i64;
  v7 = 0i64;
  v8 = a1 >> 1;
  v9 = LocalAlloc(0x40u, v8);
  if ( v9
    && (v4 = LocalAlloc(0x40u, v8)) != 0i64
    && (v6 = LocalAlloc(0x40u, v8)) != 0i64
    && (v12 = v9, (v7 = LocalAlloc(0x40u, (v5 + 3) & 0xFFFFFFFC)) != 0i64) )
  {
    if ( v5 )
    {
      v14 = v8;
      v13 = a2 - v9;
      do
      {
        *v12 = v12[v13];
        ++v12;
        --v14;
      }
      while ( v14 );
    }
    v15 = v5;
    if ( v5 < 2 * v5 )
    {
      v16 = &a2[v8];
      do
      {
        LOBYTE(v13) = *v16;
        v17 = v15 - v5;
        ++v15;
        ++v16;
        v4[v17] = v13;
      }
      while ( v15 < 2 * v5 );
    }
    v18 = 0;
    v19 = 8 * v5;
    do
    {
      v20 = sub_180006BEC(v13, (__int64)v4, v5, a4, v29, v7, v19);
      v11 = v20;
      if ( v20 < 0 )
      {
        v10 = v20;
        goto LABEL_25;
      }
      if ( v5 )
      {
        v21 = v6 - v4;
        v13 = (__int64)v4;
        v22 = v9 - v4;
        v23 = v8;
        do
        {
          *(_BYTE *)(v21 + v13) = *(_BYTE *)v13;
          *(_BYTE *)v13 = *(_BYTE *)(v22 + v13) ^ *(_BYTE *)((_BYTE *)v7 - v4 + v13);
          *(_BYTE *)(v22 + v13) = *(_BYTE *)(v21 + v13);
          ++v13;
          --v23;
        }
        while ( v23 );
      }
      ++a4;
      v19 = 8 * v5;
      ++v18;
    }
    while ( v18 < 0x10 );
    if ( v5 )
    {
      v24 = a2;
      do
      {
        *v24 = v24[v9 - a2];
        ++v24;
        --v8;
      }
      while ( v8 );
      v25 = 0;
      v26 = v4;
      do
      {
        v27 = v25 + v5;
        ++v25;
        a2[v27] = *v26++;
      }
      while ( v25 < v5 );
    }
  }
  else
  {
    v10 = -2147024882;
    v11 = -2147024882;
LABEL_25:
    sub_1800038E8(v10);
  }
  sub_180003B30(v11);
  if ( v7 )
    LocalFree(v7);
  if ( v6 )
    LocalFree(v6);
  if ( v4 )
    LocalFree(v4);
  if ( v9 )
    LocalFree(v9);
  return v11;
}

// called from sub_180006394
__int64 __fastcall sub_180006BEC(__int64 a1, __int64 a2, unsigned int a3, int *a4, int a5, void *a6, int a7)
{
  unsigned int v10; // ebx
  unsigned int v11; // edi
  char v13[16]; // [rsp+20h] [rbp-81h] BYREF
  int v14[24]; // [rsp+30h] [rbp-71h] BYREF
  int Src[6]; // [rsp+90h] [rbp-11h] BYREF

  v13[0] = 121;
  memset(v14, 0, sizeof(v14));
  v10 = 0;
  if ( a7 && (v11 = (unsigned int)(a7 + 31) >> 5, 4 * v11 <= 0x14) )
  {
    v14[16] = 1732584193;
    v14[17] = -271733879;
    v14[18] = -1732584194;
    v14[19] = 271733878;
    v14[20] = -1009589776;
    sub_180015D20(v14, v13, 1i64);
    sub_180015D20(v14, a2, a3);
    Src[0] = *a4;
    sub_180015D20(v14, Src, 4i64);
    sub_180015C00(v14, Src);
    memcpy(a6, Src, 4i64 * v11);
    *((_DWORD *)a6 + v11 - 1) >>= 32 * v11 - a7;
  }
  else
  {
    v10 = -2147024809;
    sub_1800038E8(-2147024809);
  }
  sub_180003B30(v10);
  return v10;
}

// called from sub_180006BEC
__int64 __fastcall sub_180015C00(__int64 a1, _DWORD *a2)
{
  unsigned int v2; // edi
  unsigned int v5; // r8d
  unsigned int v6; // eax
  __int64 v7; // rbx
  int v8; // ecx
  __int64 result; // rax
  int v10[2]; // [rsp+18h] [rbp-80h]
  char v11[80]; // [rsp+20h] [rbp-78h] BYREF

  v2 = *(_DWORD *)(a1 + 88);
  v5 = 64 - (v2 & 0x3F);
  v6 = v5 + 64;
  if ( v5 > 8 )
    v6 = 64 - (*(_DWORD *)(a1 + 88) & 0x3F);
  v7 = v6;
  memset(v11, 0, v6 - 8);
  v8 = (v2 >> 29) | (8 * *(_DWORD *)(a1 + 84));
  v11[0] = 0x80;
  *(int *)((char *)v10 + v7) = _byteswap_ulong(v8);
  *(int *)((char *)&v10[1] + v7) = _byteswap_ulong(8 * v2);
  sub_180015D20(a1, v11, v7);
  *a2 = _byteswap_ulong(*(_DWORD *)(a1 + 64));
  a2[1] = _byteswap_ulong(*(_DWORD *)(a1 + 68));
  a2[2] = _byteswap_ulong(*(_DWORD *)(a1 + 72));
  a2[3] = _byteswap_ulong(*(_DWORD *)(a1 + 76));
  a2[4] = _byteswap_ulong(*(_DWORD *)(a1 + 80));
  result = 0i64;
  *(_OWORD *)a1 = 0i64;
  *(_OWORD *)(a1 + 16) = 0i64;
  *(_OWORD *)(a1 + 32) = 0i64;
  *(_OWORD *)(a1 + 48) = 0i64;
  *(_QWORD *)(a1 + 84) = 0i64;
  *(_DWORD *)(a1 + 64) = 1732584193;
  *(_DWORD *)(a1 + 68) = -271733879;
  *(_DWORD *)(a1 + 72) = -1732584194;
  *(_DWORD *)(a1 + 76) = 271733878;
  *(_DWORD *)(a1 + 80) = -1009589776;
  return result;
}

// sha1 Helper 
__int64 __fastcall sub_180015D20(__int64 a1, char *a2, unsigned int a3)
{
  unsigned int v3; // ebx
  char *v4; // rdi
  __int64 result; // rax
  unsigned int v6; // r14d
  unsigned int v8; // esi
  unsigned __int64 v9; // rsi

  v3 = a3;
  v4 = a2;
  result = a3 + *(_DWORD *)(a1 + 88);
  v6 = *(_DWORD *)(a1 + 88) & 0x3F;
  *(_DWORD *)(a1 + 88) = result;
  if ( (unsigned int)result < a3 )
    ++*(_DWORD *)(a1 + 84);
  if ( v6 )
  {
    v8 = v6 + a3;
    if ( v6 + a3 >= 0x40 )
    {
      memcpy((void *)(a1 + v6), a2, 64 - v6);
      v4 += 64 - v6;
      v3 = v8 - 64;
      result = sub_180015DF0(a1 + 64, a1);
      v6 = 0;
    }
  }
  if ( v3 >= 0x40 )
  {
    v9 = (unsigned __int64)v3 >> 6;
    do
    {
      result = sub_180015DF0(a1 + 64, v4);
      v4 += 64;
      v3 -= 64;
      --v9;
    }
    while ( v9 );
  }
  if ( v3 )
    return (__int64)memcpy((void *)(a1 + v6), v4, v3);
  return result;
}

// sha1 Helper 
__int64 __fastcall sub_180015DF0(int *a1, unsigned int *a2)
{
  v2 = *a1;
  v3 = a2;
  v4 = a1[2];
  v5 = *a1;
  v6 = a1[1];
  v7 = a1[3];
  v8 = a1[4];
  v9 = *a2;
  v10 = a2[1];
  v11 = a2[2];
  v12 = v7 ^ v6 & (v4 ^ v7);
  v13 = a2[3];
  v14 = a2[4];
  v15 = __ROL4__(v6, 30);
  v16 = v2 & (v15 ^ v4);
  v17 = __ROL4__(v2, 30);
  v18 = _byteswap_ulong(v9);
  v294 = _byteswap_ulong(v10);
  v19 = v18 + __ROL4__(v5, 5) + v12 + v8 + 1518500249;
  v20 = v7 + 1518500249 + v294 + __ROL4__(v19, 5) + (v4 ^ v16);
  v21 = __ROL4__(v20, 5);
  v22 = v15 ^ v19 & (v17 ^ v15);
  v23 = __ROL4__(v19, 30);
  v24 = v20 & (v17 ^ v23);
  v25 = __ROL4__(v20, 30);
  v26 = _byteswap_ulong(v11);
  v27 = v4 + 1518500249 + v26 + v21 + v22;
  v28 = _byteswap_ulong(v13);
  v29 = v28 + __ROL4__(v27, 5) + (v17 ^ v24) + v15 + 1518500249;
  v30 = v23 ^ v27 & (v25 ^ v23);
  v31 = __ROL4__(v27, 30);
  v32 = _byteswap_ulong(v14);
  v33 = v32 + __ROL4__(v29, 5) + v30 + v17 + 1518500249;
  v34 = v25 ^ v29 & (v31 ^ v25);
  v35 = _byteswap_ulong(v3[5]);
  v36 = __ROL4__(v29, 30);
  v37 = v35 + __ROL4__(v33, 5) + 1518500249 + v34 + v23;
  v38 = v31 ^ v33 & (v36 ^ v31);
  v39 = __ROL4__(v33, 30);
  v40 = _byteswap_ulong(v3[6]);
  v41 = v40 + __ROL4__(v37, 5) + 1518500249 + v38 + v25;
  v42 = v37 & (v39 ^ v36);
  v43 = __ROL4__(v37, 30);
  v290 = _byteswap_ulong(v3[7]);
  v44 = v290 + 1518500249 + __ROL4__(v41, 5) + (v36 ^ v42) + v31;
  v45 = v39 ^ v41 & (v39 ^ v43);
  v46 = __ROL4__(v41, 30);
  v319 = _byteswap_ulong(v3[8]);
  v47 = v319 + 1518500249 + __ROL4__(v44, 5) + v45 + v36;
  v343 = _byteswap_ulong(v3[9]);
  v48 = v43 ^ v44 & (v46 ^ v43);
  v49 = __ROL4__(v44, 30);
  v50 = v343 + 1518500249 + __ROL4__(v47, 5) + v48 + v39;
  v329 = _byteswap_ulong(v3[10]);
  v51 = v46 ^ v47 & (v49 ^ v46);
  v52 = __ROL4__(v47, 30);
  v53 = v329 + 1518500249 + __ROL4__(v50, 5) + v51 + v43;
  v326 = _byteswap_ulong(v3[11]);
  v54 = v49 ^ v50 & (v52 ^ v49);
  v55 = __ROL4__(v50, 30);
  v56 = v326 + 1518500249 + __ROL4__(v53, 5) + v54 + v46;
  v57 = v52 ^ v53 & (v55 ^ v52);
  v58 = __ROL4__(v53, 30);
  v323 = _byteswap_ulong(v3[12]);
  v59 = v323 + 1518500249 + __ROL4__(v56, 5) + v57 + v49;
  v60 = v55 ^ v56 & (v55 ^ v58);
  v61 = __ROL4__(v56, 30);
  v311 = _byteswap_ulong(v3[13]);
  v62 = v311 + 1518500249 + __ROL4__(v59, 5) + v60 + v52;
  v63 = v59 & (v61 ^ v58);
  v64 = __ROL4__(v59, 30);
  v335 = _byteswap_ulong(v3[14]);
  v65 = v335 + 1518500249 + __ROL4__(v62, 5) + (v58 ^ v63) + v55;
  v66 = v61 ^ v62 & (v64 ^ v61);
  v67 = __ROL4__(v62, 30);
  v339 = _byteswap_ulong(v3[15]);
  LODWORD(v3) = v58 + 1518500249 + v66 + __ROL4__(v65, 5) + v339;
  v315 = __ROL4__(v18 ^ v26 ^ v319 ^ v311, 1);
  v68 = v61 + 1518500249 + (v64 ^ v65 & (v67 ^ v64)) + __ROL4__((_DWORD)v3, 5) + v315;
  v69 = __ROL4__(v65, 30);
  v70 = (unsigned int)v3 & (v69 ^ v67);
  LODWORD(v3) = __ROL4__((_DWORD)v3, 30);
  v305 = __ROL4__(v294 ^ v28 ^ v343 ^ v335, 1);
  v71 = v64 + 1518500249 + v305 + __ROL4__(v68, 5) + (v67 ^ v70);
  v295 = __ROL4__(v26 ^ v32 ^ v329 ^ v339, 1);
  v72 = v69 ^ v68 & (v69 ^ (unsigned int)v3);
  v73 = __ROL4__(v68, 30);
  v74 = (unsigned int)v3 ^ v71 & (v73 ^ (unsigned int)v3);
  v75 = __ROL4__(v71, 5);
  v76 = __ROL4__(v71, 30);
  v77 = v67 + 1518500249 + v295 + v75 + v72;
  v308 = __ROL4__(v315 ^ v28 ^ v35 ^ v326, 1);
  v78 = v69 + 1518500249 + v74 + __ROL4__(v77, 5) + v308;
  v79 = v77 ^ v76 ^ v73;
  v80 = __ROL4__(v77, 30);
  v81 = v32 ^ v40 ^ v323;
  v82 = v311;
  v285 = __ROL4__(v305 ^ v81, 1);
  v83 = (_DWORD)v3 + 1859775393 + v79 + __ROL4__(v78, 5) + v285;
  v84 = __ROL4__(v295 ^ v35 ^ v290 ^ v311, 1);
  v85 = v285;
  v86 = v84 + __ROL4__(v83, 5) + 1859775393 + (v78 ^ v80 ^ v76) + v73;
  v87 = __ROL4__(v78, 30);
  v88 = v87 ^ v80 ^ v83;
  v89 = __ROL4__(v83, 30);
  v312 = __ROL4__(v308 ^ v40 ^ v319 ^ v335, 1);
  v90 = v312 + __ROL4__(v86, 5) + 1859775393 + v88 + v76;
  v91 = __ROL4__(v285 ^ v290 ^ v343 ^ v339, 1);
  v92 = v86 ^ v89;
  v93 = __ROL4__(v86, 30);
  v94 = v91 + __ROL4__(v90, 5) + 1859775393 + (v87 ^ v92) + v80;
  v95 = v90 ^ v93 ^ v89;
  v299 = __ROL4__(v315 ^ v84 ^ v319 ^ v329, 1);
  v96 = __ROL4__(v90, 30);
  v97 = v299 + 1859775393 + __ROL4__(v94, 5) + v95 + v87;
  v98 = v94 ^ v96 ^ v93;
  v286 = __ROL4__(v305 ^ v312 ^ v343 ^ v326, 1);
  v99 = __ROL4__(v94, 30);
  v100 = v286 + 1859775393 + __ROL4__(v97, 5) + v98 + v89;
  v344 = __ROL4__(v295 ^ v91 ^ v329 ^ v323, 1);
  v101 = v97 ^ v99 ^ v96;
  v102 = __ROL4__(v97, 30);
  v103 = v344 + 1859775393 + __ROL4__(v100, 5) + v101 + v93;
  v104 = v102 ^ v99 ^ v100;
  v302 = __ROL4__(v308 ^ v299 ^ v326 ^ v82, 1);
  v105 = __ROL4__(v100, 30);
  v106 = v302 + 1859775393 + __ROL4__(v103, 5) + v104 + v96;
  v291 = __ROL4__(v85 ^ v286 ^ v323 ^ v335, 1);
  v320 = __ROL4__(v84 ^ v344 ^ v82 ^ v339, 1);
  v107 = v102 ^ v103 ^ v105;
  v108 = __ROL4__(v103, 30);
  v109 = v291 + __ROL4__(v106, 5) + 1859775393 + v107 + v99;
  v110 = v106 ^ v108 ^ v105;
  v111 = __ROL4__(v106, 30);
  v112 = v320 + __ROL4__(v109, 5) + 1859775393 + v110 + v102;
  v113 = v109 ^ v111 ^ v108;
  v336 = __ROL4__(v315 ^ v312 ^ v302 ^ v335, 1);
  v114 = __ROL4__(v109, 30);
  v115 = v336 + 1859775393 + __ROL4__(v112, 5) + v113 + v105;
  v340 = __ROL4__(v305 ^ v91 ^ v291 ^ v339, 1);
  v116 = v286;
  v117 = v112 ^ v114 ^ v111;
  v118 = __ROL4__(v112, 30);
  v119 = v340 + __ROL4__(v115, 5) + 1859775393 + v117 + v108;
  v120 = v295;
  v121 = v114 ^ v115;
  v122 = __ROL4__(v115, 30);
  v296 = __ROL4__(v315 ^ v295 ^ v299 ^ v320, 1);
  v123 = v296 + __ROL4__(v119, 5) + 1859775393 + (v118 ^ v121) + v111;
  v124 = v118 ^ v119 ^ v122;
  v287 = __ROL4__(v305 ^ v308 ^ v286 ^ v336, 1);
  v125 = __ROL4__(v119, 30);
  v126 = v287 + 1859775393 + __ROL4__(v123, 5) + v124 + v114;
  v332 = __ROL4__(v120 ^ v85 ^ v344 ^ v340, 1);
  v127 = v123 ^ v125 ^ v122;
  v128 = __ROL4__(v123, 30);
  v129 = v332 + __ROL4__(v126, 5) + 1859775393 + v127 + v118;
  v130 = v126 ^ v128 ^ v125;
  v316 = __ROL4__(v308 ^ v84 ^ v302 ^ v296, 1);
  v131 = __ROL4__(v126, 30);
  v132 = v316 + __ROL4__(v129, 5) + 1859775393 + v130 + v122;
  v306 = __ROL4__(v85 ^ v312 ^ v291 ^ v287, 1);
  v133 = v306 + 1859775393 + __ROL4__(v132, 5) + (v129 ^ v131 ^ v128) + v125;
  v134 = __ROL4__(v129, 30);
  v327 = __ROL4__(v312 ^ v299 ^ v336 ^ v316, 1);
  v135 = v84 ^ v91 ^ v320 ^ v332;
  v136 = v344;
  v137 = v134 ^ v131 ^ v132;
  v138 = __ROL4__(v132, 30);
  v139 = v91 ^ v116 ^ v340 ^ v306;
  v140 = v296;
  v324 = __ROL4__(v135, 1);
  v330 = __ROL4__(v139, 1);
  v141 = v324 + __ROL4__(v133, 5) + 1859775393 + v137 + v128;
  v142 = v134 ^ v133 ^ v138;
  v143 = __ROL4__(v133, 30);
  v144 = v327 + 1859775393 + __ROL4__(v141, 5) + v142 + v131;
  LODWORD(v3) = v141 ^ v143 ^ v138;
  v145 = __ROL4__(v141, 30);
  LODWORD(v3) = v134 + 1859775393 + v330 + __ROL4__(v144, 5) + (_DWORD)v3;
  v309 = __ROL4__(v299 ^ v344 ^ v296 ^ v324, 1);
  v146 = v138 + v309 + (v144 & v145 | v143 & (v144 | v145)) + __ROL4__((_DWORD)v3, 5) - 1894007588;
  v147 = v287;
  v148 = __ROL4__(v144, 30);
  v149 = v145 & ((unsigned int)v3 | v148);
  v345 = __ROL4__(v116 ^ v302 ^ v287 ^ v327, 1);
  v150 = (unsigned int)v3 & v148;
  LODWORD(v3) = __ROL4__((_DWORD)v3, 30);
  v151 = v150 | v149;
  v152 = v136 ^ v291 ^ v332 ^ v330;
  v153 = v316;
  v154 = v143 + v345 + v151 + __ROL4__(v146, 5) - 1894007588;
  v300 = __ROL4__(v152, 1);
  v155 = v148 & ((unsigned int)v3 | v146);
  v156 = (unsigned int)v3 & v146;
  v157 = __ROL4__(v146, 30);
  v288 = __ROL4__(v302 ^ v320 ^ v316 ^ v309, 1);
  v158 = v145 + v300 + (v156 | v155) + __ROL4__(v154, 5) - 1894007588;
  v159 = (unsigned int)v3 & (v154 | v157);
  v160 = v154 & v157;
  v161 = __ROL4__(v154, 30);
  v162 = v148 + v288 + (v160 | v159) + __ROL4__(v158, 5) - 1894007588;
  v303 = __ROL4__(v291 ^ v336 ^ v306 ^ v345, 1);
  LODWORD(v3) = (_DWORD)v3 + v303 + (v158 & v161 | v157 & (v158 | v161)) + __ROL4__(v162, 5) - 1894007588;
  v163 = __ROL4__(v158, 30);
  v164 = __ROL4__(v320 ^ v340 ^ v324 ^ v300, 1);
  v165 = v164 + (v162 & v163 | v161 & (v162 | v163));
  v166 = __ROL4__(v162, 30);
  v321 = v164;
  v167 = (unsigned int)v3 & v166;
  v297 = __ROL4__(v336 ^ v296 ^ v327 ^ v288, 1);
  v292 = __ROL4__(v340 ^ v147 ^ v330 ^ v303, 1);
  v168 = v157 + v165 + __ROL4__((_DWORD)v3, 5) - 1894007588;
  v313 = __ROL4__(v140 ^ v332 ^ v309 ^ v164, 1);
  v169 = v163 & ((unsigned int)v3 | v166);
  LODWORD(v3) = __ROL4__((_DWORD)v3, 30);
  v170 = v297 + (v167 | v169);
  v171 = (unsigned int)v3 & v168;
  v172 = v161 + v170 + __ROL4__(v168, 5) - 1894007588;
  v173 = (unsigned int)v3 | v168;
  v174 = __ROL4__(v168, 30);
  v175 = v163 + v292 + (v171 | v166 & v173) + __ROL4__(v172, 5) - 1894007588;
  v176 = v172 & v174 | (unsigned int)v3 & (v172 | v174);
  v177 = __ROL4__(v172, 30);
  v178 = v166 + v313 + v176 + __ROL4__(v175, 5) - 1894007588;
  v317 = __ROL4__(v147 ^ v316 ^ v345 ^ v297, 1);
  v179 = v306;
  v180 = v324;
  v181 = v317 + (v175 & v177 | v174 & (v175 | v177));
  v182 = __ROL4__(v175, 30);
  v307 = __ROL4__(v332 ^ v306 ^ v300 ^ v292, 1);
  LODWORD(v3) = (_DWORD)v3 + v181 + __ROL4__(v178, 5) - 1894007588;
  v183 = v178 & v182;
  v184 = v177 & (v178 | v182);
  v185 = __ROL4__(v178, 30);
  v186 = v153 ^ v324 ^ v288 ^ v313;
  v187 = v327;
  v325 = __ROL4__(v186, 1);
  v188 = v174 + v307 + (v183 | v184) + __ROL4__((_DWORD)v3, 5) - 1894007588;
  v328 = __ROL4__(v179 ^ v327 ^ v303 ^ v317, 1);
  v189 = v325 + ((unsigned int)v3 & v185 | v182 & ((unsigned int)v3 | v185));
  LODWORD(v3) = __ROL4__((_DWORD)v3, 30);
  v190 = (unsigned int)v3 & v188;
  v191 = v177 + v189 + __ROL4__(v188, 5) - 1894007588;
  v192 = (unsigned int)v3 | v188;
  v193 = __ROL4__(v188, 30);
  v337 = __ROL4__(v180 ^ v330 ^ v321 ^ v307, 1);
  v194 = v182 + v328 + (v190 | v185 & v192) + __ROL4__(v191, 5) - 1894007588;
  v195 = v309;
  v196 = v191 & v193 | (unsigned int)v3 & (v191 | v193);
  v197 = __ROL4__(v191, 30);
  v198 = __ROL4__(v194, 5) + v337 - 1894007588 + v196 + v185;
  v199 = v194 & v197 | v193 & (v194 | v197);
  v200 = __ROL4__(v194, 30);
  v201 = v198 & v200;
  v341 = __ROL4__(v187 ^ v309 ^ v297 ^ v325, 1);
  v202 = (_DWORD)v3 - 1894007588 + v341 + v199 + __ROL4__(v198, 5);
  v203 = v197 & (v198 | v200);
  v204 = __ROL4__(v198, 30);
  v310 = __ROL4__(v330 ^ v345 ^ v292 ^ v328, 1);
  LODWORD(v3) = v193 - 1894007588 + v310 + (v201 | v203) + __ROL4__(v202, 5);
  v205 = __ROL4__(v195 ^ v300 ^ v313 ^ v337, 1);
  v206 = v205 + (v202 & v204 | v200 & (v202 | v204));
  v207 = __ROL4__(v202, 30);
  v331 = v205;
  v333 = __ROL4__(v345 ^ v288 ^ v317 ^ v341, 1);
  v208 = v197 + v206 + __ROL4__((_DWORD)v3, 5) - 1894007588;
  v209 = v200 + v333 + (v207 & (unsigned int)v3 | v204 & (v207 | (unsigned int)v3));
  LODWORD(v3) = __ROL4__((_DWORD)v3, 30);
  v210 = v209 + __ROL4__(v208, 5) - 1894007588;
  v211 = v208 & (unsigned int)v3 | v207 & (v208 | (unsigned int)v3);
  v212 = __ROL4__(v208, 30);
  v213 = v210 & v212;
  v289 = __ROL4__(v205 ^ v288 ^ v321 ^ v325, 1);
  v346 = __ROL4__(v310 ^ v300 ^ v303 ^ v307, 1);
  v304 = __ROL4__(v333 ^ v303 ^ v297 ^ v328, 1);
  v214 = v204 + v346 + v211 + __ROL4__(v210, 5) - 1894007588;
  v215 = (unsigned int)v3 & (v210 | v212);
  v216 = __ROL4__(v210, 30);
  v217 = __ROL4__(v214, 5);
  v218 = v207 + v289 + (v213 | v215) - 1894007588;
  v219 = (_DWORD)v3 - 899497514 + v304 + (v214 ^ v216 ^ v212);
  v220 = __ROL4__(v214, 30);
  v221 = v218 + v217;
  v222 = v297 ^ v313 ^ v341;
  v223 = v219 + __ROL4__(v221, 5);
  v298 = __ROL4__(v346 ^ v321 ^ v292 ^ v337, 1);
  v224 = v298 + (v221 ^ v220 ^ v216);
  v225 = __ROL4__(v221, 30);
  v226 = v212 + v224 + __ROL4__(v223, 5) - 899497514;
  v322 = __ROL4__(v289 ^ v222, 1);
  v227 = v225 ^ v220 ^ v223;
  v228 = __ROL4__(v223, 30);
  v229 = v216 + v322 + v227 + __ROL4__(v226, 5) - 899497514;
  v293 = __ROL4__(v310 ^ v304 ^ v292 ^ v317, 1);
  v230 = v220 + v293 + (v225 ^ v226 ^ v228);
  v231 = __ROL4__(v226, 30);
  v301 = __ROL4__(v331 ^ v298 ^ v313 ^ v307, 1);
  v232 = __ROL4__(v346 ^ v293 ^ v307 ^ v328, 1);
  v233 = v230 + __ROL4__(v229, 5) - 899497514;
  v318 = __ROL4__(v333 ^ v322 ^ v317 ^ v325, 1);
  v234 = v301 + (v229 ^ v231 ^ v228);
  v235 = __ROL4__(v229, 30);
  v236 = __ROL4__(v289 ^ v301 ^ v325 ^ v337, 1);
  v237 = v225 + v234 + __ROL4__(v233, 5) - 899497514;
  v238 = v318 + (v233 ^ v235 ^ v231);
  v239 = __ROL4__(v233, 30);
  v240 = v228 + v238 + __ROL4__(v237, 5) - 899497514;
  v241 = v232 + (v237 ^ v239 ^ v235);
  v242 = __ROL4__(v237, 30);
  v243 = v231 + v241 + __ROL4__(v240, 5) - 899497514;
  v244 = v236 + (v242 ^ v239 ^ v240);
  v245 = __ROL4__(v240, 30);
  v246 = v235 + v244 + __ROL4__(v243, 5) - 899497514;
  v247 = __ROL4__(v304 ^ v318 ^ v328 ^ v341, 1);
  v248 = v242 ^ v243 ^ v245;
  v249 = __ROL4__(v243, 30);
  v342 = __ROL4__(v331 ^ v322 ^ v236 ^ v341, 1);
  v338 = __ROL4__(v310 ^ v298 ^ v232 ^ v337, 1);
  v314 = v247;
  v250 = v239 + v247 + v248 + __ROL4__(v246, 5) - 899497514;
  v251 = __ROL4__(v250, 5);
  v252 = (v246 ^ v249 ^ v245) - 899497514;
  v253 = __ROL4__(v246, 30);
  LODWORD(v3) = v252 + v338;
  v254 = v342 - 899497514 + (v250 ^ v253 ^ v249);
  v255 = __ROL4__(v250, 30);
  LODWORD(v3) = v251 + v242 + (_DWORD)v3;
  v256 = v245 + v254 + __ROL4__((_DWORD)v3, 5);
  v257 = __ROL4__(v310 ^ v333 ^ v293 ^ v247, 1);
  v258 = v257 + ((unsigned int)v3 ^ v255 ^ v253);
  LODWORD(v3) = __ROL4__((_DWORD)v3, 30);
  v259 = v249 - 899497514 + v258 + __ROL4__(v256, 5);
  v260 = __ROL4__(v331 ^ v346 ^ v301 ^ v338, 1);
  v261 = v253 + v260 + ((unsigned int)v3 ^ v255 ^ v256) - 899497514 + __ROL4__(v259, 5);
  v262 = __ROL4__(v333 ^ v289 ^ v318 ^ v342, 1);
  v263 = __ROL4__(v289 ^ v298 ^ v236 ^ v260, 1);
  v264 = __ROL4__(v346 ^ v304 ^ v232 ^ v257, 1);
  v265 = __ROL4__(v256, 30);
  v266 = v259 ^ v265;
  v267 = __ROL4__(v259, 30);
  v268 = v255 - 899497514 + v262 + ((unsigned int)v3 ^ v266) + __ROL4__(v261, 5);
  v269 = __ROL4__(v304 ^ v322 ^ v314 ^ v262, 1);
  v270 = v261 ^ v267 ^ v265;
  v271 = __ROL4__(v261, 30);
  LODWORD(v3) = __ROL4__(v268, 5) + v264 + v270 - 899497514 + (_DWORD)v3;
  v272 = v268 ^ v271 ^ v267;
  v273 = __ROL4__(v268, 30);
  v274 = v265 + v263 + v272 - 899497514 + __ROL4__((_DWORD)v3, 5);
  v275 = (unsigned int)v3 ^ v273 ^ v271;
  LODWORD(v3) = __ROL4__((_DWORD)v3, 30);
  v276 = v267 + v269 + v275 - 899497514 + __ROL4__(v274, 5);
  v277 = v273 ^ v274;
  v278 = __ROL4__(v274, 30);
  v279 = v271 + ((unsigned int)v3 ^ v277) + __ROL4__(v276, 5) + __ROL4__(v298 ^ v293 ^ v338 ^ v264, 1) - 899497514;
  v280 = (unsigned int)v3 ^ v276 ^ v278;
  v281 = __ROL4__(v276, 30);
  v282 = v273 + v280 + __ROL4__(v279, 5) + __ROL4__(v322 ^ v301 ^ v342 ^ v263, 1) - 899497514;
  v283 = *a1 + (v279 ^ v281 ^ v278);
  a1[1] += v282;
  result = (unsigned int)(v283 + __ROL4__(v282, 5) + __ROL4__(v293 ^ v318 ^ v257 ^ v269, 1) + (_DWORD)v3 - 899497514);
  a1[2] += __ROL4__(v279, 30);
  a1[3] += v281;
  a1[4] += v278;
  *a1 = result;
  return result;
}

// Sub code
__int64 __fastcall sub_1800060F4(void *Src, int a2, int a3, _QWORD *a4)
{
  __int64 v5; // r15
  unsigned int v7; // r14d
  char *v8; // rdi
  _WORD *v9; // rbx
  double v11; // xmm6_8
  double v12; // xmm6_8
  __int64 v13; // rbp
  int v14; // esi
  int v15; // ecx
  __int64 v16; // r9
  unsigned int v17; // ecx
  char *v18; // r8
  __int64 v19; // r10
  unsigned int v20; // ecx
  _WORD *v21; // rax

  v5 = a3;
  v7 = 0;
  v8 = 0i64;
  v9 = 0i64;
  sub_180003B30(0);
  v11 = log10(2.0);
  v12 = v11 * (double)a2 / log10(10.0);
  v13 = (unsigned int)((int)v12 + 1);
  if ( v12 <= (double)(int)v12 )
    v13 = (unsigned int)(int)v12;
  if ( !(_DWORD)v13 )
  {
    v14 = -2147024809;
LABEL_5:
    v15 = v14;
LABEL_6:
    sub_1800038E8(v15);
    goto LABEL_28;
  }
  if ( (int)v13 + 1 < (unsigned int)v13 )
  {
    v14 = -2147024362;
    sub_1800038E8(-2147024362);
  }
  else
  {
    v7 = v13 + 1;
    v14 = 0;
  }
  sub_180003B30(v14);
  if ( v14 < 0 )
    goto LABEL_5;
  v14 = 0;
  if ( v7 )
  {
    if ( (2 * v7) >> 1 == v7 )
    {
      v7 *= 2;
    }
    else
    {
      v14 = -2147024362;
      sub_1800038E8(-2147024362);
    }
  }
  else
  {
    v7 = 0;
  }
  sub_180003B30(v14);
  if ( v14 < 0 )
    goto LABEL_5;
  v9 = LocalAlloc(0x40u, v7);
  if ( !v9 )
  {
    v9 = 0i64;
LABEL_19:
    v15 = -2147024882;
    v14 = -2147024882;
    goto LABEL_6;
  }
  v8 = (char *)LocalAlloc(0x40u, (unsigned int)v5);
  if ( !v8 )
  {
    v8 = 0i64;
    goto LABEL_19;
  }
  memcpy(v8, Src, (unsigned int)v5);
  v16 = v5 - 1;
  v9[v13] = 0;
  do
  {
    v13 = (unsigned int)(v13 - 1);
    v17 = 0;
    if ( v16 >= 0 )
    {
      v18 = &v8[v16];
      v19 = v5;
      do
      {
        v20 = (unsigned __int8)*v18 + (v17 << 8);
        *v18-- = v20 / 0xA;
        v17 = v20 % 0xA;
        --v19;
      }
      while ( v19 );
    }
    v9[v13] = a0123456789[v17];
  }
  while ( (_DWORD)v13 );
  v21 = v9;
  v9 = 0i64;
  *a4 = v21;
LABEL_28:
  sub_180003B30(v14);
  if ( v9 )
    LocalFree(v9);
  if ( v8 )
    LocalFree(v8);
  return (unsigned int)v14;
}

// Sub code
__int64 __fastcall sub_180005D58(__int64 a1, _QWORD *a2)
{
  unsigned int v2; // r14d
  HLOCAL v3; // rbx
  unsigned int v4; // esi
  int v5; // eax
  unsigned int v6; // edi
  __int64 v7; // rcx
  __int64 v8; // rdx
  __int64 v9; // r8
  __int64 v10; // r8
  unsigned int v11; // r12d
  unsigned int v12; // r13d
  __int64 v13; // rdx
  unsigned int v14; // r15d
  unsigned int v15; // esi
  wchar_t *p_String; // rcx
  __int64 v17; // rdx
  __int64 v18; // rsi
  wchar_t v19; // ax
  wchar_t *v20; // rax
  __int64 v21; // rdx
  __int64 v22; // r8
  __int64 v23; // rax
  wchar_t *v24; // rcx
  __int64 v25; // r12
  __int64 i; // rdx
  wchar_t v27; // ax
  wchar_t *v28; // rax
  __int64 v29; // rdx
  __int64 v30; // r8
  HLOCAL v31; // rax
  int v33; // [rsp+20h] [rbp-28h]
  unsigned int v34; // [rsp+24h] [rbp-24h]
  wchar_t Buffer[2]; // [rsp+28h] [rbp-20h] BYREF
  unsigned int v36; // [rsp+2Ch] [rbp-1Ch]
  unsigned int v37; // [rsp+30h] [rbp-18h]
  __int64 v38; // [rsp+38h] [rbp-10h]
  _QWORD *v40; // [rsp+98h] [rbp+50h]
  wchar_t String; // [rsp+A0h] [rbp+58h] BYREF
  unsigned int v42; // [rsp+A8h] [rbp+60h] BYREF

  v40 = a2;
  v42 = 0;
  v2 = 0;
  v33 = 0;
  v3 = 0i64;
  v4 = 0;
  v5 = sub_180004A28(a1, &v42);
  v6 = v5;
  if ( v5 < 0 )
  {
LABEL_2:
    v7 = (unsigned int)v5;
LABEL_3:
    sub_1800038E8(v7);
    goto LABEL_58;
  }
  v10 = v42;
  if ( !v42 )
  {
    v6 = -1073418193;
LABEL_6:
    v7 = v6;
    goto LABEL_3;
  }
  v6 = 0;
  v11 = v42 / 6 + 1;
  v12 = v42 % 6;
  if ( !(v42 % 6) )
    v12 = 6;
  v36 = v12;
  if ( !(v42 % 6) )
    v11 = v42 / 6;
  v13 = v11 + v42 + 1;
  v37 = v11;
  v34 = v11 + v42 + 1;
  if ( v34 )
  {
    if ( (unsigned int)(2 * v13) >> 1 == (_DWORD)v13 )
    {
      v4 = 2 * v13;
    }
    else
    {
      v6 = -2147024362;
      sub_1800038E8(2147942934i64);
    }
  }
  sub_180003B30(v6, v13, v10);
  if ( (v6 & 0x80000000) != 0 )
    goto LABEL_6;
  v3 = LocalAlloc(0x40u, v4);
  if ( !v3 )
  {
    v3 = 0i64;
    v6 = -2147024882;
    goto LABEL_6;
  }
  v14 = 0;
  if ( v11 )
  {
    while ( v14 >= v11 - 1 )
    {
      if ( v36 == 1 )
      {
        p_String = &String;
        v17 = 2i64;
        v18 = 2i64 * (v42 - 1);
        while ( v17 != 1 )
        {
          v19 = *(wchar_t *)((char *)p_String + a1 + v18 - (_QWORD)&String);
          if ( !v19 )
            break;
          *p_String = v19;
          --v17;
          ++p_String;
        }
        v20 = p_String - 1;
        if ( v17 )
          v20 = p_String;
        *v20 = 0;
        v6 = v17 == 0 ? 0x8007007A : 0;
        if ( !v17 )
          goto LABEL_6;
        v6 = 0;
        if ( (unsigned __int16)(String - 48) > 9u )
        {
          v6 = -1073418163;
          sub_1800038E8(3221549133i64);
        }
        else
        {
          v2 = wtoi(&String);
        }
        sub_180003B30(v6, v21, v22);
        if ( (v6 & 0x80000000) != 0 )
          goto LABEL_6;
        v5 = sub_180006D28(v3, v34, v18 + a1);
        v6 = v5;
        if ( v5 < 0 )
          goto LABEL_2;
      }
      else
      {
        v2 = 0;
        v15 = 0;
        if ( v12 )
          goto LABEL_36;
      }
LABEL_54:
      *(_DWORD *)Buffer = 0;
      itow_s(v2 % 7, Buffer, 2ui64, 10);
      v5 = sub_180006D28(v3, v34, Buffer);
      v6 = v5;
      if ( v5 < 0 )
        goto LABEL_2;
      if ( ++v14 >= v11 )
        goto LABEL_57;
      v12 = v36;
    }
    v12 = 6;
    v2 = 0;
    v15 = 0;
LABEL_36:
    v23 = 6 * v14;
    v38 = v23;
    while ( 1 )
    {
      v24 = &String;
      v25 = 2 * (v23 + v15);
      for ( i = 2i64; i != 1; --i )
      {
        v27 = *(wchar_t *)((char *)v24 + a1 + v25 - (_QWORD)&String);
        if ( !v27 )
          break;
        *v24++ = v27;
      }
      v28 = v24 - 1;
      if ( i )
        v28 = v24;
      *v28 = 0;
      v6 = i == 0 ? 0x8007007A : 0;
      if ( !i )
        goto LABEL_6;
      v6 = 0;
      if ( (unsigned __int16)(String - 48) > 9u )
      {
        v6 = -1073418163;
        sub_1800038E8(3221549133i64);
      }
      else
      {
        v33 = wtoi(&String);
      }
      sub_180003B30(v6, v29, v30);
      if ( (v6 & 0x80000000) != 0 )
        goto LABEL_6;
      if ( (v15 & 1) != 0 )
        v2 += 2 * v33;
      else
        v2 += v33;
      v5 = sub_180006D28(v3, v34, v25 + a1);
      v6 = v5;
      if ( v5 < 0 )
        goto LABEL_2;
      v23 = v38;
      if ( ++v15 >= v12 )
      {
        v11 = v37;
        goto LABEL_54;
      }
    }
  }
LABEL_57:
  v31 = v3;
  v3 = 0i64;
  *v40 = v31;
LABEL_58:
  sub_180003B30(v6, v8, v9);
  if ( v3 )
    LocalFree(v3);
  return v6;
}

// called by sub_180005D58
__int64 __fastcall sub_180006D28(_WORD *a1, __int64 a2, __int64 a3)
{
  __int64 v5; // r10
  _WORD *v6; // rax
  unsigned int v7; // edx
  __int64 v8; // r8
  _WORD *v9; // rdx
  __int64 v10; // rcx
  __int64 v11; // rax
  __int64 v12; // r11
  __int16 v13; // r8
  _WORD *v14; // rax

  if ( (unsigned __int64)(a2 - 1) > 0x7FFFFFFE )
  {
    return (unsigned int)-2147024809;
  }
  else
  {
    v5 = a2;
    v6 = a1;
    do
    {
      if ( !*v6 )
        break;
      ++v6;
      --v5;
    }
    while ( v5 );
    v7 = v5 == 0 ? 0x80070057 : 0;
    v8 = (a2 - v5) & -(__int64)(v5 != 0);
    if ( v5 )
    {
      v9 = &a1[v8];
      v10 = a2 - v8;
      if ( a2 != v8 )
      {
        v11 = 1i64;
        v12 = a3 - (_QWORD)v9;
        do
        {
          if ( !v11 )
            break;
          v13 = *(_WORD *)((char *)v9 + v12);
          if ( !v13 )
            break;
          *v9 = v13;
          --v11;
          ++v9;
          --v10;
        }
        while ( v10 );
      }
      v14 = v9 - 1;
      if ( v10 )
        v14 = v9;
      v7 = v10 == 0 ? 0x8007007A : 0;
      *v14 = 0;
    }
  }
  return v7;
}