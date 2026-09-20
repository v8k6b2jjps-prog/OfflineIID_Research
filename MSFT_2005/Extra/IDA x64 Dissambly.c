function Get-PKeyData {
    param (
        [string]$key,
        [string]$configPath,
        [Int64]$HWID = 0L,
        [switch]$AsObject
    )

    $MPC        = [IntPtr]::Zero
    $IID        = ""
    $Edition    = ""
    $Channel    = ""
    $Partnum    = ""

    # for the right way to calculate IID
    # use SLGenerateOfflineInstallationIdEx
    # cause we dont know the hwid value

    # to receive the confirmation ID ........
    # you will have to have the extended product id too.
    #Call-WebService -requestType 1 -installationId $ppwszInstallation

    $results = @()

    try {
        # Validate input
        if ([string]::IsNullOrWhiteSpace($key) -or [string]::IsNullOrWhiteSpace($configPath)) {
            throw "KEY and CONFIG PATH cannot be empty."
        }
            
        try {
            
            $ret = $Global:PIDGENX::GetPKeyData(
                $key, $configPath, $Mpc, [IntPtr]::Zero, $HWID,
                [ref]$IID, [ref]$Edition, [ref]$Channel, [ref]$Partnum,
                [IntPtr]::Zero
            )

        } catch {
                
			<#
            >>> .InnerException Class <<<
            -----------------------------

            ErrorCode      : -1979645951
            Message        : Exception from HRESULT: 0x8A010001
            Data           : {}
            InnerException : 
            TargetSite     : Int32 PidGenX(System.String, System.String, System.String, Int32, IntPtr, IntPtr, IntPtr)
            StackTrace     :    at 0.PidGenX(String , String , String , Int32 , IntPtr , IntPtr , IntPtr )
								            at CallSite.Target(Closure , CallSite , Object , String , String , String , Int32 , IntPtr , IntPtr , Object )
            HelpLink       : 
            Source         : 4
            HResult        : -1979645951
            #>

            # Access the inner exception
            $innerException = $_.Exception.InnerException

            # Get the HResult directly
            $HResult   = $innerException.HResult
            $ErrorCode = $innerException.ErrorCode

            # Convert HResult to hexadecimal
            $HResultHex = "0x{0:X8}" -f $HResult

            throw "HRESULT: $ErrorText ($HResultHex)"
        }

        if ($ret -ne 0x0) {

            $HResultHex = "0x{0:X8}" -f $ret
            $ErrorText = Parse-ErrorMessage -MessageId $HResultHex
            throw "HRESULT: $ErrorText ($HResultHex)"
        }

        if ($AsObject) {
            return (
                [PSObject]@{
                    Edition = $Edition
                    Channel = $Channel
                    Partnum = $Partnum
                    IID     = $IID
                }
            )
        } else {
            $results += @{ Property = "Edition"; Value = $Edition }
            $results += @{ Property = "Channel"; Value = $Channel }
            $results += @{ Property = "Partnum"; Value = $Partnum }
            $results += @{ Property = "IID";     Value = $IID }
            return $results
        }
    } catch {
        if ($AsObject) {
            return (
                [PSObject]@{
                    Error = "$($_.Exception.Message)"
                }
            )
        } else {
            return (
                @{ Property = "Error"; Value = "$($_.Exception.Message)" }
            )
        }
    }
}

__int64 __fastcall GetPKeyData(
        wchar_t *Str,
        __int64 a2,
        const wchar_t *a3,
        __int64 a4,
        __int64 a5,
        _QWORD *a6,
        _QWORD *a7,
        _QWORD *a8,
        _QWORD *a9,
        __int64 a10)
{
  _OWORD *v12; // rbx
  void *v13; // rdi
  __int64 v14; // rcx
  unsigned int v15; // r14d
  int v16; // eax
  const wchar_t *v17; // rcx
  __int64 v18; // rax
  int v19; // r10d
  unsigned int v20; // edx
  HANDLE ProcessHeap; // rax
  _OWORD *v22; // rax
  int v23; // edx
  int v24; // r9d
  int v25; // eax
  LPVOID v26; // rax
  LPVOID v27; // rax
  LPVOID v28; // rax
  LPVOID v29; // rax
  LPVOID v30; // rdx
  void *v31; // rsi
  HANDLE v32; // rax
  void *v33; // rsi
  HANDLE v34; // rax
  void *v35; // rsi
  HANDLE v36; // rax
  void *v37; // rsi
  HANDLE v38; // rax
  HANDLE v39; // rax
  HANDLE v40; // rax
  void *v41; // rbx
  HANDLE v42; // rax
  void *v43; // rbx
  HANDLE v44; // rax
  LPVOID lpMem; // [rsp+48h] [rbp-49h] BYREF
  LPVOID v47; // [rsp+50h] [rbp-41h] BYREF
  int v48; // [rsp+58h] [rbp-39h]
  LPVOID v49; // [rsp+60h] [rbp-31h] BYREF
  __int64 v50; // [rsp+68h] [rbp-29h] BYREF
  LPVOID v51; // [rsp+70h] [rbp-21h] BYREF
  LPVOID v52; // [rsp+78h] [rbp-19h] BYREF
  LPVOID v53; // [rsp+80h] [rbp-11h] BYREF
  __int64 v54[2]; // [rsp+88h] [rbp-9h] BYREF

  v54[0] = 0i64;
  v12 = 0i64;
  v47 = 0i64;
  v13 = 0i64;
  v50 = 0i64;
  v49 = 0i64;
  v53 = 0i64;
  v52 = 0i64;
  v51 = 0i64;
  lpMem = 0i64;
  v48 = 0;
  if ( !a6 || !a7 || !a8 || !a9 )
  {
LABEL_2:
    v14 = 2147942487i64;
    v15 = -2147024809;
LABEL_32:
    sub_1800038E8(v14);
    goto LABEL_33;
  }
  if ( a2 )
    v16 = sub_1800057E0(v54, L"%s", a2);
  else
    v16 = sub_180004D94(Str, v54);
  v15 = v16;
  if ( v16 < 0 )
    goto LABEL_31;
  if ( !a3 )
  {
    v16 = sub_1800039A0(Str);
    v15 = v16;
    if ( v16 >= 0 )
    {
      v17 = L"03612";
      goto LABEL_11;
    }
LABEL_31:
    v14 = (unsigned int)v16;
    goto LABEL_32;
  }
  v17 = a3;
LABEL_11:
  v16 = sub_180003364(v17, &v47);
  v15 = v16;
  if ( v16 < 0 )
    goto LABEL_31;
  v16 = sub_180015270(&v50);
  v15 = v16;
  if ( v16 < 0 )
    goto LABEL_31;
  v16 = (*(__int64 (__fastcall **)(__int64, __int64, _QWORD, _QWORD, _QWORD))(*(_QWORD *)v50 + 40i64))(
          v50,
          v54[0],
          0i64,
          0i64,
          0i64);
  v15 = v16;
  if ( v16 < 0 )
    goto LABEL_31;
  v16 = (*(__int64 (__fastcall **)(__int64, _QWORD, wchar_t *, _QWORD, _DWORD, LPVOID *))(*(_QWORD *)v50 + 64i64))(
          v50,
          0i64,
          Str,
          0i64,
          0,
          &lpMem);
}

__int64 __fastcall sub_180015270(__int64 a1)
{
  unsigned __int64 v2; // rbx
  unsigned int v3; // edi
  HANDLE ProcessHeap; // rax
  unsigned __int64 v5; // rax
  int v6; // eax
  int v7; // eax
  __int64 v8; // rcx

  v2 = 0i64;
  if ( !a1 )
  {
    v3 = -2147024809;
LABEL_10:
    v8 = v3;
    goto LABEL_11;
  }
  ProcessHeap = GetProcessHeap();
  v5 = (unsigned __int64)HeapAlloc(ProcessHeap, 0, 0xC0ui64);
  v2 = v5;
  if ( !v5 )
  {
    v2 = 0i64;
    v3 = -2147024882;
    goto LABEL_10;
  }
  *(_DWORD *)(v5 + 12) = 0;
  memset((void *)(v5 & -(__int64)(v5 != -8i64)), 0, 0xC0ui64);
  *(_DWORD *)(v2 + 8) = 1;
  memset((void *)(v2 + 20), 0, 0xACui64);
  *(_DWORD *)(v2 + 16) = 1;
  memset((void *)(v2 + 24), 0, 0x68ui64);
  *(_QWORD *)(v2 + 72) = 0i64;
  *(_QWORD *)(v2 + 80) = 0i64;
  *(_QWORD *)(v2 + 104) = 0i64;
  *(_QWORD *)(v2 + 112) = 0i64;
  *(_QWORD *)(v2 + 128) = 0i64;
  *(_QWORD *)(v2 + 136) = 0i64;
  *(_QWORD *)(v2 + 144) = 0i64;
  *(_QWORD *)(v2 + 152) = 0i64;
  *(_QWORD *)(v2 + 160) = 0i64;
  *(_QWORD *)(v2 + 168) = 0i64;
  *(_QWORD *)(v2 + 176) = 0i64;
  *(_QWORD *)(v2 + 184) = 0i64;
  *(_QWORD *)v2 = off_1800A02D0;
  v6 = sub_180010148(v2 + 16);
  v3 = v6;
  if ( v6 < 0 )
    sub_1800038E8((unsigned int)v6);
  sub_180003B30(v3);
  if ( (v3 & 0x80000000) != 0 )
    goto LABEL_10;
  v7 = (**(__int64 (__fastcall ***)(unsigned __int64, __int64 *, __int64))v2)(v2, &qword_1800A7240, a1);
  v3 = v7;
  if ( v7 >= 0 )
    goto LABEL_12;
  v8 = (unsigned int)v7;
LABEL_11:
  sub_1800038E8(v8);
LABEL_12:
  sub_180003B30(v3);
  if ( v2 )
    (*(void (__fastcall **)(unsigned __int64))(*(_QWORD *)v2 + 16i64))(v2);
  return v3;
}
		  
/* 
.rdata:00000001800A02D0 off_1800A02D0   dq offset sub_180012AE0 ; DATA XREF: sub_180015270+BB↑o
.rdata:00000001800A02D8                 dq offset sub_18000AC90
.rdata:00000001800A02E0                 dq offset sub_180012DA0 >>> MAYBE
.rdata:00000001800A02E8                 dq offset sub_18000C6E0 >>> MAYBE
.rdata:00000001800A02F0                 dq offset sub_18000C6D0 >>> MAYBE
.rdata:00000001800A02F8                 dq offset sub_18000C970 >>> MAYBE
.rdata:00000001800A0300                 dq offset sub_18000C960
.rdata:00000001800A0308                 dq offset sub_18000EF70
.rdata:00000001800A0310                 dq offset sub_18000D160
*/

__int64 __fastcall sub_18000D160(__int64 a1, const wchar_t *a2, __int64 a3, __int64 a4, int a5, __int64 a6)
{
  return sub_180009A24(a1 + 16, a2, a3, a4, a5, a6);
}

__int64 __fastcall sub_180009A24(__int64 a1, const wchar_t *a2, __int64 a3, __int64 a4, int a5, __int64 a6)
{
  __int64 v6; // r15
  void *v7; // rbx
  unsigned int v8; // edi
  _DWORD *v9; // r14
  __int64 v13; // rcx
  unsigned int v14; // edi
  __int64 v15; // r8
  int v16; // r9d
  int v17; // ecx
  int v18; // edx
  int v19; // ecx
  int v20; // ecx
  int v21; // eax
  int v22; // eax
  HANDLE ProcessHeap; // rax
  void *v24; // rbx
  HANDLE v25; // rax
  int v27; // [rsp+40h] [rbp-20h]
  int v28; // [rsp+44h] [rbp-1Ch]
  LPVOID v29; // [rsp+48h] [rbp-18h] BYREF
  LPVOID lpMem; // [rsp+50h] [rbp-10h] BYREF
  unsigned __int16 *v31; // [rsp+58h] [rbp-8h]
  unsigned int v32; // [rsp+A0h] [rbp+40h] BYREF
  __int64 v33; // [rsp+B0h] [rbp+50h]
  unsigned int v34; // [rsp+B8h] [rbp+58h] BYREF

  v33 = a3;
  v29 = 0i64;
  v6 = a1 + 8;
  v7 = 0i64;
  v8 = 0;
  v34 = 0;
  v9 = 0i64;
  v31 = 0i64;
  v27 = 0;
  lpMem = 0i64;
  v32 = 0;
  if ( a1 != -8 )
  {
    sub_18000AA3C(a1 + 8);
    v27 = 1;
  }
  if ( !a4 )
  {
LABEL_24:
    v21 = sub_180009338(a1, a2, v33, v31, v9, v8, a5, a6);
    v14 = v21;
    if ( v21 >= 0 )
      goto LABEL_27;
    goto LABEL_25;
  }
  if ( *(_DWORD *)a4 < 0x18u )
    goto LABEL_5;
  v15 = *(_QWORD *)(a4 + 8);
  if ( !v15 )
    goto LABEL_5;
  v16 = *(_DWORD *)(a4 + 16);
  if ( !v16 )
    goto LABEL_5;
  v17 = *(_DWORD *)(a4 + 4);
  v18 = (*(_DWORD *)(a4 + 20) >> 1) & 1;
  v28 = *(_DWORD *)(a4 + 20) & 1;
  if ( v17 )
  {
    v19 = v17 - 1;
    if ( v19 )
    {
      v20 = v19 - 1;
      if ( v20 )
      {
        if ( v20 == 1 && v16 == 1 )
        {
          v31 = *(unsigned __int16 **)(a4 + 8);
          goto LABEL_19;
        }
LABEL_5:
        v13 = 2147749926i64;
        v14 = -2147217370;
LABEL_26:
        sub_1800038E8(v13);
        goto LABEL_27;
      }
      v21 = sub_18000F06C(a1, (_DWORD)a2, v15, v16, v18, (__int64)&v29, (__int64)&v32);
    }
    else
    {
      v21 = sub_18000F25C(a1, (_DWORD)a2, v15, v16, v18, (__int64)&v29, (__int64)&v32);
    }
  }
  else
  {
    v21 = sub_18001458C(a1, (_DWORD)a2, v15, v16, v18, (__int64)&v29, (__int64)&v32);
  }
  v14 = v21;
  if ( v21 < 0 )
  {
LABEL_25:
    v13 = (unsigned int)v21;
    goto LABEL_26;
  }
  v9 = v29;
  v8 = v32;
LABEL_19:
  if ( v28 || *(_DWORD *)(a4 + 4) == 3 )
    goto LABEL_24;
  v22 = sub_18000ACA4(a1, a2, v9, v8, &lpMem, &v34);
  v14 = v22;
  if ( v22 >= 0 )
  {
    v7 = lpMem;
    v8 = v34;
    v9 = lpMem;
    goto LABEL_24;
  }
  sub_1800038E8((unsigned int)v22);
  v7 = lpMem;
LABEL_27:
  sub_180003B30(v14);
  if ( v6 && v27 )
    sub_180012E7C(v6);
  if ( v7 )
  {
    ProcessHeap = GetProcessHeap();
    HeapFree(ProcessHeap, 0, v7);
  }
  v24 = v29;
  if ( v29 )
  {
    v25 = GetProcessHeap();
    HeapFree(v25, 0, v24);
  }
  return v14;
}

// Main handler

__int64 __fastcall sub_180009338(
        __int64 a1,
        const wchar_t *a2,
        __int64 a3,
        unsigned __int16 *a4,
        _DWORD *a5,
        unsigned int a6,
        int a7,
        __int64 a8)
{
  int v9; // esi
  _QWORD *v13; // rbx
  unsigned int v14; // r12d
  int v15; // eax
  __int64 v16; // r8
  int v17; // edi
  __int64 v18; // rcx
  int v19; // eax
  unsigned __int16 *v20; // rax
  int v21; // edx
  int v22; // ecx
  __int64 *v23; // r14
  size_t v24; // rsi
  __int64 v25; // r9
  __int64 v26; // r12
  __int64 v27; // r9
  char *v28; // rcx
  signed __int64 v29; // r15
  int v30; // edx
  int v31; // eax
  unsigned __int16 *v32; // rcx
  __int64 v33; // rdx
  int v34; // r8d
  int v35; // eax
  __int64 v36; // rdx
  _DWORD *v37; // r15
  __int64 v38; // rdx
  size_t v39; // r14
  HANDLE v40; // rax
  unsigned int v41; // r8d
  signed int i; // edx
  __int64 v43; // rdi
  unsigned __int16 *v44; // rcx
  size_t v45; // r10
  int v46; // r9d
  int v47; // eax
  __int64 v48; // rax
  __int64 v49; // r8
  unsigned int j; // eax
  unsigned __int16 *v51; // rax
  int v52; // edx
  int v53; // ecx
  int v54; // r14d
  HANDLE ProcessHeap; // rax
  _QWORD *v56; // rax
  __int64 v57; // r9
  unsigned int v58; // r12d
  size_t v59; // r14
  _QWORD *v60; // rdi
  unsigned __int16 *v61; // rax
  size_t v62; // r8
  int v63; // edx
  int v64; // ecx
  HANDLE v65; // rax
  int v67; // [rsp+30h] [rbp-C9h] BYREF
  __int64 v68; // [rsp+38h] [rbp-C1h] BYREF
  size_t Size; // [rsp+40h] [rbp-B9h]
  int v70; // [rsp+48h] [rbp-B1h]
  __int64 v71; // [rsp+50h] [rbp-A9h] BYREF
  RPC_WSTR StringUuid; // [rsp+58h] [rbp-A1h]
  __int64 v73; // [rsp+60h] [rbp-99h]
  __int64 v74; // [rsp+68h] [rbp-91h]
  _QWORD v75[12]; // [rsp+70h] [rbp-89h] BYREF
  UUID Uuid; // [rsp+D0h] [rbp-29h] BYREF
  __int64 v77; // [rsp+E0h] [rbp-19h] BYREF
  int v78; // [rsp+E8h] [rbp-11h]
  char v79; // [rsp+ECh] [rbp-Dh]

  v9 = a6;
  Size = (size_t)a2;
  StringUuid = a4;
  v73 = a8;
  memset(v75, 0, 0x58ui64);
  v67 = 0;
  v70 = 0;
  v13 = 0i64;
  v68 = 0i64;
  v14 = 0;
  v71 = 0i64;
  v74 = a1 + 8;
  memset(&v75[1], 0, 40);
  Uuid = 0i64;
  if ( a1 != -8 )
  {
    sub_18000AA3C(a1 + 8);
    v70 = 1;
  }
  v15 = sub_1800090B0(a3, v75);
  v17 = v15;
  if ( v15 == -2147217327 )
    goto LABEL_4;
  if ( v15 < 0 )
    goto LABEL_6;
  if ( a2 )
  {
    if ( LODWORD(v75[1]) || __PAIR64__(HIDWORD(v75[1]), 0) != LODWORD(v75[2]) || HIDWORD(v75[2]) )
    {
      v19 = sub_18000EE1C(&v75[1], &v68, v16, 0i64);
      v17 = v19;
      if ( v19 < 0 )
        goto LABEL_113;
      v20 = (unsigned __int16 *)v68;
      do
      {
        v21 = *(unsigned __int16 *)((char *)a2 + (_QWORD)v20 - v68);
        v22 = *v20 - v21;
        if ( v22 )
          break;
        ++v20;
      }
      while ( v21 );
      if ( v22 )
        goto LABEL_12;
    }
    else if ( !wcscmp(a2, L"msft:rm/algorithm/pkey/2009") )
    {
LABEL_12:
      v18 = 2147749922i64;
LABEL_13:
      v17 = v18;
      goto LABEL_114;
    }
  }
  if ( a4 )
  {
    LODWORD(Size) = 13;
    v77 = 0i64;
    v78 = 0;
    v79 = 0;
    v23 = &v77;
    v17 = sub_180011E1C(StringUuid, &Uuid, (__int64)&v68);
    if ( v17 < 0 )
      goto LABEL_6;
    v24 = (unsigned int)Size;
    if ( !(_DWORD)Size )
      v23 = 0i64;
    if ( !(unsigned __int8)sub_18000E7E8(a1 + 112, &Uuid, &v67) )
      goto LABEL_24;
    if ( !(unsigned __int8)sub_18000E8E8(
                             a1 + 128,
                             *(unsigned int *)(*(_QWORD *)(*(_QWORD *)(a1 + 120) + 8i64 * v67) + 20i64),
                             &v67,
                             v25) )
    {
      v17 = -2147418113;
      goto LABEL_6;
    }
    v26 = v67;
    if ( LODWORD(v75[3]) )
    {
      if ( LODWORD(v75[3]) != *(_DWORD *)(*(_QWORD *)(*(_QWORD *)(a1 + 136) + 8i64 * v67) + 4i64) )
        goto LABEL_24;
    }
    if ( a2 )
    {
      v27 = *(_QWORD *)(a1 + 136);
      v28 = *(char **)(*(_QWORD *)(v27 + 8i64 * v67) + 8i64);
      v29 = (char *)a2 - v28;
      do
      {
        v30 = *(unsigned __int16 *)&v28[v29];
        v31 = *(unsigned __int16 *)v28 - v30;
        if ( v31 )
          break;
        v28 += 2;
      }
      while ( v30 );
      if ( v31 )
        goto LABEL_24;
      if ( v68 )
      {
        v32 = *(unsigned __int16 **)(*(_QWORD *)(v27 + 8i64 * v67) + 8i64);
        v33 = v68 - (_QWORD)v32;
        do
        {
          v34 = *(unsigned __int16 *)((char *)v32 + v33);
          v35 = *v32 - v34;
          if ( v35 )
            break;
          ++v32;
        }
        while ( v34 );
        if ( v35 )
        {
LABEL_24:
          v18 = 2147749921i64;
          goto LABEL_13;
        }
      }
    }
    v17 = 0;
    if ( HIDWORD(v75[6]) )
    {
      if ( !(_DWORD)v24
        || (_DWORD)v24 == 13
        && v75[9] == *v23
        && LODWORD(v75[10]) == *((_DWORD *)v23 + 2)
        && BYTE4(v75[10]) == *((_BYTE *)v23 + 12) )
      {
        goto LABEL_50;
      }
    }
    else if ( (unsigned int)v24 <= 0xD )
    {
      v75[9] = 0i64;
      LODWORD(v75[10]) = 0;
      BYTE4(v75[10]) = 0;
      if ( (_DWORD)v24 )
      {
        memcpy(&v75[9], v23, v24);
        HIDWORD(v75[6]) = 1;
      }
      goto LABEL_50;
    }
    v17 = -2147217375;
    sub_1800038E8(2147749921i64);
LABEL_50:
    sub_180003B30((unsigned int)v17);
    if ( v17 < 0 )
      sub_1800038E8((unsigned int)v17);
    sub_180003B30((unsigned int)v17);
    if ( v17 < 0 )
      goto LABEL_6;
    v36 = *(_QWORD *)(a1 + 136) + 8 * v26;
    goto LABEL_54;
  }
  v37 = a5;
  if ( a5 )
  {
    if ( a6 )
    {
      v38 = LODWORD(v75[3]);
      if ( LODWORD(v75[3]) )
        goto LABEL_79;
      v54 = 0;
      if ( (a6 & 0x1FFFFFFF) == a6 )
      {
        v14 = 8 * a6;
      }
      else
      {
        v54 = -2147024362;
        sub_1800038E8(2147942934i64);
      }
      sub_180003B30((unsigned int)v54);
      v17 = v54;
      if ( v54 < 0 )
      {
        v18 = (unsigned int)v54;
        goto LABEL_114;
      }
      ProcessHeap = GetProcessHeap();
      v56 = HeapAlloc(ProcessHeap, 0, v14);
      v57 = 0i64;
      v13 = v56;
      if ( !v56 )
        goto LABEL_67;
      v58 = 0;
      v59 = Size;
      v60 = v56;
      while ( (unsigned __int8)sub_18000E8E8(a1 + 128, (unsigned int)*v37, &v67, v57) )
      {
        if ( v59 )
        {
          v61 = *(unsigned __int16 **)(*(_QWORD *)(*(_QWORD *)(a1 + 136) + 8i64 * v67) + 8i64);
          v62 = v59 - (_QWORD)v61;
          do
          {
            v63 = *(unsigned __int16 *)((char *)v61 + v62);
            v64 = *v61 - v63;
            if ( v64 )
              break;
            ++v61;
          }
          while ( v63 );
          if ( v64 )
            break;
        }
        ++v58;
        ++v37;
        *v60++ = *(_QWORD *)(*(_QWORD *)(a1 + 136) + 8i64 * v67);
        if ( v58 >= a6 )
          goto LABEL_109;
      }
    }
LABEL_77:
    v18 = 2147749926i64;
    goto LABEL_13;
  }
  v38 = LODWORD(v75[3]);
  if ( !LODWORD(v75[3]) )
  {
    v39 = Size;
    v9 = *(_DWORD *)(a1 + 132);
    if ( !Size )
    {
      if ( !v9 )
        goto LABEL_4;
      v36 = *(_QWORD *)(a1 + 136);
LABEL_110:
      if ( v9 >= 1 )
        goto LABEL_111;
LABEL_4:
      v17 = -2147217373;
LABEL_6:
      v18 = (unsigned int)v17;
LABEL_114:
      sub_1800038E8(v18);
      goto LABEL_115;
    }
    v17 = 0;
    if ( v9 )
    {
      if ( (v9 & 0x1FFFFFFF) == v9 )
      {
        v14 = 8 * v9;
      }
      else
      {
        v17 = -2147024362;
        sub_1800038E8(2147942934i64);
      }
    }
    else
    {
      v14 = 0;
    }
    sub_180003B30((unsigned int)v17);
    if ( v17 < 0 )
      goto LABEL_6;
    v40 = GetProcessHeap();
    v13 = HeapAlloc(v40, 0, v14);
    if ( v13 )
    {
      v41 = 0;
      for ( i = 0; i < (unsigned int)v9; ++i )
      {
        v43 = *(_QWORD *)(a1 + 136);
        v44 = *(unsigned __int16 **)(*(_QWORD *)(v43 + 8i64 * i) + 8i64);
        v45 = v39 - (_QWORD)v44;
        do
        {
          v46 = *(unsigned __int16 *)((char *)v44 + v45);
          v47 = *v44 - v46;
          if ( v47 )
            break;
          ++v44;
        }
        while ( v46 );
        if ( !v47 )
        {
          v48 = v41++;
          v13[v48] = *(_QWORD *)(v43 + 8i64 * i);
        }
      }
      v9 = v41;
LABEL_109:
      LODWORD(v36) = (_DWORD)v13;
      goto LABEL_110;
    }
LABEL_67:
    v13 = 0i64;
    v18 = 2147942414i64;
    goto LABEL_13;
  }
LABEL_79:
  if ( !(unsigned __int8)sub_18000E8E8(a1 + 128, v38, &v67, 0i64) )
  {
    v17 = -2147217388;
    goto LABEL_6;
  }
  if ( a6 )
  {
    for ( j = 0; j < a6; ++j )
    {
      if ( *v37 == LODWORD(v75[3]) )
        break;
      ++v37;
    }
    if ( j >= a6 )
      goto LABEL_77;
  }
  if ( LODWORD(v75[1]) || __PAIR64__(HIDWORD(v75[1]), 0) != LODWORD(v75[2]) || HIDWORD(v75[2]) )
  {
    v19 = sub_18000EE1C(&v75[1], &v68, v49, 0i64);
    v17 = v19;
    if ( v19 >= 0 )
    {
      v51 = (unsigned __int16 *)v68;
      do
      {
        v52 = *(unsigned __int16 *)((char *)v51
                                  + *(_QWORD *)(*(_QWORD *)(*(_QWORD *)(a1 + 136) + 8i64 * v67) + 8i64)
                                  - v68);
        v53 = *v51 - v52;
        if ( v53 )
          break;
        ++v51;
      }
      while ( v52 );
      if ( v53 )
        goto LABEL_12;
      goto LABEL_94;
    }
LABEL_113:
    v18 = (unsigned int)v19;
    goto LABEL_114;
  }
LABEL_94:
  v36 = *(_QWORD *)(a1 + 136) + 8i64 * v67;
LABEL_54:
  v9 = 1;
LABEL_111:
  v19 = sub_180014DA4((unsigned int)v75, v36, v9, a7, (__int64)&v71);
  v17 = v19;
  if ( v19 < 0 )
    goto LABEL_113;
  v19 = sub_180014730(a1, v75, v71, v73);
  v17 = v19;
  if ( v19 < 0 )
    goto LABEL_113;
LABEL_115:
  sub_180003B30((unsigned int)v17);
  if ( v13 )
  {
    v65 = GetProcessHeap();
    HeapFree(v65, 0, v13);
  }
  if ( v74 && v70 )
    sub_180012E7C();
  return (unsigned int)v17;
}

__int64 __fastcall sub_180014DA4(__int64 a1, __int64 *a2, unsigned int a3, int a4, _QWORD *a5)
{
  char *v5; // rbx
  _QWORD *v6; // rdi
  HANDLE ProcessHeap; // rax
  char *v11; // rax
  int v12; // eax
  unsigned int v13; // esi
  __int64 v14; // rcx
  HANDLE v15; // rax
  _QWORD *v16; // rax
  HANDLE *v17; // r14
  HANDLE EventW; // rsi
  signed int LastError; // eax
  __int64 v20; // r14
  int v21; // eax
  __int64 v23; // [rsp+20h] [rbp-48h]
  __int64 v24; // [rsp+30h] [rbp-38h] BYREF
  _QWORD *v25; // [rsp+38h] [rbp-30h] BYREF

  v5 = 0i64;
  v6 = 0i64;
  v25 = 0i64;
  if ( a4 == 1 || a3 == 1 )
  {
    if ( a3 )
    {
      while ( 1 )
      {
        v20 = *a2;
        v21 = sub_18001506C(a1, *a2, *(_QWORD *)(*a2 + 32), *(_DWORD *)(*a2 + 40), v23);
        v13 = v21;
        if ( v21 >= 0 || (v21 & 0x1FFF0000) != 0x40000 )
          break;
        LODWORD(v6) = (_DWORD)v6 + 1;
        ++a2;
        if ( (unsigned int)v6 >= a3 )
          goto LABEL_28;
      }
      if ( v21 >= 0 )
      {
        v13 = 0;
        *a5 = v20;
LABEL_30:
        sub_180003B30(v13);
        if ( (v13 & 0x80000000) == 0 )
          goto LABEL_33;
        goto LABEL_31;
      }
    }
    else
    {
LABEL_28:
      v13 = -2147217373;
    }
    sub_1800038E8(v13);
    goto LABEL_30;
  }
  ProcessHeap = GetProcessHeap();
  v11 = (char *)HeapAlloc(ProcessHeap, 0, 0xC0ui64);
  v5 = v11;
  if ( !v11 )
  {
    v5 = 0i64;
    v14 = 2147942414i64;
    goto LABEL_20;
  }
  memset(v11, 0, 0xC0ui64);
  *((_QWORD *)v5 + 8) = -1i64;
  *(_DWORD *)v5 = 1;
  sub_180013040(v5);
  memset(v5 + 80, 0, 0x58ui64);
  *(_OWORD *)(v5 + 88) = 0i64;
  *(_OWORD *)(v5 + 104) = 0i64;
  *((_QWORD *)v5 + 15) = 0i64;
  *((_QWORD *)v5 + 21) = 0i64;
  v12 = sub_18000FE2C(v5, a1, a2, a3);
  v13 = v12;
  if ( v12 >= 0 )
  {
    v13 = 0;
    v15 = GetProcessHeap();
    v16 = HeapAlloc(v15, 0, 0x10ui64);
    if ( v16 )
    {
      v16[1] = 0i64;
      v6 = v16;
      v24 = 0i64;
      *(_DWORD *)v16 = 1;
      v25 = v16;
    }
    else
    {
      v24 = 0i64;
      v13 = -2147024882;
      sub_1800038E8(2147942414i64);
    }
    sub_180003B30(v13);
    sub_18000A614(&v24);
    if ( (v13 & 0x80000000) != 0 )
    {
LABEL_31:
      v14 = v13;
      goto LABEL_32;
    }
    v17 = (HANDLE *)(v6 + 1);
    EventW = CreateEventW(0i64, 1, 0, 0i64);
    if ( v6[1] )
    {
      CloseHandle((HANDLE)v6[1]);
      *v17 = 0i64;
    }
    if ( !EventW )
    {
      *v17 = 0i64;
      LastError = GetLastError();
      v13 = LastError;
      if ( LastError )
      {
        if ( LastError > 0 )
          v13 = (unsigned __int16)LastError | 0x80070000;
      }
      else
      {
        v13 = -2147467259;
      }
      goto LABEL_31;
    }
    *v17 = EventW;
    v12 = sub_18000D170(v5);
    v13 = v12;
    if ( v12 < 0 )
      goto LABEL_5;
    if ( !WaitForSingleObject(*v17, 0x36EE80u) )
    {
      v12 = sub_18000F4A8(v5, a1, a5);
      v13 = v12;
      if ( v12 >= 0 )
        goto LABEL_33;
      goto LABEL_5;
    }
    v14 = 2147549183i64;
LABEL_20:
    v13 = v14;
    goto LABEL_32;
  }
LABEL_5:
  v14 = (unsigned int)v12;
LABEL_32:
  sub_1800038E8(v14);
LABEL_33:
  sub_180003B30(v13);
  sub_18000A614(&v25);
  if ( v5 )
    sub_180012DFC(v5);
  return v13;
}

__int64 __fastcall sub_180014730(__int64 a1, __int64 a2, __int64 a3, _QWORD *a4)
{
  int v5; // r14d
  int v9; // ebp
  void *v10; // rbx
  int v11; // edx
  int v12; // eax
  unsigned int v13; // edi
  __int64 v14; // rcx
  __int64 v15; // rdi
  __int64 v16; // rbp
  HANDLE ProcessHeap; // rax
  char *v18; // rax
  char *v19; // rsi
  HANDLE v20; // rax
  char v22; // [rsp+70h] [rbp+8h] BYREF
  int v23; // [rsp+78h] [rbp+10h] BYREF

  v5 = a1 + 144;
  v9 = *(_DWORD *)(a2 + 32) + 1000000 * *(_DWORD *)(a2 + 28);
  v10 = 0i64;
  v11 = *(_DWORD *)(a3 + 4);
  v23 = 0;
  v22 = 0;
  v12 = sub_18000EC1C((int)a1 + 144, v11, 0, v9, (__int64)&v22, (__int64)&v23);
  v13 = v12;
  if ( v12 < 0 )
    goto LABEL_2;
  if ( v22 )
  {
    v13 = -2147217371;
LABEL_14:
    v14 = v13;
    goto LABEL_15;
  }
  v12 = sub_18000EC1C(v5, *(_DWORD *)(a3 + 4), 1, v9, (__int64)&v22, (__int64)&v23);
  v13 = v12;
  if ( v12 < 0 )
    goto LABEL_2;
  if ( !v22 )
  {
    v13 = -2147217372;
    goto LABEL_14;
  }
  v15 = *(_QWORD *)(*(_QWORD *)(a1 + 152) + 8i64 * v23);
  if ( !(unsigned __int8)sub_18000E7E8(a1 + 112, v15 + 4, &v23) )
  {
    v13 = -2147418113;
    goto LABEL_14;
  }
  v16 = *(_QWORD *)(*(_QWORD *)(a1 + 120) + 8i64 * v23);
  ProcessHeap = GetProcessHeap();
  v18 = (char *)HeapAlloc(ProcessHeap, 0, 0x98ui64);
  v19 = v18;
  if ( !v18 )
  {
    v13 = -2147024882;
    goto LABEL_14;
  }
  *(_QWORD *)v18 = 1i64;
  *((_OWORD *)v18 + 1) = 0i64;
  *((_QWORD *)v18 + 18) = 0i64;
  *((_QWORD *)v18 + 1) = 0i64;
  memset(v18 + 32, 0, 0x58ui64);
  *(_OWORD *)(v19 + 40) = 0i64;
  *(_OWORD *)(v19 + 56) = 0i64;
  *((_QWORD *)v19 + 9) = 0i64;
  *((_QWORD *)v19 + 15) = 0i64;
  v10 = v19;
  *((_QWORD *)v19 + 16) = 0i64;
  *((_QWORD *)v19 + 17) = 0i64;
  v12 = sub_180015728(v19, a2, v16, v15, a3);
  v13 = v12;
  if ( v12 < 0 )
  {
LABEL_2:
    v14 = (unsigned int)v12;
LABEL_15:
    sub_1800038E8(v14);
    goto LABEL_16;
  }
  v10 = 0i64;
  *a4 = v19;
LABEL_16:
  sub_180003B30(v13);
  if ( v10 && _InterlockedExchangeAdd((volatile signed __int32 *)v10, 0xFFFFFFFF) == 1 )
  {
    sub_180003038(v10);
    v20 = GetProcessHeap();
    HeapFree(v20, 0, v10);
  }
  return v13;
}

__int64 __fastcall sub_180015728(
        __int64 a1,
        __int64 a2,
        __int64 a3,
        volatile signed __int32 *a4,
        const wchar_t **lpMem)
{
  void *v7; // rsi
  volatile signed __int32 *v8; // rdi
  const wchar_t **v9; // rbx
  unsigned int v10; // r15d
  int v11; // eax
  __int64 v12; // r8
  __int64 v13; // rcx
  int v14; // eax
  __int64 v15; // rcx
  const wchar_t *v16; // rdx
  signed int LastError; // eax
  signed int v18; // eax
  struct _FILETIME v19; // rax
  __int64 v20; // rdi
  __int64 v21; // rbx
  HANDLE ProcessHeap; // rax
  void *v23; // rbx
  HANDLE v24; // rax
  void *v25; // rbx
  HANDLE v26; // rax
  void *v27; // r12
  HANDLE v28; // rax
  void *v29; // r14
  HANDLE v30; // rax
  void *v31; // r14
  HANDLE v32; // rax
  HANDLE v33; // rax
  HANDLE v34; // rax
  HANDLE v35; // rax
  RPC_WSTR StringUuid; // [rsp+20h] [rbp-51h] BYREF
  __int64 v38; // [rsp+28h] [rbp-49h] BYREF
  __int64 v39; // [rsp+30h] [rbp-41h] BYREF
  struct _FILETIME FileTime; // [rsp+38h] [rbp-39h] BYREF
  __int64 v41; // [rsp+40h] [rbp-31h]
  volatile signed __int32 *v42; // [rsp+48h] [rbp-29h]
  const wchar_t **v43; // [rsp+50h] [rbp-21h]
  RPC_WSTR String; // [rsp+58h] [rbp-19h] BYREF
  struct _SYSTEMTIME SystemTime; // [rsp+60h] [rbp-11h] BYREF

  v43 = lpMem;
  v39 = 0i64;
  v38 = 0i64;
  FileTime = 0i64;
  v7 = (void *)a3;
  SystemTime = 0i64;
  StringUuid = 0i64;
  v42 = a4;
  v41 = a3;
  _InterlockedIncrement((volatile signed __int32 *)a3);
  v8 = a4;
  _InterlockedIncrement(a4);
  v9 = lpMem;
  _InterlockedIncrement((volatile signed __int32 *)lpMem);
  if ( UuidToStringW((const UUID *)(a3 + 4), &StringUuid) )
  {
    v10 = -2147217375;
    sub_1800038E8(2147749921i64);
    goto LABEL_40;
  }
  v11 = wcscmp(lpMem[1], L"msft:rm/algorithm/pkey/2009");
  v13 = a2 + 72;
  if ( v11 )
  {
    v14 = sub_1800153FC(v13, 12i64, v12, &v38);
    v10 = v14;
    if ( v14 < 0 )
      goto LABEL_5;
    v16 = L"msft2005:%s&%s";
  }
  else
  {
    v14 = sub_1800153FC(v13, 13i64, v12, &v38);
    v10 = v14;
    if ( v14 < 0 )
    {
LABEL_5:
      v15 = (unsigned int)v14;
LABEL_6:
      sub_1800038E8(v15);
      goto LABEL_40;
    }
    v16 = L"msft2009:%s&%s";
  }
  v14 = sub_1800057E0(&v39, v16, StringUuid, v38);
  v10 = v14;
  if ( v14 < 0 )
    goto LABEL_5;
  GetLocalTime(&SystemTime);
  if ( !SystemTimeToFileTime(&SystemTime, &FileTime) )
  {
    LastError = GetLastError();
    v10 = LastError;
    if ( LastError )
    {
      if ( LastError > 0 )
        v10 = (unsigned __int16)LastError | 0x80070000;
    }
    else
    {
      v10 = -2147467259;
    }
    goto LABEL_16;
  }
  v10 = 0;
  if ( dword_1800AFE08 == 1 )
  {
    if ( CryptGenRandom(hProv, 8u, (BYTE *)(a1 + 144)) )
      goto LABEL_25;
    v18 = GetLastError();
    v10 = v18;
    if ( v18 )
    {
      if ( v18 > 0 )
        v10 = (unsigned __int16)v18 | 0x80070000;
    }
    else
    {
      v10 = -2147467259;
    }
  }
  else
  {
    v10 = -2147418113;
  }
  sub_1800038E8(v10);
LABEL_25:
  sub_180003B30(v10);
  if ( (v10 & 0x80000000) != 0 )
  {
LABEL_16:
    v15 = v10;
    goto LABEL_6;
  }
  v19 = FileTime;
  v20 = v39;
  *(_OWORD *)(a1 + 32) = *(_OWORD *)a2;
  v39 = 0i64;
  *(_OWORD *)(a1 + 48) = *(_OWORD *)(a2 + 16);
  *(_OWORD *)(a1 + 64) = *(_OWORD *)(a2 + 32);
  *(_OWORD *)(a1 + 80) = *(_OWORD *)(a2 + 48);
  *(_OWORD *)(a1 + 96) = *(_OWORD *)(a2 + 64);
  *(_QWORD *)(a1 + 112) = *(_QWORD *)(a2 + 80);
  *(struct _FILETIME *)(a1 + 16) = v19;
  *(_DWORD *)(a1 + 24) = *(_DWORD *)(a2 + 32) + 1000000 * *(_DWORD *)(a2 + 28);
  v21 = *(_QWORD *)(a1 + 8);
  if ( v21 )
  {
    ProcessHeap = GetProcessHeap();
    HeapFree(ProcessHeap, 0, (LPVOID)(v21 - 4));
    sub_180003B30(0i64);
  }
  v7 = 0i64;
  if ( !v20 )
    v20 = 0i64;
  *(_QWORD *)(a1 + 8) = v20;
  v23 = *(void **)(a1 + 120);
  if ( v23 && !_InterlockedDecrement((volatile signed __int32 *)v23) )
  {
    sub_180003160(v23);
    v24 = GetProcessHeap();
    HeapFree(v24, 0, v23);
  }
  v8 = 0i64;
  *(_QWORD *)(a1 + 120) = v41;
  v25 = *(void **)(a1 + 128);
  if ( v25 && !_InterlockedDecrement((volatile signed __int32 *)v25) )
  {
    sub_1800032D8(v25);
    v26 = GetProcessHeap();
    HeapFree(v26, 0, v25);
  }
  v9 = 0i64;
  *(_QWORD *)(a1 + 128) = v42;
  v27 = *(void **)(a1 + 136);
  if ( v27 && !_InterlockedDecrement((volatile signed __int32 *)v27) )
  {
    sub_180003224(v27);
    v28 = GetProcessHeap();
    HeapFree(v28, 0, v27);
  }
  *(_QWORD *)(a1 + 136) = v43;
LABEL_40:
  sub_180003B30(v10);
  if ( StringUuid )
  {
    String = StringUuid;
    RpcStringFreeW(&String);
    StringUuid = 0i64;
  }
  if ( v38 )
  {
    v29 = (void *)(v38 - 4);
    v30 = GetProcessHeap();
    HeapFree(v30, 0, v29);
    sub_180003B30(0i64);
  }
  if ( v39 )
  {
    v31 = (void *)(v39 - 4);
    v32 = GetProcessHeap();
    HeapFree(v32, 0, v31);
    sub_180003B30(0i64);
  }
  if ( v9 && !_InterlockedDecrement((volatile signed __int32 *)v9) )
  {
    sub_180003224(v9);
    v33 = GetProcessHeap();
    HeapFree(v33, 0, v9);
  }
  if ( v8 && !_InterlockedDecrement(v8) )
  {
    sub_1800032D8(v8);
    v34 = GetProcessHeap();
    HeapFree(v34, 0, (LPVOID)v8);
  }
  if ( v7 && !_InterlockedDecrement((volatile signed __int32 *)v7) )
  {
    sub_180003160(v7);
    v35 = GetProcessHeap();
    HeapFree(v35, 0, v7);
  }
  return v10;
}

__int64 __fastcall sub_18001506C(__int64 a1, __int64 a2, __int64 a3, int a4, __int64 a5)
{
  wchar_t *v9; // rcx
  int v10; // eax
  __int64 v11; // rdi
  unsigned int v12; // ebx
  __int64 v13; // rcx
  __int128 v15; // [rsp+40h] [rbp-28h] BYREF

  a5 = 0i64;
  v9 = *(wchar_t **)(a2 + 8);
  v15 = 0i64;
  v10 = sub_180009EBC(v9, &a5, &v15);
  v11 = a5;
  v12 = v10;
  if ( v10 < 0 )
    goto LABEL_6;
  v10 = (*(__int64 (__fastcall **)(__int64, __int64, _QWORD, _QWORD, __int64, int))(*(_QWORD *)a5 + 24i64))(
          a5,
          a1,
          *(_QWORD *)(a2 + 16),
          *(unsigned int *)(a2 + 24),
          a3,
          a4);
  *(_OWORD *)(a1 + 8) = v15;
  *(_DWORD *)(a1 + 24) = *(_DWORD *)(a2 + 4);
  if ( v10 >= 0 )
    goto LABEL_8;
  if ( (v10 & 0x1FFF0000) != 0x40000 )
  {
    v12 = v10;
LABEL_6:
    v13 = (unsigned int)v10;
    goto LABEL_7;
  }
  v12 = -2147217373;
  v13 = 2147749923i64;
LABEL_7:
  sub_1800038E8(v13);
LABEL_8:
  sub_180003B30(v12);
  if ( v11 )
    (*(void (__fastcall **)(__int64))(*(_QWORD *)v11 + 16i64))(v11);
  return v12;
}

__int64 __fastcall sub_180009EBC(wchar_t *a1, __int64 *a2, _OWORD *a3)
{
  __int64 v5; // rbx
  int v6; // eax
  __int64 v7; // rdx
  int v8; // edi
  __int64 v9; // rcx
  int v10; // eax
  __int64 v11; // rcx
  __int64 v12; // rax
  __int64 v14; // [rsp+20h] [rbp-38h] BYREF
  __int128 v15; // [rsp+28h] [rbp-30h] BYREF

  v15 = 0i64;
  v5 = 0i64;
  v6 = sub_18000ED00(a1);
  v8 = v6;
  if ( v6 < 0 )
  {
    v9 = (unsigned int)v6;
LABEL_3:
    sub_1800038E8(v9);
    goto LABEL_17;
  }
  v14 = 0i64;
  v10 = sub_18000D828(&v15, v7, &v14);
  v8 = v10;
  if ( v10 == -2147221164 )
  {
    v8 = -2147217374;
    v11 = 2147749922i64;
LABEL_6:
    sub_1800038E8(v11);
    goto LABEL_10;
  }
  if ( v10 < 0 )
  {
    v11 = (unsigned int)v10;
    goto LABEL_6;
  }
  v5 = v14;
  v14 = 0i64;
LABEL_10:
  sub_180003B30(v8);
  if ( v14 )
  {
    (*(void (__fastcall **)(__int64))(*(_QWORD *)v14 + 16i64))(v14);
    v14 = 0i64;
  }
  if ( v8 < 0 )
  {
    v9 = (unsigned int)v8;
    goto LABEL_3;
  }
  if ( a3 )
    *a3 = v15;
  v12 = v5;
  v5 = 0i64;
  *a2 = v12;
LABEL_17:
  sub_180003B30(v8);
  if ( v5 )
    (*(void (__fastcall **)(__int64))(*(_QWORD *)v5 + 16i64))(v5);
  return (unsigned int)v8;
}

__int64 __fastcall sub_18000D828(_QWORD *a1, __int64 a2, _QWORD *a3)
{
  unsigned int v3; // ebx
  int v6; // eax
  __int64 v7; // rcx

  v3 = 0;
  if ( !a3 )
  {
    v3 = -2147024809;
LABEL_20:
    v7 = v3;
    goto LABEL_21;
  }
  *a3 = 0i64;
  if ( *a1 == 0x4D50A7362B864AA3i64 && a1[1] == 0x617C7DBDB3EB0486i64
    || *a1 == 0x4BFD49769F44BF99i64 && a1[1] == 0x8454A4FBAEA80AB0ui64 )
  {
    v6 = sub_18008D6E4(a3);
    v3 = v6;
    if ( v6 < 0 )
      goto LABEL_8;
  }
  if ( *a1 == unk_1800A6798 && a1[1] == 0x738D1AB8FFFB99A7i64 && (v6 = sub_18008DB38((__int64)a3), v3 = v6, v6 < 0)
    || *a1 == unk_1800A6788 && a1[1] == 0x888973FBB741548Dui64 && (v6 = sub_18008E04C(a3), v3 = v6, v6 < 0)
    || *a1 == 0x4F58913135BFEDB3i64 && a1[1] == 0xE0500FD1325B9A9Dui64 && (v6 = sub_18008D5FC(a3), v3 = v6, v6 < 0) )
  {
LABEL_8:
    v7 = (unsigned int)v6;
LABEL_21:
    sub_1800038E8(v7);
    goto LABEL_22;
  }
  if ( !*a3 )
  {
    v3 = -2147221164;
    goto LABEL_20;
  }
LABEL_22:
  sub_180003B30(v3);
  return v3;
}

// Option 1

__int64 __fastcall sub_18008D6E4(__int64 a1)
{
  int v2; // ebx
  HANDLE ProcessHeap; // rax
  unsigned __int64 v4; // rax
  unsigned __int64 v5; // rdi
  __int64 v6; // rcx
  int v7; // eax
  __int64 v8; // rcx

  if ( !a1 )
  {
    v2 = -2147024809;
LABEL_11:
    sub_1800038E8((unsigned int)v2);
    goto LABEL_12;
  }
  ProcessHeap = GetProcessHeap();
  v4 = (unsigned __int64)HeapAlloc(ProcessHeap, 0, 0x18ui64);
  v5 = v4;
  if ( v4 )
  {
    *(_QWORD *)(v4 + 12) = 0i64;
    *(_DWORD *)(v4 + 20) = 0;
    v6 = v4 & -(__int64)(v4 != -8i64);
    *(_OWORD *)v6 = 0i64;
    *(_QWORD *)(v6 + 16) = 0i64;
    *(_DWORD *)(v4 + 8) = 1;
    *(_QWORD *)v4 = off_1800A4468;
    v7 = ((__int64 (__fastcall *)(unsigned __int64, __int64 *, __int64))sub_18008D570)(v4, &qword_1800A67D8, a1);
    v2 = v7;
    if ( v7 >= 0 )
      goto LABEL_8;
    v8 = (unsigned int)v7;
  }
  else
  {
    v2 = -2147024882;
    v5 = 0i64;
    v8 = 2147942414i64;
  }
  sub_1800038E8(v8);
LABEL_8:
  sub_180003B30(v2);
  if ( v5 )
    (*(void (__fastcall **)(unsigned __int64))(*(_QWORD *)v5 + 16i64))(v5);
  if ( v2 < 0 )
    goto LABEL_11;
LABEL_12:
  sub_180003B30(v2);
  return (unsigned int)v2;
}

/* 
.rdata:00000001800A4468 off_1800A4468   dq offset sub_18008D570 ; DATA XREF: sub_18008D6E4+71↑o
.rdata:00000001800A4470                 dq offset sub_18000AC90
.rdata:00000001800A4478                 dq offset sub_180012C00
.rdata:00000001800A4480                 dq offset sub_18008D200
.rdata:00000001800A4488                 dq offset sub_18008D4E0
.rdata:00000001800A4490                 dq offset sub_18008D420 
*/

__int64 __fastcall sub_18008D200(__int64 a1, __int64 a2, unsigned int *a3, unsigned int a4, __int64 a5, int a6)
{
  int v10; // r15d
  __int64 v11; // rcx
  int v12; // ebx
  char *v13; // rdx
  char *v14; // r9
  __int64 v15; // r11
  char v16; // al
  char v17; // cl
  __int16 v18; // ax
  __int16 v19; // dx
  int v20; // eax
  __int16 v22; // [rsp+30h] [rbp-30h] BYREF
  int v23; // [rsp+34h] [rbp-2Ch] BYREF
  int v24; // [rsp+38h] [rbp-28h] BYREF
  char v25; // [rsp+40h] [rbp-20h] BYREF
  __int64 v26; // [rsp+41h] [rbp-1Fh]
  int v27; // [rsp+49h] [rbp-17h]

  v10 = 0;
  if ( !a2 || !a3 )
  {
    v11 = 2147942487i64;
    v12 = -2147024809;
    goto LABEL_3;
  }
  v12 = 0;
  v22 = 0;
  v26 = 0i64;
  v27 = 0;
  if ( !*(_DWORD *)(a2 + 48) )
  {
    v12 = -2147024809;
    sub_1800038E8(2147942487i64);
  }
  sub_180003B30(v12);
  if ( v12 < 0 )
    goto LABEL_8;
  v13 = &v25;
  LOBYTE(v22) = *(_BYTE *)(a2 + 56);
  v14 = (char *)(a2 + 58);
  v15 = 12i64;
  HIBYTE(v22) ^= (*(_BYTE *)(a2 + 57) ^ HIBYTE(v22)) & 7;
  do
  {
    v16 = *v14++;
    *v13 = (32 * v16) | ((unsigned __int8)v13[a2 + 57 - (_QWORD)&v25] >> 3);
    ++v13;
    --v15;
  }
  while ( v15 );
  v12 = 0;
  v17 = *(__int16 *)(a2 + 69) >> 3;
  v23 = 0;
  v24 = 0;
  HIBYTE(v27) = HIBYTE(v27) & 0x80 ^ v17 & 0x7F;
  if ( a5 || a6 )
  {
    v12 = -2147217326;
    goto LABEL_20;
  }
  if ( a4 < 4 || a4 != *a3 )
  {
    v12 = -2147217325;
    goto LABEL_20;
  }
  if ( (unsigned int)sub_18009CA30(a3, (__int64)&v22, 2u, (__int64)&v25, &v24, &v23) )
  {
    v12 = -2147217327;
LABEL_20:
    sub_1800038E8((unsigned int)v12);
    goto LABEL_21;
  }
  v10 = v23;
LABEL_21:
  sub_180003B30(v12);
  if ( v12 < 0 )
  {
LABEL_8:
    v11 = (unsigned int)v12;
    goto LABEL_3;
  }
  v18 = (unsigned __int8)v22;
  v19 = HIBYTE(v22) << 8;
  *(_DWORD *)(a2 + 32) = v10;
  *(_DWORD *)(a2 + 36) = ((_BYTE)v18 + (_BYTE)v19) & 1;
  *(_DWORD *)(a2 + 28) = (((unsigned __int16)(v18 + v19) >> 1) & 0x3FF) % 1000;
  sub_180003B30(0);
  v20 = (*(__int64 (__fastcall **)(__int64, __int64, __int64))(*(_QWORD *)a1 + 32i64))(a1, a2 + 8, a2 + 72);
  v12 = v20;
  if ( v20 >= 0 )
  {
    *(_DWORD *)(a2 + 52) = 1;
    goto LABEL_25;
  }
  v11 = (unsigned int)v20;
LABEL_3:
  sub_1800038E8(v11);
LABEL_25:
  sub_180003B30(v12);
  return (unsigned int)v12;
}

__int64 __fastcall sub_18009CA30(unsigned int *a1, __int64 a2, unsigned int a3, __int64 a4, _DWORD *a5, _DWORD *a6)
{
  HANDLE ProcessHeap; // rax
  unsigned int *v9; // rdi
  __int64 v11; // rdx
  unsigned int v12; // r15d
  unsigned int v13; // r15d
  unsigned int v14; // r10d
  int v15; // r11d
  unsigned int v16; // esi
  unsigned int v17; // r14d
  int v18; // ebx
  unsigned int v19; // r8d
  int v20; // r11d
  int v21; // edx
  unsigned int v22; // eax
  unsigned __int64 v23; // rcx
  signed __int64 *v24; // rax
  int **v25; // rsi
  char *v26; // r15
  int v27; // eax
  unsigned __int64 v28; // rcx
  unsigned __int64 v29; // r9
  unsigned int v30; // r8d
  __int64 v31; // rax
  signed __int64 v32; // rdx
  __int64 v33; // rcx
  unsigned __int64 v34; // rcx
  unsigned __int64 v35; // r9
  unsigned int v36; // r8d
  __int64 v37; // rax
  __int64 v38; // rdx
  __int64 v39; // rcx
  int v40; // eax
  unsigned int v41; // r13d
  unsigned int v42; // r12d
  unsigned int *v43; // rsi
  char v44; // cl
  int v45; // r8d
  unsigned int v46; // r9d
  char v47; // cl
  int v48; // edx
  __int64 v49; // r9
  unsigned __int64 v50; // r8
  unsigned int *v51; // rdx
  __int64 v52; // rcx
  __int64 v53; // rax
  unsigned __int64 v54; // rdx
  unsigned __int64 v55; // r8
  __int64 v56; // rcx
  __int64 v57; // rax
  unsigned int v58; // r9d
  void *v59; // rbx
  HANDLE v60; // rax
  HANDLE v61; // rax
  int v62; // [rsp+38h] [rbp-51h]
  int v63; // [rsp+38h] [rbp-51h]
  int v64; // [rsp+40h] [rbp-49h]
  int v65; // [rsp+40h] [rbp-49h]
  signed __int64 v66; // [rsp+60h] [rbp-29h] BYREF
  signed __int64 v67; // [rsp+68h] [rbp-21h] BYREF
  signed __int64 v68[2]; // [rsp+70h] [rbp-19h] BYREF
  __int64 v69[2]; // [rsp+80h] [rbp-9h] BYREF
  __int128 v70; // [rsp+90h] [rbp+7h]

  ProcessHeap = GetProcessHeap();
  v9 = (unsigned int *)HeapAlloc(ProcessHeap, 8u, 0x9F0ui64);
  if ( !v9 )
    return 10i64;
  if ( !dword_1800AFDC4 )
    dword_1800AFDC4 = 1;
  *(_OWORD *)v69 = 0i64;
  v70 = 0i64;
  SetLastError(0);
  v12 = sub_18009D280(a1, v11, (__int64)v9, (__int64)v69);
  if ( v12 )
    goto LABEL_78;
  v13 = v9[7];
  if ( v13 != 20020420 && v13 != 19980206 )
  {
    v12 = 1;
    goto LABEL_75;
  }
  v14 = v9[3];
  v15 = *v9;
  v16 = v9[5];
  v17 = 0;
  v18 = 0;
  v67 = 0i64;
  v66 = 0i64;
  v68[0] = 0i64;
  v19 = 0;
  v20 = v14 + v16 + v15;
  if ( !v20 )
    goto LABEL_22;
  do
  {
    v21 = (*(unsigned __int8 *)(((unsigned __int64)v19 >> 3) + a4) >> (v19 & 7)) & 1;
    if ( v19 >= v14 )
    {
      v22 = v19 - v14;
      if ( v19 >= v14 + v16 )
      {
        v23 = v22 - v16;
        v24 = &v66;
        if ( v21 )
        {
          _bittestandset64(&v66, v23);
          goto LABEL_20;
        }
      }
      else
      {
        v23 = v22;
        v24 = v68;
        if ( v21 )
        {
          _bittestandset64(v68, v23);
          goto LABEL_20;
        }
      }
      _bittestandreset64(v24, v23);
    }
    else if ( v21 )
    {
      _bittestandset64(&v67, v19);
    }
    else
    {
      _bittestandreset64(&v67, v19);
    }
LABEL_20:
    ++v19;
  }
  while ( v19 != v20 );
  v18 = v66;
LABEL_22:
  *((_QWORD *)v9 + 280) = a2;
  v9[562] = a3;
  if ( v13 != 19980206 )
  {
    v28 = v9[4];
    v29 = v28 >> 1;
    if ( (v28 & 1) != 0 )
      v9[v28 + 626] = v68[v29 - 1];
    v30 = 0;
    if ( v29 )
    {
      v31 = 0i64;
      do
      {
        v32 = v68[v31 - 1];
        v33 = 2 * v30;
        v9[v33 + 627] = v32;
        ++v30;
        v9[(unsigned int)(v33 + 1) + 627] = HIDWORD(v32);
        v31 = v30;
      }
      while ( v30 != v29 );
    }
    v34 = v9[1];
    v35 = v34 >> 1;
    if ( (v34 & 1) != 0 )
      v9[v34 + 631] = *((_DWORD *)&v66 + 2 * v35);
    v36 = 0;
    if ( v35 )
    {
      v37 = 0i64;
      do
      {
        v38 = *(&v66 + v37);
        v39 = 2 * v36;
        v9[v39 + 632] = v38;
        ++v36;
        v9[(unsigned int)(v39 + 1) + 632] = HIDWORD(v38);
        v37 = v36;
      }
      while ( v36 != v35 );
    }
    if ( v9[4] <= 2 )
    {
      v66 = 0i64;
      *((_QWORD *)v9 + 317) = 0i64;
      v12 = sub_18009DC10(
              93,
              *((_QWORD *)v9 + 280),
              v9[562],
              (__int64)(v9 + 627),
              v9[4],
              (__int64)(v9 + 632),
              v9[1],
              v62,
              v64,
              (__int64)&v66,
              v9[5]);
      if ( v12 )
        goto LABEL_75;
      v25 = (int **)(v9 + 192);
      *((_QWORD *)v9 + 317) = v66;
      if ( (unsigned int)sub_180093DB4(v9 + 236, (__int64)(v9 + 192), (__int64)v69)
        && (unsigned int)sub_180093DB4(v9 + 300, (__int64)(v9 + 192), (__int64)v69)
        && (unsigned int)sub_18008FB54(
                           (int)v9 + 1472,
                           (int)v9 + 1728,
                           (int)v9 + 1472,
                           v12 + 1,
                           (__int64)(v9 + 192),
                           *((_QWORD *)v9 + 117),
                           (__int64)v69) )
      {
        v26 = (char *)(v9 + 496);
        v27 = sub_180093DB4(v9 + 368, (__int64)(v9 + 192), (__int64)v69);
        goto LABEL_43;
      }
      goto LABEL_74;
    }
    goto LABEL_37;
  }
  v25 = (int **)(v9 + 192);
  if ( !(unsigned int)sub_180093DB4(v9 + 236, (__int64)(v9 + 192), (__int64)v69)
    || !(unsigned int)sub_180093DB4(v9 + 300, (__int64)(v9 + 192), (__int64)v69) )
  {
    goto LABEL_74;
  }
  v26 = (char *)(v9 + 496);
  v27 = sub_18008FB54(
          (int)v9 + 1472,
          (int)v9 + 1728,
          (int)v9 + 1984,
          1,
          (__int64)(v9 + 192),
          *((_QWORD *)v9 + 117),
          (__int64)v69);
LABEL_43:
  if ( !v27 )
    goto LABEL_74;
  v40 = **v25;
  v68[1] = *((_QWORD *)*v25 + 11);
  LODWORD(v66) = v40;
  if ( (unsigned int)sub_180090650(v26, v25, v69)
    || !(unsigned int)sub_18009D8E0(v26, (__int64)v69)
    || !(unsigned int)sub_18009D8E0(&v26[8 * (unsigned int)v66], (__int64)v69) )
  {
    goto LABEL_74;
  }
  *((_QWORD *)v9 + 280) = a2;
  v9[562] = a3;
  v41 = v9[3];
  v42 = v9[6];
  LODWORD(v66) = v9[4];
  if ( (unsigned int)v66 > 2 )
  {
LABEL_37:
    v12 = 8;
    goto LABEL_75;
  }
  v43 = v9 + 627;
  v44 = 0;
  if ( v9[7] != 19980206 )
    v44 = 121;
  v12 = sub_18009DC10(
          v44,
          a2,
          v9[562],
          (__int64)(v9 + 563),
          2 * v9[2],
          0i64,
          0,
          v62,
          v64,
          (__int64)(v9 + 627),
          v42 + v41);
  if ( !v12 )
  {
    v45 = 0;
    v9[629] = 0;
    if ( v42 )
    {
      v46 = 0;
      do
      {
        v47 = v45;
        v48 = (v9[((unsigned __int64)(v45 + v41) >> 5) + 627] >> ((v45 + v41) & 0x1F)) & 1;
        ++v45;
        v46 |= v48 << v47;
        v9[629] = v46;
      }
      while ( v45 != v42 );
    }
    v49 = (unsigned int)v66;
    v50 = (unsigned __int64)(unsigned int)v66 >> 1;
    v9[(unsigned int)(v66 - 1) + 627] &= 0xFFFFFFFFFFFFFFFFui64 >> (32 * (unsigned __int8)v66 - (unsigned __int8)v41);
    if ( (v49 & 1) != 0 )
      *(_QWORD *)&v9[2 * v50 + 630] = v43[v49 - 1];
    if ( v50 )
    {
      v51 = v9 + 627;
      do
      {
        v52 = v51[1];
        v53 = *v51;
        v51 += 2;
        *(_QWORD *)(v51 + 1) = v53 | (v52 << 32);
        --v50;
      }
      while ( v50 );
    }
    v54 = v9[4];
    v55 = v54 >> 1;
    v9[(unsigned int)(v54 - 1) + 627] &= 0xFFFFFFFFFFFFFFFFui64 >> (32 * (unsigned __int8)v54 - *((_BYTE *)v9 + 12));
    if ( (v54 & 1) != 0 )
      *(_QWORD *)&v9[2 * v55 + 630] = v43[v54 - 1];
    for ( ; v55; --v55 )
    {
      v56 = v43[1];
      v57 = *v43;
      v43 += 2;
      *(_QWORD *)(v43 + 1) = v57 | (v56 << 32);
    }
    if ( v9[7] < 0x1317CC4 || (int)v9[16] < 1 )
    {
      v12 = 0;
      v9[632] = 0;
      goto LABEL_68;
    }
    v12 = sub_18009DC10(
            45,
            *((_QWORD *)v9 + 280),
            v9[562],
            *((_QWORD *)v9 + 15),
            v9[17],
            (__int64)(v9 + 629),
            1,
            v63,
            v65,
            (__int64)(v9 + 632),
            *v9);
    if ( !v12 )
    {
LABEL_68:
      if ( !GetLastError() )
      {
        v58 = v9[3];
        if ( v58 )
        {
          while ( ((v9[((unsigned __int64)v17 >> 5) + 627] >> (v17 & 0x1F)) & 1) == _bittest64(&v67, v17) )
          {
            if ( ++v17 == v58 )
              goto LABEL_72;
          }
          v12 = 1;
        }
        else
        {
LABEL_72:
          *a6 = v9[629];
          *a5 = v18;
        }
        goto LABEL_75;
      }
LABEL_74:
      v12 = 6;
    }
  }
LABEL_75:
  v59 = (void *)*((_QWORD *)v9 + 117);
  if ( v59 )
  {
    v60 = GetProcessHeap();
    HeapFree(v60, 0, v59);
    if ( (unsigned int)sub_18008F774(v9 + 192, v69) )
      sub_18008E240(v9 + 86, v69);
  }
LABEL_78:
  v61 = GetProcessHeap();
  HeapFree(v61, 0, v9);
  if ( v69[1] )
    (*(void (__fastcall **)(__int64 *))(*(_QWORD *)v69[1] + 32i64))(v69);
  if ( v69[0] )
    (*(void (__fastcall **)(__int64 *))(*(_QWORD *)(v69[0] + 24) + 24i64))(v69);
  return v12;
}

__int64 __fastcall sub_18009D280(unsigned int *a1, __int64 a2, __int64 a3, __int64 a4)
{
  char *v4; // rbx
  int v6; // esi
  HANDLE ProcessHeap; // rax
  char *v10; // r14
  unsigned int v12; // ebp
  __int64 v13; // r13
  char *v14; // rdx
  unsigned int v15; // eax
  unsigned __int64 v16; // r8
  signed __int64 v17; // r9
  __int64 v18; // rcx
  __int64 v19; // rax
  SIZE_T v20; // rbx
  HANDLE v21; // rax
  __int64 v22; // rcx
  __int64 v23; // r12
  __int64 v24; // r8
  _QWORD *v25; // rax
  __int64 v26; // rax
  _QWORD *v27; // rcx
  HANDLE v28; // rax
  HANDLE v29; // rax
  HANDLE v30; // rax
  char *v31; // r8
  HANDLE v32; // rax

  v4 = 0i64;
  v6 = 0;
  ProcessHeap = GetProcessHeap();
  v10 = (char *)HeapAlloc(ProcessHeap, 8u, 0x280ui64);
  if ( !v10 )
    return 10i64;
  v12 = sub_18009DAB0(a1, a3);
  if ( !v12 )
  {
    v13 = *(unsigned int *)(a3 + 8);
    v14 = *(char **)(a3 + 32);
    v15 = (unsigned int)(*(_DWORD *)(a3 + 16) + 1) >> 1;
    v16 = (unsigned __int64)(unsigned int)v13 >> 1;
    *(_DWORD *)(a3 + 128) = (unsigned int)(v13 + 1) >> 1;
    *(_DWORD *)(a3 + 136) = v15;
    if ( (v13 & 1) != 0 )
      *(_QWORD *)&v10[8 * v16] = *(unsigned int *)&v14[4 * v13 - 4];
    if ( v16 )
    {
      v17 = v10 - v14;
      do
      {
        v18 = *((unsigned int *)v14 + 1);
        v19 = *(unsigned int *)v14;
        v14 += 8;
        *(_QWORD *)&v14[v17 - 8] = v19 | (v18 << 32);
        --v16;
      }
      while ( v16 );
    }
    if ( !(unsigned int)sub_18008EE44(v10, a4)
      || !(unsigned int)sub_18008E5A8(a3 + 216, a3 + 344, a4)
      || (v6 = 1, !(unsigned int)sub_18009D820(*(_QWORD *)(a3 + 40), (int)a3 + 512, (int)a3 + 216, v13, a4))
      || !(unsigned int)sub_18009D820(*(_QWORD *)(a3 + 40) + 4 * v13, (int)a3 + 640, (int)a3 + 216, v13, a4)
      || !(unsigned int)sub_18008F7F4((void *)(a3 + 512), (void *)(a3 + 640), a4)
      || !(unsigned int)sub_18009D790(*(_QWORD *)(a3 + 48), (int)a3 + 944, (int)a3 + 768, v13, a4)
      || !(unsigned int)sub_18009D790(*(_QWORD *)(a3 + 56), (int)a3 + 1200, (int)a3 + 768, v13, a4) )
    {
      v12 = 3;
      *(_QWORD *)(a3 + 936) = 0i64;
      v30 = GetProcessHeap();
      v31 = v10;
      goto LABEL_39;
    }
    v20 = 8i64 * *(_QWORD *)(a3 + 840);
    v21 = GetProcessHeap();
    v4 = (char *)HeapAlloc(v21, 0, v20);
    if ( !(unsigned int)sub_1800907C0(
                          (int)a3 + 944,
                          (int)a3 + 768,
                          (unsigned int)"shortsig: external_key_to_internal",
                          (_DWORD)v4,
                          a4)
      || !(unsigned int)sub_1800907C0(
                          (int)a3 + 1200,
                          (int)a3 + 768,
                          (unsigned int)"shortsig: external_key_to_internal",
                          (_DWORD)v4,
                          a4) )
    {
      goto LABEL_33;
    }
    if ( *(int *)(a3 + 64) >= 1 )
    {
      v22 = *(_QWORD *)(a3 + 104);
      v23 = (unsigned int)(*(_DWORD *)(a3 + 88) + 1) >> 1;
      *(_DWORD *)(a3 + 132) = v23;
      sub_18009D740(v22, a3 + 1464);
      sub_18009D740(*(_QWORD *)(a3 + 96), a3 + 1456);
      v24 = (unsigned int)v23;
      if ( !(_DWORD)v23 )
      {
LABEL_26:
        *(_DWORD *)(a3 + 64) = 1;
LABEL_27:
        *(_QWORD *)(a3 + 936) = v4;
        v28 = GetProcessHeap();
        HeapFree(v28, 0, v10);
        return v12;
      }
      v25 = (_QWORD *)(a3 + 1456 + 8 * v23);
      while ( !*v25 )
      {
        --v25;
        if ( !--v24 )
        {
          v26 = (unsigned int)v23;
          v27 = (_QWORD *)(a3 + 1448 + 8 * v23);
          while ( !*v27 )
          {
            --v27;
            if ( !--v26 )
              goto LABEL_26;
          }
          break;
        }
      }
      *(_DWORD *)(a3 + 64) = 2;
      if ( (unsigned int)sub_180093DB4((void *)(a3 + 944), a3 + 768, a4)
        && (unsigned int)sub_180093DB4((void *)(a3 + 944), a3 + 768, a4) )
      {
        if ( !(unsigned int)sub_180090650(v10 + 128, a3 + 768, a4)
          || !(*(unsigned int (__fastcall **)(__int64, _QWORD *, __int64))(*(_QWORD *)(*(_QWORD *)(a3 + 768) + 64i64)
                                                                         + 8i64))(
                a3 + 1200,
                (_QWORD *)v10 + 48,
                2i64) )
        {
          v12 = 4;
LABEL_34:
          *(_QWORD *)(a3 + 936) = v4;
          v29 = GetProcessHeap();
          HeapFree(v29, 0, v10);
LABEL_37:
          if ( !v4 )
            goto LABEL_40;
          v30 = GetProcessHeap();
          v31 = v4;
LABEL_39:
          HeapFree(v30, 0, v31);
LABEL_40:
          if ( v6 )
            sub_18008E240(a3 + 344, a4);
          return v12;
        }
        goto LABEL_27;
      }
LABEL_33:
      v12 = 3;
      goto LABEL_34;
    }
  }
  *(_QWORD *)(a3 + 936) = v4;
  v32 = GetProcessHeap();
  HeapFree(v32, 0, v10);
  if ( v12 )
    goto LABEL_37;
  return v12;
}

// Option 2

__int64 __fastcall sub_18008DB38(__int64 a1)
{
  int v2; // ebx
  HANDLE ProcessHeap; // rax
  unsigned __int64 v4; // rax
  unsigned __int64 v5; // rdi
  int v6; // eax
  __int64 v7; // rcx

  if ( !a1 )
  {
    v2 = -2147024809;
LABEL_11:
    sub_1800038E8((unsigned int)v2);
    goto LABEL_12;
  }
  ProcessHeap = GetProcessHeap();
  v4 = (unsigned __int64)HeapAlloc(ProcessHeap, 0, 0x10ui64);
  v5 = v4;
  if ( v4 )
  {
    *(_DWORD *)(v4 + 12) = 0;
    *(_OWORD *)(v4 & -(__int64)(v4 != -8i64)) = 0i64;
    *(_DWORD *)(v4 + 8) = 1;
    *(_QWORD *)v4 = off_1800A44C8;
    v6 = ((__int64 (__fastcall *)(unsigned __int64, __int64 *, __int64))sub_18008D570)(v4, &qword_1800A67D8, a1);
    v2 = v6;
    if ( v6 >= 0 )
      goto LABEL_8;
    v7 = (unsigned int)v6;
  }
  else
  {
    v2 = -2147024882;
    v5 = 0i64;
    v7 = 2147942414i64;
  }
  sub_1800038E8(v7);
LABEL_8:
  sub_180003B30(v2);
  if ( v5 )
    (*(void (__fastcall **)(unsigned __int64))(*(_QWORD *)v5 + 16i64))(v5);
  if ( v2 < 0 )
    goto LABEL_11;
LABEL_12:
  sub_180003B30(v2);
  return (unsigned int)v2;
}

/* 
.rdata:00000001800A44C8 off_1800A44C8   dq offset sub_18008D570 ; DATA XREF: sub_18008DB38+5D↑o
.rdata:00000001800A44D0                 dq offset sub_18000AC90
.rdata:00000001800A44D8                 dq offset sub_180012C00
.rdata:00000001800A44E0                 dq offset sub_18008D7D0
.rdata:00000001800A44E8                 dq offset sub_18008DA70
.rdata:00000001800A44F0                 dq offset sub_18008D9A0
 */
 
__int64 __fastcall sub_18008D7D0(__int64 a1, __int64 a2, unsigned __int8 *a3, __int64 a4)
{
  unsigned int v6; // ebx
  __int64 v7; // rcx
  int v8; // eax
  int v10; // [rsp+20h] [rbp-18h]

  if ( !a2 )
  {
    v6 = -2147024809;
LABEL_3:
    v7 = v6;
LABEL_9:
    sub_1800038E8(v7);
    goto LABEL_10;
  }
  v8 = sub_18008D85C(a2, a3, a4, a4, v10);
  v6 = v8;
  if ( v8 < 0 )
    goto LABEL_8;
  if ( !*(_DWORD *)(a2 + 52) )
  {
    v6 = -2147418113;
    goto LABEL_3;
  }
  v8 = (*(__int64 (__fastcall **)(__int64, __int64, __int64))(*(_QWORD *)a1 + 40i64))(a1, a2 + 72, a2 + 8);
  v6 = v8;
  if ( v8 < 0 )
  {
LABEL_8:
    v7 = (unsigned int)v8;
    goto LABEL_9;
  }
LABEL_10:
  sub_180003B30(v6);
  return v6;
}

__int64 __fastcall sub_18008D85C(__int64 a1, unsigned __int8 *a2, unsigned int a3, __int64 a4, int a5)
{
  __int64 v8; // rcx
  unsigned int v9; // ebx
  __int64 v10; // rcx
  int v11; // eax
  __int128 v13[2]; // [rsp+30h] [rbp-40h] BYREF
  __int128 v14[2]; // [rsp+50h] [rbp-20h] BYREF

  a5 = 0;
  memset(v14, 0, sizeof(v14));
  memset(v13, 0, sizeof(v13));
  if ( a2 && *(_DWORD *)(a1 + 48) )
  {
    if ( !dword_1800AFDC4 )
      dword_1800AFDC4 = 1;
    SetLastError(0);
    if ( !(unsigned int)sub_1800876C8((__int64)v13, a2, a3, (__int64)v14) )
    {
      v8 = 2147753985i64;
      goto LABEL_3;
    }
    if ( *(_QWORD *)&v13[0] == 0x2900000073i64 )
    {
      if ( *(_DWORD *)(a1 + 52) )
        v11 = sub_1800879C8((unsigned int)v13, (int)a1 + 72, (int)a1 + 56, (unsigned int)&a5, (__int64)v14);
      else
        v11 = sub_180087ACC((unsigned int)v13, (int)a1 + 56, (unsigned int)&a5, (int)a1 + 72, (__int64)v14);
      if ( v11 )
      {
        v9 = 0;
        if ( a5 )
        {
          *(_DWORD *)(a1 + 52) = 1;
          goto LABEL_17;
        }
        v9 = -2147217327;
        v10 = 2147749969i64;
LABEL_16:
        sub_1800038E8(v10);
LABEL_17:
        sub_18008763C(v13, v14);
        goto LABEL_18;
      }
      v10 = 2147753985i64;
    }
    else
    {
      v10 = 2147749972i64;
    }
    v9 = v10;
    goto LABEL_16;
  }
  v8 = 2147942487i64;
LABEL_3:
  v9 = v8;
  sub_1800038E8(v8);
LABEL_18:
  sub_180003B30(v9);
  return v9;
}

__int64 __fastcall sub_1800876C8(__int64 a1, unsigned __int8 *a2, unsigned int a3, __int64 a4)
{
  _DWORD *v8; // rax
  __int64 v9; // r8
  _QWORD *v10; // rcx
  unsigned __int64 v11; // rax
  unsigned __int64 v12; // rax
  unsigned __int64 v13; // rax
  unsigned __int64 v14; // rax
  unsigned __int64 v15; // rax
  unsigned __int64 v16; // rax
  __int64 v17; // rbx
  unsigned __int64 v18; // rcx
  unsigned __int64 v19; // rbx
  __int64 v20; // rdx
  __int64 v21; // rax
  __int64 v22; // rcx
  __int64 v23; // rdx
  _QWORD *v24; // rcx
  __int64 v25; // rbx
  __int64 v26; // rax
  __int64 v27; // rcx
  __int64 v29; // rax
  __int64 v30; // rbx
  __int64 v31; // rcx
  __int64 v32; // rcx
  __int64 v33; // rcx

  *(_QWORD *)(a1 + 24) = 0i64;
  v8 = (_DWORD *)sub_180009254(232i64);
  *(_QWORD *)(a1 + 24) = v8;
  if ( v8 )
  {
    *v8 = 0;
    *(_DWORD *)(*(_QWORD *)(a1 + 24) + 4i64) = 0;
    *(_QWORD *)(*(_QWORD *)(a1 + 24) + 208i64) = 0i64;
    *(_QWORD *)(*(_QWORD *)(a1 + 24) + 224i64) = 0i64;
    *(_QWORD *)(*(_QWORD *)(a1 + 24) + 192i64) = 0i64;
    *(_QWORD *)(*(_QWORD *)(a1 + 24) + 200i64) = 0i64;
    *(_QWORD *)(*(_QWORD *)(a1 + 24) + 216i64) = 0i64;
    if ( (unsigned int)sub_180087274(
                         a2,
                         a3,
                         v9,
                         *(_QWORD *)(a1 + 24) + 8i64,
                         (_QWORD *)(*(_QWORD *)(a1 + 24) + 160i64),
                         a4) )
    {
      *(_DWORD *)(*(_QWORD *)(a1 + 24) + 4i64) = 1;
      if ( (unsigned int)sub_1800880A4(*(_QWORD *)(a1 + 24) + 72i64, *(_QWORD *)(a1 + 24) + 8i64) )
      {
        **(_DWORD **)(a1 + 24) = 1;
        v10 = *(_QWORD **)(a1 + 24);
        v11 = v10[11];
        if ( v11 > 0xFFFFFFFF )
        {
          *(_DWORD *)a1 = -1;
        }
        else
        {
          *(_DWORD *)a1 = v11;
          v12 = v10[12];
          if ( v12 > 0xFFFFFFFF )
          {
            *(_DWORD *)(a1 + 4) = -1;
          }
          else
          {
            *(_DWORD *)(a1 + 4) = v12;
            v13 = v10[14];
            if ( v13 > 0xFFFFFFFF )
            {
              *(_DWORD *)(a1 + 8) = -1;
            }
            else
            {
              *(_DWORD *)(a1 + 8) = v13;
              v14 = v10[11];
              if ( v14 && (v14 = ((v14 - 1) >> 3) + 1, v14 > 0xFFFFFFFF) )
              {
                *(_DWORD *)(a1 + 12) = -1;
              }
              else
              {
                *(_DWORD *)(a1 + 12) = v14;
                v15 = v10[12];
                if ( v15 && (v15 = ((v15 - 1) >> 3) + 1, v15 > 0xFFFFFFFF) )
                {
                  *(_DWORD *)(a1 + 16) = -1;
                }
                else
                {
                  *(_DWORD *)(a1 + 16) = v15;
                  v16 = v10[15];
                  if ( v16 > 0xFFFFFFFF )
                  {
                    *(_DWORD *)(a1 + 20) = -1;
                  }
                  else
                  {
                    *(_DWORD *)(a1 + 20) = v16;
                    v17 = v10[16];
                    v18 = (unsigned __int64)(v10[12] + 63i64) >> 6;
                    v19 = v18 + v17;
                    if ( v19 >= v18 )
                    {
                      v20 = is_mul_ok(v19, 8ui64) ? sub_180009254(8 * v19) : 0i64;
                      *(_QWORD *)(*(_QWORD *)(a1 + 24) + 208i64) = v20;
                      v21 = *(_QWORD *)(a1 + 24);
                      if ( *(_QWORD *)(v21 + 208) )
                      {
                        *(_QWORD *)(v21 + 192) = v20;
                        v22 = *(_QWORD *)(a1 + 24);
                        v23 = v20 + 8i64 * *(_QWORD *)(v22 + 128);
                        *(_QWORD *)(v22 + 200) = v23;
                        v24 = *(_QWORD **)(a1 + 24);
                        if ( (__int64)(v23 + 8 * ((unsigned __int64)(v24[12] + 63i64) >> 6) - v24[26]) >> 3 == v19 )
                        {
                          v25 = v24[3] + 1i64;
                          if ( v24[3] != -1i64 )
                          {
                            v26 = sub_180009254(v24[3] + 1i64);
                            *(_QWORD *)(*(_QWORD *)(a1 + 24) + 224i64) = v26;
                            v27 = *(_QWORD *)(a1 + 24);
                            if ( *(_QWORD *)(v27 + 224) )
                            {
                              *(_QWORD *)(v27 + 216) = v26;
                              if ( v26
                                 + *(_QWORD *)(*(_QWORD *)(a1 + 24) + 24i64)
                                 - *(_QWORD *)(*(_QWORD *)(a1 + 24) + 224i64)
                                 + 1i64 == v25 )
                                return 1i64;
                            }
                          }
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  }
  v29 = *(_QWORD *)(a1 + 24);
  if ( v29 && *(_DWORD *)(v29 + 4) )
  {
    if ( v29 != -160 )
      sub_180009288(*(_QWORD *)(v29 + 184));
    v30 = *(_QWORD *)(a1 + 24);
    sub_180087BEC(*(_QWORD *)(v30 + 8), a4);
    sub_180009288(*(_QWORD *)(v30 + 64));
    v31 = *(_QWORD *)(*(_QWORD *)(a1 + 24) + 208i64);
    if ( v31 )
      sub_180009288(v31);
    v32 = *(_QWORD *)(*(_QWORD *)(a1 + 24) + 224i64);
    if ( v32 )
      sub_180009288(v32);
  }
  v33 = *(_QWORD *)(a1 + 24);
  if ( v33 )
    sub_180009288(v33);
  return 0i64;
}

// >> Here it start >>

__int64 __fastcall sub_180087274(unsigned __int8 *a1, unsigned int a2, __int64 a3, __int64 a4, _QWORD *a5, __int64 a6)
{
  _QWORD *v6; // r14
  int v8; // esi
  unsigned __int64 v9; // rbp
  unsigned __int64 v10; // rdx
  unsigned __int64 v11; // r13
  __int64 v12; // r15
  _QWORD *v13; // r15
  __int64 v14; // rax
  unsigned __int64 v15; // r14
  __int64 v16; // rax
  unsigned __int64 v17; // rcx
  unsigned __int128 v18; // rax
  unsigned __int64 v19; // rcx
  unsigned __int64 v20; // rbp
  __int64 v21; // rax
  __int64 v22; // rcx
  _QWORD *v23; // rdx
  __int64 v24; // rbp
  __int64 v25; // rbp
  __int64 v27; // rcx
  void *Src; // [rsp+30h] [rbp-38h]
  void *Srca; // [rsp+30h] [rbp-38h]

  v6 = 0i64;
  v8 = (int)a1;
  if ( a4 )
  {
    *a5 = 0i64;
    v9 = a2;
    a5[3] = 0i64;
    if ( a2 >= 4ui64
      && (*a1 | ((a1[1] | ((a1[2] | (a1[3] << 8)) << 8)) << 8)) == 1146447479
      && a2 >= 6ui64
      && a1[4] + (a1[5] << 8) == 256
      && a2 >= 0xCui64 )
    {
      v10 = a1[8] | ((a1[9] | ((unsigned __int64)*((unsigned __int16 *)a1 + 5) << 8)) << 8);
      v11 = v10 + 12;
      if ( v10 < 0xFFFFFFFFFFFFFFF4ui64 )
      {
        v12 = a6;
        if ( v11 > v9 )
          goto LABEL_36;
        v6 = (_QWORD *)a4;
        if ( !(unsigned int)sub_180085B88(a1 + 12, v10, (_DWORD *)a4, a6) || *(_DWORD *)(a4 + 12) || *(_DWORD *)(a4 + 8) )
          goto LABEL_36;
        *a5 = a4;
        v13 = *(_QWORD **)a4;
        v14 = sub_180090F98(*(_QWORD *)(*(_QWORD *)a4 + 1712i64), *(_QWORD *)(*(_QWORD *)a4 + 1656i64));
        if ( v14 )
          v15 = ((unsigned __int64)(v14 - 1) >> 3) + 1;
        else
          v15 = 1i64;
        v16 = sub_180087FF8(a4);
        if ( v16 )
        {
          if ( v9 == v16 )
          {
            v17 = 2i64 * *(_QWORD *)(a4 + 16);
            if ( is_mul_ok(*(_QWORD *)(a4 + 16), 2ui64) )
            {
              v18 = v17 * (unsigned __int128)(unsigned __int64)v13[165];
              if ( is_mul_ok(v17, v13[165]) )
              {
                v19 = v13[186];
                v20 = v19 + v18;
                if ( v19 + (unsigned __int64)v18 >= v19 )
                {
                  if ( is_mul_ok(v20, (unsigned int)(DWORD2(v18) + 8)) )
                  {
                    v21 = sub_180009254(v20 * (unsigned int)(DWORD2(v18) + 8));
                    a5[3] = v21;
                    if ( v21 )
                    {
                      a5[1] = v21;
                      v22 = v21 + 16i64 * *(_QWORD *)(a4 + 16) * v13[165];
                      a5[2] = v22;
                      if ( (v22 + 8i64 * v13[186] - v21) >> 3 == v20 )
                      {
                        v23 = *(_QWORD **)a4;
                        v24 = 0i64;
                        if ( 2i64 * *(_QWORD *)(a4 + 16) * *(_QWORD *)(*(_QWORD *)a4 + 8i64) )
                        {
                          while ( 1 )
                          {
                            Src = (void *)(a5[1] + 8 * v13[144] * v24);
                            if ( !(unsigned int)sub_180085B30(
                                                  v8 + (int)v11,
                                                  v15,
                                                  *((_DWORD *)a5 + 2) + 8 * *((_DWORD *)v13 + 288) * (int)v24,
                                                  v23[207],
                                                  a6) )
                              break;
                            v11 += v15;
                            if ( !(unsigned int)sub_18008F5E8(Src, a6) )
                              break;
                            v23 = *(_QWORD **)a4;
                            if ( ++v24 >= (unsigned __int64)(2i64
                                                           * *(_QWORD *)(a4 + 16)
                                                           * *(_QWORD *)(*(_QWORD *)a4 + 8i64)) )
                              goto LABEL_27;
                          }
                        }
                        else
                        {
LABEL_27:
                          v25 = 0i64;
                          if ( v23[1] * v23[2] )
                          {
                            while ( 1 )
                            {
                              Srca = (void *)(a5[2] + 8 * v13[144] * v25);
                              if ( !(unsigned int)sub_180085B30(
                                                    v8 + (int)v11,
                                                    v15,
                                                    *((_DWORD *)a5 + 4) + 8 * *((_DWORD *)v13 + 288) * (int)v25,
                                                    v23[207],
                                                    a6) )
                                break;
                              v11 += v15;
                              if ( !(unsigned int)sub_18008F5E8(Srca, a6) )
                                break;
                              v23 = *(_QWORD **)a4;
                              if ( (unsigned __int64)++v25 >= *(_QWORD *)(*(_QWORD *)a4 + 8i64)
                                                            * *(_QWORD *)(*(_QWORD *)a4 + 16i64) )
                                goto LABEL_31;
                            }
                          }
                          else
                          {
LABEL_31:
                            if ( v11 == a2 )
                              return 1i64;
                          }
                        }
                      }
                    }
                  }
                  else
                  {
                    a5[3] = 0i64;
                  }
                }
              }
            }
          }
        }
        v6 = (_QWORD *)a4;
      }
    }
  }
  v12 = a6;
LABEL_36:
  v27 = a5[3];
  if ( v27 )
    sub_180009288(v27);
  if ( *a5 )
  {
    if ( v6 )
    {
      sub_180087BEC(*v6, v12);
      sub_180009288(v6[7]);
    }
  }
  return 0i64;
}

/* 
PKEY2005 Validation
https://github.com/UMSKT/writeups/blob/main/PKEY2005.md 

u8 size_bignum @ 0x15;

// Bignums are stored in little endian order
struct bignum {
    u8 data[size_bignum];
};

struct field_data {
    u32 magic; // 0x00112233
    u16 eq256; // must be 0x0100
    padding[2];
    u8 must_be_0; // Enables use of unused values, but parser will error if nonzero
    u8 size_modulus; // Same as size_bignum
    u8 size_order;
    u32 ext_deg1; // Degree of first field extension
    u32 ext_deg2; // Degree of second field extension
    u32 at_0x1f; // unused
    u32 at_0x23; // unused
    u32 at_0x27; // unused
    u32 num_elements; // Number of points Qi and length of H1 vector
    u32 at_0x2f; // unused
    u32 at_0x33; // unused
    u32 at_0x37; // unused
    u8 max_quotient; // Can equal floor((24 ^ 25) / p) - 1, unused
    u8 h1_coeffs[num_elements]; // H1 radices
    bignum modulus; // Prime modulus of base field
    u8 order[size_order]; // Order of elliptic curve over base field (also a bignum)
    // Polynomials are stored as signed bytes in order of lowest to highest degree coefficients
    // Negative coefficients will be reduced in the field K, so c[i] = -u == p - u
    s8 ext_split_poly1[ext_deg1 + 1]; // Minimal polynomial of first field extension
    s8 ext_split_poly2[ext_deg2 + 1]; // Minimal polynomial of second field extension
    // Unused capability: y^2 = x^3 + ec_a_base * x + ec_b_base
    // This curve would be over the base field
    bignum ec_a_base;
    bignum ec_b_base;
    // Elliptic curve: y^2 = x^3 + ax + b
    bignum ec_a; // a coefficient
    bignum ec_b; // b coefficient
};

struct ecpoint_k3 {
    bignum x[3];
    bignum y[3];
};

struct Pubkey {
    u32 magic; // 0x44556677
    u16 eq256; // must be 0x0100
    padding[2];
    u32 field_data_size;
    field_data field;
    padding[field_data_size + 12 - $];
    ecpoint_k3 points[field.num_elements]; // Points Qi over twisted curve
    bignum pairing_val[field.ext_deg1 * field.ext_deg2]; // value of Tate pairing between generator P and signature base point S
};

Pubkey pubkey @ 0; */

__int64 __fastcall sub_180085B88(unsigned __int8 *a1, unsigned __int64 a2, _DWORD *a3, __int64 a4)
{
  _BYTE *v4; // rbx
  int v9; // ecx
  int v10; // ecx
  int v11; // edx
  unsigned __int64 v12; // r15
  unsigned __int64 v13; // r8
  __int64 v14; // rbp
  __int64 v15; // r14
  unsigned int v16; // ecx
  unsigned __int64 v17; // r11
  unsigned int v18; // ecx
  unsigned int v19; // ecx
  int v20; // eax
  __int64 v21; // rcx
  unsigned __int64 v22; // r9
  __int64 v23; // rax
  __int64 v24; // rcx
  __int64 v25; // rdx
  unsigned __int64 v26; // rax
  unsigned __int64 v27; // rcx
  unsigned __int64 v28; // rax
  unsigned __int64 v29; // r8
  unsigned __int64 v30; // rax
  unsigned __int64 v31; // rcx
  unsigned __int128 v32; // rax
  __int64 v33; // rax
  __int64 v34; // rax
  __int64 v35; // rcx
  __int64 v36; // rax
  __int64 v37; // rcx
  unsigned __int64 v38; // rax
  unsigned __int64 v39; // r8
  unsigned __int64 v40; // rax
  _QWORD *v41; // rcx
  unsigned __int64 v42; // rax
  unsigned __int64 v43; // rdx
  unsigned __int64 v44; // rax
  unsigned __int64 v45; // r9
  unsigned __int64 v46; // r8
  unsigned __int64 v47; // rdx
  unsigned __int64 v48; // rax
  unsigned __int64 v49; // rcx
  unsigned __int64 v50; // rax
  unsigned __int64 v51; // rcx
  unsigned __int64 v52; // kr30_8
  unsigned __int64 v53; // r8
  unsigned __int64 v54; // rax
  unsigned __int64 v55; // rcx
  unsigned __int64 v56; // rax
  unsigned __int64 v57; // r8
  unsigned __int64 v58; // rax
  unsigned __int64 v59; // rcx
  unsigned __int64 v60; // rax
  unsigned __int64 v61; // rbp
  bool v62; // cf
  unsigned __int64 v63; // rax
  unsigned __int64 v64; // r8
  unsigned __int64 v65; // rax
  unsigned __int64 v66; // rdx
  unsigned __int64 v67; // rax
  unsigned __int64 v68; // rcx
  __int64 v69; // rdx
  __int64 v70; // rdx
  __int64 v71; // r8
  __int64 v72; // rdx
  __int64 v73; // r8
  __int64 v74; // r8
  __int64 v75; // rax
  __int64 v76; // r8
  __int64 v77; // r8
  __int64 v78; // rcx
  __int64 v79; // rdx
  __int64 v80; // rcx
  unsigned __int64 v81; // r9
  unsigned __int64 v82; // rax
  unsigned __int64 v83; // r8
  unsigned __int64 v84; // r9
  unsigned __int64 v85; // kr40_8
  unsigned __int64 v86; // rcx
  unsigned __int128 v87; // rax
  unsigned __int64 v88; // rbp
  __int64 v89; // rax
  __int64 v90; // rdx
  __int64 v91; // r8
  __int64 v92; // rax
  __int64 v93; // r8
  __int64 v94; // rax
  __int64 v95; // r8
  __int64 v96; // rcx
  __int64 v97; // rax
  char *v98; // rax
  BOOL v99; // r8d
  int v100; // eax
  BOOL v101; // ebp
  _QWORD *v102; // r12
  _QWORD *v103; // rcx
  char *v104; // r14
  _QWORD *v105; // rdx
  __int64 v106; // r9
  unsigned __int64 v107; // r8
  __int64 v108; // rcx
  __int64 v109; // rcx
  unsigned __int64 v110; // r8
  __int64 v111; // rcx
  __int64 v112; // rax
  char *v113; // r14
  __int64 v114; // rax
  char *v115; // r14
  _BYTE *v116; // rbp
  int v117; // eax
  unsigned __int64 v118; // r14
  unsigned __int64 v119; // r9
  unsigned __int64 v120; // rcx
  unsigned __int64 v121; // rax
  void *v122; // rbp
  unsigned __int64 v123; // rcx
  __int64 v124; // rbp
  __int64 v125; // rax
  unsigned __int64 v126; // rcx
  __int64 v127; // rbp
  __int64 v128; // rax
  unsigned __int64 v129; // rcx
  __int64 v130; // rbp
  __int64 v131; // rax
  _QWORD *v132; // r10
  __int64 v133; // rcx
  __int64 v134; // r11
  __int64 v135; // rbp
  __int64 v136; // rdx
  __int64 v137; // r14
  __int64 v138; // rbp
  __int64 v139; // rdx
  __int64 v140; // rax
  int v141; // eax
  char *v143; // [rsp+40h] [rbp-C8h]
  void *v144; // [rsp+40h] [rbp-C8h]
  void *v145; // [rsp+40h] [rbp-C8h]
  void *v146; // [rsp+40h] [rbp-C8h]
  void *v147; // [rsp+40h] [rbp-C8h]
  unsigned __int64 v148; // [rsp+48h] [rbp-C0h]
  unsigned __int64 v149; // [rsp+48h] [rbp-C0h]
  unsigned __int64 v150; // [rsp+50h] [rbp-B8h]
  unsigned __int64 v151; // [rsp+58h] [rbp-B0h]
  char *v152; // [rsp+60h] [rbp-A8h]
  unsigned int v153; // [rsp+68h] [rbp-A0h]
  char *v154; // [rsp+68h] [rbp-A0h]
  unsigned int v155; // [rsp+70h] [rbp-98h]
  char *v156; // [rsp+70h] [rbp-98h]
  __int64 Size; // [rsp+78h] [rbp-90h]
  size_t Sizea; // [rsp+78h] [rbp-90h]
  unsigned __int64 v159; // [rsp+80h] [rbp-88h]
  char *v160; // [rsp+88h] [rbp-80h]
  unsigned int v161; // [rsp+90h] [rbp-78h]
  char *v162; // [rsp+90h] [rbp-78h]
  unsigned __int64 v163; // [rsp+98h] [rbp-70h]
  char *v164; // [rsp+98h] [rbp-70h]
  char *Src; // [rsp+A8h] [rbp-60h]
  __int64 v166; // [rsp+B0h] [rbp-58h]
  __int64 v167; // [rsp+B8h] [rbp-50h]
  char *v168; // [rsp+C0h] [rbp-48h]
  char *v169; // [rsp+C8h] [rbp-40h]
  unsigned __int64 v171; // [rsp+120h] [rbp+18h]

  v4 = 0i64;
  *((_QWORD *)a3 + 7) = 0i64;
  *(_QWORD *)a3 = 0i64;
  if ( a2 < 4
    || (*a1 | ((a1[1] | (*((unsigned __int16 *)a1 + 1) << 8)) << 8)) != 1122867
    || a2 < 6
    || a1[4] + (a1[5] << 8) != 256
    || a2 < 9 )
  {
    goto LABEL_223;
  }
  v9 = a1[8];
  if ( !a1[8] )
  {
    a3[2] = 0;
    goto LABEL_12;
  }
  v10 = v9 - 2;
  if ( !v10 )
  {
    a3[2] = 1;
LABEL_12:
    a3[3] = 0;
    v11 = 0;
    goto LABEL_13;
  }
  if ( v10 != 1 )
    goto LABEL_223;
  a3[2] = 1;
  v11 = 1;
  a3[3] = 1;
LABEL_13:
  if ( a2 < 0xA )
    goto LABEL_223;
  v12 = a1[9];
  if ( !a1[9] )
    goto LABEL_223;
  v171 = ((v12 - 1) >> 3) + 1;
  if ( a2 < 0xB )
    goto LABEL_223;
  v13 = a1[10];
  v148 = v13;
  if ( !a1[10] )
    goto LABEL_223;
  if ( a2 < 0xF )
    goto LABEL_223;
  v14 = a1[11] | ((a1[12] | (*(unsigned __int16 *)(a1 + 13) << 8)) << 8);
  if ( a2 < 0x13 )
    goto LABEL_223;
  v15 = a1[15] | ((a1[16] | (*(unsigned __int16 *)(a1 + 17) << 8)) << 8);
  if ( a2 < 0x17 )
    goto LABEL_223;
  v16 = a1[19] | ((a1[20] | (*(unsigned __int16 *)(a1 + 21) << 8)) << 8);
  v161 = v16;
  if ( !v11 )
  {
    if ( v16 )
      goto LABEL_223;
  }
  v17 = v16;
  v159 = v16;
  if ( a2 < 0x1B )
    goto LABEL_223;
  v18 = a1[23] | ((a1[24] | (*(unsigned __int16 *)(a1 + 25) << 8)) << 8);
  v155 = v18;
  if ( !v11 )
  {
    if ( v18 )
      goto LABEL_223;
  }
  v150 = v18;
  if ( a2 < 0x1F )
    goto LABEL_223;
  v19 = a1[27] | ((a1[28] | (*(unsigned __int16 *)(a1 + 29) << 8)) << 8);
  v153 = v19;
  if ( !v11 )
  {
    if ( v19 )
      goto LABEL_223;
  }
  v151 = v19;
  if ( a2 < 0x23 )
    goto LABEL_223;
  v20 = a1[31];
  v21 = v20 | ((a1[32] | (*(unsigned __int16 *)(a1 + 33) << 8)) << 8);
  if ( !(v20 | ((a1[32] | (*(unsigned __int16 *)(a1 + 33) << 8)) << 8)) )
    goto LABEL_223;
  v22 = (unsigned int)v21;
  v23 = v21 + 50;
  v163 = (unsigned int)v21;
  *((_QWORD *)a3 + 2) = (unsigned int)v21;
  if ( v21 + 50 < (unsigned __int64)(unsigned int)v21 )
    goto LABEL_223;
  v24 = v23 + v13;
  if ( v23 + v13 < v13 )
    goto LABEL_223;
  v25 = v24 + v14;
  if ( v24 + v14 < (unsigned __int64)(unsigned int)v14 )
    goto LABEL_223;
  if ( v15 + v25 < (unsigned __int64)(unsigned int)v15 )
    goto LABEL_223;
  v26 = 10 * v12;
  if ( !is_mul_ok(0xAui64, v12) )
    goto LABEL_223;
  v27 = v26 + v15 + v25;
  if ( v27 < v26 )
    goto LABEL_223;
  v28 = v17 * v12;
  if ( !is_mul_ok(v17, v12) )
    goto LABEL_223;
  v29 = v28 + v27;
  if ( v28 + v27 < v28 )
    goto LABEL_223;
  v30 = v150 * v12;
  if ( !is_mul_ok(v150, v12) )
    goto LABEL_223;
  v31 = v30 + v29;
  if ( v30 + v29 < v30 )
    goto LABEL_223;
  v32 = v151 * (unsigned __int128)v12;
  if ( !is_mul_ok(v151, v12) )
    goto LABEL_223;
  if ( (unsigned __int64)v32 + v31 < (unsigned __int64)v32 )
    goto LABEL_223;
  if ( !is_mul_ok((unsigned int)(DWORD2(v32) + 2), (unsigned int)v14) )
    goto LABEL_223;
  if ( !is_mul_ok((unsigned int)(DWORD2(v32) + 2) * (unsigned __int64)(unsigned int)v14, v12) )
    goto LABEL_223;
  *(_QWORD *)&v32 = v32 + v31 + (unsigned int)(DWORD2(v32) + 2) * (unsigned __int64)(unsigned int)v14 * v12;
  if ( (unsigned __int64)v32 < (unsigned int)(DWORD2(v32) + 2) * (unsigned __int64)(unsigned int)v14 * v12 )
    goto LABEL_223;
  if ( a2 != v33 )
    goto LABEL_223;
  if ( a2 < 0x27 )
    goto LABEL_223;
  *((_QWORD *)a3 + 4) = a1[35] | ((a1[36] | ((unsigned __int64)*(unsigned __int16 *)(a1 + 37) << 8)) << 8);
  if ( a2 < 0x2B )
    goto LABEL_223;
  *((_QWORD *)a3 + 6) = a1[39] | ((a1[40] | ((unsigned __int64)*(unsigned __int16 *)(a1 + 41) << 8)) << 8);
  if ( a2 < 0x2F )
    goto LABEL_223;
  *((_QWORD *)a3 + 5) = a1[43] | ((a1[44] | ((unsigned __int64)*(unsigned __int16 *)(a1 + 45) << 8)) << 8);
  if ( v22 + 1848 < v22 )
    goto LABEL_223;
  v34 = sub_180009254(v22 + 1849);
  *((_QWORD *)a3 + 7) = v34;
  if ( !v34 )
    goto LABEL_223;
  *(_QWORD *)a3 = v34;
  v35 = v34 + 1848;
  *(_DWORD *)(v34 + 40) = 0;
  *(_DWORD *)(*(_QWORD *)a3 + 44i64) = 0;
  *(_DWORD *)(*(_QWORD *)a3 + 48i64) = 0;
  *(_DWORD *)(*(_QWORD *)a3 + 52i64) = 0;
  *(_DWORD *)(*(_QWORD *)a3 + 56i64) = 0;
  *(_DWORD *)(*(_QWORD *)a3 + 60i64) = 0;
  *(_DWORD *)(*(_QWORD *)a3 + 64i64) = 0;
  *(_DWORD *)(*(_QWORD *)a3 + 68i64) = 0;
  *(_DWORD *)(*(_QWORD *)a3 + 76i64) = 0;
  *(_DWORD *)(*(_QWORD *)a3 + 72i64) = 0;
  *(_DWORD *)(*(_QWORD *)a3 + 80i64) = 0;
  v36 = *((_QWORD *)a3 + 2) + 1i64;
  *((_QWORD *)a3 + 3) = v35;
  if ( v36 + v35 - *((_QWORD *)a3 + 7) != v163 + 1849 )
    goto LABEL_223;
  *(_QWORD *)(*(_QWORD *)a3 + 8i64) = (unsigned int)v14;
  *(_QWORD *)(*(_QWORD *)a3 + 16i64) = (unsigned int)v15;
  **(_DWORD **)a3 = a3[3];
  *(_QWORD *)(*(_QWORD *)a3 + 1816i64) = ((v148 - 1) >> 3) + 1;
  *(_QWORD *)(*(_QWORD *)a3 + 1792i64) = 0i64;
  v37 = *(_QWORD *)a3;
  if ( !is_mul_ok(v171, *(_QWORD *)(*(_QWORD *)a3 + 8i64)) )
    goto LABEL_223;
  v38 = v171 * *(_QWORD *)(*(_QWORD *)a3 + 8i64) * *(_QWORD *)(v37 + 16);
  v39 = v38;
  if ( !is_mul_ok(v171 * *(_QWORD *)(*(_QWORD *)a3 + 8i64), *(_QWORD *)(v37 + 16)) )
    goto LABEL_223;
  v40 = *(_QWORD *)(*(_QWORD *)a3 + 1792i64) + v38;
  if ( v40 < v39 )
  {
    *(_QWORD *)(v37 + 1792) = -1i64;
    goto LABEL_223;
  }
  *(_QWORD *)(v37 + 1792) = v40;
  v41 = *(_QWORD **)a3;
  v42 = *(_QWORD *)(*(_QWORD *)a3 + 1816i64);
  v43 = v42 + 2;
  if ( a3[3] )
  {
    if ( v43 < v42 )
      goto LABEL_223;
    v44 = v41[224];
    v45 = v44 + v43;
    if ( v44 + v43 < v44 )
      goto LABEL_223;
    v46 = v41[1];
    v47 = v46 + v45;
    if ( v46 + v45 < v46 )
      goto LABEL_223;
    v48 = v41[2];
    v49 = v48 + v47;
    if ( v48 + v47 < v48 )
      goto LABEL_223;
    v50 = 6 * v171;
    if ( !is_mul_ok(6ui64, v171) )
      goto LABEL_223;
    v51 = v50 + v49;
    if ( v51 < v50 )
      goto LABEL_223;
    v52 = v46;
    v53 = 2 * v46;
    if ( !is_mul_ok(2ui64, v52) )
      goto LABEL_223;
    v54 = v53 * v171;
    if ( !is_mul_ok(v53, v171) )
      goto LABEL_223;
    v55 = v54 + v51;
    if ( v55 < v54 )
      goto LABEL_223;
    v56 = v159 * v171;
    if ( !is_mul_ok(v159, v171) )
      goto LABEL_223;
    v57 = v56 + v55;
    if ( v56 + v55 < v56 )
      goto LABEL_223;
    v58 = v150 * v171;
    if ( !is_mul_ok(v150, v171) )
      goto LABEL_223;
    v59 = v58 + v57;
    if ( v58 + v57 < v58 )
      goto LABEL_223;
    v60 = v151 * v171;
    if ( !is_mul_ok(v151, v171) )
      goto LABEL_223;
    v61 = v60 + v59;
    v62 = v60 + v59 < v60;
  }
  else
  {
    if ( v43 < v42 )
      goto LABEL_223;
    v63 = v41[224];
    v64 = v63 + v43;
    if ( v63 + v43 < v63 )
      goto LABEL_223;
    v65 = v41[1];
    v66 = v65 + v64;
    if ( v65 + v64 < v65 )
      goto LABEL_223;
    v67 = v41[2];
    v68 = v67 + v66;
    if ( v67 + v66 < v67 )
      goto LABEL_223;
    v61 = v68 + v171;
    v62 = v68 + v171 < v171;
  }
  if ( !v62 )
  {
    v69 = sub_180092FD0(v61);
    *(_QWORD *)(*(_QWORD *)a3 + 1840i64) = v69;
    if ( *(_QWORD *)(*(_QWORD *)a3 + 1840i64) )
    {
      *(_QWORD *)(*(_QWORD *)a3 + 1808i64) = v69;
      v70 = v69 + 8i64 * *(_QWORD *)(*(_QWORD *)a3 + 1816i64);
      *(_QWORD *)(*(_QWORD *)a3 + 1784i64) = v70;
      v71 = v70 + 8i64 * *(_QWORD *)(*(_QWORD *)a3 + 1792i64);
      *(_QWORD *)(*(_QWORD *)a3 + 24i64) = v71;
      v72 = v71 + 8 * (*(_QWORD *)(*(_QWORD *)a3 + 8i64) + 1i64);
      *(_QWORD *)(*(_QWORD *)a3 + 32i64) = v72;
      v73 = v72 + 8 * (*(_QWORD *)(*(_QWORD *)a3 + 16i64) + 1i64);
      *(_QWORD *)(*(_QWORD *)a3 + 1800i64) = v73;
      v74 = 8 * v171 + v73;
      Size = 8 * v171;
      v75 = *(_QWORD *)a3;
      if ( a3[3] )
      {
        *(_QWORD *)(v75 + 1824) = v74;
        v76 = 16 * v171 + v74;
        *(_QWORD *)(*(_QWORD *)a3 + 1832i64) = v76;
        v77 = 16 * *(_QWORD *)(*(_QWORD *)a3 + 8i64) * v171 + v76;
        *(_DWORD *)(*(_QWORD *)a3 + 1104i64) = v161;
        *(_DWORD *)(*(_QWORD *)a3 + 1120i64) = v155;
        *(_DWORD *)(*(_QWORD *)a3 + 1136i64) = v153;
        *(_QWORD *)(*(_QWORD *)a3 + 1112i64) = v77;
        v78 = v77 + 8 * v171 * (v159 + 1);
        *(_QWORD *)(*(_QWORD *)a3 + 1128i64) = v78;
        v79 = v78 + 8 * v171 * (v150 + 1);
        *(_QWORD *)(*(_QWORD *)a3 + 1144i64) = v79;
        v74 = v79 + 8 * v171 * (v151 + 1);
      }
      else
      {
        *(_QWORD *)(v75 + 1832) = 0i64;
        *(_QWORD *)(*(_QWORD *)a3 + 1824i64) = 0i64;
        *(_DWORD *)(*(_QWORD *)a3 + 1136i64) = 0;
        *(_DWORD *)(*(_QWORD *)a3 + 1120i64) = 0;
        *(_DWORD *)(*(_QWORD *)a3 + 1104i64) = 0;
        *(_QWORD *)(*(_QWORD *)a3 + 1144i64) = 0i64;
        *(_QWORD *)(*(_QWORD *)a3 + 1128i64) = 0i64;
        *(_QWORD *)(*(_QWORD *)a3 + 1112i64) = 0i64;
      }
      v80 = *(_QWORD *)a3;
      if ( (v74 - *(_QWORD *)(*(_QWORD *)a3 + 1840i64)) >> 3 == v61 && is_mul_ok(7ui64, v171) )
      {
        v81 = 2i64 * *(_QWORD *)(v80 + 8);
        if ( is_mul_ok(2ui64, *(_QWORD *)(v80 + 8)) )
        {
          v82 = v81 * v171;
          if ( is_mul_ok(v81, v171) )
          {
            v83 = v82 + 7 * v171;
            if ( v83 >= v82 )
            {
              v84 = 6i64 * *(_QWORD *)(v80 + 8);
              if ( is_mul_ok(6ui64, *(_QWORD *)(v80 + 8)) )
              {
                v85 = *(_QWORD *)(v80 + 16);
                v86 = v84 * v85;
                if ( is_mul_ok(v84, v85) )
                {
                  v87 = v86 * (unsigned __int128)v171;
                  if ( is_mul_ok(v86, v171) )
                  {
                    v88 = v87 + v83;
                    if ( (unsigned __int64)v87 + v83 >= (unsigned __int64)v87
                      && is_mul_ok(v88, (unsigned int)(DWORD2(v87) + 8)) )
                    {
                      v89 = sub_180009254(v88 * (unsigned int)(DWORD2(v87) + 8));
                      v4 = (_BYTE *)v89;
                      if ( v89 )
                      {
                        v166 = v89 + Size;
                        v90 = *(_QWORD *)(*(_QWORD *)a3 + 8i64);
                        v91 = *(_QWORD *)(*(_QWORD *)a3 + 16i64);
                        v167 = v89 + Size + 8 * v171 * (v90 + 1);
                        v92 = v90 * (v91 + 1);
                        v93 = v90 * v91;
                        v154 = (char *)(v167 + 8 * v171 * v92);
                        v94 = 8 * v171 * v93;
                        v152 = &v154[Size];
                        v156 = &v154[Size + Size];
                        v160 = &v156[Size];
                        v162 = &v156[Size + Size];
                        v168 = &v162[v94];
                        v164 = &v162[v94 + v94];
                        v169 = &v164[v94];
                        Src = &v164[v94 + v94];
                        if ( (__int64)&Src[8 * v171 * (v93 + 1) - (_QWORD)v4] >> 3 == v88 )
                        {
                          v95 = *((_QWORD *)a3 + 2);
                          if ( v95 + 48 <= a2 )
                          {
                            memcpy(*((void **)a3 + 3), a1 + 47, v95 + 1);
                            v96 = *((_QWORD *)a3 + 2);
                            v97 = 1i64;
                            if ( v96 != -1 && v96 != 0 )
                            {
                              while ( *(_BYTE *)(*((_QWORD *)a3 + 3) + v97) )
                              {
                                if ( ++v97 >= (unsigned __int64)(v96 + 1) )
                                  goto LABEL_97;
                              }
                              goto LABEL_223;
                            }
LABEL_97:
                            if ( *(_BYTE *)(*((_QWORD *)a3 + 3) + 1i64) == 1 )
                            {
                              v98 = (char *)(v12 + v96 + 48);
                              v143 = v98;
                              if ( (unsigned __int64)v98 <= a2
                                && a1[(_QWORD)v98 - 1]
                                && (unsigned int)sub_180085B30((int)a1 + (int)v96 + 48, v12, (_DWORD)v4, v171, a4) )
                              {
                                v100 = sub_18008EE44(v4, v171, v99, *(_QWORD *)a3 + 1656i64, a4);
                                *(_DWORD *)(*(_QWORD *)a3 + 80i64) = v100 != 0;
                                v101 = v100
                                    && sub_18008E5A8((__int64 *)(*(_QWORD *)a3 + 1656i64), *(_QWORD *)a3 + 1152i64, a4);
                                *(_DWORD *)(*(_QWORD *)a3 + 68i64) = v101;
                                v102 = (_QWORD *)(*(_QWORD *)a3 + 1152i64);
                                memset(
                                  *(void **)(*(_QWORD *)a3 + 1784i64),
                                  0,
                                  8i64 * *(_QWORD *)(*(_QWORD *)a3 + 1792i64));
                                memcpy(*(void **)(*(_QWORD *)a3 + 1784i64), v4, Size);
                                v103 = *(_QWORD **)a3;
                                Sizea = 1i64;
                                if ( v103[1] * v103[2] > 1ui64 )
                                {
                                  do
                                  {
                                    v101 = v101
                                        && (unsigned int)sub_180090FE4(v103[223], v103[224], (int)v4, v171, Src, a4);
                                    memcpy(
                                      *(void **)(*(_QWORD *)a3 + 1784i64),
                                      Src,
                                      8i64 * *(_QWORD *)(*(_QWORD *)a3 + 1792i64));
                                    v103 = *(_QWORD **)a3;
                                    ++Sizea;
                                  }
                                  while ( Sizea < v103[1] * v103[2] );
                                }
                                v103[137] = v102;
                                v104 = &v143[v148];
                                if ( (unsigned __int64)&v143[v148] <= a2 )
                                {
                                  if ( a1[(_QWORD)v104 - 1] )
                                  {
                                    if ( v101 )
                                    {
                                      if ( (unsigned int)sub_180085B30(
                                                           (int)v143 + (int)a1,
                                                           v148,
                                                           *(_QWORD *)(*(_QWORD *)a3 + 1808i64),
                                                           *(_QWORD *)(*(_QWORD *)a3 + 1816i64),
                                                           a4) )
                                      {
                                        v105 = *(_QWORD **)a3;
                                        v106 = *(_QWORD *)(*(_QWORD *)a3 + 8i64);
                                        if ( (unsigned __int64)&v104[v106 + 1] <= a2 )
                                        {
                                          v107 = 0i64;
                                          if ( v106 != -1 )
                                          {
                                            do
                                            {
                                              v108 = (char)a1[(_QWORD)v104++];
                                              *(_QWORD *)(v105[3] + 8 * v107++) = v108;
                                              v105 = *(_QWORD **)a3;
                                            }
                                            while ( v107 < *(_QWORD *)(*(_QWORD *)a3 + 8i64) + 1i64 );
                                          }
                                          v109 = v105[2];
                                          if ( (unsigned __int64)&v104[v109 + 1] <= a2 )
                                          {
                                            v110 = 0i64;
                                            if ( v109 != -1 )
                                            {
                                              do
                                              {
                                                v111 = (char)a1[(_QWORD)v104++];
                                                *(_QWORD *)(v105[4] + 8 * v110++) = v111;
                                                v105 = *(_QWORD **)a3;
                                              }
                                              while ( v110 < *(_QWORD *)(*(_QWORD *)a3 + 16i64) + 1i64 );
                                            }
                                            if ( (unsigned __int64)&v104[v12] <= a2 )
                                            {
                                              if ( a3[3] )
                                              {
                                                if ( !(unsigned int)sub_180085B30(
                                                                      (int)v104 + (int)a1,
                                                                      v12,
                                                                      (_DWORD)v154,
                                                                      v171,
                                                                      a4)
                                                  || !(unsigned int)sub_18008F5E8(v154, a4) )
                                                {
                                                  goto LABEL_223;
                                                }
                                              }
                                              else
                                              {
                                                v112 = 0i64;
                                                if ( v12 )
                                                {
                                                  while ( !a1[(_QWORD)v104 + v112] )
                                                  {
                                                    if ( ++v112 >= v12 )
                                                      goto LABEL_129;
                                                  }
                                                  goto LABEL_223;
                                                }
                                              }
LABEL_129:
                                              v113 = &v104[v12];
                                              if ( (unsigned __int64)&v113[v12] <= a2 )
                                              {
                                                if ( a3[3] )
                                                {
                                                  if ( !(unsigned int)sub_180085B30(
                                                                        (int)v113 + (int)a1,
                                                                        v12,
                                                                        (_DWORD)v152,
                                                                        v171,
                                                                        a4)
                                                    || !(unsigned int)sub_18008F5E8(v152, a4) )
                                                  {
                                                    goto LABEL_223;
                                                  }
                                                }
                                                else
                                                {
                                                  v114 = 0i64;
                                                  if ( v12 )
                                                  {
                                                    while ( !a1[(_QWORD)v113 + v114] )
                                                    {
                                                      if ( ++v114 >= v12 )
                                                        goto LABEL_137;
                                                    }
                                                    goto LABEL_223;
                                                  }
                                                }
LABEL_137:
                                                v115 = &v113[v12];
                                                v116 = v4;
                                                if ( (unsigned __int64)&v115[v12] <= a2 )
                                                {
                                                  if ( (unsigned int)sub_180085B30(
                                                                       (int)v115 + (int)a1,
                                                                       v12,
                                                                       (_DWORD)v156,
                                                                       v171,
                                                                       a4) )
                                                  {
                                                    if ( (unsigned int)sub_18008F5E8(v156, a4) )
                                                    {
                                                      v117 = v12 + (_DWORD)v115;
                                                      v118 = (unsigned __int64)&v115[v12 + v12];
                                                      if ( v118 <= a2 )
                                                      {
                                                        if ( (unsigned int)sub_180085B30(
                                                                             v117 + (int)a1,
                                                                             v12,
                                                                             (_DWORD)v160,
                                                                             v171,
                                                                             a4) )
                                                        {
                                                          if ( (unsigned int)sub_18008F5E8(v160, a4) )
                                                          {
                                                            v119 = a2;
                                                            v120 = v12 * (v159 + 1);
                                                            if ( v120 + v118 <= a2 )
                                                            {
                                                              v121 = 0i64;
                                                              if ( a3[3] )
                                                              {
                                                                v149 = 0i64;
                                                                while ( 1 )
                                                                {
                                                                  v4 = v116;
                                                                  v122 = (void *)(*(_QWORD *)(*(_QWORD *)a3 + 1112i64)
                                                                                + 8 * *v102 * v121);
                                                                  if ( !(unsigned int)sub_180085B30(
                                                                                        (int)v118 + (int)a1,
                                                                                        v12,
                                                                                        *(_DWORD *)(*(_QWORD *)a3
                                                                                                  + 1112i64)
                                                                                      + 8 * *(_DWORD *)v102 * (int)v121,
                                                                                        v171,
                                                                                        a4) )
                                                                    goto LABEL_223;
                                                                  v118 += v12;
                                                                  if ( !(unsigned int)sub_18008F5E8(v122, a4) )
                                                                    goto LABEL_223;
                                                                  v121 = v149 + 1;
                                                                  v149 = v121;
                                                                  v116 = v4;
                                                                  if ( v121 >= v159 + 1 )
                                                                  {
                                                                    v119 = a2;
                                                                    goto LABEL_154;
                                                                  }
                                                                }
                                                              }
                                                              if ( v120 )
                                                              {
                                                                while ( !a1[v118 + v121] )
                                                                {
                                                                  if ( ++v121 >= v120 )
                                                                    goto LABEL_153;
                                                                }
                                                                goto LABEL_223;
                                                              }
LABEL_153:
                                                              v118 += v12 * (v159 + 1);
LABEL_154:
                                                              v123 = v12 * (v150 + 1);
                                                              if ( v123 + v118 <= v119 )
                                                              {
                                                                if ( a3[3] )
                                                                {
                                                                  v124 = 0i64;
                                                                  while ( 1 )
                                                                  {
                                                                    v144 = (void *)(*(_QWORD *)(*(_QWORD *)a3 + 1128i64)
                                                                                  + 8 * *v102 * v124);
                                                                    if ( !(unsigned int)sub_180085B30(
                                                                                          (int)v118 + (int)a1,
                                                                                          v12,
                                                                                          *(_DWORD *)(*(_QWORD *)a3 + 1128i64)
                                                                                        + 8
                                                                                        * *(_DWORD *)v102
                                                                                        * (int)v124,
                                                                                          v171,
                                                                                          a4) )
                                                                      goto LABEL_223;
                                                                    v118 += v12;
                                                                    if ( !(unsigned int)sub_18008F5E8(v144, a4) )
                                                                      goto LABEL_223;
                                                                    if ( ++v124 >= v150 + 1 )
                                                                    {
                                                                      v119 = a2;
                                                                      goto LABEL_165;
                                                                    }
                                                                  }
                                                                }
                                                                v125 = 0i64;
                                                                if ( v123 )
                                                                {
                                                                  while ( !a1[v118 + v125] )
                                                                  {
                                                                    if ( ++v125 >= v123 )
                                                                      goto LABEL_164;
                                                                  }
                                                                  goto LABEL_223;
                                                                }
LABEL_164:
                                                                v118 += v12 * (v150 + 1);
LABEL_165:
                                                                v126 = v12 * (v151 + 1);
                                                                if ( v126 + v118 <= v119 )
                                                                {
                                                                  if ( a3[3] )
                                                                  {
                                                                    v127 = 0i64;
                                                                    while ( 1 )
                                                                    {
                                                                      v145 = (void *)(*(_QWORD *)(*(_QWORD *)a3 + 1144i64)
                                                                                    + 8 * *v102 * v127);
                                                                      if ( !(unsigned int)sub_180085B30(
                                                                                            (int)v118 + (int)a1,
                                                                                            v12,
                                                                                            *(_DWORD *)(*(_QWORD *)a3 + 1144i64)
                                                                                          + 8
                                                                                          * *(_DWORD *)v102
                                                                                          * (int)v127,
                                                                                            v171,
                                                                                            a4) )
                                                                        goto LABEL_223;
                                                                      v118 += v12;
                                                                      if ( !(unsigned int)sub_18008F5E8(v145, a4) )
                                                                        goto LABEL_223;
                                                                      if ( ++v127 >= v151 + 1 )
                                                                      {
                                                                        v119 = a2;
                                                                        goto LABEL_176;
                                                                      }
                                                                    }
                                                                  }
                                                                  v128 = 0i64;
                                                                  if ( v126 )
                                                                  {
                                                                    while ( !a1[v118 + v128] )
                                                                    {
                                                                      if ( ++v128 >= v126 )
                                                                        goto LABEL_175;
                                                                    }
                                                                    goto LABEL_223;
                                                                  }
LABEL_175:
                                                                  v118 += v12 * (v151 + 1);
LABEL_176:
                                                                  v129 = 2 * v12;
                                                                  if ( 2 * v12 + v118 <= v119 )
                                                                  {
                                                                    if ( a3[3] )
                                                                    {
                                                                      v130 = 0i64;
                                                                      while ( 1 )
                                                                      {
                                                                        v146 = (void *)(*(_QWORD *)(*(_QWORD *)a3
                                                                                                  + 1824i64)
                                                                                      + 8 * *v102 * v130);
                                                                        if ( !(unsigned int)sub_180085B30(
                                                                                              (int)v118 + (int)a1,
                                                                                              v12,
                                                                                              *(_DWORD *)(*(_QWORD *)a3 + 1824i64)
                                                                                            + 8
                                                                                            * *(_DWORD *)v102
                                                                                            * (int)v130,
                                                                                              v171,
                                                                                              a4) )
                                                                          goto LABEL_223;
                                                                        v118 += v12;
                                                                        if ( !(unsigned int)sub_18008F5E8(v146, a4) )
                                                                          goto LABEL_223;
                                                                        if ( (unsigned __int64)++v130 >= 2 )
                                                                        {
                                                                          v119 = a2;
                                                                          goto LABEL_187;
                                                                        }
                                                                      }
                                                                    }
                                                                    v131 = 0i64;
                                                                    if ( v129 )
                                                                    {
                                                                      while ( !a1[v118 + v131] )
                                                                      {
                                                                        if ( ++v131 >= v129 )
                                                                          goto LABEL_186;
                                                                      }
                                                                      goto LABEL_223;
                                                                    }
LABEL_186:
                                                                    v118 += 2 * v12;
LABEL_187:
                                                                    v132 = *(_QWORD **)a3;
                                                                    v133 = *(_QWORD *)(*(_QWORD *)a3 + 8i64);
                                                                    v134 = 2 * v12 * v133;
                                                                    if ( v134 + v118 <= v119 )
                                                                    {
                                                                      if ( a3[3] )
                                                                      {
                                                                        v135 = 0i64;
                                                                        if ( 2 * v133 )
                                                                        {
                                                                          while ( 1 )
                                                                          {
                                                                            v147 = (void *)(v132[229] + 8 * *v102 * v135);
                                                                            if ( !(unsigned int)sub_180085B30(
                                                                                                  (int)v118 + (int)a1,
                                                                                                  v12,
                                                                                                  *((_DWORD *)v132 + 458)
                                                                                                + 8
                                                                                                * *(_DWORD *)v102
                                                                                                * (int)v135,
                                                                                                  v171,
                                                                                                  a4) )
                                                                              goto LABEL_223;
                                                                            v118 += v12;
                                                                            if ( !(unsigned int)sub_18008F5E8(v147, a4) )
                                                                              goto LABEL_223;
                                                                            v132 = *(_QWORD **)a3;
                                                                            if ( ++v135 >= (unsigned __int64)(2i64 * *(_QWORD *)(*(_QWORD *)a3 + 8i64)) )
                                                                            {
                                                                              v119 = a2;
                                                                              break;
                                                                            }
                                                                          }
                                                                        }
                                                                      }
                                                                      else
                                                                      {
                                                                        v136 = 0i64;
                                                                        if ( v134 )
                                                                        {
                                                                          while ( !a1[v118 + v136] )
                                                                          {
                                                                            if ( ++v136 >= 2 * v12 * v133 )
                                                                              goto LABEL_197;
                                                                          }
                                                                          goto LABEL_223;
                                                                        }
LABEL_197:
                                                                        v118 += 2 * v12 * v133;
                                                                      }
                                                                      if ( v118 == v119 )
                                                                      {
                                                                        v137 = (__int64)(v132 + 165);
                                                                        if ( (*(unsigned int (__fastcall **)(_QWORD, __int64, __int64, _QWORD *, __int64))(v102[8] + 32i64))(
                                                                               v132[3],
                                                                               v166,
                                                                               v132[1] + 1i64,
                                                                               v102,
                                                                               a4) )
                                                                        {
                                                                          if ( (unsigned int)sub_180092BA8(
                                                                                               (_DWORD)v102,
                                                                                               v166,
                                                                                               *(_QWORD *)(*(_QWORD *)a3 + 8i64),
                                                                                               v137,
                                                                                               a4) )
                                                                          {
                                                                            *(_DWORD *)(*(_QWORD *)a3 + 76i64) = 1;
                                                                            v138 = *(_QWORD *)a3 + 1488i64;
                                                                            if ( (*(unsigned int (__fastcall **)(_QWORD, __int64, __int64, __int64, __int64))(*(_QWORD *)(v137 + 64) + 32i64))(
                                                                                   *(_QWORD *)(*(_QWORD *)a3 + 32i64),
                                                                                   v167,
                                                                                   *(_QWORD *)(*(_QWORD *)a3 + 16i64)
                                                                                 + 1i64,
                                                                                   v137,
                                                                                   a4) )
                                                                            {
                                                                              if ( (unsigned int)sub_180092BA8(
                                                                                                   v137,
                                                                                                   v167,
                                                                                                   *(_QWORD *)(*(_QWORD *)a3 + 16i64),
                                                                                                   v138,
                                                                                                   a4) )
                                                                              {
                                                                                *(_DWORD *)(*(_QWORD *)a3 + 72i64) = 1;
                                                                                v139 = *(_QWORD *)a3;
                                                                                if ( *(_QWORD *)(*(_QWORD *)a3 + 16i64) == 2i64 )
                                                                                {
                                                                                  v140 = *(_QWORD *)(v139 + 32);
                                                                                  if ( !*(_QWORD *)(v140 + 8)
                                                                                    && *(_QWORD *)(v140 + 16) == 1i64 )
                                                                                  {
                                                                                    v141 = (*(__int64 (__fastcall **)(__int64, _QWORD, __int64, _QWORD *, __int64))(v102[8] + 88i64))(
                                                                                             v167,
                                                                                             *(_QWORD *)(v139 + 1800),
                                                                                             1i64,
                                                                                             v102,
                                                                                             a4);
                                                                                    if ( a3[3] )
                                                                                    {
                                                                                      if ( !v141 )
                                                                                        goto LABEL_223;
                                                                                      if ( !(unsigned int)sub_18008F7F4(v154, v152, a4) )
                                                                                        goto LABEL_223;
                                                                                      *(_DWORD *)(*(_QWORD *)a3 + 40i64) = 1;
                                                                                      if ( !(unsigned int)sub_180087CF0((_DWORD)v154, (_DWORD)v152, *(_QWORD *)(*(_QWORD *)a3 + 1800i64), (_DWORD)v102, *(_QWORD *)a3 + 256i64, v137, a4) )
                                                                                        goto LABEL_223;
                                                                                      *(_DWORD *)(*(_QWORD *)a3 + 44i64) = 1;
                                                                                      if ( !(unsigned int)sub_1800912BC(v154, v138, a4)
                                                                                        || !(unsigned int)sub_1800912BC(v152, v138, a4)
                                                                                        || !(unsigned int)sub_18008F7F4(v162, v168, a4) )
                                                                                      {
                                                                                        goto LABEL_223;
                                                                                      }
                                                                                      *(_DWORD *)(*(_QWORD *)a3 + 48i64) = 1;
                                                                                    }
                                                                                    else
                                                                                    {
                                                                                      *(_DWORD *)(*(_QWORD *)a3 + 48i64) = 0;
                                                                                      *(_DWORD *)(*(_QWORD *)a3 + 44i64) = 0;
                                                                                      *(_DWORD *)(*(_QWORD *)a3 + 40i64) = 0;
                                                                                      if ( !v141 )
                                                                                        goto LABEL_223;
                                                                                    }
                                                                                    if ( (unsigned int)sub_18008F7F4(v156, v160, a4) )
                                                                                    {
                                                                                      *(_DWORD *)(*(_QWORD *)a3 + 52i64) = 1;
                                                                                      if ( (unsigned int)sub_180087CF0((_DWORD)v156, (_DWORD)v160, *(_QWORD *)(*(_QWORD *)a3 + 1800i64), (_DWORD)v102, *(_QWORD *)a3 + 760i64, v137, a4) )
                                                                                      {
                                                                                        *(_DWORD *)(*(_QWORD *)a3 + 56i64) = 1;
                                                                                        if ( (unsigned int)sub_1800912BC(v156, v138, a4) )
                                                                                        {
                                                                                          if ( (unsigned int)sub_1800912BC(v160, v138, a4)
                                                                                            && (unsigned int)sub_18008F7F4(v164, v169, a4) )
                                                                                          {
                                                                                            *(_DWORD *)(*(_QWORD *)a3 + 60i64) = 1;
                                                                                            sub_180009288(v4);
                                                                                            return 1i64;
                                                                                          }
                                                                                        }
                                                                                      }
                                                                                    }
                                                                                  }
                                                                                }
                                                                              }
                                                                            }
                                                                          }
                                                                        }
                                                                      }
                                                                    }
                                                                  }
                                                                }
                                                              }
                                                            }
                                                          }
                                                        }
                                                      }
                                                    }
                                                  }
                                                }
                                              }
                                            }
                                          }
                                        }
                                      }
                                    }
                                  }
                                }
                              }
                            }
                          }
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  }
LABEL_223:
  if ( *((_QWORD *)a3 + 7) )
  {
    sub_180087BEC(*(_QWORD *)a3, a4);
    sub_180009288(*((_QWORD *)a3 + 7));
  }
  if ( v4 )
    sub_180009288(v4);
  return 0i64;
}

__int64 __fastcall sub_180085B30(__int64 a1, __int64 a2, __int64 a3, __int64 a4, __int64 a5)
{
  unsigned int v5; // ebx
  unsigned __int64 v6; // rax

  v5 = 0;
  if ( a2 )
    v6 = ((unsigned __int64)(a2 - 1) >> 3) + 1;
  else
    v6 = 0i64;
  if ( a4 != v6 )
    return 0i64;
  LOBYTE(v5) = (unsigned int)sub_180090B74(a1, a2, a3, 8 * a2, a5) != 0;
  return v5;
}

__int64 __fastcall sub_180090B74(__int64 a1, __int64 a2, void *a3, __int64 a4, __int64 a5)
{
  char v5; // r15
  unsigned __int64 v6; // rbx
  unsigned __int64 v7; // r12
  unsigned int v10; // esi
  _QWORD *v11; // r8
  __int64 v12; // r14
  unsigned __int64 v13; // r11
  __int64 v14; // r9
  __int64 v15; // r10
  unsigned __int64 v16; // rdx
  __int64 v17; // rcx
  __int64 v18; // rax
  __int64 v19; // rax

  v5 = a4;
  v6 = (unsigned __int64)(a4 + 63) >> 6;
  v7 = (unsigned __int64)(a4 + 7) >> 3;
  v10 = 1;
  if ( a4 )
  {
    if ( a3 && a1 )
    {
      memset(a3, 0, 8 * v6);
      if ( v6 )
      {
        v11 = a3;
        v12 = a1 - (_QWORD)a3;
        v13 = v6;
        while ( 1 )
        {
          v14 = 0i64;
          v15 = 0i64;
          v16 = v7 + (_BYTE *)a3 - (_BYTE *)v11;
          if ( v16 > 8 )
            break;
          if ( v16 )
            goto LABEL_9;
LABEL_11:
          *v11++ = v14;
          if ( !--v13 )
            goto LABEL_12;
        }
        v16 = 8i64;
LABEL_9:
        v17 = 0i64;
        do
        {
          v18 = *((unsigned __int8 *)v11 + v12 + v15++);
          v19 = v18 << v17;
          v17 += 8i64;
          v14 ^= v19;
        }
        while ( v15 != v16 );
        goto LABEL_11;
      }
LABEL_12:
      *((_QWORD *)a3 + v6 - 1) &= 0xFFFFFFFFFFFFFFFFui64 >> (((_BYTE)v6 << 6) - v5);
    }
    else
    {
      v10 = 0;
      sub_180009218(12i64, a2, a5);
    }
  }
  return v10;
}

_BOOL8 __fastcall sub_18008F5E8(char *Src, unsigned __int64 a2, char *a3, unsigned __int64 *a4, __int64 a5)
{
  unsigned __int64 v5; // rbp
  unsigned __int64 v8; // rdi
  char *v9; // r14
  char *v10; // rsi
  __int64 v11; // rdx
  BOOL v12; // ebx
  char *v13; // rax

  v5 = *a4;
  v8 = a2;
  v9 = Src;
  v10 = 0i64;
  if ( (int)sub_1800936DC(Src, a2, a4[7], *a4) < 0
    || ((v10 = (char *)sub_180092FD0(v5)) == 0i64 || !(unsigned int)sub_180094D6C(v9, (__int64)(a4 + 4), 0i64, v10, a5)
      ? (v12 = 0)
      : (v12 = 1),
        v9 = v10,
        v8 = v5,
        v12) )
  {
    if ( v8 )
    {
      v13 = &v9[8 * v8 - 8];
      do
      {
        if ( *(_QWORD *)v13 )
          break;
        v13 -= 8;
        --v8;
      }
      while ( v8 );
    }
    if ( v8 <= v5 )
    {
      memcpy(a3, v9, 8 * v8);
      memset(&a3[8 * v8], 0, 8 * (v5 - v8));
    }
    else
    {
      sub_180009218(6i64, v11, a5);
    }
    v12 = sub_18008F360(a3, a5) != 0;
  }
  if ( v10 )
    sub_180009288(v10);
  return v12;
}

LPVOID __fastcall sub_180092FD0(__int64 a1)
{
  SIZE_T v1; // rbx
  HANDLE ProcessHeap; // rax

  v1 = 8 * a1;
  ProcessHeap = GetProcessHeap();
  return HeapAlloc(ProcessHeap, 0, v1);
}

__int64 __fastcall sub_180094D6C(
        char *Src,
        unsigned __int64 a2,
        char *a3,
        unsigned __int64 a4,
        char *a5,
        char *a6,
        char *a7,
        __int64 a8)
{
  unsigned __int64 v10; // rbp
  __int64 v12; // rcx
  unsigned int v13; // ebx
  __int64 v14; // rbp
  __int64 v15; // rcx
  char *v16; // rdx
  char *v17; // r15
  char *v18; // rdx
  unsigned __int64 v19; // rbp
  __int64 v20; // rcx
  unsigned __int64 v21; // r10
  __int64 v22; // r9
  unsigned __int128 v23; // rax
  unsigned __int64 v24; // rbp
  __int64 v25; // rdx
  bool v26; // zf
  __int64 v27; // rax
  char *v29; // [rsp+40h] [rbp-88h]
  unsigned __int64 v30; // [rsp+48h] [rbp-80h]
  char *v31; // [rsp+50h] [rbp-78h]
  unsigned __int64 v32; // [rsp+58h] [rbp-70h]
  __int64 v33; // [rsp+60h] [rbp-68h]
  char v34[16]; // [rsp+68h] [rbp-60h] BYREF

  v10 = a2;
  v29 = a5;
  if ( !a4 )
  {
    v12 = 3i64;
LABEL_39:
    v13 = 0;
    sub_180009218(v12, a2, a8);
    return v13;
  }
  if ( !Src || !a3 || !a7 )
  {
    v12 = 12i64;
    goto LABEL_39;
  }
  if ( Src == a6 || Src == a7 || a3 == a6 || a3 == a7 )
  {
    v12 = 14i64;
    goto LABEL_39;
  }
  a2 = *(_QWORD *)&a3[8 * a4 - 8];
  if ( !a2 )
  {
    v12 = 6i64;
    goto LABEL_39;
  }
  if ( v10 >= a4 )
  {
    if ( a4 == 1 )
    {
      return (unsigned int)sub_180095084((_DWORD)Src, a2, (_DWORD)a5, (_DWORD)a6, v10, (__int64)a7, a8) != 0;
    }
    else
    {
      if ( !a5 )
      {
        sub_1800952DC(a3, a4, v34, a8);
        v29 = v34;
      }
      *(_QWORD *)&a7[8 * a4 - 8] = 0i64;
      v14 = v10 - a4;
      memcpy(a7, &Src[8 * v14 + 8], 8 * a4 - 8);
      v15 = v14 + 1;
      v13 = 1;
      v16 = &a6[8 * v14 + 8];
      v17 = (char *)(Src - a6);
      do
      {
        v18 = v16 - 8;
        v31 = v18;
        v33 = v15 - 1;
        if ( !v15 )
          break;
        v19 = *(_QWORD *)&a7[8 * a4 - 8];
        v30 = v19;
        v20 = a4 - 1;
        if ( a4 != 1 )
        {
          do
          {
            *(_QWORD *)&a7[8 * v20] = *(_QWORD *)&a7[8 * v20 - 8];
            --v20;
          }
          while ( v20 );
        }
        *(_QWORD *)a7 = *(_QWORD *)&v18[(_QWORD)v17];
        if ( v19 || (int)sub_180093764(a7, a3, a4) >= 0 )
        {
          v21 = (v19 << *((_QWORD *)v29 + 1)) | (*(_QWORD *)&a7[8 * a4 - 8] >> 1 >> (63 - v29[8]));
          v22 = (*(_QWORD *)&a7[8 * a4 - 8] << *((_QWORD *)v29 + 1)) | (*(_QWORD *)&a7[8 * a4 - 16] >> 1 >> (63 - v29[8]));
          v23 = v21 * (unsigned __int128)*(unsigned __int64 *)v29;
          v24 = (v22 + (__int64)v23 < (unsigned __int64)v22) + *((_QWORD *)&v23 + 1) + v21;
          if ( v22 < 0 )
            v24 += v22 + (__int64)v23 + (*(_QWORD *)v29 >> 1) < (unsigned __int64)(v22 + v23);
          v19 = (v24 != -1i64) + v24;
          v32 = sub_180090A6C(a3, v19, a7, a4);
          v26 = v32 == v30;
          if ( v32 > v30 )
          {
            --v19;
            if ( a4 << 6 == 256 )
              v27 = sub_1800022B0(a7, a3, a7);
            else
              v27 = sub_180002280(a7, a3, a7, a4);
            v26 = v32 - v27 == v30;
          }
          if ( !v26 )
          {
            v13 = 0;
            sub_180009218(5i64, v25, a8);
          }
        }
        v16 = v31;
        if ( a6 )
          *(_QWORD *)v31 = v19;
        v15 = v33;
      }
      while ( v13 );
    }
  }
  else
  {
    memcpy(a7, Src, 8 * v10);
    memset(&a7[8 * v10], 0, 8 * (a4 - v10));
    return 1;
  }
  return v13;
}

__int64 __fastcall sub_1800952DC(__int64 a1, unsigned __int64 a2, unsigned __int64 *a3, __int64 a4)
{
  unsigned __int64 v5; // rbx
  __int64 v7; // r8
  __int64 v8; // rbp
  __int64 v9; // r8
  __int64 v10; // r9
  unsigned __int64 v11; // r10
  unsigned __int64 v12; // rdi
  unsigned __int64 v13; // rdx
  unsigned __int64 v14; // rdi
  unsigned __int64 v15; // r9
  unsigned int v16; // edi
  unsigned __int64 v17; // r8
  unsigned __int64 v18; // rax
  unsigned __int64 v19; // r10
  unsigned __int64 v20; // rdx
  __int64 v21; // rcx
  unsigned __int64 v22; // rcx
  unsigned __int128 v23; // rax
  bool v24; // cc
  unsigned __int64 v25; // kr00_8
  __int64 v26; // rcx
  unsigned __int64 v28; // [rsp+30h] [rbp-58h] BYREF
  unsigned __int64 v29; // [rsp+38h] [rbp-50h] BYREF
  __int64 v30[9]; // [rsp+40h] [rbp-48h] BYREF

  v5 = a2;
  if ( !a1 || !a3 )
  {
    v26 = 12i64;
    goto LABEL_30;
  }
  if ( !a2 || (v7 = *(_QWORD *)(a1 + 8 * a2 - 8)) == 0 )
  {
    v26 = 6i64;
LABEL_30:
    v16 = 0;
    sub_180009218(v26, a2, a4);
    return v16;
  }
  v28 = 0i64;
  v29 = 0i64;
  v8 = 64 - sub_180091150(v7);
  if ( v5 < 2 )
  {
    v11 = 0i64;
  }
  else
  {
    v11 = *(_QWORD *)(a1 + 8 * v5 - 16);
    if ( v5 >= 3 )
    {
      v12 = *(_QWORD *)(a1 + 8 * v5 - 24);
      goto LABEL_10;
    }
  }
  v12 = 0i64;
LABEL_10:
  v13 = (v9 << v8) | (v11 >> 1 >> (63 - (unsigned __int8)v8));
  v14 = (v11 << v8) | (v12 >> 1 >> (63 - (unsigned __int8)v8));
  v30[0] = ~v13;
  v30[1] = ~v14;
  if ( (unsigned int)sub_180094CB8((unsigned int)v30, v13, (unsigned int)&v28, (unsigned int)&v29, v10) )
  {
    v15 = v28;
    if ( (v28 * (unsigned __int128)v14) >> 64 > v29 )
      v15 = v28 - 1;
    v16 = 1;
    v17 = (0xFFFFFFFFFFFFFFFFui64 >> v8) - *(_QWORD *)(a1 + 8 * v5 - 8);
    v18 = v17;
    v19 = v17;
    v20 = v17;
    while ( 1 )
    {
      --v5;
      if ( v18 >= v15 )
        break;
      if ( v5 )
      {
        v21 = *(_QWORD *)(8 * v5 + a1 - 8);
      }
      else
      {
        v21 = 0i64;
        v19 = v20;
      }
      v22 = ~v21;
      v23 = v15 * (unsigned __int128)*(unsigned __int64 *)(a1 + 8 * v5);
      if ( *((_QWORD *)&v23 + 1) == v19 )
        v24 = (unsigned __int64)v23 <= v22;
      else
        v24 = *((_QWORD *)&v23 + 1) <= v17;
      if ( !v24 )
      {
        --v15;
        break;
      }
      v25 = v22 - v23;
      *(_QWORD *)&v23 = (__PAIR128__(v17, v22) - (unsigned __int64)v23) >> 64;
      v17 = v25;
      v19 = v22 - v15 * *(_QWORD *)(a1 + 8 * v5);
      if ( (_QWORD)v23 == *((_QWORD *)&v23 + 1) )
      {
        v18 = v25;
        v20 = v25;
        if ( v5 )
          continue;
      }
      break;
    }
    a3[1] = v8;
    *a3 = v15;
  }
  else
  {
    return 0;
  }
  return v16;
}

__int64 __fastcall sub_180093764(__int64 a1, _QWORD *a2, __int64 a3)
{
  unsigned __int64 v3; // r10
  _QWORD *v4; // rbx
  unsigned __int64 v5; // r9
  __int64 v6; // r11
  __int64 v7; // rcx
  __int64 v8; // rdx
  unsigned __int64 v9; // r9

  v3 = 0i64;
  v4 = a2;
  v5 = 0i64;
  if ( a3 )
  {
    v6 = a1 - (_QWORD)a2;
    do
    {
      v7 = *(_QWORD *)((char *)v4 + v6);
      v8 = v7 ^ *v4;
      v3 = (v7 ^ (v8 | v7 ^ (v7 - *v4 - v3))) >> 63;
      v9 = *v4 ^ (v8 | *v4 ^ (*v4 - v7 - v5));
      ++v4;
      v5 = v9 >> 63;
      --a3;
    }
    while ( a3 );
  }
  return (unsigned int)(v5 - v3);
}

_BOOL8 __fastcall sub_1800022B0(_QWORD *a1, _QWORD *a2, _QWORD *a3)
{
  bool v3; // cf
  __int64 v4; // r10
  __int64 v5; // r10
  _BOOL8 v6; // rtt
  __int64 v7; // r11
  __int64 v8; // r11
  _BOOL8 v9; // rtt
  __int64 v10; // r9
  __int64 v11; // r9
  _BOOL8 v12; // rtt

  v3 = __CFADD__(*a1, *a2);
  v4 = a1[1];
  *a3 = *a1 + *a2;
  v6 = v3;
  v3 = __CFADD__(v3, v4);
  v5 = v6 + v4;
  v3 |= __CFADD__(a2[1], v5);
  v7 = a2[2];
  a3[1] = a2[1] + v5;
  v9 = v3;
  v3 = __CFADD__(v3, v7);
  v8 = v9 + v7;
  v3 |= __CFADD__(a1[2], v8);
  v10 = a1[3];
  a3[2] = a1[2] + v8;
  v12 = v3;
  v3 = __CFADD__(v3, v10);
  v11 = v12 + v10;
  v3 |= __CFADD__(a2[3], v11);
  a3[3] = a2[3] + v11;
  return v3;
}

_BOOL8 __fastcall sub_180002280(__int64 a1, __int64 a2, __int64 a3, int a4)
{
  bool v4; // cf
  __int64 v5; // rax
  __int64 v6; // r11
  __int64 v7; // r11
  _BOOL8 v8; // rtt

  v4 = 0;
  v5 = 0i64;
  do
  {
    v6 = *(_QWORD *)(a1 + v5);
    v8 = v4;
    v4 = __CFADD__(v4, v6);
    v7 = v8 + v6;
    v4 |= __CFADD__(*(_QWORD *)(a2 + v5), v7);
    --a4;
    *(_QWORD *)(a3 + v5) = *(_QWORD *)(a2 + v5) + v7;
    v5 = (unsigned int)(v5 + 8);
  }
  while ( a4 );
  return v4;
}

// Helpers

LPVOID __fastcall sub_180009254(SIZE_T a1)
{
  HANDLE ProcessHeap; // rax

  ProcessHeap = GetProcessHeap();
  return HeapAlloc(ProcessHeap, 0, a1);
}