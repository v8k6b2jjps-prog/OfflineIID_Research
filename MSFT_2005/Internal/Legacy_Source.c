__int64 __fastcall sub_18009CA30(__int64 a1, __int64 a2, unsigned int a3, __int64 a4, _DWORD *a5, _DWORD *a6)
{
  HANDLE ProcessHeap; // rax
  unsigned int *v9; // rdi
  __int64 v11; // rdx
  unsigned int v12; // r15d
  unsigned int v13; // r15d
  unsigned int v14; // r10d
  unsigned int v15; // r11d
  unsigned int v16; // esi
  unsigned int v17; // r14d
  int v18; // ebx
  unsigned int v19; // r8d
  unsigned int v20; // r11d
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
  __int64 v32; // rdx
  __int64 v33; // rcx
  unsigned __int64 v34; // rcx
  unsigned __int64 v35; // r9
  unsigned int v36; // r8d
  __int64 v37; // rax
  __int64 v38; // rdx
  __int64 v39; // rcx
  signed __int64 *v40; // rcx
  __int64 v41; // r12
  int v42; // eax
  __int64 v43; // rsi
  unsigned int v44; // r13d
  unsigned int v45; // r12d
  unsigned int *v46; // rsi
  __int64 v47; // rcx
  int v48; // r8d
  unsigned int v49; // r9d
  char v50; // cl
  int v51; // edx
  __int64 v52; // r9
  unsigned __int64 v53; // r8
  unsigned int *v54; // rdx
  __int64 v55; // rcx
  __int64 v56; // rax
  unsigned __int64 v57; // rdx
  unsigned __int64 v58; // r8
  __int64 v59; // rcx
  __int64 v60; // rax
  char *v61; // rcx
  unsigned int v62; // r9d
  void *v63; // rbx
  HANDLE v64; // rax
  HANDLE v65; // rax
  signed __int64 v66; // [rsp+60h] [rbp-29h] BYREF
  signed __int64 v67; // [rsp+68h] [rbp-21h] BYREF
  signed __int64 v68; // [rsp+70h] [rbp-19h] BYREF
  __int64 v69; // [rsp+78h] [rbp-11h]
  __int128 v70[2]; // [rsp+80h] [rbp-9h] BYREF

  ProcessHeap = GetProcessHeap();
  v9 = (unsigned int *)HeapAlloc(ProcessHeap, 8u, 0x9F0ui64);
  if ( !v9 )
    return 10i64;
  if ( !dword_1800AFDC4 )
    dword_1800AFDC4 = 1;
  memset(v70, 0, sizeof(v70));
  SetLastError(0);
  v12 = sub_18009D280(a1, v11, v9, v70);
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
  v68 = 0i64;
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
        v24 = &v68;
        if ( v21 )
        {
          _bittestandset64(&v68, v23);
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
      v9[v28 + 626] = *((_DWORD *)&v67 + 2 * v29);
    v30 = 0;
    if ( v29 )
    {
      v31 = 0i64;
      do
      {
        v32 = *(&v67 + v31);
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
      v40 = &v66;
      LOBYTE(v40) = 93;
      v12 = sub_18009DC10(v40, *((_QWORD *)v9 + 280), v9[562], v9 + 627, v9[4], v9 + 632, v9[1]);
      if ( v12 )
        goto LABEL_75;
      v25 = (int **)(v9 + 192);
      *((_QWORD *)v9 + 317) = v66;
      if ( (unsigned int)sub_180093DB4(
                           (int)v9 + 944,
                           (unsigned int)&v68,
                           1,
                           (int)v9 + 1472,
                           (__int64)(v9 + 192),
                           (__int64)v70)
        && (unsigned int)sub_180093DB4(
                           (int)v9 + 1200,
                           (int)v9 + 2536,
                           v12 + 1,
                           (int)v9 + 1728,
                           (__int64)(v9 + 192),
                           (__int64)v70)
        && (unsigned int)sub_18008FB54(
                           (int)v9 + 1472,
                           (int)v9 + 1728,
                           (int)v9 + 1472,
                           v12 + 1,
                           (__int64)(v9 + 192),
                           *((_QWORD *)v9 + 117),
                           (__int64)v70) )
      {
        v26 = (char *)(v9 + 496);
        v27 = sub_180093DB4((int)v9 + 1472, (unsigned int)&v68, 1, (int)v9 + 1984, (__int64)(v9 + 192), (__int64)v70);
        goto LABEL_43;
      }
      goto LABEL_74;
    }
    goto LABEL_37;
  }
  v25 = (int **)(v9 + 192);
  if ( !(unsigned int)sub_180093DB4(
                        (int)v9 + 944,
                        (unsigned int)&v68,
                        1,
                        (int)v9 + 1472,
                        (__int64)(v9 + 192),
                        (__int64)v70)
    || !(unsigned int)sub_180093DB4(
                        (int)v9 + 1200,
                        (unsigned int)&v67,
                        1,
                        (int)v9 + 1728,
                        (__int64)(v9 + 192),
                        (__int64)v70) )
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
          (__int64)v70);
LABEL_43:
  if ( !v27 )
    goto LABEL_74;
  v41 = v9[2];
  v42 = **v25;
  v69 = *((_QWORD *)*v25 + 11);
  LODWORD(v66) = v42;
  if ( (unsigned int)sub_180090650(v26, v25, v70) )
    goto LABEL_74;
  v43 = v69;
  if ( !(unsigned int)sub_18009D8E0(v26, v9 + 563, v69, (unsigned int)v41, v70)
    || !(unsigned int)sub_18009D8E0(&v26[8 * (unsigned int)v66], &v9[v41 + 563], v43, (unsigned int)v41, v70) )
  {
    goto LABEL_74;
  }
  *((_QWORD *)v9 + 280) = a2;
  v9[562] = a3;
  v44 = v9[3];
  v45 = v9[6];
  LODWORD(v66) = v9[4];
  if ( (unsigned int)v66 > 2 )
  {
LABEL_37:
    v12 = 8;
    goto LABEL_75;
  }
  v46 = v9 + 627;
  v47 = 0i64;
  if ( v9[7] != 19980206 )
    v47 = 121i64;
  v12 = sub_18009DC10(v47, a2, v9[562], v9 + 563, 2 * v9[2], 0i64, 0);
  if ( !v12 )
  {
    v48 = 0;
    v9[629] = 0;
    if ( v45 )
    {
      v49 = 0;
      do
      {
        v50 = v48;
        v51 = (v9[((unsigned __int64)(v48 + v44) >> 5) + 627] >> ((v48 + v44) & 0x1F)) & 1;
        ++v48;
        v49 |= v51 << v50;
        v9[629] = v49;
      }
      while ( v48 != v45 );
    }
    v52 = (unsigned int)v66;
    v53 = (unsigned __int64)(unsigned int)v66 >> 1;
    v9[(unsigned int)(v66 - 1) + 627] &= 0xFFFFFFFFFFFFFFFFui64 >> (32 * (unsigned __int8)v66 - (unsigned __int8)v44);
    if ( (v52 & 1) != 0 )
      *(_QWORD *)&v9[2 * v53 + 630] = v46[v52 - 1];
    if ( v53 )
    {
      v54 = v9 + 627;
      do
      {
        v55 = v54[1];
        v56 = *v54;
        v54 += 2;
        *(_QWORD *)(v54 + 1) = v56 | (v55 << 32);
        --v53;
      }
      while ( v53 );
    }
    v57 = v9[4];
    v58 = v57 >> 1;
    v9[(unsigned int)(v57 - 1) + 627] &= 0xFFFFFFFFFFFFFFFFui64 >> (32 * (unsigned __int8)v57 - *((_BYTE *)v9 + 12));
    if ( (v57 & 1) != 0 )
      *(_QWORD *)&v9[2 * v58 + 630] = v46[v57 - 1];
    for ( ; v58; --v58 )
    {
      v59 = v46[1];
      v60 = *v46;
      v46 += 2;
      *(_QWORD *)(v46 + 1) = v60 | (v59 << 32);
    }
    if ( v9[7] < 0x1317CC4 || (int)v9[16] < 1 )
    {
      v12 = 0;
      v9[632] = 0;
      goto LABEL_68;
    }
    v61 = (char *)(v9 + 632);
    LOBYTE(v61) = 45;
    v12 = sub_18009DC10(v61, *((_QWORD *)v9 + 280), v9[562], *((_QWORD *)v9 + 15), v9[17], v9 + 629, 1);
    if ( !v12 )
    {
LABEL_68:
      if ( !GetLastError() )
      {
        v62 = v9[3];
        if ( v62 )
        {
          while ( ((v9[((unsigned __int64)v17 >> 5) + 627] >> (v17 & 0x1F)) & 1) == _bittest64(&v67, v17) )
          {
            if ( ++v17 == v62 )
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
  v63 = (void *)*((_QWORD *)v9 + 117);
  if ( v63 )
  {
    v64 = GetProcessHeap();
    HeapFree(v64, 0, v63);
    if ( (unsigned int)sub_18008F774(v9 + 192, v70) )
      sub_18008E240(v9 + 86, v70);
  }
LABEL_78:
  v65 = GetProcessHeap();
  HeapFree(v65, 0, v9);
  if ( *((_QWORD *)&v70[0] + 1) )
    (*(void (__fastcall **)(__int128 *))(**((_QWORD **)&v70[0] + 1) + 32i64))(v70);
  if ( *(_QWORD *)&v70[0] )
    (*(void (__fastcall **)(__int128 *))(*(_QWORD *)(*(_QWORD *)&v70[0] + 24i64) + 24i64))(v70);
  return v12;
}

__int64 __fastcall sub_18009CA30(__int64 a1, __int64 a2, unsigned int a3, __int64 a4, _DWORD *a5, _DWORD *a6)
{
  HANDLE ProcessHeap; // rax
  unsigned int *v9; // rdi
  __int64 v11; // rdx
  unsigned int v12; // r15d
  unsigned int v13; // r15d
  unsigned int v14; // r10d
  unsigned int v15; // r11d
  unsigned int v16; // esi
  unsigned int v17; // r14d
  int v18; // ebx
  unsigned int v19; // r8d
  unsigned int v20; // r11d
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
  __int64 v32; // rdx
  __int64 v33; // rcx
  unsigned __int64 v34; // rcx
  unsigned __int64 v35; // r9
  unsigned int v36; // r8d
  __int64 v37; // rax
  __int64 v38; // rdx
  __int64 v39; // rcx
  signed __int64 *v40; // rcx
  __int64 v41; // r12
  int v42; // eax
  __int64 v43; // rsi
  unsigned int v44; // r13d
  unsigned int v45; // r12d
  unsigned int *v46; // rsi
  __int64 v47; // rcx
  int v48; // r8d
  unsigned int v49; // r9d
  char v50; // cl
  int v51; // edx
  __int64 v52; // r9
  unsigned __int64 v53; // r8
  unsigned int *v54; // rdx
  __int64 v55; // rcx
  __int64 v56; // rax
  unsigned __int64 v57; // rdx
  unsigned __int64 v58; // r8
  __int64 v59; // rcx
  __int64 v60; // rax
  char *v61; // rcx
  unsigned int v62; // r9d
  void *v63; // rbx
  HANDLE v64; // rax
  HANDLE v65; // rax
  signed __int64 v66; // [rsp+60h] [rbp-29h] BYREF
  signed __int64 v67; // [rsp+68h] [rbp-21h] BYREF
  signed __int64 v68; // [rsp+70h] [rbp-19h] BYREF
  __int64 v69; // [rsp+78h] [rbp-11h]
  __int128 v70[2]; // [rsp+80h] [rbp-9h] BYREF

  ProcessHeap = GetProcessHeap();
  v9 = (unsigned int *)HeapAlloc(ProcessHeap, 8u, 0x9F0ui64);
  if ( !v9 )
    return 10i64;
  if ( !dword_1800AFDC4 )
    dword_1800AFDC4 = 1;
  memset(v70, 0, sizeof(v70));
  SetLastError(0);
  v12 = sub_18009D280(a1, v11, v9, v70);
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
  v68 = 0i64;
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
        v24 = &v68;
        if ( v21 )
        {
          _bittestandset64(&v68, v23);
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
      v9[v28 + 626] = *((_DWORD *)&v67 + 2 * v29);
    v30 = 0;
    if ( v29 )
    {
      v31 = 0i64;
      do
      {
        v32 = *(&v67 + v31);
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
      v40 = &v66;
      LOBYTE(v40) = 93;
      v12 = sub_18009DC10(v40, *((_QWORD *)v9 + 280), v9[562], v9 + 627, v9[4], v9 + 632, v9[1]);
      if ( v12 )
        goto LABEL_75;
      v25 = (int **)(v9 + 192);
      *((_QWORD *)v9 + 317) = v66;
      if ( (unsigned int)sub_180093DB4(
                           (int)v9 + 944,
                           (unsigned int)&v68,
                           1,
                           (int)v9 + 1472,
                           (__int64)(v9 + 192),
                           (__int64)v70)
        && (unsigned int)sub_180093DB4(
                           (int)v9 + 1200,
                           (int)v9 + 2536,
                           v12 + 1,
                           (int)v9 + 1728,
                           (__int64)(v9 + 192),
                           (__int64)v70)
        && (unsigned int)sub_18008FB54(
                           (int)v9 + 1472,
                           (int)v9 + 1728,
                           (int)v9 + 1472,
                           v12 + 1,
                           (__int64)(v9 + 192),
                           *((_QWORD *)v9 + 117),
                           (__int64)v70) )
      {
        v26 = (char *)(v9 + 496);
        v27 = sub_180093DB4((int)v9 + 1472, (unsigned int)&v68, 1, (int)v9 + 1984, (__int64)(v9 + 192), (__int64)v70);
        goto LABEL_43;
      }
      goto LABEL_74;
    }
    goto LABEL_37;
  }
  v25 = (int **)(v9 + 192);
  if ( !(unsigned int)sub_180093DB4(
                        (int)v9 + 944,
                        (unsigned int)&v68,
                        1,
                        (int)v9 + 1472,
                        (__int64)(v9 + 192),
                        (__int64)v70)
    || !(unsigned int)sub_180093DB4(
                        (int)v9 + 1200,
                        (unsigned int)&v67,
                        1,
                        (int)v9 + 1728,
                        (__int64)(v9 + 192),
                        (__int64)v70) )
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
          (__int64)v70);
LABEL_43:
  if ( !v27 )
    goto LABEL_74;
  v41 = v9[2];
  v42 = **v25;
  v69 = *((_QWORD *)*v25 + 11);
  LODWORD(v66) = v42;
  if ( (unsigned int)sub_180090650(v26, v25, v70) )
    goto LABEL_74;
  v43 = v69;
  if ( !(unsigned int)sub_18009D8E0(v26, v9 + 563, v69, (unsigned int)v41, v70)
    || !(unsigned int)sub_18009D8E0(&v26[8 * (unsigned int)v66], &v9[v41 + 563], v43, (unsigned int)v41, v70) )
  {
    goto LABEL_74;
  }
  *((_QWORD *)v9 + 280) = a2;
  v9[562] = a3;
  v44 = v9[3];
  v45 = v9[6];
  LODWORD(v66) = v9[4];
  if ( (unsigned int)v66 > 2 )
  {
LABEL_37:
    v12 = 8;
    goto LABEL_75;
  }
  v46 = v9 + 627;
  v47 = 0i64;
  if ( v9[7] != 19980206 )
    v47 = 121i64;
  v12 = sub_18009DC10(v47, a2, v9[562], v9 + 563, 2 * v9[2], 0i64, 0);
  if ( !v12 )
  {
    v48 = 0;
    v9[629] = 0;
    if ( v45 )
    {
      v49 = 0;
      do
      {
        v50 = v48;
        v51 = (v9[((unsigned __int64)(v48 + v44) >> 5) + 627] >> ((v48 + v44) & 0x1F)) & 1;
        ++v48;
        v49 |= v51 << v50;
        v9[629] = v49;
      }
      while ( v48 != v45 );
    }
    v52 = (unsigned int)v66;
    v53 = (unsigned __int64)(unsigned int)v66 >> 1;
    v9[(unsigned int)(v66 - 1) + 627] &= 0xFFFFFFFFFFFFFFFFui64 >> (32 * (unsigned __int8)v66 - (unsigned __int8)v44);
    if ( (v52 & 1) != 0 )
      *(_QWORD *)&v9[2 * v53 + 630] = v46[v52 - 1];
    if ( v53 )
    {
      v54 = v9 + 627;
      do
      {
        v55 = v54[1];
        v56 = *v54;
        v54 += 2;
        *(_QWORD *)(v54 + 1) = v56 | (v55 << 32);
        --v53;
      }
      while ( v53 );
    }
    v57 = v9[4];
    v58 = v57 >> 1;
    v9[(unsigned int)(v57 - 1) + 627] &= 0xFFFFFFFFFFFFFFFFui64 >> (32 * (unsigned __int8)v57 - *((_BYTE *)v9 + 12));
    if ( (v57 & 1) != 0 )
      *(_QWORD *)&v9[2 * v58 + 630] = v46[v57 - 1];
    for ( ; v58; --v58 )
    {
      v59 = v46[1];
      v60 = *v46;
      v46 += 2;
      *(_QWORD *)(v46 + 1) = v60 | (v59 << 32);
    }
    if ( v9[7] < 0x1317CC4 || (int)v9[16] < 1 )
    {
      v12 = 0;
      v9[632] = 0;
      goto LABEL_68;
    }
    v61 = (char *)(v9 + 632);
    LOBYTE(v61) = 45;
    v12 = sub_18009DC10(v61, *((_QWORD *)v9 + 280), v9[562], *((_QWORD *)v9 + 15), v9[17], v9 + 629, 1);
    if ( !v12 )
    {
LABEL_68:
      if ( !GetLastError() )
      {
        v62 = v9[3];
        if ( v62 )
        {
          while ( ((v9[((unsigned __int64)v17 >> 5) + 627] >> (v17 & 0x1F)) & 1) == _bittest64(&v67, v17) )
          {
            if ( ++v17 == v62 )
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
  v63 = (void *)*((_QWORD *)v9 + 117);
  if ( v63 )
  {
    v64 = GetProcessHeap();
    HeapFree(v64, 0, v63);
    if ( (unsigned int)sub_18008F774(v9 + 192, v70) )
      sub_18008E240(v9 + 86, v70);
  }
LABEL_78:
  v65 = GetProcessHeap();
  HeapFree(v65, 0, v9);
  if ( *((_QWORD *)&v70[0] + 1) )
    (*(void (__fastcall **)(__int128 *))(**((_QWORD **)&v70[0] + 1) + 32i64))(v70);
  if ( *(_QWORD *)&v70[0] )
    (*(void (__fastcall **)(__int128 *))(*(_QWORD *)(*(_QWORD *)&v70[0] + 24i64) + 24i64))(v70);
  return v12;
}

__int64 __fastcall sub_180093DB4(void *Src, const signed __int64 *a2, __int64 a3, void *a4, __int64 **a5, __int64 a6)
{
  __int64 **v6; // r13
  char *v10; // rbp
  __int64 v11; // r9
  __int64 v12; // r10
  unsigned int *v13; // rcx
  signed __int64 *v14; // r14
  unsigned __int64 v15; // rsi
  unsigned __int64 v16; // r12
  __int64 *v17; // rax
  unsigned __int64 v19; // rdi
  signed __int64 *v20; // rax
  BOOL v21; // ebx
  unsigned __int64 v22; // r12
  unsigned __int64 v23; // rsi
  signed __int64 *v24; // r10
  int v25; // eax
  char v26; // cl
  int v27; // r8d
  unsigned __int64 v28; // rdx
  int v29; // r12d
  int v30; // edi
  int v31; // esi
  int v32; // eax
  unsigned __int64 v33; // r9
  int v34; // r11d
  __int64 v35; // r9
  unsigned __int64 v36; // rcx
  unsigned __int64 v37; // rdx
  int v38; // eax
  int v39; // ecx
  int v40; // edx
  int v41; // ecx
  int v42; // eax
  int v43; // eax
  unsigned __int64 v44; // rdx
  unsigned __int64 v45; // rcx
  unsigned __int64 v46; // rax
  int v47; // r9d
  unsigned __int64 v48; // rcx
  __int64 v49; // rsi
  __int64 v50; // rax
  unsigned __int64 v51; // rdx
  int v52; // eax
  const signed __int64 *v53; // [rsp+40h] [rbp-C8h]
  __int64 v54; // [rsp+48h] [rbp-C0h]
  __int64 v55; // [rsp+50h] [rbp-B8h]
  __int64 v56; // [rsp+58h] [rbp-B0h]
  unsigned __int64 v57; // [rsp+60h] [rbp-A8h]
  __int64 v58; // [rsp+68h] [rbp-A0h]
  unsigned __int64 v59; // [rsp+68h] [rbp-A0h]
  unsigned __int64 v60; // [rsp+70h] [rbp-98h]
  __int64 v61; // [rsp+78h] [rbp-90h]
  int v62; // [rsp+78h] [rbp-90h]
  char v63; // [rsp+80h] [rbp-88h]
  signed __int64 *v64; // [rsp+80h] [rbp-88h]
  __int64 v65; // [rsp+88h] [rbp-80h]
  unsigned __int64 v66; // [rsp+90h] [rbp-78h]
  signed __int64 *v67; // [rsp+98h] [rbp-70h]
  __int64 v68; // [rsp+98h] [rbp-70h]
  signed __int64 *v69; // [rsp+A8h] [rbp-60h]
  signed __int64 *v70; // [rsp+C0h] [rbp-48h]
  char *v71; // [rsp+C8h] [rbp-40h]
  __int64 v74; // [rsp+130h] [rbp+28h]

  v6 = a5;
  v55 = **a5;
  v10 = 0i64;
  v57 = sub_180090F98(a2, a3);
  v13 = (unsigned int *)&unk_1800AA200;
  v53 = 0i64;
  LODWORD(v14) = 0;
  v15 = 2i64;
  v16 = 4i64;
  v65 = 4i64;
  do
  {
    if ( v57 <= *v13 )
      break;
    ++v15;
    ++v13;
  }
  while ( v15 < 7 );
  v17 = a5[6];
  v60 = v15;
  if ( v17 )
    return ((__int64 (__fastcall *)(void *, const signed __int64 *, __int64, void *, __int64 **, __int64))v17)(
             Src,
             a2,
             v12,
             a4,
             a5,
             a6);
  v19 = (1i64 << ((unsigned __int8)v15 - 1)) - 1;
  v66 = v19;
  v56 = v11 * (v19 + 3);
  v71 = (char *)a5[9] + v56 + v12;
  v20 = (signed __int64 *)sub_180092FD0();
  v70 = v20;
  if ( !v20 )
  {
    v21 = 0;
    v22 = 0i64;
    v23 = 0i64;
    goto LABEL_118;
  }
  memset(v20, 0, 8i64 * (_QWORD)v71);
  v53 = v70;
  v14 = &v70[a3];
  v10 = (char *)&v14[v56];
  memcpy(v14, Src, 16 * **a5);
  if ( v15 == 2 )
  {
    memcpy(a4, Src, 16 * **a5);
    v24 = v70;
    v22 = 0i64;
    v21 = 1;
    v54 = 1i64;
    v23 = 0i64;
  }
  else
  {
    v54 = 3i64;
    v58 = 16 * v55;
    v25 = sub_18009AD44((_DWORD)Src, (_DWORD)Src, (int)v14 + 16 * (int)v55, 1, (__int64)a5, (__int64)v10, a6);
    if ( v15 == 3 )
    {
      if ( v25 )
      {
        memcpy(a4, &v14[(unsigned __int64)v58 / 8], 16 * **a5);
        v21 = 1;
      }
      else
      {
        v21 = 0;
      }
      v24 = v70;
    }
    else
    {
      v21 = v25
         && (unsigned int)sub_18008FB54(
                            (int)v14 + (int)v58,
                            (int)v14 + (int)v58,
                            (_DWORD)a4,
                            1,
                            (__int64)a5,
                            (__int64)v10,
                            a6);
      if ( v15 >= 4 )
      {
        do
        {
          v26 = v16 - 3;
          v27 = 2 * v54;
          v63 = v16 - 3;
          v54 *= 2i64;
          v28 = 1i64;
          v61 = 1i64;
          if ( !(1ui64 >> ((unsigned __int8)v16 - 3)) )
          {
            v29 = v55 * v27;
            v30 = (_DWORD)v14 + 8 * v55 * (v27 - 2);
            v31 = (int)v14;
            do
            {
              v21 = v21
                 && (v32 = sub_1800900C8((int)a4, v31, v31 + 8 * v29, v30, (__int64)a5, v10, a6),
                     v28 = v61,
                     v26 = v63,
                     v32);
              v31 += v58;
              v28 += 2i64;
              v30 -= v58;
              v61 = v28;
            }
            while ( !(v28 >> v26) );
            v14 = &v70[a3];
            v15 = v60;
            v16 = v65;
          }
          if ( v16 != v15 )
            v21 = v21
               && (unsigned int)sub_18008FB54((_DWORD)a4, (_DWORD)a4, (_DWORD)a4, 1, (__int64)a5, (__int64)v10, a6);
          v65 = ++v16;
        }
        while ( v16 <= v15 );
        v19 = v66;
      }
      v24 = v70;
    }
    v22 = 0i64;
    v23 = 0i64;
    if ( !v21 )
      goto LABEL_44;
  }
  v33 = 0i64;
  if ( v57 )
  {
    do
    {
      v23 += (unsigned __int64)_bittest64(a2, v33) << ((unsigned __int8)v33 - (unsigned __int8)v22);
      if ( v33 >= v22 + v60 + 1 )
      {
        if ( (v23 & 1) != 0 )
        {
          v23 += v19 - ((2 * v19) & (v23 + v19));
          _bittestandset64(v24, v22);
        }
        v23 >>= 1;
        ++v22;
      }
      ++v33;
    }
    while ( v33 != v57 );
    v6 = a5;
    v34 = 1;
    goto LABEL_45;
  }
LABEL_44:
  v34 = 1;
  if ( v21 )
  {
LABEL_45:
    v35 = v54;
    while ( 1 )
    {
      do
      {
        v64 = v24;
        v69 = v24;
        v67 = v24;
        if ( !v34 )
          goto LABEL_118;
        v36 = v23 - v35;
        v62 = (v23 - v35) & 1;
        v37 = v23 / 3;
        v59 = v23 % 3;
        v34 = 0;
        if ( !v23 )
        {
          v38 = sub_180090984(a4, v6, a6);
          goto LABEL_49;
        }
        if ( (v23 & 1) != 0 && v23 <= v19 )
        {
          memcpy(a4, &v14[v55 * (v23 - 1)], 16 * **v6);
LABEL_50:
          v24 = (signed __int64 *)v53;
          v35 = v54;
          goto LABEL_51;
        }
      }
      while ( v23 == v35 );
      if ( (v23 & 1) == 0 && v23 <= 2 * v19 )
      {
        v39 = v23 - 1;
        if ( v23 - 1 > v19 )
          v39 = v19;
        v40 = (_DWORD)v14 + 8 * v55 * (v23 - v39 - 1);
        v41 = (_DWORD)v14 + 8 * v55 * (v39 - 1);
LABEL_61:
        v38 = sub_18008FB54(v41, v40, (_DWORD)a4, 1, (__int64)v6, (__int64)v10, a6);
LABEL_49:
        if ( !v38 )
          goto LABEL_101;
        goto LABEL_50;
      }
      if ( v62 && v23 <= v35 + v19 )
      {
        v42 = v36 - 1;
        v41 = (int)a4;
        v40 = (_DWORD)v14 + 8 * v55 * v42;
        goto LABEL_61;
      }
      if ( (v23 & 1) != 0 && v23 <= 3 * v19 )
      {
        v19 = v66;
        if ( !(unsigned int)sub_18009AD44(
                              (unsigned int)v14 + 8 * v55 * ((((v23 - v66) | 2) >> 1) - 1),
                              (unsigned int)v14 + 8 * v55 * (v23 - 2 * (((v23 - v66) | 2) >> 1) - 1),
                              (_DWORD)a4,
                              1,
                              (__int64)v6,
                              (__int64)v10,
                              a6) )
          goto LABEL_100;
        goto LABEL_50;
      }
      if ( (v36 & 3) == 2 && v36 <= 2 * v19 )
      {
        v38 = sub_18009AD44(
                (unsigned int)v14 + 8 * v55 * ((v36 >> 1) - 1),
                (_DWORD)a4,
                (_DWORD)a4,
                1,
                (__int64)v6,
                (__int64)v10,
                a6);
        goto LABEL_49;
      }
      if ( (v23 & 1) == 0 && v23 <= 2 * (v35 + v19) )
      {
        v34 = 1;
        goto LABEL_99;
      }
      if ( (v23 & 3) == 0 && v23 <= 4 * v19 )
        goto LABEL_97;
      if ( (v23 & 1) != 0 )
      {
        if ( !v59 )
          goto LABEL_87;
LABEL_93:
        if ( v23 <= 5 * v19 )
        {
          if ( !(unsigned int)sub_18008FB54(
                                (int)v14 + 8 * (int)v55 * ((int)v19 - 1),
                                (unsigned int)v14 + 8 * v55 * (2 * ((v23 - v19 + 2) >> 2) - v19 - 1),
                                (_DWORD)a4,
                                1,
                                (__int64)v6,
                                (__int64)v10,
                                a6) )
            goto LABEL_101;
          v53 = v67;
          if ( !(unsigned int)sub_18009AD44(
                                (_DWORD)a4,
                                (unsigned int)v14 + 8 * v55 * (v23 - 4 * ((v23 - v19 + 2) >> 2) - 1),
                                (_DWORD)a4,
                                1,
                                (__int64)v6,
                                (__int64)v10,
                                a6) )
            goto LABEL_101;
          v24 = v67;
          goto LABEL_85;
        }
LABEL_97:
        v34 = 1;
        if ( (v23 & 1) != 0 )
        {
          v23 += v19 - ((2 * v19) & (v23 + v19));
          _bittestandset64(v24, v22);
        }
LABEL_99:
        ++v22;
        v23 >>= 1;
      }
      else
      {
        if ( v59 )
          goto LABEL_97;
        if ( v37 <= 2 * v19 )
        {
          v43 = v37 - 1;
          if ( v37 - 1 > v19 )
            v43 = v19;
          if ( !(unsigned int)sub_18008FB54(
                                (int)v14 + 8 * (int)v55 * (v43 - 1),
                                (int)v14 + 8 * (int)v55 * ((int)v37 - v43 - 1),
                                (_DWORD)a4,
                                1,
                                (__int64)v6,
                                (__int64)v10,
                                a6)
            || (v53 = v64,
                !(unsigned int)sub_18009AD44((_DWORD)a4, (_DWORD)a4, (_DWORD)a4, 1, (__int64)v6, (__int64)v10, a6)) )
          {
LABEL_101:
            v21 = 0;
            break;
          }
          v24 = v64;
          goto LABEL_85;
        }
LABEL_87:
        if ( !v62 || (v44 = v37 - v35, v44 > v19) )
        {
          if ( (v23 & 1) == 0 )
            goto LABEL_97;
          goto LABEL_93;
        }
        if ( !(unsigned int)sub_18008FB54(
                              (int)v14 + 8 * (int)v55 * ((int)v44 - 1),
                              (_DWORD)a4,
                              (_DWORD)a4,
                              1,
                              (__int64)v6,
                              (__int64)v10,
                              a6)
          || (v53 = v69,
              !(unsigned int)sub_18009AD44((_DWORD)a4, (_DWORD)a4, (_DWORD)a4, 1, (__int64)v6, (__int64)v10, a6)) )
        {
LABEL_100:
          v21 = 0;
          break;
        }
        v24 = v69;
LABEL_85:
        v35 = v54;
        v53 = v24;
LABEL_51:
        v34 = 0;
        v21 = 1;
      }
    }
  }
LABEL_118:
  while ( v57 )
  {
    v45 = --v57;
    if ( !v21 )
      break;
    v68 = _bittest64(v53, v45);
    v74 = _bittest64(a2, v57);
    v46 = v68 + v57;
    while ( v22 > v46 )
    {
      v21 = sub_18008FB54((_DWORD)a4, (_DWORD)a4, (_DWORD)a4, 1, (__int64)v6, (__int64)v10, a6) != 0;
      v46 = v68 + v57;
      --v22;
      v23 *= 2i64;
      if ( !v21 )
        goto LABEL_118;
    }
    if ( v68 )
    {
      v47 = -1;
      v48 = v22 - v57;
      v49 = (v23 << ((unsigned __int8)v22 - (unsigned __int8)v57)) - v74;
      if ( v49 <= 0 )
        v47 = 1;
      v50 = -v49 | 1;
      v51 = v50 * v47;
      v23 = v50 + v49;
      if ( v48 > 1 || v51 > v19 )
      {
        v21 = 0;
        sub_180009218(5i64, v51, a6);
      }
      else
      {
        v22 = v57;
        if ( v48 )
          v52 = sub_18009AD44(
                  (_DWORD)a4,
                  (int)v14 + 8 * (int)v55 * ((int)v51 - 1),
                  (_DWORD)a4,
                  v47,
                  (__int64)v6,
                  (__int64)v10,
                  a6);
        else
          v52 = sub_18008FB54(
                  (_DWORD)a4,
                  (int)v14 + 8 * (int)v55 * ((int)v51 - 1),
                  (_DWORD)a4,
                  v47,
                  (__int64)v6,
                  (__int64)v10,
                  a6);
        v21 = v52 != 0;
      }
    }
    else
    {
      v23 -= v74 << ((unsigned __int8)v57 - (unsigned __int8)v22);
    }
  }
  if ( v70 )
  {
    memset(v70, 0, 8i64 * (_QWORD)v71);
    sub_180009288(v70);
  }
  return v21;
}

_BOOL8 __fastcall sub_18008FB54(char *a1, char *a2, char *a3, int a4, int **a5, __int64 a6, __int64 a7)
{
  int v8; // ebp
  int *v11; // rdi
  __int64 v12; // r10
  __int64 v13; // rcx
  char *v14; // r14
  char *v15; // r12
  char *v17; // rdx
  BOOL v18; // ebx
  char *v19; // r13
  int v20; // eax
  __int64 v21; // r10
  int v22; // r9d
  __int64 v23; // rbx
  char *v24; // rbp
  int v25; // r9d
  int v26; // r9d
  char *v28; // [rsp+40h] [rbp-58h]
  char *v29; // [rsp+48h] [rbp-50h]
  char *v30; // [rsp+50h] [rbp-48h]
  __int64 v34; // [rsp+C0h] [rbp+28h]

  v8 = 0;
  v11 = *a5;
  v12 = *(_QWORD *)*a5;
  v28 = &a1[8 * v12];
  v29 = &a2[8 * v12];
  v30 = &a3[8 * v12];
  if ( !a6 )
  {
    v13 = 12i64;
LABEL_43:
    v18 = 0;
    sub_180009218(v13, a2, a7);
    return v18;
  }
  if ( v11[10] < 1 || ((a4 + 1) & 0xFFFFFFFD) != 0 )
  {
    v13 = 6i64;
    goto LABEL_43;
  }
  v14 = (char *)(a6 + 8 * v12);
  v15 = &v14[8 * v12];
  v34 = (__int64)&v15[8 * v12];
  if ( (unsigned int)sub_180090650(a2, a5, a7) )
  {
    v17 = a1;
LABEL_7:
    memcpy(a3, v17, 16i64 * *(_QWORD *)*a5);
    return 1;
  }
  if ( (unsigned int)sub_180090650(a1, a5, a7) )
  {
    if ( a4 != 1 )
      return sub_1800906FC(a2, a3) != 0;
    v17 = a2;
    goto LABEL_7;
  }
  if ( a4 == -1 )
  {
    memcpy(v14, v29, 8i64 * *(_QWORD *)v11);
  }
  else if ( !(*(unsigned int (__fastcall **)(char *, char *, __int64, int *, __int64))(*((_QWORD *)v11 + 8) + 88i64))(
               v29,
               v14,
               1i64,
               v11,
               a7) )
  {
    return 0;
  }
  v19 = a1;
  v20 = (*(__int64 (__fastcall **)(char *, char *, __int64, int *, __int64))(*((_QWORD *)v11 + 8) + 8i64))(
          a1,
          a2,
          1i64,
          v11,
          a7);
  v21 = *((_QWORD *)v11 + 8);
  if ( !v20 )
  {
    if ( !(*(unsigned int (__fastcall **)(char *, char *, char *, __int64, int *, __int64))v21)(
            v28,
            v14,
            v15,
            1i64,
            v11,
            a7) )
      return 0;
    v24 = a2;
    if ( !(*(unsigned int (__fastcall **)(char *, char *, char *, __int64, int *, __int64))(*((_QWORD *)v11 + 8) + 128i64))(
            a1,
            a2,
            v14,
            1i64,
            v11,
            a7) )
      return 0;
    v23 = v34;
    if ( !(unsigned int)sub_180093A14((_DWORD)v14, a6, (_DWORD)v11, v34, a7)
      || !(unsigned int)sub_18008E440((_DWORD)v15, a6, a6, v25, (__int64)v11, v34, a7) )
    {
      return 0;
    }
    goto LABEL_34;
  }
  if ( (*(unsigned int (__fastcall **)(char *, char *, __int64, int *, __int64))(v21 + 8))(v28, v14, 1i64, v11, a7) )
  {
    v8 = 1;
    v18 = sub_180090984(a3, a5, a7) != 0;
  }
  else
  {
    v18 = (**((unsigned int (__fastcall ***)(char *, char *, char *, __int64, int *, __int64))v11 + 8))(
            v28,
            v28,
            v14,
            1i64,
            v11,
            a7)
       && (unsigned int)sub_18008E440((_DWORD)a1, (_DWORD)a1, a6, v22, (__int64)v11, v34, a7)
       && (**((unsigned int (__fastcall ***)(__int64, int *, char *, __int64, int *, __int64))v11 + 8))(
            a6,
            a5[1],
            v15,
            1i64,
            v11,
            a7)
       && (**((unsigned int (__fastcall ***)(__int64, char *, char *, __int64, int *, __int64))v11 + 8))(
            a6,
            v15,
            v15,
            1i64,
            v11,
            a7)
       && (**((unsigned int (__fastcall ***)(__int64, char *, char *, __int64, int *, __int64))v11 + 8))(
            a6,
            v15,
            v15,
            1i64,
            v11,
            a7)
       && (unsigned int)sub_180093A14((_DWORD)v14, a6, (_DWORD)v11, v34, a7)
       && (unsigned int)sub_18008E440((_DWORD)v15, a6, a6, v22, (__int64)v11, v34, a7);
  }
  if ( !v8 && v18 )
  {
    v19 = a1;
    v23 = v34;
    v24 = a2;
LABEL_34:
    if ( (unsigned int)sub_18008E440(a6, a6, (_DWORD)v14, v22, (__int64)v11, v23, a7) )
    {
      if ( (*(unsigned int (__fastcall **)(char *, char *, char *, __int64, int *, __int64))(*((_QWORD *)v11 + 8)
                                                                                           + 128i64))(
             v14,
             v19,
             v14,
             1i64,
             v11,
             a7) )
      {
        if ( (*(unsigned int (__fastcall **)(char *, char *, char *, __int64, int *, __int64))(*((_QWORD *)v11 + 8)
                                                                                             + 128i64))(
               v14,
               v24,
               v14,
               1i64,
               v11,
               a7) )
        {
          if ( (*(unsigned int (__fastcall **)(char *, char *, char *, __int64, int *, __int64))(*((_QWORD *)v11 + 8)
                                                                                               + 128i64))(
                 v19,
                 v14,
                 v15,
                 1i64,
                 v11,
                 a7) )
          {
            memcpy(a3, v14, 8i64 * *(_QWORD *)v11);
            if ( (unsigned int)sub_18008E440(a6, (_DWORD)v15, (_DWORD)v14, v26, (__int64)v11, v23, a7) )
            {
              if ( (*(unsigned int (__fastcall **)(char *, char *, char *, __int64, int *, __int64))(*((_QWORD *)v11 + 8) + 128i64))(
                     v14,
                     v28,
                     v30,
                     1i64,
                     v11,
                     a7) )
              {
                return 1;
              }
            }
          }
        }
      }
    }
    return 0;
  }
  return v18;
}

__int64 __fastcall sub_18009D280(__int64 a1, __int64 a2, __int64 a3, __int64 a4)
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
      if ( (unsigned int)sub_180093DB4(
                           (void *)(a3 + 944),
                           (const signed __int64 *)(a3 + 1464),
                           (unsigned int)v23,
                           v10 + 128,
                           (__int64 **)(a3 + 768),
                           a4)
        && (unsigned int)sub_180093DB4(
                           (void *)(a3 + 944),
                           (const signed __int64 *)(a3 + 1456),
                           (unsigned int)v23,
                           v10 + 384,
                           (__int64 **)(a3 + 768),
                           a4) )
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

_BOOL8 __fastcall sub_18009AD44(char *a1, char *a2, char *a3, int a4, __int64 *a5, __int64 a6, __int64 a7)
{
  __int64 v7; // rsi
  __int64 v9; // rbp
  char *v10; // r15
  __int64 v11; // r13
  char *v12; // r14
  _QWORD *v13; // rdi
  __int64 v14; // rcx
  __int64 v15; // rdx
  char *v16; // rdx
  size_t v17; // r8
  int v18; // eax
  __int64 v21; // rdx
  BOOL v22; // ecx
  int v23; // r9d
  int v24; // r9d
  bool v25; // zf
  __int64 v26; // rdx
  int v27; // r9d
  int v28; // eax
  __int64 v29; // r9
  __int64 v30; // r10
  char *v31; // r8
  __int64 v32; // rdx
  int v33; // r9d
  __int64 v34; // rdx
  _QWORD *v35; // rcx
  int v36; // r9d
  int v37; // r9d
  int v38; // r9d
  char *v39; // r10
  __int64 v40; // r9
  char *v41; // r12
  __int64 v42; // r8
  __int64 v43; // rdx
  __int64 v44; // rcx
  int v45; // r9d
  int v46; // r9d
  int v47; // r9d
  char *v48; // [rsp+40h] [rbp-98h]
  int v49; // [rsp+48h] [rbp-90h]
  char *v50; // [rsp+48h] [rbp-90h]
  char *v51; // [rsp+50h] [rbp-88h]
  int v52; // [rsp+58h] [rbp-80h]
  char *v53; // [rsp+60h] [rbp-78h]
  __int64 v54; // [rsp+68h] [rbp-70h]
  __int64 v55; // [rsp+70h] [rbp-68h]
  char *v56; // [rsp+78h] [rbp-60h]
  int v57; // [rsp+80h] [rbp-58h]
  __int64 v58; // [rsp+88h] [rbp-50h]
  BOOL Srca; // [rsp+E8h] [rbp+10h]
  int v64; // [rsp+108h] [rbp+30h]

  v7 = a7;
  v9 = 0i64;
  v10 = 0i64;
  v51 = 0i64;
  v11 = 0i64;
  v12 = 0i64;
  v57 = 0;
  v13 = (_QWORD *)*a5;
  v49 = 1;
  v58 = *a5;
  v55 = 0i64;
  v14 = *(_QWORD *)*a5;
  v52 = *(_DWORD *)(*a5 + 40);
  v54 = v14;
  v53 = &a2[8 * v14];
  v48 = &a1[8 * v14];
  v56 = &a3[8 * v14];
  if ( a6 )
  {
    v10 = (char *)(a6 + 8 * v14);
    v9 = a6;
    v12 = &v10[8 * v14];
    v57 = a6 + 8 * v14;
    v11 = (__int64)&v12[8 * v14 + 8 * v14];
    v51 = &v12[8 * v14];
    v55 = v11;
  }
  else
  {
    v49 = 0;
    sub_180009218(12i64, &a1[8 * v14], a7);
  }
  if ( (unsigned int)sub_180090650(a1, a5, a7) )
  {
    if ( !v49 )
      return 0;
    if ( a4 == 1 )
    {
      v16 = a2;
      v17 = 16i64 * *(_QWORD *)*a5;
LABEL_99:
      memcpy(a3, v16, v17);
      return 1;
    }
    if ( a4 != -1 )
    {
      sub_180009218(6i64, v15, a7);
      return 0;
    }
    v18 = sub_1800906FC(a2, a3);
    return v18 != 0;
  }
  if ( (unsigned int)sub_180090650(a2, a5, a7) )
  {
    if ( !v49 )
      return 0;
    v18 = sub_18008FB54(a1, a1, a3, 1, (int **)a5, a6, a7);
    return v18 != 0;
  }
  v22 = v49
     && (*(unsigned int (__fastcall **)(char *, char *, char *, __int64, _QWORD *, __int64))(v13[8] + 128i64))(
          a1,
          a2,
          v12,
          1i64,
          v13,
          a7)
     && (*(unsigned int (__fastcall **)(char *, char *, __int64, _QWORD *, __int64))(v13[8] + 88i64))(
          v53,
          v10,
          1i64,
          v13,
          a7);
  if ( a4 == 1 )
  {
    v50 = v53;
    v53 = v10;
  }
  else
  {
    if ( a4 != -1 )
    {
      sub_180009218(6i64, v21, a7);
      v53 = 0i64;
      v50 = 0i64;
      goto LABEL_31;
    }
    v50 = v10;
  }
  if ( v22
    && (*(unsigned int (__fastcall **)(char *, char *, char *, __int64, _QWORD *, __int64))(v13[8] + 128i64))(
         a1,
         a2,
         v12,
         1i64,
         v13,
         a7) )
  {
    v64 = 1;
    goto LABEL_32;
  }
LABEL_31:
  v64 = 0;
LABEL_32:
  if ( (*(unsigned int (__fastcall **)(char *, __int64, _QWORD *, __int64))(v13[8] + 48i64))(v12, 1i64, v13, a7) )
  {
    if ( (*(unsigned int (__fastcall **)(char *, char *, __int64, _QWORD *, __int64))(v13[8] + 8i64))(
           v48,
           v53,
           1i64,
           v13,
           a7) )
    {
      if ( v64 )
      {
        v16 = a1;
        v17 = 16i64 * *(_QWORD *)*a5;
        goto LABEL_99;
      }
      return 0;
    }
    if ( !(*(unsigned int (__fastcall **)(char *, char *, __int64, _QWORD *, __int64))(v13[8] + 8i64))(
            v48,
            v50,
            1i64,
            v13,
            a7) )
    {
      sub_180009218(5i64, v26, a7);
      goto LABEL_44;
    }
    if ( v52 < 2 )
    {
      if ( !v64
        || !(unsigned int)sub_18008E440((_DWORD)a1, (_DWORD)a1, v9, v27, (__int64)v13, v11, a7)
        || !(*(unsigned int (__fastcall **)(__int64, __int64, char *, __int64, _QWORD *, __int64))v13[8])(
              a5[1],
              v9,
              v12,
              1i64,
              v13,
              a7)
        || !(*(unsigned int (__fastcall **)(char *, __int64, char *, __int64, _QWORD *, __int64))v13[8])(
              v12,
              v9,
              v12,
              1i64,
              v13,
              a7)
        || !(*(unsigned int (__fastcall **)(char *, __int64, char *, __int64, _QWORD *, __int64))v13[8])(
              v12,
              v9,
              v12,
              1i64,
              v13,
              a7)
        || !(*(unsigned int (__fastcall **)(char *, char *, char *, __int64, _QWORD *, __int64))v13[8])(
              v48,
              v48,
              v51,
              1i64,
              v13,
              a7)
        || !(unsigned int)sub_180093A14((_DWORD)v51, v9, (_DWORD)v13, v11, a7) )
      {
        goto LABEL_44;
      }
      v25 = (unsigned int)sub_18008E440((_DWORD)v12, v9, v9, v36, (__int64)v13, v11, a7) == 0;
LABEL_65:
      if ( v25 )
        goto LABEL_44;
      goto LABEL_66;
    }
    if ( !v64
      || !(unsigned int)sub_180093A14((_DWORD)a1, v9, (_DWORD)v13, v11, a7)
      || !(unsigned int)sub_18008E440((_DWORD)v48, v9, v9, v33, (__int64)v13, v11, a7) )
    {
      goto LABEL_44;
    }
    v34 = 0i64;
    v24 = 1;
    v35 = (_QWORD *)v9;
    while ( v34 != v54 )
    {
      ++v34;
      *v35 ^= *(_QWORD *)&a1[(_QWORD)v35 - v9];
      ++v35;
    }
LABEL_38:
    v25 = v24 == 0;
    goto LABEL_65;
  }
  if ( !v64
    || !(unsigned int)sub_180093A14((_DWORD)v12, v9, (_DWORD)v13, v11, a7)
    || !(*(unsigned int (__fastcall **)(char *, char *, char *, __int64, _QWORD *, __int64))(v13[8] + 128i64))(
          v48,
          v50,
          v51,
          1i64,
          v13,
          a7)
    || !(unsigned int)sub_18008E440(v9, (_DWORD)v51, v9, v23, (__int64)v13, v11, a7) )
  {
    v24 = 0;
    goto LABEL_38;
  }
LABEL_66:
  if ( (unsigned int)sub_18008E440(v9, v9, (_DWORD)v12, v24, (__int64)v13, v11, a7) )
  {
    v28 = 1;
    goto LABEL_45;
  }
LABEL_44:
  v28 = 0;
LABEL_45:
  if ( v52 >= 2 )
  {
    v29 = 0i64;
    v30 = 0i64;
    if ( !v28 )
      return 0;
    v31 = v12;
    while ( v30 != v54 )
    {
      ++v30;
      v32 = *(_QWORD *)v31 ^ *(_QWORD *)&v31[a2 - v12] ^ *(_QWORD *)(v31 - v12 + v9) ^ *(_QWORD *)&v31[a5[1] - (_QWORD)v12];
      v29 |= v32;
      *(_QWORD *)v31 = v32;
      v31 += 8;
    }
    v7 = a7;
    if ( v29 )
    {
      if ( !(unsigned int)sub_180093A14((_DWORD)v12, (_DWORD)v10, (_DWORD)v13, v55, a7) )
        return 0;
      if ( !(unsigned int)sub_18008E440((_DWORD)v10, (_DWORD)a1, (_DWORD)v10, v37, (__int64)v13, v55, a7) )
        return 0;
      if ( !(*(unsigned int (__fastcall **)(char *, __int64, char *, __int64, _QWORD *, __int64))v13[8])(
              v10,
              v9,
              v10,
              1i64,
              v13,
              a7) )
        return 0;
      if ( !(unsigned int)sub_18008E440((_DWORD)v10, (_DWORD)v10, v9, v38, (__int64)v13, v55, a7) )
        return 0;
      v39 = &v12[-v9];
      v40 = 0i64;
      v41 = &a1[-v9];
      v42 = v9;
      while ( v40 != v54 )
      {
        ++v40;
        v43 = *(_QWORD *)&v39[v42] ^ *(_QWORD *)v42 ^ *(_QWORD *)&v10[v42 - v9] ^ *(_QWORD *)(a5[1] - v9 + v42);
        v44 = *(_QWORD *)&v48[v42 - v9] ^ *(_QWORD *)&v41[v42];
        *(_QWORD *)&v39[v42] = v43 ^ *(_QWORD *)&v41[v42];
        *(_QWORD *)&a3[v42 - v9] = v43;
        *(_QWORD *)&v56[v42 - v9] = v44;
        v42 += 8i64;
      }
      if ( !(unsigned int)sub_18008E440(v57, (_DWORD)v12, (_DWORD)v12, v40, v58, v55, a7) )
        return 0;
      v18 = (**(__int64 (__fastcall ***)(char *, char *, char *, __int64, __int64, __int64))(v58 + 64))(
              v56,
              v12,
              v56,
              1i64,
              v58,
              a7);
      return v18 != 0;
    }
LABEL_85:
    v18 = sub_180090984(a3, a5, v7);
    return v18 != 0;
  }
  Srca = v28
      && (*(unsigned int (__fastcall **)(char *, char *, char *, __int64, _QWORD *, __int64))(v13[8] + 128i64))(
           v12,
           a1,
           v12,
           1i64,
           v13,
           a7)
      && (*(unsigned int (__fastcall **)(char *, char *, char *, __int64, _QWORD *, __int64))(v13[8] + 128i64))(
           v12,
           a2,
           v12,
           1i64,
           v13,
           a7);
  if ( (*(unsigned int (__fastcall **)(char *, char *, __int64, _QWORD *, __int64))(v13[8] + 8i64))(
         v12,
         a1,
         1i64,
         v13,
         a7) )
  {
    if ( !Srca )
      return 0;
    goto LABEL_85;
  }
  if ( Srca
    && (*(unsigned int (__fastcall **)(char *, char *, char *, __int64, _QWORD *, __int64))(v13[8] + 128i64))(
         v12,
         a1,
         v51,
         1i64,
         v13,
         a7)
    && (unsigned int)sub_180093A14((_DWORD)v51, (_DWORD)v10, (_DWORD)v13, v11, a7)
    && (unsigned int)sub_18008E440((_DWORD)v48, (_DWORD)v10, (_DWORD)v10, v45, (__int64)v13, v11, a7)
    && (*(unsigned int (__fastcall **)(char *, char *, char *, __int64, _QWORD *, __int64))v13[8])(
         v10,
         v10,
         v10,
         1i64,
         v13,
         a7)
    && (*(unsigned int (__fastcall **)(char *, __int64, char *, __int64, _QWORD *, __int64))v13[8])(
         v10,
         v9,
         v10,
         1i64,
         v13,
         a7)
    && (unsigned int)sub_18008E440((_DWORD)v10, (_DWORD)v10, v9, v46, (__int64)v13, v11, a7)
    && (*(unsigned int (__fastcall **)(__int64, char *, __int64, __int64, _QWORD *, __int64))(v13[8] + 128i64))(
         v9,
         v12,
         v9,
         1i64,
         v13,
         a7)
    && (*(unsigned int (__fastcall **)(__int64, char *, char *, __int64, _QWORD *, __int64))(v13[8] + 128i64))(
         v9,
         a1,
         v12,
         1i64,
         v13,
         a7)
    && (*(unsigned int (__fastcall **)(char *, char *, char *, __int64, _QWORD *, __int64))(v13[8] + 128i64))(
         v12,
         a1,
         v51,
         1i64,
         v13,
         a7)
    && (unsigned int)sub_18008E440((_DWORD)v51, (_DWORD)v10, (_DWORD)v51, v47, (__int64)v13, v11, a7)
    && (*(unsigned int (__fastcall **)(char *, char *, char *, __int64, _QWORD *, __int64))(v13[8] + 128i64))(
         v51,
         v48,
         v56,
         1i64,
         v13,
         a7) )
  {
    v16 = v12;
    v17 = 8i64 * *v13;
    goto LABEL_99;
  }
  return 0;
}

__int64 __fastcall sub_1800900C8(char *a1, char *a2, char *a3, char *a4, int **a5, char *Src, __int64 a7)
{
  __int64 v8; // rbx
  int *v9; // rsi
  __int64 v10; // r8
  __int64 v11; // rcx
  unsigned int v12; // edi
  char *v13; // r13
  char *v14; // r12
  int v15; // r9d
  int v16; // r9d
  int v17; // r9d
  int v18; // r9d
  int v19; // r9d
  int v20; // r9d
  char *v21; // r9
  signed __int64 v22; // r10
  signed __int64 v23; // r13
  __int64 v24; // rcx
  __int64 v25; // rdx
  __int64 v26; // r8
  char *v28; // [rsp+40h] [rbp-68h]
  char *v29; // [rsp+48h] [rbp-60h]
  __int64 v30; // [rsp+50h] [rbp-58h]
  __int64 v35; // [rsp+D0h] [rbp+28h]

  v8 = 0i64;
  v9 = *a5;
  v10 = *(_QWORD *)*a5;
  v30 = v10;
  v35 = 8 * v10;
  v29 = &a2[8 * v10];
  v28 = &a1[8 * v10];
  if ( v9[10] <= 0 )
  {
    v11 = 6i64;
LABEL_3:
    v12 = 0;
    sub_180009218(v11, 8 * v10, a7);
    return v12;
  }
  if ( !Src )
  {
    v11 = 12i64;
    goto LABEL_3;
  }
  v13 = &Src[16 * v10];
  v14 = &v13[16 * v10];
  v12 = 1;
  if ( (unsigned int)sub_180090650(a1, a5, a7)
    || (unsigned int)sub_180090650(a2, a5, a7)
    || (*(unsigned int (__fastcall **)(char *, char *, __int64, int *, __int64))(*((_QWORD *)v9 + 8) + 8i64))(
         a1,
         a2,
         1i64,
         v9,
         a7) )
  {
    if ( sub_18008FB54(a1, a2, Src, 1, a5, (__int64)v13, a7) && sub_18008FB54(a1, a2, a4, -1, a5, (__int64)v13, a7) )
    {
      memcpy(a3, Src, 16i64 * *(_QWORD *)*a5);
      return v12;
    }
    return 0;
  }
  if ( !(*(unsigned int (__fastcall **)(char *, char *, char *, __int64, int *, __int64))(*((_QWORD *)v9 + 8) + 128i64))(
          a1,
          a2,
          Src,
          1i64,
          v9,
          a7)
    || !(unsigned int)sub_180093A14((_DWORD)Src, (_DWORD)v14, (_DWORD)v9, (int)v14 + (int)v35, a7)
    || !(*(unsigned int (__fastcall **)(char *, char *, char *, __int64, int *, __int64))(*((_QWORD *)v9 + 8) + 128i64))(
          v28,
          v29,
          &Src[v35],
          1i64,
          v9,
          a7)
    || !(**((unsigned int (__fastcall ***)(char *, char *, char *, __int64, int *, __int64))v9 + 8))(
          v28,
          v29,
          &v13[v35],
          1i64,
          v9,
          a7)
    || !(unsigned int)sub_18008E440(
                        (_DWORD)v14,
                        (int)v35 + (int)Src,
                        (int)v35 + (int)Src,
                        v15,
                        (__int64)v9,
                        (__int64)&v14[v35],
                        a7)
    || !(unsigned int)sub_18008E440(
                        (_DWORD)v14,
                        (int)v35 + (int)v13,
                        (int)v35 + (int)v13,
                        v16,
                        (__int64)v9,
                        (__int64)&v14[v35],
                        a7)
    || !(unsigned int)sub_18008E440(
                        (int)v35 + (int)Src,
                        (int)v35 + (int)Src,
                        (_DWORD)Src,
                        v17,
                        (__int64)v9,
                        (__int64)&v14[v35],
                        a7)
    || !(unsigned int)sub_18008E440(
                        (int)v35 + (int)v13,
                        (int)v35 + (int)v13,
                        (_DWORD)v13,
                        v18,
                        (__int64)v9,
                        (__int64)&v14[v35],
                        a7)
    || !(**((unsigned int (__fastcall ***)(char *, char *, char *, __int64, int *, __int64))v9 + 8))(
          a1,
          a2,
          v14,
          1i64,
          v9,
          a7)
    || !(*(unsigned int (__fastcall **)(char *, char *, char *, __int64, int *, __int64))(*((_QWORD *)v9 + 8) + 128i64))(
          Src,
          v14,
          Src,
          1i64,
          v9,
          a7)
    || !(*(unsigned int (__fastcall **)(char *, char *, char *, __int64, int *, __int64))(*((_QWORD *)v9 + 8) + 128i64))(
          v13,
          v14,
          v13,
          1i64,
          v9,
          a7)
    || !(*(unsigned int (__fastcall **)(char *, char *, char *, __int64, int *, __int64))(*((_QWORD *)v9 + 8) + 128i64))(
          a1,
          Src,
          v14,
          1i64,
          v9,
          a7)
    || !(unsigned int)sub_18008E440(
                        (int)v35 + (int)Src,
                        (_DWORD)v14,
                        (int)v35 + (int)Src,
                        v19,
                        (__int64)v9,
                        (__int64)&v14[v35],
                        a7)
    || !(*(unsigned int (__fastcall **)(char *, char *, char *, __int64, int *, __int64))(*((_QWORD *)v9 + 8) + 128i64))(
          a1,
          v13,
          v14,
          1i64,
          v9,
          a7)
    || !(unsigned int)sub_18008E440(
                        (int)v35 + (int)v13,
                        (_DWORD)v14,
                        (int)v35 + (int)v13,
                        v20,
                        (__int64)v9,
                        (__int64)&v14[v35],
                        a7)
    || !(*(unsigned int (__fastcall **)(char *, char *, char *, __int64, int *, __int64))(*((_QWORD *)v9 + 8) + 128i64))(
          &Src[v35],
          v28,
          &Src[v35],
          1i64,
          v9,
          a7)
    || !(*(unsigned int (__fastcall **)(char *, char *, char *, __int64, int *, __int64))(*((_QWORD *)v9 + 8) + 128i64))(
          &v13[v35],
          v28,
          &v13[v35],
          1i64,
          v9,
          a7) )
  {
    return 0;
  }
  v21 = &a4[v35];
  v22 = &v13[-v35] - a4;
  v23 = v13 - a4;
  while ( v8 != v30 )
  {
    ++v8;
    v24 = *(_QWORD *)&v21[Src - a4];
    v25 = *(_QWORD *)&v21[v22];
    v26 = *(_QWORD *)&v21[v23];
    *(_QWORD *)&v21[&a3[-v35] - a4] = *(_QWORD *)&v21[&Src[-v35] - a4];
    *(_QWORD *)&v21[a3 - a4] = v24;
    *(_QWORD *)&v21[-8 * v30] = v25;
    *(_QWORD *)v21 = v26;
    v21 += 8;
  }
  return v12;
}



