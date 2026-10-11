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

__int64 __fastcall sub_18009DC10(
        char a1,
        __int64 a2,
        unsigned int a3,
        __int64 a4,
        int a5,
        __int64 a6,
        int a7,
        __int64 a8,
        __int64 a9,
        __int64 a10,
        int a11)
{
  unsigned int v13; // r12d
  __int64 *v14; // rax
  __int64 v15; // r8
  int *v16; // rcx
  int v17; // r13d
  unsigned int v18; // ebx
  __int64 v19; // rdx
  unsigned int v20; // r14d
  int v21; // r8d
  __int64 v22; // rax
  char *v23; // rdi
  __int64 v24; // r15
  unsigned __int64 v25; // rsi
  unsigned int v26; // r9d
  __int64 v27; // r10
  int v28; // r8d
  __int64 v29; // rax
  char v31[8]; // [rsp+20h] [rbp-E0h] BYREF
  unsigned int v32; // [rsp+28h] [rbp-D8h]
  int *v33; // [rsp+30h] [rbp-D0h]
  __int64 *v34; // [rsp+38h] [rbp-C8h]
  __int64 v35; // [rsp+40h] [rbp-C0h]
  __int64 v36; // [rsp+48h] [rbp-B8h]
  __int64 v37; // [rsp+50h] [rbp-B0h]
  __int128 v38[4]; // [rsp+60h] [rbp-A0h] BYREF
  _QWORD v39[2]; // [rsp+A0h] [rbp-60h] BYREF
  __int128 v40; // [rsp+B0h] [rbp-50h]
  int v41[4]; // [rsp+C0h] [rbp-40h] BYREF
  __int64 v42[3]; // [rsp+D0h] [rbp-30h] BYREF
  char Src[24]; // [rsp+E8h] [rbp-18h] BYREF

  v36 = a10;
  v31[0] = a1;
  v32 = (unsigned int)(a11 + 31) >> 5;
  if ( !a6 && a7 )
    return 5i64;
  v13 = 0;
  v39[0] = 0xEFCDAB8967452301ui64;
  v39[1] = 0x1032547698BADCFEi64;
  v41[0] = a5;
  v42[0] = a4;
  v41[1] = a7;
  v42[1] = a6;
  v41[2] = 0;
  v42[2] = 0i64;
  v40 = 0i64;
  LODWORD(v40) = -1009589776;
  memset(v38, 0, sizeof(v38));
  if ( a1 )
    sub_180015D20(v38, v31, 1i64);
  sub_180015D20(v38, a2, a3);
  v14 = v42;
  v15 = 3i64;
  v16 = v41;
  v34 = v42;
  v33 = v41;
  v35 = 3i64;
  do
  {
    v17 = *v16;
    v18 = 0;
    v19 = *v14;
    v20 = 0;
    v37 = *v14;
    if ( v17 )
    {
      do
      {
        v21 = *(_DWORD *)(v19 + 4i64 * v20);
        Src[v18] = v21;
        Src[v18 + 1] = BYTE1(v21);
        Src[v18 + 2] = BYTE2(v21);
        v22 = v18 + 3;
        v18 += 4;
        Src[v22] = HIBYTE(v21);
        if ( v18 > 0x10 || v20 == v17 - 1 )
        {
          v23 = Src;
          v24 = BYTE8(v40) & 0x3F;
          DWORD2(v40) += v18;
          if ( DWORD2(v40) < v18 )
            ++DWORD1(v40);
          if ( (_DWORD)v24 && (unsigned int)v24 + v18 >= 0x40 )
          {
            memcpy((char *)v38 + v24, Src, (unsigned int)(64 - v24));
            v23 = &Src[(unsigned int)(64 - v24)];
            v18 = v24 + v18 - 64;
            sub_180015DF0(v39, v38);
            LODWORD(v24) = 0;
          }
          if ( v18 >= 0x40 )
          {
            v25 = (unsigned __int64)v18 >> 6;
            do
            {
              sub_180015DF0(v39, v23);
              v23 += 64;
              v18 -= 64;
              --v25;
            }
            while ( v25 );
          }
          if ( v18 )
            memcpy((char *)v38 + (unsigned int)v24, v23, v18);
          v18 = 0;
        }
        v19 = v37;
        ++v20;
      }
      while ( v20 != v17 );
      v14 = v34;
      v16 = v33;
      v15 = v35;
    }
    ++v16;
    ++v14;
    --v15;
    v33 = v16;
    v35 = v15;
    v34 = v14;
  }
  while ( v15 );
  sub_180015C00(v38, Src);
  v26 = v32;
  if ( 4 * v32 > 0x14 )
    return 5i64;
  if ( v32 )
  {
    v27 = v36;
    do
    {
      v28 = (unsigned __int8)Src[4 * v13]
          + (((unsigned __int8)Src[4 * v13 + 1]
            + (((unsigned __int8)Src[4 * v13 + 2] + ((unsigned __int8)Src[4 * v13 + 3] << 8)) << 8)) << 8);
      v29 = v13++;
      *(_DWORD *)(v27 + 4 * v29) = v28;
    }
    while ( v13 != v26 );
  }
  *(_DWORD *)(v36 + 4i64 * (v26 - 1)) >>= 32 * v26 - a11;
  return 0i64;
}

void __fastcall sub_180009218(DWORD a1, __int64 a2, __int64 a3)
{
  SetLastError(a1);
  if ( a3 )
  {
    *(_QWORD *)(a3 + 24) = 0i64;
    *(_DWORD *)(a3 + 16) = a1;
  }
}

__int64 __fastcall sub_18009DAB0(unsigned int *a1, __int64 a2)
{
  __int64 v4; // r9
  __int64 v5; // rdx
  unsigned int v6; // ecx
  unsigned int v7; // ebx
  unsigned int v8; // edi
  __int64 v9; // r10
  unsigned int v10; // eax
  unsigned int v11; // ecx
  unsigned int *v12; // rcx
  unsigned int *v13; // rdx
  __int64 v14; // rsi
  __int64 v15; // rcx
  int v16; // eax
  __int64 result; // rax
  __int64 v18; // r11

  if ( !a1 )
    return 3i64;
  v4 = *a1;
  if ( (unsigned int)v4 < 0x1C )
    return 3i64;
  v5 = a1[1];
  if ( (unsigned int)(v5 - 7) > 2 )
    return 3i64;
  v6 = a1[3];
  *(_DWORD *)(a2 + 28) = v6;
  v7 = a1[5];
  *(_DWORD *)(a2 + 12) = v7;
  v8 = a1[6];
  *(_DWORD *)(a2 + 20) = v8;
  v9 = a1[4];
  *(_DWORD *)(a2 + 8) = v9;
  *(_DWORD *)(a2 + 16) = (v7 + 31) >> 5;
  if ( v6 < 0x1317CC4 )
  {
    *(_DWORD *)a2 = 0;
    v11 = 0;
    v10 = 0;
  }
  else
  {
    v10 = a1[7];
    *(_DWORD *)a2 = v10;
    v11 = a1[8];
  }
  *(_DWORD *)(a2 + 24) = v11;
  v12 = &a1[v5];
  v13 = &v12[v9];
  *(_DWORD *)(a2 + 4) = (v10 + 31) >> 5;
  *(_QWORD *)(a2 + 32) = v12;
  *(_QWORD *)(a2 + 40) = v13;
  v14 = (unsigned int)(2 * v9);
  v15 = (__int64)&v13[v14 + v14];
  *(_QWORD *)(a2 + 48) = &v13[v14];
  *(_QWORD *)(a2 + 56) = v15;
  if ( v7 > 0x20 )
    return 3i64;
  if ( v8 > 0x40 )
    return 3i64;
  if ( (unsigned int)v9 > 0x20 )
    return 3i64;
  if ( v4 != ((v14 * 4 + v15 - (_QWORD)a1) & 0xFFFFFFFFFFFFFFFCui64) )
    return 3i64;
  v16 = *(_DWORD *)(a2 + 28);
  if ( v16 != 19980206 && v16 != 20020420 )
    return 3i64;
  result = sub_18009DA10(a1);
  if ( (_DWORD)result )
    return 3i64;
  *(_QWORD *)(v18 + 64) = 0i64;
  *(_QWORD *)(v18 + 96) = 0i64;
  *(_QWORD *)(v18 + 104) = 0i64;
  *(_QWORD *)(v18 + 112) = 0i64;
  *(_QWORD *)(v18 + 72) = 0i64;
  *(_QWORD *)(v18 + 80) = 0i64;
  *(_DWORD *)(v18 + 88) = 0;
  *(_QWORD *)(v18 + 128) = 0i64;
  *(_DWORD *)(v18 + 136) = 0;
  return result;
}

__int64 __fastcall sub_18008EE44(_BYTE *Src, __int64 a2, BOOL a3, __int64 a4, __int64 a5)
{
  unsigned __int64 v6; // r15
  char *v9; // r12
  __int64 v10; // rax
  __int64 v11; // rdx
  __int64 v12; // r14
  unsigned int v13; // edi
  int v14; // eax
  __int64 v15; // rdx
  __int64 v16; // rbp
  __int64 v17; // rcx
  __int64 v18; // rsi
  unsigned __int64 v19; // r8
  __int64 v20; // rcx
  unsigned __int64 v21; // r15
  _QWORD *v22; // r12
  __int64 v23; // rdx
  __int64 v24; // rdx
  unsigned __int64 v26; // [rsp+30h] [rbp-48h]
  __int64 Srca[8]; // [rsp+38h] [rbp-40h] BYREF
  int v29; // [rsp+88h] [rbp+10h] BYREF
  BOOL v30; // [rsp+90h] [rbp+18h]

  v30 = a3;
  v6 = (unsigned __int64)(a2 + 1) >> 1;
  v26 = v6;
  Srca[0] = sub_180092FD0(a2 + v6 + 2 * a2);
  v9 = (char *)Srca[0];
  v10 = sub_180092FD0(2 * (v6 + a2) + 1);
  v12 = v10;
  if ( v10 && Srca[0] )
  {
    if ( a2 && *(_QWORD *)&Src[8 * a2 - 8] )
    {
      *(_QWORD *)(a4 + 88) = 0i64;
      *(_QWORD *)(a4 + 80) = &v9[8 * a2];
      v13 = 1;
      *(_QWORD *)(a4 + 56) = v9;
      *(_QWORD *)a4 = a2;
      *(_QWORD *)(a4 + 64) = &v9[16 * a2];
      *(_QWORD *)(a4 + 8) = v6;
      *(_DWORD *)(a4 + 28) = 1;
      *(_QWORD *)(a4 + 72) = &v9[24 * a2];
      memcpy(v9, Src, 8 * a2);
      v14 = sub_1800952DC(Src, a2, a4 + 32, a5);
      v16 = 0i64;
      v30 = v14 != 0;
      if ( (*Src & 1) == 0 )
        goto LABEL_10;
      if ( v14 )
      {
        v17 = *(_QWORD *)Src;
        if ( (*(_QWORD *)Src & 1) != 0 )
        {
          v19 = 5i64;
          v15 = (3 * v17) ^ 2;
          v20 = 1 - v17 * v15;
          do
          {
            v19 *= 2i64;
            v15 *= v20 + 1;
            v20 *= v20;
          }
          while ( v19 < 0x20 );
          v30 = 1;
          v16 = v15 * (v20 + 1);
LABEL_10:
          *(_QWORD *)(a4 + 48) = v16;
          *(_DWORD *)(a4 + 24) = (_DWORD)a2 << 6;
          if ( v16 )
          {
            **(_QWORD **)(a4 + 72) = v16;
            *(_QWORD *)(v12 + 8 * a2) = sub_180091108(*(_QWORD *)(a4 + 56), v16, v12, a2);
            if ( v6 != 1 )
            {
              v21 = v6 - 1;
              v22 = (_QWORD *)(v12 + 8);
              do
              {
                v23 = -(*v22 * v16);
                *(_QWORD *)((char *)v22 + *(_QWORD *)(a4 + 72) - v12) = v23;
                v22[a2] = sub_180090A0C(*(_QWORD *)(a4 + 56), v23, v22, a2);
                ++v22;
                --v21;
              }
              while ( v21 );
              v6 = v26;
              v9 = (char *)Srca[0];
            }
            memcpy(*(void **)(a4 + 64), (const void *)(v12 + 8 * v6), 8 * a2);
            v18 = a5;
          }
          else
          {
            v18 = a5;
            v30 = 0;
            sub_180009218(6u, v15, a5);
          }
          v29 = 0;
          Srca[0] = 1i64;
          if ( v30 && (unsigned int)sub_180096A3C(a4, &v29) )
          {
            if ( v29 )
            {
              v29 = -v29;
              if ( (unsigned int)sub_180096A3C(a4, &v29) && (unsigned int)sub_18008F5E8(Srca, v18) )
                goto LABEL_27;
            }
            else
            {
              sub_180009218(5u, v24, v18);
            }
          }
          v13 = 0;
LABEL_27:
          *(_QWORD *)(a4 + 112) = 0i64;
          *(_QWORD *)(a4 + 120) = 0i64;
          goto LABEL_30;
        }
        sub_180009218(6u, v15, a5);
      }
      v30 = 0;
      goto LABEL_10;
    }
    v13 = 0;
    sub_180009218(6u, v11, a5);
LABEL_30:
    sub_180009288(v12);
    if ( v13 )
      return v13;
    goto LABEL_31;
  }
  v13 = 0;
  if ( v10 )
    goto LABEL_30;
LABEL_31:
  *(_QWORD *)(a4 + 56) = 0i64;
  if ( v9 )
    sub_180009288(v9);
  return v13;
}

_BOOL8 __fastcall sub_18008E5A8(__int64 *a1, __int64 a2, __int64 a3)
{
  __int64 v3; // rbp
  int v7; // edx
  BOOL v8; // edi
  unsigned __int64 v9; // rcx
  __int64 v10; // rax
  __int64 v11; // rax
  __int64 v12; // rbx

  v3 = *a1;
  *(_QWORD *)(a2 + 56) = 0i64;
  v7 = sub_18008E154(a2, 0i64);
  *(_QWORD *)(a2 + 8) = 1i64;
  *(_QWORD *)a2 = v3;
  *(_DWORD *)(a2 + 40) = 1;
  *(_QWORD *)(a2 + 88) = a1;
  *(_QWORD *)(a2 + 64) = &off_1800A4530;
  v8 = v7 != 0;
  v9 = a1[2];
  *(_QWORD *)(a2 + 24) = v9;
  if ( v9 <= v3 + 8 * v3 + 6 )
    v9 = v3 + 8 * v3 + 6;
  *(_QWORD *)(a2 + 32) = v9 + v3;
  *(_QWORD *)(a2 + 16) = v3 + v9 + v3;
  v10 = a1[10];
  *(_QWORD *)(a2 + 48) = v10;
  if ( v7 )
  {
    if ( *((_DWORD *)a1 + 7) )
    {
      v11 = sub_180092FD0(v3);
      *(_QWORD *)(a2 + 56) = v11;
      *(_QWORD *)(a2 + 96) = v11;
      v12 = v11;
      if ( v11 != 0 && v8 && (unsigned int)sub_18008F360(*(void **)(a2 + 48), a3) )
      {
        return 1;
      }
      else
      {
        v8 = 0;
        if ( v12 )
          sub_180009288(v12);
      }
    }
    else
    {
      *(_QWORD *)(a2 + 96) = v10;
    }
  }
  return v8;
}

__int64 __fastcall sub_18008E240(__int64 a1, __int64 a2)
{
  _QWORD *v3; // rdi
  unsigned int v4; // esi
  __int64 result; // rax
  __int64 v6; // rcx

  if ( !*(_DWORD *)(a1 + 40) )
  {
    sub_180009218(6u, a2, a2);
    v3 = (_QWORD *)(a1 + 64);
LABEL_3:
    v4 = 0;
    goto LABEL_4;
  }
  v3 = (_QWORD *)(a1 + 64);
  if ( !(*(unsigned int (**)(void))(*(_QWORD *)(a1 + 64) + 24i64))() )
    goto LABEL_3;
  v6 = *(_QWORD *)(a1 + 56);
  v4 = 1;
  if ( v6 )
  {
    sub_180009288(v6);
    *(_QWORD *)(a1 + 56) = 0i64;
  }
LABEL_4:
  *v3 = 0i64;
  result = v4;
  *(_DWORD *)(a1 + 40) = 0;
  return result;
}

_BOOL8 __fastcall sub_18009D820(char *a1, __int64 a2, __int64 a3, unsigned int a4, __int64 a5)
{
  unsigned __int64 v5; // r10
  char *v6; // r11
  __int64 v7; // rdx
  __int64 v8; // rax
  __int64 Src[16]; // [rsp+30h] [rbp-A8h] BYREF

  v5 = (unsigned __int64)a4 >> 1;
  if ( (a4 & 1) != 0 )
    Src[v5] = *(unsigned int *)&a1[4 * a4 - 4];
  if ( v5 )
  {
    v6 = (char *)((char *)Src - a1);
    do
    {
      v7 = *((unsigned int *)a1 + 1);
      v8 = *(unsigned int *)a1;
      a1 += 8;
      *(_QWORD *)&a1[(_QWORD)v6 - 8] = v8 | (v7 << 32);
      --v5;
    }
    while ( v5 );
  }
  return (unsigned int)sub_18008F5E8(Src, a5) != 0;
}

__int64 __fastcall sub_18008F7F4(void *Src, void *a2, __int64 *a3, __int64 a4, __int64 a5)
{
  __int64 v5; // r13
  __int64 v10; // rbx
  __int64 v11; // rax
  __int64 v12; // r14
  __int64 v13; // rbp
  __int64 v14; // r8
  unsigned int v15; // ebx
  __int64 v16; // rdx
  __int64 v17; // r14
  __int64 v18; // r14
  int v19; // r14d
  int v20; // eax
  __int64 v21; // rax
  __int64 v22; // rdx
  int v23; // r9d
  int v24; // r9d
  int v25; // r9d
  void *v26; // rcx
  __int64 v27; // rdx
  _QWORD *v28; // rcx
  int v29; // eax
  __int64 v31; // [rsp+90h] [rbp+18h] BYREF
  __int64 v32; // [rsp+98h] [rbp+20h] BYREF

  v5 = *a3;
  v10 = 5 * *a3;
  v11 = sub_180092FD0(v10 + 1);
  *(_DWORD *)(a4 + 56) = 0;
  v12 = v11;
  v13 = a5;
  *(_QWORD *)(a4 + 40) = v11;
  v14 = a3[2];
  v31 = v11;
  *(_QWORD *)(a4 + 72) = v10 + v14;
  v15 = 1;
  *(_DWORD *)(a4 + 68) = (*(__int64 (__fastcall **)(void *, __int64, __int64 *, __int64))(a3[8] + 48))(
                           a2,
                           1i64,
                           a3,
                           v13);
  *(_DWORD *)(a4 + 64) = (*(__int64 (__fastcall **)(void *, __int64, __int64 *, __int64))(a3[8] + 48))(
                           Src,
                           1i64,
                           a3,
                           v13);
  if ( !v12 )
    goto LABEL_19;
  *(_QWORD *)(a4 + 48) = 0i64;
  v16 = v31;
  *(_QWORD *)(a4 + 8) = v12;
  v17 = 8 * v5 + v12;
  *(_QWORD *)(a4 + 80) = 1i64;
  *(_QWORD *)(a4 + 16) = v17;
  v18 = 8 * v5 + v17;
  v32 = -3i64;
  *(_QWORD *)(a4 + 24) = v18;
  *(_QWORD *)(a4 + 32) = v18 + 16 * v5;
  if ( !(*(unsigned int (__fastcall **)(__int64 *, __int64, __int64, __int64 *, __int64))(a3[8] + 32))(
          &v32,
          v16,
          1i64,
          a3,
          v13) )
  {
    v19 = 0;
    goto LABEL_6;
  }
  v19 = 1;
  if ( !(*(unsigned int (__fastcall **)(void *, _QWORD, __int64, __int64 *, __int64))(a3[8] + 8))(
          Src,
          *(_QWORD *)(a4 + 8),
          1i64,
          a3,
          v13) )
  {
LABEL_6:
    v20 = 0;
    goto LABEL_7;
  }
  v20 = 1;
LABEL_7:
  *(_DWORD *)(a4 + 60) = v20;
  if ( v19 )
  {
    v21 = a3[8];
    v22 = *(_QWORD *)(a4 + 16);
    v31 = 27i64;
    if ( (*(unsigned int (__fastcall **)(__int64 *, __int64, __int64, __int64 *, __int64))(v21 + 32))(
           &v31,
           v22,
           1i64,
           a3,
           v13) )
    {
      if ( (unsigned int)sub_18008E440(
                           *(_QWORD *)(a4 + 16),
                           (_DWORD)a2,
                           *(_QWORD *)(a4 + 16),
                           v23,
                           (__int64)a3,
                           0i64,
                           v13) )
      {
        if ( (unsigned int)sub_18008E440(
                             *(_QWORD *)(a4 + 16),
                             (_DWORD)a2,
                             *(_QWORD *)(a4 + 16),
                             v24,
                             (__int64)a3,
                             0i64,
                             v13) )
        {
          if ( (*(unsigned int (__fastcall **)(void *, void *, _QWORD, __int64, __int64 *, __int64))a3[8])(
                 Src,
                 Src,
                 *(_QWORD *)(a4 + 8),
                 1i64,
                 a3,
                 v13) )
          {
            if ( (unsigned int)sub_18008E440(
                                 *(_QWORD *)(a4 + 8),
                                 *(_QWORD *)(a4 + 8),
                                 *(_QWORD *)(a4 + 8),
                                 v25,
                                 (__int64)a3,
                                 0i64,
                                 v13) )
            {
              if ( (unsigned int)sub_1800949C8(
                                   (_DWORD)Src,
                                   *(_QWORD *)(a4 + 8),
                                   *(_QWORD *)(a4 + 16),
                                   *(_QWORD *)(a4 + 8),
                                   (__int64)a3,
                                   0i64,
                                   v13) )
              {
                if ( !(*(unsigned int (__fastcall **)(_QWORD, __int64, __int64 *, __int64))(a3[8] + 48))(
                        *(_QWORD *)(a4 + 8),
                        1i64,
                        a3,
                        v13) )
                {
                  v26 = *(void **)(a4 + 8);
                  *(_QWORD *)a4 = a3;
                  memcpy(v26, Src, 8 * *a3);
                  memcpy(*(void **)(a4 + 16), a2, 8 * *a3);
                  if ( (unsigned int)sub_180090984(*(_QWORD *)(a4 + 24), a4, v13) )
                  {
                    v28 = *(_QWORD **)(a4 + 32);
                    if ( v5 != -1 )
                    {
                      *v28 = 1i64;
                      memset(v28 + 1, 0, 8 * (v5 + 1) - 8);
                      v29 = 1;
                      goto LABEL_20;
                    }
                    sub_180009218(0xDu, v27, v13);
                  }
                }
              }
            }
          }
        }
      }
    }
  }
LABEL_19:
  v29 = 0;
LABEL_20:
  *(_DWORD *)(a4 + 136) = 1;
  *(_QWORD *)(a4 + 144) = sub_180097690;
  *(_QWORD *)(a4 + 152) = sub_1800907C0;
  *(_QWORD *)(a4 + 160) = sub_180090650;
  if ( v29 )
  {
    *(_QWORD *)(a4 + 128) = 2i64;
    *(_DWORD *)(a4 + 120) = 0;
    *(_QWORD *)(a4 + 104) = 0i64;
    *(_QWORD *)(a4 + 112) = 0i64;
  }
  else
  {
    v15 = 0;
    sub_18008F774(a4, v13);
  }
  return v15;
}

_BOOL8 __fastcall sub_18008F774(__int64 *a1, __int64 a2)
{
  BOOL v3; // esi
  __int64 v4; // rcx
  int v5; // ebx
  __int64 v6; // rcx
  _BOOL8 result; // rax

  v3 = 1;
  if ( *((_DWORD *)a1 + 14) )
  {
    v4 = *a1;
    if ( v4 )
    {
      v5 = sub_18008E240(v4, a2);
      sub_180009288(*a1);
      v3 = v5 != 0;
    }
  }
  v6 = a1[5];
  if ( v6 )
    sub_180009288(v6);
  a1[5] = 0i64;
  result = v3;
  a1[3] = 0i64;
  a1[1] = 0i64;
  a1[2] = 0i64;
  a1[4] = 0i64;
  *a1 = 0i64;
  return result;
}

_BOOL8 __fastcall sub_18009D790(char *a1, __int64 a2, unsigned int **a3, unsigned int a4, __int64 a5)
{
  __int64 v7; // rbx
  __int64 v8; // rbp
  __int64 v9; // r15

  v7 = a4;
  v8 = *((_QWORD *)*a3 + 11);
  v9 = **a3;
  return sub_18009D820(a1, a2, v8, a4, a5) && sub_18009D820(&a1[4 * v7], a2 + 8 * v9, v8, v7, a5);
}

__int64 __fastcall sub_18009D740(unsigned int *a1, __int64 a2, unsigned __int64 a3)
{
  unsigned __int64 v3; // r9
  __int64 v4; // r10
  __int64 v5; // rdx
  __int64 v6; // rax

  v3 = a3 >> 1;
  if ( (a3 & 1) != 0 )
    *(_QWORD *)(a2 + 8 * v3) = a1[a3 - 1];
  if ( v3 )
  {
    v4 = a2 - (_QWORD)a1;
    do
    {
      v5 = a1[1];
      v6 = *a1;
      a1 += 2;
      *(_QWORD *)((char *)a1 + v4 - 8) = v6 | (v5 << 32);
      --v3;
    }
    while ( v3 );
  }
  return 1i64;
}

__int64 __fastcall sub_180090F98(__int64 a1, __int64 a2)
{
  __int64 v2; // r8
  _QWORD *i; // rax
  __int64 v5; // rax
  __int64 v6; // r8

  v2 = a2;
  if ( !a2 )
    return 0i64;
  for ( i = (_QWORD *)(a1 - 8 + 8 * a2); !*i; --i )
  {
    if ( !--v2 )
      return 0i64;
  }
  v5 = sub_180091150(*(_QWORD *)(a1 + 8 * v2 - 8));
  return (v6 << 6) + v5 - 64;
}

unsigned __int64 __fastcall sub_180091150(__int64 a1)
{
  unsigned __int64 v1; // rcx
  __int64 v2; // rax

  v1 = a1 | 1;
  v2 = 64i64;
  while ( v1 < 0x800000000000000i64 )
  {
    v2 -= 5i64;
    v1 *= 32i64;
  }
  return v2 - ((0x24949Cui64 >> (v1 >> 60) >> (2 * (unsigned __int8)(v1 >> 60))) & 7);
}

LPVOID __fastcall sub_180092FD0(__int64 a1)
{
  SIZE_T v1; // rbx
  HANDLE ProcessHeap; // rax

  v1 = 8 * a1;
  ProcessHeap = GetProcessHeap();
  return HeapAlloc(ProcessHeap, 0, v1);
}

__int64 __fastcall sub_18009D8E0(char *Src, __int64 a2, __int64 *a3, unsigned int a4, __int64 a5)
{
  __int64 v5; // rbp
  unsigned int v6; // ebx
  char *v7; // r10
  unsigned __int64 v10; // r14
  unsigned __int64 v11; // r8
  char *v12; // r11
  __int64 v13; // rdx
  __int64 v14; // rcx
  __int64 v15; // rax
  __int64 v16; // rcx
  unsigned __int64 v17; // rax
  unsigned __int64 v18; // r8
  __int64 v19; // rax
  __int64 v20; // rdx
  __int64 v21; // rcx
  __int64 v23[16]; // [rsp+30h] [rbp-C8h]

  v5 = *a3;
  v6 = 0;
  v7 = (char *)a3[7];
  v10 = a4;
  v11 = 0i64;
  if ( !v5 )
    goto LABEL_6;
  v12 = (char *)(Src - v7);
  do
  {
    v13 = *(_QWORD *)&v7[(_QWORD)v12];
    v14 = *(_QWORD *)v7;
    v7 += 8;
    v15 = v13 - v14;
    v16 = v13 ^ v14;
    v17 = v15 - v11;
    v11 = (v13 ^ (v16 | v13 ^ v17)) >> 63;
    --v5;
  }
  while ( v5 );
  if ( ((v13 ^ (v16 | v13 ^ v17)) & 0x8000000000000000ui64) != 0i64 )
  {
    sub_18008F360(Src, a5);
  }
  else
  {
LABEL_6:
    SetLastError(7u);
    if ( a5 )
    {
      *(_DWORD *)(a5 + 16) = 7;
      *(_QWORD *)(a5 + 24) = 0i64;
    }
  }
  v18 = v10 >> 1;
  if ( (v10 & 1) != 0 )
    *(_DWORD *)(a2 + 4 * v10 - 4) = v23[v18];
  if ( v18 )
  {
    v19 = 0i64;
    do
    {
      v20 = v23[v19];
      v21 = 2 * v6;
      *(_DWORD *)(a2 + 4 * v21) = v20;
      ++v6;
      *(_DWORD *)(a2 + 4i64 * (unsigned int)(v21 + 1)) = HIDWORD(v20);
      v19 = v6;
    }
    while ( v6 != v18 );
  }
  return 1i64;
}

__int64 __fastcall sub_180090650(__int64 a1, __int64 **a2, __int64 a3)
{
  __int64 *v3; // rdi
  unsigned int v6; // ebx
  __int64 v8; // rbp
  __int64 v9; // rcx
  __int64 v10; // rax

  v3 = *a2;
  v6 = 1;
  v8 = **a2;
  if ( !(*(unsigned int (__fastcall **)(__int64, __int64, __int64 *, __int64))(v3[8] + 48))(a1, 1i64, v3, a3) )
    return 0;
  v9 = a1 + 8 * v8;
  v10 = v3[8];
  if ( !(*((_DWORD *)a2 + 17)
       ? (*(__int64 (__fastcall **)(__int64, __int64, __int64, __int64 *, __int64))(v10 + 8))(v9, v3[6], 1i64, v3, a3)
       : (*(unsigned int (__fastcall **)(__int64, __int64, __int64 *, __int64))(v10 + 48))(v9, 1i64, v3, a3)) )
    return 0;
  return v6;
}

__int64 __fastcall sub_1800906FC(char *Src, char *a2, __int64 **a3, __int64 a4)
{
  __int64 *v4; // rdi
  char *v8; // rsi
  char *v9; // rbp
  unsigned int v10; // ebx

  v4 = *a3;
  v8 = &a2[8 * **a3];
  v9 = &Src[8 * **a3];
  v10 = 1;
  if ( (unsigned int)sub_180090650((__int64)Src, a3, a4) )
  {
    memcpy(v8, v9, 8 * *v4);
  }
  else if ( !(*(unsigned int (__fastcall **)(char *, char *, __int64, __int64 *, __int64))(v4[8] + 88))(
               v9,
               v8,
               1i64,
               v4,
               a4) )
  {
    return 0;
  }
  memcpy(a2, Src, 8 * *v4);
  return v10;
}

_BOOL8 __fastcall sub_180090984(__int64 a1, __int64 **a2, __int64 a3)
{
  __int64 *v3; // rdi
  __int64 v6; // rbp
  int v7; // edx
  _BOOL8 result; // rax

  v3 = *a2;
  v6 = **a2;
  v7 = (*(__int64 (__fastcall **)(__int64, __int64, __int64 *, __int64))(v3[8] + 136))(a1, 2i64, v3, a3);
  result = v7 != 0;
  if ( *((_DWORD *)a2 + 17) )
  {
    if ( v7 )
    {
      memcpy((void *)(a1 + 8 * v6), (const void *)v3[6], 8 * *v3);
      return 1i64;
    }
    else
    {
      return 0i64;
    }
  }
  return result;
}

__int64 __fastcall sub_180093A14(__int64 a1, __int64 a2, __int64 a3, __int64 a4, __int64 a5)
{
  unsigned int v6; // edi
  __int64 v7; // rax
  __int64 v10; // rdx
  __int64 v12[2]; // [rsp+30h] [rbp-28h] BYREF
  int v13; // [rsp+40h] [rbp-18h]

  v6 = 1;
  v12[1] = *(_QWORD *)(a3 + 32);
  v7 = *(_QWORD *)(a3 + 64);
  v12[0] = a4;
  v13 = 0;
  if ( (*(unsigned int (__fastcall **)(__int64, __int64, __int64, __int64))(v7 + 48))(a1, 1i64, a3, a5) )
  {
    sub_180009218(3u, v10, a5);
LABEL_5:
    v6 = 0;
    goto LABEL_6;
  }
  if ( !(unsigned int)sub_18009300C(v12, v10, a5)
    || !(*(unsigned int (__fastcall **)(__int64, __int64, __int64, __int64 *, __int64))(*(_QWORD *)(a3 + 64) + 40i64))(
          a1,
          a2,
          a3,
          v12,
          a5) )
  {
    goto LABEL_5;
  }
LABEL_6:
  if ( v13 )
    sub_180009288(v12[0]);
  return v6;
}

_BOOL8 __fastcall sub_18008E440(__int64 a1, __int64 a2, __int64 a3, __int64 a4, __int64 *a5, __int64 a6, __int64 a7)
{
  __int64 v9; // rdi
  __int64 v10; // rbp
  int v11; // eax
  __int64 v12; // r14
  __int64 v13; // rsi
  __int64 v14; // r15
  BOOL v15; // ebx
  __int64 v16; // r12
  __int64 v18[2]; // [rsp+40h] [rbp-48h] BYREF
  int v19; // [rsp+50h] [rbp-38h]

  v18[0] = a6;
  v9 = a2;
  v10 = *a5;
  v18[1] = a5[3];
  v19 = 0;
  v11 = sub_18009300C(v18, a2, a7);
  v12 = v18[0];
  if ( v11 )
  {
    v13 = 0i64;
    v14 = a3 - v9;
    v15 = 1;
    v16 = a1 - v9;
    do
    {
      if ( v13 == v10 )
        break;
      v15 = (*(__int64 (__fastcall **)(__int64, __int64, __int64, __int64 *, __int64, __int64))(a5[8] + 64))(
              v16 + v9,
              v9,
              v14 + v9,
              a5,
              v12,
              a7) != 0;
      v13 += v10;
      v9 += 8 * v10;
    }
    while ( v15 );
  }
  else
  {
    v15 = 0;
  }
  if ( v19 )
    sub_180009288(v12);
  return v15;
}

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

__int64 __fastcall sub_180015DF0(int *a1, unsigned int *a2)
{
  int v2; // r8d
  unsigned int *v3; // rbx
  int v4; // ebp
  int v5; // eax
  int v6; // r10d
  int v7; // r11d
  int v8; // r9d
  unsigned int v9; // edi
  unsigned int v10; // esi
  unsigned int v11; // r14d
  int v12; // ecx
  unsigned int v13; // r15d
  unsigned int v14; // r12d
  int v15; // edx
  int v16; // r10d
  int v17; // r8d
  unsigned __int32 v18; // edi
  int v19; // r9d
  int v20; // r10d
  int v21; // eax
  int v22; // r11d
  int v23; // r9d
  int v24; // ecx
  int v25; // r10d
  unsigned __int32 v26; // r14d
  int v27; // r11d
  unsigned __int32 v28; // r15d
  int v29; // edx
  int v30; // ecx
  int v31; // r11d
  unsigned __int32 v32; // r12d
  int v33; // r8d
  int v34; // ecx
  unsigned __int32 v35; // ebp
  int v36; // edx
  int v37; // r9d
  int v38; // ecx
  int v39; // r8d
  unsigned __int32 v40; // r13d
  int v41; // r10d
  int v42; // ecx
  int v43; // r9d
  int v44; // r11d
  int v45; // ecx
  int v46; // r10d
  int v47; // edx
  int v48; // ecx
  int v49; // r11d
  int v50; // r8d
  int v51; // ecx
  int v52; // edx
  int v53; // r9d
  int v54; // ecx
  int v55; // r8d
  int v56; // r10d
  int v57; // ecx
  int v58; // r9d
  int v59; // r11d
  int v60; // ecx
  int v61; // r10d
  int v62; // edx
  int v63; // ecx
  int v64; // r11d
  int v65; // r8d
  int v66; // ecx
  int v67; // edx
  int v68; // r9d
  int v69; // r8d
  unsigned int v70; // r10d
  int v71; // r10d
  unsigned int v72; // r11d
  int v73; // r9d
  unsigned int v74; // ecx
  int v75; // eax
  int v76; // r10d
  int v77; // r11d
  int v78; // edx
  int v79; // ecx
  int v80; // r11d
  int v81; // r8d
  unsigned __int32 v82; // r12d
  int v83; // r8d
  int v84; // edi
  int v85; // ebp
  int v86; // r9d
  int v87; // edx
  int v88; // ecx
  int v89; // r8d
  int v90; // r10d
  int v91; // r13d
  int v92; // ecx
  int v93; // r9d
  int v94; // r11d
  int v95; // ecx
  int v96; // r10d
  int v97; // edx
  int v98; // ecx
  int v99; // r11d
  int v100; // r8d
  int v101; // ecx
  int v102; // edx
  int v103; // r9d
  int v104; // ecx
  int v105; // r8d
  int v106; // r10d
  int v107; // ecx
  int v108; // r9d
  int v109; // r11d
  int v110; // ecx
  int v111; // r10d
  int v112; // edx
  int v113; // ecx
  int v114; // r11d
  int v115; // r8d
  int v116; // r12d
  int v117; // ecx
  int v118; // edx
  int v119; // r9d
  int v120; // r15d
  int v121; // ecx
  int v122; // r8d
  int v123; // r10d
  int v124; // ecx
  int v125; // r9d
  int v126; // r11d
  int v127; // ecx
  int v128; // r10d
  int v129; // edx
  int v130; // ecx
  int v131; // r11d
  int v132; // r8d
  int v133; // r9d
  int v134; // edx
  int v135; // r14d
  int v136; // edi
  int v137; // ecx
  int v138; // r8d
  int v139; // esi
  int v140; // r13d
  int v141; // r10d
  int v142; // ecx
  int v143; // r9d
  int v144; // r11d
  int v145; // r10d
  int v146; // r8d
  int v147; // r14d
  int v148; // r11d
  unsigned int v149; // ecx
  unsigned int v150; // eax
  int v151; // ecx
  int v152; // eax
  int v153; // edi
  int v154; // r9d
  unsigned int v155; // ecx
  unsigned int v156; // eax
  int v157; // r8d
  int v158; // r10d
  unsigned int v159; // ecx
  int v160; // eax
  int v161; // r9d
  int v162; // r11d
  int v163; // r10d
  int v164; // esi
  int v165; // ecx
  int v166; // r11d
  unsigned int v167; // eax
  int v168; // r8d
  unsigned int v169; // ecx
  int v170; // ecx
  unsigned int v171; // eax
  int v172; // r9d
  unsigned int v173; // ecx
  int v174; // r8d
  int v175; // r10d
  unsigned int v176; // ecx
  int v177; // r9d
  int v178; // r11d
  int v179; // ebp
  int v180; // r12d
  int v181; // ecx
  int v182; // r10d
  int v183; // eax
  int v184; // ecx
  int v185; // r11d
  int v186; // esi
  int v187; // edi
  int v188; // r8d
  int v189; // ecx
  unsigned int v190; // eax
  int v191; // r9d
  unsigned int v192; // ecx
  int v193; // r8d
  int v194; // r10d
  int v195; // r12d
  unsigned int v196; // ecx
  int v197; // r9d
  int v198; // r11d
  int v199; // ecx
  int v200; // r10d
  int v201; // eax
  int v202; // edi
  int v203; // ecx
  int v204; // r11d
  int v205; // r8d
  int v206; // ecx
  int v207; // edi
  int v208; // r9d
  int v209; // ecx
  int v210; // r10d
  unsigned int v211; // ecx
  int v212; // r9d
  int v213; // eax
  int v214; // r11d
  unsigned int v215; // ecx
  int v216; // r10d
  int v217; // r8d
  int v218; // ecx
  int v219; // eax
  int v220; // r11d
  int v221; // r8d
  int v222; // edi
  int v223; // edx
  int v224; // eax
  int v225; // r8d
  int v226; // r9d
  int v227; // eax
  int v228; // edx
  int v229; // r10d
  int v230; // eax
  int v231; // r9d
  int v232; // r12d
  int v233; // r11d
  int v234; // eax
  int v235; // r10d
  int v236; // r13d
  int v237; // r8d
  int v238; // eax
  int v239; // r11d
  int v240; // edx
  int v241; // eax
  int v242; // r8d
  int v243; // r9d
  int v244; // eax
  int v245; // edx
  int v246; // r10d
  int v247; // esi
  int v248; // eax
  int v249; // r9d
  int v250; // r11d
  int v251; // ecx
  int v252; // eax
  int v253; // r10d
  int v254; // eax
  int v255; // r11d
  int v256; // edi
  int v257; // r15d
  int v258; // eax
  int v259; // esi
  int v260; // r14d
  unsigned int v261; // r9d
  int v262; // ebp
  int v263; // r14d
  int v264; // edx
  int v265; // edi
  int v266; // eax
  int v267; // esi
  unsigned int v268; // r8d
  int v269; // ebp
  int v270; // eax
  int v271; // r9d
  int v272; // eax
  int v273; // r8d
  int v274; // r11d
  unsigned int v275; // eax
  int v276; // r10d
  int v277; // eax
  int v278; // r11d
  unsigned int v279; // r9d
  unsigned int v280; // eax
  int v281; // r10d
  int v282; // r8d
  int v283; // ecx
  __int64 result; // rax
  int v285; // [rsp+0h] [rbp-88h]
  int v286; // [rsp+0h] [rbp-88h]
  int v287; // [rsp+0h] [rbp-88h]
  int v288; // [rsp+0h] [rbp-88h]
  int v289; // [rsp+0h] [rbp-88h]
  unsigned __int32 v290; // [rsp+4h] [rbp-84h]
  int v291; // [rsp+4h] [rbp-84h]
  int v292; // [rsp+4h] [rbp-84h]
  int v293; // [rsp+4h] [rbp-84h]
  unsigned __int32 v294; // [rsp+8h] [rbp-80h]
  int v295; // [rsp+8h] [rbp-80h]
  int v296; // [rsp+8h] [rbp-80h]
  int v297; // [rsp+8h] [rbp-80h]
  int v298; // [rsp+8h] [rbp-80h]
  int v299; // [rsp+Ch] [rbp-7Ch]
  int v300; // [rsp+Ch] [rbp-7Ch]
  int v301; // [rsp+Ch] [rbp-7Ch]
  int v302; // [rsp+10h] [rbp-78h]
  int v303; // [rsp+10h] [rbp-78h]
  int v304; // [rsp+10h] [rbp-78h]
  int v305; // [rsp+14h] [rbp-74h]
  int v306; // [rsp+14h] [rbp-74h]
  int v307; // [rsp+14h] [rbp-74h]
  int v308; // [rsp+18h] [rbp-70h]
  int v309; // [rsp+18h] [rbp-70h]
  int v310; // [rsp+18h] [rbp-70h]
  unsigned __int32 v311; // [rsp+1Ch] [rbp-6Ch]
  int v312; // [rsp+1Ch] [rbp-6Ch]
  int v313; // [rsp+1Ch] [rbp-6Ch]
  int v314; // [rsp+1Ch] [rbp-6Ch]
  int v315; // [rsp+20h] [rbp-68h]
  int v316; // [rsp+20h] [rbp-68h]
  int v317; // [rsp+20h] [rbp-68h]
  int v318; // [rsp+20h] [rbp-68h]
  unsigned __int32 v319; // [rsp+24h] [rbp-64h]
  int v320; // [rsp+24h] [rbp-64h]
  int v321; // [rsp+24h] [rbp-64h]
  int v322; // [rsp+24h] [rbp-64h]
  unsigned __int32 v323; // [rsp+28h] [rbp-60h]
  int v324; // [rsp+28h] [rbp-60h]
  int v325; // [rsp+28h] [rbp-60h]
  unsigned __int32 v326; // [rsp+2Ch] [rbp-5Ch]
  int v327; // [rsp+2Ch] [rbp-5Ch]
  int v328; // [rsp+2Ch] [rbp-5Ch]
  unsigned __int32 v329; // [rsp+30h] [rbp-58h]
  int v330; // [rsp+30h] [rbp-58h]
  int v331; // [rsp+30h] [rbp-58h]
  int v332; // [rsp+34h] [rbp-54h]
  int v333; // [rsp+34h] [rbp-54h]
  unsigned __int32 v335; // [rsp+98h] [rbp+10h]
  int v336; // [rsp+98h] [rbp+10h]
  int v337; // [rsp+98h] [rbp+10h]
  int v338; // [rsp+98h] [rbp+10h]
  unsigned __int32 v339; // [rsp+A0h] [rbp+18h]
  int v340; // [rsp+A0h] [rbp+18h]
  int v341; // [rsp+A0h] [rbp+18h]
  int v342; // [rsp+A0h] [rbp+18h]
  unsigned __int32 v343; // [rsp+A8h] [rbp+20h]
  int v344; // [rsp+A8h] [rbp+20h]
  int v345; // [rsp+A8h] [rbp+20h]
  int v346; // [rsp+A8h] [rbp+20h]

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