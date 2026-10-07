pidgenx.dll 10.0.26040.1000 (x64) - PKEY2005 validator function map
====================================================================
Root: sub_18008D85C(keyObj, pubKey, pubKeySize) -> HRESULT
  keyObj +0x30 = 1 (have raw key), +0x38 = 16 raw key bytes
  on success: +0x34 = 1, +0x48 = M (6 bytes)
  0 = valid, 0x80041051 = not this key, 0x80042001 = blob did not parse

Columns:  address | C# name (PidKeyData.cs) | name in PidKeyData.md | confidence
Confidence: confirmed = seen in a real run,
            emulated  = the function itself was executed in an emulator on random
                        inputs and its output matched independent arithmetic,
            high      = constant / clear structure / exact match to PkeyLib source,
            likely / guess = inferred from call order and arguments, not traced.
(No "likely"/"guess" remain in the main tree; see the resolution notes inline.)

--------------------------------------------------------------------
sub_18008D85C        PKeyCalc.TryPubKey                                   confirmed
|
+- sub_1800876C8     PubKeyParser.Parse (wrapper, allocates context)      high
|  |                 .md: fPubkeyParser
|  +- sub_180087274  Parse: outer header 0x44556677, 14 points,           high
|  |  |              pairing value (points/pairing -> Montgomery via 8F5E8)
|  |  +- sub_180085B88  Parse: field data 0x00112233                      high
|  |     |              (p, n, radices, polynomials, a, b); builds the
|  |     |              Fp/K3/K6 field tower (85B30, 8EE44, 8E5A8, 92BA8)
|  |     +- sub_18008EE44  create_modulus: p^-1 mod 2^64, R mod p,        emulated
|  |                       picks the Montgomery multiply by size
|  +- sub_1800880A4  post-parse scalar setup                             high
|                    WAS "likely". REALLY: builds the M-radix table
|                    (Pi(H1Bases+1)) and reduced order into the key
|                    context (+0x10 bitlen, +0x20/48 order, +0x30 rem).
|                    Tail of fPubkeyParser; no separate C# function.
|
+- sub_180087ACC     PKeyCalc.TryCandidate                                high
|  |
|  +- sub_180090B74   new BigInteger(eb) (key bytes -> number)            high
|  |
|  +- sub_180089030   body of TryCandidate                                high
|  |  |               .md: fCalculateH1 / compute_h1_core
|  |  |
|  |  +- sub_18008854C  xT / keyByte lines + Curve.LiftX                  high
|  |  |  +- sub_180094D6C  B / Gf.P and Gf.Mod(B) in one call             emulated
|  |  |  |                 .md: mp_divrem_knuth (one division -> q and r)
|  |  |  +- sub_1800931E4  Fp.IsQR = Legendre symbol                      emulated
|  |  |  |                 WAS "likely". +1 QR / -1 non-residue,
|  |  |  |                 150/150 vs a^((p-1)/2).
|  |  |  +- sub_180095490  Fp.Sqrt = full Tonelli-Shanks                  emulated
|  |  |  |                 WAS "(indirect) likely". 150/150 vs python sqrt;
|  |  |  |                 p = 1 (mod 4) so no fast path (README 2.1).
|  |  |  +- sub_180093DB4  Pt6.Mul = ec scalar multiply k*P               high
|  |  |                    WAS "likely". double-and-add (ec_double 9AD44,
|  |  |                    ec_add 900C8/8FB54); order check n*T == O on T.
|  |  |
|  |  +- sub_18008ABC0  the h1[2], h1[3] lines                           high
|  |  |                 .md: mp_extract_byte_digits
|  |  +- sub_180088854  Pt6.From(x*inv2, y*inv2sq) = twist -> K6          high
|  |  |                 WAS "likely". Exactly your PkeyLib inv2/inv2sq
|  |  |                 lines; README 2.2 twist x'=x.t^-2, y'=y.t^-3, t^2=-2.
|  |  +- sub_1800912BC  TatePairing.Emb = K_embed (sub-field -> K6)       emulated
|  |  |                 WAS "guess". Fp->K6 = [x,0,0,0,0,0];
|  |  |                 K3->K6 = [a0,a1,a2,0,0,0]. 40/40.
|  |  +- sub_1800884C4  TatePairing.Pair (thin wrapper)                   high
|  |  |  +- sub_18008B428  TatePairing.Pair (the pairing itself)          high
|  |  |     |              .md: squared_tate_pairing (Miller loop)
|  |  |     +- sub_18008AD24  Miller doubling/addition + line eval        high
|  |  |
|  |  +- sub_180089528  H1Search.Solve (sets digit bounds, then search)   high
|  |     +- sub_18008A1E0  body of Solve: build table, sort, scan         high
|  |     +- sub_18008998C  the odometer loops in Solve (recursive)        high
|  |     |                 .md: mp_signed_block_loop
|  |     +- sub_180089F74  HashM + Probe + LowerBound                     high
|  |                       .md: sa_checksum4, sa_match_entry
|  |
|  +- sub_18008837C  PKeyCalc.ExtractM                                    high
|  |  |              .md: fExtractM
|  |  +- sub_18008AAB4  Horner loop inside ExtractM                       high
|  |                    .md: extract_scalar_digits
|  |
|  +- sub_180090ADC  ExtractMBytes (number -> bytes)                      high
|
+- sub_1800879C8     Confirmation-ID path (M supplied directly)           high
|  |                 WAS "no C# equivalent". README 3.6 last para: M known,
|  |                 so NO tree search - one point, one pairing, one compare.
|  +- sub_180088A50  split_M_to_digits (inverse of fExtractM)             high
|  |                 WAS "likely". calls split_digits (8ABC0) + horner (8AAB4).
|  +- sub_180088B7C  combine_point_pair_compare                           high
|                    WAS "likely". Q = sum v_i Q_i (map_point + Pt6.Mul
|                    93DB4), ONE tate_pairing (via 884C4), compare to
|                    stored pairing value. No-search version of the MITM.
|
+- sub_18008763C     (no C# equivalent) frees the parsed key              high

--------------------------------------------------------------------
Montgomery / multiply layer  (was "no single address")
--------------------------------------------------------------------
This IS resolved now. The field object's vtable is at (field_desc + 0x40);
README 4.4 "vtable slot 8" == the 8th qword == +0x40 == the field multiply.

  sub_18008E440  Kmul = Fp3/Fp6 multiply   .md: mp_slot_limb_loop       emulated
                 over K3 == your Fp3 operator*, over K6 == Fp6 operator*,
                 over Fp == a*b mod p. One K6 Kmul = 18 montmuls.
  sub_180091740  Kext_mul (extension-field worker under Kmul)            high
  sub_1800949C8  Kmuladd = f1*f2 + f3 in the field                       emulated
  sub_180093A14  Kinvert = field inverse (Fp*/Fp3/Fp6)                   emulated
  field vtable (desc+0x40): +00 add  +10 pow  +48 square  +50 x^p
                            +58 neg  +80 sub                             emulated

  Beneath the field layer, scalar Montgomery multiply (your Fpm.Mul):
  sub_180002460  montmul_asm  = Fpm.Mul   general, any modulus >=2 limbs  emulated
                 CIOS Montgomery multiply; 2-limb case is R=2^128, same
                 shape as your Fpx. (This is your sub_180002460.)
  sub_180002CE0  montmul256   = Fpm.Mul   256-bit (4-limb) specialisation emulated
  sub_180002690  montmul1024  = Fpm.Mul   1024-bit (16-limb)             high
  sub_180096C20  montmul_c    = Fpm.Mul   1-limb C fallback              emulated
  sub_180096A3C  picks which of the above by limb count / bit size       emulated
  sub_18008F14C  mod_mul      range-checks a,b < p then -> [modulus+0x60] emulated
  sub_18008F2A4  mod_mul_nocheck (skips the range check)                 emulated
  sub_18008F360  mod_shift    a * 2^k mod p (signed k)                   emulated
  mp_b_sub_exp_loop (README) = field pow (K6 exponent slot +0x10) = your PowBig

  Stacking (measured by emulation): 1 K6 Kmul = 18 montmul; 1 K6 inverse
  = 72; 1 K6 pow(180-bit) = 4284. Everything bottoms out in sub_180002460,
  matching README 6.2 (MITM field multiplies ~93% of total time).

--------------------------------------------------------------------
General helpers seen all over this tree
  sub_180009254, sub_180092FD0   allocate (092FD0 = alloc n limbs)
  sub_180009288                  free
  sub_180009218                  set HRESULT on the error/context object
  sub_18009300C                  get scratch temps from the field context
  sub_1800038E8, sub_180003B30   error / trace logging of the HRESULT
  sub_18009E001/E00D/E019        memcpy / memmove / memset thunks

--------------------------------------------------------------------
Above the root (how the DLL gets here)   [chain spot-checked, unchanged]
  GetPKeyData / PidGenX2
   -> sub_180015270   create config object (vtable 0x1800A02D0)
   -> sub_18000C970   load pkeyconfig            (vtable +40)
   -> sub_18000D160 -> sub_180009A24 -> sub_180009338   dispatcher (vtable +64)
       -> sub_1800090B0   key string -> key object (base-24 decode)
       -> sub_18000E8E8   binary search of public-key table by GroupId
                          (only when the group is already known)
       -> sub_180014DA4   try candidate public keys (loop or worker threads)
           -> sub_180014224   worker thread body
           -> sub_18001506C   one attempt: AlgorithmId -> object -> validate
               -> sub_180009EBC -> sub_18000ED00   AlgorithmId string -> id
               -> sub_18000D828   factory
                    pkey/2005      -> sub_18008DB38 (vtable 0x1800A44C8)
                    pkey/2009      -> sub_18008E04C
                    pkey/980       -> sub_18008D5FC
                    pkey/985, 986  -> sub_18008D6E4 (vtable 0x1800A4468)
               -> sub_18008D7D0   pkey/2005 validate method   [verified -> D85C]
                    -> sub_18008D85C   (the root of this map)
                    -> sub_18008D9A0   M -> upgrade / serial / security
                         -> sub_18008D420   upgrade bit and serial
       -> sub_180014730   build the final result object

M layout (6 bytes at keyObj +0x48, little-endian)
  bit 0        upgrade
  bits 1-30    serial (channel * 1000000 + sequence)
  bits 31-40   security value

--------------------------------------------------------------------
Not executed end-to-end (named by structure, not run)
  sub_18008B428 (tate_pairing Miller loop), sub_18008AD24 (its step), and the
  ec_double/ec_add split (sub_18009AD44 / sub_1800900C8). The field +
  Montgomery layer under them was verified by emulation; the pairing as a
  whole was not run. Microsoft's pidgenx.pdb (GUID
  72919320-C6C9-3841-B23C-F51C99789E97, age 1) carries the real symbols;
  the MS symbol server was not reachable from this environment.
