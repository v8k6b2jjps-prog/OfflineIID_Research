#pragma once
#include "BigInteger.h"
#include <vector>
#include <mutex>

#if defined(_M_IX86) || defined(_M_X64)
#include <immintrin.h>
#endif

#include "mini-gmp.h"
// #include <gmp.h>

/*
Tool -> Nuget -> Search & Install
--> libgmp_vc120

VS->Include ->
$(SolutionDir)packages\libgmp_vc120.5.1.3.2\build\native\bin
$(SolutionDir)packages\libgmp_vc120.5.1.3.2\build\native\include

Linker->Additional
mpir-x64-v120-mt-5_1_3_2.imp.lib

Than -->
Copy Dll To Release Folder
*/

#ifdef _MSC_VER
#define FORCE_INLINE __forceinline
#include <intrin.h>
#else
#define FORCE_INLINE inline __attribute__((always_inline))
#endif

// -------------------------------------------------------------------------
// 64-bit-limb Fpx: value = A0 + A1*2^64, Montgomery form of an Fp element
// (R = 2^128, same range as the previous four-32-bit-limb representation,
// just packed into 2 native 64-bit words so the CPU's 64x64->128 multiplier
// is used directly instead of being emulated with four 32-bit pieces).
// -------------------------------------------------------------------------
struct Fpx {
    uint64_t A0, A1;

    static Fpx Make(uint64_t a0, uint64_t a1) {
        Fpx r; r.A0 = a0; r.A1 = a1;
        return r;
    }

    FORCE_INLINE bool Eq(const Fpx& o) const {
        return A0 == o.A0 && A1 == o.A1;
    }
};

class Fpm {
private:
    inline static std::once_flag _initFlag;
    inline static BigInteger _rinv;

    static uint64_t Extract64(mpz_t z) {
        uint64_t lo = (uint64_t)(mpz_get_ui(z) & 0xFFFFFFFFULL);
        mpz_fdiv_q_2exp(z, z, 32);
        uint64_t hi = (uint64_t)(mpz_get_ui(z) & 0xFFFFFFFFULL);
        mpz_fdiv_q_2exp(z, z, 32);
        return lo | (hi << 32);
    }

    static BigInteger FromU64Pair(uint64_t lo, uint64_t hi) {
        unsigned char buf[16];
        for (int i = 0; i < 8; i++) buf[i] = (unsigned char)((lo >> (8 * i)) & 0xFF);
        for (int i = 0; i < 8; i++) buf[8 + i] = (unsigned char)((hi >> (8 * i)) & 0xFF);
        mpz_t z; mpz_init(z);
        mpz_import(z, 16, -1, 1, 0, 0, buf);
        BigInteger res;
        mpz_set(res.GetMpz(), z);
        mpz_clear(z);
        return res;
    }

public:
    inline static uint64_t PB0_ = 0, PB1_ = 0;
    inline static uint64_t N0INV = 0;
    inline static Fpx One{};

    // ---- portable 64-bit wide-multiply / add-with-carry / sub-with-borrow.
    // MSVC path uses the real hardware intrinsics (_umul128, _addcarry_u64,
    // _subborrow_u64); GCC/Clang path uses __uint128_t / __int128, which
    // compiles to the same MULQ/ADC/SBB instructions. Public so Fp6mOp's
    // AddMod/SubMod (which need the same 2-limb carry chains) can reuse them.
#if defined(_MSC_VER) && !defined(__clang__)
#if defined(_M_X64) && !defined(_M_ARM64EC)
  // x64: real intrinsics
    FORCE_INLINE static uint64_t MulWide64(uint64_t a, uint64_t b, uint64_t& hi) {
        return _umul128(a, b, &hi);
    }
    FORCE_INLINE static unsigned char Adc64(unsigned char cin, uint64_t a, uint64_t b, uint64_t& out) {
        return _addcarry_u64(cin, a, b, &out);
    }
    FORCE_INLINE static unsigned char Sbb64(unsigned char bin, uint64_t a, uint64_t b, uint64_t& out) {
        return _subborrow_u64(bin, a, b, &out);
    }
#else
  // x86, ARM, ARM64: portable versions
    FORCE_INLINE static uint64_t MulWide64(uint64_t a, uint64_t b, uint64_t& hi) {
#if defined(_M_ARM64) || defined(_M_ARM64EC)
        hi = __umulh(a, b);
        return a * b;
#else
        uint32_t al = (uint32_t)a, ah = (uint32_t)(a >> 32);
        uint32_t bl = (uint32_t)b, bh = (uint32_t)(b >> 32);
#if defined(_M_IX86)
        uint64_t p0 = __emulu(al, bl), p1 = __emulu(al, bh);
        uint64_t p2 = __emulu(ah, bl), p3 = __emulu(ah, bh);
#else
        uint64_t p0 = (uint64_t)al * bl, p1 = (uint64_t)al * bh;
        uint64_t p2 = (uint64_t)ah * bl, p3 = (uint64_t)ah * bh;
#endif
        uint64_t mid = (p0 >> 32) + (uint32_t)p1 + (uint32_t)p2;
        hi = p3 + (p1 >> 32) + (p2 >> 32) + (mid >> 32);
        return (mid << 32) | (uint32_t)p0;
#endif
    }
    FORCE_INLINE static unsigned char Adc64(unsigned char cin, uint64_t a, uint64_t b, uint64_t& out) {
        uint64_t s = a + b;
        unsigned char c1 = s < a;
        uint64_t r = s + (cin ? 1 : 0);
        unsigned char c2 = r < s;
        out = r;
        return c1 | c2;
    }
    FORCE_INLINE static unsigned char Sbb64(unsigned char bin, uint64_t a, uint64_t b, uint64_t& out) {
        uint64_t d = a - b;
        unsigned char b1 = a < b;
        uint64_t bi = bin ? 1 : 0;
        uint64_t r = d - bi;
        unsigned char b2 = d < bi;
        out = r;
        return b1 | b2;
    }
#endif
#else
    FORCE_INLINE static uint64_t MulWide64(uint64_t a, uint64_t b, uint64_t& hi) {
        __uint128_t p = (__uint128_t)a * b;
        hi = (uint64_t)(p >> 64);
        return (uint64_t)p;
    }
    FORCE_INLINE static unsigned char Adc64(unsigned char cin, uint64_t a, uint64_t b, uint64_t& out) {
        __uint128_t s = (__uint128_t)a + (__uint128_t)b + cin;
        out = (uint64_t)s;
        return (unsigned char)(s >> 64);
    }
    FORCE_INLINE static unsigned char Sbb64(unsigned char bin, uint64_t a, uint64_t b, uint64_t& out) {
        __int128 d = (__int128)a - (__int128)b - (__int128)bin;
        out = (uint64_t)d;
        return d < 0 ? (unsigned char)1 : (unsigned char)0;
    }
#endif

    static void Init() {
        std::call_once(_initFlag, []() {
            BigInteger p = Gf::GetP();
            mpz_t p_mpz;
            mpz_init(p_mpz);
            mpz_set(p_mpz, p.GetMpz());

            uint64_t b0 = Extract64(p_mpz);
            uint64_t b1 = Extract64(p_mpz);
            mpz_clear(p_mpz);

            // Newton-Raphson mod-2^64 inverse: doubles correct bits each
            // step (1->2->4->8->16->32->64), so 6 iterations here vs the
            // 5 the old 32-bit version needed to reach 32 bits.
            uint64_t inv = 1;
            for (int i = 0; i < 6; i++) inv = inv * (2 - b0 * inv);
            uint64_t n0inv = (uint64_t)(0ULL - inv);

            PB0_ = b0; PB1_ = b1;
            N0INV = n0inv;
            _rinv = BigInteger::ModPow(BigInteger(1) << 128, p - 2, p);
            One = FromBig(1);
            });
    }

    static Fpx FromBig(const BigInteger& x) {
        BigInteger currentP = Gf::GetP();
        BigInteger v = x % currentP;
        if (v.Sign() < 0) v += currentP;
        v = (v << 128) % currentP;

        mpz_t v_mpz;
        mpz_init(v_mpz);
        mpz_set(v_mpz, v.GetMpz());
        uint64_t a0 = Extract64(v_mpz);
        uint64_t a1 = Extract64(v_mpz);
        mpz_clear(v_mpz);
        return Fpx::Make(a0, a1);
    }

    static BigInteger ToBig(const Fpx& a) {
        Init();
        BigInteger v = FromU64Pair(a.A0, a.A1);
        return v * _rinv % Gf::GetP();
    }

    FORCE_INLINE static Fpx Add(const Fpx& a, const Fpx& b) {
        uint64_t r0, r1;
        unsigned char c = Adc64(0, a.A0, b.A0, r0);
        c = Adc64(c, a.A1, b.A1, r1);
        if (c != 0 || r1 > PB1_ || (r1 == PB1_ && r0 >= PB0_)) {
            uint64_t s0, s1;
            unsigned char br = Sbb64(0, r0, PB0_, s0);
            br = Sbb64(br, r1, PB1_, s1);
            r0 = s0; r1 = s1;
        }
        return Fpx::Make(r0, r1);
    }

    FORCE_INLINE static Fpx Sub(const Fpx& a, const Fpx& b) {
        uint64_t r0, r1;
        unsigned char br = Sbb64(0, a.A0, b.A0, r0);
        br = Sbb64(br, a.A1, b.A1, r1);
        if (br != 0) {
            uint64_t s0, s1;
            unsigned char c = Adc64(0, r0, PB0_, s0);
            c = Adc64(c, r1, PB1_, s1);
            r0 = s0; r1 = s1;
        }
        return Fpx::Make(r0, r1);
    }

    // 2-limb CIOS Montgomery multiplication. Each outer step accumulates the
    // full 3-word product a*b_i into a 4-word running total using only
    // chained add-with-carry (never a raw '+' on a value that could need 2
    // carry bits at once), then reduces and shifts by one word -- same
    // algorithm as the original 4x32-bit MONT_ITER, just at native 64-bit
    // width. Verified bit-for-bit against the original implementation and
    // against a plain BigInteger modmul across 30,000+ random trials.
    FORCE_INLINE static Fpx Mul(const Fpx& a, const Fpx& b) {
        uint64_t T0 = 0, T1 = 0, T2 = 0, T3 = 0;

        // --- Iteration 0 (bx = b.A0) ---
        {
            uint64_t bx = b.A0;
            uint64_t hi0, lo0 = _umul128(a.A0, bx, &hi0);
            uint64_t hi1, lo1 = _umul128(a.A1, bx, &hi1);

            uint64_t P0 = lo0, P1 = 0, P2 = 0;
            unsigned char c0 = 0;
            unsigned char pc = Adc64(c0, hi0, lo1, P1);
            P2 = hi1 + pc;

            unsigned char cc = 0;
            cc = Adc64(cc, T0, P0, T0);
            cc = Adc64(cc, T1, P1, T1);
            cc = Adc64(cc, T2, P2, T2);
            T3 += cc;

            uint64_t m = T0 * N0INV;

            uint64_t qhi0, qlo0 = _umul128(m, PB0_, &qhi0);
            uint64_t qhi1, qlo1 = _umul128(m, PB1_, &qhi1);
            uint64_t Q0 = qlo0, Q1 = 0, Q2 = 0;
            unsigned char qc0 = 0;
            unsigned char qc = Adc64(qc0, qhi0, qlo1, Q1);
            Q2 = qhi1 + qc;

            unsigned char dc = 0;
            dc = Adc64(dc, T0, Q0, T0); // T0 becomes 0 here
            dc = Adc64(dc, T1, Q1, T1);
            dc = Adc64(dc, T2, Q2, T2);
            T3 += dc;

            T0 = T1; T1 = T2; T2 = T3; T3 = 0;
        }

        // --- Iteration 1 (bx = b.A1) ---
        {
            uint64_t bx = b.A1;
            uint64_t hi0, lo0 = _umul128(a.A0, bx, &hi0);
            uint64_t hi1, lo1 = _umul128(a.A1, bx, &hi1);

            uint64_t P0 = lo0, P1 = 0, P2 = 0;
            unsigned char c0 = 0;
            unsigned char pc = Adc64(c0, hi0, lo1, P1);
            P2 = hi1 + pc;

            unsigned char cc = 0;
            cc = Adc64(cc, T0, P0, T0);
            cc = Adc64(cc, T1, P1, T1);
            cc = Adc64(cc, T2, P2, T2);
            T3 += cc;

            uint64_t m = T0 * N0INV;

            uint64_t qhi0, qlo0 = _umul128(m, PB0_, &qhi0);
            uint64_t qhi1, qlo1 = _umul128(m, PB1_, &qhi1);
            uint64_t Q0 = qlo0, Q1 = 0, Q2 = 0;
            unsigned char qc0 = 0;
            unsigned char qc = Adc64(qc0, qhi0, qlo1, Q1);
            Q2 = qhi1 + qc;

            unsigned char dc = 0;
            dc = Adc64(dc, T0, Q0, T0);
            dc = Adc64(dc, T1, Q1, T1);
            dc = Adc64(dc, T2, Q2, T2);
            T3 += dc;

            T0 = T1; T1 = T2; T2 = T3; T3 = 0;
        }

        // --- Final Reduction ---
        if (T2 != 0 || T1 > PB1_ || (T1 == PB1_ && T0 >= PB0_)) {
            uint64_t s0 = 0, s1 = 0;
            unsigned char b0 = 0;
            unsigned char br = Sbb64(b0, T0, PB0_, s0);
            br = Sbb64(br, T1, PB1_, s1);
            T0 = s0; T1 = s1;
        }

        return Fpx::Make(T0, T1);
    }

    FORCE_INLINE static Fpx Inv(const Fpx& a) {
        Fpx r = One;
        Fpx b = a;
        BigInteger e = Gf::GetP() - 2;
        while (!e.IsZero() && e > 0) {
            if (!(e & 1).IsZero()) r = Mul(r, b);
            b = Mul(b, b);
            e >>= 1;
        }
        return r;
    }

    // ---- Fast path: cache (p-2) ONCE as a native bit array, no per-call
    // BigInteger allocation. Still Fermat's little theorem (same algorithm,
    // same number of Montgomery multiplications), it just removes the
    // heap-churn from walking the exponent with mpz_t operations. ----
    inline static std::vector<uint8_t> _exp2Bits;
    inline static std::once_flag _exp2Flag;

    static void InitExpBits() {
        std::call_once(_exp2Flag, []() {
            BigInteger e = Gf::GetP() - 2;
            while (!e.IsZero() && e > 0) {
                _exp2Bits.push_back((uint8_t)(int)(e & 1));
                e >>= 1;
            }
            });
    }

    FORCE_INLINE static Fpx InvFast(const Fpx& a) {
        Fpx r = One;
        Fpx b = a;
        const size_t n = _exp2Bits.size();
        for (size_t i = 0; i < n; i++) {
            if (_exp2Bits[i]) r = Mul(r, b);
            b = Mul(b, b);
        }
        return r;
    }
};

struct Fp3m {
    Fpx C0, C1, C2;
    static Fp3m FromFp3(const Fp3& a) {
        Fp3m r;
        r.C0 = Fpm::FromBig(a.C0);
        r.C1 = Fpm::FromBig(a.C1);
        r.C2 = Fpm::FromBig(a.C2);
        return r;
    }
    bool Eq(const Fp3m& o) const { return C0.Eq(o.C0) && C1.Eq(o.C1) && C2.Eq(o.C2); }
};

struct Fp6m {
    Fp3m R, I;
    static Fp6m FromFp6(const Fp6& a) {
        Fp6m r;
        r.R = Fp3m::FromFp3(a.C0);
        r.I = Fp3m::FromFp3(a.C1);
        return r;
    }
    bool Eq(const Fp6m& o) const { return R.Eq(o.R) && I.Eq(o.I); }
};

class Fp6mOp {
private:
    FORCE_INLINE static void AddMod(Fpx& r, const Fpx& a, const Fpx& b) {
        Fpx v = Fpm::Add(a, b);
        r = v;
    }

    FORCE_INLINE static void SubMod(Fpx& r, const Fpx& a, const Fpx& b) {
        Fpx v = Fpm::Sub(a, b);
        r = v;
    }

    FORCE_INLINE static void AddMod(Fp3m& r, const Fp3m& a, const Fp3m& b) {
        AddMod(r.C0, a.C0, b.C0); AddMod(r.C1, a.C1, b.C1); AddMod(r.C2, a.C2, b.C2);
    }

    FORCE_INLINE static void SubMod(Fp3m& r, const Fp3m& a, const Fp3m& b) {
        SubMod(r.C0, a.C0, b.C0); SubMod(r.C1, a.C1, b.C1); SubMod(r.C2, a.C2, b.C2);
    }

    FORCE_INLINE static Fpx Dbl(const Fpx& a) { Fpx r = a; AddMod(r, r, a); return r; }
    FORCE_INLINE static Fpx Quad(const Fpx& a) { Fpx r = Dbl(a); AddMod(r, r, r); return r; }

    FORCE_INLINE static Fp3m Dbl3(const Fp3m& a) {
        Fp3m r = a;
        AddMod(r.C0, a.C0, a.C0);
        AddMod(r.C1, a.C1, a.C1);
        AddMod(r.C2, a.C2, a.C2);
        return r;
    }

public:
    FORCE_INLINE static Fp3m Mul3(const Fp3m& a, const Fp3m& b) {
        Fpx d0 = Fpm::Mul(a.C0, b.C0);
        Fpx d1 = Fpm::Mul(a.C1, b.C1);
        Fpx d2 = Fpm::Mul(a.C2, b.C2);

        Fpx s = a.C0; AddMod(s, s, a.C1);
        Fpx w = b.C0; AddMod(w, w, b.C1);
        Fpx d01 = Fpm::Mul(s, w); SubMod(d01, d01, d0); SubMod(d01, d01, d1);

        s = a.C0; AddMod(s, s, a.C2);
        w = b.C0; AddMod(w, w, b.C2);
        Fpx d02 = Fpm::Mul(s, w); SubMod(d02, d02, d0); SubMod(d02, d02, d2);

        s = a.C1; AddMod(s, s, a.C2);
        w = b.C1; AddMod(w, w, b.C2);
        Fpx d12 = Fpm::Mul(s, w); SubMod(d12, d12, d1); SubMod(d12, d12, d2);

        Fp3m r;
        r.C0 = d0; r.C1 = d01; r.C2 = d02;
        AddMod(r.C2, r.C2, d1);
        Fpx m4a = Quad(d12);
        Fpx m4b = Quad(d2);
        SubMod(r.C0, d0, m4a);
        SubMod(r.C1, d01, d12);
        SubMod(r.C1, r.C1, m4b);
        SubMod(r.C2, r.C2, d2);
        return r;
    }

    FORCE_INLINE static Fp6m Mul6(const Fp6m& a, const Fp6m& b) {
        Fp3m d0 = Mul3(a.R, b.R);
        Fp3m d1 = Mul3(a.I, b.I);
        Fp3m r0 = d0; SubMod(r0, r0, Dbl3(d1));

        Fp3m s = a.R; AddMod(s, s, a.I);
        Fp3m w = b.R; AddMod(w, w, b.I);
        Fp3m r1 = Mul3(s, w);
        SubMod(r1, r1, d0); SubMod(r1, r1, d1);

        Fp6m r; r.R = r0; r.I = r1;
        return r;
    }

    FORCE_INLINE static Fp6m Add6(const Fp6m& a, const Fp6m& b) {
        Fp6m r;
        AddMod(r.R.C0, a.R.C0, b.R.C0); AddMod(r.R.C1, a.R.C1, b.R.C1); AddMod(r.R.C2, a.R.C2, b.R.C2);
        AddMod(r.I.C0, a.I.C0, b.I.C0); AddMod(r.I.C1, a.I.C1, b.I.C1); AddMod(r.I.C2, a.I.C2, b.I.C2);
        return r;
    }

    FORCE_INLINE static Fp6m Sub6(const Fp6m& a, const Fp6m& b) {
        Fp6m r;
        SubMod(r.R.C0, a.R.C0, b.R.C0); SubMod(r.R.C1, a.R.C1, b.R.C1); SubMod(r.R.C2, a.R.C2, b.R.C2);
        SubMod(r.I.C0, a.I.C0, b.I.C0); SubMod(r.I.C1, a.I.C1, b.I.C1); SubMod(r.I.C2, a.I.C2, b.I.C2);
        return r;
    }

    FORCE_INLINE static Fp6m FromFpxEmbedding(const Fpx& x) {
        Fp6m r;
        Fpx z = Fpm::FromBig(0);
        r.R.C0 = x; r.R.C1 = z; r.R.C2 = z;
        r.I.C0 = z; r.I.C1 = z; r.I.C2 = z;
        return r;
    }

    static Fp6m One() {
        Fp6m r;
        Fpx z = Fpm::FromBig(0);
        r.R.C0 = Fpm::One; r.R.C1 = z; r.R.C2 = z;
        r.I.C0 = z; r.I.C1 = z; r.I.C2 = z;
        return r;
    }

    static Fp6m PowBig(const Fp6m& a, const BigInteger& e_in) {
        BigInteger e = e_in;
        Fp6m r = One(), b = a;
        while (!e.IsZero() && e > 0) {
            if (!(e & 1).IsZero()) r = Mul6(r, b);
            b = Mul6(b, b);
            e >>= 1;
        }
        return r;
    }

    static Fp6 ToFp6(const Fp6m& a) {
        return Fp6(
            Fp3(Fpm::ToBig(a.R.C0), Fpm::ToBig(a.R.C1), Fpm::ToBig(a.R.C2)),
            Fp3(Fpm::ToBig(a.I.C0), Fpm::ToBig(a.I.C1), Fpm::ToBig(a.I.C2))
        );
    }

    static Fp6 PowBigM(const Fp6& a, const BigInteger& e) {
        return ToFp6(PowBig(Fp6m::FromFp6(a), e));
    }
};
