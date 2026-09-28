#pragma once
#include <vector>
#include <cstdint>
#include <algorithm>
#include <string>
#include <thread>
#include <atomic>
#include <chrono>
#include <stdexcept>
#include "BigInteger.h"
#include "Montgomery.h"
#include "TatePairing.h"
#include "PCoreAffinity.h"

class H1Search {
public:
    inline static std::atomic<int> Abort{ 0 };
    inline static std::atomic<long> ProbeCalls{ 0 };
    inline static std::atomic<long> ProbeHashHits{ 0 };
    inline static double ProbeProdMms = 0.0;

    // v2: cache the P-core masks once. If the CPU is hybrid we run the MITM
    // on the P-cores only (identical cores -> equal chunks balance perfectly,
    // no HT contention, no E-core stragglers). If not hybrid, masks is empty
    // and everything falls back to the previous hardware_concurrency path.
    inline static std::vector<DWORD_PTR> PCoreMasks = GetPerformanceCoreMasks();

    // ---- Shared global thread budget -------------------------------------
    // The MITM (build + scan) is embarrassingly parallel and is 93% of the
    // work, but Solve can be called concurrently from an outer pool (one per
    // public-key entry). Rather than hardcode the inner layer to 1 thread
    // (which strands the whole machine when validating a single key) or to
    // hardware_concurrency (which oversubscribes when many entries run at
    // once), threads are drawn from ONE global budget: total slots =
    // hardware_concurrency. Each Solve with threads<=0 claims as many free
    // slots as are available at entry (min 1), runs the MITM across them,
    // and returns them. Single key in flight -> MITM gets all cores, exactly
    // like the C# reference's nested Parallel.For. Many keys -> each stays
    // small. Pass threads>0 to override with an explicit count.
    inline static std::atomic<int> FreeSlots{ -1 };

    static int TotalSlots() {
        // v2: on a hybrid CPU, the budget is the number of physical P-cores,
        // so the MITM never spills onto E-cores. Falls back to logical-core
        // count on non-hybrid / detection failure.
        if (!PCoreMasks.empty()) return (int)PCoreMasks.size();
        int hc = (std::max)(1, (int)std::thread::hardware_concurrency());
        return hc;
    }

    // Claim up to `want` free slots (at least 1). Returns the number claimed;
    // the caller MUST release exactly that many.
    static int ClaimSlots(int want) {
        int expected = FreeSlots.load(std::memory_order_relaxed);
        if (expected < 0) { // lazy init on first use
            int init = TotalSlots();
            FreeSlots.compare_exchange_strong(expected, init, std::memory_order_relaxed);
            expected = FreeSlots.load(std::memory_order_relaxed);
        }
        for (;;) {
            int avail = (std::max)(0, expected);
            int take = (std::min)(want, avail);
            if (take <= 1) {
                // nothing free (or only ourselves) -> run serial, claim 0 extra
                return 1;
            }
            if (FreeSlots.compare_exchange_weak(expected, expected - take,
                std::memory_order_acq_rel, std::memory_order_relaxed)) {
                return take;
            }
            // expected reloaded by compare_exchange_weak; retry
        }
    }

    static void ReleaseSlots(int claimed) {
        if (claimed > 1) FreeSlots.fetch_add(claimed, std::memory_order_acq_rel);
    }

    FORCE_INLINE static uint32_t HashM(const Fp6m& v) {
        uint64_t mix = v.R.C0.A0 ^ v.R.C1.A0 ^ v.R.C2.A0 ^ v.I.C0.A0 ^ v.I.C1.A0 ^ v.I.C2.A0;
        // Apply a fast finalizer (MurmurHash3 style avalanche) to prevent clustering
        mix ^= mix >> 33;
        mix *= 0xff51afd7ed558ccdULL;
        mix ^= mix >> 33;
        return (uint32_t)(mix ^ (mix >> 32));
    }

private:
    FORCE_INLINE static Fp6m ProdM(const std::vector<Fp6m>& g, const std::vector<int>& lo, const std::vector<int>& hi, int from, int to, int64_t s, int* digsOut) {
        Fp6m v = Fp6mOp::One();
        int64_t t = s;
        int count = to - from + 1;
        for (int i = 0; i < count; i++) {
            int radix = hi[from + i] - lo[from + i] + 1;
            int d = (int)(t % radix); t /= radix;
            digsOut[i] = d;
            BigInteger expVal(lo[from + i] + d);
            v = Fp6mOp::Mul6(v, Fp6mOp::PowBig(g[from + i], expVal));
        }
        return v;
    }

    // Split [0,total) into nth contiguous chunks and run `body(begin,end)` on
    // each. When nth==1 the chunk runs inline on the CALLING thread with no
    // std::thread created at all -- this matters because Solve is itself
    // normally invoked from an outer thread pool (see Export.cpp), so the
    // inner layer is deliberately serial and spawning+joining a thread just
    // to run one chunk was pure overhead. Behaviour for nth>1 is unchanged.
    template <typename Body>
    static void RunChunks(int nth, int64_t total, Body body) {
        int nchunk = (std::max)(1, nth);
        int64_t chunk = (total + nchunk - 1) / nchunk;
        if (nchunk == 1) {
            body((int64_t)0, total);
            return;
        }
        std::vector<std::thread> workers;
        workers.reserve(nchunk);
        for (int c = 0; c < nchunk; c++) {
            int64_t begin = (int64_t)c * chunk;
            int64_t end = (std::min)(begin + chunk, total);
            workers.emplace_back([&, c, begin, end]() {
                // v2: pin this worker to P-core #c (identical cores => the equal
                // [begin,end) split is now correctly balanced; no HT contention).
                PinToPerformanceCore(PCoreMasks, (size_t)c);
                body(begin, end);
            });
        }
        for (auto& t : workers) t.join();
    }

public:
    static std::vector<int> Solve(const std::vector<Fp6>& g, const Fp6& target, const std::vector<int>& lo, const std::vector<int>& hi, std::string& note, int threads = 0) {
        Abort.store(0, std::memory_order_relaxed);
        int n = (int)lo.size();
        // threads > 0 : explicit override. threads <= 0 : draw from the shared
        // global budget so nested parallelism self-limits (see FreeSlots).
        int claimed = 1;
        int nth;
        if (threads > 0) {
            nth = threads;
        } else {
            claimed = ClaimSlots(TotalSlots());
            nth = claimed;
        }
        struct SlotGuard { int c; ~SlotGuard() { ReleaseSlots(c); } } slotGuard{ claimed };
        Fpm::Init();

        std::vector<Fp6> ginv(n);
        {
            std::vector<Fp6> pref(n + 1);
            pref[0] = Fp6::One();
            for (int k = 0; k < n; k++) pref[k + 1] = pref[k] * g[k];
            Fp6 acc = pref[n].Inverse();
            for (int k = n - 1; k >= 0; k--) {
                ginv[k] = acc * pref[k];
                acc = acc * g[k];
            }
        }

        std::vector<Fp6m> gm(n), gim(n);
        for (int k = 0; k < n; k++) {
            gm[k] = Fp6m::FromFp6(g[k]);
            gim[k] = Fp6m::FromFp6(ginv[k]);
        }
        Fp6m tgt = Fp6m::FromFp6(target);

        std::vector<int> order = { 0, 1, 2, 3, 4, 5, 13, 6, 7, 8, 9, 10, 11, 12 };
        std::vector<int> loP(n), hiP(n);
        std::vector<Fp6m> gmP(n), gimP(n);
        for (int i = 0; i < n; i++) {
            loP[i] = lo[order[i]];
            hiP[i] = hi[order[i]];
            gmP[i] = gm[order[i]];
            gimP[i] = gim[order[i]];
        }

        const int R0 = 0, R1 = 6;
        int rn = R1 - R0 + 1;
        int64_t rsize = 1;
        for (int k = R0; k <= R1; k++) rsize *= (hiP[k] - loP[k] + 1);

        std::vector<int> actR;
        for (int i = 0; i < rn; i++) {
            if (hiP[R0 + i] > loP[R0 + i]) actR.push_back(i);
        }

        std::vector<Fp6m> rwrap(rn);
        for (int i = 0; i < rn; i++) {
            BigInteger expVal(hiP[R0 + i] - loP[R0 + i]);
            rwrap[i] = Fp6mOp::PowBig(gimP[R0 + i], expVal);
        }

        std::vector<uint64_t> keys(rsize);

        RunChunks(nth, rsize, [&](int64_t begin, int64_t end) {
            if (begin >= end) return;
            int d0[16];
            Fp6m prod = ProdM(gmP, loP, hiP, R0, R1, begin, d0);
            int dg[16];
            for (int i = 0; i < rn; i++) dg[i] = d0[i];

            for (int64_t s = begin; s < end; s++) {
                if ((s & 0x3FF) == 0 && Abort.load(std::memory_order_relaxed) != 0) return;
                keys[s] = ((uint64_t)HashM(prod) << 32) | (uint64_t)s;
                for (size_t _j = 0; _j < actR.size(); _j++) {
                    int i = actR[_j];
                    if (dg[i] < hiP[R0 + i] - loP[R0 + i]) {
                        dg[i]++;
                        prod = Fp6mOp::Mul6(prod, gmP[R0 + i]);
                        break;
                    }
                    dg[i] = 0;
                    prod = Fp6mOp::Mul6(prod, rwrap[i]);
                }
            }
            });

        // =========================================================================
        // Flat Open-Addressing Hash Table with Linear Probing
        // =========================================================================
        const size_t tableSize = 1 << 20;
        const size_t tableMask = tableSize - 1;
        std::vector<int64_t> hashTable(tableSize, -1);

        for (int64_t i = 0; i < rsize; i++) {
            uint32_t full_hash = (uint32_t)(keys[i] >> 32);
            size_t idx = full_hash & tableMask;
            while (hashTable[idx] != -1) {
                idx = (idx + 1) & tableMask;
            }
            hashTable[idx] = i;
        }

        const int L0 = 7, L1 = 13;
        int ln = L1 - L0 + 1;
        int64_t lsize = 1;
        for (int k = L0; k <= L1; k++) lsize *= (hiP[k] - loP[k] + 1);

        std::vector<int> actL;
        for (int i = 0; i < ln; i++) {
            if (hiP[L0 + i] > loP[L0 + i]) actL.push_back(i);
        }

        std::vector<Fp6m> lwrapi(ln);
        for (int i = 0; i < ln; i++) {
            BigInteger expVal(hiP[L0 + i] - loP[L0 + i]);
            lwrapi[i] = Fp6mOp::PowBig(gmP[L0 + i], expVal);
        }

        Fp6 tgtI_fp6 = Fp6::One() / target;
        Fp6m tgtI = Fp6m::FromFp6(tgtI_fp6);

        std::string hitNote = "";
        std::vector<int> hitSol;
        bool found = false;
        int stopFlag = 0;

        auto probe = [&](const Fp6m& needed, int64_t s, std::vector<int>& solutionOut) -> bool {
            ProbeCalls++;
            uint32_t fh = HashM(needed);
            size_t idx = fh & tableMask;

            while (hashTable[idx] != -1) {
                int64_t pp = hashTable[idx];
                if ((uint32_t)(keys[pp] >> 32) == fh) {
                    ProbeHashHits++;
                    int64_t rs = (int64_t)(uint32_t)keys[pp];
                    int rd[16];
                    Fp6m rv = ProdM(gmP, loP, hiP, R0, R1, rs, rd);
                    if (rv.Eq(needed)) {
                        int ld[16];
                        ProdM(gm, loP, hiP, L0, L1, s, ld);
                        solutionOut.assign(n, 0);
                        for (int i = 0; i < n; i++) solutionOut[order[i]] = loP[i];
                        for (int i = 0; i < ln; i++) solutionOut[order[L0 + i]] = loP[L0 + i] + ld[i];
                        for (int i = 0; i < rn; i++) solutionOut[order[R0 + i]] = loP[R0 + i] + rd[i];
                        return true;
                    }
                }
                idx = (idx + 1) & tableMask;
            }
            return false;
            };

        int64_t chunkL = (lsize + (std::max)(1, nth) - 1) / (std::max)(1, nth);
        RunChunks(nth, lsize, [&](int64_t begin, int64_t end) {
            if (begin >= end) return;
            int ci = (chunkL > 0) ? (int)(begin / chunkL) : 0; // for the diagnostic note only
            int d0[16];
            Fp6m li0 = ProdM(gimP, loP, hiP, L0, L1, begin, d0);
            int dg[16];
            for (int i = 0; i < ln; i++) dg[i] = d0[i];

            Fp6m la = Fp6mOp::Mul6(tgt, li0);
            Fp6m lb = Fp6mOp::Mul6(tgtI, li0);

            // Reused across the whole scan: probe() only writes into this
            // on an actual hit (roughly once in the entire run), so a
            // single instance is behavior-identical to a fresh vector per
            // iteration -- but avoids ~2^19 heap allocations per worker.
            std::vector<int> tempSol;

            for (int64_t s = begin; s < end; s++) {
                if ((s & 0x3FF) == 0 && Abort.load(std::memory_order_relaxed) != 0) return;
                if (stopFlag != 0) return;

                bool matched = false;
                if (probe(la, s, tempSol)) matched = true;
                else if (probe(lb, s, tempSol)) matched = true;

                if (matched) {
                    if (stopFlag == 0) {
                        stopFlag = 1;
                        hitSol = tempSol;
                        hitNote = "左半 #" + std::to_string(s) + " 命中右半（并行块 " + std::to_string(ci) + "）";
                        found = true;
                    }
                    return;
                }

                for (size_t _j = 0; _j < actL.size(); _j++) {
                    int i = actL[_j];
                    if (dg[i] < hiP[L0 + i] - loP[L0 + i]) {
                        dg[i]++;
                        la = Fp6mOp::Mul6(la, gimP[L0 + i]);
                        lb = Fp6mOp::Mul6(lb, gimP[L0 + i]);
                        break;
                    }
                    dg[i] = 0;
                    la = Fp6mOp::Mul6(la, lwrapi[i]);
                    lb = Fp6mOp::Mul6(lb, lwrapi[i]);
                }
            }
            });

        if (found) {
            note = hitNote;
            return hitSol;
        }
        note = "未找到";
        return {};
    }
};