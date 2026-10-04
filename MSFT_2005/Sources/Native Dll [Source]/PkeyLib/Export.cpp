#include "pch.h"
#include "Helper.h"
#include "BigInteger.h"
#include "pKeyCalc.h"
#include "Montgomery.h"
#include "TatePairing.h"
#include "H1Search.h"
#include "PCoreAffinity.h"
#include <fstream>
#include <sstream>
#include <vector>
#include <string>
#include <cstring>
#include <cstdlib>
#include <thread>
#include <atomic>
#include <Windows.h>
#include <objbase.h>

#ifdef _WIN32
#define DLL_EXPORT __declspec(dllexport)
#else
#define DLL_EXPORT
#endif

// =====================================================================
// CPU tuning notes (i7-13700KF: 8 P-cores + HT = 16 P-threads, 8 E-cores)
//
// The OUTER loop below runs INDEPENDENT groups, so -- unlike the inner
// MITM chunk split -- it is a throughput problem, not a balance problem.
// We therefore:
//   * spread it across all 16 homogeneous P-THREADS (P-cores + their HT
//     siblings), not just the 8 physical P-cores. HT adds ~20-30% here
//     because the 8 MB table probes and the modmul dependency chains
//     leave issue slots the sibling thread can use.
//   * skip the 8 E-cores on purpose: if the *winning* group landed on a
//     Gracemont core it would run ~2x slower and stall the whole result
//     while the P-threads sit idle with nothing left to steal.
//   * dispatch groups from a shared atomic counter (work-stealing), so a
//     P-thread that finishes a doomed group immediately grabs the next
//     one instead of waiting on a static slice.
//   * force the INNER MITM serial in this mode (FreeSlots = 0): with 16
//     groups already in flight there are no spare cores to nest into, and
//     nesting would just oversubscribe. One group == one serial MITM on
//     one pinned P-thread.
//
// The single-group path (targetGroupId set, or a config with one entry)
// does the opposite: 1 outer worker, inner MITM claims all 8 P-cores and
// runs fully parallel -- the warm path that beats a serial validator.
// =====================================================================

// Internal Base64 decoder for Helper::ParseKeyEntriesSimple
static std::vector<unsigned char> InternalBase64Decode(std::string_view b64) {
    static constexpr int kLookup[] = {
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,
        52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1,
        -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
        15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
        -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
        41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1
    };
    int in_len = (int)b64.size();
    int i = 0, in_ = 0;
    unsigned char char_array_4[4], char_array_3[3];
    std::vector<unsigned char> ret;

    while (in_len-- && (b64[in_] != '=') && (std::isalnum(b64[in_]) || b64[in_] == '+' || b64[in_] == '/')) {
        char_array_4[i++] = b64[in_++];
        if (i == 4) {
            for (i = 0; i < 4; i++)
                char_array_4[i] = (unsigned char)kLookup[char_array_4[i]];
            char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
            char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
            char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];
            for (i = 0; i < 3; i++) ret.push_back(char_array_3[i]);
            i = 0;
        }
    }
    if (i) {
        for (int j = i; j < 4; j++) char_array_4[j] = 0;

        for (int j = 0; j < i; j++) {
            char_array_4[j] = (unsigned char)kLookup[char_array_4[j]];
        }

        char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
        char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
        char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

        for (int j = 0; j < i - 1; j++) ret.push_back(char_array_3[j]);
    }
    return ret;
}

#ifdef _WIN32
// One affinity mask per logical P-THREAD (splits each physical P-core mask
// into its individual HT-lane bits). On the 13700KF this yields 16 masks.
// Empty on non-hybrid / detection failure -> caller falls back.
static std::vector<DWORD_PTR> GetPerformanceThreadMasks() {
    std::vector<DWORD_PTR> out;
    for (DWORD_PTR m : GetPerformanceCoreMasks()) {
        while (m) {
            DWORD_PTR lsb = m & (DWORD_PTR)(~m + 1); // lowest set bit
            out.push_back(lsb);
            m &= (m - 1);
        }
    }
    return out;
}
#endif

extern "C" {
    // Raw-buffer variant (Zero Disk I/O, no strings, no key decoding).
    //
    // rawKey / rawKeySize:
    //     The already-encoded binary key: exactly the 16 bytes that
    //     Helper::EncodeBinaryKey produces from the key text.
    //     rawKeySize must be 16.
    // xmlData / xmlSize:
    //     The raw bytes of the pkeyconfig XML, exactly as stored on disk.
    // outUid8Bytes:
    //     Caller buffer, 8 bytes.
    // outGroupId:
    //     Optional, may be null.
    // targetGroupId:
    //     0  -> scan every group (dynamic, all P-threads)
    //     >0 -> validate ONLY that group, inner MITM fully parallel
    DLL_EXPORT bool VerifyBinaryKey(
        const unsigned char* rawKey,
        int rawKeySize,
        const unsigned char* xmlData,
        int xmlSize,
        unsigned char* outUid8Bytes,
        int* outGroupId,
        int targetGroupId
    ) {
        try {
            if (!rawKey || rawKeySize != 16 ||
                !xmlData || xmlSize <= 0 ||
                !outUid8Bytes) {
                return false;
            }

            // Fresh run: clear any leftover abort flag BEFORE any worker starts,
            // so it can never race with the winner raising it below.
            H1Search::Abort.store(0, std::memory_order_relaxed);

            // The key arrives already encoded; just copy the 16 bytes.
            std::vector<unsigned char> bEncryptArray(rawKey, rawKey + 16);

            std::string outerXml(reinterpret_cast<const char*>(xmlData), (size_t)xmlSize);

            std::vector<PublicKeyEntry> pkEntries;
            if (!Helper::ParseKeyEntriesSimple(outerXml, pkEntries, InternalBase64Decode)) {
                return false;
            }

            struct ParsedEntry {
                int groupId;
                PubKey pubKey;
            };
            std::vector<ParsedEntry> parsedEntries;
            parsedEntries.reserve(pkEntries.size());

            for (const auto& entry : pkEntries) {
                try {
                    PubKey k = PubKeyParser::Parse(entry.pubKeyBytes);
                    int gId = 0;
                    try { gId = std::stoi(entry.groupId); }
                    catch (...) { gId = 0; }
                    parsedEntries.push_back({ gId, std::move(k) });
                }
                catch (...) {
                    // Skip malformed entries safely
                }
            }

            // Optional single-group fast path.
            if (targetGroupId > 0) {
                std::vector<ParsedEntry> only;
                for (auto& pe : parsedEntries) {
                    if (pe.groupId == targetGroupId) { only.push_back(std::move(pe)); break; }
                }
                parsedEntries.swap(only);
            }

            if (parsedEntries.empty()) {
                return false;
            }

            const bool singleGroup = (parsedEntries.size() == 1);

            // Inner-MITM budget:
            //   single group  -> let the ONE search grab every P-core (parallel)
            //   many groups    -> force each search serial; throughput comes from
            //                     running many groups at once (no nested spawn).
            H1Search::FreeSlots.store(singleGroup ? H1Search::TotalSlots() : 0,
                                      std::memory_order_relaxed);

            std::atomic<bool>   foundValid(false);
            std::atomic<size_t> nextIdx(0);
            int resolvedGroupId = 0;
            std::vector<unsigned char> resolvedUid;

            // Worker set.
            unsigned int numWorkers;
#ifdef _WIN32
            std::vector<DWORD_PTR> pinMasks;
            if (!singleGroup) {
                pinMasks = GetPerformanceThreadMasks();          // 16 on 13700KF
                if (pinMasks.empty()) {                          // non-hybrid fallback
                    unsigned int hc = std::thread::hardware_concurrency();
                    if (hc == 0) hc = 4;
                    for (unsigned int i = 0; i < hc && i < 64; ++i)
                        pinMasks.push_back((DWORD_PTR)1 << i);
                }
                numWorkers = (unsigned int)pinMasks.size();
            } else {
                numWorkers = 1;                                  // inner MITM is the parallel one
            }
#else
            numWorkers = singleGroup ? 1u
                                     : (std::max)(1u, std::thread::hardware_concurrency());
#endif
            if (numWorkers > (unsigned int)parsedEntries.size())
                numWorkers = (unsigned int)parsedEntries.size();

            std::vector<std::thread> workers;
            workers.reserve(numWorkers);

            for (unsigned int t = 0; t < numWorkers; ++t) {
                workers.emplace_back([&, t]() {
#ifdef _WIN32
                    if (!singleGroup && t < pinMasks.size()) {
                        SetThreadAffinityMask(GetCurrentThread(), pinMasks[t]);
                    }
                    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_HIGHEST);
#endif
                    for (;;) {
                        if (foundValid.load(std::memory_order_relaxed)) break;
                        size_t i = nextIdx.fetch_add(1, std::memory_order_relaxed);
                        if (i >= parsedEntries.size()) break;

                        const auto& entry = parsedEntries[i];
                        std::string actPkeyConfig;
                        std::vector<unsigned char> h1Coeffs;
                        std::vector<unsigned char> uid;

                        bool success = PKeyCalc::TryParsedPubKey(entry.pubKey, bEncryptArray, actPkeyConfig, h1Coeffs, uid);
                        if (success) {
                            bool expected = false;
                            if (foundValid.compare_exchange_strong(expected, true)) {
                                // Only the CAS winner writes these; safe without a lock.
                                resolvedUid = uid;
                                resolvedGroupId = entry.groupId;
                                // Stop every other in-flight MITM at its next poll,
                                // instead of grinding its full 2^18 scan to a miss.
                                H1Search::Abort.store(1, std::memory_order_relaxed);
                            }
                            break;
                        }
                    }
                    });
            }

            for (auto& worker : workers) {
                if (worker.joinable()) worker.join();
            }

            if (foundValid.load()) {
                if (resolvedUid.size() >= 8) {
                    std::memcpy(outUid8Bytes, resolvedUid.data(), 8);
                }
                else {
                    std::memset(outUid8Bytes, 0, 8);
                    std::memcpy(outUid8Bytes, resolvedUid.data(), resolvedUid.size());
                }
                if (outGroupId) *outGroupId = resolvedGroupId;
                return true;
            }
            return false;
        }
        catch (...) {
            return false;
        }
    }

    // Convenience variant: key as text, config as a file path.
    // Encodes the key to its 16 raw bytes, reads the file, scans every group.
    DLL_EXPORT bool VerifyKey(
        const char* cdKeyStr,
        const char* configFilePath,
        unsigned char* outUid8Bytes,
        int* outGroupId
    )
    {
        try {
            if (!cdKeyStr ||
                !configFilePath ||
                !outUid8Bytes ||
                !outGroupId) {
                return false;
            }

            *outGroupId = 0;

            // Key text -> 16 raw bytes (VerifyKeyBytes no longer does this).
            std::vector<unsigned char> rawKey;
            try {
                rawKey = Helper::EncodeBinaryKey(std::string(cdKeyStr));
            }
            catch (const std::exception&) {
                return false;
            }
            if (rawKey.size() != 16) {
                return false;
            }

            std::ifstream file(configFilePath, std::ios::binary);
            if (!file.is_open()) {
                return false;
            }

            std::stringstream buffer;
            buffer << file.rdbuf();

            std::string outerXml = buffer.str();

            unsigned char uid[8] = {};
            int groupId = 0;

            const bool success = VerifyBinaryKey(
                rawKey.data(),
                static_cast<int>(rawKey.size()),
                reinterpret_cast<const unsigned char*>(outerXml.data()),
                static_cast<int>(outerXml.size()),
                uid,
                &groupId,
                0
            );

            if (!success) {
                return false;
            }

            std::memcpy(outUid8Bytes, uid, 8);
            *outGroupId = groupId;

            return true;
        }
        catch (...) {
            return false;
        }
    }
}
