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

#ifdef _WIN32
#define DLL_EXPORT __declspec(dllexport)
#else
#define DLL_EXPORT
#endif

// Internal Base64 decoder for Helper::ParseKeyEntriesSimple[cite: 3, 6]
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

extern "C" {
    // High-performance Memory-Stream variant (Zero Disk I/O)[cite: 7]
    DLL_EXPORT bool VerifyKeyFromMemory(
        const char* cdKeyStr,
        const char* configXmlData,
        int configXmlLen,
        unsigned char* outUid8Bytes,
        int* outGroupId
    ) {
        try {
            if (!cdKeyStr || !configXmlData || configXmlLen <= 0 || !outUid8Bytes) {
                return false;
            }

            // 1. Construct outer XML directly from in-memory byte buffer[cite: 7]
            std::string outerXml(configXmlData, configXmlLen);

            // 2. Encode CD-Key string into 16-byte binary array[cite: 2]
            std::vector<unsigned char> bEncryptArray;
            try {
                bEncryptArray = Helper::EncodeBinaryKey(std::string(cdKeyStr));
            }
            catch (const std::exception&) {
                return false;
            }

            if (bEncryptArray.size() != 16) {
                return false;
            }

            // 3. Parse public key entries from XML container[cite: 2, 3]
            std::vector<PublicKeyEntry> pkEntries;
            if (!Helper::ParseKeyEntriesSimple(outerXml, pkEntries, InternalBase64Decode)) {
                return false;
            }

            // 4. Pre-parse all public keys once upfront[cite: 7]
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
                    try {
                        gId = std::stoi(entry.groupId);
                    }
                    catch (...) {
                        gId = 0;
                    }
                    parsedEntries.push_back({ gId, std::move(k) });
                }
                catch (...) {
                    // Skip malformed entries safely
                }
            }

            if (parsedEntries.empty()) {
                return false;
            }

            // 5. Test pre-parsed candidate public keys concurrently using hardware threads[cite: 2]
            std::atomic<bool> foundValid(false);
            int resolvedGroupId = 0;
            std::vector<unsigned char> resolvedUid;

            unsigned int numThreads = std::thread::hardware_concurrency();
            if (numThreads == 0) numThreads = 4;

            // v2: on a hybrid CPU, run the outer entry loop on P-cores only so
            // it doesn't contend with the inner MITM's P-core threads and so
            // no entry lands on a slow E-core. Falls back to all logical cores
            // on non-hybrid CPUs.
            std::vector<DWORD_PTR> pCoreMasks = GetPerformanceCoreMasks();
            if (!pCoreMasks.empty()) numThreads = (unsigned int)pCoreMasks.size();

            size_t totalEntries = parsedEntries.size();
            size_t chunkSize = (totalEntries + numThreads - 1) / numThreads;

            std::vector<std::thread> workers;
            workers.reserve(numThreads);

            for (unsigned int t = 0; t < numThreads; ++t) {
                size_t startIdx = t * chunkSize;
                size_t endIdx = (std::min)(startIdx + chunkSize, totalEntries);
                if (startIdx >= endIdx) continue;

                workers.emplace_back([&, t, startIdx, endIdx]() {
                    PinToPerformanceCore(pCoreMasks, (size_t)t);
                    for (size_t i = startIdx; i < endIdx; ++i) {
                        if (foundValid.load()) break;

                        const auto& entry = parsedEntries[i];
                        std::string actPkeyConfig;
                        std::vector<unsigned char> h1Coeffs;
                        std::vector<unsigned char> uid;

                        bool success = PKeyCalc::TryParsedPubKey(entry.pubKey, bEncryptArray, actPkeyConfig, h1Coeffs, uid);
                        if (success) {
                            bool expected = false;
                            if (foundValid.compare_exchange_strong(expected, true)) {
                                resolvedUid = uid;
                                resolvedGroupId = entry.groupId;
                            }
                            break;
                        }
                    }
                    });
            }

            // Wait for all worker threads to complete[cite: 2]
            for (auto& worker : workers) {
                if (worker.joinable()) {
                    worker.join();
                }
            }

            if (foundValid.load()) {
                if (resolvedUid.size() >= 8) {
                    std::memcpy(outUid8Bytes, resolvedUid.data(), 8);
                }
                else {
                    std::memset(outUid8Bytes, 0, 8);
                    std::memcpy(outUid8Bytes, resolvedUid.data(), resolvedUid.size());
                }

                if (outGroupId) {
                    *outGroupId = resolvedGroupId;
                }

                return true;
            }

            return false;
        }
        catch (...) {
            return false;
        }
    }

    // Legacy File-Path variant (backward compatible wrapper around memory stream)[cite: 2, 7]
    DLL_EXPORT bool VerifyAndExtractKey(
        const char* cdKeyStr,
        const char* configFilePath,
        unsigned char* outUid8Bytes,
        int* outGroupId
    ) {
        try {
            if (!configFilePath) return false;
            std::ifstream file(configFilePath, std::ios::binary);
            if (!file.is_open()) return false;
            std::stringstream buffer;
            buffer << file.rdbuf();
            std::string outerXml = buffer.str();
            return VerifyKeyFromMemory(cdKeyStr, outerXml.data(), (int)outerXml.size(), outUid8Bytes, outGroupId);
        }
        catch (...) {
            return false;
        }
    }

    // Raw variant: bypasses CD-key string parsing and .xrm-ms extraction entirely[cite: 2]
    DLL_EXPORT bool VerifyRawKeyAgainstPubKey(
        const unsigned char* rawKey16,
        const unsigned char* pubKeyBytes,
        int pubKeyLen,
        unsigned char* outUid8Bytes,
        unsigned char* outH1Coeffs15,
        char* outActPkeyConfigB64,
        int outActPkeyConfigB64Len
    ) {
        try {
            if (!rawKey16 || !pubKeyBytes || !outUid8Bytes || pubKeyLen <= 0) {
                return false;
            }

            std::vector<unsigned char> bEncryptArray(rawKey16, rawKey16 + 16);
            std::vector<unsigned char> pubKey(pubKeyBytes, pubKeyBytes + pubKeyLen);

            std::string actPkeyConfig;
            std::vector<unsigned char> h1Coeffs;
            std::vector<unsigned char> uid;

            bool success = PKeyCalc::TryPubKey(pubKey, bEncryptArray, actPkeyConfig, h1Coeffs, uid);
            if (!success) {
                return false;
            }

            if (uid.size() >= 8) {
                std::memcpy(outUid8Bytes, uid.data(), 8);
            }
            else {
                std::memset(outUid8Bytes, 0, 8);
                std::memcpy(outUid8Bytes, uid.data(), uid.size());
            }

            if (outH1Coeffs15) {
                std::memset(outH1Coeffs15, 0, 15);
                std::memcpy(outH1Coeffs15, h1Coeffs.data(), (std::min)((size_t)15, h1Coeffs.size()));
            }

            if (outActPkeyConfigB64 && outActPkeyConfigB64Len > 0) {
                size_t copyLen = (std::min)((size_t)(outActPkeyConfigB64Len - 1), actPkeyConfig.size());
                std::memcpy(outActPkeyConfigB64, actPkeyConfig.data(), copyLen);
                outActPkeyConfigB64[copyLen] = '\0';
            }

            return true;
        }
        catch (...) {
            return false;
        }
    }
}