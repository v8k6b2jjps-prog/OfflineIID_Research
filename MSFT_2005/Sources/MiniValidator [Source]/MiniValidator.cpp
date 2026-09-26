#define NOMINMAX
#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <wincrypt.h>
#include <iostream>
#include <fstream>
#include <string>
#include <string_view>
#include <vector>
#include <stdint.h>
#include <algorithm>
#include <thread>
#include <atomic>
#include <chrono>

#include "resource.h"

#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "ole32.lib")

typedef int(__fastcall* PubkeyParserDelegate)(intptr_t* pDstMem, unsigned char* PublicKeyBytes, unsigned int dwSize, int* retValue);
typedef int(__fastcall* CalculateH1Delegate)(unsigned char* pMem1, unsigned char* pMem2, unsigned char* PID3Array, unsigned char* isValid, unsigned char* h1Coeffs, int* retValue);
typedef int(__fastcall* ExtractMDelegate)(unsigned char* pMem1, unsigned char* h1Coeffs, unsigned char* M, int* retValue);

typedef struct _PubkeyData {
    unsigned char header[44];
    unsigned char bytes1[44];
    unsigned char bytes2[36];
    int end_marker;
} PubkeyData;

struct PublicKeyEntry {
    std::string groupId;
    std::vector<unsigned char> pubKeyBytes;
};

// Fast Base64 decoder using Win32 API
std::vector<unsigned char> Base64Decode(std::string_view sv) {
    DWORD outLen = 0;
    if (!CryptStringToBinaryA(sv.data(), (DWORD)sv.size(), CRYPT_STRING_BASE64, NULL, &outLen, NULL, NULL)) {
        return {};
    }
    std::vector<unsigned char> out(outLen);
    if (!CryptStringToBinaryA(sv.data(), (DWORD)sv.size(), CRYPT_STRING_BASE64, out.data(), &outLen, NULL, NULL)) {
        return {};
    }
    out.resize(outLen);
    return out;
}

// Fast Base64 encoder using Win32 API
std::string Base64Encode(const unsigned char* data, DWORD len) {
    DWORD outLen = 0;
    if (!CryptBinaryToStringA(data, len, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, &outLen)) {
        return "";
    }
    std::string out(outLen, '\0');
    if (!CryptBinaryToStringA(data, len, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, &out[0], &outLen)) {
        return "";
    }
    out.resize(outLen);
    return out;
}

// CD-Key Base-24 Encoder
std::vector<unsigned char> EncodeBinaryKey(const std::string& cdKey) {
    std::string alphabet = "BCDFGHJKMPQRTVWXY2346789";
    std::string rawKey = "";
    for (char c : cdKey) {
        if (c != '-') rawKey += (char)toupper(c);
    }

    if (rawKey.length() != 25) {
        throw std::runtime_error("Key must be 25 characters.");
    }

    std::vector<unsigned char> digits(25, 0);
    bool isNKey = false;
    int digitCount = 0;

    for (char ch : rawKey) {
        if (ch == 'N' && !isNKey) {
            isNKey = true;
            for (int i = digitCount; i > 0; i--) {
                digits[i] = digits[i - 1];
            }
            digits[0] = (unsigned char)digitCount;
            digitCount++;
            continue;
        }

        size_t val = alphabet.find(ch);
        if (val == std::string::npos) {
            throw std::runtime_error("Invalid character in key.");
        }
        digits[digitCount] = (unsigned char)val;
        digitCount++;
    }

    std::vector<unsigned char> binary(16, 0);
    for (int digit : digits) {
        uint32_t carry = digit;
        for (int i = 0; i < 16; i++) {
            uint32_t res = (binary[i] * 24) + carry;
            binary[i] = (unsigned char)(res & 0xFF);
            carry = res >> 8;
        }
    }

    if (isNKey) {
        binary[14] |= 0x08;
    }

    return binary;
}

// Extract embedded DLL to disk for loading
HMODULE ExtractAndLoadDll(LPCWSTR dllFileName) {
    HRSRC hRes = FindResourceW(NULL, MAKEINTRESOURCE(IDR_MY_DLL), RT_RCDATA);
    if (!hRes) return NULL;

    HGLOBAL hData = LoadResource(NULL, hRes);
    if (!hData) return NULL;

    LPVOID pData = LockResource(hData);
    DWORD dwSize = SizeofResource(NULL, hRes);
    if (!pData || dwSize == 0) return NULL;

    WCHAR dllPath[MAX_PATH];
    GetModuleFileNameW(NULL, dllPath, MAX_PATH);

    wchar_t* lastSlash = wcsrchr(dllPath, L'\\');
    if (lastSlash) *(lastSlash + 1) = L'\0';
    wcscat(dllPath, dllFileName);

    if (GetFileAttributesW(dllPath) == INVALID_FILE_ATTRIBUTES) {
        HANDLE hFile = CreateFileW(dllPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile != INVALID_HANDLE_VALUE) {
            DWORD written = 0;
            WriteFile(hFile, pData, dwSize, &written, NULL);
            CloseHandle(hFile);
        }
    }

    return LoadLibraryW(dllPath);
}

// High-speed Memory-Mapped File Loader
std::string LoadFileFast(const std::string& path) {
    HANDLE hFile = CreateFileA(path.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return "";

    DWORD fileSize = GetFileSize(hFile, NULL);
    if (fileSize == INVALID_FILE_SIZE) {
        CloseHandle(hFile);
        return "";
    }

    HANDLE hMapping = CreateFileMappingA(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!hMapping) {
        CloseHandle(hFile);
        return "";
    }

    const char* pData = (const char*)MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
    std::string content;
    if (pData) {
        content.assign(pData, fileSize);
        UnmapViewOfFile((void*)pData);
    }

    CloseHandle(hMapping);
    CloseHandle(hFile);
    return content;
}

// Helper to retrieve Performance Core (P-core) affinity masks
std::vector<DWORD_PTR> GetPerformanceCoreMasks() {
    std::vector<DWORD_PTR> pCoreMasks;
    DWORD len = 0;
    if (!GetLogicalProcessorInformationEx(RelationProcessorCore, nullptr, &len) && GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
        std::vector<BYTE> buf(len);
        if (GetLogicalProcessorInformationEx(RelationProcessorCore, (PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX)buf.data(), &len)) {
            DWORD offset = 0;
            UCHAR maxEfficiency = 0;

            while (offset < len) {
                auto info = reinterpret_cast<PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX>(buf.data() + offset);
                if (info->Relationship == RelationProcessorCore) {
                    if (info->Processor.EfficiencyClass > maxEfficiency) {
                        maxEfficiency = info->Processor.EfficiencyClass;
                    }
                }
                offset += info->Size;
            }

            offset = 0;
            while (offset < len) {
                auto info = reinterpret_cast<PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX>(buf.data() + offset);
                if (info->Relationship == RelationProcessorCore) {
                    if (info->Processor.EfficiencyClass == maxEfficiency || maxEfficiency == 0) {
                        for (WORD i = 0; i < info->Processor.GroupCount; ++i) {
                            pCoreMasks.push_back(info->Processor.GroupMask[i].Mask);
                        }
                    }
                }
                offset += info->Size;
            }
        }
    }
    return pCoreMasks;
}

bool ParseKeyEntriesSimple(const std::string& outerXml, std::vector<PublicKeyEntry>& pkEntries) {
    size_t infoBinPos = outerXml.find("pkeyConfigData");
    if (infoBinPos == std::string::npos) return false;

    size_t contentStart = outerXml.find('>', infoBinPos) + 1;
    size_t contentEnd = outerXml.find("</", contentStart);
    std::string_view base64InfoBin(&outerXml[contentStart], contentEnd - contentStart);

    std::string cleanedB64;
    cleanedB64.reserve(base64InfoBin.size());
    for (char c : base64InfoBin) {
        if (!isspace((unsigned char)c)) cleanedB64.push_back(c);
    }

    std::vector<unsigned char> decodedInnerBytes = Base64Decode(cleanedB64);
    if (decodedInnerBytes.empty()) return false;

    std::string innerXml(decodedInnerBytes.begin(), decodedInnerBytes.end());
    if (innerXml.find("ProductKeyConfiguration") == std::string::npos) {
        if (decodedInnerBytes.size() > 2 && decodedInnerBytes[1] == 0) {
            std::wstring wstr((wchar_t*)decodedInnerBytes.data(), decodedInnerBytes.size() / 2);
            innerXml = std::string(wstr.begin(), wstr.end());
        }
    }

    std::string_view innerSv = innerXml;
    size_t searchPos = 0;
    while (true) {
        // Find start of public key block safely
        size_t pkStart = innerSv.find("<pkc:PublicKey>", searchPos);
        if (pkStart == std::string_view::npos) {
            pkStart = innerSv.find("<PublicKey>", searchPos);
            if (pkStart == std::string::npos) break;
        }

        // Find end of public key block safely
        size_t pkEnd = innerSv.find("</pkc:PublicKey>", pkStart);
        if (pkEnd == std::string::npos) {
            pkEnd = innerSv.find("</PublicKey>", pkStart);
            if (pkEnd == std::string::npos) break;
            pkEnd += sizeof("</PublicKey>") - 1;
        }
        else {
            pkEnd += sizeof("</pkc:PublicKey>") - 1;
        }

        std::string_view block = innerSv.substr(pkStart, pkEnd - pkStart);
        searchPos = pkEnd;

        // Extract GroupId
        std::string groupId = "";
        size_t gStart = block.find("GroupId>");
        if (gStart == std::string_view::npos) gStart = block.find(":GroupId>");
        if (gStart != std::string_view::npos) {
            gStart = block.find('>', gStart) + 1;
            size_t gEnd = block.find("</", gStart);
            groupId = std::string(block.substr(gStart, gEnd - gStart));
        }

        // Extract PublicKeyValue
        size_t kStart = block.find("PublicKeyValue>");
        if (kStart == std::string_view::npos) kStart = block.find(":PublicKeyValue>");
        if (kStart != std::string_view::npos) {
            kStart = block.find('>', kStart) + 1;
            size_t kEnd = block.find("</", kStart);
            std::string_view rawKeyB64 = block.substr(kStart, kEnd - kStart);

            std::string cleanKeyB64;
            cleanKeyB64.reserve(rawKeyB64.size());
            for (char c : rawKeyB64) {
                if (!isspace((unsigned char)c)) cleanKeyB64.push_back(c);
            }

            std::vector<unsigned char> pubKeyBytes = Base64Decode(cleanKeyB64);
            if (pubKeyBytes.size() == 1579) {
                pkEntries.push_back({ groupId, pubKeyBytes });
            }
        }
    }

    return !pkEntries.empty();
}

int main(int argc, char* argv[]) {
    HANDLE hMutex = CreateMutexW(NULL, TRUE, L"Local\\PKeyValidator_SingleInstance_Mutex");
    if (!hMutex || GetLastError() == ERROR_ALREADY_EXISTS) {
        if (hMutex) CloseHandle(hMutex);
        return 1;
    }

    if (argc < 2) {
        std::cout << "Usage: PKeyValidator.exe <CD-KEY> [ConfigFilePath]" << std::endl;
        ReleaseMutex(hMutex);
        CloseHandle(hMutex);
        return 1;
    }

    std::string cdKey = argv[1];
    std::string configPath = (argc >= 3) ? argv[2] : "pkeyconfig.xrm-ms";

    std::vector<unsigned char> encData;
    try {
        encData = EncodeBinaryKey(cdKey);
    }
    catch (...) {
        ReleaseMutex(hMutex);
        CloseHandle(hMutex);
        return 1;
    }

    LPCWSTR dllName = L"PidKeyData_temp.dll";
    HMODULE hModule = ExtractAndLoadDll(dllName);
    if (!hModule) {
        ReleaseMutex(hMutex);
        CloseHandle(hMutex);
        return 1;
    }

    PubkeyParserDelegate pPubkeyParser = (PubkeyParserDelegate)GetProcAddress(hModule, "PubkeyParser");
    CalculateH1Delegate pCalculateH1 = (CalculateH1Delegate)GetProcAddress(hModule, "CalculateH1");
    ExtractMDelegate pExtractM = (ExtractMDelegate)GetProcAddress(hModule, "ExtractM");

    if (!pPubkeyParser || !pCalculateH1 || !pExtractM) {
        FreeLibrary(hModule);
        DeleteFileW(dllName);
        ReleaseMutex(hMutex);
        CloseHandle(hMutex);
        return 1;
    }

    auto startTime = std::chrono::high_resolution_clock::now();

    std::string outerXml = LoadFileFast(configPath);
    if (outerXml.empty()) {
        FreeLibrary(hModule);
        DeleteFileW(dllName);
        ReleaseMutex(hMutex);
        CloseHandle(hMutex);
        return 1;
    }

    std::vector<PublicKeyEntry> pkEntries;
    if (!ParseKeyEntriesSimple(outerXml, pkEntries)) {
        FreeLibrary(hModule);
        DeleteFileW(dllName);
        ReleaseMutex(hMutex);
        CloseHandle(hMutex);
        return 1;
    }

    std::atomic<bool> foundValid(false);
    bool outIsUpgrade = false;
    uint32_t outSerial = 0;
    uint32_t outSecurity = 0;
    std::string outGroupId = "";
    size_t outKeySize = 0;

    std::vector<DWORD_PTR> pCoreMasks = GetPerformanceCoreMasks();
    size_t numThreads = pCoreMasks.empty() ? std::thread::hardware_concurrency() : pCoreMasks.size();
    if (numThreads == 0) numThreads = 4;

    auto worker = [&](size_t threadIndex, size_t startIdx, size_t endIdx) {
        if (!pCoreMasks.empty()) {
            SetThreadAffinityMask(GetCurrentThread(), pCoreMasks[threadIndex % pCoreMasks.size()]);
        }
        SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_HIGHEST);

        for (size_t i = startIdx; i < endIdx; ++i) {
            if (foundValid) break;

            const auto& entry = pkEntries[i];

            intptr_t pMem[8] = { 0 };
            int retValue[5] = { 0 };
            pPubkeyParser(pMem, (unsigned char*)entry.pubKeyBytes.data(), (unsigned int)entry.pubKeyBytes.size(), retValue);

            PubkeyData* pData = (PubkeyData*)(uintptr_t)pMem[6];
            if (pData) {
                unsigned char ifTrue[4] = { 0 };
                unsigned char h1Coeffs[15] = { 0 };
                pCalculateH1(pData->bytes1, pData->bytes2, (unsigned char*)encData.data(), ifTrue, h1Coeffs, retValue);

                if (ifTrue[0] == 1) {
                    unsigned char M[8] = { 0 };
                    retValue[4] = 1;
                    pExtractM(pData->bytes1, h1Coeffs, M, retValue);

                    uint64_t m_value = *(uint64_t*)M;

                    bool expectedFound = false;
                    if (foundValid.compare_exchange_strong(expectedFound, true)) {
                        outIsUpgrade = (m_value & 0x1) != 0;
                        outSerial = (uint32_t)((m_value >> 1) & 0x3FFFFFFF);
                        outSecurity = (uint32_t)((m_value >> 31) & 0x3FF);
                        outGroupId = entry.groupId;
                        outKeySize = entry.pubKeyBytes.size();
                    }
                    break;
                }
            }
        }
        };

    std::vector<std::thread> threads;
    size_t totalItems = pkEntries.size();
    size_t chunkSize = (totalItems + numThreads - 1) / numThreads;

    for (size_t t = 0; t < numThreads; ++t) {
        size_t start = t * chunkSize;
        size_t end = std::min(start + chunkSize, totalItems);
        if (start < end) {
            threads.emplace_back(worker, t, start, end);
        }
    }

    for (auto& th : threads) {
        if (th.joinable()) {
            th.join();
        }
    }

    auto endTime = std::chrono::high_resolution_clock::now();
    double elapsedSeconds = std::chrono::duration<double>(endTime - startTime).count();

    if (foundValid) {
        uint64_t act_hash = (uint64_t)(outIsUpgrade & 0x1);
        act_hash |= (((uint64_t)outSerial & ((1ULL << 30) - 1)) << 1);
        act_hash |= (((uint64_t)outSecurity & ((1ULL << 20) - 1)) << 31);

        unsigned char keyData[12] = { 0 };
        std::memcpy(keyData, &act_hash, sizeof(act_hash));
        std::string act_data = Base64Encode(keyData, 12);

        std::cout << "Status       : Valid Key" << std::endl;
        std::cout << "Upgrade Flag : " << outIsUpgrade << std::endl;
        std::cout << "Serial       : " << outSerial << " (0x" << std::hex << outSerial << std::dec << ")" << std::endl;
        std::cout << "Security ID  : " << outSecurity << " (0x" << std::hex << outSecurity << std::dec << ")" << std::endl;
        std::cout << "Group ID     : " << outGroupId << std::endl;
        std::cout << "Key Size     : " << outKeySize << " bytes" << std::endl;
        std::cout << "Act Data     : " << act_data << std::endl;
    }
    else {
        std::cout << "Status       : Invalid Key (Mismatch across " << totalItems << " groups)" << std::endl;
    }

    std::cout << "Elapsed Time : " << elapsedSeconds << "s" << std::endl;

    FreeLibrary(hModule);
    DeleteFileW(dllName);

    ReleaseMutex(hMutex);
    CloseHandle(hMutex);

    return 0;
}