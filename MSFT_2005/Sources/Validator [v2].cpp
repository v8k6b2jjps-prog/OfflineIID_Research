#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <wincrypt.h>
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <stdint.h>
#include <algorithm>

#pragma comment(lib, "crypt32.lib")

// Function pointer definitions for PidKeyData.dll (x86 __fastcall convention)
typedef int(__fastcall* PubkeyParserDelegate)(intptr_t* pDstMem, unsigned char* PublicKeyBytes, unsigned int dwSize, int* retValue);
typedef int(__fastcall* CalculateH1Delegate)(unsigned char* pMem1, unsigned char* pMem2, unsigned char* PID3Array, unsigned char* isValid, unsigned char* h1Coeffs, int* retValue);
typedef int(__fastcall* ExtractMDelegate)(unsigned char* pMem1, unsigned char* h1Coeffs, unsigned char* M, int* retValue);

typedef struct _PubkeyData {
    unsigned char header[44];
    unsigned char bytes1[44];
    unsigned char bytes2[36];
    int end_marker;
} PubkeyData;

// Helper: Base64 decode string to byte vector using Win32 API
std::vector<unsigned char> Base64Decode(const std::string& in) {
    DWORD outLen = 0;
    if (!CryptStringToBinaryA(in.data(), (DWORD)in.size(), CRYPT_STRING_BASE64, NULL, &outLen, NULL, NULL)) {
        return {};
    }
    std::vector<unsigned char> out(outLen);
    CryptStringToBinaryA(in.data(), (DWORD)in.size(), CRYPT_STRING_BASE64, out.data(), &outLen, NULL, NULL);
    out.resize(outLen);
    return out;
}

// Helper: Extract content between XML tags
std::string ExtractBetween(const std::string& str, const std::string& startTag, const std::string& endTag, size_t& offset) {
    size_t start = str.find(startTag, offset);
    if (start == std::string::npos) return "";
    start += startTag.length();
    size_t end = str.find(endTag, start);
    if (end == std::string::npos) return "";
    offset = end + endTag.length();
    return str.substr(start, end - start);
}

// CD-Key Base-24 Encoder
std::vector<unsigned char> EncodeBinaryKey(std::string cdKey) {
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

int main(int argc, char* argv[]) {
    std::cout << "=== Native C++ PKey Config Enumerator & Validator ===" << std::endl;

    if (argc < 2) {
        std::cout << "Usage: PKeyValidator.exe <CD-KEY> [ConfigFilePath]" << std::endl;
        return 1;
    }

    std::string cdKey = argv[1];
    std::string configPath = (argc >= 3) ? argv[2] : "pkeyconfig.xrm-ms";

    // 1. Encode CD-Key
    std::vector<unsigned char> encData;
    try {
        encData = EncodeBinaryKey(cdKey);
    }
    catch (const std::exception& e) {
        std::cerr << "Error encoding CD-Key: " << e.what() << std::endl;
        return 1;
    }

    // 2. Load Config File
    std::ifstream file(configPath, std::ios::binary);
    if (!file) {
        std::cerr << "Failed to open configuration file: " << configPath << std::endl;
        return 1;
    }
    std::string outerXml((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    file.close();

    // 3. Extract base64 payload from infoBin name="pkeyConfigData"
    size_t pos = 0;
    // Find infoBin node containing name="pkeyConfigData"
    size_t infoBinPos = outerXml.find("pkeyConfigData");
    if (infoBinPos == std::string::npos) {
        std::cerr << "Could not find 'pkeyConfigData' inside config file." << std::endl;
        return 1;
    }

    // Find content between tags > and </...infoBin>
    size_t contentStart = outerXml.find('>', infoBinPos) + 1;
    size_t contentEnd = outerXml.find("</", contentStart);
    std::string base64InfoBin = outerXml.substr(contentStart, contentEnd - contentStart);

    // Clean whitespaces/newlines from base64 string
    base64InfoBin.erase(remove_if(base64InfoBin.begin(), base64InfoBin.end(), isspace), base64InfoBin.end());

    std::vector<unsigned char> decodedInnerBytes = Base64Decode(base64InfoBin);
    if (decodedInnerBytes.empty()) {
        std::cerr << "Failed to decode inner base64 configuration data." << std::endl;
        return 1;
    }

    // Convert decoded bytes to string (handle UTF-8 or UTF-16)
    std::string innerXml(decodedInnerBytes.begin(), decodedInnerBytes.end());
    if (innerXml.find("ProductKeyConfiguration") == std::string::npos) {
        // Try interpreting as wide string / Unicode if UTF-8 lookup failed
        if (decodedInnerBytes.size() > 2 && decodedInnerBytes[1] == 0) {
            std::wstring wstr((wchar_t*)decodedInnerBytes.data(), decodedInnerBytes.size() / 2);
            innerXml = std::string(wstr.begin(), wstr.end());
        }
    }

    // 4. Load PidKeyData.dll
    HMODULE hModule = LoadLibrary(L"PidKeyData.dll");
    if (!hModule) {
        std::cerr << "Failed to load PidKeyData.dll from current directory." << std::endl;
        return 1;
    }

    PubkeyParserDelegate pPubkeyParser = (PubkeyParserDelegate)GetProcAddress(hModule, "PubkeyParser");
    CalculateH1Delegate pCalculateH1 = (CalculateH1Delegate)GetProcAddress(hModule, "CalculateH1");
    ExtractMDelegate pExtractM = (ExtractMDelegate)GetProcAddress(hModule, "ExtractM");

    if (!pPubkeyParser || !pCalculateH1 || !pExtractM) {
        std::cerr << "Failed to resolve DLL functions." << std::endl;
        FreeLibrary(hModule);
        return 1;
    }

    // 5. Loop through all PublicKey nodes in inner XML
    size_t searchPos = 0;
    int processedCount = 0;
    bool foundValid = false;

    while (true) {
        size_t pkStart = innerXml.find("<pkc:PublicKey>", searchPos);
        if (pkStart == std::string::npos) {
            // Try without prefix if needed
            pkStart = innerXml.find("<PublicKey>", searchPos);
            if (pkStart == std::string::npos) break;
        }

        size_t pkEnd = innerXml.find("</pkc:PublicKey>", pkStart);
        if (pkEnd == std::string::npos) pkEnd = innerXml.find("</PublicKey>", pkStart);
        if (pkEnd == std::string::npos) break;

        std::string pkBlock = innerXml.substr(pkStart, pkEnd - pkStart);
        searchPos = pkEnd;

        // Extract GroupId
        size_t dummy = 0;
        std::string groupId = ExtractBetween(pkBlock, "<pkc:GroupId>", "</pkc:GroupId>", dummy);
        if (groupId.empty()) groupId = ExtractBetween(pkBlock, "<GroupId>", "</GroupId>", dummy);

        // Extract PublicKeyValue (Base64)
        dummy = 0;
        std::string pubKeyB64 = ExtractBetween(pkBlock, "<pkc:PublicKeyValue>", "</pkc:PublicKeyValue>", dummy);
        if (pubKeyB64.empty()) pubKeyB64 = ExtractBetween(pkBlock, "<PublicKeyValue>", "</PublicKeyValue>", dummy);

        if (!pubKeyB64.empty()) {
            pubKeyB64.erase(remove_if(pubKeyB64.begin(), pubKeyB64.end(), isspace), pubKeyB64.end());
            std::vector<unsigned char> pubKeyBytes = Base64Decode(pubKeyB64);

            if (pubKeyBytes.size() == 1579) {
                processedCount++;

                // Validate against this public key
                intptr_t pMem[8] = { 0 };
                int retValue[5] = { 0 };
                pPubkeyParser(pMem, pubKeyBytes.data(), (unsigned int)pubKeyBytes.size(), retValue);

                PubkeyData* pData = (PubkeyData*)(uintptr_t)pMem[6];
                if (pData) {
                    unsigned char ifTrue[4] = { 0 };
                    unsigned char h1Coeffs[15] = { 0 };
                    pCalculateH1(pData->bytes1, pData->bytes2, encData.data(), ifTrue, h1Coeffs, retValue);

                    if (ifTrue[0] == 1) {
                        unsigned char M[8] = { 0 };
                        retValue[4] = 1;
                        pExtractM(pData->bytes1, h1Coeffs, M, retValue);

                        uint64_t m_value = *(uint64_t*)M;
                        bool isUpgrade = m_value & 0x1;
                        uint32_t serial = (uint32_t)((m_value >> 1) & 0x3FFFFFFF);
                        uint32_t security = (uint32_t)((m_value >> 31) & 0x3FF);

                        std::cout << "\nStatus       : Valid Key" << std::endl;
                        std::cout << "Upgrade Flag : " << isUpgrade << std::endl;
                        std::cout << "Serial       : " << serial << " (0x" << std::hex << serial << std::dec << ")" << std::endl;
                        std::cout << "Security ID  : " << security << " (0x" << std::hex << security << std::dec << ")" << std::endl;
                        std::cout << "Group ID     : " << groupId << std::endl;
                        std::cout << "Key Size     : " << pubKeyBytes.size() << " bytes" << std::endl;

                        foundValid = true;
                        break;
                    }
                }
            }
        }
    }

    if (!foundValid) {
        std::cout << "\nStatus       : Invalid Key (Signature mismatch across " << processedCount << " groups)" << std::endl;
    }

    FreeLibrary(hModule);
    return 0;
}