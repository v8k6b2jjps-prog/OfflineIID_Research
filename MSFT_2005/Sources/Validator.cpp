#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <stdio.h>
#include <stdint.h>

// https://github.com/laomms/PKey2005Decoder
// https://github.com/UMSKT/writeups/blob/main/PKEY2005.md

// Compile As x86 App
// Dll Helper is x86 Version

typedef int(__fastcall* PubkeyParserDelegate)(intptr_t* pDstMem, unsigned char* PublicKeyBytes, unsigned int dwSize, int* retValue);
typedef int(__fastcall* CalculateH1Delegate)(unsigned char* pMem1, unsigned char* pMem2, unsigned char* PID3Array, unsigned char* isValid, unsigned char* h1Coeffs, int* retValue);
typedef int(__fastcall* ExtractMDelegate)(unsigned char* pMem1, unsigned char* pMem2, unsigned char* M, int* retValue);

typedef struct _PubkeyData {
    unsigned char header[44];
    unsigned char bytes1[44];
    unsigned char bytes2[36];
    int end_marker;
} PubkeyData;

int main() {
    // 1. Load the DLL from the current folder
    HMODULE hModule = LoadLibrary(L"PidKeyData.dll");
    if (!hModule) {
        printf("Failed to load PidKeyData.dll from current directory.\n");
        return 1;
    }

    PubkeyParserDelegate pPubkeyParser = (PubkeyParserDelegate)GetProcAddress(hModule, "PubkeyParser");
    CalculateH1Delegate pCalculateH1 = (CalculateH1Delegate)GetProcAddress(hModule, "CalculateH1");
    ExtractMDelegate pExtractM = (ExtractMDelegate)GetProcAddress(hModule, "ExtractM");

    if (!pPubkeyParser || !pCalculateH1 || !pExtractM) {
        printf("Failed to resolve DLL functions.\n");
        FreeLibrary(hModule);
        return 1;
    }

    // 2. Read public key from Bink.bin in the current folder (Expected size: 1579 bytes / 0x62B)
    FILE* fBin = fopen("Bink.bin", "rb");
    if (!fBin) {
        printf("Failed to open Bink.bin in the current directory.\n");
        FreeLibrary(hModule);
        return 1;
    }

    unsigned char bPublicKey[1579];
    size_t binBytesRead = fread(bPublicKey, 1, 1579, fBin);
    fclose(fBin);

    if (binBytesRead != 1579) {
        printf("Warning: Bink.bin size (%zu bytes) does not match expected 1579 bytes.\n", binBytesRead);
    }

    // 3. Read 16-byte raw CD key info from external KeyData.bin file
    FILE* fKey = fopen("KeyData.bin", "rb");
    if (!fKey) {
        printf("Failed to open KeyData.bin in the current directory.\n");
        FreeLibrary(hModule);
        return 1;
    }

    unsigned char encData[16];
    size_t keyBytesRead = fread(encData, 1, 16, fKey);
    fclose(fKey);

    if (keyBytesRead != 16) {
        printf("Error: KeyData.bin must be exactly 16 bytes (read %zu bytes).\n", keyBytesRead);
        FreeLibrary(hModule);
        return 1;
    }

    // 4. Step 1: Parse the Public Key
    intptr_t pMem[8] = { 0 };
    int retValue[5] = { 0 };
    int result = pPubkeyParser(pMem, bPublicKey, 1579, retValue);

    PubkeyData* pData = (PubkeyData*)(uintptr_t)pMem[6];
    if (!pData) {
        printf("Failed to extract PubkeyData context.\n");
        FreeLibrary(hModule);
        return 1;
    }

    // 5. Step 2: Calculate H1 using the external raw bytes loaded from KeyData.bin
    unsigned char ifTrue[4] = { 0 };
    unsigned char h1Coeffs[15] = { 0 };

    result = pCalculateH1(pData->bytes1, pData->bytes2, encData, ifTrue, h1Coeffs, retValue);

    // 6. Step 3: If valid, extract the M scalar value and unpack fields
    if (ifTrue[0] == 1) {
        unsigned char M[8] = { 0 };
        retValue[4] = 1;
        result = pExtractM(pData->bytes1, h1Coeffs, M, retValue);

        // Treat the 8-byte M array as a 64-bit integer
        uint64_t m_value = *(uint64_t*)M;

        bool isUpgrade = m_value & 0x1;
        uint32_t serial = (m_value >> 1) & 0x3FFFFFFF;
        uint32_t security = (m_value >> 31) & 0x3FF;

        printf("Status       : Valid Key\n");
        printf("Upgrade Flag : %d\n", isUpgrade);
        printf("Serial       : %u (0x%X)\n", serial, serial);
        printf("Security ID  : %u (0x%X)\n", security, security);
    }
    else {
        printf("Status       : Invalid Key (Signature mismatch)\n");
    }

    FreeLibrary(hModule);
    return 0;
}