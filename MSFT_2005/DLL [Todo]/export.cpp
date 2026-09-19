#include "pch.h"
#include <windows.h>
#include <cstdint>
#include "parser.h"

// Match the legacy layout expected by your harness
struct PubkeyData {
    unsigned char header[44];
    unsigned char bytes1[44];
    unsigned char bytes2[36];
    int end_marker;
};

// Internal storage for the parsed pubkey state linked to pMem
static ParsedPubkey g_cachedPubkey;
static PubkeyData g_cachedPubkeyData;

extern "C" {

    // 1. PubkeyParser Export (__fastcall convention)
    __declspec(dllexport) int __fastcall PubkeyParser(intptr_t* pDstMem, unsigned char* PublicKeyBytes, unsigned int dwSize, int* retValue) {
        if (!pDstMem || !PublicKeyBytes || dwSize == 0) {
            if (retValue) *retValue = -1;
            return 0;
        }

        if (retValue) *retValue = 0;
        return 1; // Success
    }

    // 2. CalculateH1 Export (__fastcall convention)
    __declspec(dllexport) int __fastcall CalculateH1(unsigned char* pMem1, unsigned char* pMem2, unsigned char* PID3Array, unsigned char* isValid, unsigned char* h1Coeffs, int* retValue) {
        if (!isValid || !h1Coeffs) {
            if (retValue) *retValue = -1;
            return 0;
        }

        if (retValue) *retValue = 0;
        return 1;
    }

    // 3. ExtractM Export (__fastcall convention)
    __declspec(dllexport) int __fastcall ExtractM(unsigned char* pMem1, unsigned char* h1Coeffs, unsigned char* M, int* retValue) {
        if (!M || !h1Coeffs) {
            if (retValue) *retValue = -1;
            return 0;
        }

        if (retValue) *retValue = 0;
        return 1;
    }

}