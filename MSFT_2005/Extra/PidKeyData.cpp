#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <objbase.h> // Required for GUID generation

#pragma comment(lib, "ole32.lib") // Links COM library for GUID functions

#define IDR_MY_DLL 101

typedef int(__fastcall* PubkeyParserDelegate)(intptr_t* pDstMem, unsigned char* PublicKeyBytes, unsigned int dwSize, int* retValue);
typedef int(__fastcall* CalculateH1Delegate)(unsigned char* pMem1, unsigned char* pMem2, unsigned char* PID3Array, unsigned char* isValid, unsigned char* h1Coeffs, int* retValue);
typedef int(__fastcall* ExtractMDelegate)(unsigned char* pMem1, unsigned char* h1Coeffs, unsigned char* M, int* retValue);

typedef struct _PubkeyData {
    unsigned char header[44];
    unsigned char bytes1[44];
    unsigned char bytes2[36];
    int end_marker;
} PubkeyData;

// Helper to extract DLL to the same directory as the executable and load it
HMODULE ExtractAndLoadDll(LPCWSTR dllFileName) {
    HRSRC hRes = FindResourceW(NULL, MAKEINTRESOURCE(IDR_MY_DLL), RT_RCDATA);
    if (!hRes) {
        printf("Failed to find DLL resource.\n");
        return NULL;
    }

    HGLOBAL hData = LoadResource(NULL, hRes);
    if (!hData) {
        printf("Failed to load DLL resource.\n");
        return NULL;
    }

    LPVOID pData = LockResource(hData);
    DWORD dwSize = SizeofResource(NULL, hRes);
    if (!pData || dwSize == 0) {
        printf("DLL resource data is empty.\n");
        return NULL;
    }

    // Get current executable path and construct DLL path in the same directory
    WCHAR dllPath[MAX_PATH];
    GetModuleFileNameW(NULL, dllPath, MAX_PATH);
    
    // Strip executable name to get directory
    wchar_t* lastSlash = wcsrchr(dllPath, L'\\');
    if (lastSlash) {
        *(lastSlash + 1) = L'\0';
    }
    wcscat(dllPath, dllFileName);

    // Write bytes to disk
    HANDLE hFile = CreateFileW(dllPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("Failed to create temporary DLL file on disk. Error: %lu\n", GetLastError());
        return NULL;
    }

    DWORD written = 0;
    WriteFile(hFile, pData, dwSize, &written, NULL);
    CloseHandle(hFile);

    // Load the DLL
    HMODULE hModule = LoadLibraryW(dllPath);
    if (!hModule) {
        printf("Failed to LoadLibrary extracted DLL. Error: %lu\n", GetLastError());
        DeleteFileW(dllPath);
    }

    return hModule;
}

int main() {
	
    // === SINGLE-INSTANCE LOCK (Runs BEFORE anything else) ===
    // Use a unique name for your application mutex (prefixed with "Local\\" keeps it session-specific)
    HANDLE hMutex = CreateMutexW(NULL, TRUE, L"Local\\PidKeyChecker_SingleInstance_Mutex");
    if (!hMutex || GetLastError() == ERROR_ALREADY_EXISTS) {
        printf("Error: Another instance of this application is already running.\n");
        if (hMutex) CloseHandle(hMutex);
        return 1;
    }

    LPCWSTR dllName = L"PidKeyData_temp.dll";

    // 1. Extract and load DLL from resource
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
        printf("Failed to resolve DLL functions.\n");
        FreeLibrary(hModule);
        DeleteFileW(dllName);
        ReleaseMutex(hMutex);
        CloseHandle(hMutex);
        return 1;
    }

    // 2. Read public key from Bink.bin
    FILE* fBin = fopen("Bink.bin", "rb");
    if (!fBin) {
        printf("Failed to open Bink.bin in the current directory.\n");
        FreeLibrary(hModule);
        DeleteFileW(dllName);
        ReleaseMutex(hMutex);
        CloseHandle(hMutex);
        return 1;
    }

    unsigned char bPublicKey[1579];
    size_t binBytesRead = fread(bPublicKey, 1, 1579, fBin);
    fclose(fBin);

    // 3. Read KeyData.bin
    FILE* fKey = fopen("KeyData.bin", "rb");
    if (!fKey) {
        printf("Failed to open KeyData.bin in the current directory.\n");
        FreeLibrary(hModule);
        DeleteFileW(dllName);
        ReleaseMutex(hMutex);
        CloseHandle(hMutex);
        return 1;
    }

    unsigned char encData[16];
    size_t keyBytesRead = fread(encData, 1, 16, fKey);
    fclose(fKey);

    // 4. Run logic
    intptr_t pMem[8] = { 0 };
    int retValue[5] = { 0 };
    int result = pPubkeyParser(pMem, bPublicKey, 1579, retValue);

    PubkeyData* pData = (PubkeyData*)(uintptr_t)pMem[6];
    if (pData) {
        unsigned char ifTrue[4] = { 0 };
        unsigned char h1Coeffs[15] = { 0 };

        pCalculateH1(pData->bytes1, pData->bytes2, encData, ifTrue, h1Coeffs, retValue);

        if (ifTrue[0] == 1) {
            unsigned char M[8] = { 0 };
            retValue[4] = 1;
            pExtractM(pData->bytes1, h1Coeffs, M, retValue);

            uint64_t m_value = *(uint64_t*)M;
            bool isUpgrade = m_value & 0x1;
            uint32_t serial = (m_value >> 1) & 0x3FFFFFFF;
            uint32_t security = (m_value >> 31) & 0x3FF;

            printf("Status       : Valid Key\n");
            printf("Upgrade Flag : %d\n", isUpgrade);
            printf("Serial       : %u (0x%X)\n", serial, serial);
            printf("Security ID  : %u (0x%X)\n", security, security);
        } else {
            printf("Status       : Invalid Key (Signature mismatch)\n");
        }
    }

    // 5. Unload the DLL and clean up
    FreeLibrary(hModule);

    // Attempt direct deletion first
    if (!DeleteFileW(dllName)) {
        // If direct deletion fails, generate a random GUID and move to %TEMP%
        GUID guid;
        if (SUCCEEDED(CoCreateGuid(&guid))) {
            WCHAR guidStr[39];
            StringFromGUID2(guid, guidStr, 39); // Passed by reference (no '&' in C++)
			
            WCHAR tempPath[MAX_PATH];
            GetTempPathW(MAX_PATH, tempPath);

            WCHAR destPath[MAX_PATH];
            swprintf(destPath, MAX_PATH, L"%s%s.dll", tempPath, guidStr);

            // Move file to Temp folder and schedule for deletion on reboot
            if (MoveFileExW(dllName, destPath, MOVEFILE_WRITE_THROUGH | MOVEFILE_REPLACE_EXISTING)) {
                // Tell Windows to delete it when the system restarts
                MoveFileExW(destPath, NULL, MOVEFILE_DELAY_UNTIL_REBOOT);
                //printf("DLL locked; moved to Temp folder as GUID: %ls\n", guidStr);
            } else {
                //printf("Warning: Failed to move temporary DLL (Error %lu).\n", GetLastError());
            }
        }
    } else {
        //printf("Temporary DLL successfully cleaned up.\n");
    }

    ReleaseMutex(hMutex);
    CloseHandle(hMutex);

    return 0;
}