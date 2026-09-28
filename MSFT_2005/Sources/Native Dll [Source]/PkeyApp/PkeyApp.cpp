#include <iostream>
#include <iomanip>
#include <fstream>
#include <vector>
#include <cstring>
#include <cstdint>
#include <chrono>

// Import the functions exported by your DLL (including the new Ex variant with 'fast')
extern "C" {
    __declspec(dllimport) bool VerifyKeyFromMemory(
        const char* cdKeyStr,
        const char* configXmlData,
        int configXmlLen,
        unsigned char* outUid8Bytes,
        int* outGroupId
    );
}

static void PrintHex(const unsigned char* data, size_t len, const char* label) {
    std::cout << label << ": 0x";
    for (size_t i = 0; i < len; i++) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)data[i];
    }
    std::cout << std::dec << "\n";
}

// Loads a raw file into memory (Zero Disk I/O stream helper)
static bool LoadRawFile(const char* path, std::vector<unsigned char>& out) {
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f.is_open()) return false;
    std::streamsize size = f.tellg();
    f.seekg(0, std::ios::beg);
    out.resize((size_t)size);
    return (bool)f.read(reinterpret_cast<char*>(out.data()), size);
}

int main() {
    const char* testCdKey = "RHTBY-VWY6D-QJRJ9-JGQ3X-Q2289";
    const char* configFile = "C:\\Users\\Administrator\\Desktop\\pkeyconfig.xrm-ms";

    std::cout << "=== Native PKey Test Harness ===\n";
    std::cout << "Key: " << testCdKey << "\n";
    std::cout << "Config Path: " << configFile << "\n\n";

    // 1. Load config file into memory buffer first (Zero Disk I/O pipeline)
    std::vector<unsigned char> xmlBuffer;
    if (!LoadRawFile(configFile, xmlBuffer)) {
        std::cout << "[ERROR] Failed to load config file into memory.\n";
        return 1;
    }

    unsigned char uid[8] = { 0 };
    int groupId = 0;

    std::cout << "Testing CD-Key verification via DLL (Memory stream with fast hint = true)...\n";

    auto startTime = std::chrono::high_resolution_clock::now();

    // Call the new extended function with fast = true
    bool success = VerifyKeyFromMemory(
        testCdKey,
        reinterpret_cast<const char*>(xmlBuffer.data()),
        (int)xmlBuffer.size(),
        uid,
        &groupId
    );

    auto endTime = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> elapsed = endTime - startTime;

    if (success) {
        uint64_t rawUniqueId = 0;
        std::memcpy(&rawUniqueId, uid, 8);

        bool upgradeFlag = (rawUniqueId & 0x1) == 1;
        uint32_t pid = (uint32_t)((rawUniqueId >> 1) & 0x3FFFFFFF);
        uint32_t auth = (uint32_t)((rawUniqueId >> 31) & 0x3FF);

        std::cout << "\n=== Validation Successful ===\n";
        std::cout << "Status        : Valid Key\n";
        std::cout << "Upgrade Flag : " << (upgradeFlag ? 1 : 0) << "\n";
        std::cout << "Serial (PID) : " << pid << " (0x" << std::hex << pid << std::dec << ")\n";
        std::cout << "Auth / SecID : " << auth << " (0x" << std::hex << auth << std::dec << ")\n";
        std::cout << "Group ID     : " << groupId << "\n";
        std::cout << "Key ID       : " << pid << "\n";
        PrintHex(uid, 8, "UID Bytes");
        std::cout << "Elapsed Time : " << std::fixed << std::setprecision(2) << elapsed.count() << "s\n";
    }
    else {
        std::cout << "\nStatus        : Invalid Key (Signature mismatch across public key groups)\n";
        std::cout << "[FAILED] Full pipeline verification failed.\n";
        std::cout << "Elapsed Time : " << std::fixed << std::setprecision(2) << elapsed.count() << "s\n";
    }

    std::cout << "\nPress any key to exit...";
    std::cin.get();
    return 0;
}