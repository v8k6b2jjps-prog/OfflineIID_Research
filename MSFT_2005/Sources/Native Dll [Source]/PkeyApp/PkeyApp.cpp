#include <iostream>
#include <iomanip>
#include <fstream>
#include <vector>
#include <string>
#include <algorithm>
#include <filesystem>
#include <cstring>
#include <cstdint>
#include <chrono>

namespace fs = std::filesystem;

// Matches the new export file: VerifyKey takes a config FILE PATH and reads
// the file itself (it scans every group, i.e. targetGroupId = 0 internally).
extern "C" {
    __declspec(dllimport) bool VerifyKey(
        const char* cdKeyStr,
        const char* configFilePath,
        unsigned char* outUid8Bytes,
        int* outGroupId
    );
}

static void PrintHex(const unsigned char* data, size_t len, const char* label) {
    std::cout << label << ": 0x";
    for (size_t i = 0; i < len; i++) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)data[i];
    }
    std::cout << std::dec << std::setfill(' ') << "\n";
}

int main() {
    const char* testCdKey = "RHTBY-VWY6D-QJRJ9-JGQ3X-Q2289";
    const char* configRoot = "C:\\Windows\\Temp\\pkeyconfigs";

    std::cout << "=== Native PKey Test Harness (all configs) ===\n";
    std::cout << "Key: " << testCdKey << "\n";
    std::cout << "Config Root: " << configRoot << "\n\n";

    // Collect every *.xrm-ms under the root, recursively
    std::vector<fs::path> files;
    std::error_code ec;
    for (fs::recursive_directory_iterator it(configRoot, fs::directory_options::skip_permission_denied, ec), end;
        !ec && it != end; it.increment(ec)) {
        std::error_code ec2;
        if (!it->is_regular_file(ec2)) continue;
        std::string ext = it->path().extension().string();
        std::transform(ext.begin(), ext.end(), ext.begin(), [](unsigned char c) { return (char)::tolower(c); });
        if (ext == ".xrm-ms") files.push_back(it->path());
    }
    std::sort(files.begin(), files.end());

    if (files.empty()) {
        std::cout << "[ERROR] No .xrm-ms files found.\n";
        return 1;
    }
    std::cout << files.size() << " config file(s) found.\n";

    int validCount = 0, invalidCount = 0, loadFailCount = 0;

    for (size_t i = 0; i < files.size(); i++) {
        // VerifyKey takes a narrow (ANSI code page) path. string() throws if
        // the path has characters the code page cannot represent.
        std::string pathStr;
        try {
            pathStr = files[i].string();
        }
        catch (const std::exception&) {
            std::cout << "\n[" << (i + 1) << "/" << files.size() << "] "
                      << "[ERROR] Path is not representable in the ANSI code page, skipped." << std::endl;
            loadFailCount++;
            continue;
        }

        // Printed and flushed BEFORE the call: if the DLL crashes, the last
        // line on screen is the file that did it.
        std::cout << "\n[" << (i + 1) << "/" << files.size() << "] " << pathStr << std::endl;

        // VerifyKey returns false both for "cannot open the config" and for
        // "key not valid". Probe the file the same way the DLL opens it, so
        // the two cases stay separate in the report.
        {
            std::ifstream probe(pathStr.c_str(), std::ios::binary);
            if (!probe.is_open()) {
                std::cout << "  [ERROR] Config file could not be opened.\n";
                loadFailCount++;
                continue;
            }
        }

        unsigned char uid[8] = { 0 };
        int groupId = 0;

        auto startTime = std::chrono::high_resolution_clock::now();

        bool success = VerifyKey(
            testCdKey,
            pathStr.c_str(),
            uid,
            &groupId
        );

        auto endTime = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double> elapsed = endTime - startTime;

        if (success) {
            validCount++;
            uint64_t rawUniqueId = 0;
            std::memcpy(&rawUniqueId, uid, 8);

            bool upgradeFlag = (rawUniqueId & 0x1) == 1;
            uint32_t pid = (uint32_t)((rawUniqueId >> 1) & 0x3FFFFFFF);
            uint32_t auth = (uint32_t)((rawUniqueId >> 31) & 0x3FF);

            std::cout << "  Status       : Valid Key\n";
            std::cout << "  Upgrade Flag : " << (upgradeFlag ? 1 : 0) << "\n";
            std::cout << "  Serial (PID) : " << pid << " (0x" << std::hex << pid << std::dec << ")\n";
            std::cout << "  Auth / SecID : " << auth << " (0x" << std::hex << auth << std::dec << ")\n";
            std::cout << "  Group ID     : " << groupId << "\n";
            std::cout << "  ";
            PrintHex(uid, 8, "UID Bytes   ");
        }
        else {
            invalidCount++;
            std::cout << "  Status       : Invalid Key\n";
        }
        std::cout << "  Elapsed Time : " << std::fixed << std::setprecision(2) << elapsed.count() << "s" << std::endl;
        std::cout.unsetf(std::ios::floatfield);
        // No break: keep going even after a success.
    }

    std::cout << "\n=== Done, no crash ===\n";
    std::cout << "Files tested : " << files.size() << "\n";
    std::cout << "Valid        : " << validCount << "\n";
    std::cout << "Invalid      : " << invalidCount << "\n";
    std::cout << "Load failed  : " << loadFailCount << "\n";

    std::cout << "\nPress any key to exit...";
    std::cin.get();
    return 0;
}
