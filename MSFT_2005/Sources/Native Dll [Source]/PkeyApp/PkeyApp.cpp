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
#include <limits>

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

// One elapsed measurement, printed at every scale from nanoseconds up. The
// count is an exact integer nanosecond tick (no floating-point rounding to
// 0.01 s like the old "%.2fs"), so sub-microsecond differences stay visible.
static void PrintElapsed(const char* indent, long long ns) {
    const double us = ns / 1e3;
    const double ms = ns / 1e6;
    const double s = ns / 1e9;
    std::cout << indent << "Elapsed Time : "
        << ns << " ns"
        << "  (" << std::fixed << std::setprecision(3) << us << " us"
        << " | " << std::setprecision(3) << ms << " ms"
        << " | " << std::setprecision(6) << s << " s)"
        << std::endl;
    std::cout.unsetf(std::ios::floatfield);
}

int main() {
    const char* testCdKey = "RHTBY-VWY6D-QJRJ9-JGQ3X-Q2289";
    const char* configRoot = "C:\\Windows\\Temp\\pkeyconfigs";

    std::cout << "=== Native PKey Test Harness (all configs) ===\n";
    std::cout << "Key: " << testCdKey << "\n";
    std::cout << "Config Root: " << configRoot << "\n";
    std::cout << "Timer: std::chrono::steady_clock, "
        << "resolution "
        << (double)std::chrono::steady_clock::period::num
        / std::chrono::steady_clock::period::den * 1e9
        << " ns/tick\n\n";

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

    // Timing aggregates (nanoseconds), over every file that actually reached
    // the DLL -- valid and invalid alike; load failures never call VerifyKey.
    long long timedRuns = 0;
    long long totalNs = 0;
    long long minNs = (std::numeric_limits<long long>::max)();
    long long maxNs = 0;
    std::string minFile, maxFile;
    long long validTotalNs = 0, validRuns = 0;   // split so the single hit is visible
    long long invalidTotalNs = 0, invalidRuns = 0;

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

        auto startTime = std::chrono::steady_clock::now();

        bool success = VerifyKey(
            testCdKey,
            pathStr.c_str(),
            uid,
            &groupId
        );

        auto endTime = std::chrono::steady_clock::now();
        long long ns = std::chrono::duration_cast<std::chrono::nanoseconds>(endTime - startTime).count();

        // Fold into the aggregates.
        timedRuns++;
        totalNs += ns;
        if (ns < minNs) { minNs = ns; minFile = pathStr; }
        if (ns > maxNs) { maxNs = ns; maxFile = pathStr; }

        if (success) {
            validCount++;
            validRuns++; validTotalNs += ns;
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
            invalidRuns++; invalidTotalNs += ns;
            std::cout << "  Status       : Invalid Key\n";
        }
        PrintElapsed("  ", ns);
        // No break: keep going even after a success.
    }

    std::cout << "\n=== Done, no crash ===\n";
    std::cout << "Files tested : " << files.size() << "\n";
    std::cout << "Valid        : " << validCount << "\n";
    std::cout << "Invalid      : " << invalidCount << "\n";
    std::cout << "Load failed  : " << loadFailCount << "\n";

    if (timedRuns > 0) {
        std::cout << "\n=== Timing (nanoseconds, over " << timedRuns << " DLL call(s)) ===\n";
        std::cout << "  Total        : ";
        PrintElapsed("", totalNs);
        std::cout << "  Mean / call  : ";
        PrintElapsed("", totalNs / timedRuns);
        std::cout << "  Fastest      : ";
        PrintElapsed("", minNs);
        std::cout << "               " << minFile << "\n";
        std::cout << "  Slowest      : ";
        PrintElapsed("", maxNs);
        std::cout << "               " << maxFile << "\n";
        if (validRuns > 0) {
            std::cout << "  Mean (valid) : ";
            PrintElapsed("", validTotalNs / validRuns);
        }
        if (invalidRuns > 0) {
            std::cout << "  Mean (reject): ";
            PrintElapsed("", invalidTotalNs / invalidRuns);
        }
    }

    std::cout << "\nPress any key to exit...";
    std::cin.get();
    return 0;
}