#pragma once
#include "pch.h"
#include <windows.h>
#include <sstream>
#include <vector>
#include <string>
#include <cstdint>
#include <stdexcept>

// Define structures matching the .pubkey layout
struct PointCoords {
    std::vector<std::vector<uint8_t>> x; // ext_deg1 bigints of size_modulus bytes
    std::vector<std::vector<uint8_t>> y; // ext_deg1 bigints of size_modulus bytes
};

struct ParsedPubkey {
    uint32_t modulusSize;
    uint32_t orderSize;
    uint32_t extDeg1;
    uint32_t extDeg2;
    uint32_t numBases;

    std::vector<uint8_t> modulus;
    std::vector<uint8_t> order;
    std::vector<int8_t> k3MinPoly;
    std::vector<int8_t> k6MinPoly;

    std::vector<uint8_t> h1Bases;
    std::vector<uint8_t> curveA;
    std::vector<uint8_t> curveB;

    std::vector<PointCoords> points;
    std::vector<std::vector<std::vector<uint8_t>>> pairingVal;
};

// Updated inline parser accepting raw memory buffer directly
inline bool ParsePubkeyInternal(const uint8_t* dataBytes, size_t dataSize, ParsedPubkey& outData) {
    if (!dataBytes || dataSize == 0) return false;

    // Wrap the raw memory buffer in a binary string stream
    std::string buffer(reinterpret_cast<const char*>(dataBytes), dataSize);
    std::istringstream f(buffer, std::ios::binary);

    auto readInt = [&f]() -> uint32_t {
        uint32_t val = 0;
        f.read(reinterpret_cast<char*>(&val), 4);
        return val;
        };

    // 1. Validate Magics
    uint32_t magic1 = readInt();
    if (magic1 != 0x44556677) return false;

    f.seekg(4, std::ios::cur); // Skip 4 bytes
    uint32_t fieldDataSize = readInt();
    uint32_t magic2 = readInt();
    if (magic2 != 0x00112233) return false;

    f.seekg(4, std::ios::cur); // Skip 4 bytes

    // 2. Read Meta configuration bytes/ints
    uint8_t mustBe0 = f.get();
    if (mustBe0 != 0) return false;

    outData.modulusSize = f.get();
    outData.orderSize = f.get();

    uint32_t data[9];
    for (int i = 0; i < 9; ++i) {
        data[i] = readInt();
    }

    outData.extDeg1 = data[3];
    outData.extDeg2 = data[4];
    outData.numBases = data[8];

    f.seekg(1, std::ios::cur); // Skip 1 byte

    // 3. Read H1 Bases
    outData.h1Bases.resize(outData.numBases);
    f.read(reinterpret_cast<char*>(outData.h1Bases.data()), outData.numBases);

    // 4. Read Modulus & Order
    outData.modulus.resize(outData.modulusSize);
    f.read(reinterpret_cast<char*>(outData.modulus.data()), outData.modulusSize);

    outData.order.resize(outData.orderSize);
    f.read(reinterpret_cast<char*>(outData.order.data()), outData.orderSize);

    // 5. Read Extension Minimum Polynomials
    outData.k3MinPoly.resize(outData.extDeg1 + 1);
    f.read(reinterpret_cast<char*>(outData.k3MinPoly.data()), outData.extDeg1 + 1);

    outData.k6MinPoly.resize(outData.extDeg2 + 1);
    f.read(reinterpret_cast<char*>(outData.k6MinPoly.data()), outData.extDeg2 + 1);

    // Skip intermediate padding block
    f.seekg(outData.modulusSize * 2, std::ios::cur);

    // 6. Read Curve Parameters (a and b)
    outData.curveA.resize(outData.modulusSize);
    f.read(reinterpret_cast<char*>(outData.curveA.data()), outData.modulusSize);

    outData.curveB.resize(outData.modulusSize);
    f.read(reinterpret_cast<char*>(outData.curveB.data()), outData.modulusSize);

    // 7. Jump to Point data section
    f.seekg(fieldDataSize + 12, std::ios::beg);

    // Read Points (Qi bases)
    outData.points.resize(outData.numBases);
    for (uint32_t i = 0; i < outData.numBases; ++i) {
        outData.points[i].x.resize(outData.extDeg1, std::vector<uint8_t>(outData.modulusSize));
        for (uint32_t j = 0; j < outData.extDeg1; ++j) {
            f.read(reinterpret_cast<char*>(outData.points[i].x[j].data()), outData.modulusSize);
        }

        outData.points[i].y.resize(outData.extDeg1, std::vector<uint8_t>(outData.modulusSize));
        for (uint32_t j = 0; j < outData.extDeg1; ++j) {
            f.read(reinterpret_cast<char*>(outData.points[i].y[j].data()), outData.modulusSize);
        }
    }

    // 8. Read Pairing Target Matrix
    outData.pairingVal.resize(outData.extDeg2, std::vector<std::vector<uint8_t>>(outData.extDeg1, std::vector<uint8_t>(outData.modulusSize)));
    for (uint32_t i = 0; i < outData.extDeg2; ++i) {
        for (uint32_t j = 0; j < outData.extDeg1; ++j) {
            f.read(reinterpret_cast<char*>(outData.pairingVal[i][j].data()), outData.modulusSize);
        }
    }

    return true;
}