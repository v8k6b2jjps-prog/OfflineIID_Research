#define NOMINMAX
#include <windows.h>
#include <algorithm> 
#include <iostream>
#include <vector>
#include <string>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <iomanip>

// Helper to print byte vectors in hex for debugging
void PrintHex(const std::string& label, const std::vector<uint8_t>& data) {
    std::cout << "  [DEBUG] " << label << " [" << data.size() << "]: ";
    for (uint8_t b : data) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b) << " ";
    }
    std::cout << std::dec << "\n";
}

class IidHelper {
public:
    static std::wstring BinaryToDecimalString(const std::vector<uint8_t>& src, int bitCount) {
        double v11 = std::log10(2.0);
        double v12 = v11 * static_cast<double>(bitCount) / std::log10(10.0);

        int digitCount = static_cast<int>(v12) + 1;
        if (v12 <= static_cast<double>(static_cast<int>(v12))) {
            digitCount = static_cast<int>(v12);
        }
        if (digitCount <= 0) return L"";

        std::vector<uint8_t> buffer = src;
        size_t v5 = buffer.size();
        std::wstring result(digitCount, L'0');

        int v13 = digitCount;
        int v16 = static_cast<int>(v5) - 1;

        do {
            v13--;
            uint32_t remainder = 0;
            if (v16 >= 0) {
                int currentIndex = v16;
                size_t innerCount = v5;
                do {
                    uint32_t current = buffer[currentIndex] + (remainder << 8);
                    buffer[currentIndex] = static_cast<uint8_t>(current / 10);
                    remainder = current % 10;
                    currentIndex--;
                    innerCount--;
                } while (innerCount > 0);
            }
            result[v13] = static_cast<wchar_t>(L'0' + remainder);
        } while (v13 > 0);

        return result;
    }

    static std::vector<uint8_t> DecimalStringToBinary(const std::wstring& decimal, size_t byteCount) {
        std::vector<uint8_t> buffer(byteCount, 0);

        for (wchar_t ch : decimal) {
            if (ch < L'0' || ch > L'9') continue;
            uint32_t carry = static_cast<uint32_t>(ch - L'0');

            for (size_t i = byteCount; i > 0; --i) {
                uint32_t value = static_cast<uint32_t>(buffer[i - 1]) * 10u + carry;
                buffer[i - 1] = static_cast<uint8_t>(value & 0xFF);
                carry = value >> 8;
            }

            if (carry != 0) {
                throw std::runtime_error("Decimal string value exceeds byte buffer capacity.");
            }
        }

        // Fix endianness/byte traversal mismatch to match encoder layout
        std::reverse(buffer.begin(), buffer.end());

        return buffer;
    }

    static std::wstring FormatInstallationId(const std::wstring& rawDigits) {
        std::wstring formatted;
        size_t totalLen = rawDigits.length();
        size_t groupSize = 6;
        size_t groupCount = (totalLen + groupSize - 1) / groupSize;

        for (size_t g = 0; g < groupCount; ++g) {
            size_t start = g * groupSize;
            size_t len = std::min(groupSize, totalLen - start);
            int weightedSum = 0;

            for (size_t i = 0; i < len; ++i) {
                wchar_t c = rawDigits[start + i];
                int digit = c - L'0';

                if (i % 2 != 0) {
                    weightedSum += 2 * digit;
                }
                else {
                    weightedSum += digit;
                }

                formatted.push_back(c);
            }

            int checkDigit = weightedSum % 7;
            formatted.push_back(L'0' + checkDigit);
        }

        return formatted;
    }

    static std::wstring StripCheckDigits(const std::wstring& formattedIid) {
        std::wstring raw;
        for (size_t i = 0; i < formattedIid.size(); ++i) {
            if (((i + 1) % 7) != 0)
                raw.push_back(formattedIid[i]);
        }
        return raw;
    }

    // Inverse of 3-bit left shift
    static std::vector<uint8_t> UnshiftBlock(const std::vector<uint8_t>& shifted) {
        if (shifted.size() != 23) {
            throw std::runtime_error("Expected 23-byte shifted block.");
        }

        std::vector<uint8_t> cipher(22, 0);
        for (size_t i = 0; i < 22; ++i) {
            cipher[i] = static_cast<uint8_t>(
                (shifted[i] >> 3) |
                ((shifted[i + 1] & 0x07) << 5)
                );
        }
        return cipher;
    }
};

class Sha1Helper {
private:
    uint32_t state[5];
    uint32_t count[2];
    uint8_t buffer[64];

    static uint32_t rol32(uint32_t value, int bits) {
        return (value << bits) | (value >> (32 - bits));
    }

    void Transform(const uint8_t* blockBytes) {
        const uint32_t* a2 = reinterpret_cast<const uint32_t*>(blockBytes);
        uint32_t w[16];
        for (int i = 0; i < 16; ++i) {
            w[i] = _byteswap_ulong(a2[i]);
        }

        uint32_t expanded[80];
        for (int i = 0; i < 16; ++i) expanded[i] = w[i];
        for (int i = 16; i < 80; ++i) {
            uint32_t val = expanded[i - 3] ^ expanded[i - 8] ^ expanded[i - 14] ^ expanded[i - 16];
            expanded[i] = (val << 1) | (val >> 31);
        }

        uint32_t a = state[0], b = state[1], c = state[2], d = state[3], e = state[4];

        for (int i = 0; i < 80; ++i) {
            uint32_t f, k;
            if (i < 20) {
                f = (b & c) | (~b & d);
                k = 0x5A827999;
            }
            else if (i < 40) {
                f = b ^ c ^ d;
                k = 0x6ED9EBA1;
            }
            else if (i < 60) {
                f = (b & c) | (b & d) | (c & d);
                k = 0x8F1BBCDC;
            }
            else {
                f = b ^ c ^ d;
                k = 0xCA62C1D6;
            }

            uint32_t temp = rol32(a, 5) + f + e + k + expanded[i];
            e = d; d = c; c = rol32(b, 30); b = a; a = temp;
        }

        state[0] += a; state[1] += b; state[2] += c; state[3] += d; state[4] += e;
    }

public:
    Sha1Helper() { Reset(); }

    void Reset() {
        state[0] = 0x67452301; state[1] = 0xEFCDAB89; state[2] = 0x98BADCFE;
        state[3] = 0x10325476; state[4] = 0xC3D2E1F0;
        count[0] = count[1] = 0;
        std::memset(buffer, 0, sizeof(buffer));
    }

    void Update(const uint8_t* data, size_t len) {
        size_t i = 0;
        uint32_t j = count[0] & 0x3F;
        uint32_t new_count0 = count[0] + static_cast<uint32_t>(len);
        if (new_count0 < count[0]) count[1]++;
        count[0] = new_count0;

        size_t partLen = 64 - j;
        if (len >= partLen) {
            std::memcpy(&buffer[j], data, partLen);
            Transform(buffer);
            for (i = partLen; i + 63 < len; i += 64) {
                Transform(&data[i]);
            }
            j = 0;
        }
        else {
            i = 0;
        }
        std::memcpy(&buffer[j], &data[i], len - i);
    }

    void Finalize(uint8_t digest[20]) {
        uint64_t total_bits_low = static_cast<uint64_t>(count[0]) << 3;
        uint64_t total_bits_high = (static_cast<uint64_t>(count[1]) << 3) | (count[0] >> 29);

        uint8_t bits[8];
        bits[0] = static_cast<uint8_t>(total_bits_high >> 24);
        bits[1] = static_cast<uint8_t>(total_bits_high >> 16);
        bits[2] = static_cast<uint8_t>(total_bits_high >> 8);
        bits[3] = static_cast<uint8_t>(total_bits_high);
        bits[4] = static_cast<uint8_t>(total_bits_low >> 24);
        bits[5] = static_cast<uint8_t>(total_bits_low >> 16);
        bits[6] = static_cast<uint8_t>(total_bits_low >> 8);
        bits[7] = static_cast<uint8_t>(total_bits_low);

        uint32_t index = count[0] & 0x3F;
        uint32_t padLen = (index < 56) ? (56 - index) : (120 - index);

        static uint8_t padding[64] = { 0x80 };
        Update(padding, padLen);
        Update(bits, 8);

        for (int i = 0; i < 5; ++i) {
            uint32_t swapped = _byteswap_ulong(state[i]);
            std::memcpy(digest + (i * 4), &swapped, 4);
        }
    }
};

class EncryptionContextHelper {
private:
    static void GetDefaultContext(uint32_t roundKeys[16]) {
        uint64_t constants[8] = {
            0x84D8F8F0D45EC86BULL, 0xF413937D2F2A4177ULL,
            0xBB9515A2E6668A1BULL, 0x972B328367B09D0EULL,
            0xEEDC7D7CCDD9FE49ULL, 0xEB3B0BE7DF1207B0ULL,
            0xCFA627FDDF98BD56ULL, 0x573A73F8C236845DULL
        };
        std::memcpy(roundKeys, constants, sizeof(constants));
    }

    static int RunRoundHash(const uint8_t* block, size_t blockSize, uint32_t roundKey, int bitLen, uint8_t* outputHash) {
        Sha1Helper sha1;
        uint8_t prefix = 121; // 'y' domain separator
        sha1.Update(&prefix, 1);
        sha1.Update(block, blockSize);
        sha1.Update(reinterpret_cast<const uint8_t*>(&roundKey), sizeof(roundKey));

        uint8_t digest[20];
        sha1.Finalize(digest);

        size_t byteCount = (bitLen + 31) >> 5;
        std::memcpy(outputHash, digest, 4 * byteCount);

        if (byteCount > 0) {
            uint32_t* lastDword = reinterpret_cast<uint32_t*>(outputHash + 4 * (byteCount - 1));
            *lastDword >>= (32 * byteCount - bitLen);
        }
        return 0;
    }

public:
    static int Process(unsigned int size, uint8_t* data, bool decrypt = false) {
        unsigned int halfSize = size >> 1;
        if (halfSize == 0) return -2147024809;

        uint32_t roundKeys[16];
        GetDefaultContext(roundKeys);

        std::vector<uint8_t> left(halfSize);
        std::vector<uint8_t> right(halfSize);
        std::vector<uint8_t> temp(halfSize);
        std::vector<uint8_t> roundHashOutput((halfSize + 3) & ~3, 0);

        std::memcpy(left.data(), data, halfSize);
        std::memcpy(right.data(), data + halfSize, halfSize);

        int bitLen = 8 * halfSize;

        if (!decrypt) {
            // Encryption rounds (0 to 15)
            for (int round = 0; round < 16; ++round) {
                RunRoundHash(right.data(), halfSize, roundKeys[round], bitLen, roundHashOutput.data());
                for (size_t i = 0; i < halfSize; ++i) {
                    temp[i] = right[i];
                    right[i] = left[i] ^ roundHashOutput[i];
                    left[i] = temp[i];
                }
            }
        }
        else {
            // Decryption rounds (15 down to 0)
            for (int round = 15; round >= 0; --round) {
                RunRoundHash(left.data(), halfSize, roundKeys[round], bitLen, roundHashOutput.data());
                for (size_t i = 0; i < halfSize; ++i) {
                    uint8_t old_left = right[i] ^ roundHashOutput[i];
                    uint8_t old_right = left[i];
                    left[i] = old_left;
                    right[i] = old_right;
                }
            }
        }

        std::memcpy(data, left.data(), halfSize);
        std::memcpy(data + halfSize, right.data(), halfSize);
        return 0;
    }
};

__int64 BuildAndEncryptCipherBlock(const uint8_t* pKeyDataStruct, int64_t hwid, std::vector<uint8_t>& outCipherBlock) {
    outCipherBlock.assign(22, 0);
    uint32_t var50 = 0;

    const uint8_t* a1 = pKeyDataStruct;
    if (!a1) return 0x80070057;

    uint8_t v6 = a1[37];
    const uint8_t* v7 = a1 + 16;
    uint16_t v9 = *reinterpret_cast<const uint16_t*>(a1 + 32);

    *reinterpret_cast<uint16_t*>(outCipherBlock.data()) = v9;
    outCipherBlock[2] = a1[34];
    uint8_t v9_low = a1[35] & 0x0F;
    outCipherBlock[3] = (16 * v6) | (v9_low & 0x0F);

    uint8_t v13 = a1[38] >> 4;
    outCipherBlock[4] = (v6 >> 4) | (16 * a1[38]);
    outCipherBlock[5] = v13 & 1;

    uint8_t* v12 = outCipherBlock.data() + 6;
    uint8_t* v14 = outCipherBlock.data() + 5;
    intptr_t v15 = (intptr_t)v7 - (intptr_t)v14;

    int v11 = 2;
    do {
        uint8_t v16 = *reinterpret_cast<uint8_t*>(v15 + (intptr_t)v14);
        *v14 &= 1u;
        *v12 &= ~1u;
        *v14 = *v14 | (2 * v16);
        *v12 = *v12 | (v16 >> 7);
        v14++; v12++; v11--;
    } while (v11);

    uint32_t v18 = *reinterpret_cast<const uint32_t*>(a1 + 20);
    outCipherBlock[7] ^= (outCipherBlock[7] ^ (2 * a1[18])) & 0x1E;

    uint32_t v5 = 0;
    if (v18) v5 = 1000000 * v18;
    uint32_t serialVal = *reinterpret_cast<const uint32_t*>(a1 + 24);
    var50 = v5 + serialVal;

    intptr_t v21 = 0;
    uint8_t* v22 = outCipherBlock.data() + 8;
    int v23 = 3;
    do {
        uint8_t v24_val = reinterpret_cast<const uint8_t*>(&var50)[v21];
        uint8_t v25 = outCipherBlock[v21 + 7];
        *v22 &= 0xE0u;
        *v22++ |= (v24_val >> 3);
        outCipherBlock[v21 + 7] = (v25 & 0x1F) | (32 * v24_val);
        v21++; v23--;
    } while (v23);

    outCipherBlock[10] = (32 * (var50 >> 24)) | (outCipherBlock[10] & 0x1F);
    uint32_t seqVal = *reinterpret_cast<const uint32_t*>(a1 + 28);
    //outCipherBlock[11] = ((seqVal != 0) ? 8 : 0) | (outCipherBlock[11] & 0xF0) ^ ((var50 >> 3) & 7);
    uint8_t byte3_v50 = static_cast<uint8_t>(var50 >> 24);
    outCipherBlock[11] = ((seqVal != 0) ? 8 : 0) | (outCipherBlock[11] & 0xF0) ^ ((byte3_v50 >> 3) & 7);

    const uint8_t* hwidBytes = reinterpret_cast<const uint8_t*>(&hwid);
    uint8_t* v26 = outCipherBlock.data() + 12;
    int v27 = 8;
    int v28_idx = 0;
    do {
        uint8_t v29 = hwidBytes[v28_idx];
        uint8_t v30 = outCipherBlock[v28_idx + 11];
        *v26 &= 0xF0u;
        *v26++ |= (v29 >> 4);
        outCipherBlock[v28_idx + 11] = (v30 & 0x0F) | (16 * v29);
        v28_idx++; v27--;
    } while (v27);

    PrintHex("Unencrypted Plaintext 22B", outCipherBlock);

    // Encrypt
    EncryptionContextHelper::Process(22, outCipherBlock.data(), false);
    PrintHex("Encrypted Cipher 22B", outCipherBlock);

    // 3-bit left shift into 23 bytes
    std::vector<uint8_t> shiftedBlock(23, 0);
    for (int i = 0; i < 22; ++i) {
        uint8_t v40 = outCipherBlock[i];
        uint8_t v41 = shiftedBlock[i];
        shiftedBlock[i + 1] &= 0xF8;
        shiftedBlock[i + 1] |= (v40 >> 5);
        shiftedBlock[i] = (v41 & 0x07) | (v40 << 3);
    }
    outCipherBlock = shiftedBlock;
    PrintHex("Shifted 23B Buffer", outCipherBlock);

    return 0;
}

void ReadBackParameters(const std::vector<uint8_t>& plaintext22) {
    if (plaintext22.size() < 22) return;

    // 1. Extract Security ID (28-bit value packed across bytes 0 to 3)
    uint32_t securityID = 0;
    uint16_t secIdLow = *reinterpret_cast<const uint16_t*>(plaintext22.data());
    uint8_t secIdByte2 = plaintext22[2];
    uint8_t secIdNibble = plaintext22[3] & 0x0F;

    securityID = secIdLow | (static_cast<uint32_t>(secIdByte2) << 16) | (static_cast<uint32_t>(secIdNibble) << 24);

    // 2. Unpack Group ID (Bytes 5 and 6)
    uint16_t groupID = 0;
    for (int i = 0; i < 2; ++i) {
        uint8_t reconstructedByte = static_cast<uint8_t>(
            (plaintext22[5 + i] >> 1) | ((plaintext22[6 + i] & 0x01) << 7)
            );
        reinterpret_cast<uint8_t*>(&groupID)[i] = reconstructedByte;
    }

    // 3. Unpack Serial (Bytes 7 to 10)
    uint32_t var50 = 0;
    for (int i = 0; i < 3; ++i) {
        uint8_t extractedByte = static_cast<uint8_t>(
            (plaintext22[7 + i] >> 5) | ((plaintext22[8 + i] & 0x1F) << 3)
            );
        reinterpret_cast<uint8_t*>(&var50)[i] = extractedByte;
    }
    uint32_t serial = var50;    

    // 4. Unpack HWID (Bytes 11 to 19)
    int64_t hwid = 0;
    uint8_t hwidBytes[8] = { 0 };
    for (int i = 0; i < 8; ++i) {
        uint8_t high = (plaintext22[12 + i] & 0x0F) << 4;
        uint8_t low = plaintext22[11 + i] >> 4;
        hwidBytes[i] = high | low;
    }
    std::memcpy(&hwid, hwidBytes, 8);

    // Print Results
    std::wcout << L"\n--- Decoded Parameters ---" << std::endl;
    std::wcout << L"  - Group ID    : " << groupID << std::endl;
    std::wcout << L"  - Serial      : " << serial << std::endl;
    std::wcout << L"  - Security ID : " << securityID << std::endl;
    std::wcout << L"  - HWID        : " << hwid << std::endl;
}

typedef int64_t(__fastcall* InnerCallFunc)(void* signatureBase, int64_t hwid, int64_t reserved, wchar_t** pOutString);

int main() {
    std::wcout << L"=== PKey 2009 Encoder & Decoder Pipeline ===\n\n";

    std::vector<uint8_t> pkeyData(88, 0);
    uint32_t groupID = 4365;
    uint32_t serial = 9999;
    uint64_t securityID = 79956565659;
    int64_t hwid = -7995656565;

    std::memcpy(pkeyData.data() + 16, &groupID, 4);
    std::memcpy(pkeyData.data() + 24, &serial, 4);
    std::memcpy(pkeyData.data() + 32, &securityID, 8);

    // Load pidgenxIn.dll and execute the native encoder engine
    std::wstring formattedIid = L"";
    std::wstring dllPath = L"D:\\Software\\MS Tools Pack\\Product Key Tools\\pidgenxIn.dll";
    HMODULE hDll = LoadLibraryExW(dllPath.c_str(), NULL, LOAD_WITH_ALTERED_SEARCH_PATH);

    if (hDll) {
        // RVA calculation: 6442477368 (Absolute) - 0x180000000 (Preferred Base) = 0x6738
        uint32_t rva = 0x6738;
        InnerCallFunc innerCall = (InnerCallFunc)((uint8_t*)hDll + rva);

        wchar_t* pOutString = nullptr;
        int64_t result = innerCall(pkeyData.data(), hwid, 0LL, &pOutString);

        if (result >= 0 && pOutString != nullptr) {
            formattedIid = pOutString;
            std::wcout << L"PidgenX Formatted IID:\n" << formattedIid << L"\n\n";
            std::wcout << L"--------------------------------------------------\n\n";
        }
        else {
            std::fprintf(stderr, "[-] Native encoder call failed with code: 0x%016llX\n", result);
        }
        FreeLibrary(hDll);
    }
    else {
        std::cerr << "[-] Failed to load pidgenxIn.dll. Error: " << GetLastError() << "\n";
        return 1;
    }

    std::vector<uint8_t> cipherBlock;
    BuildAndEncryptCipherBlock(pkeyData.data(), hwid, cipherBlock);

    std::wstring rawDecimal = IidHelper::BinaryToDecimalString(cipherBlock, 179);
    formattedIid = IidHelper::FormatInstallationId(rawDecimal);

    std::wcout << L"Generated Formatted IID:\n" << formattedIid << L"\n\n";
    std::wcout << L"--------------------------------------------------\n\n";

    std::cout << "[DECODER] Starting decoding pipeline...\n";

    std::wstring rawDigits = IidHelper::StripCheckDigits(formattedIid);
    std::vector<uint8_t> decodedShifted23 = IidHelper::DecimalStringToBinary(rawDigits, 23);
    std::vector<uint8_t> decodedCipher22 = IidHelper::UnshiftBlock(decodedShifted23);

    EncryptionContextHelper::Process(22, decodedCipher22.data(), true);
    PrintHex("Decrypted Plaintext 22B", decodedCipher22);

    // Read back parameters from decrypted buffer
    ReadBackParameters(decodedCipher22);

    std::cout << "\n[DECODER SUCCESS] Pipeline completed.\n";
    return 0;
}