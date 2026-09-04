#include "pch.h"
#include "Helpers.h"

// 1. Core Functions (BuildAndEncryptCipherBlock, ReadBackParameters, etc.)
// ... (paste these here if they aren't already in your pch.h)

// 2. Exported DLL Functions
extern "C"
{
    __declspec(dllexport) int GetInstallationIdString(
        uint32_t groupID,
        uint32_t serial,
        uint64_t securityID,
        int64_t hwid,
        wchar_t* outBuffer,
        int bufferSize
    ) {
        try {
            std::vector<uint8_t> pkeyData(88, 0);
            std::memcpy(pkeyData.data() + 16, &groupID, 4);
            std::memcpy(pkeyData.data() + 24, &serial, 4);
            std::memcpy(pkeyData.data() + 32, &securityID, 8);

            std::vector<uint8_t> cipherBlock;
            __int64 hr = BuildAndEncryptCipherBlock(pkeyData.data(), hwid, cipherBlock);
            if (hr != 0) return static_cast<int>(hr);

            std::wstring rawDecimal = IidHelper::BinaryToDecimalString(cipherBlock, 179);
            std::wstring formattedIid = IidHelper::FormatInstallationId(rawDecimal);

            if (outBuffer && bufferSize > static_cast<int>(formattedIid.length())) {
                wcscpy_s(outBuffer, bufferSize, formattedIid.c_str());
                return 0;
            }
            return -1;
        }
        catch (...) {
            return -2;
        }
    }

    __declspec(dllexport) int ReadParametersFromString(
        const wchar_t* formattedIid,
        DecodedParameters* outParams
    ) {
        try {
            if (!formattedIid || !outParams) return -1;

            std::wstring fIid(formattedIid);
            std::wstring rawDigits = IidHelper::StripCheckDigits(fIid);
            std::vector<uint8_t> decodedShifted23 = IidHelper::DecimalStringToBinary(rawDigits, 23);
            std::vector<uint8_t> decodedCipher22 = IidHelper::UnshiftBlock(decodedShifted23);
            EncryptionContextHelper::Process(22, decodedCipher22.data(), true);

            *outParams = ReadBackParameters(decodedCipher22);
            return 0;
        }
        catch (...) {
            return -1;
        }
    }
}