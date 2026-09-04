using System;
using System.Security.Cryptography;
using System.Text;

namespace Msft2009
{
    public static class MSFT
    {

        public static int GetInstallationIdString(
                uint groupID,
                uint serial,
                ulong securityID,
                long hwid,
                out string formattedIid
            )
        {
            formattedIid = string.Empty;
            try
            {
                byte[] pkeyData = new byte[88];
                Buffer.BlockCopy(BitConverter.GetBytes(groupID), 0, pkeyData, 16, 4);
                Buffer.BlockCopy(BitConverter.GetBytes(serial), 0, pkeyData, 24, 4);
                Buffer.BlockCopy(BitConverter.GetBytes(securityID), 0, pkeyData, 32, 8);

                byte[] cipherBlock;
                long hr = InstallationIdManager.BuildAndEncryptCipherBlock(pkeyData, hwid, out cipherBlock);
                if (hr != 0) return (int)hr;

                string rawDecimal = IidHelper.BinaryToDecimalString(cipherBlock, 179);
                formattedIid = IidHelper.FormatInstallationId(rawDecimal);
                return 0;
            }
            catch
            {
                return -2;
            }
        }

        public static int ReadParametersFromString(
            string formattedIid,
            out DecodedParameters outParams
        )
        {
            outParams = new DecodedParameters();
            try
            {
                if (string.IsNullOrEmpty(formattedIid)) return -1;

                string rawDigits = IidHelper.StripCheckDigits(formattedIid);
                byte[] decodedShifted23 = IidHelper.DecimalStringToBinary(rawDigits, 23);
                byte[] decodedCipher22 = IidHelper.UnshiftBlock(decodedShifted23);
                EncryptionContextHelper.Process(22, decodedCipher22, true);

                outParams = InstallationIdManager.ReadBackParameters(decodedCipher22);
                return 0;
            }
            catch
            {
                return -1;
            }
        }
    }
}

public class IidHelper
{
    public static byte[] DecimalStringToBinary(string decimalStr, int byteCount)
    {
        byte[] buffer = new byte[byteCount];

        foreach (char ch in decimalStr)
        {
            if (ch < '0' || ch > '9') continue;
            uint carry = (uint)(ch - '0');

            for (int i = byteCount; i > 0; --i)
            {
                uint value = (uint)buffer[i - 1] * 10u + carry;
                buffer[i - 1] = (byte)(value & 0xFF);
                carry = value >> 8;
            }

            if (carry != 0)
            {
                throw new InvalidOperationException("Decimal string value exceeds byte buffer capacity.");
            }
        }

        Array.Reverse(buffer);
        return buffer;
    }

    public static string BinaryToDecimalString(byte[] src, int bitCount)
    {
        double v11 = Math.Log10(2.0);
        double v12 = v11 * bitCount / Math.Log10(10.0);

        int digitCount = (int)v12 + 1;
        if (v12 <= (int)v12)
        {
            digitCount = (int)v12;
        }
        if (digitCount <= 0) return string.Empty;

        byte[] buffer = (byte[])src.Clone();
        int v5 = buffer.Length;
        char[] resultChars = new string('0', digitCount).ToCharArray();

        int v13 = digitCount;
        int v16 = v5 - 1;

        do
        {
            v13--;
            uint remainder = 0;
            if (v16 >= 0)
            {
                int currentIndex = v16;
                int innerCount = v5;
                do
                {
                    uint current = buffer[currentIndex] + (remainder << 8);
                    buffer[currentIndex] = (byte)(current / 10);
                    remainder = current % 10;
                    currentIndex--;
                    innerCount--;
                } while (innerCount > 0);
            }
            resultChars[v13] = (char)('0' + remainder);
        } while (v13 > 0);

        return new string(resultChars);
    }

    public static string FormatInstallationId(string rawDigits)
    {
        StringBuilder formatted = new StringBuilder();
        int totalLen = rawDigits.Length;
        int groupSize = 6;
        int groupCount = (totalLen + groupSize - 1) / groupSize;

        for (int g = 0; g < groupCount; ++g)
        {
            int start = g * groupSize;
            int len = Math.Min(groupSize, totalLen - start);
            int weightedSum = 0;

            for (int i = 0; i < len; ++i)
            {
                char c = rawDigits[start + i];
                int digit = c - '0';

                if (i % 2 != 0)
                {
                    weightedSum += 2 * digit;
                }
                else
                {
                    weightedSum += digit;
                }

                formatted.Append(c);
            }

            int checkDigit = weightedSum % 7;
            formatted.Append((char)('0' + checkDigit));
        }

        return formatted.ToString();
    }

    public static string StripCheckDigits(string formattedIid)
    {
        StringBuilder raw = new StringBuilder();
        for (int i = 0; i < formattedIid.Length; ++i)
        {
            if (((i + 1) % 7) != 0)
                raw.Append(formattedIid[i]);
        }
        return raw.ToString();
    }

    public static byte[] UnshiftBlock(byte[] shifted)
    {
        if (shifted.Length != 23)
        {
            throw new ArgumentException("Expected 23-byte shifted block.");
        }

        byte[] cipher = new byte[22];
        for (int i = 0; i < 22; ++i)
        {
            cipher[i] = (byte)(
                (shifted[i] >> 3) |
                ((shifted[i + 1] & 0x07) << 5)
            );
        }
        return cipher;
    }
}

public class Sha1Helper
{
    private readonly IncrementalHash _hasher;

    public Sha1Helper()
    {
        _hasher = IncrementalHash.CreateHash(HashAlgorithmName.SHA1);
    }

    public void Update(byte[] data, int offset, int count)
    {
        _hasher.AppendData(data, offset, count);
    }

    public void Update(byte[] data)
    {
        _hasher.AppendData(data);
    }

    public void Finalize(byte[] digest)
    {
        byte[] hash = _hasher.GetHashAndReset();
        Buffer.BlockCopy(hash, 0, digest, 0, Math.Min(hash.Length, digest.Length));
    }
}

public class EncryptionContextHelper
{
    private static void GetDefaultContext(uint[] roundKeys)
    {
        ulong[] constants = {
            0x84D8F8F0D45EC86B, 0xF413937D2F2A4177,
            0xBB9515A2E6668A1B, 0x972B328367B09D0E,
            0xEEDC7D7CCDD9FE49, 0xEB3B0BE7DF1207B0,
            0xCFA627FDDF98BD56, 0x573A73F8C236845D
        };
        for (int i = 0; i < 8; i++)
        {
            roundKeys[i * 2] = (uint)(constants[i] & 0xFFFFFFFF);
            roundKeys[i * 2 + 1] = (uint)(constants[i] >> 32);
        }
    }

    private static int RunRoundHash(byte[] block, int blockSize, uint roundKey, int bitLen, byte[] outputHash)
    {
        Sha1Helper sha1 = new Sha1Helper();
        byte[] prefix = { 121 }; // 'y' domain separator
        sha1.Update(prefix, 0, 1);
        sha1.Update(block, 0, blockSize);

        byte[] roundKeyBytes = BitConverter.GetBytes(roundKey);
        sha1.Update(roundKeyBytes, 0, roundKeyBytes.Length);

        byte[] digest = new byte[20];
        sha1.Finalize(digest);

        int byteCount = (bitLen + 31) >> 5;
        Array.Copy(digest, 0, outputHash, 0, 4 * byteCount);

        if (byteCount > 0)
        {
            int lastIndex = 4 * (byteCount - 1);
            uint lastDword = BitConverter.ToUInt32(outputHash, lastIndex);
            lastDword >>= (32 * byteCount - bitLen);
            byte[] dwordBytes = BitConverter.GetBytes(lastDword);
            Array.Copy(dwordBytes, 0, outputHash, lastIndex, 4);
        }
        return 0;
    }

    public static int Process(uint size, byte[] data, bool decrypt = false)
    {
        uint halfSize = size >> 1;
        if (halfSize == 0) return -2147024809;

        uint[] roundKeys = new uint[16];
        GetDefaultContext(roundKeys);

        byte[] left = new byte[halfSize];
        byte[] right = new byte[halfSize];
        byte[] temp = new byte[halfSize];
        byte[] roundHashOutput = new byte[((int)halfSize + 3) & ~3];

        Buffer.BlockCopy(data, 0, left, 0, (int)halfSize);
        Buffer.BlockCopy(data, (int)halfSize, right, 0, (int)halfSize);

        int bitLen = (int)(8 * halfSize);

        if (!decrypt)
        {
            for (int round = 0; round < 16; ++round)
            {
                RunRoundHash(right, (int)halfSize, roundKeys[round], bitLen, roundHashOutput);
                for (int i = 0; i < halfSize; ++i)
                {
                    temp[i] = right[i];
                    right[i] = (byte)(left[i] ^ roundHashOutput[i]);
                    left[i] = temp[i];
                }
            }
        }
        else
        {
            for (int round = 15; round >= 0; --round)
            {
                RunRoundHash(left, (int)halfSize, roundKeys[round], bitLen, roundHashOutput);
                for (int i = 0; i < halfSize; ++i)
                {
                    byte old_left = (byte)(right[i] ^ roundHashOutput[i]);
                    byte old_right = left[i];
                    left[i] = old_left;
                    right[i] = old_right;
                }
            }
        }

        Buffer.BlockCopy(left, 0, data, 0, (int)halfSize);
        Buffer.BlockCopy(right, 0, data, (int)halfSize, (int)halfSize);
        return 0;
    }
}

public struct DecodedParameters
{
    public uint securityID;
    public ushort groupID;
    public uint serial;
    public long hwid;
}

public class InstallationIdManager
{
    public static long BuildAndEncryptCipherBlock(byte[] pKeyDataStruct, long hwid, out byte[] outCipherBlock)
    {
        outCipherBlock = new byte[22];
        uint var50 = 0;

        if (pKeyDataStruct == null) return 0x80070057; // E_INVALIDARG

        byte v6 = pKeyDataStruct[37];
        ushort v9 = BitConverter.ToUInt16(pKeyDataStruct, 32);

        byte[] v9Bytes = BitConverter.GetBytes(v9);
        outCipherBlock[0] = v9Bytes[0];
        outCipherBlock[1] = v9Bytes[1];
        outCipherBlock[2] = pKeyDataStruct[34];
        byte v9_low = (byte)(pKeyDataStruct[35] & 0x0F);
        outCipherBlock[3] = (byte)((16 * v6) | (v9_low & 0x0F));

        byte v13 = (byte)(pKeyDataStruct[38] >> 4);
        outCipherBlock[4] = (byte)((v6 >> 4) | (16 * pKeyDataStruct[38]));
        outCipherBlock[5] = (byte)(v13 & 1);

        int v7Offset = 16;
        int v14Idx = 5;
        int v12Idx = 6;
        int v11 = 2;
        do
        {
            int srcIdx = v7Offset + (v14Idx - 5);
            byte v16 = pKeyDataStruct[srcIdx];
            outCipherBlock[v14Idx] = (byte)(outCipherBlock[v14Idx] & 1u);
            outCipherBlock[v12Idx] = (byte)(outCipherBlock[v12Idx] & ~1u);
            outCipherBlock[v14Idx] = (byte)(outCipherBlock[v14Idx] | (byte)(2 * v16));
            outCipherBlock[v12Idx] = (byte)(outCipherBlock[v12Idx] | (byte)(v16 >> 7));
            v14Idx++; v12Idx++; v11--;
        } while (v11 > 0);

        uint v18 = BitConverter.ToUInt32(pKeyDataStruct, 20);
        outCipherBlock[7] = (byte)(outCipherBlock[7] ^ ((outCipherBlock[7] ^ (2 * pKeyDataStruct[18])) & 0x1E));

        uint v5 = 0;
        if (v18 != 0) v5 = 1000000 * v18;
        uint serialVal = BitConverter.ToUInt32(pKeyDataStruct, 24);
        var50 = v5 + serialVal;

        byte[] var50Bytes = BitConverter.GetBytes(var50);
        int v21 = 0;
        int v22Idx = 8;
        int v23 = 3;
        do
        {
            byte v24_val = var50Bytes[v21];
            byte v25 = outCipherBlock[v21 + 7];
            outCipherBlock[v22Idx] = (byte)(outCipherBlock[v22Idx] & 0xE0u);
            outCipherBlock[v22Idx] = (byte)(outCipherBlock[v22Idx] | (byte)(v24_val >> 3));
            outCipherBlock[v21 + 7] = (byte)((v25 & 0x1F) | (32 * v24_val));
            v21++; v22Idx++; v23--;
        } while (v23 > 0);

        outCipherBlock[10] = (byte)((32 * (var50 >> 24)) | (outCipherBlock[10] & 0x1F));
        uint seqVal = BitConverter.ToUInt32(pKeyDataStruct, 28);
        byte byte3_v50 = (byte)(var50 >> 24);
        outCipherBlock[11] = (byte)(((seqVal != 0) ? 8 : 0) | ((outCipherBlock[11] & 0xF0) ^ ((byte3_v50 >> 3) & 7)));

        byte[] hwidBytes = BitConverter.GetBytes(hwid);
        int v26Idx = 12;
        int v27 = 8;
        int v28_idx = 0;
        do
        {
            byte v29 = hwidBytes[v28_idx];
            byte v30 = outCipherBlock[v28_idx + 11];
            outCipherBlock[v26Idx] = (byte)(outCipherBlock[v26Idx] & 0xF0u);
            outCipherBlock[v26Idx] = (byte)(outCipherBlock[v26Idx] | (byte)(v29 >> 4));
            outCipherBlock[v28_idx + 11] = (byte)((v30 & 0x0F) | (16 * v29));
            v28_idx++; v26Idx++; v27--;
        } while (v27 > 0);

        EncryptionContextHelper.Process(22, outCipherBlock, false);

        byte[] shiftedBlock = new byte[23];
        for (int i = 0; i < 22; ++i)
        {
            byte v40 = outCipherBlock[i];
            byte v41 = shiftedBlock[i];
            shiftedBlock[i + 1] = (byte)(shiftedBlock[i + 1] & 0xF8);
            shiftedBlock[i + 1] = (byte)(shiftedBlock[i + 1] | (byte)(v40 >> 5));
            shiftedBlock[i] = (byte)((v41 & 0x07) | (v40 << 3));
        }
        outCipherBlock = shiftedBlock;

        return 0;
    }

    public static DecodedParameters ReadBackParameters(byte[] plaintext22)
    {
        DecodedParameters paramsStruct = new DecodedParameters();
        if (plaintext22 == null || plaintext22.Length < 22) return paramsStruct;

        ushort secIdLow = BitConverter.ToUInt16(plaintext22, 0);
        byte secIdByte2 = plaintext22[2];
        byte secIdNibble = (byte)(plaintext22[3] & 0x0F);

        paramsStruct.securityID = (uint)(secIdLow | (secIdByte2 << 16) | (secIdNibble << 24));

        byte[] groupIDBytes = new byte[2];
        for (int i = 0; i < 2; ++i)
        {
            groupIDBytes[i] = (byte)(
                (plaintext22[5 + i] >> 1) | ((plaintext22[6 + i] & 0x01) << 7)
            );
        }
        paramsStruct.groupID = BitConverter.ToUInt16(groupIDBytes, 0);

        uint var50 = 0;
        byte[] var50Bytes = new byte[4];
        for (int i = 0; i < 3; ++i)
        {
            var50Bytes[i] = (byte)(
                (plaintext22[7 + i] >> 5) | ((plaintext22[8 + i] & 0x1F) << 3)
            );
        }

        // Reconstruct the 4th byte (bits 24-31) from indices 10 and 11
        byte byte3_high = (byte)(plaintext22[10] >> 5);
        byte byte3_low = (byte)((plaintext22[11] & 0x07) << 3);
        var50Bytes[3] = (byte)(byte3_high | byte3_low);

        paramsStruct.serial = BitConverter.ToUInt32(var50Bytes, 0);

        byte[] hwidBytes = new byte[8];
        for (int i = 0; i < 8; ++i)
        {
            byte high = (byte)((plaintext22[12 + i] & 0x0F) << 4);
            byte low = (byte)(plaintext22[11 + i] >> 4);
            hwidBytes[i] = (byte)(high | low);
        }
        paramsStruct.hwid = BitConverter.ToInt64(hwidBytes, 0);

        return paramsStruct;
    }
}