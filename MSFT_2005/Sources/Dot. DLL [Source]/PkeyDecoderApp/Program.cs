using PidKeyPlugIn;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Xml.Linq;

class Program
{
    // CD-Key Base-24 Alphabet
    private static readonly string Alphabet = "BCDFGHJKMPQRTVWXY2346789";

    static int Main(string[] args)
    {
        Console.WriteLine("=== C# PKey Config Enumerator & Validator ===");

        if (args.Length < 1)
        {
            Console.WriteLine("Usage: PKeyValidatorApp.exe <CD-KEY> [ConfigFilePath]");
            Console.WriteLine("Example: PKeyValidatorApp.exe XXXXX-XXXXX-XXXXX-XXXXX-XXXXX pkeyconfig.xrm-ms");
            return 1;
        }

        string cdKey = args[0];
        string configPath = (args.Length >= 2) ? args[1] : "pkeyconfig.xrm-ms";

        // 1. Encode CD-Key to 16-byte binary array
        byte[] bEncryptArray;
        try
        {
            bEncryptArray = EncodeBinaryKey(cdKey);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error encoding CD-Key: {ex.Message}");
            return 1;
        }

        // 2. Load and parse configuration file (.xrm-ms)
        if (!File.Exists(configPath))
        {
            Console.WriteLine($"Error: Configuration file not found: {configPath}");
            return 1;
        }

        List<PublicKeyEntry> publicKeys;
        try
        {
            publicKeys = ExtractPublicKeysFromConfig(configPath);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error parsing config file: {ex.Message}");
            return 1;
        }

        Console.WriteLine($"Loaded {publicKeys.Count} public key groups from configuration. Scanning using all {Environment.ProcessorCount} CPU threads...");

        // 3. Loop through all public keys in parallel using all CPU threads
        var sw = Stopwatch.StartNew();
        bool foundValid = false;

        int seq = 0;
        string cfg = null;
        byte[] h = null;
        byte[] u = null;
        string matchedGroupId = null;
        object threadLock = new object();

        // Configure to utilize all available processor cores
        var parallelOptions = new ParallelOptions
        {
            MaxDegreeOfParallelism = Environment.ProcessorCount
        };

        Parallel.ForEach(publicKeys, parallelOptions, (pk, state) =>
        {
            if (foundValid) state.Stop(); // Exit early if another thread already found it
            if (pk.PublicKeyBytes.Length != 1579) return; // Standard size check

            int localSeq;
            string localCfg;
            byte[] localH, localU;

            bool success = PKeyCalc.TryPubKey(pk.PublicKeyBytes, bEncryptArray, out localSeq, out localCfg, out localH, out localU);

            if (success)
            {
                lock (threadLock)
                {
                    if (!foundValid)
                    {
                        seq = localSeq;
                        cfg = localCfg;
                        h = localH;
                        u = localU;
                        matchedGroupId = pk.GroupId;
                        foundValid = true;
                    }
                }
                state.Stop();
            }
        });

        sw.Stop();

        if (!foundValid)
        {
            Console.WriteLine($"\nStatus       : Invalid Key (Signature mismatch across public key groups)");
            Console.WriteLine($"Elapsed Time : {sw.Elapsed.TotalSeconds:F2}s");
            return 1;
        }

        // 4. Unpack DECODED_PKEY struct bitfields from Unique ID
        ulong rawUniqueId = BitConverter.ToUInt64(u, 0);
        bool upgradeFlag = (rawUniqueId & 0x1) == 1;
        uint pid = (uint)((rawUniqueId >> 1) & 0x3FFFFFFF);
        uint auth = (uint)((rawUniqueId >> 31) & 0x3FF);

        // Derive hash data
        int value1 = (u[3] >> 7) | (u[4] * 2);
        int value2 = (u[5] * 2 | u[4] >> 7) & 3;
        byte b1 = (byte)(value1 & 0xFF);
        byte b2 = (byte)(value2 & 0xFF);
        byte[] hashData = new byte[] { b1, b2, 0, 0, 0, 0, 0, 0 };

        // 5. Output Results
        Console.WriteLine("\n=== Validation Successful ===");
        Console.WriteLine($"Status       : Valid Key");
        Console.WriteLine($"Upgrade Flag : {(upgradeFlag ? 1 : 0)}");
        Console.WriteLine($"Serial (PID) : {pid} (0x{pid:X})");
        Console.WriteLine($"Auth / SecID : {auth} (0x{auth:X})");
        Console.WriteLine($"Group ID     : {matchedGroupId}");
        Console.WriteLine($"Key ID       : {seq}");
        Console.WriteLine($"Config String: {cfg}");
        Console.WriteLine($"Elapsed Time : {sw.Elapsed.TotalSeconds:F2}s");

        return 0;
    }

    /// <p>Encodes a 25-character CD-Key into a 16-byte binary array using Base-24 arithmetic.</p>
    private static byte[] EncodeBinaryKey(string cdKey)
    {
        string rawKey = new string(cdKey.Where(c => c != '-').Select(char.ToUpper).ToArray());
        if (rawKey.Length != 25)
        {
            throw new ArgumentException("CD-Key must be exactly 25 characters (excluding hyphens).");
        }

        int[] digits = new int[25];
        bool isNKey = false;
        int digitCount = 0;

        foreach (char ch in rawKey)
        {
            if (ch == 'N' && !isNKey)
            {
                isNKey = true;
                for (int i = digitCount; i > 0; i--)
                {
                    digits[i] = digits[i - 1];
                }
                digits[0] = digitCount;
                digitCount++;
                continue;
            }

            int val = Alphabet.IndexOf(ch);
            if (val == -1)
            {
                throw new ArgumentException($"Invalid character '{ch}' in CD-Key.");
            }
            digits[digitCount] = val;
            digitCount++;
        }

        byte[] binary = new byte[16];
        foreach (int digit in digits)
        {
            uint carry = (uint)digit;
            for (int i = 0; i < 16; i++)
            {
                uint res = (uint)(binary[i] * 24) + carry;
                binary[i] = (byte)(res & 0xFF);
                carry = res >> 8;
            }
        }

        if (isNKey)
        {
            binary[14] |= 0x08;
        }

        return binary;
    }

    private class PublicKeyEntry
    {
        public string GroupId { get; set; }
        public byte[] PublicKeyBytes { get; set; }
    }

    /// <summary>
    /// Parses the .xrm-ms file, extracts the inner base64 pkeyConfigData, and retrieves all PublicKeys & GroupIds.
    /// </summary>
    private static List<PublicKeyEntry> ExtractPublicKeysFromConfig(string configPath)
    {
        string outerXml = File.ReadAllText(configPath);

        // Find pkeyConfigData node
        int infoBinPos = outerXml.IndexOf("pkeyConfigData", StringComparison.OrdinalIgnoreCase);
        if (infoBinPos == -1) throw new Exception("Could not find 'pkeyConfigData' in configuration file.");

        int contentStart = outerXml.IndexOf('>', infoBinPos) + 1;
        int contentEnd = outerXml.IndexOf("</", contentStart);
        string base64InfoBin = outerXml.Substring(contentStart, contentEnd - contentStart);

        // Clean whitespace/newlines from base64 string
        base64InfoBin = new string(base64InfoBin.Where(c => !char.IsWhiteSpace(c)).ToArray());

        byte[] decodedInnerBytes = Convert.FromBase64String(base64InfoBin);
        string innerXml;

        // Handle UTF-16 vs UTF-8 encoding
        if (decodedInnerBytes.Length > 2 && decodedInnerBytes[1] == 0)
        {
            innerXml = Encoding.Unicode.GetString(decodedInnerBytes);
        }
        else
        {
            innerXml = Encoding.UTF8.GetString(decodedInnerBytes);
        }

        var results = new List<PublicKeyEntry>();
        int searchPos = 0;

        while (true)
        {
            int pkStart = innerXml.IndexOf("<PublicKey>", searchPos, StringComparison.OrdinalIgnoreCase);
            if (pkStart == -1) pkStart = innerXml.IndexOf("<pkc:PublicKey>", searchPos, StringComparison.OrdinalIgnoreCase);
            if (pkStart == -1) break;

            int pkEnd = innerXml.IndexOf("</PublicKey>", pkStart, StringComparison.OrdinalIgnoreCase);
            if (pkEnd == -1) pkEnd = innerXml.IndexOf("</pkc:PublicKey>", pkStart, StringComparison.OrdinalIgnoreCase);
            if (pkEnd == -1) break;

            string pkBlock = innerXml.Substring(pkStart, pkEnd - pkStart);
            searchPos = pkEnd;

            string groupId = ExtractTag(pkBlock, "GroupId");
            string pubKeyB64 = ExtractTag(pkBlock, "PublicKeyValue");

            if (!string.IsNullOrEmpty(pubKeyB64))
            {
                pubKeyB64 = new string(pubKeyB64.Where(c => !char.IsWhiteSpace(c)).ToArray());
                try
                {
                    byte[] pubKeyBytes = Convert.FromBase64String(pubKeyB64);
                    results.Add(new PublicKeyEntry { GroupId = groupId, PublicKeyBytes = pubKeyBytes });
                }
                catch
                {
                    // Ignore malformed base64 blocks
                }
            }
        }

        return results;
    }

    private static string ExtractTag(string xml, string tagName)
    {
        string tag1 = $"<{tagName}>";
        string tag2 = $"<pkc:{tagName}>";

        int start = xml.IndexOf(tag1, StringComparison.OrdinalIgnoreCase);
        if (start == -1) start = xml.IndexOf(tag2, StringComparison.OrdinalIgnoreCase);
        if (start == -1) return string.Empty;

        start = xml.IndexOf('>', start) + 1;
        string endTag1 = $"</{tagName}>";
        string endTag2 = $"</pkc:{tagName}>";

        int end = xml.IndexOf(endTag1, start, StringComparison.OrdinalIgnoreCase);
        if (end == -1) end = xml.IndexOf(endTag2, start, StringComparison.OrdinalIgnoreCase);
        if (end == -1) return string.Empty;

        return xml.Substring(start, end - start);
    }
}