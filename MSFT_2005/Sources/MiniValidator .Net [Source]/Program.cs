// PKeyValidator - C# port of MiniValidator.cpp for the 32-bit PidKeyData.dll.
// Must be built as x86 (the DLL is PE32 / i386). Written in plain C# 5 so it
// compiles with the csc.exe that ships with Windows as well as with newer SDKs.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

internal static class Program
{
    // ------------------------------------------------------------------
    // Native exports. In the 32-bit DLL these are real __fastcall functions
    // (arg1 in ECX, arg2 in EDX, the rest on the stack, callee cleans up).
    // .NET cannot P/Invoke __fastcall, so the delegates are StdCall and point
    // at a tiny stub that moves the first two arguments into ECX/EDX.
    // ------------------------------------------------------------------
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int PubkeyParserFn(IntPtr pDstMem, IntPtr publicKeyBytes, uint size, IntPtr retValue);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int CalculateH1Fn(IntPtr pMem1, IntPtr pMem2, IntPtr pid3, IntPtr isValid, IntPtr h1Coeffs, IntPtr retValue);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int ExtractMFn(IntPtr pMem1, IntPtr h1Coeffs, IntPtr m, IntPtr retValue);

    [DllImport("kernel32", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr LoadLibraryW(string path);

    [DllImport("kernel32", SetLastError = true)]
    private static extern bool FreeLibrary(IntPtr module);

    [DllImport("kernel32", CharSet = CharSet.Ansi, ExactSpelling = true, BestFitMapping = false, SetLastError = true)]
    private static extern IntPtr GetProcAddress(IntPtr module, string name);

    [DllImport("kernel32", SetLastError = true)]
    private static extern IntPtr VirtualAlloc(IntPtr address, UIntPtr size, uint allocationType, uint protect);

    [DllImport("kernel32")]
    private static extern bool FlushInstructionCache(IntPtr process, IntPtr address, UIntPtr size);

    [DllImport("kernel32")]
    private static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32")]
    private static extern IntPtr GetCurrentThread();

    [DllImport("kernel32")]
    private static extern UIntPtr SetThreadAffinityMask(IntPtr thread, UIntPtr mask);

    [DllImport("kernel32", SetLastError = true)]
    private static extern bool GetLogicalProcessorInformationEx(int relationship, IntPtr buffer, ref uint length);

    internal sealed class PublicKeyEntry
    {
        public string GroupId;
        public IntPtr Bytes;   // unmanaged copy, stays at a fixed address for the whole run
        public int Length;
    }

    // Offsets inside the per-thread scratch block handed to the DLL.
    private const int OffMem = 0;      // intptr_t pMem[8]      (32 bytes on x86)
    private const int OffRet = 32;     // int retValue[5]
    private const int OffValid = 52;   // unsigned char ifTrue[4]
    private const int OffH1 = 56;      // unsigned char h1Coeffs[15] (+ padding)
    private const int OffM = 80;       // unsigned char M[8]
    private const int OffKey = 88;     // 16-byte binary key (not re-zeroed)
    private const int ScratchSize = 112;

    // PubkeyData layout: header[44], bytes1[44], bytes2[36]
    private const int PubkeyDataBytes1 = 44;
    private const int PubkeyDataBytes2 = 88;

    private static PubkeyParserFn s_pubkeyParser;
    private static CalculateH1Fn s_calculateH1;
    private static ExtractMFn s_extractM;

    private static List<PublicKeyEntry> s_entries;
    private static List<UIntPtr> s_coreMasks;
    private static byte[] s_key;

    private static int s_found;        // 0 / 1, written with Interlocked
    private static ulong s_foundM;
    private static PublicKeyEntry s_foundEntry;

    private static int Main(string[] args)
    {
        bool createdNew;
        using (Mutex mutex = new Mutex(true, @"Local\PKeyValidator_SingleInstance_Mutex", out createdNew))
        {
            if (!createdNew) return 1;
            try { return Run(args); }
            finally { mutex.ReleaseMutex(); }
        }
    }

    private static int Run(string[] args)
    {
        if (args.Length < 1)
        {
            Console.WriteLine("Usage: PKeyValidator.exe <CD-KEY> [ConfigFilePath]");
            return 1;
        }

        if (IntPtr.Size != 4)
        {
            Console.Error.WriteLine("This build must run as a 32-bit process (compile with /platform:x86).");
            return 1;
        }

        string configPath = args.Length >= 2 ? args[1] : "pkeyconfig.xrm-ms";

        try { s_key = EncodeBinaryKey(args[0]); }
        catch (Exception ex)
        {
            Console.Error.WriteLine(ex.Message);
            return 1;
        }

        string tempDll;
        IntPtr module = LoadNativeDll(out tempDll);
        if (module == IntPtr.Zero)
        {
            Console.Error.WriteLine("Could not load PidKeyData.dll. Put the 32-bit DLL next to the exe or embed it as a resource.");
            return 1;
        }

        try
        {
            IntPtr pParser = GetProcAddress(module, "PubkeyParser");
            IntPtr pCalcH1 = GetProcAddress(module, "CalculateH1");
            IntPtr pExtractM = GetProcAddress(module, "ExtractM");
            if (pParser == IntPtr.Zero || pCalcH1 == IntPtr.Zero || pExtractM == IntPtr.Zero)
            {
                Console.Error.WriteLine("PidKeyData.dll is missing an expected export.");
                return 1;
            }

            IntPtr[] thunks = MakeFastcallThunks(new IntPtr[] { pParser, pCalcH1, pExtractM });
            if (thunks == null)
            {
                Console.Error.WriteLine("Could not allocate executable memory for the call stubs.");
                return 1;
            }
            s_pubkeyParser = (PubkeyParserFn)Marshal.GetDelegateForFunctionPointer(thunks[0], typeof(PubkeyParserFn));
            s_calculateH1 = (CalculateH1Fn)Marshal.GetDelegateForFunctionPointer(thunks[1], typeof(CalculateH1Fn));
            s_extractM = (ExtractMFn)Marshal.GetDelegateForFunctionPointer(thunks[2], typeof(ExtractMFn));

            Stopwatch timer = Stopwatch.StartNew();

            string outerXml;
            try { outerXml = File.ReadAllText(configPath); }
            catch (Exception ex)
            {
                Console.Error.WriteLine("Could not read " + configPath + ": " + ex.Message);
                return 1;
            }

            s_entries = new List<PublicKeyEntry>();
            if (!ParseKeyEntries(outerXml, s_entries))
            {
                Console.Error.WriteLine("No public keys found in " + configPath + ".");
                return 1;
            }

            s_coreMasks = GetPerformanceCoreMasks();
            int numThreads = s_coreMasks.Count > 0 ? s_coreMasks.Count : Environment.ProcessorCount;
            if (numThreads <= 0) numThreads = 4;

            int total = s_entries.Count;
            int chunk = (total + numThreads - 1) / numThreads;
            List<Thread> threads = new List<Thread>();
            for (int t = 0; t < numThreads; t++)
            {
                int index = t;
                int start = t * chunk;
                int end = Math.Min(start + chunk, total);
                if (start >= end) continue;
                Thread th = new Thread(delegate() { Worker(index, start, end); });
                th.Start();
                threads.Add(th);
            }
            foreach (Thread th in threads) th.Join();

            timer.Stop();

            if (s_found != 0)
            {
                ulong m = s_foundM;
                bool isUpgrade = (m & 0x1) != 0;
                uint serial = (uint)((m >> 1) & 0x3FFFFFFF);
                uint security = (uint)((m >> 31) & 0x3FF);

                ulong actHash = isUpgrade ? 1UL : 0UL;
                actHash |= ((ulong)serial & ((1UL << 30) - 1)) << 1;
                actHash |= ((ulong)security & ((1UL << 20) - 1)) << 31;

                byte[] keyData = new byte[12];
                Buffer.BlockCopy(BitConverter.GetBytes(actHash), 0, keyData, 0, 8);

                Console.WriteLine("Status       : Valid Key");
                Console.WriteLine("Upgrade Flag : " + (isUpgrade ? "1" : "0"));
                Console.WriteLine("Serial       : " + serial + " (0x" + serial.ToString("x") + ")");
                Console.WriteLine("Security ID  : " + security + " (0x" + security.ToString("x") + ")");
                Console.WriteLine("Group ID     : " + s_foundEntry.GroupId);
                Console.WriteLine("Key Size     : " + s_foundEntry.Length + " bytes");
                Console.WriteLine("Act Data     : " + Convert.ToBase64String(keyData));
            }
            else
            {
                Console.WriteLine("Status       : Invalid Key (Mismatch across " + total + " groups)");
            }

            Console.WriteLine("Elapsed Time : " + timer.Elapsed.TotalSeconds.ToString("G6", CultureInfo.InvariantCulture) + "s");
            return 0;
        }
        finally
        {
            FreeLibrary(module);
            if (tempDll != null)
            {
                try { File.Delete(tempDll); } catch { }
            }
        }
    }

    // ------------------------------------------------------------------
    // Worker: one per thread, walks its slice of the public-key list.
    // ------------------------------------------------------------------
    private static void Worker(int threadIndex, int start, int end)
    {
        Thread.BeginThreadAffinity();
        IntPtr s = Marshal.AllocHGlobal(ScratchSize);
        try
        {
            if (s_coreMasks.Count > 0)
                SetThreadAffinityMask(GetCurrentThread(), s_coreMasks[threadIndex % s_coreMasks.Count]);
            Thread.CurrentThread.Priority = ThreadPriority.Highest;

            IntPtr pMem = IntPtr.Add(s, OffMem);
            IntPtr pRet = IntPtr.Add(s, OffRet);
            IntPtr pValid = IntPtr.Add(s, OffValid);
            IntPtr pH1 = IntPtr.Add(s, OffH1);
            IntPtr pM = IntPtr.Add(s, OffM);
            IntPtr pKey = IntPtr.Add(s, OffKey);
            Marshal.Copy(s_key, 0, pKey, 16);

            for (int i = start; i < end; i++)
            {
                if (Thread.VolatileRead(ref s_found) != 0) break;

                for (int z = 0; z < OffKey; z += 4) Marshal.WriteInt32(s, z, 0);

                PublicKeyEntry entry = s_entries[i];
                s_pubkeyParser(pMem, entry.Bytes, (uint)entry.Length, pRet);

                IntPtr pData = Marshal.ReadIntPtr(s, OffMem + 6 * IntPtr.Size);   // pMem[6]
                if (pData == IntPtr.Zero) continue;

                IntPtr bytes1 = IntPtr.Add(pData, PubkeyDataBytes1);
                IntPtr bytes2 = IntPtr.Add(pData, PubkeyDataBytes2);
                s_calculateH1(bytes1, bytes2, pKey, pValid, pH1, pRet);

                if (Marshal.ReadByte(s, OffValid) != 1) continue;

                Marshal.WriteInt32(s, OffRet + 4 * 4, 1);                         // retValue[4] = 1
                s_extractM(bytes1, pH1, pM, pRet);
                ulong m = (ulong)Marshal.ReadInt64(s, OffM);

                if (Interlocked.CompareExchange(ref s_found, 1, 0) == 0)
                {
                    s_foundM = m;
                    s_foundEntry = entry;
                }
                break;
            }
        }
        finally
        {
            Marshal.FreeHGlobal(s);
            Thread.EndThreadAffinity();
        }
    }

    // ------------------------------------------------------------------
    // stdcall -> fastcall stubs (x86 only).
    //   pop eax        ; return address
    //   pop ecx        ; arg 1
    //   pop edx        ; arg 2
    //   push eax       ; put the return address back
    //   mov eax, target
    //   jmp eax        ; callee's "ret N" removes the remaining stack args
    // Only valid for functions with at least two pointer-sized arguments.
    // ------------------------------------------------------------------
    private static IntPtr[] MakeFastcallThunks(IntPtr[] targets)
    {
        const int StubSize = 16;
        const uint MEM_COMMIT_RESERVE = 0x3000;
        const uint PAGE_EXECUTE_READWRITE = 0x40;

        UIntPtr size = (UIntPtr)(uint)(targets.Length * StubSize);
        IntPtr mem = VirtualAlloc(IntPtr.Zero, size, MEM_COMMIT_RESERVE, PAGE_EXECUTE_READWRITE);
        if (mem == IntPtr.Zero) return null;

        IntPtr[] result = new IntPtr[targets.Length];
        for (int i = 0; i < targets.Length; i++)
        {
            byte[] addr = BitConverter.GetBytes(targets[i].ToInt32());
            byte[] stub = new byte[]
            {
                0x58, 0x59, 0x5A, 0x50,
                0xB8, addr[0], addr[1], addr[2], addr[3],
                0xFF, 0xE0
            };
            result[i] = IntPtr.Add(mem, i * StubSize);
            Marshal.Copy(stub, 0, result[i], stub.Length);
        }
        FlushInstructionCache(GetCurrentProcess(), mem, size);
        return result;
    }

    // ------------------------------------------------------------------
    // DLL loading: PidKeyData.dll next to the exe wins; otherwise the copy
    // embedded as a resource is written to %TEMP% and loaded from there.
    // ------------------------------------------------------------------
    private static IntPtr LoadNativeDll(out string tempPath)
    {
        tempPath = null;

        string sideBySide = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "PidKeyData.dll");
        if (File.Exists(sideBySide)) return LoadLibraryW(sideBySide);

        Assembly asm = Assembly.GetExecutingAssembly();
        foreach (string name in asm.GetManifestResourceNames())
        {
            if (!name.EndsWith("PidKeyData.dll", StringComparison.OrdinalIgnoreCase)) continue;

            byte[] data;
            using (Stream stream = asm.GetManifestResourceStream(name))
            {
                data = new byte[stream.Length];
                int read = 0;
                while (read < data.Length)
                {
                    int n = stream.Read(data, read, data.Length - read);
                    if (n <= 0) break;
                    read += n;
                }
            }

            string path = Path.Combine(Path.GetTempPath(), "PidKeyData_" + Process.GetCurrentProcess().Id + ".dll");
            File.WriteAllBytes(path, data);
            tempPath = path;
            return LoadLibraryW(path);
        }

        return IntPtr.Zero;
    }

    // ------------------------------------------------------------------
    // CD-key (base-24, 25 chars) -> 16-byte binary form.
    // ------------------------------------------------------------------
    internal static byte[] EncodeBinaryKey(string cdKey)
    {
        const string Alphabet = "BCDFGHJKMPQRTVWXY2346789";

        string rawKey = cdKey.Replace("-", "").ToUpperInvariant();
        if (rawKey.Length != 25) throw new ArgumentException("Key must be 25 characters.");

        byte[] digits = new byte[25];
        bool isNKey = false;
        int digitCount = 0;

        foreach (char ch in rawKey)
        {
            if (ch == 'N' && !isNKey)
            {
                isNKey = true;
                for (int i = digitCount; i > 0; i--) digits[i] = digits[i - 1];
                digits[0] = (byte)digitCount;
                digitCount++;
                continue;
            }

            int val = Alphabet.IndexOf(ch);
            if (val < 0) throw new ArgumentException("Invalid character in key.");
            digits[digitCount++] = (byte)val;
        }

        byte[] binary = new byte[16];
        foreach (byte digit in digits)
        {
            uint carry = digit;
            for (int i = 0; i < 16; i++)
            {
                uint res = (uint)binary[i] * 24 + carry;
                binary[i] = (byte)(res & 0xFF);
                carry = res >> 8;
            }
        }

        if (isNKey) binary[14] |= 0x08;
        return binary;
    }

    // ------------------------------------------------------------------
    // pkeyconfig.xrm-ms -> list of (GroupId, 1579-byte public key).
    // ------------------------------------------------------------------
    internal static bool ParseKeyEntries(string outerXml, List<PublicKeyEntry> entries)
    {
        const StringComparison Ord = StringComparison.Ordinal;

        int infoBinPos = outerXml.IndexOf("pkeyConfigData", Ord);
        if (infoBinPos < 0) return false;

        int contentStart = outerXml.IndexOf('>', infoBinPos) + 1;
        if (contentStart <= 0) return false;
        int contentEnd = outerXml.IndexOf("</", contentStart, Ord);
        if (contentEnd < 0) return false;

        byte[] decoded = TryBase64(outerXml.Substring(contentStart, contentEnd - contentStart));
        if (decoded == null || decoded.Length == 0) return false;

        string inner = Encoding.UTF8.GetString(decoded);
        if (inner.IndexOf("ProductKeyConfiguration", Ord) < 0 && decoded.Length > 2 &&
            (decoded[1] == 0 || (decoded[0] == 0xFF && decoded[1] == 0xFE)))
        {
            inner = Encoding.Unicode.GetString(decoded);
        }

        int searchPos = 0;
        while (true)
        {
            int pkStart = inner.IndexOf("<pkc:PublicKey>", searchPos, Ord);
            if (pkStart < 0)
            {
                pkStart = inner.IndexOf("<PublicKey>", searchPos, Ord);
                if (pkStart < 0) break;
            }

            int pkEnd = inner.IndexOf("</pkc:PublicKey>", pkStart, Ord);
            if (pkEnd < 0)
            {
                pkEnd = inner.IndexOf("</PublicKey>", pkStart, Ord);
                if (pkEnd < 0) break;
                pkEnd += "</PublicKey>".Length;
            }
            else
            {
                pkEnd += "</pkc:PublicKey>".Length;
            }

            string block = inner.Substring(pkStart, pkEnd - pkStart);
            searchPos = pkEnd;

            string groupId = ElementText(block, "GroupId>") ?? "";
            string keyB64 = ElementText(block, "PublicKeyValue>");
            if (keyB64 == null) continue;

            byte[] pubKey = TryBase64(keyB64);
            if (pubKey == null || pubKey.Length != 1579) continue;

            PublicKeyEntry entry = new PublicKeyEntry();
            entry.GroupId = groupId;
            entry.Length = pubKey.Length;
            entry.Bytes = Marshal.AllocHGlobal(pubKey.Length);
            Marshal.Copy(pubKey, 0, entry.Bytes, pubKey.Length);
            entries.Add(entry);
        }

        return entries.Count > 0;
    }

    private static string ElementText(string block, string tagTail)
    {
        int start = block.IndexOf(tagTail, StringComparison.Ordinal);
        if (start < 0) return null;
        start = block.IndexOf('>', start) + 1;
        int end = block.IndexOf("</", start, StringComparison.Ordinal);
        if (end < 0) return null;
        return block.Substring(start, end - start);
    }

    private static byte[] TryBase64(string text)
    {
        try { return Convert.FromBase64String(text); }   // whitespace is ignored
        catch (FormatException) { return null; }
    }

    // ------------------------------------------------------------------
    // One affinity mask per performance core (highest EfficiencyClass).
    // Empty list if the API is unavailable; the caller then just uses
    // Environment.ProcessorCount threads without pinning.
    // ------------------------------------------------------------------
    private static List<UIntPtr> GetPerformanceCoreMasks()
    {
        const int RelationProcessorCore = 0;
        const int ERROR_INSUFFICIENT_BUFFER = 122;

        List<UIntPtr> masks = new List<UIntPtr>();
        try
        {
            uint len = 0;
            if (GetLogicalProcessorInformationEx(RelationProcessorCore, IntPtr.Zero, ref len) ||
                Marshal.GetLastWin32Error() != ERROR_INSUFFICIENT_BUFFER || len == 0)
            {
                return masks;
            }

            IntPtr buf = Marshal.AllocHGlobal((int)len);
            try
            {
                if (!GetLogicalProcessorInformationEx(RelationProcessorCore, buf, ref len)) return masks;

                // SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX:
                //   +0 Relationship, +4 Size, +8 Flags, +9 EfficiencyClass,
                //   +30 GroupCount, +32 GROUP_AFFINITY[] { KAFFINITY Mask; WORD Group; WORD Reserved[3]; }
                int groupAffinitySize = IntPtr.Size + 8;
                byte maxEfficiency = 0;

                for (int off = 0; off < len; )
                {
                    int size = Marshal.ReadInt32(buf, off + 4);
                    if (size <= 0) break;
                    if (Marshal.ReadInt32(buf, off) == RelationProcessorCore)
                    {
                        byte eff = Marshal.ReadByte(buf, off + 9);
                        if (eff > maxEfficiency) maxEfficiency = eff;
                    }
                    off += size;
                }

                for (int off = 0; off < len; )
                {
                    int size = Marshal.ReadInt32(buf, off + 4);
                    if (size <= 0) break;
                    if (Marshal.ReadInt32(buf, off) == RelationProcessorCore &&
                        Marshal.ReadByte(buf, off + 9) == maxEfficiency)
                    {
                        int groupCount = (ushort)Marshal.ReadInt16(buf, off + 30);
                        for (int g = 0; g < groupCount; g++)
                        {
                            IntPtr mask = Marshal.ReadIntPtr(buf, off + 32 + g * groupAffinitySize);
                            if (mask == IntPtr.Zero) continue;
                            masks.Add(IntPtr.Size == 4 ? (UIntPtr)(uint)mask.ToInt32() : (UIntPtr)(ulong)mask.ToInt64());
                        }
                    }
                    off += size;
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buf);
            }
        }
        catch (EntryPointNotFoundException)
        {
            masks.Clear();   // pre-Windows 7
        }
        return masks;
    }
}
