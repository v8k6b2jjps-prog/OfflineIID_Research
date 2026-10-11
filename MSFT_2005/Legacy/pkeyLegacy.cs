using System;
using System.Diagnostics;
using System.Numerics;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

namespace PidKeyPlugIn
{
    // =========================================================================
    // Legacy (BINK1998 / BINK2002) product-key validator.
    //
    // A managed re-implementation of pidgenx.dll (x64, 10.0.26040.1000):
    //
    //   sub_18008CFF0  wrapper for BINK1998 keys (31-bit data, 4-byte message)
    //   sub_18008D200  wrapper for BINK2002 keys (11-bit data, 2-byte message)
    //   sub_18009CA30  shared core (curve math + SHA-1), returns 0 = valid
    //   sub_18009DAB0  BINK header parser
    //   sub_18009DA10  BINK checksum (sum of all DWORDs must be 0)
    //   sub_18009DC10  SHA-1 helper (optional prefix byte, truncation by ">>")
    //
    // Self-contained: it has its own GF(p) arithmetic and does NOT touch the
    // static Gf.P used by pkey2005, because each legacy BINK has its own p.
    // Written for C# 5 so PowerShell 5.1 can compile it with Add-Type.
    // =========================================================================

    /// <summary>Which wrapper splits the 114-bit key into data and payload.</summary>
    public enum LegacyKeyLayout
    {
        /// <summary>Picked from the BINK date (19980206 means Pid1998, anything else means Pid2002).</summary>
        Auto = 0,
        /// <summary>Windows 98/XP: 31 data bits (upgrade + 30-bit serial), message is 4 bytes.</summary>
        Pid1998 = 1,
        /// <summary>Server 2003/XP x64: 11 data bits (upgrade + 10-bit channel), message is 2 bytes.</summary>
        Pid2002 = 2
    }

    /// <summary>Status codes, the same values the native core returns.</summary>
    public static class LegacyStatus
    {
        public const int Ok = 0;               // valid key
        public const int HashMismatch = 1;     // signature does not match, or unknown BINK date
        public const int BadBink = 3;          // header, size, checksum or curve points rejected
        public const int HashError = 5;        // SHA-1 helper refused the request (too many output bits)
        public const int MathError = 6;        // point at infinity or other curve failure
        public const int Unsupported = 8;      // hash longer than 64 bits
        public const int BadKey = 100;         // managed only: key string or raw bytes unusable

        // HRESULTs the public wrapper turns these into
        public const int E_KeyRejected = unchecked((int)0x80041051);
        public const int E_BadArgs = unchecked((int)0x80041052);
        public const int E_BinkSize = unchecked((int)0x80041053);
    }

    // -------------------------------------------------------------------------
    // BINK parsing
    // -------------------------------------------------------------------------
    public sealed class LegacyBink
    {
        public const uint Date1998 = 19980206;
        public const uint Date2002 = 20020420;

        public uint BinkId;            // only when the blob came with the 4-byte resource ID in front
        public uint Size;              // dword[0]  (bytes, excluding the resource ID)
        public uint HeaderDwords;      // dword[1]  7, 8 or 9
        public uint Checksum;          // dword[2]
        public uint Date;              // dword[3]  19980206 / 20020420
        public uint KeyDwords;         // dword[4]  12 (384-bit) / 16 (512-bit)
        public uint HashBits;          // dword[5]  28 / 31
        public uint SigBits;           // dword[6]  55 / 62
        public uint AuthBits;          // dword[7]  0 / 10   (only read when Date >= 20020420)
        public uint PidBits;           // dword[8]  0 / 20   (only read when Date >= 20020420)

        public BigInteger P, A, B, Gx, Gy, Kx, Ky;

        public bool Is1998 { get { return Date == Date1998; } }

        /// <summary>
        /// Parses a BINK. Accepts both the pidgenx layout (dword[0] == length) and the
        /// pidgen.dll resource layout, which has the BINK ID in front (dword[1] == length - 4).
        /// Returns a LegacyStatus code; 0 means success.
        /// </summary>
        public static int TryParse(byte[] blob, out LegacyBink bink)
        {
            bink = null;
            if (blob == null || blob.Length < 0x1C) return LegacyStatus.BadBink;

            uint binkId = 0;
            byte[] b = blob;
            if (BitConverter.ToUInt32(blob, 0) != (uint)blob.Length &&
                blob.Length >= 0x20 &&
                BitConverter.ToUInt32(blob, 4) == (uint)(blob.Length - 4))
            {
                binkId = BitConverter.ToUInt32(blob, 0);
                b = new byte[blob.Length - 4];
                Buffer.BlockCopy(blob, 4, b, 0, b.Length);
            }

            // ---- sub_18009DAB0 ------------------------------------------------
            uint size = U32(b, 0);
            if (size < 0x1C) return LegacyStatus.BadBink;
            if (size != (uint)b.Length) return LegacyStatus.BadBink;   // wrapper: 0x80041053

            uint hdr = U32(b, 1);
            if (hdr < 7 || hdr > 9) return LegacyStatus.BadBink;

            var k = new LegacyBink();
            k.BinkId = binkId;
            k.Size = size;
            k.HeaderDwords = hdr;
            k.Checksum = U32(b, 2);
            k.Date = U32(b, 3);
            k.KeyDwords = U32(b, 4);
            k.HashBits = U32(b, 5);
            k.SigBits = U32(b, 6);
            if (k.Date >= Date2002)
            {
                if (b.Length < 9 * 4) return LegacyStatus.BadBink;
                k.AuthBits = U32(b, 7);
                k.PidBits = U32(b, 8);
            }

            if (k.HashBits > 32 || k.SigBits > 64 || k.KeyDwords > 32 || k.KeyDwords == 0)
                return LegacyStatus.BadBink;

            // p, a, b, Gx, Gy, Kx, Ky: seven integers of KeyDwords each, right after the header
            ulong expected = 4UL * hdr + 7UL * 4UL * k.KeyDwords;
            if ((ulong)size != expected) return LegacyStatus.BadBink;

            if (k.Date != Date1998 && k.Date != Date2002) return LegacyStatus.BadBink;

            // ---- sub_18009DA10: sum of every DWORD must be zero -------------------
            uint sum = 0;
            for (int i = 0; i + 4 <= b.Length; i += 4) sum = unchecked(sum + BitConverter.ToUInt32(b, i));
            if (sum != 0) return LegacyStatus.BadBink;

            int len = (int)k.KeyDwords * 4;
            int off = (int)hdr * 4;
            k.P = LeInt(b, off, len); off += len;
            k.A = LeInt(b, off, len); off += len;
            k.B = LeInt(b, off, len); off += len;
            k.Gx = LeInt(b, off, len); off += len;
            k.Gy = LeInt(b, off, len); off += len;
            k.Kx = LeInt(b, off, len); off += len;
            k.Ky = LeInt(b, off, len);

            if (k.P < 5 || k.P.IsEven) return LegacyStatus.BadBink;

            // the native "external_key_to_internal" step rejects points that are not on the curve
            var c = new LegacyCurve(k.P, k.A, k.B);
            if (!c.IsOnCurve(k.Gx, k.Gy) || !c.IsOnCurve(k.Kx, k.Ky)) return LegacyStatus.BadBink;

            bink = k;
            return LegacyStatus.Ok;
        }

        static uint U32(byte[] b, int index) { return BitConverter.ToUInt32(b, index * 4); }

        internal static BigInteger LeInt(byte[] b, int offset, int count)
        {
            var buf = new byte[count + 1];               // trailing 0 keeps it positive
            Buffer.BlockCopy(b, offset, buf, 0, count);
            return new BigInteger(buf);
        }
    }

    // -------------------------------------------------------------------------
    // Result
    // -------------------------------------------------------------------------
    public sealed class LegacyKeyResult
    {
        public bool IsValid;
        public int Status;               // LegacyStatus code
        public int HResult;              // what the public pidgenx wrapper would report
        public LegacyKeyLayout Layout;
        public uint BinkId;
        public uint BinkDate;

        public uint Data;                // raw data field (upgrade bit + serial/channel)
        public int Upgrade;
        public int Channel;              // BBB
        public int Sequence;             // CCCCCC
        public uint Hash;                // hash field taken from the key
        public ulong Signature;          // signature field taken from the key
        public uint AuthInfo;            // core "out A" (BINK2002 auth field, 0 for BINK1998)
        public uint PidValue;            // core "out B" (BINK2002 sequence, 0 for BINK1998)

        public int Index = -1;           // VerifyAll: position in the input arrays
        public string GroupId;           // VerifyAll: GroupId of the matching BINK
        public string AlgorithmId;       // VerifyAll: AlgorithmId of the matching BINK
        public double ElapsedMs;         // VerifyAll: time spent on this BINK

        public override string ToString()
        {
            return string.Format(
                "Group={8} Valid={0} Status={1} Layout={2} Upgrade={3} Channel={4:D3} Sequence={5:D6} Auth=0x{6:X} Pid=0x{7:X}",
                IsValid, Status, Layout, Upgrade, Channel, Sequence, AuthInfo, PidValue, GroupId);
        }
    }

    // -------------------------------------------------------------------------
    // Validator
    // -------------------------------------------------------------------------
    public static class PKeyLegacyValidator
    {
        const string Alphabet = "BCDFGHJKMPQRTVWXY2346789";
        const int KeyBits = 114;

        // ---- convenience entry points -----------------------------------------

        /// <summary>Same signature as before: raw 16-byte key + BINK, true if valid.</summary>
        public static bool Validate(byte[] rawKeyBytes, byte[] binkBytes)
        {
            return Verify(rawKeyBytes, binkBytes, LegacyKeyLayout.Auto).IsValid;
        }

        public static bool Validate(string productKey, byte[] binkBytes)
        {
            return Verify(productKey, binkBytes, LegacyKeyLayout.Auto).IsValid;
        }

        public static LegacyKeyResult Verify(string productKey, byte[] binkBytes)
        {
            return Verify(productKey, binkBytes, LegacyKeyLayout.Auto);
        }

        public static LegacyKeyResult Verify(string productKey, byte[] binkBytes, LegacyKeyLayout layout)
        {
            byte[] raw = DecodeProductKey(productKey);
            if (raw == null)
                return Fail(LegacyStatus.BadKey, LegacyStatus.E_BadArgs, layout, null);
            return Verify(raw, binkBytes, layout);
        }

        public static LegacyKeyResult Verify(byte[] rawKeyBytes, byte[] binkBytes)
        {
            return Verify(rawKeyBytes, binkBytes, LegacyKeyLayout.Auto);
        }

        /// <summary>
        /// Same mapping pidgenx uses (algorithm string -> GUID -> class -> wrapper):
        ///   msft:rm/algorithm/pkey/980        -> sub_18008D5FC -> sub_18008CFF0 -> Pid1998
        ///   msft:rm/algorithm/pkey/985 / 986  -> sub_18008D6E4 -> sub_18008D200 -> Pid2002
        /// Anything else (null, unknown) returns Auto, which then uses the BINK date.
        /// </summary>
        public static LegacyKeyLayout LayoutFromAlgorithmId(string algorithmId)
        {
            if (string.IsNullOrEmpty(algorithmId)) return LegacyKeyLayout.Auto;
            string a = algorithmId.Trim();
            if (a.EndsWith("/980", StringComparison.OrdinalIgnoreCase)) return LegacyKeyLayout.Pid1998;
            if (a.EndsWith("/985", StringComparison.OrdinalIgnoreCase) ||
                a.EndsWith("/986", StringComparison.OrdinalIgnoreCase)) return LegacyKeyLayout.Pid2002;
            return LegacyKeyLayout.Auto;
        }

        /// <summary>True for the three legacy algorithm IDs this class handles.</summary>
        public static bool IsLegacyAlgorithm(string algorithmId)
        {
            return LayoutFromAlgorithmId(algorithmId) != LegacyKeyLayout.Auto;
        }

        public static LegacyKeyResult Verify(string productKey, byte[] binkBytes, string algorithmId)
        {
            return Verify(productKey, binkBytes, LayoutFromAlgorithmId(algorithmId));
        }

        public static LegacyKeyResult Verify(byte[] rawKeyBytes, byte[] binkBytes, string algorithmId)
        {
            return Verify(rawKeyBytes, binkBytes, LayoutFromAlgorithmId(algorithmId));
        }

        /// <summary>
        /// Checks one key against many BINKs in parallel.
        ///   rawKeyBytes  : 16-byte key (DecodeProductKey)
        ///   groupIds     : GroupId per entry (copied into the result)
        ///   algorithmIds : AlgorithmId per entry (980 / 985 / 986; others are skipped)
        ///   binks        : BINK per entry, byte[] or Base64 string
        ///   allMatches   : false = stop at the first match, true = check every BINK
        ///   maxThreads   : 0 or less = one per CPU core, 1 = serial
        /// Returns true if at least one BINK accepted the key. 'matches' holds only the
        /// valid results, in input order (one item when allMatches is false; empty if none).
        /// </summary>
        public static bool VerifyAll(byte[] rawKeyBytes, string[] groupIds, string[] algorithmIds, object[] binks,
                                     bool allMatches, int maxThreads, out LegacyKeyResult[] matches)
        {
            if (rawKeyBytes == null) throw new ArgumentNullException("rawKeyBytes");
            if (groupIds == null || algorithmIds == null || binks == null ||
                groupIds.Length != binks.Length || algorithmIds.Length != binks.Length)
                throw new ArgumentException("groupIds, algorithmIds and binks must have the same length");

            var results = new LegacyKeyResult[binks.Length];
            var opt = new ParallelOptions();
            opt.MaxDegreeOfParallelism = maxThreads > 0 ? maxThreads : Environment.ProcessorCount;
            int found = 0;

            Parallel.For(0, binks.Length, opt, (i, state) =>
            {
                if (!allMatches && Volatile.Read(ref found) != 0) { state.Stop(); return; }
                if (!IsLegacyAlgorithm(algorithmIds[i])) return;

                var sw = Stopwatch.StartNew();
                byte[] bink = binks[i] as byte[];
                if (bink == null)
                {
                    string s = binks[i] as string;
                    try { bink = s == null ? null : Convert.FromBase64String(s); }
                    catch (FormatException) { bink = null; }
                }

                LegacyKeyResult r = Verify(rawKeyBytes, bink, algorithmIds[i]);
                sw.Stop();
                r.Index = i;
                r.GroupId = groupIds[i];
                r.AlgorithmId = algorithmIds[i];
                r.ElapsedMs = sw.Elapsed.TotalMilliseconds;

                if (r.IsValid)
                {
                    results[i] = r;
                    if (!allMatches) { Interlocked.Exchange(ref found, 1); state.Stop(); }
                }
            });

            var list = new System.Collections.Generic.List<LegacyKeyResult>();
            foreach (var r in results)
            {
                if (r == null) continue;
                list.Add(r);
                if (!allMatches) break;          // several threads may hit at once: keep the first in input order
            }
            matches = list.ToArray();
            return matches.Length > 0;
        }

        /// <summary>Same as above, product key as text.</summary>
        public static bool VerifyAll(string productKey, string[] groupIds, string[] algorithmIds, object[] binks,
                                     bool allMatches, int maxThreads, out LegacyKeyResult[] matches)
        {
            byte[] raw = DecodeProductKey(productKey);
            if (raw == null) { matches = new LegacyKeyResult[0]; return false; }
            return VerifyAll(raw, groupIds, algorithmIds, binks, allMatches, maxThreads, out matches);
        }

        /// <summary>
        /// Full validation. rawKeyBytes is the little-endian base-24 value of the key
        /// (at least 15 bytes; bits 0..113 are used).
        /// </summary>
        public static LegacyKeyResult Verify(byte[] rawKeyBytes, byte[] binkBytes, LegacyKeyLayout layout)
        {
            if (rawKeyBytes == null || rawKeyBytes.Length < 15)
                return Fail(LegacyStatus.BadKey, LegacyStatus.E_BadArgs, layout, null);

            LegacyBink bink;
            int st = LegacyBink.TryParse(binkBytes, out bink);
            if (st != LegacyStatus.Ok)
                return Fail(st, st == LegacyStatus.BadBink && SizeMismatch(binkBytes)
                                ? LegacyStatus.E_BinkSize : LegacyStatus.E_KeyRejected, layout, null);

            if (layout == LegacyKeyLayout.Auto)
                layout = bink.Is1998 ? LegacyKeyLayout.Pid1998 : LegacyKeyLayout.Pid2002;

            // ---- wrapper PRE: split the 114-bit key into data + payload --------
            int n = Math.Min(rawKeyBytes.Length, 16);
            var tmp = new byte[n + 1];
            Buffer.BlockCopy(rawKeyBytes, 0, tmp, 0, n);
            BigInteger key = new BigInteger(tmp) & ((BigInteger.One << KeyBits) - 1);

            int dataBits = layout == LegacyKeyLayout.Pid1998 ? 31 : 11;
            int dataBytes = layout == LegacyKeyLayout.Pid1998 ? 4 : 2;     // r8d = 4 / 2

            uint data = (uint)(key & ((BigInteger.One << dataBits) - 1));
            BigInteger payload = key >> dataBits;

            byte[] msg = new byte[dataBytes];
            for (int i = 0; i < dataBytes; i++) msg[i] = (byte)(data >> (8 * i));

            // ---- core ------------------------------------------------------------
            uint outA, outB;
            ulong hash, sig;
            st = Core(bink, msg, payload, out outA, out outB, out hash, out sig);

            var r = new LegacyKeyResult();
            r.Status = st;
            r.IsValid = st == LegacyStatus.Ok;
            r.HResult = r.IsValid ? 0 : LegacyStatus.E_KeyRejected;
            r.Layout = layout;
            r.BinkId = bink.BinkId;
            r.BinkDate = bink.Date;
            r.Data = data;
            r.Hash = (uint)hash;
            r.Signature = sig;
            r.AuthInfo = outA;
            r.PidValue = outB;

            // ---- wrapper POST: field decode --------------------------------------
            r.Upgrade = (int)(data & 1);
            if (layout == LegacyKeyLayout.Pid1998)
            {
                uint v = data >> 1;                         // 30-bit serial
                r.Channel = (int)(v / 1000000);
                r.Sequence = (int)(v % 1000000);
            }
            else
            {
                r.Channel = (int)(((data >> 1) & 0x3FF) % 1000);
                r.Sequence = (int)outB;                     // comes out of the second SHA-1
            }
            return r;
        }

        // ---- sub_18009CA30 -----------------------------------------------------

        /// <summary>
        /// Mirrors the native core. msg = the data bytes the wrapper passes (a2/a3),
        /// payload = key bits above the data field (a4). Returns a LegacyStatus code.
        /// </summary>
        public static int Core(LegacyBink bink, byte[] msg, BigInteger payload,
                               out uint outA, out uint outB, out ulong keyHash, out ulong keySig)
        {
            outA = 0; outB = 0; keyHash = 0; keySig = 0;

            if (bink.Date != LegacyBink.Date1998 && bink.Date != LegacyBink.Date2002)
                return LegacyStatus.HashMismatch;

            // bit unpack: [hash | signature | auth], LSB first
            int hBits = (int)bink.HashBits, sBits = (int)bink.SigBits, aBits = (int)bink.AuthBits;
            ulong h = (ulong)(payload & Mask(hBits));
            ulong s = (ulong)((payload >> hBits) & Mask(sBits));
            ulong a = (ulong)((payload >> (hBits + sBits)) & Mask(Math.Min(aBits, 64)));
            keyHash = h; keySig = s;

            uint hashDwords = (bink.HashBits + 31) >> 5;    // v9[4]
            uint authDwords = (bink.AuthBits + 31) >> 5;    // v9[1]
            if (hashDwords > 2) return LegacyStatus.Unsupported;

            var curve = new LegacyCurve(bink.P, bink.A, bink.B);
            var G = LegacyPoint.Affine(bink.Gx, bink.Gy);
            var K = LegacyPoint.Affine(bink.Kx, bink.Ky);

            LegacyPoint R;
            if (bink.Is1998)
            {
                // R = s*G + h*K
                R = curve.Add(curve.Mul(G, s), curve.Mul(K, h));
            }
            else
            {
                // e = SHA1(0x5D || msg || hash dwords || auth dwords), truncated to SigBits
                byte[] m1 = Concat(new byte[] { 0x5D }, msg,
                                   Dwords(new BigInteger(h), (int)hashDwords),
                                   Dwords(new BigInteger(a), (int)authDwords));
                BigInteger e;
                if (!TruncDigest(m1, sBits, out e)) return LegacyStatus.HashError;

                // R = s * (s*G + e*K)
                LegacyPoint t = curve.Add(curve.Mul(G, s), curve.Mul(K, e));
                R = curve.Mul(t, s);
            }

            BigInteger rx, ry;
            if (!curve.ToAffine(R, out rx, out ry)) return LegacyStatus.MathError;

            // SHA1([0x79 if not 1998] || msg || R.x || R.y), truncated to HashBits + PidBits
            int ks = (int)bink.KeyDwords;
            byte[] prefix = bink.Is1998 ? new byte[0] : new byte[] { 0x79 };
            byte[] m2 = Concat(prefix, msg, Dwords(rx, ks), Dwords(ry, ks));

            int outBits = hBits + (int)bink.PidBits;
            BigInteger d;
            if (!TruncDigest(m2, outBits, out d)) return LegacyStatus.HashError;

            ulong pid = (ulong)((d >> hBits) & Mask((int)bink.PidBits));
            ulong calc = (ulong)(d & Mask(hBits));

            if (calc != h) return LegacyStatus.HashMismatch;

            outA = (uint)a;
            outB = (uint)pid;
            return LegacyStatus.Ok;
        }

        // ---- sub_18009DC10 truncation ------------------------------------------
        // Take ceil(bits/32) little-endian DWORDs of the digest and shift the LAST one
        // right by (32*n - bits). So for 28 bits the result is dword0 >> 4, NOT dword0 & 0x0FFFFFFF.
        static bool TruncDigest(byte[] message, int bits, out BigInteger value)
        {
            value = BigInteger.Zero;
            int n = (bits + 31) >> 5;
            if (n == 0) return true;
            if (4 * n > 20) return false;

            byte[] dg;
            using (var sha = SHA1.Create()) dg = sha.ComputeHash(message);

            for (int i = 0; i < n; i++)
            {
                uint w = BitConverter.ToUInt32(dg, 4 * i);
                if (i == n - 1) w >>= (32 * n - bits);
                value |= new BigInteger(w) << (32 * i);
            }
            return true;
        }

        // ---- base-24 product key -> 16 raw bytes (legacy keys have no 'N') ----
        public static byte[] DecodeProductKey(string productKey)
        {
            if (productKey == null) return null;
            string k = productKey.Replace("-", "").Replace(" ", "").ToUpperInvariant();
            if (k.Length != 25) return null;

            BigInteger v = BigInteger.Zero;
            foreach (char ch in k)
            {
                int d = Alphabet.IndexOf(ch);
                if (d < 0) return null;
                v = v * 24 + d;
            }
            byte[] le = v.ToByteArray();
            var raw = new byte[16];
            Buffer.BlockCopy(le, 0, raw, 0, Math.Min(le.Length, 16));
            return raw;
        }

        // ---- helpers -----------------------------------------------------------
        static BigInteger Mask(int bits)
        {
            return bits <= 0 ? BigInteger.Zero : (BigInteger.One << bits) - 1;
        }

        static byte[] Dwords(BigInteger v, int count)
        {
            var o = new byte[count * 4];
            byte[] le = v.ToByteArray();
            Buffer.BlockCopy(le, 0, o, 0, Math.Min(le.Length, o.Length));
            return o;
        }

        static byte[] Concat(params byte[][] parts)
        {
            int len = 0;
            foreach (var p in parts) len += p.Length;
            var o = new byte[len];
            int off = 0;
            foreach (var p in parts) { Buffer.BlockCopy(p, 0, o, off, p.Length); off += p.Length; }
            return o;
        }

        static bool SizeMismatch(byte[] bink)
        {
            if (bink == null || bink.Length < 8) return true;
            return BitConverter.ToUInt32(bink, 0) != (uint)bink.Length &&
                   BitConverter.ToUInt32(bink, 4) != (uint)(bink.Length - 4);
        }

        static LegacyKeyResult Fail(int status, int hr, LegacyKeyLayout layout, LegacyBink bink)
        {
            var r = new LegacyKeyResult();
            r.Status = status;
            r.HResult = hr;
            r.Layout = layout;
            if (bink != null) { r.BinkId = bink.BinkId; r.BinkDate = bink.Date; }
            return r;
        }
    }

    // -------------------------------------------------------------------------
    // Short-Weierstrass curve y^2 = x^3 + a*x + b over GF(p), Jacobian coordinates.
    // Per-instance modulus, so different BINKs can be checked in parallel.
    // -------------------------------------------------------------------------
    public struct LegacyPoint
    {
        public BigInteger X, Y, Z;     // Z == 0 means infinity
        public bool IsInfinity { get { return Z.IsZero; } }

        public static LegacyPoint Infinity { get { return new LegacyPoint { X = 1, Y = 1, Z = 0 }; } }
        public static LegacyPoint Affine(BigInteger x, BigInteger y) { return new LegacyPoint { X = x, Y = y, Z = 1 }; }
    }

    public sealed class LegacyCurve
    {
        readonly BigInteger p, a, b;

        public LegacyCurve(BigInteger p, BigInteger a, BigInteger b)
        {
            this.p = p; this.a = Mod(a); this.b = Mod(b);
        }

        BigInteger Mod(BigInteger x)
        {
            if (x.Sign >= 0 && x < p) return x;
            BigInteger r = x % p;
            return r.Sign < 0 ? r + p : r;
        }

        BigInteger Inv(BigInteger x) { return BigInteger.ModPow(Mod(x), p - 2, p); }   // p is prime

        public bool IsOnCurve(BigInteger x, BigInteger y)
        {
            if (x.Sign < 0 || x >= p || y.Sign < 0 || y >= p) return false;
            return Mod(y * y) == Mod(x * x * x + a * x + b);
        }

        public LegacyPoint Double(LegacyPoint P)
        {
            if (P.IsInfinity || P.Y.IsZero) return LegacyPoint.Infinity;
            BigInteger yy = Mod(P.Y * P.Y);
            BigInteger s = Mod(4 * P.X * yy);
            BigInteger zz = Mod(P.Z * P.Z);
            BigInteger m = Mod(3 * P.X * P.X + a * zz * zz);
            BigInteger x3 = Mod(m * m - 2 * s);
            BigInteger y3 = Mod(m * (s - x3) - 8 * yy * yy);
            BigInteger z3 = Mod(2 * P.Y * P.Z);
            return new LegacyPoint { X = x3, Y = y3, Z = z3 };
        }

        public LegacyPoint Add(LegacyPoint P, LegacyPoint Q)
        {
            if (P.IsInfinity) return Q;
            if (Q.IsInfinity) return P;

            BigInteger z1z1 = Mod(P.Z * P.Z), z2z2 = Mod(Q.Z * Q.Z);
            BigInteger u1 = Mod(P.X * z2z2), u2 = Mod(Q.X * z1z1);
            BigInteger s1 = Mod(P.Y * Q.Z * z2z2), s2 = Mod(Q.Y * P.Z * z1z1);

            if (u1 == u2) return s1 == s2 ? Double(P) : LegacyPoint.Infinity;

            BigInteger h = Mod(u2 - u1), r = Mod(s2 - s1);
            BigInteger hh = Mod(h * h), hhh = Mod(h * hh);
            BigInteger v = Mod(u1 * hh);
            BigInteger x3 = Mod(r * r - hhh - 2 * v);
            BigInteger y3 = Mod(r * (v - x3) - s1 * hhh);
            BigInteger z3 = Mod(P.Z * Q.Z * h);
            return new LegacyPoint { X = x3, Y = y3, Z = z3 };
        }

        public LegacyPoint Mul(LegacyPoint P, ulong k) { return Mul(P, new BigInteger(k)); }

        public LegacyPoint Mul(LegacyPoint P, BigInteger k)
        {
            LegacyPoint r = LegacyPoint.Infinity;
            if (k.Sign <= 0 || P.IsInfinity) return r;
            int bits = 0;
            for (BigInteger t = k; !t.IsZero; t >>= 1) bits++;
            for (int i = bits - 1; i >= 0; i--)
            {
                r = Double(r);
                if (!((k >> i) & 1).IsZero) r = Add(r, P);
            }
            return r;
        }

        public bool ToAffine(LegacyPoint P, out BigInteger x, out BigInteger y)
        {
            x = y = BigInteger.Zero;
            if (P.IsInfinity) return false;
            BigInteger zi = Inv(P.Z), zi2 = Mod(zi * zi);
            x = Mod(P.X * zi2);
            y = Mod(P.Y * zi2 * zi);
            return true;
        }
    }
}
