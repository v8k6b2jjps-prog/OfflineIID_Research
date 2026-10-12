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
    // BINK set loaded from a JSON file (Legacy_Binks.json format):
    //   { "Format": "LegacyBinks", "Version": 1, "Binks": [
    //       { "BinkId", "GroupId", "AlgorithmId", "Layout", "Date", "KeyDwords",
    //         "HashBits", "SigBits", "AuthBits", "PidBits",
    //         "P", "A", "B", "Gx", "Gy", "Kx", "Ky" }, ... ] }
    // P..Ky are decimal strings (hex with 0x also accepted). Each entry is turned into a
    // normal pidgenx BINK blob, so it goes through LegacyBink.TryParse like any other
    // BINK (size, checksum, on-curve). Header fields that are missing or 0 get the
    // standard BINK1998 / BINK2002 values. Built-in JSON reader, no extra assemblies,
    // so it compiles the same on PowerShell 5.1 and 7.
    // -------------------------------------------------------------------------
    public sealed class LegacyBinkSet
    {
        public string[] GroupIds;
        public string[] AlgorithmIds;
        public string[] Families;         // per entry: "Family" names joined with "; " ("" if none)
        public object[] Binks;            // byte[] per entry; null if the entry was unusable
        public string[] Errors;           // per entry: null, or why it was skipped
        public int Count { get { return Binks.Length; } }

        public static LegacyBinkSet FromJsonFile(string path)
        {
            return FromJson(System.IO.File.ReadAllText(path, System.Text.Encoding.UTF8));
        }

        public static LegacyBinkSet FromJson(string json)
        {
            var root = MiniJson.Parse(json) as System.Collections.Generic.Dictionary<string, object>;
            if (root == null) throw new FormatException("JSON root is not an object");
            object o;
            if (!root.TryGetValue("Binks", out o) || !(o is System.Collections.Generic.List<object>))
                throw new FormatException("JSON has no \"Binks\" array");
            var list = (System.Collections.Generic.List<object>)o;

            var set = new LegacyBinkSet();
            int n = list.Count;
            set.GroupIds = new string[n];
            set.AlgorithmIds = new string[n];
            set.Families = new string[n];
            set.Binks = new object[n];
            set.Errors = new string[n];
            for (int i = 0; i < n; i++)
            {
                var e = list[i] as System.Collections.Generic.Dictionary<string, object>;
                set.GroupIds[i] = e == null ? "" : Str(e, "GroupId") ?? "";
                set.AlgorithmIds[i] = "";
                set.Families[i] = e == null ? "" : Family(e);
                if (e == null) { set.Errors[i] = "entry is not an object"; continue; }
                try
                {
                    string alg;
                    byte[] blob = BuildBlob(e, out alg);
                    LegacyBink chk;
                    int st = LegacyBink.TryParse(blob, out chk);       // same checks as any BINK
                    if (st != LegacyStatus.Ok)
                        throw new FormatException("rejected by the BINK parser (status " + st + ", e.g. G or K not on the curve)");
                    set.Binks[i] = blob;
                    set.AlgorithmIds[i] = alg;
                }
                catch (Exception ex) { set.Binks[i] = null; set.Errors[i] = ex.Message; }   // skipped by VerifyAll
            }
            return set;
        }

        static byte[] BuildBlob(System.Collections.Generic.Dictionary<string, object> e, out string algorithmId)
        {
            // layout: AlgorithmId, then Layout, then Date, then the size of P
            LegacyKeyLayout layout = PKeyLegacyValidator.LayoutFromAlgorithmId(Str(e, "AlgorithmId"));
            string ls = Str(e, "Layout");
            uint date = U(e, "Date");
            BigInteger p = Num(e, "P");
            if (layout == LegacyKeyLayout.Auto && string.Equals(ls, "Pid1998", StringComparison.OrdinalIgnoreCase)) layout = LegacyKeyLayout.Pid1998;
            if (layout == LegacyKeyLayout.Auto && string.Equals(ls, "Pid2002", StringComparison.OrdinalIgnoreCase)) layout = LegacyKeyLayout.Pid2002;
            if (layout == LegacyKeyLayout.Auto && date == LegacyBink.Date1998) layout = LegacyKeyLayout.Pid1998;
            if (layout == LegacyKeyLayout.Auto && date == LegacyBink.Date2002) layout = LegacyKeyLayout.Pid2002;
            if (layout == LegacyKeyLayout.Auto)
            {
                int bits = 0;
                for (BigInteger t = p; !t.IsZero; t >>= 1) bits++;
                layout = bits <= 384 ? LegacyKeyLayout.Pid1998 : LegacyKeyLayout.Pid2002;
            }
            bool is98 = layout == LegacyKeyLayout.Pid1998;

            string a0 = Str(e, "AlgorithmId");
            algorithmId = PKeyLegacyValidator.IsLegacyAlgorithm(a0) ? a0.Trim()
                        : (is98 ? "msft:rm/algorithm/pkey/980" : "msft:rm/algorithm/pkey/986");

            uint kd = Or(U(e, "KeyDwords"), is98 ? 12u : 16u);
            uint[] hdr = is98
                ? new uint[] { 0, 7, 0, Or(date, LegacyBink.Date1998), kd, Or(U(e, "HashBits"), 28u), Or(U(e, "SigBits"), 55u) }
                : new uint[] { 0, 9, 0, Or(date, LegacyBink.Date2002), kd, Or(U(e, "HashBits"), 31u), Or(U(e, "SigBits"), 62u),
                               Or(U(e, "AuthBits"), 10u), Or(U(e, "PidBits"), 20u) };
            int size = 4 * hdr.Length + 7 * 4 * (int)kd;
            hdr[0] = (uint)size;

            var blob = new byte[size];
            for (int i = 0; i < hdr.Length; i++) Buffer.BlockCopy(BitConverter.GetBytes(hdr[i]), 0, blob, 4 * i, 4);

            int off = 4 * hdr.Length;
            foreach (BigInteger v in new[] { p, Num(e, "A"), Num(e, "B"), Num(e, "Gx"), Num(e, "Gy"), Num(e, "Kx"), Num(e, "Ky") })
            {
                if (v.Sign < 0) throw new FormatException("curve values must not be negative");
                byte[] le = v.ToByteArray();
                int n = le.Length;
                if (n > 1 && le[n - 1] == 0) n--;                       // drop the sign byte
                if (n > 4 * (int)kd) throw new FormatException("curve value too large for " + kd + " dwords");
                Buffer.BlockCopy(le, 0, blob, off, n);
                off += 4 * (int)kd;
            }

            uint sum = 0;
            for (int i = 0; i < size; i += 4) sum = unchecked(sum + BitConverter.ToUInt32(blob, i));
            Buffer.BlockCopy(BitConverter.GetBytes(unchecked(0u - sum)), 0, blob, 8, 4);
            return blob;
        }

        // "Family": [ "name", ... ] or "name"  ->  "name; name"
        static string Family(System.Collections.Generic.Dictionary<string, object> e)
        {
            object o;
            if (!e.TryGetValue("Family", out o) || o == null) return "";
            var list = o as System.Collections.Generic.List<object>;
            if (list == null) return o.ToString();
            var parts = new System.Collections.Generic.List<string>();
            foreach (object x in list) if (x != null && x.ToString().Length > 0) parts.Add(x.ToString());
            return string.Join("; ", parts.ToArray());
        }

        static uint Or(uint v, uint def) { return v != 0 ? v : def; }

        static string Str(System.Collections.Generic.Dictionary<string, object> e, string key)
        {
            object o;
            return e.TryGetValue(key, out o) && o != null ? o.ToString() : null;
        }

        static uint U(System.Collections.Generic.Dictionary<string, object> e, string key)
        {
            string s = Str(e, key);
            uint v;
            return s != null && uint.TryParse(s, System.Globalization.NumberStyles.None,
                                              System.Globalization.CultureInfo.InvariantCulture, out v) ? v : 0;
        }

        static BigInteger Num(System.Collections.Generic.Dictionary<string, object> e, string key)
        {
            string s = Str(e, key);
            if (s == null) throw new FormatException("missing \"" + key + "\"");
            s = s.Trim();
            if (s.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
                return BigInteger.Parse("0" + s.Substring(2), System.Globalization.NumberStyles.HexNumber,
                                        System.Globalization.CultureInfo.InvariantCulture);
            return BigInteger.Parse(s, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture);
        }
    }

    // -------------------------------------------------------------------------
    // Minimal JSON reader: objects -> Dictionary<string,object>, arrays -> List<object>,
    // strings -> string, numbers -> their text (string, so big values stay exact),
    // true/false -> bool, null -> null.
    // -------------------------------------------------------------------------
    internal sealed class MiniJson
    {
        readonly string s;
        int i;

        MiniJson(string text) { s = text; }

        public static object Parse(string text)
        {
            if (text == null) throw new ArgumentNullException("text");
            var p = new MiniJson(text);
            if (p.s.Length > 0 && p.s[0] == '﻿') p.i = 1;     // BOM
            object v = p.Value();
            p.Ws();
            if (p.i != p.s.Length) throw p.Err("unexpected text after the end");
            return v;
        }

        FormatException Err(string m) { return new FormatException("JSON: " + m + " at position " + i); }

        void Ws() { while (i < s.Length && char.IsWhiteSpace(s[i])) i++; }

        object Value()
        {
            Ws();
            if (i >= s.Length) throw Err("unexpected end");
            char c = s[i];
            if (c == '{') return Obj();
            if (c == '[') return Arr();
            if (c == '"') return Str();
            if (c == '-' || (c >= '0' && c <= '9')) return Number();
            if (Lit("true")) return true;
            if (Lit("false")) return false;
            if (Lit("null")) return null;
            throw Err("unexpected character '" + c + "'");
        }

        bool Lit(string w)
        {
            if (string.CompareOrdinal(s, i, w, 0, w.Length) != 0) return false;
            i += w.Length;
            return true;
        }

        System.Collections.Generic.Dictionary<string, object> Obj()
        {
            var d = new System.Collections.Generic.Dictionary<string, object>(StringComparer.OrdinalIgnoreCase);
            i++; Ws();
            if (i < s.Length && s[i] == '}') { i++; return d; }
            while (true)
            {
                Ws();
                if (i >= s.Length || s[i] != '"') throw Err("expected a property name");
                string k = Str();
                Ws();
                if (i >= s.Length || s[i] != ':') throw Err("expected ':'");
                i++;
                d[k] = Value();
                Ws();
                if (i < s.Length && s[i] == ',') { i++; continue; }
                if (i < s.Length && s[i] == '}') { i++; return d; }
                throw Err("expected ',' or '}'");
            }
        }

        System.Collections.Generic.List<object> Arr()
        {
            var l = new System.Collections.Generic.List<object>();
            i++; Ws();
            if (i < s.Length && s[i] == ']') { i++; return l; }
            while (true)
            {
                l.Add(Value());
                Ws();
                if (i < s.Length && s[i] == ',') { i++; continue; }
                if (i < s.Length && s[i] == ']') { i++; return l; }
                throw Err("expected ',' or ']'");
            }
        }

        string Str()
        {
            var sb = new System.Text.StringBuilder();
            i++;                                                    // opening quote
            while (true)
            {
                if (i >= s.Length) throw Err("unterminated string");
                char c = s[i++];
                if (c == '"') return sb.ToString();
                if (c != '\\') { sb.Append(c); continue; }
                if (i >= s.Length) throw Err("bad escape");
                char e = s[i++];
                switch (e)
                {
                    case '"': sb.Append('"'); break;
                    case '\\': sb.Append('\\'); break;
                    case '/': sb.Append('/'); break;
                    case 'b': sb.Append('\b'); break;
                    case 'f': sb.Append('\f'); break;
                    case 'n': sb.Append('\n'); break;
                    case 'r': sb.Append('\r'); break;
                    case 't': sb.Append('\t'); break;
                    case 'u':
                        if (i + 4 > s.Length) throw Err("bad \\u escape");
                        sb.Append((char)Convert.ToInt32(s.Substring(i, 4), 16));
                        i += 4;
                        break;
                    default: throw Err("bad escape");
                }
            }
        }

        string Number()
        {
            int start = i;
            while (i < s.Length && "+-0123456789.eE".IndexOf(s[i]) >= 0) i++;
            return s.Substring(start, i - start);
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
        public string Products;          // VerifyAll: product names known for this GroupId (may be empty)
        public double ElapsedMs;         // VerifyAll: time spent on this BINK

        public override string ToString()
        {
            return string.Format(
                "Group={8} Valid={0} Status={1} Layout={2} Upgrade={3} Channel={4:D3} Sequence={5:D6} Auth=0x{6:X} Pid=0x{7:X} Products={9}",
                IsValid, Status, Layout, Upgrade, Channel, Sequence, AuthInfo, PidValue, GroupId, Products);
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
                r.Products = LegacyBuiltInBinks.ProductsFor(groupIds[i]);
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

        // ---- BINKs from a JSON file (Legacy_Binks.json format) ------------------------

        /// <summary>
        /// Checks one key against the BINKs in a JSON file (see LegacyBinkSet for the format).
        /// Same results as VerifyAll. Entries that cannot be used are skipped.
        /// </summary>
        public static bool VerifyJson(byte[] rawKeyBytes, string jsonPath, bool allMatches, int maxThreads,
                                      out LegacyKeyResult[] matches)
        {
            return VerifySet(rawKeyBytes, LegacyBinkSet.FromJsonFile(jsonPath), allMatches, maxThreads, out matches);
        }

        /// <summary>Same as above, product key as text.</summary>
        public static bool VerifyJson(string productKey, string jsonPath, bool allMatches, int maxThreads,
                                      out LegacyKeyResult[] matches)
        {
            byte[] raw = DecodeProductKey(productKey);
            if (raw == null) { matches = new LegacyKeyResult[0]; return false; }
            return VerifyJson(raw, jsonPath, allMatches, maxThreads, out matches);
        }

        /// <summary>Checks one key against a set already loaded with LegacyBinkSet.FromJsonFile (load once, check many).</summary>
        public static bool VerifySet(byte[] rawKeyBytes, LegacyBinkSet set, bool allMatches, int maxThreads,
                                     out LegacyKeyResult[] matches)
        {
            if (set == null) throw new ArgumentNullException("set");
            bool ok = VerifyAll(rawKeyBytes, set.GroupIds, set.AlgorithmIds, set.Binks, allMatches, maxThreads, out matches);
            foreach (LegacyKeyResult r in matches)                    // the file's Family wins over the built-in names
                if (set.Families != null && r.Index >= 0 && r.Index < set.Families.Length &&
                    !string.IsNullOrEmpty(set.Families[r.Index]))
                    r.Products = set.Families[r.Index];
            return ok;
        }

        /// <summary>Same as above, product key as text.</summary>
        public static bool VerifySet(string productKey, LegacyBinkSet set, bool allMatches, int maxThreads,
                                     out LegacyKeyResult[] matches)
        {
            byte[] raw = DecodeProductKey(productKey);
            if (raw == null) { matches = new LegacyKeyResult[0]; return false; }
            return VerifySet(raw, set, allMatches, maxThreads, out matches);
        }

        // ---- built-in BINK table (no XML / JSON needed) ---------------------------

        /// <summary>
        /// Checks one key against the BINKs compiled into this class (LegacyBuiltInBinks).
        /// Same behaviour and results as VerifyAll; no config file is read.
        /// </summary>
        public static bool VerifyBuiltIn(byte[] rawKeyBytes, bool allMatches, int maxThreads, out LegacyKeyResult[] matches)
        {
            return VerifyAll(rawKeyBytes, LegacyBuiltInBinks.GroupIds, LegacyBuiltInBinks.AlgorithmIds,
                             LegacyBuiltInBinks.Binks, allMatches, maxThreads, out matches);
        }

        /// <summary>Same as above, product key as text.</summary>
        public static bool VerifyBuiltIn(string productKey, bool allMatches, int maxThreads, out LegacyKeyResult[] matches)
        {
            byte[] raw = DecodeProductKey(productKey);
            if (raw == null) { matches = new LegacyKeyResult[0]; return false; }
            return VerifyBuiltIn(raw, allMatches, maxThreads, out matches);
        }

        /// <summary>Number of built-in BINKs.</summary>
        public static int BuiltInCount { get { return LegacyBuiltInBinks.Binks.Length; } }

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

    // -------------------------------------------------------------------------
    // Built-in BINKs: public curve data only, stored as standard pidgenx BINK blobs
    // (Base64), so they go through the same TryParse checks (size, checksum, on-curve).
    // Groups 0-51 = pkey/980 (BINK1998), 64-137 = pkey/986 (BINK2002), 254/255 = test.
    // Source: Legacy_Binks.json (UMSKT keys.json, AGPL-3.0) merged with Legacy_License.xml;
    // group 11 taken from the XML (keys.json "0B" was a copy of "09").
    // -------------------------------------------------------------------------
	
	// https://raw.githubusercontent.com/techguy16/umsktpy/refs/heads/nobridge/keys.json
	// https://github.com/ntriver-org/PKeyMaster/blob/main/PKeyMaster/BIN/PKeyConfigs/Pre-Vista Custom Made/Pre-Vista (Windows 98 to XP - Office 2000 to 2007 - etc)/pkeyconfig-custom-made.xrm-ms
		
    public static class LegacyBuiltInBinks
    {
        static readonly string[][] Table = new string[][]
        {
            new[] { "0", "msft:rm/algorithm/pkey/980",
                "bAEAAAcAAACj94bCrt8wAQwAAAAcAAAANwAAABl5wuyQp6Y9iG1I7eF2NeOisL3ZLoetBIODW3WkGfMeb9WVEhlgeHhf38i910/zkwEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAKlhgJQjGGsQWo8/CYsHzfvNIFl+mB8K/q3aDa+r6GhN/1ohA2Y+tqznN8PLNQgmD3yKv34dQF8TY8Zyt2NU4YLIrCW7r9Oso9yT3X9ZQVa95iqzlNVmTlDWSaQfKZWwGeacRMsrSAlFw/MotPXkCHFkv6UBoVnQFoZD9al+UPz0JE0r3nhNXHMeeWYuRBx1e5ImsKgHiWcxUjwR7VgWWkHvmT5LqceNskcbcydu6afmZAoErNCB4KG2V+lRF2f3IA==" },
            new[] { "1", "msft:rm/algorithm/pkey/980",
                "bAEAAAcAAACqvITZrt8wAQwAAAAcAAAANwAAANlYkSBPjsJhDip8Os+aZPwrmvEkp+S+OxaDme+2DjpEgQ6r9jSbTcV0ToO2XgjtjAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAANfUPTl8QhveOqUjDCOI/MeJTISOLHvholMA03jExCzokhtygzcNPxi9PLLFP8pYRXuLll5qoVC16xqeD6pNjXRiyfcdqGgfFy8B0vo5UCcEa/eeVrWFOWWoK+LTm4ayT7mHUpysv4usuBEFTxT4E3zyxNHvRrnz9SUot0xrRm6n7GW4zvTeyLInvr+67DR7FwCQ7gNQjpycgIqUVjxKzRYtM0kfJy3v1qwz+7sJvzbjQwN1fiNKB1vOQ+Hv5g2qWQ==" },
            new[] { "2", "msft:rm/algorithm/pkey/980",
                "bAEAAAcAAACllaGBrt8wAQwAAAAcAAAANwAAAMHDTDB3IY40NyNNPcrJandFICm+IB1qTTSRKiklxHg91ZRJXfUqxUDtHfC3TsXx8gEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAFF7Mg3fdMwgYa/Za4Gi9jA9WAI7fkxtlATR4C8ffflC2o2gFKBxiTBEHYEe8NYbVAiyFLARxd9JfhX3tg/6RBrudWexUeJ5Vt/ahZyn+SWCI2uMonjvW8X98cZGxbhuu7kl7OOOrmT33sZKwyeMYfbJ14RzlhVg3sOMpXxfLHbDRFJpMJMC8bgm/g3ylJc70XQleW7oLCYpUuTlxMOAZQSCNmeZs+OfJsaKesK8hebYgKTLRvELjGVW/RWLK1dVwA==" },
            new[] { "3", "msft:rm/algorithm/pkey/980",
                "bAEAAAcAAACEw4tnrt8wAQwAAAAcAAAANwAAAClQm2vlHGlWzvDEEzeLv/Rd58eYEPejErBG4S5AcqJ5P2Q0luhRG0Hhnzph8k8i7AEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAjkU8CDFES+paJpr+Noiupjg9UtxCsFq+q+DuhWW8FIquD/WJKICNVG5UZe5XhtWsNtO9Q7XnksSz7XqLKMJHWZ4a4XDEEFc5UrZbEZ/BH0BuCAT53IUX9sRHzArxPqBHoCbRYV0Lh8uta2OigfWD18Kgmt4tWyDiOUrm3gT8UPFNm7RNaIoWkbatX/p7qJsIWV2WDJGJhDQs++k7iZa4xGwSx+gRqFLLSEJaelyDZ/D6BekRqh5aekfPl60x8Gg==" },
            new[] { "4", "msft:rm/algorithm/pkey/980",
                "bAEAAAcAAACeORxvrt8wAQwAAAAcAAAANwAAAAF9CXAi6jkCfyVLh9VqkR92JDfAYRhOXXUhXnGJPYHrefrCjUFuqHs8mgwdww3cogEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAPIGHAxqpQGhEtvK7LnaFSeK9sEOZQCaJm1Y+nw8Qap0n9YkqdgfkmRv4Qka0uzgko7tAdZx7t+reui6+EuC5VZK3qNqX/vkYBRb4YXSUbQ778txBxvdYI4VhU5AXW8akn2nWobio9oUR4b6fBx91zM6zq0OYXAFHrMpDOwEnex1BpcqLdiOBGSZGN/u0QUUj06nAkYjt9qpxCcfp5CyMmRKhIh5BWsLAtZG6J1h+b9AEEdBjtNae7g0bU6o2A4Rmw==" },
            new[] { "5", "msft:rm/algorithm/pkey/980",
                "bAEAAAcAAACu4U5Mrt8wAQwAAAAcAAAANwAAAJk20JvoKW810tZLD8nYVaQ+n2lDTbo8otgerw0x7KE5Tg94HyLOQiN8taQQ5blzhQEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAObKiuP18/NnDqQjEwc3xc8jnsH+eLP8gq5+Hi4c/c1etEvPP0cDbVF2IVCdyF8UBWpq6cCAK73GFazlxOBFGjsI1C+WOHn7e/4c6XrwnkRlyp1rHBDPWcnucvjP68niVRlYCAzYwyYWS2W93TNbdr0qYzrIPHaTBwBMzAwRFBLI9TyxBHJUcAB8r8/S0/B/JAdrYzOikGhpdIooPxGY4Clqmd6YruolD7FOjERRCHOh6zCcA+pcVvEdTfbnLO0+Yg==" },
            new[] { "6", "msft:rm/algorithm/pkey/980",
                "bAEAAAcAAADnnxtXrt8wAQwAAAAcAAAANwAAAOlCfTBMZLHe1G6c+OPuBG0CSI9Wozi2h0iyS5QgxrpJn8JPRISZQ7BOknkjeq3U9gEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAL2Bb+bR5b+LxyNun7pRYo3p+hqUmn9eE5wSQm8vBwtLEN7LQ3ogwxHOuG8zIkvVg1hvfssCg2jzsY7Hlctq6HYR6gBlFB7Uz8QRMaDuh2aKhc/XCp8QBFlJktlcRIZxZU4h/BoeAUh48MkhzOgVuUE2kgiT/eGA5VfI1YKd34ijzT/rNYvp3EF/UUaKgFldvnYsiU5S3SkSwyIfcrc3PHHqWt6ravO7gLunAJMbJTfGmanePpPk4U6RWU5QlJCOYA==" },
            new[] { "7", "msft:rm/algorithm/pkey/980",
                "bAEAAAcAAAAxXIlErt8wAQwAAAAcAAAANwAAAIEz71T/WljK/kRU+LQezfsyimX68lA5jz/G1rimy+Aq99o9zf1HKuL3l+W7mnMR3QEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAFKjwTxiNcvk9v6qwAOCB9BQIOraFiY9wKi49XE9O2p7DxOMBcSpQdnOBMrDfMWiE07i72TcD1tQabOFQ9YnU2Tn0fGpfkTgUXDzOjnQw8UpsQws9hrXN7gXzfDqxT1vk6AsZ7Wj+uhF/iT5uzXGyRGaCPrGCQ09KopFpna4174aZouRHLOJxMNk83e8ptzCPODrzKBtGjAGLPqHZcGeebbGX+QEo+J6ANiV3y6yr5UczGry/fzq4dQa5cKyNwPBWA==" },
            new[] { "8", "msft:rm/algorithm/pkey/980",
                "bAEAAAcAAAD/9xamrt8wAQwAAAAcAAAANwAAACECyAgixyLTVBzKNkGeYY1QKh+9WWCdRudXfn1bH2mqT2AoZ2VdqHYSaZ9dmjpR8gEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACs0Z50Zy0FM2I2bGJHfczWdD5dEUMRuKL+tnUsRZYFsqI7z75nnZG1oaT8K6FF+hV/AJ7fui7gamBmkMvzOBeYuHrgbH6jPuIIaAb6vZi/XW+UgouLTvVw5/fbwWr/1Po7I9qPbuPuc9UG+ptlXrX1OpovNG7CXnwRWoh2oNBjXOhGVLgYEYtE+gMLqEXIZniHq1K/7xdfWv5PhUOlKgKLhQUThKo/RToSet7HHfYVkmd9uOpZPZi0w5N2+3zQXWw==" },
            new[] { "9", "msft:rm/algorithm/pkey/980",
                "bAEAAAcAAADLzkPkrt8wAQwAAAAcAAAANwAAADHi4LSYaHPolwAgc36NQ+Eg2OcIrAfta3wOIKlFFRx4VePM44YJbU/r9rffCxw3ygEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAKL2WuPGjFjVx+IS4AAODJbOa5RR/UmqqhwAdz0N38HOrKoBHx8XQZD/0ojreM84cP30XxHPpwS6+HjRpyUwzmVGM2y162ZpeHQ4JA9Frmrkbdx7vyzXbT13AYCyUb7NRpTpIgsjqm+CMGOWlbkZdqAjafzsQYOVhuPSST34KFX7UUby/zkeismfKuyhAzTERHL3LczNOLoZgI3MJx3snILRibou1DbRJgVNDlVEe0dRcjx+LTdN+vVGGPIyGzsQgA==" },
            new[] { "10", "msft:rm/algorithm/pkey/980",
                "bAEAAAcAAAAa2R3yrt8wAQwAAAAcAAAANwAAAIGhK1iBUo/LAEsdsaw/C1mx9rIc+TEhmWbk/a/AB5D2RdtH+3BvqVHbgowvPRaX8QEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAN+ODS3mzpFwia3lMe0EqUKSkuraA6WU1oMh3ZspiKJjbhKZfqTHlGPYVDX4jCiYmzeoCX67aXWeWYL9Sav0HEcmR5hqk6+y07NUH01ZAXAYN98sDa0V+qNGFlR78a4evt60ZZvzpyMmS5WZoov/2zLf0vvE3qdBScb63AbHpqawNzsQlvLxU7NbekuXPnbraFQAcbvqif9udx5EVbdWAUz/18TGrnVGvTRzysNaAhlZY2O63SPVycDWxe+hnAitSw==" },
            new[] { "11", "msft:rm/algorithm/pkey/980",
                "bAEAAAcAAABseop2rt8wAQwAAAAcAAAANwAAABGQS9dHX+QNYy9TAJpCvTh1HkcZIRuPXHP9nIR440dN3PNoJI/YkgV9RM68+6MumQEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE1DEnFZZ1YHqpLWZpTw0oZ7j83I+IRYVTMNiyzwRXcmv3jK2tP4+njYxfvNRDDBDzjF8D/DTFqrnt+5QpWSQlGjzwZs6rNYbGgxTuxTcqeaC/fDsROK3z6JqUfIKXeWL/A8vRfbGM7IGaa1DivUi5gMmW4z9AENyNoDHm1AdDnsAIoGRh3ij6hD4Jkw4jaTkj+J0UXk8PvcJLgi3ZxcmtXhEg9rrgWUVU15XFlbcJCLcG/sNDypeBw25/FXhTGgHw==" },
            new[] { "12", "msft:rm/algorithm/pkey/980",
                "bAEAAAcAAABRF/4zrt8wAQwAAAAcAAAANwAAAIEefU2/EM+sweZcUXqHuM172xqU9FQCg9GmjjqWVm8Holl9j15VMPd7n+OqS7Ki7wEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAALAxJgrRIJqcznIHHmT8lWCaVVJHYE12tBl+g1lYsQFSzlT7LmTfgyWe5jCA4S5K0om9ZYfmrlHOOCooW0glBARUGAfroLSguEDIV9RUSeAJZ5Z/AlFQE9rNl9PUI2Wy655YDag103yxyRyv2YwwZAxIk0pVH77IaQtY7baW2MF/qlinaXETSi/fpwrYyxhBtTfjz4yNXDlVe8WJFDaQqSgZUMLYnAmwg28P+VS6jmr+0SvYu3NNnwqkUACm+V92WA==" },
            new[] { "13", "msft:rm/algorithm/pkey/980",
                "bAEAAAcAAABkQHN+rt8wAQwAAAAcAAAANwAAAKGB9dtgabJ7aL4QZ7Epb80WvtEaixW86+K7a623wdJd+w76pMQvA3KflcnVW30ligEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAANYeCUN+l6Aqxnpz7ZrIl0i4D4P8Vtsn/nw4+XFnVu+fJzWZ/F++YKjG6cBDnCwtK32ViimWjoF7WHggpvoc2yyKaSS42GjxTgshsmISyWru8dygpPIZMMj0ek7NPL5EO2N8y3J0aLP/dC/+L3HpHZzl6rLPFtKgS9fyJPirYwWiadFVnM6Jd4ZJ0cR7THhPdNyr0pVd4CKLF66tPNkF1j5Fqv8DlCW5KCdtz8J38rE5H4JhhqfhZCM/06XT4OeRFw==" },
            new[] { "14", "msft:rm/algorithm/pkey/980",
                "bAEAAAcAAAC4/ijert8wAQwAAAAcAAAANwAAAIG0wYOeAn9CGthhJ+KlVB2eXy+34sSuc71mB+0msnGHs/zJ4SJaV//lpGTtWIIn7AEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABgb9xVFqlH1iSz0FKL7YyAGbQL7WHtzZzBKdTF9rx+dBsTBx+XFalilbqJbf+FHtAc6ibs8G4zralRYHqU6OccUXlnNAt3+cZ7uZdGlrmK7l7eC+R3iYeotDggM0OhNFh+YkjM2CJjmpYjB5mpYHm2lAv42xzpEnJc4h6/B+GDDo1abZlxKtnjQlgO+c4+ujMcUBUUQ9lTHHVAHX17TtIO8kcEQaPGHERJXzroduYkUhtA+cM0ODOHH43WUEPwzFg==" },
            new[] { "15", "msft:rm/algorithm/pkey/980",
                "bAEAAAcAAAC3BR1Mrt8wAQwAAAAcAAAANwAAAIn6h1mwHSQeKtl3REsw6UqdHGqFHLK0EleMEvBSXW78q45xUIvq5aJHotC/ijX99QEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQ5OYBrfwo99ONZwuyzkEGOgZ3Ve+KPv5WmqTsWYKPanLYpN3CfPFYkWH9cfgZ0zi99s7UNRIwibUn3n9IlXT6JD17+5pLvHTR+oQmNChEXdNUyB9NRHqEND0jojTHpYDxYobFTkMn5IZ0vbdIjE83Y6Zq44/KLuUW6Bk1SJFBYNdzcaDHBA+lh/xZlwjr87x0vzgeSCznKs3Ffizau9I0e9pxBYGhuJH5dZ3YJwENJGGwGQ+J+FNnCYo9SvlnrTw==" },
            new[] { "16", "msft:rm/algorithm/pkey/980",
                "bAEAAAcAAAB+szd6rt8wAQwAAAAcAAAANwAAALmjvj49uImfh2xY497JMBxhebDIIYRLwUfALQtmDejlv49nOfODaV2iu8BqMkZu4gEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGDM1ZwKJfE27OGjCQoxP022FkhcQaRd3Fa8cwAcI59kU3RYoc/X7oa5WRH9dpwuefoJr3ik0UB4dt+6wcyeCpuJ0d3NaIURxBqV8UBFvFSDyC2ZtGh7KCTqgqDQs9zkuAbkL1AkEWW17EqofQFDDvP3zZr5m9plrHeNaaLOGb+AFtxMbzZeJ71qCPvxvxTKYP4f7N/mV1M4sweldvb4DnW/DDT7x+subgVZDfQWwYIsQvO1UXMCusHjtdOzsaq/xg==" },
            new[] { "18", "msft:rm/algorithm/pkey/980",
                "bAEAAAcAAAA9Verrrt8wAQwAAAAcAAAANwAAAFFPJW3Br0FY+W6twFZ8cbTdZyc1CDK8pFz7XgH4yGlrPlAClxrbZlm6g89at4T8hQEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAInLjUFkxNsZEvIcekDCYyMTMql3J1ISJq8Zc92kQXkQ5QUVy3HQkk0+UpY3D6c+SCDEyKNMnXP6QQhWlWG96XOYRApFsnLU+Wn4HmNsq9B2VAOh8z2qkosJf1tMVeuDIl/l39NAyr7Kh1dJU+N+gLbqFVBiHKurGJhTZBYDnde8PUQWYuxa7jp3yXN2rxLxNbXSRteIkAN6kAsAZIY0b05qnHjqn5Aq5eicIYolsHL8WWFKlTa76d4jhg6QQEzTVg==" },
            new[] { "19", "msft:rm/algorithm/pkey/980",
                "bAEAAAcAAACm+qU+rt8wAQwAAAAcAAAANwAAAInddobwoRmfF0cDC9/TAEYQ0XNJ99CnxeS36sMYSdCqxdGxbPQCS+UtnLD0vEY90wEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAO9WDlQPrTYA9UlN6c84v38+bc+CVwmkCEeRj76D50/33Efd1LhmNm4w7ngLJsVgskpsMHElEilTkljEGnuwh1948HwjTVwnEiJKl8mHXY2h/LvNYG6/K/i/WfplG6UypwC3WPGYLao32mTp8yg1yWbTgYk9i1KEJC/bkJOQY40QFraNwn90pi10VpG9B0n8F9es/zmTiXmiQBPvEUrFmax8XBBzbUxq6vYBTdCk2sICUfJsnr4lE+rxaeocTu4RrA==" },
            new[] { "24", "msft:rm/algorithm/pkey/980",
                "bAEAAAcAAABp7jOHrt8wAQwAAAAcAAAANwAAAFl+J0oNLeNXR5KnpTjrcOn69KVwQ/1AvcXo3/LWyoPfuMWFPhryv9fFFMK2Sj9thAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAP/kZ58Z8AyRWkp7k/lpcHuOMAgWn+EYMO5JaJ44RE2Thpfw1bDl+twrkvhOQv//KM09WW1dayQsAkS1sOYML3d01rCClM2+CuYVnl++F1+DsLOzzYQtT39qzPaDNaJMYT+HXFeYu3vF0UcLgTqvuuHOzmAD2B2AkueIlgrdUdgan7k4FuFVvNpKIieXrQmROL9RLepdPpQ6H5SSIrpR77RwAo0br2wHZKfnQaG08HG44TyS3ewioiGyw03B1ePeHA==" },
            new[] { "25", "msft:rm/algorithm/pkey/980",
                "bAEAAAcAAAAXhOmort8wAQwAAAAcAAAANwAAAOnjuMvmcCPYk3miknX/KxWpIYtrLUxim0XZO8dlWF+C9g9+k8E6CQMzBzQULg5LwgEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgYMSx83pwkbTUTG9BjjlGO9BfmTbwnf+9rid+h6nfc5hhV1nNS3SctGPgAqg9HMd+cq3t47UzbqOq37XJM8LTWo1YFfz+YKepVLJzIOjClU7UJ7lBGEmDnXo7n1ohzJTzQ57VWI0geflKryqxnlhJDh+9yEZJ24y8lctbQ+TqmGTSwIdsY/ZUewae/VNUxcgoKIDf9mkVMDRLMt6Jkfbbaa8kEqKXNffuoVYQYVlPc05pW0JfSy1rNTBIDztlPBw==" },
            new[] { "28", "msft:rm/algorithm/pkey/980",
                "bAEAAAcAAABWWQ6Prt8wAQwAAAAcAAAANwAAAEHycoPqV9rb8OiZPPZEdQBPIYUVUI4wgukXKTwm6rbVzZztwo0k3dkMZemYkJOv8QEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABPgvwmmtnj9N+VeOcQWmUD11cwE2bINcdVlyHZ75gCpDTfauISodMgacxJgcll+lKC8Y9KcAR+cHTDFBTBhLJNhOtRZofA6zQPoRUg67DSijBJIhp3q+tT9yq+vRZiPQU6JRZcrniCOJwfL2s6DNczfrlIijXcaiA6oLmnK7Wc6YdnqP4uepESuhyzjVTFkl4ia9zx66AIWsBWsEkhzHXfLshfpDQuj/X+QB8y48NGPWFvqgbhIgCR0xeJ0JMoFvA==" },
            new[] { "29", "msft:rm/algorithm/pkey/980",
                "bAEAAAcAAACzBaYFrt8wAQwAAAAcAAAANwAAADkDIz7ZvZx+uu5RI8vRRyMieNV5Be+wFE5SBWWLwl/zrkHkh/bVyrGUfettfLnqtAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAdORakbKqrU7MhG02fhF+Z2IxwzLmfjryzxzBDv1d8ZC9zEQ1RCQDANY9aWBcWYi2q5Pu9qnC3MnJSYokvk4usq+Ij1dFlO1JNwkC8nECH6CiIeYv2mT6pySbyjTICeMXZVlnV2EEVwU0sWKDdFFtqUik9Qm7ZZ65kJDKb+b8VZNNv0hkcCVHRKP8Ulrz2vHwABqT/3CWwdStrhnCD62UZHmUDNg4C/TRb4QhNNQScQgX0WX59PiOkCs5skpB8BZw==" },
            new[] { "32", "msft:rm/algorithm/pkey/980",
                "bAEAAAcAAAAKWKttrt8wAQwAAAAcAAAANwAAALEZbaB4LoDmXJKjcfDcP7E6u9RpEWl5VQ8raIIyqGtpwAFsHfDSFbx7dD6D46RfvQEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAOBEav9oo9mdIgw5KUPzzQCt965DNDKexZ/P+ClvS6IVWNcAxzPfdkZMFPkfDiFxK48418EBMnLMLp39oJUtfcvM0RQPE6uyh6k9ZLR2oovirZyfjRdYsQU5vEMf39CUOAMpjTZscmS47qq1Eom2NeKwsHPf87wmivFt7wYwQoqCOndtOETOpTMS9KYPs5YCFCHPNsymsWXS+s3ISFRedBqGUZ8cPMyyy6aPo5DKU4C0UIAe7+ZjnvFv/Sh834Fzsg==" },
            new[] { "33", "msft:rm/algorithm/pkey/980",
                "bAEAAAcAAACUT0DQrt8wAQwAAAAcAAAANwAAALktbzC+1fNz0t53YY5j5rWcqMvr+ckDZy86XnkM/B9w3lEBhzCMbObBdCUQR3k20gEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAPnZmq3Uo1LkH3eXpYHildw3L+x6ivDwNBbU0654GNBMNEjDI/RpaxzexrMbJMDmLgN8RV0BYwVqsDxK0S4kWXfvaKts+21kKFuTqZj2dXyuCjkIoKAb8n4g0DTGEJtdfiIkQkaYS4rJgDWeyj0/PBaaMXxnrZxZUCE/MLYbk6AyHBeEUxvKky+azOkmIVgdWyEgZX4wp3JPLm7TTeliaQsj5s/xgEU+dY2nTZxnlzv5sLDh+hS0boVFUF9LXdTXxg==" },
            new[] { "34", "msft:rm/algorithm/pkey/980",
                "bAEAAAcAAADCv0fhrt8wAQwAAAAcAAAANwAAAMGjT96PidKZ6bh8zD17TqNo/wRwgSaOkZF1QOFArGkMC44uC4QKAEukSaGRkPufzQEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAFQqQ214mVFZuT6lLtq1L+1FWI3NZtxUg4rWMmm3cyOAfrTt2sS+qskwC0RPnJGmT54xRxJ+lDlH5/TIakzzTjNEu9xrk8UcKRwDGHyZTq03Tm/Pq5oKQyD0n0BHv5uBYLbSDnAfI0vRGO85lTsE4fqi07X+bjZ/h0ehwstGE85Cz0Xr9Zr7sEkB7NW34YYmJoMh/0Wl7dyQr8MAmrH7XPHzIJ93ryHKttwMTekvPMjC/S6dAk9q+TTRRtBRmcOoMg==" },
            new[] { "35", "msft:rm/algorithm/pkey/980",
                "bAEAAAcAAACcsFpnrt8wAQwAAAAcAAAANwAAAHHavMAXnYy8VCPD2gt+iLv1ixxOrNrNlZSbnbsuB97eaBoqRxCd2nMg+xfj+XA38AEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAJsloB/Hy95LLUaeyU/hJgzowFuGTloiayAz8ePRYokmyQg+sOJG1C0xQz8dUv5ae0uJXiDXV+NOVtanJQDZKCiboPvejnWhc6YELU3Xn4m0pi336805bf2RlYc4orQv5y/dXFl7hnJhYC5PsfZ3xvfa0URQCx86shqVlnPjXw/JBNiyZLQ49wQLJPL2DSaSI05bCHyYDDdilBQd3ROqR3VMTc3XMetQqsPoC6V55/FZtCGm5ERl7xZvl5WKsjeWSQ==" },
            new[] { "36", "msft:rm/algorithm/pkey/980",
                "bAEAAAcAAADbhTuhrt8wAQwAAAAcAAAANwAAAMlHfTQikCC2pOZAE+zRQmGScaLgJCaxpl6pmVsk0qXnaxZVwxVG+OjhYbQuyai+mwEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAG+Ir6sRkG+EWCj0SmeA/RW+DJIsbiBk5ltpaBW9U+fN3asIj56pmeBsa9xRVusvHUjw9fX+eQX+y4MO7+/1EGBBawiEBMHqkQxB/fUDGxUS9l55vzfDNPlWujYaE9ACCz1KX6PkzB4B2iaGJr5S7HYT+OEBrhJEzDvNROQRXUB7YxSkWB2XQZODJTh9CBmIMFJWDzWFRaKBKQU5Us+pBtD5pcCdGK3BK2aM9B/yH9+WeR0lSXCaAOC/RRIBbCVQiw==" },
            new[] { "37", "msft:rm/algorithm/pkey/980",
                "bAEAAAcAAAAuaH71rt8wAQwAAAAcAAAANwAAAGmy0Xt40GZICGcIkCXA17NTjsMxfy+rvYF0BDpZLB/i1sm6vJ71JPMBg1ua0wws+gEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAFGk4qnLw+N5XpMTUeFkA40WwkAGdSQ/6Q6jvqZUkyhjYVmLoD+JlJzr7w0tYJl9TcY1PQ39wYM1LZFvEYfJUQfywx2R1XEhXiyeFvxhKx294UFOkotuP5boqdii9QQg5ilQ2HhK8dWM5PsaJ3DExrW7/hz3rq93zy0DYydhI8WCdyhmKkbpIQkd/5UYGZPd5lO8w0YaM3hIQYsmLPj0xRw8rR+E/HRBgqfowVh13tdE2IQFqXFm5fCiIPLgcuSJyw==" },
            new[] { "40", "msft:rm/algorithm/pkey/980",
                "bAEAAAcAAABaMaPert8wAQwAAAAcAAAANwAAAPH/0WJ1DaOdOYXAXXjbJpRHdx2AeFfRmwrL572l3CQo9m7QsegeXfiFaLYGBjqVygEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADudszVGCM4h1qOaHui5DNmahs17iXVbTiDgOyZT7Tgq5qSIffO/wdLQn5LjL+QLK2enRLKLYGws2AKQ6jIRUtm4x5PXPYlOfRSg1FkFC2EAQvvbsG5um9ZmNt/83z7lpV9+ZSKXZWC60iKSU9FWNZ6eYHCQ0fC4oJ4XibWRLPsI9XfRh4ADLjSsway39dgqIVKCoQnop51HG4vTqM7GIDcGbsuhPAFcV3miKaBZEL92LM/5avgqJoaSbH4vUR3Qtg==" },
            new[] { "41", "msft:rm/algorithm/pkey/980",
                "bAEAAAcAAACMAcE9rt8wAQwAAAAcAAAANwAAAEEwzsS1IcSAeEwEVtjPj5+KEcpmyReoIK40w5QjRIw87DP1O+fW5momJ0jSItgRiAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAMhul7AwSXuELFOE7SsUKA8gL6qyIILa7RltjSsjjeMfZZqZlPPHYI8NIhNOwkqLLCUq0vbpW2wrj+4nHC7BeZ/ncwnbTvoUn+PDYd7HBEsAg+Eu43HECD50JVB1+e+zC9uMb/2JcWsWVCy3MxyQ2hhKckyun7UHsLUsomBg13geEWO7KUjeXlBhj2/eiZJGf0iKMMNG8Eh77Y/xrmJdWnow2Ln4pMZOb92pc8EBDoPInRBpYsXBpTTiZd6Jif9cBg==" },
            new[] { "42", "msft:rm/algorithm/pkey/980",
                "bAEAAAcAAABy0AfCrt8wAQwAAAAcAAAANwAAAMk5KCsQDaSHGorxLTYK66gogpab/zSb1I2JtjpPpIc/oBN7bue8eEmS/GOtrUrfxgEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAANKE/fTG8Ha5dysJk6wctrH0kEBF+qPYwR43rWftlPZlrvq0EYRb/Um6NzV0ImcsKt1tWF/TgPcLcFTwNhOcWL+zzPuOxn17cSOGc5NZtvRAyJfrOtohoQ3NnS+shzOzu+Ks91fGEThJLBUHeffM5zzzd6eQbPMxUxeZ45ChBKlblAuM8R3Thxu3G+9eMPRFMNq+4J+YZFtkuDFkanATpMogftIvmTNECGkbM+JMoN44KCmh0WyNMeLu3wODN8x5bA==" },
            new[] { "43", "msft:rm/algorithm/pkey/980",
                "bAEAAAcAAAAlzjh0rt8wAQwAAAAcAAAANwAAAGEoXw0jWkmDAIBA5HEXeCnHQSt22LY/hV+1gnwlNMn4f0AtGEEInX1oKDvRBA4cmQEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAHjb5SN9h2t1t8I9XftNuXQsYIDbowFLsOMnU/1rdFtsNJgKw94j4ya3bheDDoTtOXQUnJwxvuNjwF7OgJMA5xajlA0pJ7RLZ4KCp8YqCv1pjjHWeIUdAo7tLfMGBzL2hKh6YBhybDs6ClreYsnM1fD+9RyffphiQVk7LTBO9UdBqItibK7Q0KyMVMkkYfPWIQgeKxrfb40HEix0D92Ue5LzbfNzPsnxJ0IdKSszM3xbU5DG35HhPg3vdx/LZMxCkQ==" },
            new[] { "44", "msft:rm/algorithm/pkey/980",
                "bAEAAAcAAAAs6/P9rt8wAQwAAAAcAAAANwAAAHGbjB0Cw+iL5hyZNl1sHSFgjdwxBgTucoB7A1hmnLlWt9QlGlHb49Lx8vlqEhucngEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAH87pA0QeYV8BvRm/7Dh/FMONe2+qRYMNwpaoFj8jCin6WxzjG68YlIOR5UQYY7QjLCi/RD0wDYSjR4Tm6xdVpshjIN0xDz8ig8IlsbT02WFEVEcpT6oztwCykIYev/+ITEbWZo0KICYNXNL846XG1r+lfzVcDOuQJFNlcFHel2BYMrMlBwiWlewzw6PAT0GjDr0lMPHK2xh55ULb9dXiTh93uqvqlOLduaoNeSt2AtT6t+9LuCEplbKtm8cZyt6Vw==" },
            new[] { "45", "msft:rm/algorithm/pkey/980",
                "bAEAAAcAAACRioAert8wAQwAAAAcAAAANwAAAIHkDTDnujG1pdgthYeO6lHgCEh6TbBEJxQKg8+9C/5GJoh7sPOmKZwiXpu08nG53wEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAJX2CD87twV5p7hbImzFLoYq33aHGoDFPBFerruODZs6TMPZLu9pz6HT6m5j3bKAtOuyOEpqF1MarHkAqxf+78iZT2E4KbE2hm9PCTi/1myqBOsMFS/EN7PMI1k1DCLLsQNYsYYBIfC7sVx0Vo1NfmskKm69k6xau1GlqizQuHzp6TotDnx1X+wLRmGx/1AuHxt2lJBjJs5Ncco0oOjhomkm9Re4Dqc2wl0W3Dp0L0ysjSDJ9PX6emEL8Q7/ecieYA==" },
            new[] { "46", "msft:rm/algorithm/pkey/980",
                "bAEAAAcAAACCjVM5rt8wAQwAAAAcAAAANwAAAKkTJ7MDweCql3EBDbKoBOmOIxLqArVifcC8vZPLmE1FKa5Qo5sumkj0cZ7LFM/dkgEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEJ3867xFHrjQ2SW3Lh2VA021SgKfrEs7rpieUmemK+gItRQcKW+OY2JsCHOXnfjRl72BHbiC/e+xiuTeQBYs5HBfD/OszEr253ASpwsIgfYAxZJzWlUMo5H9DQsHXSOfPhLqQuwipiwwX0X9vpk32S8tbt6HoobihfknMyl9piwLlRDYataxEHsFYAZdb6NXfor6axET4krZzME8+vmVcrbgCBRuc1KRGd28F9N6mx0SIt1kXEMkZ/IA0gLmpCiIw==" },
            new[] { "47", "msft:rm/algorithm/pkey/980",
                "bAEAAAcAAAASZ0gart8wAQwAAAAcAAAANwAAACGylovt1CC7TYe3T9gJalE5XNUOGK52wE98aPNTxDejng3NgaXB5neTnaj2SscRsgEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAATVHkw9PQyE1NLwVO4eSEyQxF9xEL3/tfC4KKn5rei26ZSzwiirGYvndWI2F1FNqCtqfyQxJxSv/Pkq9MK5t8jRTIKrY7duh+OwFi+0sghInb9yWpeo3DCyJ088xKHYcKgXZqA1Rn65umg4IXnXp+ETGTLmVyuuP/daJLW3euf11ie2T9DV1CgqKsBBem89QRg5h2kmBmPyI/FaDobcvrqfu5yHhPfQu5YzEDh/fWZwmpen077m1PcsZQUa6KlfPA==" },
            new[] { "48", "msft:rm/algorithm/pkey/980",
                "bAEAAAcAAAAtdwNOrt8wAQwAAAAcAAAANwAAAKkrXmzlEmq3TO8HAmq8PlnSUdKCxNa5aSpPsZiJTTiZnJTIRoiw72Q+dzVg+P/4zwEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAPNUhT+bhdta6Oyh8VbthhoiFuexsfeomvn7U0sa7HubWiKgAovs9K3N5wqH5qAkzXP+LGpJwiT+si3aqwce3o0oXg93aI5SNgWGddw688Qjj0/1mLYgmB6b7hJfsS9XEunWslGh8gdriIPjdQBpvP4GseUW3bMqhaQ367xlbvcfMtgYHIQsLgCQWNL/s89BqC4RjlzgNNQxEn4q3opai503reR981UoO/XHB3NgMID8jMtr64/0i6feI1ihMwxuCg==" },
            new[] { "49", "msft:rm/algorithm/pkey/980",
                "bAEAAAcAAADQshcSrt8wAQwAAAAcAAAANwAAAPksqgs3EDJx8CQTqVlupci+ynJhe1PtQU2vvjyHodbTs03Fl3TAnf5K4R/Op9iOpQEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAFjRIbq4OLsZ/GtUqiLbLFijeR3Ji0aYi+gzGPddIlForJkFPGr450prlj2S8cmwSJiV/BCOAriOGKj3c9AR9c8OJWvFBSYJqIsfStIpDp3j9LkiecUcPzapcFlz5PQen40UD5rRAFHnO8psIE1CjbwgQCdhgrvgRv3wiUcvHI2LThCJcamMsUZMq1C2fBPVCtnIfurx4pix2OXz843bfvTXNgdUwcnA4Y11aqGL504KbVkKGQsL3Ia4/U3FYU/RbA==" },
            new[] { "50", "msft:rm/algorithm/pkey/980",
                "bAEAAAcAAABSdkcDrt8wAQwAAAAcAAAANwAAALFnhniJi7p3fKTgWEQEr1HTdqoGXrVs6ooJrN4mU0e2HniFFZgKvCfq/2YcCV7NiAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAPy0/ntSE/rDEdQw+SxsQ68CUYcO14BPHjDz1Wwdyga7Uf5ZRtRzqPeMuOkXHHyvUu0efmWmeUvGPwO5+0AevPv00pwT3Ag3kJqB+fT7c32M86TiSvDJiNI/HyGn8wMsgJcsBtTtNMgCQhllBa4x4HWOsEd7L93fUrQp0algGoFNpEGuEYO4edOJo1w+ppogiChjN3TstV1jg0RjdBUSbZUIcqTfuPsucmF97bdjIhBJX0D713OnvyY5id5QyaE1Pg==" },
            new[] { "51", "msft:rm/algorithm/pkey/980",
                "bAEAAAcAAAAPlrFzrt8wAQwAAAAcAAAANwAAAFE0T89q1LeINWc2kv1kDK3af6kEe3U9BtXRSkpeE6YtzafOrEJe5LuJFYbps6+d0wEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAALDfBf3xkzcK1zCWZCizxgPDcn0wqSgY5ujsUywocKTSxRwfFD3BfO7TUQC5nlapC/P9FPtsG1HkI8toMWWShiuksde0WGmeyE1b6ftwNvZOJTjqdjcf1ZXPqlJzEusZxzDX0oG/JiGja5qpCIaSNA9hFYVajep0DVg9KIUm+r9HSH7IA8L3HQTy3r2FThPlBfi/CXuYKfu9/6CSIG9BYTs9jIqD1DZRak3CsZw8tey2jL+uqM6chOfOmwDZ7lz7bQ==" },
            new[] { "64", "msft:rm/algorithm/pkey/986",
                "5AEAAAkAAAAo9NXzxHwxARAAAAAfAAAAPgAAAAoAAAAUAAAAYTA6fzzNCto1jcQMAmWUdsoD5GxNmU7nOeAVaXpHNs6p0Uv/R1XZ2Pc9WkVT0zYSBtKLiFaK4v5SdCUyWCUSpAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAArwBY/nvGwgc8QnLw99aTMzn2uD8hfvZN8U0ASmLEyQCUZhL+D9FxTp+BGuk9CyMSXDoafeQT3bGs9L6EOJ6ETaq8gCwlHrqXDnltPBl6ldKv6vYiCEJ0HWyR5CFQ6MBi499qXsrW/8I7s0clZ2KXHHGl0f5Y+XZYeeRHX6z/5zLyREt+OTuB46ZHwBg2HRtencvdjhuVVA4PMHuqlWqteIoqybvBcIxeKbpEu143kJ/KZvnjNtXOHJPkWmfHoVaQxkAbOzBhz7zJq70/vL4MKaW7CPSDTb6enp2w38jyqWkDFLInSU9GRXF3sfCnad8a8tLiBzRFax7D+VN7ha0uhw==" },
            new[] { "65", "msft:rm/algorithm/pkey/986",
                "5AEAAAkAAABcBgdSxHwxARAAAAAfAAAAPgAAAAoAAAAUAAAAEb9/Ucd6pwvWDRV4hkIOhyVmN+SE5O2+VlxeuHMQ7eXX52sWEUkYICa6FMo4t/j81h2vEKaV08owagrLMywZwgEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAeLWBxysHNf4+QL5Sdu+nFV2uG+Dv8yG78Tgwz5JXkfEEivBhFM7vTfzI6LNY+0svQS0AoD1p76e+RHYDkKfzum7d3TJrFvSXwNOnVxhv+luItozBoZ9RX1jLBBfHrNb1/GAQvfLj0ZYEDnpAup6FGPorC/XqSrthK1i3LXa6pL3cyCENGAqE5UrCezVOT8agghyDroTiN2g0fyfmNjrNSuf/RhkKzqXVZ4xP85eEcQZE/RgPbl41giLSuzROTzZVlb9ccN/5VJjhResDUO7vZUoi+XT8dh1lv4tCUu1/WXf8sfVpd4y21TanYhK+Jx6vNFwTVtgsbySAURX0fZqMTw==" },
            new[] { "66", "msft:rm/algorithm/pkey/986",
                "5AEAAAkAAACQfNsSxHwxARAAAAAfAAAAPgAAAAoAAAAUAAAAWTvCY9CpEOkGeTKEZdw4hKWI4aI2vhF7u6OEtbn2X5PzsoLNfxu+kot6skLv/KelfGo+pQgbcuBYQKn8ffUf9wEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAALZ6kr4zhSPqLcqTJDMSgf962DJQ2i2Cqvj8leUX6KbyDm2PnfE4VcdYQ6gchb2VbtDqTlXBqxQdt7e0d63s/3o0tOdhlK8EZnOInvdXCPVUbU3D/Cljfq129Q0babhIO6lw/PJeO+SU9NNP2j/OiNbjzRNzDaZxeceomNaHaVBUlfUxsYRUh31P9HUGyk2f9xY9JaE78xoGhHKqyyf0h8SIhrYvJqYMxeHyMPWvTkKy44ZmUepGFMTkPqmB9wIuy6vzUJkYpjP6bg5K7c965xtNSCp8lwXg7QM/KC1Jg9O2Wh9DVwUX0J4v/Y4u+kmnaJPthqp4AhxrQlY6k4UsLuA==" },
            new[] { "67", "msft:rm/algorithm/pkey/986",
                "5AEAAAkAAADosBHgxHwxARAAAAAfAAAAPgAAAAoAAAAUAAAAUQMgSY9QXJMTxBGJOjHsbP85jv+4Zscc439eNo+6LyPcfNGdro0EalsnZvYxsM3OZaxpyt+EOnXuScY0coU+hAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAASgkVcctzC83QnRyQ/OhEexpZ7FhubTbBoi3MplA2mz758DzFRfFDX/NHaY+mapgHaaN0OUjVZVnXDp5DSa4eNvZfR0eUPcOGIDX/VBp+SB9rTLym7o5Kb4xBxNKRwoHQChAKVsGvUEZ2Da1KQTwB5NH3ZLmcchrH2IRtST2smltzWISVsJkXaKzwvWFCbkjwfdeoe2zbfZbGyhriWazOLGd068uH3jc8TVyKqWObB7Ug2n0FevCpsjbWTY2WIMNuIWREvdbwgNM13v8s+q+sFStM2sXEirUW1KwZZtKW+4zA1bmGpf0rSVQY11/Ecy0jEsHdQqHWMD4Mp/7rdtemJA==" },
            new[] { "68", "msft:rm/algorithm/pkey/986",
                "5AEAAAkAAADerCY+xHwxARAAAAAfAAAAPgAAAAoAAAAUAAAAYeLvcrC13fjhlxYGSy+qi5b/Wnz9CvddjBJUW/eTTpW/WqaAe96iluOcrliqLHWK8v5ogA8LxJBtr6Hv61IVwAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAOGZTCWDz9DJNs7aNQEJ8XKmGDYmKrEfYyvh1ZID6uSY5UjJcmA/17P1/JpO241Y5EDho4+rQX+Iy/7upYRLWuLfEcAQiXN/uWELcUGXe6ASGBkSFdgNNHQWc7RUvhJkDUKfeVni5tvOQMwkF4VBUbYLd4Rmupl2v59I/9L4mvgA8jRw8Sh/PobTgfE7OW9kbptyE950Tu6lpL8AXQArq+NfNNZ4swvtUbh21lWhMqqyW+6fcKnBHuui80cXWuRuVkSw5TpXn4nIDrrzo5RXCjfADy5brMG3Q9brDCC5dLErw3cgE/fC+qIQfKzanpVF7KDTSXsz6TmboSXkLoG56KA==" },
            new[] { "69", "msft:rm/algorithm/pkey/986",
                "5AEAAAkAAAA0afnGxHwxARAAAAAfAAAAPgAAAAoAAAAUAAAAUUIMtYvwAJVLiZL7ygugh7DX+xun/gK07ClJzxcHFJ6uJqi0bM5VK61q0+2SdI0cOxRfpDZ/xgqFFk4CL+rHoAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAApX/LUfHtLUjr1mRd87j4oToEObGRQMZo+vViqUp/tlBvP9upWThZ2zQXBrQAcDDZPsvSWncJ3pevuvyAbtkGGxfNpy4ZLErAdp+axQP/+q4G81ZKPOioMBuDreJsxKf3uwmoQgfLms4eFM3QS664+ls6ej7tXp8dpL5xrcywSHUYDjYYPdsr24XlICPiOfHMIiY1SI0ya4IE9joytSpPrdc52dCV25MPSYiAqxIA62UAO7SFy0onpcxZju75vCpyzb9o3IFq/HM2CJtz+r7T440aVcbMTQtUk6ObVVBF1TfKLwVqZiSk8cXAIuSS9ML/ji4Uaka0JiNZ9uwiN4QuQw==" },
            new[] { "70", "msft:rm/algorithm/pkey/986",
                "5AEAAAkAAAD4J5KsxHwxARAAAAAfAAAAPgAAAAoAAAAUAAAAeez2ZvpTFN5FX5W84ANpVGRPkEADkxEJLTjwT0hWkZpJMhTx2IDkVB6mJHM5dpXCz6lDX9XPxOfZBDSX+H61ygEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAMHg7UXnyLSKI1JO/AjASL04je906UJa4bqoEE6FRHWTonJna1zqYfS2EkyCFewIPHgB75vAgyienBEr7AcNRsXkSIvZIz5Kq5gWwCRWIb5CdMzlcYdvpXqZ8xKODcjOdmyU9d3wCjtyaU2n5mPfzsTltswplUmQ04wQwlJRCyWnsycqnIarV1xPjxVhbZNuhib9aHjwuUtROt5ngn5Sa8Sucm7U7/wQGEA0MOL+TcfGS2GrhsLqmT2BiJbhmxQOScYlgDTfVFhSA3iFmxjBz3iy4/XFgY4yNcee5nz9a+lCie3tK7WZc1vZRE/Iyp9zMQR3n3EHWaw7C2HWxqZD+Cw==" },
            new[] { "71", "msft:rm/algorithm/pkey/986",
                "5AEAAAkAAABMssAtxHwxARAAAAAfAAAAPgAAAAoAAAAUAAAAYXNHdfrGEIDYsp/0FodBE21LGulZlm8qTElkzLJHVVLO56W3xZqFt+AwzOy9+33W8qg4b+DGdNK+B2sKCrbeywEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA0wHAapCHDeyugnF9bMPtAIVnT2DpyOBEMfrXSKhpHqUhIWzKuM2I2E+36IHa173DDPcXN9Qh8SvDBtQolQD8CP3VDXrIgyNCYQnhNf7QKVD994fs4J8qQNF8XqhZ6EigM0PeQUp9Dg3jHJjV6AptJc+iyYqL3HE5e+UNSD1tfqZ+TFD0M1QXoiPbGeOz5PgT7lrGpM5CJathl5SewmlrpWfoWb9lxTIk6q7ieVsOz1i7+5BTmCsRK5d69yDbRC+yqZWpWM3uCLIGkrnw8I7kBN6B9OtPV6VDG1dVcwtxPN/peFpz4RZhmH53CcgAZBiEWWjmhNxC/9In26rIfpO0mA==" },
            new[] { "80", "msft:rm/algorithm/pkey/986",
                "5AEAAAkAAADzSq/3xHwxARAAAAAfAAAAPgAAAAoAAAAUAAAAablon/OMshDwhB04kmVGajGKvQhHWyNh9zmRVyIshG3v+7ef22QPdcQsfjWMgYqsCf00jzH+ilgCwGP1REYb3wEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAM8ccKnXEXAVaXdqx6VBxJigmp6+9dX4aYQUXiXtJcpSgchwlewlhTlSeaCxz69el7yPbzbnwNr2Ts9lbNddWQ6KyQChJCkBUDyBo6cod+6apg0oDbMTsKoT0J5UwOFQeH8E+PVVUVSOQMoWyScOrmsL8O9JhRgWjifSrw2LgQIBl1ssH1WcuVgMvfCbFX02CgoyLH3rxqDuUDgfYNSvUPKjV2j98983FKeUOUZ3lQ0zAe+bSJxQR3aLaHBPbPAAco7rrgcQmphyAD+Np6eelUaF4iSNjo7ZYKP5yEduRtrhI6bxJ/d3Hf1kzjLKoEsUKjPPgxFzgkmo1lc1QkowbfQ==" },
            new[] { "81", "msft:rm/algorithm/pkey/986",
                "5AEAAAkAAADnr1TrxHwxARAAAAAfAAAAPgAAAAoAAAAUAAAAWZ3ITHFvQq4gTsBePJV2Ro3hI3H4To0//jEEBh3nNyndJHE0YbPa7PrpA8m1Z2MUja5AcI1FxM/BT5GNXcqT5AEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAxVs4Xi1it+oysPzFW+vZKuH/MfVNpvvZ31pYy7A7C43GkI2NEuVhiqDZpFWF+C8woVszRFYDomDePU/kUb1hPilo/1Se6SzZYhSZWgpQjSJfzgAfxrYJR/AUHD+V22suxSnkNfxYpduNydcqOyX3iKK4jVG0Uq4r7qU2btbyYyJPeE9UebKHZ29OFFbABS/EYR3dpiUxH1CtsGEPv3OKUuO7+8eEvB+ZR9zlFGYHN+VINf4yoh3w1ZOW4pzENE2ZHy8CdOurLiGzui8dxPinlPRbjO+MnY0YcVq5aqbFESCBQm5n4raX6UogXc5ox/oGrp3fz94+opQXmfZ8BHqZHg==" },
            new[] { "82", "msft:rm/algorithm/pkey/986",
                "5AEAAAkAAAD1VyIBxHwxARAAAAAfAAAAPgAAAAoAAAAUAAAAmaspMkhGR3RoNOcMRu7uiIrJjG+c2DSd7HOILvK3h9Gwv9f2LvW/xMRvmNApbuDWfLHSTsdVKAOt8aIyNuRUlwEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA7s8L6u8rNAeFkPKDlHVRRfw3m9yavyCYZ8cw+uHpqskLYj4kEPu8tk0+jgK2RtxuOkUawel5h9+mr8S7NpOJkciAjqd17huykqFyop7cZN+CkTKREtyrFqDHiPvDzxo5DBsXoDFtfMT18Gv2xOVnD1eDlpisOqEezK5S3rU3j0O6lwoLpQOYzM1PQL4mHPmiF3FLd2k5FuSmcV08jMkuNEswS47ehWL1w8tLXcr50aqrLwVA9lqVltHCX997RXd+zCsQvO4ihigtksGrJC8/u8Ea16SRH7F1mjSA6h4B0rqqkiBF0XEj04wfD8oYHQb8jIk6JO0d8EgdomaOCks2Yg==" },
            new[] { "83", "msft:rm/algorithm/pkey/986",
                "5AEAAAkAAAAwQTI+xHwxARAAAAAfAAAAPgAAAAoAAAAUAAAAQcecazpq/ICgxYnWHicJMBvLB5BRtZm2YlswyrfPiqaXoO/iIZeSuEaklEqUIVwfZyHzE/06y2qxVhGQX1oG1QEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA0mgRZlRJxhjQU9QYf2LT3VVJUtcOacthYokKej3+Ds1bGBLMzMj5aOAF0njNnJXyhnVc+kbdbeohgJPa27gGvm65knl2pO7oc2SWNyT5xwFNW0O6AmA9a54AHebZnNvgeLKINmJ9U/h/FVOicShegwR5ZQCakL8TUmMu6IN75CfoI9fdTlaMQiXGXaBEzFPeZwi7yy6z+LOqebfJBIAstCh3aagaR8JcfoFNMgVUoScqSYXvy267yTWM9SteAfkwlwUYF3lhN6Ye/j22tYnUW2mOKblD8tfgixXhs6DnZWgt2IDANFOuCIyfFLs3Dl2ihCm6zet/J+E14V3WjeKb1A==" },
            new[] { "84", "msft:rm/algorithm/pkey/986",
                "5AEAAAkAAADxgs20xHwxARAAAAAfAAAAPgAAAAoAAAAUAAAAaYDtrq4V5ViofrLFi83xpmRcpTatMRsgT6jFNY3Quzhe1ZVfq66KmKUtzmJPSPTEHX2jWu45RpIQNKR54tvZ7gEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAsyi3XLP2AueyF/5WulXYpEhW8Hv1KBmZUNt5qvefcalraP5ZCDEV7Y8yCR/esoHCkHHgTlZlVOiXADfbcdrfmRBtMqzinIjeN+DHjhrEyU1mcaNsn0lcY0zg/XbiaelWrDVG90KN7NtYE0GzTVXtzhn9l9FCYqeLTimAO494sOmYt/cdMP671lFbUk0W/fhCl28eWhQF/7vvToK31w9Kvp0OEqUhKJzH8IevNk/yCJ+NhMJ28fDe9JqYqBFEVHpdiMbZ6yy/uWkdefxnUe91ZSuWNpapdwyJEi8IufQpQ05OZ4MF2w0B0zsTUKoACgrvZtPO5/gal4y8OP1yybeebw==" },
            new[] { "85", "msft:rm/algorithm/pkey/986",
                "5AEAAAkAAADQEoojxHwxARAAAAAfAAAAPgAAAAoAAAAUAAAAKdOCmdCKL8+w13uVMjN4lbHZNQqkRuRsmsZ4/tUcS4PYPhmM14xzkKD99PhJXNYZ1koVm7qjNftMogGJSHX4xwEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA1xFJ5AOR4lpJ7AdxFkF9Yzh4BeZyKiZrK1NY9C8Q+xqQlQCHpAXktUqJ1iA576hGD5+m5Fz1uvkvtgt+4DkwdaTkV9xq0i1PU7AkIJc6P3Q0i5wwfxGdQAe7BNFFTiuJhxXOAxghci2aV5K8nK/W93zdCmKigYJledJmCqBHUhXmEJjIl1u6a352hlQ5jSo1GG7uujwqAxK9Sr3+/j7sjnlw18ZTKxkQQVSqk+/tYYvlzOVy6qiNCpJeOzLFxctYUrgfRdvCcZImaYGLUdK65tU6fOfIp4vbMrdkrK22py5TlNtCIJfnTqAIWiNyOYuUdwkXuf35L555PNaSMKnwwg==" },
            new[] { "86", "msft:rm/algorithm/pkey/986",
                "5AEAAAkAAABXZcXhxHwxARAAAAAfAAAAPgAAAAoAAAAUAAAAuf0g0wqnFO7aEx3YNGZBa/kat7/RXVJiz6bQhY2SbriBR+YsLeGjZHeX840DL2dWRRzvbGbtudaHk4VqG9tzwQEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAjNrcMmF2+3mip/iSahhJx5TxShGHzijSME2/k88mFxX7lLH0BaFON/zPqts7uOCxG6FeG5siEaAn1ZAkaXe2XuFOzRCgOrYJ0IQQ23NVzi36xguvd+XuMHZCZA2KBG3IrAbK4wvp+oraNHEkBhlU8upQ95KyGHlsBCrkxnic7X215YhBUY/VNxQ0Zksv6jbKaQLchn3ShCVv9x1dIGvKBXCs4LhPXoFVBwbXnSBBNpb/aQhIoWiOfCibxBD6YWQWsz1bVDkGZ4Ocqcc1cw+mSMCtEtehqIS6VJRw/U2KI8T8tCA8KFnGE5d9cCZXCl1qdMErgwWWjv+rAdqZ87zqMA==" },
            new[] { "87", "msft:rm/algorithm/pkey/986",
                "5AEAAAkAAADNzjP5xHwxARAAAAAfAAAAPgAAAAoAAAAUAAAAeUQ0vVnkcqjyJGUEBViQ5VPu/ExMCXF0mPHsvxbCTcF++jh5VipckRl9pUPE2ALEHb9bM+9pxaxVXStR8jwV5wEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAhSZxgO55EzGnJTeqL57C+RJFO2tTkX8f0/bwydAaVmYrXUhDJ34i153bsSYXN3CAgqIpmgrW0JeEkcOhApFe3Dg2ALoqpAmy4J6WpTZx0KUuSfHFnCWu/9qzqLv8HHB1JM9rQRhEHmh66CuO6xd8znpGjIf4uqQ7Kl+MbAShqXL1+cEg6Tbpb+MMKe76xqQE5WdFKoK9LrXMQ8ImQfdyYl4Gn0rejFoLvb/222fuhNIg8kh3asRhzijLQ48tqC/WVz80GYNDTLkEVXS75I+ZIOB4a+zTwyLWp/Xvh49E7c7F5Pm/It2VIBl0rlGfYYu8y9WlI9HnIiUV4YzusSj75Q==" },
            new[] { "88", "msft:rm/algorithm/pkey/986",
                "5AEAAAkAAAB6nAKexHwxARAAAAAfAAAAPgAAAAoAAAAUAAAA6VbFQ5G05y24wA5FQW9kKVxS1CIGmuAThR6X3jhlEi9hV29ViVHf2GwVXOUGR80dkaxusgsT0WNtRnejCEwCuwEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/9eTcMeyCQQgrUDCctHnfRH7w09YLvzEdP1hkmlbLxZgjjHzXgTjDH8alnpS7SAvniB3BmGykJ4ZTPRKqFnspm/iekb5uKufN/PMB7zquOcgnOEXo+BXq+WDhSaveyuEjTM5nRYeFQLrxsGGYr6DD9mpFUXCq5U29hHptZHm4FDQdkwtFNAxQi2lHfmXxdWArAP3xbZXABoC2ZhwJgnrr7CnPPqQOrvEwnlH+IR+jlssZqstjrqnPdoH0+ljX3IQQIk+WVES0T3EJzImACpNmC6OmRZFct6p7Rd8rh4gxqANG6CaPWAfNABG8szxYDnP/ulBYSsbOf2iJuTQEWLJhQ==" },
            new[] { "89", "msft:rm/algorithm/pkey/986",
                "5AEAAAkAAAANv6R0xHwxARAAAAAfAAAAPgAAAAoAAAAUAAAAoddW+tJsWWRE9SSL0BQeTsBmSJQOR1vGxqH+v5i0RTw+J1ac7jD8q8mzF5eoQTeUR/MdFegpY3EPz6wseGv2owEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA0gXApFIWu6rcobp+pUfDSR/KQX+DQJhS8+xz1n20RludwxJEgaFxGvMOAvNnUv8XHaKvqwiqaI72tRMM02QRGwYFhS7M4ezb28iF+OK/HcAPp4YpQpCJ9tXIpqGbCktKP7VmCCObmizZzCrUFiycvOzhfJeiRcD4CFousLhm2xG5gcABEc2omULeP+Pim5vs7OXlNzIOqTwu6Yx3Set2pIXGAU0AtD2PScYAPON+Away4/1OQHq0THKz+yCRsf9HtcOcoQa0exvPB99CmnBvgtkBR8oW2ujwgFX9uOAK4oGZRD5gszjeI1mCkuwlLB5I7/2e/pFMpnxwg1xjTgRjNA==" },
            new[] { "90", "msft:rm/algorithm/pkey/986",
                "5AEAAAkAAACLp8uMxHwxARAAAAAfAAAAPgAAAAoAAAAUAAAAeSOEflr+B+q7YTw8fowlknX9R33kU0Y6+vuVlsgZLmgMWme8ZACUJ0NzZIKb5RiBrRFBE5jeqgDhp/YZ7XquyQEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAApwZURzvOl7PE+oiNaRNmSXQQFvLuMsJr8AFYv3Tl3v4kL4lbzmBQvSVSXsGeepcf0ojcNzY85HhqRZufn+yshcSzMN+9WHJOlN8TlAylCxLXjSyUIrU9WW6hVqWBotuC0NMv9ztTZ2y4pqF2Zb4r4uBdaCgeT4s+5E9dP5jRt2YOjMlYVQTyzOQeZJigIB6OEbWFC364qYHvo7SnLVWfNwebShkQdbtFo3rsG9Pxqwtkuq6pKrWT26g2xYDZa7+QrsO07+cGvWygQ2d2yTj0qP78vDVksEzMoB4XDSUeCBV/7MttH4Xk6e/gaWOgS+4zz+KC1c1FKTZoONBY5tGHaw==" },
            new[] { "91", "msft:rm/algorithm/pkey/986",
                "5AEAAAkAAAD0HpqixHwxARAAAAAfAAAAPgAAAAoAAAAUAAAAweYzQxy2ur0WvtPRQy48ksz3EBdSVdUEKdZveuIwG1l+xPIWwCQdwpWBTKaHmFIM8LQTpNPCI/Dpbv7CLtXCpwEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAByOX1eprBjNA8GJYZradEy5BLzF7wC33xvSEM8LcccvckCM9L9ufRmKPBPW56KlpIift0a2TBMsCpaB7TGYcFnFqugLsZjlVqa7Zk+NZoJ5uGgrBdvAfe/oFNyrVn81ZMAuFxFiXSklQTjsS4CCbM9aOQXi1URgOh4KivERRDDim5FCZYQ/qPKfIhpmPnszKn+XtQT4zi3ZZAfbhluJtuzoaMXm5shrNpf7G3GokCnKa+GONK0+y0lLk8Pirq7NEUrn5bS7Sk5C35QV1YXlA2HHbByfe3Y9HYg4GapPkhVCIaD3Mmh5IzYzme4dYPw9mgcOv7XF3F96AQpgEZuATJw==" },
            new[] { "100", "msft:rm/algorithm/pkey/986",
                "5AEAAAkAAABG1nBhxHwxARAAAAAfAAAAPgAAAAoAAAAUAAAAidklegMUDR4wHgQIzZtVsn4t9gv0J+6/MidYk5sZRc3Rot6Qa5sxYox6FI9bxp5WkmINzw03HBIJ8h6gBJ201AEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAo/bTUfS+Coq66/BVcLI7NtObMnomNLRx9sMWIiv3N3AYEC9mpIUIR8A23MTVfUTBiUCqs8ItNBLO8gNa5iOKguIxys3gOnfXVbK4XxP1IpLMJmoVBtDHVgAFcbzXAvVmEDo1e/N+JAtdxe5P8ViM9oNAYpiyQxaeZsvJlTKCsCNfjmTuUikLupNiSBGD0/AMw8ebpfC4EHmW22nzT1kpGcdbSJYPA0f2qOmNzEufNcllnhRpYwnxMwg89hMFuf4lv2id9ri6UwKWBa3GkGpN1k4tILQCef8S8H9dMB2QmJIMsKB3+Ct7zH99hynjG8TmVONJzdOXXvCEVT6RwqKGoQ==" },
            new[] { "101", "msft:rm/algorithm/pkey/986",
                "5AEAAAkAAAArRZCpxHwxARAAAAAfAAAAPgAAAAoAAAAUAAAAoQRazl5havG2v/1Bj5N0N9KJrAMJsfeqizPyeeSB4B/SxMMbsFUE7LLuYMRe1N40PZSlZPiD94U2hsdold7+pgEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAqApOARa+/Pbo9P4z7bIAHPLeEA5BW5QR2U2eqTGJpCHRBMOFusHCc6Nx4TVJfIwsRjXzV4qPz6WUeGlEAuLPPPj2hYlRiXok4hbSs5aco/AUaxbIgEd0rb8OhRff6NNdIloF30j7ktp6pCMiIXoxgTLIaq6yMnVU9l6k1oNFP318T9L40U+9ql9+Ku24q+f1mnYjvWaey12TgcH6ipkOSJSBxBBi73pd5RsXO20//RL3lzDPC5dCzrPqrF2nyNMZrwUHNAqjMp+v4irV1JsJJqx2VSgLjAbK++WueA+16EWOEMuxCUyYN8MuO7ptzl3exjRH0g+gQ1TrG8WzzTihRw==" },
            new[] { "102", "msft:rm/algorithm/pkey/986",
                "5AEAAAkAAAA51F5jxHwxARAAAAAfAAAAPgAAAAoAAAAUAAAAuTMbker4VMwy3RRfk5UfMBUub5nox1futr2KPAvskXUYcF87gP2tk144Jukcqov/VcNuGQs0ZUMgOFuEZRSRjQEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAVYZ9Qpp2+dUEpuOjKq8QAhDdL+85pXzATHknFlt3y6Il96sWkQyrUn4Dyq1dPgBmw4Zm7+VtUOMSaYEvjXUfUSuxbFkdCcMoWjL+6nuqXCXoSDtxlwxuCBQqmFjNhpEDiutkJ7qXyTI6mZWO0hRLadcan+n0VyhS6las/JTDHi0uT97extdCReHRWAdKv7DlH7Z+p6lrw64T5wBQgT8x/CVhyFirIXkdUQk2/f+/cT2C1016oxiPBHxGhdx1t14wRysUdahpfqrVp62h0kpd74NTDLsP942t0hePp8HSp5HZrfSnpKOX8Ul1FfhQq8P5PT2Ta0KtYUoobVh8Sd55Ng==" },
            new[] { "103", "msft:rm/algorithm/pkey/986",
                "5AEAAAkAAAAH9Mp9xHwxARAAAAAfAAAAPgAAAAoAAAAUAAAAAX0Yrib0kgpckrFGCgYMYQ4E51iIdSS7ipOYj0ATHF8JTyXy83vA7R5WZBJ7wkuNbpe8Rg8QbwQTqlcjNChvnQEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAx3C6xi32YkciGNWksVp18yB/CGYP1kVqA9nAXkBzjY5gWeTvBQFPefiUSYsrUKwvRqRRzqbzez1l3bevJXrgiownh4NgE6G2LHF+6y7AOW2c0e5QI5dxXYhVFpXNBqGJRaX5VEnM9z1WPjl6L7CqaY+n4+wf3TXzs7Fqfqe6YUPiwtV/28PL6XgJ8nwRX+sFoMggWqeE1bFMIlshJK0DBeOP4lP5hzffMqj8FET9QE1jTspQ0J3agp1vKQQX/Slacya44JXVW7ugDe9z2D1uwoIbHb335FR/uqvl53x+REAsm3yJKun3oaVY56zGZ6m+vP0FDgq+iGBd4gYLgWE+HQ==" },
            new[] { "104", "msft:rm/algorithm/pkey/986",
                "5AEAAAkAAADrAFcIxHwxARAAAAAfAAAAPgAAAAoAAAAUAAAAiQO8sKcaqw8Jgp7T254pO9d+FDFcQD8ukdKmIpvFSWLhI8PPDjvD9YiaiKPBmVOyBZxNKkT8x/5EAjpeRvXn9AEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAiz2BAUGdToT/TVAWet44T3TP7mG9Rxp9M745lJzdr8aOTK5YDyYwF5xPk9ax/MVEh8U6Py81IGCwlMqSbEd6ZYIAYwzu4lCjDZulc9Q2INdKPFOXosPIYbpOx7okO5k3crg2uhjW8RYi+EbxN5RQ9vrJl9exCfUfmWE0+e1u2sZ4Y+6WG2MQMNgJz8dn0S/8qjoJP6HE5TVtzpLUG8P+Y1OxpbCSWdn7gioE38xljjgI/eMC7sD7FsJwAcJ2IMLl/1aAU5PYt/90Q7FhqjB5ija/Xh4nMmSs9yOOLNPT3YTAOUUSfhE8RUcMWFXjwSP77IQ9YSEN+hyU0fofRFEATQ==" },
            new[] { "105", "msft:rm/algorithm/pkey/986",
                "5AEAAAkAAADCtRZZxHwxARAAAAAfAAAAPgAAAAoAAAAUAAAAwbY6wdZ3NT2FFwq5/VVfEac0M6PJ/y74HSSuu0Q0H+LmZSnrhgj9jfgGl4RSIVMIJYDmlfpRAyq1NMNXAGYEoAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYpchFORz2cscPylvJjNPcQvHD8bs0DNQqqE8J+gblx+8QBQ4a7IJ+Fx5KKxx86kamhHNcf+z/vN0BlXcAV31iHCXfkL0xd7OSR4DUR2aGUngkY6T0FtdojDvqTmurbBdNL8ZM9E7o2OJJ7Zx1YBc7JH9CiAl9oTn3nM9JVXqXUb3N8yCwSJbKrxcOcmf3sHWtXvKHBE7InQM6rxo1KhzmGIGjM9sE3O8QzopOdHau3np6QxA0DxjrX20wcMcqCWSngPo+Deeb5mRPOlGFhQHZuulBLwUgM+pTPybpLTT3F52/qrMZNxMWvXX7ROxL18L6SpMQZzm465P9P66GkobKg==" },
            new[] { "106", "msft:rm/algorithm/pkey/986",
                "5AEAAAkAAAAwxgq+xHwxARAAAAAfAAAAPgAAAAoAAAAUAAAAWZeLdkteVWOCRBk/frAxkNBdmAd7RiDNN2QUirr83LG6W9ju6j5VSUD6IuKtcCJWFO5BBXi03XAV4PNQolG0tgEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA0ENnN2EQeQ5mJYrIGYBr789rOHG7oZDMqSF4n2u1L8uv/a+I/b0eSNpOkMZ8EUvLmw4O0A+L0txe7dOkKxJpNCgq655TJPqAY+S7C4D+PUpOXli5CWiTY9F3OB8/vugPLSSzbHnkuC8/1bgBnl34toXqhtBBXTxfo78NKptkd7DMTJ0GJRcrp7fvQqX1IvLjXB3LvsO8ZJ4KxutuytMwQ1DLGqfLt9psaTp/W1hpB0E5wghQd2OfQjmGI0AXhWBzWNjAxN2stIkKkl7lIwEK7+M0z/lxrGUtxkZVF5Uez7YrttlPOuIBw8Lkw3HIuWv/rB3pH7zwoE8I4lkENL85mw==" },
            new[] { "107", "msft:rm/algorithm/pkey/986",
                "5AEAAAkAAADFrkGkxHwxARAAAAAfAAAAPgAAAAoAAAAUAAAAcTnDpAvgNSCvjyjzFbQ7/gJNk3uVoKOAbeT+3vU46Qb6ljpMvaIamGWBUtW/rp9cWZLi7i4cy1martu4TOqqrwEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA11hNm2a9TeYtHBomoQvJ0sUKctNJBEAG+stqAMaDUTcVbc1Su8ZdisYz2V//DalIV7Ey+CKdV45KxGcTrq4cW2SYzab2IN7ScCOl4FEvml2eeENHIFL0izeoUkJz+zuqVLYZKJWKXb9ySDxfeqCQZN564ln75XTlRByci6cVriQtw70OWKGR8NBNYcGAjJVuPKr0XPsGuk79yBUlpMXxFk9atEByOyfHgG0UV3grNzNDQjHzrnoV+N8FKla7nTIPODvQJy+fWv8H2mkbf6EiKrscvSxP6QRi7qjV+u/xYfhStKl1J+r1AqgVtRONg8DlgXyF2eI4DQNOfggwXj0seg==" },
            new[] { "108", "msft:rm/algorithm/pkey/986",
                "5AEAAAkAAABVZPtKxHwxARAAAAAfAAAAPgAAAAoAAAAUAAAA0RptOUpOLbUKZkyvUEM0uD+Bkq6VdpNGmwBlhQC5xy8HvuyFte+Bpbee93MRI9ItlCaAK+L37jrGAx2Rkv9PgQEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAtYQpUdM0K6xccCyETZHeK/PkosJLNHzPsyBVana9XgJQvzcW79Bsib7gLCynLNXapsQN80csZKqaWkkGAZT7PE0lpTN4T2Ji6ZL6OIxPkWhNDkt2MK80ufrpTbUigTDG8xtLuS/IPv7+cWuffr6SdVObvZtGTS+fvdEW+jjEWF3P+cZrP3jsRJTKugf/TW/lc65OeiQLeg38m/nKWhlGn9l9UWANiMC3wDP7FVZDD8P5Zn/SZBJs+jGfhKshWyEF/79QU6dudQ+/52glvdZqCY42jKE39hsOinIN+0vom2V22ZRBl3Sfw9vj5MP8lnbaw8RvSEKSMvWp3qBp7ib4DA==" },
            new[] { "109", "msft:rm/algorithm/pkey/986",
                "5AEAAAkAAAAf+8WuxHwxARAAAAAfAAAAPgAAAAoAAAAUAAAAGQT9ovUFMSFmFz5AOkfgEu1OFVRfWxSjOqSiKvXXeH9/smEkkhUHpv9w/6m+f+ZWBbqW1ny6O3HPKnyRA3wO0QEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGL+6PliCeF6uQMAZ/Vvcjxlc9yGsrDjhW0tvvT39Ah+uPJDGSsq0iLSJsxkfoKyMTwRE7fl/I7OuSmx2b8b4PvDS1zmtMBgkI4ndZNI5ZW3wu+Ghn6Iy3TgfO2y2428y+NIfvYacXNTBaMrdNLXYT1q00Uu8+iqLZQTZmhhbmgxONciBvXAxYYHVxHeKXpocAU8kK+WPyya5knpJzTc7m7jscPHFQyQVTeU+AnSLvqRZHf143ex/5XkbBWIjSGR1P72mrCTgzQMUh29+BTZm0+NEEf5tCxwOop1ErOb1ESRUAiQSq//2BH3KCCJuCqD1UtrS6letUPyj2R5JgV8ZVQ==" },
            new[] { "110", "msft:rm/algorithm/pkey/986",
                "5AEAAAkAAAABZzyJxHwxARAAAAAfAAAAPgAAAAoAAAAUAAAAEb+dNu2wyzoorHP8pNiMFLuV7n6Aav/2GFjRyC5k+qT1YlJQeosZ7eE5zmXbnqAHFUGZELy4fg96BGUv6mf7jAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAflZZtYxoakLZ/1JrHWxOV6hE02xiVKjfrhAu2S2osd7lc/DkEdC8PER87SSPHez3XH6oHxyXbqVpoCJIvb8pePk7vGtzx6O/aTrBVET+88E3WWdlK5yvqZ2faLnv5yZgh14w1DstxQ0pPyCMCD+NJqgcRjGgcgNeqvDUrwyAbm/DgHLFqVRdZ3gWMiLLKR6RtanQBKC7NdMABrLgQQiXuXJOZS83F3ex0pNtI4tWEZ4ba/W+N6sqn6Mmr4AVjlOAx4bUVFVcBe1rg6iNjF20bciK24kNgLzeoMuJiaTVyIii+Y9+xQoYcxQKmp/KS5k/8p+51VLrJY22+HrxE7U/Jg==" },
            new[] { "111", "msft:rm/algorithm/pkey/986",
                "5AEAAAkAAAD6TyQbxHwxARAAAAAfAAAAPgAAAAoAAAAUAAAAqfVZoM72riB5pNzZY8UnyOGdTS6XRwyCA3meyjvQYWEt22StLnaYS2VGLX5GJMVz2wZzFku5E3cKS5knZNOL+QEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAmGxSTRTMooI6b/ogiauNu6jcaz0MlWk+e9aMyTfU6ZhQiIQLNFa9xmN9VbJKbOO6mcUPRwgTqhxnQJkkc39ve831NKNpJX72CMkjkGEOXLyz4oZuA75ifDOrb/NOhKYyt4EddMNqn7Z1PeD34fWF8GCA5GzeES+yaEwrjQz3KLvwtVVIgtsKb/KYgyM6an8gBxkGeIIw+DLeltt1ROPnA/aVRcPtcp+jUi/sOa3MPkKhsE5zNXISK34t5I8D5edERxMOG/GekncMr1yLF2KLE6iMQw9s17ObR1MbbeMDtEOpLk0dVXUCOWeY8tF3EevdePY2IqMaA61yX8+9ybj5Mw==" },
            new[] { "112", "msft:rm/algorithm/pkey/986",
                "5AEAAAkAAAAuxqTmxHwxARAAAAAfAAAAPgAAAAoAAAAUAAAAUa/y295Q4OrHAEfR31KQFsjAjfLFJVVY47Zjcat6AD1Xup8gxtiV6QnHMG12H7Bq0kGZ9IkDEYPlcZsrxPRa2QEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAiQqkCJr9C30Fb8sGWEg4jjNDqSbRER++pbID8akqSZi3jmf1QffUlOUw7jIjMfEcoYywN8zVfkl7EDPx1Y3nZoc7LZ/Se30QWOGHj35lQA34qYylWMTMIOjT14L8BZVu91RNJFylcIcAWaQnhjVhwOcrbXp4pf6H2mBELpVn6pfFrdLF9eq+0oP6t03Ddah8PyO4pqecdLI6QpsVuDpxiK/zAVKyn1TbU8Fije3Wk05vMTwveoxHGmpUs7ohq6dZPMiBCLqxLlN6gLIrr9b0svKHmulvX7AfkdevKtfnzs2Mvp4hf3M2qb1DJFd6BYGitSqxUubn5SpIBju8cqr1eA==" },
            new[] { "113", "msft:rm/algorithm/pkey/986",
                "5AEAAAkAAAB+9URMxHwxARAAAAAfAAAAPgAAAAoAAAAUAAAACQZ0PGjTgZnqvjaMlaHwseequqIYnhUxMgM+BtZ1scOF+UVgyn8mN4/XQvYe0FN1Tj9W0dSGwLySyfNdhdhKywEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAlFBuWR2u3D2tbF2nBZzohUYuNOFmkz8J/8+4y1pfU/RTV/As8FYGcvxeXzFeXvrYXzfaMNR+DIvItWe6/hdBH85nI5mABajQ30O0a/J6lSNeziwVQ2VDPsVedcvz5dIFyjvFBGePUYyPFCNKdW6usMOxCakktk/3hmAgobBUp6Hd/uJRv4w1zhdp+VIzc6SuDqjXaySmdU8gKgAUvyQTJGBSeyv0/wMK3LLJvhU9iNN/8cw4ozrbPaKbeCQhFdxUx246lpF05qjKtF6BI458NL36sXwPwtiikbu90ESBq3wCFCPtO22ab+Qt8DQL4aEZ12BadT5GHfszgPsl1hL0mg==" },
            new[] { "114", "msft:rm/algorithm/pkey/986",
                "5AEAAAkAAAALjX++xHwxARAAAAAfAAAAPgAAAAoAAAAUAAAA6T455WpTG/gfTYWhM3FOWvWYeGznSuDO53v2iK0OoW9iG/8cXKykyN4icKMCXA9XhudTIEySBtd1v9MxvQcJ3QEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAiIdAvVq+pKxWqDaYwCHBaFmzrl2NvVcrh+ZDvQHxgaRdyE2rwEqjuWkoYXYUzt9cdZROcnaJ5RRQz82c7r7TCaSkTX+Au4LfvRIC9wkgaJ12lEW5T+dp0BppruORVaQylmCLKZ683fDKQWhadoaRC7l8vpsvyvPMiFdK8mb7176lc5SF9bWQq147Cwy6I2xVdGvH35oABlyHepqMqoHyObVaiwzIK8+GvoMLfmXU9coYVJHahmepmYAP3j6SPWlCj8TAiEP1Zu3UHoMZHmnY3n8MRv2CiCKyMirqk7aMl2ZipotrJW8F/ZT4rtoSoC0HdLaVrS2rXw7OPvFhqp0ffA==" },
            new[] { "115", "msft:rm/algorithm/pkey/986",
                "5AEAAAkAAABdVe/1xHwxARAAAAAfAAAAPgAAAAoAAAAUAAAAAbQCiZe1kbHhv/w4lSY5tZyVv4VNiHEjJ288o7Mrud8hCCazoXvh04N3aQiuh3MdKag4EeAthu56CJJv5C9lsgEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAt/ILfZq2klRtOx4wvW/FQUUi0p+FIOAUt2Znww8DaKlP9cekEz2UwyFHmkS33qbl6eFPf4LTabYgSjCmd9oVjztLCsMLl+n5cUlAe3xG4jHpodu537RY++Sy7g8zRz9crgOcBPMpOhX/dLwxlGaWshsyE31/kvBp5FUdyaNgnxeRjLEnLAUgvDBajL6HtuDgExZw5iS5gHAc2tUEa+6Fe1Fnasvm9F6SLgqVpoPMiKJtlj5HRSVEMU1rNVfl3ZNA6d8+droCtoPmGoF9b5t8yzZs1Je9mU++F5d4zwnSSh89qNR+1zA6IojkVIoXVF0+X/cPbF5PGWUmYrJJ7uEaEw==" },
            new[] { "116", "msft:rm/algorithm/pkey/986",
                "5AEAAAkAAADWvd2RxHwxARAAAAAfAAAAPgAAAAoAAAAUAAAASXXSbspG+te2QKFOEJ9iiPrkZwRIK4eAzq++LDYsATxMnE4rgKJ9ABDeBjKxAAhc+bMbogLmt6Xql31ckoQciQEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAJHD0IwHN911SuF5yw7uhOr/V4+EOKR2emO+i3iGr6n3qFh8DXaUEH6qzVPbu9KTuykzVHXrTFmFehsqkpBbvCQw4VBAskkvolgGDm6DKKSjKk1pvSCdnGDFiOWo0nG/Whrng9aBTYKDILtCvzmhsm1s8gW22meOpUgQGY/hgAlf9aKw9fGs61p8noAUwrHy9m4n9WAmP+L2DSRLNy5Wqov1uolho7+nMVl/yHWXCR4wn+ly5kBi9kIMurUrKImIhzpsLXsvAGTOohWcW5JqR1QWEd/pWGtTSog1WxChwdSW4ON6WR/VyzcpxwwN0Xph46GxlbypBuaPptZ90CUoAgg==" },
            new[] { "117", "msft:rm/algorithm/pkey/986",
                "5AEAAAkAAAD62yoHxHwxARAAAAAfAAAAPgAAAAoAAAAUAAAAqWQ++2LPrFvxIrz9qTIBvvZKUJFwJaXSTux77gdgnlvizE9EyxCvjmVgRLuGQ0YeRvIKw0ZCHmoMeSq+I43asgEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAT1Zqs7Zf3Wcz7jE92N2BFwKW5+RBMv0y0bnvQpJXuXA25KIAEsX7XwChOah+7kiJxnOeLuClh2nGNeqxGwTPSxHFvxUWpNQY7vi+A+jLMy4P7LCff+AE3I3ajLNta0L9P/cPr4BVP0NKa6m/V6fGt3ZApPbhDF6AqC+lq/mzD2oYk6vesoXTY9mjFTaBQdyYMrUvU4KpU2afQZrXuUqUFgf52g8L1VW2BC2falJVFs8UZtM9QFYBZxPKjA+UTiFTyNjgKB0IJP//hMfsmsKzEqaocddC+1EQu5v+D/YL7BbhmR57Q3MZKAO8JiUTB5CJl1qGkOrAaGkLRMskxjbDnQ==" },
            new[] { "118", "msft:rm/algorithm/pkey/986",
                "5AEAAAkAAACZNALjxHwxARAAAAAfAAAAPgAAAAoAAAAUAAAAGVuhwc3z36yy3HLvGCLAH8TtO7fuPqF+ZlXMvcABhevFmo803/80W7bLIUlZUjX608gUqeInih+jq1GxZYal8gEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAf2NA4paXOLT262MsiEIlIcPP0W2pGhw6E7dRhHhJN66qb9vnU7uwHJwwXWCx2LUKo6onqX4Cdd8s69PnNYrLeK/eUAxiQV4cFCNbxKTIjI9cFx5/kgT00+hEOwyzJuALFNxNV1H4lrGSrU38ghn4m2yUeamIeAiOnI6r8RWlchSaM1maWHGXxV6wmv1lyvSq+/66jYxkEpg0mV986f1HOS8fw5CB05yMSRmZv+7Y0lS3sT2WCF0J2ryMUKc1/S53aGmuz/Q97iv7tZeIC2cH73O3Ue98swLgIlP9YVofN5SnJ5BSH8QSoYbDb21L8kGjn6sA3XbMr36BVTQcghvORw==" },
            new[] { "119", "msft:rm/algorithm/pkey/986",
                "5AEAAAkAAAAfC013xHwxARAAAAAfAAAAPgAAAAoAAAAUAAAAKelGcnpRWvRNUbWZQlz0GofBM/gUuoRbYpYWC+34BV4zO7nMsBmfzx1dNIUTnIeTxKXhv4mlgxBWNdMG0SP9gQEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAhpR4bd+5Dvtl1uB84Q8DkIqQ/6meazQtwjDARCBgiZkufBwFy7oko9FxdRImrCmWZx4sTNftX/rQuRaiqYGzQU6dF8RnX03sVrFamy9l3G0Is7G9YxgaU2kjIa8Vt/rTn+cUSw/gRv49/pXMTgqbWoFK0I7ffB9x2sP62pbeFGMpOatP8B+wmWypsEbe0AnAJjvo2TklnxeebG2RS+zXSy5vcSZ4gPCBgEyzuFkblvthiIOVvo/FLGOQfMei5UNI9sSGcPUARfdMuLhMOykS5Q36ILBh2bA1Zknd8Bcy1AYx5cFrW488oPagE3V/lzoVlW6eWYMNgGJa0CAXW9yqMA==" },
            new[] { "120", "msft:rm/algorithm/pkey/986",
                "5AEAAAkAAAALdzB6xHwxARAAAAAfAAAAPgAAAAoAAAAUAAAAQeUuwj/ml7v5lwcB46r6beBH68ezN+8gfuaWznRIilCSN8DaKjiL8ZtZarKP3XtnwAjQ/J9pmefY1KAdjopW2wEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADr4D1y8wl4xwOl0EeEnA1xbEKokG4LUACi2C3bwn5Q3LmFd0FaMjhsBEKDr6C+ZoROY46arq1cH1KMxdqaxBdOZOPIxBfS0okTRkdy4lRSHJ18mJUhrzDM8Nysg+1Hppcr0gt1y0fa4XH3W9DRDZpNthuhklPwd0w1IVstqe53o8TwAzREvqsV/+Dbh/GGLFgXrMZApi/L0bz0CVO0ZULOJf6d0hYAOj+Thr3covouqHQT2z5s/DiWUfN8FUmymCgfNLwJGxGEXLEvi0q/KjMYLSzLk6k95afh+UTBXF15Mma1YwMyOOgpC5PWmbJiePKFuJ1WRNRPy1GnXsm0knCQ==" },
            new[] { "121", "msft:rm/algorithm/pkey/986",
                "5AEAAAkAAAC9o61axHwxARAAAAAfAAAAPgAAAAoAAAAUAAAAMTHGb1sckLUgTS+EKl2Du9PT6EzcGWxhOX9nXeie+2s7dSsypT5tAIlT64pHQSivveMrKdrnxMoY6FXjAVhYvwEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA3EAkuD0wMHd5hQH+lN8W3QkhiW1jU+DV+ClFZbq+fR9WZaXCtShef0dXkkuVMTgBckHS8b+qpjUeI/wrq+qUT2xAvMj9qXpUxPUraGJN8bdvBZiYNbqy5wFk0Yh7yZ/EAR40LKoHfG186ExE5Xmlt5n1x6G+LWx8hG7u2zZinx/dSibHR2EmT1LbOJx4G6CrkzJdAfnIIvSn96HeAHTcbnOv+Sk+P79Q7soIot8Ppmqo+ozPnABmnrmowy40hK93uFRcCMNpWu3NySQ7m3RQcz9Pg6HPPRDCZ5G8Pia9F59HApaAlOz1iPyXpI5C6cQaugil26YqIvWTJZYItQxWVg==" },
            new[] { "124", "msft:rm/algorithm/pkey/986",
                "5AEAAAkAAABRfQcexHwxARAAAAAfAAAAPgAAAAoAAAAUAAAAMR/8Tn44L434xYns61YEBg8r04h8TWHRPjCVwo8Eufk9CRCaKRIIucxEbzvebR2JFwQWQavHQ5vUbDyQ1PM/8wEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGaeOIG9dQHXzN/jRS57Dxc1hxEZUrdMdMWTpvRZnnC47jb2mDgorBfZNMuC9825I0PzILbTHSnR5PexJEYN/8M6piHTNx1iWKR/7YF3Atr6kvlIvZHDKkNCGYMWqo3xaJaOfX0GBGc38bBeItZHAg+/PTeTYclQOwTMwLzJc8E1b37ApTfpYeix8bLgltgbGiOW30SWKl43VtW1HcHbqt++VJPxlojcxXaxmRrh3Al0rxjCw2GCOGqLGBH9IWJ9PRNoAz54RcgRpxgJiXiAtH9GOhxQyAqMfJXWCfq2r0tDDSmt6yvpmdj98WOzj+VNVdw5OQ0uHyT6WDa3XnAXJUQ==" },
            new[] { "125", "msft:rm/algorithm/pkey/986",
                "5AEAAAkAAABUMyYWxHwxARAAAAAfAAAAPgAAAAoAAAAUAAAAqUZZuq8ZO4bebPGxG9PEdJO2QFOPe/NPyi290yvzVLtEnCwJ2Gj1Eh6jHzFxt3LZs21jRm1PzlBJ+xl4CAmY3QEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAsHMLCPndUF/06OkSjGKxa20jr/Jkk7odZePIddqs2xzc+3teZ/FKEzfdZzAUROz0yDCP4CzEwzj0oXWCQyZeHlyNC8xjntR0CzbZuTb+a5zIPWXsr71FitGScK5d5dQ5bKqxZGF05fvbEHNsCiWpx5XVpj47HEB03D6aknQ16tvGh5A71J8effhz3DwGCurFjZgkjxXvnI7MsBXRYVEwbznqBVbh+cK3rSvLdUSyTmh+JMZEnaaRVhGdXJo+xU6IumiayktmEOKmbNcgCyAn4/M324JrKZo42Hs7NzOkb6r0GvCI5me69F9w6BCSegLBuFkFix87z00tQJ+euLvM3A==" },
            new[] { "126", "msft:rm/algorithm/pkey/986",
                "5AEAAAkAAADeOJSgxHwxARAAAAAfAAAAPgAAAAoAAAAUAAAASZBNRF5TG709KLkNdZN00dV2NGpYXhh+dLiiAm4miWbXliLujsQAEjY1lzEzdWtf9YOY1RRIEilu/g/SGh8prQEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA7xO5IR//Pn8uS6W7J7AZZiVZxNmpK+5OTpiZ/IAiKybecaPelc/gjOwq7aUbELaoCXIO8pyX+vvTPUX6vvMTHi54KDez5/d/C1lAnLI+3ullr/0PZ2g7otWwDpcJaNw6JA9/OizSN2g5x+i60ftPjbxOI/wCWR3jha0Cc7vd+X5gubVOVkKcLZ6GM5MHSCbQ3x8FMhJU/fNYDmEE9MIbaZE8CB2hXi5nr4bsZCqbThzGZjByWWJ+G7vNwxFJMaOAis7Z9aPBKue/OMM0vrAlgprnXPJBvnox3Tg9nOLa6ficZlyP5/FIpYQunu9lsQnUyjkblwfmbXMkc7BsZGyzew==" },
            new[] { "127", "msft:rm/algorithm/pkey/986",
                "5AEAAAkAAAB0QK3ZxHwxARAAAAAfAAAAPgAAAAoAAAAUAAAAgc3nV2T0XmbCXIxPezpHbzUUyClwU/vvtMxV6w4sd76QSbqMsvhx/CmS1QNJmFyh0hcLAzNvRFN4cMzfxKIJ3gEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA5yhVm/aJ6Z3PLDAk9APlfFyISNoq/ND1NGiNWKzqH07wFpk+/Ljv7R7RKYhdj4dVyPqOyS/9r1D25IaOCkoXzWCjgoO/bYeZWNFiy2aggPWcbyR1VOx5IwojtJ/Oh4Q4fQlsMANf3yAe6XMELJLRBBZrLhL4+trUIRT72t5yK9slW8YU+G2SINGhBdCthQcpfoZ9zz5GEpXsZX7MSGHM8zNv9H0k9K3CbyhXRToemsy+J5gys1nFyySVsoa0z+jF6wxWA/foFh4jg8VCSlJ2M6CEAnaMAtj2pZCS6wBS+sP5befxoPmYZpf2q+mWlP0jOSe00t61LzOI1P4zmCRRRQ==" },
            new[] { "128", "msft:rm/algorithm/pkey/986",
                "5AEAAAkAAAC/+STKxHwxARAAAAAfAAAAPgAAAAoAAAAUAAAAeR+GYQWMUhJWVR5VgPQ/W2ewhvWnvkVksjCpIfHgb71LQyObTMGrTbNWUk3lgj06gj9J+ocReLg6rBWviOmNxQEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA4msPmB203hUgItiOi2ZX/U7JJywp0UZIgflwQ+NaWRBnxwlDojE2b2tnS9c6iiSoV2G38HioiP3GI0DoKyPUo0TPjNjSA8oKEzJRUWsbjAEdu74tQ7r5T1DbJN2TiVd3l2jDnc1VlqzGf17exaren+hFmoaMEBoK2eogQxi+dJrhoeGB2IwNhFW6xL2ww8CJOsNOQrwxn5RObSOGxKpfyxY12deueHO8sOLvTwDjVKU44wp/jyPiPnRVPIzaqmwzfK5t2v6JtE2ou5GUPa7uInnEKeyPrd9dEWiS1Td8wKe8KNFcefgOcPAp1NQjacBFHv3tSu7UJ/3nB8BErtrNuQ==" },
            new[] { "129", "msft:rm/algorithm/pkey/986",
                "5AEAAAkAAACmBzpixHwxARAAAAAfAAAAPgAAAAoAAAAUAAAAQdFc9kOVuiAP5DmAEwELZyvXxSrzuVlQ5h2hRHlndKU5KKMFPUT6Qjhp7SPb7GLtNe72cL7UvXIwW9L7lFsXqAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAI33BqrOtkRqBsTM0ybSHuD2N9dxHjxB+NN1yuGWL0xraB57z5aixVOBtAqKkqi6I8vXD/QlufTQDx86RIgIEjtyb7XvQ1uzoskxXKwed/Sc+x8PkwSU4lUY+z+EEaQwrYwSgVS5OuftZ3C11jtWVlCOBd/yveMYbIJtIl9pmB5seAEUWkdIrCSN4RO/W+PVHOqFikrCEQP9gwTuRxN98NK9l9uqvhQfqqlL5st3kpKzyFToADWLgAGSg+BtgIElyzpi1iulRoqJN+Jr7dkNaNU0XhIwLaRczKntWKhIHW6T3GmxR63N9TShOULsyVW3STvpyMbRu+C0BL+CBfYNIYQ==" },
            new[] { "130", "msft:rm/algorithm/pkey/986",
                "5AEAAAkAAABhizm1xHwxARAAAAAfAAAAPgAAAAoAAAAUAAAAUb0q3ITEukHv9okJKkpu3dWfMlKquRGy/RUsB4ATUWyQISXajjxv44LWlh4kTnkJgP0uJ/Lo4qV3hZy1Ae9QiwEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIpiBgB1qrZxh9YYbZ3y3EVh9BLjTGTICutYpRBPhEKB1Id1lZsbsSYjENw4+80ewonAkVu/OwZmAJZUgW9HQYx/So1HCoafCXIW7a73qToPMa7j2WGqJ5yjaPUTmBbrKIypyBlg/GxqgjU6ovD3lVcjKpZ60mGMhHwlsZVOX+hVrveS8C1NTugADuGsXANWewJIX3boipAXINVJnHFhx5z5lx13aPvM0pEn3Jm4LjLclqadPahP9gaetYLHhimFeSSMsRKUTKxV/T54FnkveN5BZYOi093SBEDnDbWYOooGEtU9bxU1RmoCSDtoG0LaRmyjoQvswNiR1tQWEAkGagA==" },
            new[] { "131", "msft:rm/algorithm/pkey/986",
                "5AEAAAkAAAD0hSt+xHwxARAAAAAfAAAAPgAAAAoAAAAUAAAAue02WVy2VotDyT/54/wz+iEGpTYTMKUEyZBVWV4dZjcDOFMNHTZY1IQkaLeUuFGXV1ZM4o9tko/x2C0/7ICk4gEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAqYdIgzQxG2n8NeAECV4toG/WiFEZjPBLnq0QuDo0x9ro1XS+iOTs4sSZt9RSa7dCW65z+BFNL619Mw6phAu9bFAnSf79kkfDfieKuZtvAuNIj1GjhRt8xxKJA7KODkvC8PoPi/pmdEhJzHUZnfGmxPFLYP0+5yYgKP8aHozEWVsv2S4gB+OrlFJ735rY5AGuAeRiRCKdSDU+S9eIOOxcrS5kO9XSAAYpnqpYvqdI0rClOkRezmII2icCkVWTGbRuqvy9v0iFtXJ8U3k0gJgxZBEobBTMEqlVdiziHhiz1IgOXLmrSg7FzOkYk/9fqK+gtPLcgkJfbO/05xofNTkDvg==" },
            new[] { "132", "msft:rm/algorithm/pkey/986",
                "5AEAAAkAAACKPSRPxHwxARAAAAAfAAAAPgAAAAoAAAAUAAAAye50vyxoFbWMLflB7+I1lWuKlGXcMrnlqrl79Pfbh4QtvAaHTw8qYSnKteDwOoYzLP6uL5OmTd4imUmo0Cp9ogEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQrmLv5ZNMqDVfkmtbKFNBqPOwkRcYjgkFPkRshOqahjNyBtruQUfFZzNV3G3fF05f5VZePTMTPrrjwEKDs4qareLIqcoYJ/Z/RV3E1NVS6SKEzHVPXQuWJ2pXlDUgyrVMNm9OgGmqNvQ67uIxWxpO0ilI9gfT5FXcBtZJMr4r59H+yvz2JNIuazE4Y0lCU6UxDDK5+rFl6ikYqApaJ0RzyDGcLpJcOk4T3LPJ+cGTCLpZohEQ5Gla4yM47ihFXwe4SdhPcsFO/nFc7bwiQruHWgV8HkWXDOVXkVvQL7+OgqgeUuIzcUNthuiBHTCuXf+UiG0Mx4kMc5sgzOo7SpwgQ==" },
            new[] { "133", "msft:rm/algorithm/pkey/986",
                "5AEAAAkAAAApnieXxHwxARAAAAAfAAAAPgAAAAoAAAAUAAAA8W8IpR6IhUoDegsuNEQgcwQ7EuTsJrHcGLX/gVtzZUSlhnNB7V8fo8mhqE5uI8sSmfHp0QhJVTXLCBrRigO9pgEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQpiMadx3fc1XXUV/SU+bsjml8azJVFZXU8KdzFwmb1u/mc/sXirfLhOrrnd7OwNYvX5+fxtouSAipAAtyZpNjydBIpPaTGGE1jxI1XkYUQcuNc5SZ/8l17sPGvmBu/1qTVIFZs3wItAGMHKfkdQv9k3WdyS68+2ALf0Ze888GCBlIYIj4nz+HR1OGkT96JAUJ1drh2aFBwj/yFN+2XgGaF1WqyiyJhFKPQuPQ7DPAf2Gu0yqCdSxgH4y2sqa2CdQndxjrLB4KpX92NoDibkNS3eL2dqRu3zpMrs6ZeAiy6ZlD4drOTZXOJ2IR4OeT0R92qTTTXvLzJeY3PmdZLLXjA==" },
            new[] { "134", "msft:rm/algorithm/pkey/986",
                "5AEAAAkAAAAR1YIjxHwxARAAAAAfAAAAPgAAAAoAAAAUAAAAEfULs7XVaWsKSa+suZBtil21vUsPGlZ5bbO7u6bpoxNQ+PPSWtdDvxKAUeokspHsRpIY9baem/KqB9ZKwCkihAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAuFgn/gMmEZ/aIHjpNI3u+MHoqqGGoRYIVPaouN/fLUR0rRB/nMXEgkHhj6WqnNXq8bCz2FzzK8jHbnjNCfr+fwJaOKJjhR148Z2CV10PWs2OEIx3iALGgT9LJVNOzGNBW1G2q/nR84Qft2Prtt29orp2RaOnuG3KbXnLK52AxGSMZclVGhGVG8Vs8kN2cVSOcjtiGJrhBv0IrUwwx8IAr6pbDOSMsfHU+Ag+4cYWIW+rNNLLSTSHLNha7RAef2pCKxwGV0EmbSegdp9An5KW1SIhRaX1rdBpPkI+MCRb68rNRzs/O1qkeszT66aKmW2jizaD/j0UDV5lAxGX1qpqfA==" },
            new[] { "135", "msft:rm/algorithm/pkey/986",
                "5AEAAAkAAADRTVc2xHwxARAAAAAfAAAAPgAAAAoAAAAUAAAAISzp1mgs+peBDcwYkMQd/ycIfKg592vv2SEAuQeC5M9QMHCRoauQfXsSWLdCL7zeVDkJNqhiqPesv0HfBU8x5QEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAv68NZpsIU4PCCFenWD2JLirGZzN+a0fW/BatGpyGlCMap8Qk/Hcr7IITgIqLLUnAefWCJxeIbHpf7XzenDAlokoydJxVC25Je/9O2GZ9MUH5RNCo1erVTlfuJGFPZZgwqYQdOqvCzzNUClR9g8DKc+7FaCDhEyV+NtFvFmPgHa29Kc79OMFISpZXxSoMHASnzMFkNLyY2YHYNcejkGpU6kj3pq8iWxmqD+lBS8kvYHpi4PQNlz0CrcfQ04JMpUdux5Y0DRHXh+SOx/2tDCvKvRt+COk2wXd8S0r+kHt5Igc5WA8WoWrRzyEY0yiR5j32Q8EpDkr3OnGjjrbgujJX0A==" },
            new[] { "136", "msft:rm/algorithm/pkey/986",
                "5AEAAAkAAADY9ThixHwxARAAAAAfAAAAPgAAAAoAAAAUAAAAScC8QdtJmUHElzbXQ/aP+DZ/XXCtQyT+Fj5vQF7yZReER0ddn+Ov29+ToKy1jtpaOIgB8WhgBazSwcwTOSQLuAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAeLrQ03lak5lS+rHiZQUG076RWw9/E6T0d58yxeIvyxVsIQXbRhtuOPpy6GStDQHaPxvBNRY40yXXm7CpxEoYWMmL3gjOIZKGFnhUS7oPhgudFWGc7b7k8JFpV+YUsOxbxnzLUYw2xDzfe8MQ63opXGePS4kqyvPV8Y85asKTPEMSC5NAW0MVDdCCfI5yQ5DNfxSPk2cqeqBHrgN9bIXs8Yl+wKtH5OpnyBsR/9BKLs/BsCHblVwatY2Uc/0yzQ2uNWCjiVeVJUkx+OAcCfPU1RlSv2vPKtmVlwcgtGfaGSMdwOajw05yo5bw6/PBzyDR/puGmU/4PUy6xm1p2+21BQ==" },
            new[] { "137", "msft:rm/algorithm/pkey/986",
                "5AEAAAkAAACURehixHwxARAAAAAfAAAAPgAAAAoAAAAUAAAAgYKaCrc82m4I9bapnuIqb1lpjcvyXJLXXz0U5qqTZYKhgJWIOV31IqEDM5QkuuzfpuYDNrcEg/dGTA4KhvnkugEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA8GeI78Yx5OsHR2hJAoYfZAES7J+DmAgrat6F3w4bF8BIdXS30Wa/NNNujq4yjwIa6w7DhfrtX703YYPkdOcteLDjARK52wzAe3TjQaXo90YxS51ghKf9A/nK78k8HNW2juQs/m/Cmfidc3VRaaUWfg+D8bh4GGflcxIIjB6rLJalRJ9wlNQerCirS5TyOuPG8FxgBrKI8Fn+Ys1rmlOjLmrwEfdtI5FSF95AQa2zwDx04uMlqlZ0c3Khn16HSK+GqIgpbe50g3T4RVyfKS0LIU0mnymLkBAk+QtGuJdwX/s5BdXJ+CJOA6MIi/bh4HCAqyalyM1Vq3zCUdFy8R3jgw==" },
            new[] { "254", "msft:rm/algorithm/pkey/980",
                "bAEAAAcAAACYocmxrt8wAQwAAAAcAAAANwAAADEHywEeknQLHistB2jF/yHFXDK2RNsCCd4uxm21xNREb8cNuk7lCw+SsSIlq92GjQEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAANuGZ/tcjFNyDkmUl5QV/CUN3aHkoPDDF/aYzpwHMRC3cxZPkbv6Ad6eefJmWPV3RVXwqLgMLA8VxyjOgWlOVdXzidwRNAlAlFyq0GpaBo5ibl9+NURfBrKl6DwbTbjGXuDkpqyA74yZIwZw1mxiAbbeOwxeKpaeY1if3/GvXQK2hMFSH7y4DHI8G7RYUatzGWW7xrSyU+sXTELJws1/iA+4qsTKquCg4V/bbrgm+Y1K59se3Mff8DWI7B2+q6SNOQ==" },
            new[] { "255", "msft:rm/algorithm/pkey/980",
                "bAEAAAcAAADMHnlkrt8wAQwAAAAcAAAANwAAAPGJPrl/XslATw1kLJ4cW9dDs1FZJ4H7FoantZ2J21L2PpXJTHs0VAGrPBC5NUBkugEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADlNE97iyWi170VnlN4B3TVWMHvNvNWId+75XaGvq8Lf+GyMPc5NqydrzGR3i71xe92TBeXr8eB86DUNTjEiI0KvM59y2sl3punPrCbgt25QuzJxNTLCQd92JL7fSpD/LtwWAmzQhfXd8A3mAXUFdYc7tshRf2bNK1ILCeylSt8r8L0Ogy+pu95Dbk84E6NwLl5/8oSq/hJ9ThetejwFQJL4NJdDiJPxeOTp5kwt+c/4tTSMmFaNiZ009fq2ePpahQ==" }
        };

        // GroupId (= BINK ID in decimal) -> product names. Community list from UMSKT keys.json;
        // not verified against Microsoft data, and one BINK can belong to several products.
        static readonly System.Collections.Generic.Dictionary<int, string> ProductMap =
            new System.Collections.Generic.Dictionary<int, string>
        {
            { 0, "Windows CE Platform Builder 3; Windows CE .Net Platform Builder 4" },
            { 1, "Windows CE Platform Builder 3; Windows CE .Net Platform Builder 4" },
            { 2, "Windows 98 (all)" },
            { 3, "Windows 98 (all)" },
            { 4, "Office 2000" },
            { 5, "Office 2000" },
            { 6, "Internet Security and Acceleration (ISA) Server 2004" },
            { 7, "Internet Security and Acceleration (ISA) Server 2004" },
            { 8, "PLUS! for Windows XP" },
            { 9, "PLUS! for Windows XP" },
            { 10, "Windows 2000 Server (all)" },
            { 12, "Office Communicator 2007" },
            { 13, "Windows CE Platform Builder 3; Office Communicator 2007; Windows Embedded POSReady 2009; Windows CE .Net Platform Builder 5" },
            { 14, "Windows CE Platform Builder 3; Commerce Server 2002" },
            { 15, "Windows CE Platform Builder 3; Commerce Server 2002" },
            { 18, "Windows 2000 Professional" },
            { 19, "Windows 2000 Server (all); Windows 2000 Professional" },
            { 24, "Office for Mac 2004 / 2008" },
            { 25, "Office for Mac 2004 / 2008" },
            { 28, "Windows ME" },
            { 29, "Windows ME" },
            { 32, "Office XP Applications; Works Suite 2003 and 2004" },
            { 33, "Office XP Applications; Works Suite 2003 and 2004" },
            { 34, "Office XP" },
            { 35, "Office XP" },
            { 36, "Visual Studio .Net / .Net 2003" },
            { 37, "Visual Studio .Net / .Net 2003" },
            { 40, "Windows XP Professional Evaluation" },
            { 41, "Windows XP Professional Evaluation" },
            { 42, "Windows XP Home" },
            { 43, "Windows XP Home" },
            { 44, "Windows XP Pro; Windows XP Pro IA-64" },
            { 45, "Windows XP Pro; Windows XP Pro IA-64" },
            { 46, "Windows XP Pro VLK; Windows XP Fundamentals for Legacy PCs" },
            { 47, "Windows XP Pro VLK; Windows XP Fundamentals for Legacy PCs" },
            { 48, "Windows XP Professional K" },
            { 49, "Windows XP Professional K" },
            { 50, "Windows XP Starter Edition" },
            { 51, "Windows XP Starter Edition" },
            { 64, "Windows Longhorn (6.0.3683.0 -> 6.0.4029.0)" },
            { 65, "Windows Longhorn (6.0.3683.0 -> 6.0.4029.0)" },
            { 80, "Halo: Combat Evolved; Halo: Custom Edition" },
            { 81, "Halo: Combat Evolved; Halo: Custom Edition" },
            { 82, "Visual Studio 2005; Plus! Digital Media Edition for Windows XP; Rise of Nations - Rise of Legends" },
            { 83, "Visual Studio 2005; Plus! Digital Media Edition for Windows XP; Rise of Nations - Rise of Legends" },
            { 84, "Windows Longhorn (6.0.4033.0); Windows Server 2003" },
            { 85, "Windows Longhorn (6.0.4033.0); Windows Server 2003" },
            { 88, "Windows Server 2003" },
            { 89, "Windows Server 2003" },
            { 90, "Windows Server 2003 VLK" },
            { 91, "Windows Server 2003 VLK" },
            { 100, "Windows XP Pro 64 Bit Edition VLK" },
            { 101, "Windows XP Pro 64 Bit Edition VLK" },
            { 102, "Windows XP Pro 64 Bit Edition" },
            { 103, "Windows XP Pro 64 Bit Edition" },
            { 104, "Windows Server 2003 64 Bit; Windows Server 2003 64 Bit VLK" },
            { 105, "Windows Server 2003 64 Bit; Windows Server 2003 64 Bit VLK" },
            { 108, "Windows Server 2003 64 Bit; Windows Server 2003 64 Bit VLK" },
            { 109, "Windows Server 2003 64 Bit; Windows Server 2003 64 Bit VLK" },
            { 110, "Office 2003 Applications" },
            { 111, "Office 2003 Applications" },
            { 112, "Office 2003 Small Business; Office 2003 Student and Teacher" },
            { 113, "Office 2003 Small Business; Office 2003 Student and Teacher" },
            { 114, "Office 2003 Professional" },
            { 115, "Office 2003 Professional" },
            { 116, "Windows Longhorn (6.0.4039.0 -> Pre PIDGENX)" },
            { 117, "Windows Longhorn (6.0.4039.0 -> Pre PIDGENX)" },
            { 120, "Identity Lifecycle Manager 2007; Visual Studio 2008" },
            { 121, "Identity Lifecycle Manager 2007; Visual Studio 2008" },
            { 126, "Office 2007 Applications" },
            { 127, "Office 2007 Applications" },
            { 128, "Office 2007 Basic / Small Business" },
            { 129, "Office 2007 Basic / Small Business" },
            { 130, "Office 2007 Standard / Professional / Ultimate / Enterprise" },
            { 131, "Office 2007 Standard / Professional / Ultimate / Enterprise" },
            { 136, "Office 2007 Home & Student" },
            { 137, "Office 2007 Home & Student" },
        };

        /// <summary>Product names for a GroupId (decimal string), or "" if unknown.</summary>
        public static string ProductsFor(string groupId)
        {
            int g; string p;
            if (groupId != null && int.TryParse(groupId.Trim(), out g) && ProductMap.TryGetValue(g, out p)) return p;
            return "";
        }

        public static readonly string[] GroupIds;
        public static readonly string[] AlgorithmIds;
        public static readonly object[] Binks;          // byte[] each, decoded once

        static LegacyBuiltInBinks()
        {
            int n = Table.Length;
            GroupIds = new string[n];
            AlgorithmIds = new string[n];
            Binks = new object[n];
            for (int i = 0; i < n; i++)
            {
                GroupIds[i] = Table[i][0];
                AlgorithmIds[i] = Table[i][1];
                Binks[i] = Convert.FromBase64String(Table[i][2]);
            }
        }
    }
}
