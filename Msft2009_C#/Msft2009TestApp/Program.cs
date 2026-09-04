using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace TestApp
{
    internal class Program
    {
        static void Main(string[] args)
        {
            string val;
            int status = Msft2009.MSFT.GetInstallationIdString(5150, 80009470, 85828656449731L, -989889565665111, out val);

            if (status == 0)
            {
                Console.WriteLine($"Generated Installation ID: {val}");
            }
            else
            {
                Console.WriteLine($"Failed with error code: {status}");
            }

            DecodedParameters decodedParams;
            int decodeStatus = Msft2009.MSFT.ReadParametersFromString(val, out decodedParams);

            if (decodeStatus == 0)
            {
                Console.WriteLine("\n--- Successfully Decoded Back ---");
                Console.WriteLine($"Group ID:    {decodedParams.groupID}");
                Console.WriteLine($"Serial:      {decodedParams.serial}");
                Console.WriteLine($"Security ID: {decodedParams.securityID}");
                Console.WriteLine($"HWID:        {decodedParams.hwid}");
            }
            else
            {
                Console.WriteLine($"Decoding failed with error: {decodeStatus}");
            }
        }
    }
}