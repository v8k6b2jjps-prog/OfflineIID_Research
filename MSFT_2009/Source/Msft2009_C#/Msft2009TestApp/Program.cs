using System;

namespace TestApp
{
    internal class Program
    {
        static void Main(string[] args)
        {
            // Key: W269N - WFGWX - YVC9B - 4J6C9 - T83GX
            // Integer: 6154343795018908688006397247360239
            // Group: 3311
            // Serial: 1
            // Security: 7792597778124621
            // Checksum: 606
            // Upgrade: 0
            // Extra: 0

            string val;
            int status = MSFT.GetInstallationIdString(3311, 1, 7792597778124621, -7066209111506718658, out val);

            if (status == 0)
            {
                Console.WriteLine($"Generated Installation ID: {val}");
            }
            else
            {
                Console.WriteLine($"Failed with error code: {status}");
            }

            DecodedParameters decodedParams;
            int decodeStatus = MSFT.ReadParametersFromString(val, out decodedParams);

            if (decodeStatus == 0)
            {
                Console.WriteLine("\n--- Successfully Decoded Back ---");
                Console.WriteLine($"Group ID:    {decodedParams.groupID}");
                Console.WriteLine($"Serial:      {decodedParams.serial}");
                Console.WriteLine($"Security ID: {decodedParams.securityID}");
                Console.WriteLine($"HWID:        {decodedParams.hwid}");

                // Capture the returned ulong from the search function
                ulong foundId = MSFT.FindSecurityIdLegacy(
                    val,
                    7792597778123000,
                    7792597778127000
                );

                Console.WriteLine($"\n--- Brute Force Result ---");
                if (foundId > 0)
                {
                    Console.WriteLine($"Found Security ID: {foundId}");
                }
                else
                {
                    Console.WriteLine("Security ID not found within the specified range.");
                }
            }
            else
            {
                Console.WriteLine($"Decoding failed with error: {decodeStatus}");
            }
        }
    }
}