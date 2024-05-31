using Honoo.BouncyCastle.Helpers;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Test
{
    internal class KeyGenerator
    {
        internal static void Test()
        {
            bool re = false;
            while (true)
            {
                Console.Clear();
                Console.WriteLine("========================================================================================================================");
                Console.WriteLine();
                Console.WriteLine("                             Honoo.BouncyCastle.Helpers        Runtime version " + Environment.Version);
                Console.WriteLine();
                Console.WriteLine("========================================================================================================================");
                Console.WriteLine();
                Console.WriteLine("  1. RSA 2048 Key");
                Console.WriteLine("  2. ECDSA Prime256v1 Key");
                Console.WriteLine("  3. Secure Random Bytes 128bit(16bytes)");
                Console.WriteLine();
                Console.WriteLine("  z. Return");
                Console.WriteLine();
                Console.WriteLine();
                Console.Write("Choice a project:");
                while (true)
                {
                    var kc = Console.ReadKey(true).KeyChar;
                    switch (kc)
                    {
                        case '1': Console.Clear(); RSA(); break;
                        case '2': Console.Clear(); ECDSA(); break;
                        case '3': Console.Clear(); RandomBytes(128); break;
                        case 'z': case 'Z': re = true; break;
                        default: continue;
                    }
                    break;
                }
                if (re)
                {
                    break;
                }
                else
                {
                    Console.ReadKey(true);
                }
            }
        }

        private static void ECDSA()
        {
            ECDSA alg = new ECDSA();
            string pem1 = alg.ExportPem(true);
            string pem2 = alg.ExportPem(false);

            Console.WriteLine(pem1);
            Console.WriteLine();
            Console.WriteLine(pem2);
        }

        private static void RandomBytes(int bit)
        {
            byte[] bytes = new byte[bit / 8];
            Console.WriteLine("+++++++++ 1 +++++++++");
            Common.Random.NextBytes(bytes);
            Console.WriteLine(BitConverter.ToString(bytes).Replace("-", ""));
            Console.WriteLine();
            Console.WriteLine("new byte[] { 0x" + BitConverter.ToString(bytes).Replace("-", ", 0x") + " };");
            Console.WriteLine();
            Console.WriteLine();
            Console.WriteLine("+++++++++ 2 +++++++++");
            Common.Random.NextBytes(bytes);
            Console.WriteLine(BitConverter.ToString(bytes).Replace("-", ""));
            Console.WriteLine();
            Console.WriteLine("new byte[] { 0x" + BitConverter.ToString(bytes).Replace("-", ", 0x") + " };");
        }

        private static void RSA()
        {
            RSA alg = new RSA();
            string pem1 = alg.ExportPem(true);
            string pem2 = alg.ExportPem(false);
            string xml1 = alg.ExportXml(true);
            string xml2 = alg.ExportXml(false);

            Console.WriteLine(pem1);
            Console.WriteLine();
            Console.WriteLine(pem2);
            Console.WriteLine();
            Console.WriteLine();
            Console.WriteLine(xml1);
            Console.WriteLine();
            Console.WriteLine(xml2);
        }
    }
}