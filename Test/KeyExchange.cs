using Honoo.BouncyCastle.Helpers;
using System;
using System.Linq;
using System.Security.Cryptography;

namespace Test
{
    internal static class KeyExchange
    {
        internal static void Test()
        {
            Demo();
            Console.ReadKey(true);
        }

        private static void Demo()
        {
            // Alice work
            IKeyExchangeTerminalA keA = new ECDH().GetTerminalA();
            keA.GenerateParameters(384);
            byte[] p = keA.P;
            byte[] g = keA.G;
            byte[] publicKeyA = keA.PublicKeyA;

            // Bob work
            IKeyExchangeTerminalB keB = new ECDH().GetTerminalB();
            keB.GenerateParameters(p, g, publicKeyA);
            byte[] pmsB = keB.DeriveKeyMaterial(true);
            byte[] publicKeyB = keB.PublicKeyB;

            // Cracker work
            IKeyExchangeTerminalB keC = new ECDH().GetTerminalB();
            keC.GenerateParameters(p, g, publicKeyA);
            byte[] pmsC = keC.DeriveKeyMaterial(true);
            byte[] publicKeyC = keC.PublicKeyB;

            // Alice work
            byte[] pmsAB = keA.DeriveKeyMaterial(publicKeyB, true);
            byte[] pmsAC = keA.DeriveKeyMaterial(publicKeyC, true);

            //
            Console.WriteLine("    Alice-Bob pms:" + BitConverter.ToString(pmsAB).Replace("-", ""));
            Console.WriteLine("          Bob pms:" + BitConverter.ToString(pmsB).Replace("-", ""));
            Console.WriteLine();
            Console.WriteLine("Alice-Cracker pms:" + BitConverter.ToString(pmsAC).Replace("-", ""));
            Console.WriteLine("      Cracker pms:" + BitConverter.ToString(pmsC).Replace("-", ""));
        }
    }
}