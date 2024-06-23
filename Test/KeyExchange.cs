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

            // Alice work
            byte[] pmsA = keA.DeriveKeyMaterial(publicKeyB, true);

            //
            bool same = pmsA.SequenceEqual(pmsB);
            Console.WriteLine($"ECDH Alice pms same as Bob pms: {same}");
            Console.WriteLine("Alice   pms:" + BitConverter.ToString(pmsA).Replace("-", ""));
            Console.WriteLine("Bob     pms:" + BitConverter.ToString(pmsB).Replace("-", ""));
            Console.WriteLine("Cracker pms:" + BitConverter.ToString(pmsC).Replace("-", ""));
        }
    }
}