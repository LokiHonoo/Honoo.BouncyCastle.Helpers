using Honoo.BouncyCastle.Helpers;
using System;

namespace Test
{
    internal static class ECDH
    {
        internal static void Test()
        {
            Console.WriteLine();
            Console.WriteLine("====  ECDH Test  =======================================================================================================");
            Console.WriteLine();
            //
            Demo1();
            //
            Console.WriteLine("\r\n\r\n");
        }

        private static void Demo1()
        {
            //
            // Alice work.
            //
            IECDHTerminalA terminalA = AsymmetricAlgorithms.ECDH.GenerateTerminalA(256);
            // Send to Bob.
            byte[] publicKeyA = terminalA.PublicKey;
            byte[] pA = terminalA.P;
            byte[] gA = terminalA.G;
            //
            // Bob work.
            //
            IECDHTerminalB terminalB = AsymmetricAlgorithms.ECDH.GenerateTerminalB(publicKeyA, pA, gA);
            byte[] pmsB = terminalB.DeriveKeyMaterial(true);
            // Send to Alice.
            byte[] publicKeyB = terminalB.PublicKey;
            //
            // Alice work.
            //
            byte[] pmsA = terminalA.DeriveKeyMaterial(publicKeyB, true);
            //
            //
            //
            Console.WriteLine(BitConverter.ToString(pmsA).Replace("-", "") + "  " + pmsA.Length + " bytes.");
            Console.WriteLine(BitConverter.ToString(pmsB).Replace("-", "") + "  " + pmsB.Length + " bytes.");
        }
    }
}