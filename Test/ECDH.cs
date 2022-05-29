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
            IECDHTerminalA terminalA = AsymmetricAlgorithmHelper.ECDH.GenerateTerminalA(256, 25);
            // Send exchangeA to Bob.
            byte[] exchangeToBob = terminalA.ExchangeA;
            //
            // Bob work.
            //
            IECDHTerminalB terminalB = AsymmetricAlgorithmHelper.ECDH.GenerateTerminalB(exchangeToBob);
            byte[] pmsB = terminalB.DeriveKeyMaterial();
            // Send exchangeB to Alice.
            byte[] exchangeToAlice = terminalB.ExchangeB;
            //
            // Alice work.
            //
            byte[] pmsA = terminalA.DeriveKeyMaterial(exchangeToAlice);
            //
            //
            //
            Console.WriteLine(BitConverter.ToString(pmsA).Replace("-", "") + "  " + pmsA.Length + " bytes.");
            Console.WriteLine(BitConverter.ToString(pmsB).Replace("-", "") + "  " + pmsB.Length + " bytes.");
        }
    }
}