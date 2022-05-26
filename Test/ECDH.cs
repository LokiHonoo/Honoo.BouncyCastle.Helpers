using Honoo.BouncyCastle.Helpers;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
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
            DHParameters parametersA = AsymmetricAlgorithmHelper.ECDH.GenerateParametersA(256, 25);
            AsymmetricCipherKeyPair keyPairA = AsymmetricAlgorithmHelper.ECDH.GenerateKeyPair(parametersA);
            string publicKeyAString = PemHelper.KeyToPem(keyPairA.Public);
            string p = parametersA.P.ToString();
            string g = parametersA.G.ToString();
            //
            // Bob work.
            //
            AsymmetricKeyParameter publicKeyA = PemHelper.PemToKey(publicKeyAString);
            Org.BouncyCastle.Math.BigInteger parametersAP = new Org.BouncyCastle.Math.BigInteger(p);
            Org.BouncyCastle.Math.BigInteger parametersAG = new Org.BouncyCastle.Math.BigInteger(g);
            DHParameters parametersB = AsymmetricAlgorithmHelper.ECDH.GenerateParametersB(parametersAP, parametersAG);
            AsymmetricCipherKeyPair keyPairB = AsymmetricAlgorithmHelper.ECDH.GenerateKeyPair(parametersB);
            IBasicAgreement agreementB = AsymmetricAlgorithmHelper.ECDH.GenerateAgreement(keyPairB.Private);
            byte[] pmsB = agreementB.CalculateAgreement(publicKeyA).ToByteArrayUnsigned();
            string publicKeyBString = PemHelper.KeyToPem(keyPairB.Public);
            //
            // Alice work.
            //
            AsymmetricKeyParameter publicKeyB = PemHelper.PemToKey(publicKeyBString);
            IBasicAgreement agreementA = AsymmetricAlgorithmHelper.ECDH.GenerateAgreement(keyPairA.Private);
            byte[] pmsA = agreementA.CalculateAgreement(publicKeyB).ToByteArrayUnsigned();
            //
            //
            //
            Console.WriteLine(BitConverter.ToString(pmsA).Replace("-", ""));
            Console.WriteLine(BitConverter.ToString(pmsB).Replace("-", ""));
        }
    }
}