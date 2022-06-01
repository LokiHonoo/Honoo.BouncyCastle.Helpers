using Honoo.BouncyCastle.Helpers;
using System;

namespace Test
{
    internal static class Pem
    {
        internal static void Test()
        {
            Console.WriteLine();
            Console.WriteLine("====  Pem Test  ========================================================================================================");
            Console.WriteLine();
            //
            Demo();
            //
            Console.WriteLine("\r\n\r\n\r\n");
        }

        private static void Demo()
        {
            PemTestObject obj = Certificate.Demo();
            //
            string keyPairPem1 = PemHelper.KeyPair2Pem(obj.KeyPair);
            string keyPairPem2 = PemHelper.KeyPair2Pem(obj.KeyPair, PemHelper.DEKAlgorithmNames.AES_128_CBC, "12345");
            string priKeyPem1 = PemHelper.Key2Pem(obj.KeyPair.Private);
            string priKeyPem2 = PemHelper.PrivateKey2Pem(obj.KeyPair.Private, PemHelper.DEKAlgorithmNames.AES_128_CBC, "12345");
            string pubKeyPem = PemHelper.Key2Pem(obj.KeyPair.Public);
            string certPem = PemHelper.Cert2Pem(obj.Cert);
            string crlPem = PemHelper.Crl2Pem(obj.Crl);
            string csrPem = PemHelper.Csr2Pem(obj.Csr);
            //
            var keyPair1 = PemHelper.Pem2KeyPair(keyPairPem1);
            var keyPair2 = PemHelper.Pem2KeyPair(keyPairPem2, "12345");
            var priKey1 = PemHelper.Pem2Key(priKeyPem1);
            var priKey2 = PemHelper.Pem2PrivateKey(priKeyPem2, "12345");
            var pubKey1 = PemHelper.Pem2Key(pubKeyPem);
            var cert = PemHelper.Pem2Cert(certPem);
            var crl = PemHelper.Pem2Crl(crlPem);
            var csr = PemHelper.Pem2Csr(csrPem);
            //
            byte[] priKeyRaw1 = RawHelper.Key2Raw(obj.KeyPair.Private);
            byte[] priKeyRaw2 = RawHelper.PrivateKey2Raw(obj.KeyPair.Private, RawHelper.PBEAlgorithmNames.PBEwithSHA_1andDES_CBC, "12345", new byte[] { 1, 1, 1 }, 12);
            byte[] pubKeyRaw1 = RawHelper.Key2Raw(obj.KeyPair.Public);
            //
            var priKey11 = RawHelper.Raw2Key(priKeyRaw1, true);
            var priKey22 = RawHelper.Raw2PrivateKey(priKeyRaw2, "12345");
            var pubKey11 = RawHelper.Raw2Key(pubKeyRaw1, false);
            //
            Console.WriteLine(keyPairPem1);
            Console.WriteLine(priKeyPem1);
            //
            Console.WriteLine(priKey2.Equals(priKey22));

            var pubKey44 = AsymmetricAlgorithmHelper.GeneratePublicKey(priKey11);
            Console.WriteLine(pubKey44.Equals(pubKey1));
        }
    }
}