using Honoo.BouncyCastle.Helpers;
using Org.BouncyCastle.Crypto;
using System;

namespace Test
{
    internal class Temporaries
    {
        internal static void Test()
        {
            AsymmetricCipherKeyPair keyPair = AsymmetricAlgorithmHelper.RSA.GenerateKeyPair();
            AsymmetricKeyParameter pri = keyPair.Private;
            AsymmetricKeyParameter pub = AsymmetricAlgorithmHelper.GeneratePublicKey(pri);
            Console.WriteLine(pub.Equals(keyPair.Public));
            //
            keyPair = AsymmetricAlgorithmHelper.DSA.GenerateKeyPair();
            pri = keyPair.Private;
            pub = AsymmetricAlgorithmHelper.GeneratePublicKey(pri);
            Console.WriteLine(pub.Equals(keyPair.Public));
            //
            //
            //
            Console.WriteLine("\r\n\r\n");
        }
    }
}