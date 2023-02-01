using Honoo.BouncyCastle.Helpers;
using Org.BouncyCastle.Crypto;
using System;

namespace Test
{
    internal class Pri2Pub
    {
        internal static void Test()
        {
            AsymmetricCipherKeyPair keyPair = AsymmetricAlgorithms.RSA.GenerateKeyPair();
            AsymmetricAlgorithmHelper.TryGeneratePublicKey(keyPair.Private, out AsymmetricKeyParameter publicKey);
            Console.WriteLine(publicKey.Equals(keyPair.Public));
            //
            keyPair = AsymmetricAlgorithms.ECDSA.GenerateKeyPair();
            AsymmetricAlgorithmHelper.TryGeneratePublicKey(keyPair.Private, out publicKey);
            Console.WriteLine(publicKey.Equals(keyPair.Public));
            //
            keyPair = AsymmetricAlgorithms.DSA.GenerateKeyPair();
            AsymmetricAlgorithmHelper.TryGeneratePublicKey(keyPair.Private, out publicKey);
            Console.WriteLine(publicKey.Equals(keyPair.Public));
            //
            keyPair = AsymmetricAlgorithms.SM2.GenerateKeyPair();
            AsymmetricAlgorithmHelper.TryGeneratePublicKey(keyPair.Private, out publicKey);
            Console.WriteLine(publicKey.Equals(keyPair.Public));
            //
            keyPair = AsymmetricAlgorithms.ElGamal.GenerateKeyPair();
            AsymmetricAlgorithmHelper.TryGeneratePublicKey(keyPair.Private, out publicKey);
            Console.WriteLine(publicKey.Equals(keyPair.Public));
            //
            keyPair = AsymmetricAlgorithms.GOST3410.GenerateKeyPair();
            AsymmetricAlgorithmHelper.TryGeneratePublicKey(keyPair.Private, out publicKey);
            Console.WriteLine(publicKey.Equals(keyPair.Public));
            //
            keyPair = AsymmetricAlgorithms.ECGOST3410.GenerateKeyPair();
            AsymmetricAlgorithmHelper.TryGeneratePublicKey(keyPair.Private, out publicKey);
            Console.WriteLine(publicKey.Equals(keyPair.Public));
            //
            keyPair = AsymmetricAlgorithms.Ed448.GenerateKeyPair();
            AsymmetricAlgorithmHelper.TryGeneratePublicKey(keyPair.Private, out publicKey);
            Console.WriteLine(publicKey.Equals(keyPair.Public));
            //
            //
            //
            Console.WriteLine("\r\n\r\n");
        }
    }
}