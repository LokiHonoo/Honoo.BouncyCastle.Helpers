using Honoo.BouncyCastle.Helpers;
using Org.BouncyCastle.Crypto;
using System;

namespace Test
{
    internal class Pri2Pub
    {
        internal static void Test()
        {
            AsymmetricCipherKeyPair keyPair = AsymmetricAlgorithmHelper.RSA.GenerateKeyPair();
            AsymmetricAlgorithmHelper.TryGeneratePublicKey(keyPair.Private,out AsymmetricKeyParameter publicKey);
            Console.WriteLine(publicKey.Equals(keyPair.Public));
            //
            keyPair = AsymmetricAlgorithmHelper.ECDSA.GenerateKeyPair();
            AsymmetricAlgorithmHelper.TryGeneratePublicKey(keyPair.Private, out publicKey);
            Console.WriteLine(publicKey.Equals(keyPair.Public));
            //
            keyPair = AsymmetricAlgorithmHelper.DSA.GenerateKeyPair();
            AsymmetricAlgorithmHelper.TryGeneratePublicKey(keyPair.Private, out publicKey);
            Console.WriteLine(publicKey.Equals(keyPair.Public));
            //
            keyPair = AsymmetricAlgorithmHelper.SM2.GenerateKeyPair();
            AsymmetricAlgorithmHelper.TryGeneratePublicKey(keyPair.Private, out publicKey);
            Console.WriteLine(publicKey.Equals(keyPair.Public));
            //
            keyPair = AsymmetricAlgorithmHelper.ElGamal.GenerateKeyPair();
            AsymmetricAlgorithmHelper.TryGeneratePublicKey(keyPair.Private, out publicKey);
            Console.WriteLine(publicKey.Equals(keyPair.Public));
            //
            keyPair = AsymmetricAlgorithmHelper.GOST3410.GenerateKeyPair();
            AsymmetricAlgorithmHelper.TryGeneratePublicKey(keyPair.Private, out publicKey);
            Console.WriteLine(publicKey.Equals(keyPair.Public));
            //
            keyPair = AsymmetricAlgorithmHelper.ECGOST3410.GenerateKeyPair();
            AsymmetricAlgorithmHelper.TryGeneratePublicKey(keyPair.Private, out publicKey);
            Console.WriteLine(publicKey.Equals(keyPair.Public));
            //
            keyPair = AsymmetricAlgorithmHelper.Ed448.GenerateKeyPair();
            AsymmetricAlgorithmHelper.TryGeneratePublicKey(keyPair.Private, out publicKey);
            Console.WriteLine(publicKey.Equals(keyPair.Public));
            //
            //
            //
            Console.WriteLine("\r\n\r\n");
        }
    }
}