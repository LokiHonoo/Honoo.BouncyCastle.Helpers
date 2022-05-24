using Honoo.BouncyCastle.Helpers;
using Org.BouncyCastle.Asn1.Bsi;
using Org.BouncyCastle.Asn1.CryptoPro;
using Org.BouncyCastle.Asn1.Eac;
using Org.BouncyCastle.Asn1.GM;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.TeleTrust;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using System;
using System.Collections.Generic;

namespace Test
{
    internal class Temporaries
    {
        internal static void Test()
        {
            if (SignatureAlgorithmHelper.TryGetOid("SHA512withSM2", out Org.BouncyCastle.Asn1.DerObjectIdentifier a))
            {
                Console.WriteLine(a.Id);
            }

            if (SignatureAlgorithmHelper.TryGetAlgorithm("SHA512withSM2", out var b))
            {
                byte[] test = Utilities.ScoopBytes(93);
                AsymmetricCipherKeyPair keyPair = b.AsymmetricAlgorithm.GenerateKeyPair();
                ISigner signer = b.GenerateSigner(keyPair.Private);
                ISigner verifier = b.GenerateSigner(keyPair.Public);
                signer.BlockUpdate(test, 0, test.Length);
                byte[] signature = signer.GenerateSignature();
                verifier.BlockUpdate(test, 0, test.Length);
                Console.WriteLine(verifier.VerifySignature(signature));
            }

            //
            Console.WriteLine("\r\n\r\n");


        }
    }
}