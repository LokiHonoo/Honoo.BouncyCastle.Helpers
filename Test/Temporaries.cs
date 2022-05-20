using Honoo.BouncyCastle.Helpers;
using Org.BouncyCastle.Crypto;
using System.Collections.Generic;

namespace Test
{
    internal class Temporaries
    {
        internal static void Test()
        {
            byte[] test = Utilities.ScoopBytes(93);
            List<string> names = new List<string>();
            names.AddRange(new string[] { "RIPEMD320withRSA" });
            foreach (string name in names)
            {

                SignatureAlgorithmHelper.TryGetAlgorithm(name, out ISignatureAlgorithm algorithm);
                AsymmetricCipherKeyPair keyPair = algorithm.AsymmetricAlgorithm.GenerateKeyPair();
                ISigner signer = algorithm.GenerateSigner(keyPair.Private);
                ISigner verifier = algorithm.GenerateSigner(keyPair.Public);
                signer.BlockUpdate(test, 0, test.Length);
                byte[] signature = signer.GenerateSignature();
                verifier.BlockUpdate(test, 0, test.Length);
                bool diff = !verifier.VerifySignature(signature);
            }
        }
    }
}