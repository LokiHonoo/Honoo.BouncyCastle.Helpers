using Honoo.BouncyCastle.Helpers;
using Org.BouncyCastle.Crypto;
using System;
using System.Collections.Generic;
using System.Reflection;

namespace Test
{
    internal static class Signature
    {
        private static int _diff = 0;
        private static int _execute = 0;
        private static int _total = 0;

        internal static void Test()
        {
            _total = 0;
            _execute = 0;
            _diff = 0;
            Console.WriteLine();
            Console.WriteLine("====  Signature Test  ==================================================================================================");
            Console.WriteLine();
            //
            Demo1();
            //
            Test1();
            //
            Console.WriteLine("\r\n\r\n");
            Console.WriteLine("Total={0}  Ignore={1}  Diff={2}", _total, _total - _execute, _diff);
        }

        private static void Demo1()
        {
            byte[] test = new byte[83];
            Utilities.Random.NextBytes(test);
            AsymmetricCipherKeyPair keyPair = SignatureAlgorithmHelper.SHA256withECDSA.GenerateKeyPair();
            // example 1
            byte[] signature1 = SignatureAlgorithmHelper.SHA256withECDSA.Sign(keyPair.Private, test);
            bool same1 = SignatureAlgorithmHelper.SHA256withECDSA.Verify(keyPair.Public, test, signature1);
            // example 2
            ISigner signer = SignatureAlgorithmHelper.SHA256withECDSA.GenerateSigner(keyPair.Private);
            ISigner verifier = SignatureAlgorithmHelper.SHA256withECDSA.GenerateVerifier(keyPair.Public);
            signer.BlockUpdate(test, 0, test.Length);
            byte[] signature2 = signer.GenerateSignature();
            verifier.BlockUpdate(test, 0, test.Length);
            bool same2 = verifier.VerifySignature(signature2);
        }

        private static void Test1()
        {
            byte[] test = new byte[83];
            Utilities.Random.NextBytes(test);
            //
            Type type = typeof(SignatureAlgorithmHelper);
            PropertyInfo[] properties = type.GetProperties(BindingFlags.Static | BindingFlags.Public);
            foreach (PropertyInfo property in properties)
            {
                if (property.GetValue(type, null) is ISignatureAlgorithm algorithm)
                {
                    _total++;
                    AsymmetricCipherKeyPair keyPair = algorithm.GenerateKeyPair();
                    ISigner signer = algorithm.GenerateSigner(keyPair.Private);
                    ISigner verifier = algorithm.GenerateVerifier(keyPair.Public);
                    XTest(algorithm, signer, verifier, test);
                    _execute++;
                }
            }
            //
            List<string> names = new List<string>();
            names.AddRange(new string[] { "ED25519", "ED25519CTX", "ED25519PH", "ED448", "ED448PH" });
            names.AddRange(new string[] { "SHA3-256withRSA/ISO9796-2", "SHA1withRSA/X9.31" });
            names.AddRange(new string[] { "RIPEMD128WITHSM2", "RIPEMD160WITHSM2", "RIPEMD256WITHSM2", "RIPEMD256WITHSM2" });
            foreach (string name in names)
            {
                _total++;
                _execute++;
                SignatureAlgorithmHelper.TryGetAlgorithm(name, out ISignatureAlgorithm algorithm);
                AsymmetricCipherKeyPair keyPair = algorithm.GenerateKeyPair();
                ISigner signer = algorithm.GenerateSigner(keyPair.Private);
                ISigner verifier = algorithm.GenerateVerifier(keyPair.Public);
                XTest(algorithm, signer, verifier, test);
            }
        }

        private static void XTest(ISignatureAlgorithm algorithm, ISigner signer, ISigner verifier, byte[] test)
        {
            string id = algorithm.Oid is null ? string.Empty : algorithm.Oid.Id;
            Console.Write("{0}{1}{2} ", algorithm.Name.PadRight(32), signer.AlgorithmName.PadRight(32), id.PadRight(32));
            try
            {
                signer.BlockUpdate(test, 0, test.Length);
                byte[] signature = signer.GenerateSignature();
                verifier.BlockUpdate(test, 0, test.Length);
                bool diff = !verifier.VerifySignature(signature);
                //
                if (diff)
                {
                    Console.ForegroundColor = ConsoleColor.Cyan;
                    Console.WriteLine("diff");
                    _diff++;
                    Console.ResetColor();
                }
                else
                {
                    Console.WriteLine("same");
                }
            }
            catch (Exception)
            {
                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.WriteLine("error");
                _diff++;
                Console.ResetColor();
            }
        }
    }
}