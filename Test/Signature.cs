using Honoo.BouncyCastle.Helpers;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Security;
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
            ////
            Test1();
            Console.WriteLine();
            Console.WriteLine();
            Test2();
            //
            Console.WriteLine("\r\n\r\n");
            Console.WriteLine("Total={0}  Ignore={1}  Diff={2}", _total, _total - _execute, _diff);
        }

        private static void Demo1()
        {
            byte[] test = Utilities.ScoopBytes(93);
            //AsymmetricCipherKeyPair keyPair = AsymmetricAlgorithmHelper.ECDSA.GenerateKeyPair();
            AsymmetricCipherKeyPair keyPair = SignatureAlgorithmHelper.SHA256withECDSA.AsymmetricAlgorithm.GenerateKeyPair();
            ISigner signer = SignatureAlgorithmHelper.SHA256withECDSA.GenerateSigner(keyPair.Private);
            ISigner verifier = SignatureAlgorithmHelper.SHA256withECDSA.GenerateSigner(keyPair.Public);
            signer.BlockUpdate(test, 0, test.Length);
            byte[] signature = signer.GenerateSignature();
            verifier.BlockUpdate(test, 0, test.Length);
            bool same = verifier.VerifySignature(signature);
        }

        private static void Test1()
        {
            byte[] test = Utilities.ScoopBytes(93);
            //
            Type type = typeof(SignatureAlgorithmHelper);
            PropertyInfo[] properties = type.GetProperties(BindingFlags.Static | BindingFlags.Public);
            foreach (PropertyInfo property in properties)
            {
                if (property.GetValue(type, null) is ISignatureAlgorithm algorithm)
                {
                    _total++;
                    AsymmetricCipherKeyPair keyPair = algorithm.AsymmetricAlgorithm.GenerateKeyPair();
                    ISigner signer = algorithm.GenerateSigner(keyPair.Private);
                    ISigner verifier = algorithm.GenerateSigner(keyPair.Public);
                    XTest(algorithm, signer, verifier, test);
                    _execute++;
                }
            }
            //
            List<string> names = new List<string>();
            names.AddRange(new string[] { "Ed25519ctx", "Ed448ph", "SHA3-256withRSA/ISO9796-2", "SHA1withRSA/X9.31" });
            names.AddRange(new string[] { "RIPEMD128WITHSM2", "RIPEMD160WITHSM2", "RIPEMD256WITHSM2", "RIPEMD256WITHSM2" });
            names.AddRange(new string[] { "SHA1WITHSM2", "SHA224WITHSM2", "SHA256WITHSM2", "SHA384WITHSM2", "SHA512WITHSM2" });
            foreach (string name in names)
            {
                _total++;
                _execute++;
                SignatureAlgorithmHelper.TryGetAlgorithm(name, out ISignatureAlgorithm algorithm);
                AsymmetricCipherKeyPair keyPair = algorithm.AsymmetricAlgorithm.GenerateKeyPair();
                ISigner signer = algorithm.GenerateSigner(keyPair.Private);
                ISigner verifier = algorithm.GenerateSigner(keyPair.Public);
                XTest(algorithm, signer, verifier, test);
            }
        }

        private static void Test2()
        {
            List<string> hashs = new List<string>();
            Type type = typeof(HashAlgorithmHelper);
            PropertyInfo[] properties = type.GetProperties(BindingFlags.Static | BindingFlags.Public);
            foreach (PropertyInfo property in properties)
            {
                if (property.GetValue(type, null) is IHashAlgorithm algorithm)
                {
                    hashs.Add(algorithm.Mechanism);
                }
            }
            List<string> algorithms = new List<string>();
            string[] suffixs = new string[] { "CVC-ECDSA", "PLAIN-ECDSA", "DSA", "RSA", "ECDSA", "ECGOST3410", "ECNR", "GOST3410", "RSA/X9.31", "ISO9796-2", "RSAANDMGF1", "SM2" };
            foreach (string suffix in suffixs)
            {
                foreach (string prefix in hashs)
                {
                    algorithms.Add(prefix + "with" + suffix);
                }
            }
            SecureRandom random = SecureRandom.GetInstance("MD5PRNG");
            var rsa = new Honoo.BouncyCastle.Helpers.Security.Crypto.Asymmetric.RSA(768, 8);
            var key = rsa.GenerateKeyPair().Private;
            DefaultSignatureAlgorithmIdentifierFinder finder = new DefaultSignatureAlgorithmIdentifierFinder();
            foreach (string algorithm in algorithms)
            {
                _total++;
                _execute++;
                string tag1 = "------------------------------- ";
                string tag2 = "x";
                string tag3 = "x";
                bool oidy = false;
                try
                {
                    var identifier = finder.Find(algorithm);
                    tag1 = identifier.Algorithm.Id;
                    oidy = true;
                }
                catch { }
                try
                {
                    _ = new Asn1SignatureFactory(algorithm, key, random);
                    tag2 = "X509 name availabled.";
                }
                catch { }
                if (oidy)
                {
                    try
                    {
                        _ = new Asn1SignatureFactory(tag1, key, random);
                        tag3 = "X509 oid availabled.";
                    }
                    catch { }
                }
                Console.WriteLine("{0}{1}{2}{3}", algorithm.PadRight(38), tag1.PadRight(32), tag2.PadRight(24), tag3);
            }
        }

        private static void XTest(ISignatureAlgorithm algorithm, ISigner signer, ISigner verifier, byte[] test)
        {
            signer.BlockUpdate(test, 0, test.Length);
            byte[] signature = signer.GenerateSignature();
            verifier.BlockUpdate(test, 0, test.Length);
            bool diff = !verifier.VerifySignature(signature);
            //
            string id = algorithm.Oid is null ? string.Empty : algorithm.Oid.Id;
            Console.Write("{0}{1}{2} ", algorithm.Mechanism.PadRight(32), signer.AlgorithmName.PadRight(32), id.PadRight(32));
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
    }
}