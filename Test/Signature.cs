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
        private static readonly byte[] _input = new byte[123];
        private static int _diff = 0;
        private static int _execute = 0;
        private static int _total = 0;

        internal static void Test()
        {
            Utilities.Random.NextBytes(_input);
            //
            _total = 0;
            _execute = 0;
            _diff = 0;
            Console.WriteLine();
            Console.WriteLine("====  Signature Test  ==================================================================================================");
            Console.WriteLine();
            //
            Demo1();
            Console.WriteLine();
            Console.WriteLine();
            //
            Test1();
            Console.WriteLine();
            Console.WriteLine();
            //
            Test2();
            //
            Console.WriteLine("\r\n\r\n");
            Console.WriteLine("Total={0}  Ignore={1}  Diff={2}", _total, _total - _execute, _diff);
        }

        private static void Demo1()
        {
            AsymmetricCipherKeyPair keyPair = SignatureAlgorithms.SHA256withECDSA.AsymmetricAlgorithm.GenerateKeyPair();
            // example 1
            byte[] signature = SignatureAlgorithms.SHA256withECDSA.Sign(keyPair.Private, _input);
            _ = SignatureAlgorithms.SHA256withECDSA.Verify(keyPair.Public, _input, signature);
            // example 2
            ISigner signer = SignatureAlgorithms.SHA256withECDSA.GenerateSigner(keyPair.Private);
            ISigner verifier = SignatureAlgorithms.SHA256withECDSA.GenerateVerifier(keyPair.Public);
            signer.BlockUpdate(_input, 0, _input.Length);
            signature = signer.GenerateSignature();
            verifier.BlockUpdate(_input, 0, _input.Length);
            _ = verifier.VerifySignature(signature);
        }

        private static void Test1()
        {
            Type type = typeof(SignatureAlgorithms);
            PropertyInfo[] properties = type.GetProperties(BindingFlags.Static | BindingFlags.Public);
            foreach (PropertyInfo property in properties)
            {
                if (property.GetValue(type, null) is ISignatureAlgorithm algorithm)
                {
                    _total++;
                    AsymmetricCipherKeyPair keyPair = algorithm.AsymmetricAlgorithm.GenerateKeyPair();
                    ISigner signer = algorithm.GenerateSigner(keyPair.Private);
                    ISigner verifier = algorithm.GenerateVerifier(keyPair.Public);
                    XTest(algorithm, signer, verifier, _input);
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
                AsymmetricCipherKeyPair keyPair = algorithm.AsymmetricAlgorithm.GenerateKeyPair();
                ISigner signer = algorithm.GenerateSigner(keyPair.Private);
                ISigner verifier = algorithm.GenerateVerifier(keyPair.Public);
                XTest(algorithm, signer, verifier, _input);
            }
        }

        private static void Test2()
        {
            List<string> hashs = new List<string>();
            Type type = typeof(HashAlgorithms);
            PropertyInfo[] properties = type.GetProperties(BindingFlags.Static | BindingFlags.Public);
            foreach (PropertyInfo property in properties)
            {
                if (property.GetValue(type, null) is IHashAlgorithm algorithm)
                {
                    hashs.Add(algorithm.Name);
                }
            }
            List<string> names = new List<string>();
            string[] suffixs = new string[] { "CVC-ECDSA", "PLAIN-ECDSA", "DSA", "RSA", "ECDSA", "ECGOST3410", "ECNR", "GOST3410", "RSA/X9.31", "ISO9796-2", "RSAANDMGF1", "SM2" };
            foreach (string suffix in suffixs)
            {
                foreach (string prefix in hashs)
                {
                    names.Add(prefix + "with" + suffix);
                }
            }
            SecureRandom random = SecureRandom.GetInstance("MD5PRNG");
            var key = AsymmetricAlgorithms.ECDSA.GenerateKeyPair().Private;
            DefaultSignatureAlgorithmIdentifierFinder finder = new DefaultSignatureAlgorithmIdentifierFinder();

            foreach (string name in names)
            {
                string tag1 = "----------------------- ";
                string tag2 = "-----------------------";
                string tag3 = "x";
                string tag4 = "x";
                bool oidy = false;
                if (SignatureAlgorithmHelper.TryGetAlgorithm(name, out ISignatureAlgorithm algorithm))
                {
                    if (algorithm.Oid != null)
                    {
                        tag1 = algorithm.Oid.Id;
                    }
                }
                try
                {
                    var identifier = finder.Find(name);
                    tag2 = identifier.Algorithm.Id;
                    oidy = true;
                }
                catch { }
                try
                {
                    _ = new Asn1SignatureFactory(name, key, random);
                    tag3 = "name ok.";
                }
                catch { }
                if (oidy)
                {
                    try
                    {
                        _ = new Asn1SignatureFactory(tag2, key, random);
                        tag4 = "oid ok.";
                    }
                    catch { }
                }
                Console.WriteLine("{0}{1}{2}{3}{4}", name.PadRight(38), tag1.PadRight(24), tag2.PadRight(24), tag3.PadRight(10), tag4);
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