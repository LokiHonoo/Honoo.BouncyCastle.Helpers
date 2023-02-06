using Honoo.BouncyCastle.Helpers;
using Org.BouncyCastle.Crypto;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Globalization;
using System.Reflection;
using System.Security.Cryptography;

namespace Test
{
    internal static class Hash
    {
        private static int _diff = 0;
        private static int _execute = 0;
        private static readonly byte[] _input = new byte[123];
        private static int _total = 0;

        internal static void Test()
        {
            Utilities.Random.NextBytes(_input);
            //
            _total = 0;
            _execute = 0;
            _diff = 0;
            Console.WriteLine();
            Console.WriteLine("====  Hash Test  =======================================================================================================");
            Console.WriteLine();
            //
            Demo1();
            Demo2();
            Demo3();
            Demo4();
            ////
            Test1();
            Test2();
            Test3(false);
            Test3(true);
            Test4(false);
            Test4(true);
            //
            Console.WriteLine("\r\n\r\n");
            Console.WriteLine("Total={0}  Ignore={1}  Diff={2}", _total, _total - _execute, _diff);
        }

        private static void Demo1()
        {
            // example 1
            _ = HashAlgorithms.SHA3_256.ComputeHash(_input);
            // example 2
            IDigest digest = HashAlgorithms.SHA3_256.GenerateDigest();
            byte[] hash = new byte[HashAlgorithms.SHA3_256.HashSize / 8];
            digest.BlockUpdate(_input, 0, _input.Length);
            digest.DoFinal(hash, 0);
        }

        private static void Demo2()
        {
            byte[] key = new byte[71]; // Any value
            Utilities.Random.NextBytes(key);
            ICipherParameters parameters = HMACAlgorithms.SHA3_256_HMAC.GenerateParameters(key);
            // example 1
            _ = HMACAlgorithms.SHA3_256_HMAC.ComputeHash(parameters, _input);
            // example 2
            IMac digest = HMACAlgorithms.SHA3_256_HMAC.GenerateDigest(parameters);
            byte[] hash = new byte[HMACAlgorithms.SHA3_256_HMAC.HashSize / 8];
            digest.BlockUpdate(_input, 0, _input.Length);
            digest.DoFinal(hash, 0);
        }

        private static void Demo3()
        {
            byte[] key = new byte[128 / 8]; // AES key size
            Utilities.Random.NextBytes(key);
            ICipherParameters parameters = CMACAlgorithms.AES_CMAC.GenerateParameters(key);
            // example 1
            _ = CMACAlgorithms.AES_CMAC.ComputeHash(parameters, _input);
            // example 2
            IMac digest = CMACAlgorithms.AES_CMAC.GenerateDigest(parameters);
            byte[] hash = new byte[CMACAlgorithms.AES_CMAC.HashSize / 8];
            digest.BlockUpdate(_input, 0, _input.Length);
            digest.DoFinal(hash, 0);
        }

        private static void Demo4()
        {
            byte[] key = new byte[128 / 8]; // AES key size
            Utilities.Random.NextBytes(key);
            byte[] iv = new byte[128 / 8]; // AES IV size
            Utilities.Random.NextBytes(iv);
            ICipherParameters parameters = MACAlgorithms.AES_MAC.GenerateParameters(key, iv);
            // example 1
            _ = MACAlgorithms.AES_MAC.ComputeHash(MACCipherMode.CBC, MACPaddingMode.NoPadding, parameters, _input);
            // example 2
            IMac digest = MACAlgorithms.AES_MAC.GenerateDigest(MACCipherMode.CBC, MACPaddingMode.NoPadding, parameters);
            byte[] hash = new byte[MACAlgorithms.AES_MAC.HashSize / 8];
            digest.BlockUpdate(_input, 0, _input.Length);
            digest.DoFinal(hash, 0);
        }

        private static void Test1()
        {
            Type type = typeof(HashAlgorithms);
            PropertyInfo[] properties = type.GetProperties(BindingFlags.Static | BindingFlags.Public);
            foreach (PropertyInfo property in properties)
            {
                if (property.GetValue(type, null) is IHashAlgorithm algorithm)
                {
                    _total++;
                    IDigest digest = algorithm.GenerateDigest();
                    XTest(algorithm.Name, digest, _input);
                    _execute++;
                }
            }
            //
            List<string> names = new List<string>();
            names.AddRange(new string[] { "BLAKE2b-88", "SHA-512/368", "SHA512/368", "Skein-256-48" });
            foreach (string name in names)
            {
                _total++;
                _execute++;
                HashAlgorithmHelper.TryGetAlgorithm(name, out IHashAlgorithm algorithm);
                IDigest digest = algorithm.GenerateDigest();
                XTest(algorithm.Name, digest, _input);
            }
            Console.WriteLine();
        }

        private static void Test2()
        {
            byte[] key = new byte[19];
            Utilities.Random.NextBytes(key);
            //
            Type type = typeof(HMACAlgorithms);
            PropertyInfo[] properties = type.GetProperties(BindingFlags.Static | BindingFlags.Public);
            foreach (PropertyInfo property in properties)
            {
                if (property.GetValue(type, null) is IHMAC algorithm)
                {
                    _total++;
                    ICipherParameters parameters = algorithm.GenerateParameters(key);
                    IMac digest = algorithm.GenerateDigest(parameters);
                    XTest(algorithm.Name, digest, _input);
                    _execute++;
                }
            }
            //
            Console.WriteLine();
        }

        private static void Test3(bool testMax)
        {
            Type type = typeof(CMACAlgorithms);
            PropertyInfo[] properties = type.GetProperties(BindingFlags.Static | BindingFlags.Public);
            foreach (PropertyInfo property in properties)
            {
                if (property.GetValue(type, null) is ICMAC algorithm)
                {
                    _total++;
                    int keySize = testMax ? Math.Min(algorithm.LegalKeySizes[0].MaxSize, 65536) : algorithm.LegalKeySizes[0].MinSize;
                    byte[] key = new byte[keySize / 8];
                    Utilities.Random.NextBytes(key);
                    ICipherParameters parameters = algorithm.GenerateParameters(key);
                    IMac digest = algorithm.GenerateDigest(parameters);
                    XTest(algorithm.Name, digest, _input);
                    _execute++;
                }
            }
            Console.WriteLine();
        }

        private static void Test4(bool testMax)
        {
            Array modes = Enum.GetValues(typeof(MACCipherMode));
            Array paddings = Enum.GetValues(typeof(MACPaddingMode));
            //
            Type type = typeof(MACAlgorithms);
            PropertyInfo[] properties = type.GetProperties(BindingFlags.Static | BindingFlags.Public);
            foreach (PropertyInfo property in properties)
            {
                if (property.GetValue(type, null) is IMAC algorithm)
                {
                    foreach (int modeValue in modes)
                    {
                        MACCipherMode mode = (MACCipherMode)modeValue;
                        foreach (int paddingValue in paddings)
                        {
                            _total++;
                            MACPaddingMode padding = (MACPaddingMode)paddingValue;
                            string mechanism = string.Format(CultureInfo.InvariantCulture, "{0}/{1}/{2}", algorithm.Name, mode.ToString(), padding.ToString());
                            if (algorithm.TryGetIVSizes(mode, padding, out KeySizes[] ivSizes))
                            {
                                int keySize = testMax ? Math.Min(algorithm.LegalKeySizes[0].MaxSize, 65536) : algorithm.LegalKeySizes[0].MinSize;
                                byte[] key = new byte[keySize / 8];
                                Utilities.Random.NextBytes(key);
                                int ivSize = testMax ? Math.Min(ivSizes[0].MaxSize, 65536) : ivSizes[0].MinSize;

                                if (mode == MACCipherMode.CFB && (padding == MACPaddingMode.X923 || padding == MACPaddingMode.ISO7816_4) && ivSize == 8)
                                {
                                    ivSize = 24;
                                }

                                byte[] iv = new byte[ivSize / 8];
                                Utilities.Random.NextBytes(iv);
                                ICipherParameters parameters = algorithm.GenerateParameters(key, iv);

                                IMac digest = algorithm.GenerateDigest(mode, padding, parameters);
                                try
                                {
                                    XTest(mechanism, digest, _input);
                                    _execute++;
                                }
                                catch (Exception)
                                {
                                    Console.WriteLine("{0}-------- Ignored --------", mechanism.PadRight(32));
                                }
                            }
                        }
                    }
                }
            }
        }

        private static void XTest(string mechanism, IDigest digest, byte[] test)
        {
            byte[] hash1 = new byte[digest.GetDigestSize()];
            byte[] hash2 = new byte[digest.GetDigestSize()];
            digest.BlockUpdate(test, 0, test.Length);
            digest.DoFinal(hash1, 0);
            digest.BlockUpdate(test, 0, test.Length);
            digest.DoFinal(hash2, 0);
            bool diff = !StructuralComparisons.StructuralEqualityComparer.Equals(hash2, hash1);
            Console.Write("{0}{1} hash {2} bits - ", mechanism.PadRight(32), digest.AlgorithmName.PadRight(32), hash1.Length * 8);
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

        private static void XTest(string mechanism, IMac digest, byte[] test)
        {
            byte[] hash1 = new byte[digest.GetMacSize()];
            byte[] hash2 = new byte[digest.GetMacSize()];
            digest.BlockUpdate(test, 0, test.Length);
            digest.DoFinal(hash1, 0);
            digest.BlockUpdate(test, 0, test.Length);
            digest.DoFinal(hash2, 0);
            bool diff = !StructuralComparisons.StructuralEqualityComparer.Equals(hash2, hash1);
            Console.Write("{0}{1} hash {2} bits - ", mechanism.PadRight(32), digest.AlgorithmName.PadRight(32), hash1.Length * 8);
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