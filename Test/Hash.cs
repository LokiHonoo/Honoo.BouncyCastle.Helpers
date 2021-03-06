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
        private static int _total = 0;

        internal static void Test()
        {
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
            Test3();
            Test4();
            //
            Console.WriteLine("\r\n\r\n");
            Console.WriteLine("Total={0}  Ignore={1}  Diff={2}", _total, _total - _execute, _diff);
        }

        private static void Demo1()
        {
            byte[] test = new byte[123];
            Utilities.Random.NextBytes(test);
            // example 1
            byte[] hash1 = HashAlgorithmHelper.SHA3_256.ComputeHash(test);
            // example 2
            IDigest digest = HashAlgorithmHelper.SHA3_256.GenerateDigest();
            byte[] hash2 = new byte[HashAlgorithmHelper.SHA3_256.HashSize / 8];
            digest.BlockUpdate(test, 0, test.Length);
            digest.DoFinal(hash2, 0);
        }

        private static void Demo2()
        {
            byte[] test = new byte[123];
            Utilities.Random.NextBytes(test);
            byte[] key = new byte[72]; // Any value
            Utilities.Random.NextBytes(key);
            ICipherParameters parameters = HMACHelper.SHA3_256_HMAC.GenerateParameters(key);
            // example 1
            byte[] hash1 = HMACHelper.SHA3_256_HMAC.ComputeHash(parameters, test);
            // example 2
            IMac digest = HMACHelper.SHA3_256_HMAC.GenerateDigest(parameters);
            byte[] hash2 = new byte[HMACHelper.SHA3_256_HMAC.HashSize / 8];
            digest.BlockUpdate(test, 0, test.Length);
            digest.DoFinal(hash2, 0);
        }

        private static void Demo3()
        {
            byte[] test = new byte[123];
            Utilities.Random.NextBytes(test);
            byte[] key = new byte[128 / 8]; // AES key size
            Utilities.Random.NextBytes(key);
            ICipherParameters parameters = CMACHelper.AES_CMAC.GenerateParameters(key);
            // example 1
            byte[] hash1 = CMACHelper.AES_CMAC.ComputeHash(parameters, test);
            // example 2
            IMac digest = CMACHelper.AES_CMAC.GenerateDigest(parameters);
            byte[] hash = new byte[CMACHelper.AES_CMAC.HashSize / 8];
            digest.BlockUpdate(test, 0, test.Length);
            digest.DoFinal(hash, 0);
        }

        private static void Demo4()
        {
            byte[] test = new byte[123];
            Utilities.Random.NextBytes(test);
            byte[] key = new byte[128 / 8]; // AES key size
            Utilities.Random.NextBytes(key);
            byte[] iv = new byte[128 / 8]; // AES IV size
            Utilities.Random.NextBytes(iv);
            ICipherParameters parameters = MACHelper.AES_MAC.GenerateParameters(key, iv);
            // example 1
            byte[] hash1 = MACHelper.AES_MAC.ComputeHash(MACCipherMode.CBC, MACPaddingMode.NoPadding, parameters, test);
            // example 2
            IMac digest = MACHelper.AES_MAC.GenerateDigest(MACCipherMode.CBC, MACPaddingMode.NoPadding, parameters);
            byte[] hash = new byte[MACHelper.AES_MAC.HashSize / 8];
            digest.BlockUpdate(test, 0, test.Length);
            digest.DoFinal(hash, 0);
        }

        private static int GetQualitySize(KeySizes[] sizes)
        {
            int size = sizes[0].MinSize;
            int max = Math.Min(sizes[sizes.Length - 1].MaxSize, 256);
            foreach (KeySizes item in sizes)
            {
                while (size < max)
                {
                    if (item.SkipSize == 0)
                    {
                        size = item.MinSize;
                        break;
                    }
                    else if (size + item.SkipSize <= item.MaxSize)
                    {
                        size += item.SkipSize;
                    }
                    else
                    {
                        break;
                    }
                }
            }
            return size;
        }

        private static void Test1()
        {
            byte[] test = new byte[123];
            Utilities.Random.NextBytes(test);
            //
            Type type = typeof(HashAlgorithmHelper);
            PropertyInfo[] properties = type.GetProperties(BindingFlags.Static | BindingFlags.Public);
            foreach (PropertyInfo property in properties)
            {
                if (property.GetValue(type, null) is IHashAlgorithm algorithm)
                {
                    _total++;
                    IDigest digest = algorithm.GenerateDigest();
                    XTest(algorithm.Name, digest, test);
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
                XTest(algorithm.Name, digest, test);
            }
            Console.WriteLine();
        }

        private static void Test2()
        {
            byte[] test = new byte[123];
            Utilities.Random.NextBytes(test);
            byte[] key = new byte[19];
            Utilities.Random.NextBytes(key);
            //
            Type type = typeof(HMACHelper);
            PropertyInfo[] properties = type.GetProperties(BindingFlags.Static | BindingFlags.Public);
            foreach (PropertyInfo property in properties)
            {
                if (property.GetValue(type, null) is IHMAC algorithm)
                {
                    _total++;
                    ICipherParameters parameters = algorithm.GenerateParameters(key);
                    IMac digest = algorithm.GenerateDigest(parameters);
                    XTest(algorithm.Name, digest, test);
                    _execute++;
                }
            }
            //
            Console.WriteLine();
        }

        private static void Test3()
        {
            byte[] test = new byte[123];
            Utilities.Random.NextBytes(test);
            //
            Type type = typeof(CMACHelper);
            PropertyInfo[] properties = type.GetProperties(BindingFlags.Static | BindingFlags.Public);
            foreach (PropertyInfo property in properties)
            {
                if (property.GetValue(type, null) is ICMAC algorithm)
                {
                    _total++;
                    int keySize = GetQualitySize(algorithm.KeySizes);
                    byte[] key = new byte[keySize / 8];
                    Utilities.Random.NextBytes(key);
                    ICipherParameters parameters = algorithm.GenerateParameters(key);
                    IMac digest = algorithm.GenerateDigest(parameters);
                    XTest(algorithm.Name, digest, test);
                    _execute++;
                }
            }
            Console.WriteLine();
        }

        private static void Test4()
        {
            Array modes = Enum.GetValues(typeof(MACCipherMode));
            Array paddings = Enum.GetValues(typeof(MACPaddingMode));
            byte[] test = new byte[123];
            Utilities.Random.NextBytes(test);
            //
            Type type = typeof(MACHelper);
            PropertyInfo[] properties = type.GetProperties(BindingFlags.Static | BindingFlags.Public);
            foreach (PropertyInfo property in properties)
            {
                if (property.GetValue(type, null) is IMAC algorithm)
                {
                    foreach (int modeValue in modes)
                    {
                        MACCipherMode mode = (MACCipherMode)modeValue;
                        int keySize = GetQualitySize(algorithm.KeySizes);
                        byte[] key = new byte[keySize / 8];
                        Utilities.Random.NextBytes(key);
                        algorithm.TryGetIVSizes(mode, out KeySizes[] ivSizes);
                        int ivSize = GetQualitySize(ivSizes);
                        byte[] iv = new byte[ivSize / 8];
                        Utilities.Random.NextBytes(iv);
                        ICipherParameters parameters = algorithm.GenerateParameters(key, iv);
                        foreach (int paddingValue in paddings)
                        {
                            _total++;
                            MACPaddingMode padding = (MACPaddingMode)paddingValue;
                            string mechanism = string.Format(CultureInfo.InvariantCulture, "{0}/{1}/{2}", algorithm.Name, mode.ToString(), padding.ToString());
                            IMac digest = algorithm.GenerateDigest(mode, padding, parameters);
                            try
                            {
                                XTest(mechanism, digest, test);
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