using Honoo.BouncyCastle.Helpers;
using Org.BouncyCastle.Crypto;
using System;
using System.Collections;
using System.Globalization;
using System.Reflection;
using System.Security.Cryptography;

namespace Test
{
    internal static class Symmetric
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
            Console.WriteLine("====  Symmetric Test  ==================================================================================================");
            Console.WriteLine();
            //
            Demo1();
            Demo2();
            Demo3();
            Console.WriteLine("\r\n\r\n");
            //
            Test1(false);
            Test1(true);
            Test2(false);
            Test2(true);
            //
            Console.WriteLine("\r\n\r\n");
            Console.WriteLine("Total={0}  Ignore={1}  Diff={2}", _total, _total - _execute, _diff);
        }

        private static void Demo1()
        {
            byte[] key = new byte[128 / 8];
            Utilities.Random.NextBytes(key);
            byte[] iv = new byte[128 / 8];
            Utilities.Random.NextBytes(iv);
            ICipherParameters parameters = SymmetricAlgorithms.AES.GenerateParameters(key, iv);
            // example 1
            byte[] enc = SymmetricAlgorithms.AES.Encrypt(SymmetricCipherMode.CBC, SymmetricPaddingMode.PKCS7, parameters, _input, 0, _input.Length);
            _ = SymmetricAlgorithms.AES.Decrypt(SymmetricCipherMode.CBC, SymmetricPaddingMode.PKCS7, parameters, enc, 0, enc.Length);
            // example 2
            IBufferedCipher encryptor = SymmetricAlgorithms.AES.GenerateEncryptor(SymmetricCipherMode.CBC, SymmetricPaddingMode.PKCS7, parameters);
            IBufferedCipher decryptor = SymmetricAlgorithms.AES.GenerateDecryptor(SymmetricCipherMode.CBC, SymmetricPaddingMode.PKCS7, parameters);
            enc = encryptor.DoFinal(_input, 0, _input.Length);
            _ = decryptor.DoFinal(enc, 0, enc.Length);
        }

        private static void Demo2()
        {
            byte[] key = new byte[128 / 8];
            Utilities.Random.NextBytes(key);
            byte[] nonce = new byte[64 / 8]; // See SymmetricCipherMode.GCM summary
            Utilities.Random.NextBytes(nonce);
            int macSize = 96; // See SymmetricCipherMode.GCM summary
            ICipherParameters parameters = SymmetricAlgorithms.AES.GenerateParameters(key, nonce, macSize, null);
            // example 1
            byte[] enc = SymmetricAlgorithms.AES.Encrypt(SymmetricCipherMode.GCM, SymmetricPaddingMode.NoPadding, parameters, _input, 0, _input.Length);
            _ = SymmetricAlgorithms.AES.Decrypt(SymmetricCipherMode.GCM, SymmetricPaddingMode.NoPadding, parameters, enc, 0, enc.Length);
            // example 2
            IBufferedCipher encryptor = SymmetricAlgorithms.AES.GenerateEncryptor(SymmetricCipherMode.GCM, SymmetricPaddingMode.NoPadding, parameters);
            IBufferedCipher decryptor = SymmetricAlgorithms.AES.GenerateDecryptor(SymmetricCipherMode.GCM, SymmetricPaddingMode.NoPadding, parameters);
            byte[] enc2 = encryptor.DoFinal(_input, 0, _input.Length);
            _ = decryptor.DoFinal(enc2, 0, enc2.Length);
        }

        private static void Demo3()
        {
            byte[] key = new byte[128 / 8];
            Utilities.Random.NextBytes(key);
            byte[] iv = new byte[128 / 8];
            Utilities.Random.NextBytes(iv);
            ICipherParameters parameters = SymmetricAlgorithms.HC128.GenerateParameters(key, iv);
            // example 1
            byte[] enc = SymmetricAlgorithms.HC128.Encrypt(parameters, _input, 0, _input.Length);
            _ = SymmetricAlgorithms.HC128.Decrypt(parameters, enc, 0, enc.Length);
            // example 2
            IBufferedCipher encryptor = SymmetricAlgorithms.HC128.GenerateEncryptor(parameters);
            IBufferedCipher decryptor = SymmetricAlgorithms.HC128.GenerateDecryptor(parameters);
            byte[] enc2 = encryptor.DoFinal(_input, 0, _input.Length);
            _ = decryptor.DoFinal(enc2, 0, enc2.Length);
        }

        private static void Test1(bool testMax)
        {
            Array modes1 = Enum.GetValues(typeof(SymmetricCipherMode));
            Array paddings = Enum.GetValues(typeof(SymmetricPaddingMode));
            //
            Type type = typeof(SymmetricAlgorithms);
            PropertyInfo[] properties = type.GetProperties(BindingFlags.Static | BindingFlags.Public);
            foreach (PropertyInfo property in properties)
            {
                if (property.GetValue(type, null) is ISymmetricBlockAlgorithm algorithm)
                {
                    foreach (int modeValue in modes1)
                    {
                        SymmetricCipherMode mode = (SymmetricCipherMode)modeValue;
                        foreach (int paddingValue in paddings)
                        {
                            _total++;
                            SymmetricPaddingMode padding = (SymmetricPaddingMode)paddingValue;
                            string mechanism = string.Format(CultureInfo.InvariantCulture, "{0}/{1}/{2}", algorithm.Name, mode.ToString(), padding.ToString());

                            if (algorithm.TryGetIVSizes(mode, padding, out KeySizes[] ivSizes))
                            {
                                int keySize = testMax ? Math.Min(algorithm.LegalKeySizes[0].MaxSize, 65536) : algorithm.LegalKeySizes[0].MinSize;
                                byte[] key = new byte[keySize / 8];
                                Utilities.Random.NextBytes(key);
                                int ivSize = testMax ? Math.Min(ivSizes[0].MaxSize, 65536) : ivSizes[0].MinSize;
                                byte[] iv = ivSize == 0 ? null : new byte[ivSize / 8];
                                if (iv != null)
                                {
                                    Utilities.Random.NextBytes(iv);
                                }
                                ICipherParameters parameters = algorithm.GenerateParameters(key, iv);
                                IBufferedCipher encryptor = algorithm.GenerateEncryptor(mode, padding, parameters);
                                IBufferedCipher decryptor = algorithm.GenerateDecryptor(mode, padding, parameters);
                                try
                                {
                                    if (mode == SymmetricCipherMode.GCM)
                                    {
                                        XTestGCM(mechanism, encryptor, decryptor, _input);
                                    }
                                    else if (padding == SymmetricPaddingMode.NoPadding)
                                    {
                                        byte[] testMult = new byte[algorithm.BlockSize / 8 * 4];
                                        Utilities.Random.NextBytes(testMult);
                                        XTest(mechanism, encryptor, decryptor, testMult);
                                    }
                                    else
                                    {
                                        XTest(mechanism, encryptor, decryptor, _input);
                                    }
                                    _execute++;
                                }
                                catch (Exception)
                                {
                                    Console.WriteLine("{0}-------------------------------- Ignored.", mechanism.PadRight(32));
                                }
                            }
                        }
                    }
                }
            }
        }

        private static void Test2(bool testMax)
        {
            Type type = typeof(SymmetricAlgorithms);
            PropertyInfo[] properties = type.GetProperties(BindingFlags.Static | BindingFlags.Public);
            foreach (PropertyInfo property in properties)
            {
                if (property.GetValue(type, null) is ISymmetricStreamAlgorithm algorithm)
                {
                    _total++;
                    int keySize = testMax ? Math.Min(algorithm.LegalKeySizes[0].MaxSize, 65536) : algorithm.LegalKeySizes[0].MinSize;
                    byte[] key = new byte[keySize / 8];
                    Utilities.Random.NextBytes(key);
                    int ivSize = testMax ? Math.Min(algorithm.LegalIVSizes[0].MaxSize, 65536) : algorithm.LegalIVSizes[0].MinSize;
                    byte[] iv = ivSize == 0 ? null : new byte[ivSize / 8];
                    if (iv != null)
                    {
                        Utilities.Random.NextBytes(iv);
                    }
                    ICipherParameters parameters = algorithm.GenerateParameters(key, iv);
                    IBufferedCipher encryptor = algorithm.GenerateEncryptor(parameters);
                    IBufferedCipher decryptor = algorithm.GenerateDecryptor(parameters);
                    XTest(algorithm.Name, encryptor, decryptor, _input);
                    _execute++;
                }
            }
        }

        private static void XTest(string mechanism, IBufferedCipher encryptor, IBufferedCipher decryptor, byte[] test)
        {
            byte[] enc1 = encryptor.DoFinal(test, 0, test.Length);
            byte[] dec1 = decryptor.DoFinal(enc1, 0, enc1.Length);
            byte[] enc2 = encryptor.DoFinal(test, 0, test.Length);
            byte[] dec2 = decryptor.DoFinal(enc2, 0, enc2.Length);
            bool diff = !StructuralComparisons.StructuralEqualityComparer.Equals(dec2, dec1);
            Console.Write("{0}{1} src {2} bytes, enc {3} bytes, dec {4} bytes - ",
                mechanism.PadRight(32),
                encryptor.AlgorithmName.PadRight(32),
                test.Length,
                enc1.Length,
                dec1.Length);
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

        /// <summary>
        /// Warning: GCM cipher mode cannot be auto reused. The cipher instance needs to be recreated every time. (BouncyCastle 1.9.0 has not been fixed).
        /// </summary>
        /// <param name="encryptor"></param>
        /// <param name="decryptor"></param>
        /// <param name="test"></param>
        private static void XTestGCM(string mechanism, IBufferedCipher encryptor, IBufferedCipher decryptor, byte[] test)
        {
            byte[] enc1 = encryptor.DoFinal(test, 0, test.Length);
            byte[] dec1 = decryptor.DoFinal(enc1, 0, enc1.Length);
            bool diff = !StructuralComparisons.StructuralEqualityComparer.Equals(test, dec1);
            Console.Write("{0}{1} src {2} bytes, enc {3} bytes, dec {4} bytes - ",
                mechanism.PadRight(32),
                encryptor.AlgorithmName.PadRight(32),
                test.Length,
                enc1.Length,
                dec1.Length);
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