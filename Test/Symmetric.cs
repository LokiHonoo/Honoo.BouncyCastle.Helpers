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
        private static int _diff = 0;
        private static int _execute = 0;
        private static int _total = 0;

        internal static void Test()
        {
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
            ////
            Test1();
            Test2();
            //
            Console.WriteLine("\r\n\r\n");
            Console.WriteLine("Total={0}  Ignore={1}  Diff={2}", _total, _total - _execute, _diff);
        }

        private static void Demo1()
        {
            byte[] test = new byte[123];
            Utilities.Random.NextBytes(test);
            byte[] key = new byte[128 / 8]; // AES key size
            Utilities.Random.NextBytes(key);
            byte[] iv = new byte[128 / 8]; // AES IV size
            Utilities.Random.NextBytes(iv);
            ICipherParameters parameters = SymmetricAlgorithmHelper.AES.GenerateParameters(key, iv);
            // example 1
            byte[] enc1 = SymmetricAlgorithmHelper.AES.Encrypt(SymmetricCipherMode.CBC, SymmetricPaddingMode.PKCS7, parameters, test, 0, test.Length);
            _ = SymmetricAlgorithmHelper.AES.Decrypt(SymmetricCipherMode.CBC, SymmetricPaddingMode.PKCS7, parameters, enc1, 0, enc1.Length);
            // example 2
            IBufferedCipher encryptor = SymmetricAlgorithmHelper.AES.GenerateEncryptor(SymmetricCipherMode.CBC, SymmetricPaddingMode.PKCS7, parameters);
            IBufferedCipher decryptor = SymmetricAlgorithmHelper.AES.GenerateDecryptor(SymmetricCipherMode.CBC, SymmetricPaddingMode.PKCS7, parameters);
            byte[] enc2 = encryptor.DoFinal(test, 0, test.Length);
            _ = decryptor.DoFinal(enc2, 0, enc2.Length);
        }

        private static void Demo2()
        {
            byte[] test = new byte[123];
            Utilities.Random.NextBytes(test);
            byte[] key = new byte[128 / 8]; // AES key size
            Utilities.Random.NextBytes(key);
            byte[] nonce = new byte[16 / 8]; // SymmetricAeadCipherMode.CCM legal
            Utilities.Random.NextBytes(nonce);
            int macSize = 96; // SymmetricAeadCipherMode.CCM legal
            ICipherParameters parameters = SymmetricAlgorithmHelper.AES.GenerateParameters(key, nonce, macSize, null);
            // example 1
            byte[] enc1 = SymmetricAlgorithmHelper.AES.Encrypt(SymmetricAeadCipherMode.GCM, parameters, test, 0, test.Length);
            _ = SymmetricAlgorithmHelper.AES.Decrypt(SymmetricAeadCipherMode.GCM, parameters, enc1, 0, enc1.Length);
            // example 2
            IBufferedCipher encryptor = SymmetricAlgorithmHelper.AES.GenerateEncryptor(SymmetricAeadCipherMode.GCM, parameters);
            IBufferedCipher decryptor = SymmetricAlgorithmHelper.AES.GenerateDecryptor(SymmetricAeadCipherMode.GCM, parameters);
            byte[] enc2 = encryptor.DoFinal(test, 0, test.Length);
            _ = decryptor.DoFinal(enc2, 0, enc2.Length);
        }

        private static void Demo3()
        {
            byte[] test = new byte[123];
            Utilities.Random.NextBytes(test);
            byte[] key = new byte[128 / 8]; // HC128 key size
            Utilities.Random.NextBytes(key);
            byte[] iv = new byte[128 / 8]; // HC128 IV size
            Utilities.Random.NextBytes(iv);
            ICipherParameters parameters = SymmetricAlgorithmHelper.HC128.GenerateParameters(key, iv);
            // example 1
            byte[] enc1 = SymmetricAlgorithmHelper.HC128.Encrypt(parameters, test, 0, test.Length);
            _ = SymmetricAlgorithmHelper.HC128.Decrypt(parameters, enc1, 0, enc1.Length);
            // example 2
            IBufferedCipher encryptor = SymmetricAlgorithmHelper.HC128.GenerateEncryptor(parameters);
            IBufferedCipher decryptor = SymmetricAlgorithmHelper.HC128.GenerateDecryptor(parameters);
            byte[] enc2 = encryptor.DoFinal(test, 0, test.Length);
            _ = decryptor.DoFinal(enc2, 0, enc2.Length);
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
            Array modes1 = Enum.GetValues(typeof(SymmetricCipherMode));
            Array modes2 = Enum.GetValues(typeof(SymmetricAeadCipherMode));
            Array paddings = Enum.GetValues(typeof(SymmetricPaddingMode));
            byte[] test = new byte[123];
            Utilities.Random.NextBytes(test);
            //
            Type type = typeof(SymmetricAlgorithmHelper);
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
                                int keySize = GetQualitySize(algorithm.KeySizes);
                                byte[] key = new byte[keySize / 8];
                                Utilities.Random.NextBytes(key);
                                int ivSize = GetQualitySize(ivSizes);
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
                                    if (padding == SymmetricPaddingMode.NoPadding)
                                    {
                                        byte[] testMult = new byte[algorithm.BlockSize / 8 * 4];
                                        Utilities.Random.NextBytes(testMult);
                                        XTest(mechanism, encryptor, decryptor, testMult);
                                    }
                                    else
                                    {
                                        XTest(mechanism, encryptor, decryptor, test);
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
                    foreach (int modeValue in modes2)
                    {
                        SymmetricAeadCipherMode mode = (SymmetricAeadCipherMode)modeValue;
                        _total++;
                        string mechanism = string.Format(CultureInfo.InvariantCulture, "{0}/{1}", algorithm.Name, mode.ToString());

                        if (algorithm.TryGetIVSizes(mode, out KeySizes[] ivSizes))
                        {
                            int keySize = GetQualitySize(algorithm.KeySizes);
                            byte[] key = new byte[keySize / 8];
                            Utilities.Random.NextBytes(key);
                            int ivSize = GetQualitySize(ivSizes);
                            byte[] iv = ivSize == 0 ? null : new byte[ivSize / 8];
                            if (iv != null)
                            {
                                Utilities.Random.NextBytes(iv);
                            }
                            ICipherParameters parameters = algorithm.GenerateParameters(key, iv);

                            IBufferedCipher encryptor = algorithm.GenerateEncryptor(mode, parameters);
                            IBufferedCipher decryptor = algorithm.GenerateDecryptor(mode, parameters);
                            try
                            {
                                if (mode == SymmetricAeadCipherMode.GCM)
                                {
                                    XTestGCM(mechanism, encryptor, decryptor, test);
                                }
                                else
                                {
                                    XTest(mechanism, encryptor, decryptor, test);
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

        private static void Test2()
        {
            byte[] test = new byte[37];
            Utilities.Random.NextBytes(test);
            //
            Type type = typeof(SymmetricAlgorithmHelper);
            PropertyInfo[] properties = type.GetProperties(BindingFlags.Static | BindingFlags.Public);
            foreach (PropertyInfo property in properties)
            {
                if (property.GetValue(type, null) is ISymmetricStreamAlgorithm algorithm)
                {
                    _total++;
                    int keySize = GetQualitySize(algorithm.KeySizes);
                    byte[] key = new byte[keySize / 8];
                    Utilities.Random.NextBytes(key);
                    int ivSize = GetQualitySize(algorithm.IVSizes);
                    byte[] iv = ivSize == 0 ? null : new byte[ivSize / 8];
                    if (iv != null)
                    {
                        Utilities.Random.NextBytes(iv);
                    }
                    ICipherParameters parameters = algorithm.GenerateParameters(key, iv);
                    IBufferedCipher encryptor = algorithm.GenerateEncryptor(parameters);
                    IBufferedCipher decryptor = algorithm.GenerateDecryptor(parameters);
                    XTest(algorithm.Name, encryptor, decryptor, test);
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
        /// BUG: GCM cipher mode cannot be resue. The algorithm instance needs to be recreated every time.
        /// </summary>
        /// <param name="encryptor"></param>
        /// <param name="decryptor"></param>
        /// <param name="test"></param>
        private static void XTestGCM(string mechanism, IBufferedCipher encryptor, IBufferedCipher decryptor, byte[] test)
        {
            byte[] enc1 = encryptor.DoFinal(test, 0, test.Length);
            byte[] dec1 = decryptor.DoFinal(enc1, 0, enc1.Length);
            bool diff = !StructuralComparisons.StructuralEqualityComparer.Equals(dec1, test);
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