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
            byte[] test = Utilities.ScoopBytes(123);
            byte[] key = Utilities.ScoopBytes(128 / 8);
            byte[] iv = Utilities.ScoopBytes(128 / 8);
            ICipherParameters parameters = SymmetricAlgorithmHelper.AES.GenerateParameters(key, iv);
            IBufferedCipher encryptor = SymmetricAlgorithmHelper.AES.GenerateCipher(true, SymmetricCipherMode.CBC, SymmetricPaddingMode.PKCS7, parameters);
            IBufferedCipher decryptor = SymmetricAlgorithmHelper.AES.GenerateCipher(false, SymmetricCipherMode.CBC, SymmetricPaddingMode.PKCS7, parameters);
            byte[] enc = encryptor.DoFinal(test, 0, test.Length);
            _ = decryptor.DoFinal(enc, 0, enc.Length);
        }

        private static void Demo2()
        {
            byte[] test = Utilities.ScoopBytes(123);
            byte[] key = Utilities.ScoopBytes(128 / 8);
            byte[] nonce = Utilities.ScoopBytes(104 / 8);
            int macSize = 96;
            ICipherParameters parameters = SymmetricAlgorithmHelper.AES.GenerateParameters(key, nonce, macSize, null);
            IBufferedCipher encryptor = SymmetricAlgorithmHelper.AES.GenerateCipher(true, SymmetricCipherMode.CCM, SymmetricPaddingMode.NoPadding, parameters);
            IBufferedCipher decryptor = SymmetricAlgorithmHelper.AES.GenerateCipher(false, SymmetricCipherMode.CCM, SymmetricPaddingMode.NoPadding, parameters);
            byte[] enc = encryptor.DoFinal(test, 0, test.Length);
            _ = decryptor.DoFinal(enc, 0, enc.Length);
        }

        private static void Demo3()
        {
            byte[] test = Utilities.ScoopBytes(123);
            byte[] key = Utilities.ScoopBytes(128 / 8);
            byte[] iv = Utilities.ScoopBytes(128 / 8);
            ICipherParameters parameters = SymmetricAlgorithmHelper.HC128.GenerateParameters(key, iv);
            IBufferedCipher encryptor = SymmetricAlgorithmHelper.HC128.GenerateCipher(true, parameters);
            IBufferedCipher decryptor = SymmetricAlgorithmHelper.HC128.GenerateCipher(false, parameters);
            byte[] enc = encryptor.DoFinal(test, 0, test.Length);
            _ = decryptor.DoFinal(enc, 0, enc.Length);
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
            Array modes = Enum.GetValues(typeof(SymmetricCipherMode));
            Array paddings = Enum.GetValues(typeof(SymmetricPaddingMode));
            byte[] test = Utilities.ScoopBytes(37);
            //
            Type type = typeof(SymmetricAlgorithmHelper);
            PropertyInfo[] properties = type.GetProperties(BindingFlags.Static | BindingFlags.Public);
            foreach (PropertyInfo property in properties)
            {
                if (property.GetValue(type, null) is IBlockAlgorithm algorithm)
                {
                    foreach (int modeValue in modes)
                    {
                        SymmetricCipherMode mode = (SymmetricCipherMode)modeValue;
                        foreach (int paddingValue in paddings)
                        {
                            _total++;
                            SymmetricPaddingMode padding = (SymmetricPaddingMode)paddingValue;
                            string mechanism = string.Format(CultureInfo.InvariantCulture, "{0}/{1}/{2}", algorithm.Mechanism, mode.ToString(), padding.ToString());

                            if (algorithm.TryGetIVSizes(mode, padding, out KeySizes[] ivSizes))
                            {
                                int keySize = GetQualitySize(algorithm.KeySizes);
                                byte[] key = Utilities.ScoopBytes(keySize / 8);
                                int ivSize = GetQualitySize(ivSizes);
                                byte[] iv = ivSize == 0 ? null : Utilities.ScoopBytes(ivSize / 8);
                                ICipherParameters parameters = algorithm.GenerateParameters(key, iv);

                                IBufferedCipher encryptor = algorithm.GenerateCipher(true, mode, padding, parameters);
                                IBufferedCipher decryptor = algorithm.GenerateCipher(false, mode, padding, parameters);
                                try
                                {
                                    if (mode == SymmetricCipherMode.GCM)
                                    {
                                        XTestGCM(mechanism, encryptor, decryptor, test);
                                    }
                                    else if (padding == SymmetricPaddingMode.NoPadding)
                                    {
                                        byte[] testMult = Utilities.ScoopBytes(algorithm.BlockSize / 8 * 4);
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
                }
            }
        }

        private static void Test2()
        {
            byte[] test = Utilities.ScoopBytes(37);
            //
            Type type = typeof(SymmetricAlgorithmHelper);
            PropertyInfo[] properties = type.GetProperties(BindingFlags.Static | BindingFlags.Public);
            foreach (PropertyInfo property in properties)
            {
                if (property.GetValue(type, null) is IStreamAlgorithm algorithm)
                {
                    _total++;
                    int keySize = GetQualitySize(algorithm.KeySizes);
                    byte[] key = Utilities.ScoopBytes(keySize / 8);
                    int ivSize = GetQualitySize(algorithm.IVSizes);
                    byte[] iv = ivSize == 0 ? null : Utilities.ScoopBytes(ivSize / 8);

                    ICipherParameters parameters = algorithm.GenerateParameters(key, iv);
                    IBufferedCipher encryptor = algorithm.GenerateCipher(true, parameters);
                    IBufferedCipher decryptor = algorithm.GenerateCipher(false, parameters);
                    XTest(algorithm.Mechanism, encryptor, decryptor, test);
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