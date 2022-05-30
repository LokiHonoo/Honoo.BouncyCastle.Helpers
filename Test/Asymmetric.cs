using Honoo.BouncyCastle.Helpers;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Globalization;
using System.Security.Cryptography;

namespace Test
{
    internal static class Asymmetric
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
            Console.WriteLine("====  Asymmetric Test  =================================================================================================");
            Console.WriteLine();
            //
            Demo1();
            Demo2();
            ////
            Test1();
            //
            Console.WriteLine("\r\n\r\n");
            Console.WriteLine("Total={0}  Ignore={1}  Diff={2}", _total, _total - _execute, _diff);
        }

        private static void Demo1()
        {
            byte[] test = new byte[5];
            Utilities.Random.NextBytes(test);
            AsymmetricCipherKeyPair keyPair = AsymmetricAlgorithmHelper.RSA.GenerateKeyPair();
            // example 1
            byte[] enc1 = AsymmetricAlgorithmHelper.RSA.Encrypt(AsymmetricPaddingMode.PKCS1, keyPair.Public, test, 0, test.Length);
            _ = AsymmetricAlgorithmHelper.RSA.Decrypt(AsymmetricPaddingMode.PKCS1, keyPair.Private, enc1, 0, enc1.Length);
            // example 2
            IAsymmetricBlockCipher encryptor = AsymmetricAlgorithmHelper.RSA.GenerateEncryptor(AsymmetricPaddingMode.PKCS1, keyPair.Public);
            IAsymmetricBlockCipher decryptor = AsymmetricAlgorithmHelper.RSA.GenerateDecryptor(AsymmetricPaddingMode.PKCS1, keyPair.Private);
            byte[] enc2 = encryptor.ProcessBlock(test, 0, test.Length);
            byte[] dec2 = decryptor.ProcessBlock(enc2, 0, enc2.Length);
            //
            Console.WriteLine(BitConverter.ToString(test).Replace("-", ""));
            Console.WriteLine(BitConverter.ToString(dec2).Replace("-", ""));
        }

        private static void Demo2()
        {
            byte[] test = new byte[5];
            Utilities.Random.NextBytes(test);
            AsymmetricCipherKeyPair keyPair = AsymmetricAlgorithmHelper.RSA.GenerateKeyPair();
            // example 1
            byte[] enc1 = AsymmetricAlgorithmHelper.RSA.Encrypt(AsymmetricPaddingMode.PKCS1, keyPair.Public, test, 0, test.Length);
            _ = AsymmetricAlgorithmHelper.RSA.Decrypt(AsymmetricPaddingMode.PKCS1, keyPair.Private, enc1, 0, enc1.Length);
            // example 2
            IAsymmetricBlockCipher encryptor = AsymmetricAlgorithmHelper.RSA.GenerateEncryptor(AsymmetricPaddingMode.OAEP,
                                                                                               HashAlgorithmHelper.RIPEMD160,
                                                                                               HashAlgorithmHelper.SHAKE_256,
                                                                                               keyPair.Public);
            IAsymmetricBlockCipher decryptor = AsymmetricAlgorithmHelper.RSA.GenerateDecryptor(AsymmetricPaddingMode.OAEP,
                                                                                               HashAlgorithmHelper.RIPEMD160,
                                                                                               HashAlgorithmHelper.SHAKE_256,
                                                                                               keyPair.Private);
            byte[] enc2 = encryptor.ProcessBlock(test, 0, test.Length);
            byte[] dec2 = decryptor.ProcessBlock(enc2, 0, enc2.Length);
            Console.WriteLine(BitConverter.ToString(test).Replace("-", ""));
            Console.WriteLine(BitConverter.ToString(dec2).Replace("-", ""));
        }

        private static void Test1()
        {
            Array paddings = Enum.GetValues(typeof(AsymmetricPaddingMode));
            //
            List<IAsymmetricEncryptionAlgorithm> algorithms = new List<IAsymmetricEncryptionAlgorithm>();
            AsymmetricAlgorithmHelper.TryGetAlgorithm("ElGamal", out IAsymmetricEncryptionAlgorithm encryption);
            algorithms.Add(encryption);
            AsymmetricAlgorithmHelper.TryGetAlgorithm("RSA", out encryption);
            algorithms.Add(encryption);
            //
            byte[] test = new byte[5];
            Utilities.Random.NextBytes(test);
            foreach (IAsymmetricEncryptionAlgorithm algorithm in algorithms)
            {
                foreach (int paddingValue in paddings)
                {
                    _total++;
                    AsymmetricPaddingMode padding = (AsymmetricPaddingMode)paddingValue;
                    string mechanism = string.Format(CultureInfo.InvariantCulture, "{0}/{1}", algorithm.Name, padding.ToString());
                    try
                    {
                        AsymmetricCipherKeyPair keyPair = algorithm.GenerateKeyPair();
                        IAsymmetricBlockCipher encryptor = algorithm.GenerateEncryptor(padding, keyPair.Public);
                        IAsymmetricBlockCipher decryptor = algorithm.GenerateDecryptor(padding, keyPair.Private);
                        XTest(mechanism, encryptor, decryptor, test);
                        _execute++;
                    }
                    catch (Exception)
                    {
                        Console.WriteLine("{0}-------------------------------- Ignored.", mechanism.PadRight(32));
                    }
                }
            }
            {
                AsymmetricCipherKeyPair keyPair;
                using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(2048))
                {
                    keyPair = DotNetUtilities.GetRsaKeyPair(rsa);
                }
                IAsymmetricBlockCipher encryptor = AsymmetricAlgorithmHelper.RSA.GenerateEncryptor(AsymmetricPaddingMode.NoPadding, keyPair.Public);
                IAsymmetricBlockCipher decryptor = AsymmetricAlgorithmHelper.RSA.GenerateDecryptor(AsymmetricPaddingMode.NoPadding, keyPair.Private);
                XTest("Use .NET RSA KEY 2048", encryptor, decryptor, test);
            }
        }

        private static void XTest(string mechanism, IAsymmetricBlockCipher encryptor, IAsymmetricBlockCipher decryptor, byte[] test)
        {
            byte[] enc = encryptor.ProcessBlock(test, 0, test.Length);
            byte[] dec = decryptor.ProcessBlock(enc, 0, enc.Length);
            bool diff = !StructuralComparisons.StructuralEqualityComparer.Equals(dec, test);
            //
            Console.Write("{0}{1} max {2} bytes - src {3} bytes, enc {4} bytes - ",
                mechanism.PadRight(32),
                encryptor.AlgorithmName.PadRight(32),
                encryptor.GetInputBlockSize(),
                test.Length,
                enc.Length);
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