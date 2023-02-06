using Honoo.BouncyCastle.Helpers;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using System;
using System.Collections;
using System.Globalization;
using System.Security.Cryptography;

namespace Test
{
    internal static class Asymmetric
    {
        private static int _diff = 0;
        private static int _execute = 0;
        private static readonly byte[] _input = new byte[15];
        private static int _total = 0;

        internal static void Test()
        {
            Utilities.Random.NextBytes(_input);
            //
            _total = 0;
            _execute = 0;
            _diff = 0;
            Console.WriteLine();
            Console.WriteLine("====  Asymmetric Test  =================================================================================================");
            Console.WriteLine();
            //
            Demo1();
            Demo2();
            Console.WriteLine("\r\n\r\n");
            //
            Test1();
            Test2();
            //
            Console.WriteLine("\r\n\r\n");
            Console.WriteLine("Total={0}  Ignore={1}  Diff={2}", _total, _total - _execute, _diff);
        }

        private static void Demo1()
        {
            AsymmetricCipherKeyPair keyPair = AsymmetricAlgorithms.RSA.GenerateKeyPair();
            // example 1
            byte[] enc = AsymmetricAlgorithms.RSA.Encrypt(AsymmetricPaddingMode.PKCS1, keyPair.Public, _input, 0, _input.Length);
            _ = AsymmetricAlgorithms.RSA.Decrypt(AsymmetricPaddingMode.PKCS1, keyPair.Private, enc, 0, enc.Length);
            // example 2
            IAsymmetricBlockCipher encryptor = AsymmetricAlgorithms.RSA.GenerateEncryptor(AsymmetricPaddingMode.PKCS1, keyPair.Public);
            IAsymmetricBlockCipher decryptor = AsymmetricAlgorithms.RSA.GenerateDecryptor(AsymmetricPaddingMode.PKCS1, keyPair.Private);
            enc = encryptor.ProcessBlock(_input, 0, _input.Length);
            _ = decryptor.ProcessBlock(enc, 0, enc.Length);
        }

        private static void Demo2()
        {
            AsymmetricCipherKeyPair keyPair = AsymmetricAlgorithms.RSA.GenerateKeyPair();
            // example 1
            byte[] enc = AsymmetricAlgorithms.RSA.Encrypt(AsymmetricPaddingMode.OAEP,
                                                          HashAlgorithms.Whirlpool,
                                                          HashAlgorithms.Whirlpool,
                                                          keyPair.Public,
                                                          _input,
                                                          0,
                                                          _input.Length);
            _ = AsymmetricAlgorithms.RSA.Decrypt(AsymmetricPaddingMode.OAEP,
                                                 HashAlgorithms.Whirlpool,
                                                 HashAlgorithms.Whirlpool,
                                                 keyPair.Private,
                                                 enc,
                                                 0,
                                                 enc.Length);
            // example 2
            IAsymmetricBlockCipher encryptor = AsymmetricAlgorithms.RSA.GenerateEncryptor(AsymmetricPaddingMode.OAEP,
                                                                                          HashAlgorithms.RIPEMD160,
                                                                                          HashAlgorithms.SHAKE_256,
                                                                                          keyPair.Public);
            IAsymmetricBlockCipher decryptor = AsymmetricAlgorithms.RSA.GenerateDecryptor(AsymmetricPaddingMode.OAEP,
                                                                                          HashAlgorithms.RIPEMD160,
                                                                                          HashAlgorithms.SHAKE_256,
                                                                                          keyPair.Private);
            enc = encryptor.ProcessBlock(_input, 0, _input.Length);
            _ = decryptor.ProcessBlock(enc, 0, enc.Length);
        }

        private static void Test1()
        {
            Array paddings = Enum.GetValues(typeof(AsymmetricPaddingMode));
            foreach (int paddingValue in paddings)
            {
                _total++;
                AsymmetricPaddingMode padding = (AsymmetricPaddingMode)paddingValue;
                string mechanism = string.Format(CultureInfo.InvariantCulture, "{0}/{1}", AsymmetricAlgorithms.ElGamal.Name, padding.ToString());
                if (padding == AsymmetricPaddingMode.ISO9796_1)
                {
                    Console.WriteLine("{0}-------------------------------- Ignored.", mechanism.PadRight(32));
                }
                else
                {
                    AsymmetricCipherKeyPair keyPair = AsymmetricAlgorithms.ElGamal.GenerateKeyPair();
                    IAsymmetricBlockCipher encryptor = AsymmetricAlgorithms.ElGamal.GenerateEncryptor(padding, keyPair.Public);
                    IAsymmetricBlockCipher decryptor = AsymmetricAlgorithms.ElGamal.GenerateDecryptor(padding, keyPair.Private);
                    XTest(mechanism, encryptor, decryptor);
                    _execute++;
                }
            }
            foreach (int paddingValue in paddings)
            {
                _total++;
                AsymmetricPaddingMode padding = (AsymmetricPaddingMode)paddingValue;
                string mechanism = string.Format(CultureInfo.InvariantCulture, "{0}/{1}", AsymmetricAlgorithms.RSA.Name, padding.ToString());
                AsymmetricCipherKeyPair keyPair = AsymmetricAlgorithms.RSA.GenerateKeyPair();
                IAsymmetricBlockCipher encryptor = AsymmetricAlgorithms.RSA.GenerateEncryptor(padding, keyPair.Public);
                IAsymmetricBlockCipher decryptor = AsymmetricAlgorithms.RSA.GenerateDecryptor(padding, keyPair.Private);
                XTest(mechanism, encryptor, decryptor);
                _execute++;
            }
        }

        private static void Test2()
        {
            AsymmetricCipherKeyPair keyPair;
            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(2048))
            {
                keyPair = DotNetUtilities.GetRsaKeyPair(rsa);
            }
            IAsymmetricBlockCipher encryptor = AsymmetricAlgorithms.RSA.GenerateEncryptor(AsymmetricPaddingMode.NoPadding, keyPair.Public);
            IAsymmetricBlockCipher decryptor = AsymmetricAlgorithms.RSA.GenerateDecryptor(AsymmetricPaddingMode.NoPadding, keyPair.Private);
            XTest("Use .NET RSA KEY 2048", encryptor, decryptor);
        }

        private static void XTest(string mechanism, IAsymmetricBlockCipher encryptor, IAsymmetricBlockCipher decryptor)
        {
            byte[] enc = encryptor.ProcessBlock(_input, 0, _input.Length);
            byte[] dec = decryptor.ProcessBlock(enc, 0, enc.Length);
            bool diff = !StructuralComparisons.StructuralEqualityComparer.Equals(dec, _input);
            //
            Console.Write("{0}{1} max {2} bytes - src {3} bytes, enc {4} bytes - ",
                          mechanism.PadRight(32),
                          encryptor.AlgorithmName.PadRight(32),
                          encryptor.GetInputBlockSize(),
                          _input.Length,
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