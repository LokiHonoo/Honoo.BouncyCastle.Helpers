using Honoo.BouncyCastle.Helpers;
using Honoo.BouncyCastle.Helpers.Security.Crypto.Asymmetric;
using Org.BouncyCastle.Crypto;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Globalization;
using System.Reflection;

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
            ////
            Test1();
            //
            Console.WriteLine("\r\n\r\n");
            Console.WriteLine("Total={0}  Ignore={1}  Diff={2}", _total, _total - _execute, _diff);
        }

        private static void Demo1()
        {
            byte[] test = Utilities.ScoopBytes(4);
            AsymmetricCipherKeyPair keyPair = AsymmetricAlgorithmHelper.RSA.GenerateKeyPair();
            IAsymmetricBlockCipher encryptor = AsymmetricAlgorithmHelper.RSA.GenerateCipher(AsymmetricPaddingMode.PKCS1, keyPair.Public);
            IAsymmetricBlockCipher decryptor = AsymmetricAlgorithmHelper.RSA.GenerateCipher(AsymmetricPaddingMode.PKCS1, keyPair.Private);
            byte[] enc = encryptor.ProcessBlock(test, 0, test.Length);
            _ = decryptor.ProcessBlock(enc, 0, enc.Length);
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
            byte[] test = Utilities.ScoopBytes(4);
            foreach (IAsymmetricEncryptionAlgorithm algorithm in algorithms)
            {
                foreach (int paddingValue in paddings)
                {
                    _total++;
                    AsymmetricPaddingMode padding = (AsymmetricPaddingMode)paddingValue;
                    string mechanism = string.Format(CultureInfo.InvariantCulture, "{0}/{1}", algorithm.Mechanism, padding.ToString());
                    try
                    {
                        AsymmetricCipherKeyPair keyPair = algorithm.GenerateKeyPair();
                        IAsymmetricBlockCipher encryptor = algorithm.GenerateCipher(padding, keyPair.Public);
                        IAsymmetricBlockCipher decryptor = algorithm.GenerateCipher(padding, keyPair.Private);
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
                AsymmetricCipherKeyPair keyPair = ((RSA)AsymmetricAlgorithmHelper.RSA).GenerateKeyPair(true);
                IAsymmetricBlockCipher encryptor = AsymmetricAlgorithmHelper.RSA.GenerateCipher(AsymmetricPaddingMode.NoPadding, keyPair.Public);
                IAsymmetricBlockCipher decryptor = AsymmetricAlgorithmHelper.RSA.GenerateCipher(AsymmetricPaddingMode.NoPadding, keyPair.Private);
                XTest(".NET RSA KEY 2048", encryptor, decryptor, test);
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