using Honoo.BouncyCastle.Helpers;
using Org.BouncyCastle.Crypto;
using System;
using System.Diagnostics;
using System.Security.Cryptography;

namespace Test
{
    internal static class EncryptionSpeed
    {
        private static readonly byte[] _input = new byte[13000];

        internal static void Test()
        {
            Utilities.Random.NextBytes(_input);
            Stopwatch stopwatch = new Stopwatch();
            byte[] key = new byte[128 / 8];
            Utilities.Random.NextBytes(key);
            byte[] iv = new byte[128 / 8];
            Utilities.Random.NextBytes(iv);
            ICipherParameters parameters = SymmetricAlgorithms.AES.GenerateParameters(key, iv);
            //
            Console.WriteLine();
            Console.WriteLine("====  Encryption Speed Test  ===========================================================================================");

            Console.WriteLine();
            //
            using (Aes algorithm = Aes.Create())
            {
                using (ICryptoTransform encryptor = algorithm.CreateEncryptor(key, iv), decryptor = algorithm.CreateDecryptor(key, iv))
                {
                    stopwatch.Restart();
                    for (int i = 0; i < 10000; i++)
                    {
                        byte[] enc = encryptor.TransformFinalBlock(_input, 0, _input.Length);
                        _ = decryptor.TransformFinalBlock(enc, 0, enc.Length);
                    }
                }
                stopwatch.Stop();
                Console.WriteLine(".NET AES Enc/Dec source 13KiB 10000 times : " + stopwatch.ElapsedMilliseconds + " milliseconds");
            }
            //
            {
                stopwatch.Restart();
                IBufferedCipher encryptor = SymmetricAlgorithms.AES.GenerateEncryptor(SymmetricCipherMode.CBC, SymmetricPaddingMode.PKCS7, parameters);
                IBufferedCipher decryptor = SymmetricAlgorithms.AES.GenerateDecryptor(SymmetricCipherMode.CBC, SymmetricPaddingMode.PKCS7, parameters);
                for (int i = 0; i < 10000; i++)
                {
                    byte[] enc = encryptor.DoFinal(_input, 0, _input.Length);
                    _ = decryptor.DoFinal(enc, 0, enc.Length);
                }
                stopwatch.Stop();
                Console.WriteLine("BouncyCastle AES Enc/Dec source 13KiB 10000 times : " + stopwatch.ElapsedMilliseconds + " milliseconds");
            }
        }
    }
}