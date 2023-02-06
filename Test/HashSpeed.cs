using Honoo.BouncyCastle.Helpers;
using Org.BouncyCastle.Crypto;
using System;
using System.Diagnostics;
using System.Security.Cryptography;

namespace Test
{
    internal static class HashSpeed
    {
        private static readonly byte[] _input = new byte[13000];

        internal static void Test()
        {
            Utilities.Random.NextBytes(_input);
            Stopwatch stopwatch = new Stopwatch();
            //
            Console.WriteLine();
            Console.WriteLine("====  Hash Speed Test  =================================================================================================");
            Console.WriteLine();
            //
            using (SHA256 algorithm = SHA256.Create())
            {
                stopwatch.Restart();
                for (int i = 0; i < 10000; i++)
                {
                    algorithm.ComputeHash(_input);
                }
                stopwatch.Stop();
                Console.WriteLine(".NET SHA256 Compute source 13KiB 10000 times : " + stopwatch.ElapsedMilliseconds + " milliseconds");
            }
            //
            stopwatch.Restart();
            for (int i = 0; i < 10000; i++)
            {
                IDigest digest = HashAlgorithms.SHA256.GenerateDigest();
                byte[] hash = new byte[HashAlgorithms.SHA256.HashSize / 8];
                digest.BlockUpdate(_input, 0, _input.Length);
                digest.DoFinal(hash, 0);
            }
            stopwatch.Stop();
            Console.WriteLine("BouncyCastle SHA256 Compute source 13KiB 10000 times : " + stopwatch.ElapsedMilliseconds + " milliseconds");
        }
    }
}