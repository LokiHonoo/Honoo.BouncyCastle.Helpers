﻿using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using System.Security.Cryptography;

namespace Honoo.BouncyCastle.Helpers.Security.Crypto.Symmetric
{
    /// <summary>
    /// HC256.
    /// <para/>Legal key size 128, 256 bits. Legal IV size 128-256 bits (8 bits increments).
    /// </summary>
    public sealed class HC256 : SymmetricStreamAlgorithm
    {
        #region Properties

        private static readonly KeySizes[] _ivSizes = new KeySizes[] { new KeySizes(128, 256, 8) };
        private static readonly KeySizes[] _keySizes = new KeySizes[] { new KeySizes(128, 256, 128) };

        #endregion Properties

        #region Construction

        /// <summary>
        /// HC256.
        /// <para/>Legal key size 128, 256 bits. Legal IV size 128-256 bits (8 bits increments).
        /// </summary>
        public HC256() : base("HC256", SymmetricAlgorithmKind.Stream, _keySizes, _ivSizes)
        {
        }

        #endregion Construction

        /// <summary>
        /// Generate engine.
        /// </summary>
        /// <returns></returns>
        protected override IStreamCipher GenerateEngine()
        {
            return new HC256Engine();
        }
    }
}