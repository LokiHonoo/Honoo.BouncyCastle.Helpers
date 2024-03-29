﻿using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using System.Security.Cryptography;

namespace Honoo.BouncyCastle.Helpers.Security.Crypto.Symmetric
{
    /// <summary>
    /// RC6.
    /// <para/>Legal block size 128 bits. Legal key size is more than or equal to 8 bits (8 bits increments).
    /// </summary>
    public sealed class RC6 : SymmetricBlockAlgorithm
    {
        #region Properties

        private static readonly KeySizes[] _blockSizes = new KeySizes[] { new KeySizes(128, 128, 0) };
        private static readonly KeySizes[] _keySizes = new KeySizes[] { new KeySizes(8, 2147483640, 8) };

        #endregion Properties

        #region Construction

        /// <summary>
        /// RC6.
        /// <para/>Legal block size 128 bits. Legal key size is more than or equal to 8 bits (8 bits increments).
        /// </summary>
        public RC6() : base("RC6", SymmetricAlgorithmKind.Block, _blockSizes, 128, _keySizes)
        {
        }

        #endregion Construction

        internal override IBlockCipher GenerateEngine()
        {
            return new RC6Engine();
        }
    }
}