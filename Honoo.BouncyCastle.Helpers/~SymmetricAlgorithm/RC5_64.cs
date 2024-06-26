﻿using Honoo.BouncyCastle.Helpers.Utilities;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using System.Security.Cryptography;

namespace Honoo.BouncyCastle.Helpers
{
    /// <summary>
    /// Using the BouncyCastle implementation of the algorithm.
    /// </summary>
    public sealed class RC5_64 : SymmetricBlockAlgorithm
    {
        #region Properties

        private const int BLOCK_SIZE = 128;
        private const int DEFAULT_KEY_SIZE = 256;
        private const SymmetricAlgorithmKind KIND = SymmetricAlgorithmKind.Block;
        private const string NAME = "RC5-64";
        private static readonly KeySizes[] LEGAL_KEY_SIZES = new KeySizes[] { new KeySizes(8, 2040, 8) };

        /// <summary>
        /// Gets legal key size bits. Legal key size 8-2040 bits (8 bits increments).
        /// </summary>
        public override KeySizes[] LegalKeySizes => (KeySizes[])LEGAL_KEY_SIZES.Clone();

        #endregion Properties

        #region Construction

        /// <summary>
        /// Initializes a new instance of the RC5_64 class.
        /// </summary>
        public RC5_64() : base(NAME, BLOCK_SIZE, DEFAULT_KEY_SIZE)
        {
        }

        #endregion Construction

        /// <summary>
        /// Creates an instance of the algorithm.
        /// </summary>
        /// <returns></returns>
        public static RC5_64 Create()
        {
            return new RC5_64();
        }

        /// <inheritdoc/>
        public override bool ValidKeySize(int keySize, out string exception)
        {
            if (DetectionUtilities.ValidSize(LEGAL_KEY_SIZES, keySize))
            {
                exception = string.Empty;
                return true;
            }
            else
            {
                exception = "Legal key size 8-2040 bits (8 bits increments).";
                return false;
            }
        }

        internal static SymmetricAlgorithmName GetAlgorithmName()
        {
            return new SymmetricAlgorithmName(NAME, KIND, BLOCK_SIZE, () => { return new RC5_64(); });
        }

        /// <inheritdoc/>
        internal override IBlockCipher GetEngine()
        {
            return new RC564Engine();
        }

        /// <inheritdoc/>
        protected override KeyParameter GetKeyParameter(byte[] key)
        {
            return new RC5Parameters(key, 12);
        }
    }
}