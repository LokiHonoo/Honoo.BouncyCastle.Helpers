using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Security.Cryptography;

namespace Honoo.BouncyCastle.Helpers.Security.Crypto.Symmetric
{
    /// <summary>
    /// Threefish.
    /// <para/>Legal block size 256, 512, 1024 bits. Legal key size 256, 512, 1024 bits. Key size must be same as block size.
    /// </summary>
    public sealed class Threefish : BlockAlgorithm
    {
        #region Properties

        private static readonly KeySizes[] _blockSizes = new KeySizes[]
        {
            new KeySizes(256, 256, 0),
            new KeySizes(512, 512, 0),
            new KeySizes(1024, 1024, 0)
        };

        private static readonly IDictionary<int, KeySizes[]> _keySizes = new Dictionary<int, KeySizes[]>()
        {
            { 256, new KeySizes[] { new KeySizes(256, 256, 0) } },
            { 512, new KeySizes[] { new KeySizes(512, 512, 0) } },
            { 1024, new KeySizes[] { new KeySizes(1024, 1024, 0) } }
        };

        #endregion Properties

        #region Constructor

        /// <summary>
        /// Threefish.
        /// <para/>Legal block size 256, 512, 1024 bits. Legal key size 256, 512, 1024 bits. Key size must be same as block size.
        /// </summary>
        /// <param name="blockSize">Block size bits.</param>
        /// <exception cref="Exception"/>
        public Threefish(int blockSize)
            : base(string.Format(CultureInfo.InvariantCulture, "Threefish-{0}", blockSize), SymmetricAlgorithmKind.Block, _blockSizes, blockSize, GetKeySizes(blockSize))
        {
        }

        #endregion Constructor

        internal override IBlockCipher GenerateEngine()
        {
            return new ThreefishEngine(base.BlockSize);
        }

        private static KeySizes[] GetKeySizes(int blockSize)
        {
            _keySizes.TryGetValue(blockSize, out KeySizes[] keySizes);
            return keySizes;
        }
    }
}