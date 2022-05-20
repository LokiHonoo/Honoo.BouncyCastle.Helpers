using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Security.Cryptography;

namespace Honoo.BouncyCastle.Helpers.Security.Crypto.Symmetric
{
    /// <summary>
    /// DSTU7624.
    /// <para/>Legal block size 128, 256, 512 bits.
    /// <para/>When block size is 128 bits, Legal key size 128, 256 bits.
    /// <para/>When block size is 256 bits, Legal key size 256, 512 bits.
    /// <para/>When block size is 512 bits, Legal key size 512 bits.
    /// </summary>
    public sealed class DSTU7624 : BlockAlgorithm
    {
        #region Properties

        private static readonly KeySizes[] _blockSizes = new KeySizes[]
        {
            new KeySizes(128, 128, 0),
            new KeySizes(256, 256, 0),
            new KeySizes(512, 512, 0)
        };

        private static readonly IDictionary<int, KeySizes[]> _keySizes = new Dictionary<int, KeySizes[]>()
        {
            { 128, new KeySizes[] { new KeySizes(128, 256, 128) } },
            { 256, new KeySizes[] { new KeySizes(256, 512, 256) } },
            { 512, new KeySizes[] { new KeySizes(512, 512, 0) } }
        };

        #endregion Properties

        #region Constructor

        /// <summary>
        /// DSTU7624.
        /// <para/>Legal block size 128, 256, 512 bits.
        /// <para/>When block size is 128 bits, Legal key size 128, 256 bits.
        /// <para/>When block size is 256 bits, Legal key size 256, 512 bits.
        /// <para/>When block size is 512 bits, Legal key size 512 bits.
        /// </summary>
        /// <param name="blockSize">Block size bits.</param>
        /// <exception cref="Exception"/>
        public DSTU7624(int blockSize)
            : base(string.Format(CultureInfo.InvariantCulture, "DSTU7624-{0}", blockSize), _blockSizes, blockSize, GetKeySizes(blockSize))
        {
        }

        #endregion Constructor

        internal override IBlockCipher GenerateEngine()
        {
            return new Dstu7624Engine(base.BlockSize);
        }

        private static KeySizes[] GetKeySizes(int blockSize)
        {
            _keySizes.TryGetValue(blockSize, out KeySizes[] keySizes);
            return keySizes;
        }
    }
}