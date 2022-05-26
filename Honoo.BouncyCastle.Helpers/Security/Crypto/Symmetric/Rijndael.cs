using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using System;
using System.Globalization;
using System.Security.Cryptography;

namespace Honoo.BouncyCastle.Helpers.Security.Crypto.Symmetric
{
    /// <summary>
    /// Rijndael.
    /// <para/>Legal block size 128, 160, 192, 224, 256 bits. Legal key size 128, 160, 192, 224, 256 bits.
    /// </summary>
    public sealed class Rijndael : SymmetricBlockAlgorithm
    {
        #region Properties

        private static readonly KeySizes[] _blockSizes = new KeySizes[] { new KeySizes(128, 256, 32) };
        private static readonly KeySizes[] _keySizes = new KeySizes[] { new KeySizes(128, 256, 32) };

        #endregion Properties

        #region Constructor

        /// <summary>
        /// Rijndael.
        /// <para/>Legal block size 128, 160, 192, 224, 256 bits. Legal key size 128, 160, 192, 224, 256 bits.
        /// </summary>
        /// <param name="blockSize">Block size bits.</param>
        /// <exception cref="Exception"/>
        public Rijndael(int blockSize)
            : base(string.Format(CultureInfo.InvariantCulture, "Rijndael-{0}", blockSize), SymmetricAlgorithmKind.Block, _blockSizes, blockSize, _keySizes)
        {
        }

        #endregion Constructor

        internal override IBlockCipher GenerateEngine()
        {
            return new RijndaelEngine(base.BlockSize);
        }
    }
}