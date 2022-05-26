using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using System.Security.Cryptography;

namespace Honoo.BouncyCastle.Helpers.Security.Crypto.Symmetric
{
    /// <summary>
    /// SM4.
    /// <para/>Legal block size 128 bits. Legal key size 128 bits.
    /// </summary>
    public sealed class SM4 : BlockAlgorithm
    {
        #region Properties

        private static readonly KeySizes[] _blockSizes = new KeySizes[] { new KeySizes(128, 128, 0) };
        private static readonly KeySizes[] _keySizes = new KeySizes[] { new KeySizes(128, 128, 0) };

        #endregion Properties

        #region Constructor

        /// <summary>
        /// SM4.
        /// <para/>Legal block size 128 bits. Legal key size 128 bits.
        /// </summary>
        public SM4() : base("SM4", SymmetricAlgorithmKind.Block, _blockSizes, 128, _keySizes)
        {
        }

        #endregion Constructor

        internal override IBlockCipher GenerateEngine()
        {
            return new SM4Engine();
        }
    }
}