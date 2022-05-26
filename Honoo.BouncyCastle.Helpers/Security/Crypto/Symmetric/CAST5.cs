using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using System.Security.Cryptography;

namespace Honoo.BouncyCastle.Helpers.Security.Crypto.Symmetric
{
    /// <summary>
    /// CAST5.
    /// <para/>Legal block size 64 bits. Legal key size 40-128 bits (8 bits increments).
    /// </summary>
    public sealed class CAST5 : SymmetricBlockAlgorithm
    {
        #region Properties

        private static readonly KeySizes[] _blockSizes = new KeySizes[] { new KeySizes(64, 64, 0) };
        private static readonly KeySizes[] _keySizes = new KeySizes[] { new KeySizes(40, 128, 8) };

        #endregion Properties

        #region Constructor

        /// <summary>
        /// CAST5.
        /// <para/>Legal block size 64 bits. Legal key size 40-128 bits (8 bits increments).
        /// </summary>
        public CAST5() : base("CAST5", SymmetricAlgorithmKind.Block, _blockSizes, 64, _keySizes)
        {
        }

        #endregion Constructor

        internal override IBlockCipher GenerateEngine()
        {
            return new Cast5Engine();
        }
    }
}