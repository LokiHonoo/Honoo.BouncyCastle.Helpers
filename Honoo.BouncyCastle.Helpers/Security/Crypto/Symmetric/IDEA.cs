using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using System.Security.Cryptography;

namespace Honoo.BouncyCastle.Helpers.Security.Crypto.Symmetric
{
    /// <summary>
    /// IDEA.
    /// <para/>Legal block size 64 bits. Legal key size 8-128 bits (8 bits increments).
    /// </summary>
    public sealed class IDEA : BlockAlgorithm
    {
        #region Properties

        private static readonly KeySizes[] _blockSizes = new KeySizes[] { new KeySizes(64, 64, 0) };
        private static readonly KeySizes[] _keySizes = new KeySizes[] { new KeySizes(8, 128, 8) };

        #endregion Properties

        #region Constructor

        /// <summary>
        /// IDEA.
        /// <para/>Legal block size 64 bits. Legal key size 8-128 bits (8 bits increments).
        /// </summary>
        public IDEA() : base("IDEA", _blockSizes, 64, _keySizes)
        {
        }

        #endregion Constructor

        internal override IBlockCipher GenerateEngine()
        {
            return new IdeaEngine();
        }
    }
}