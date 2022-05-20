using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using System.Security.Cryptography;

namespace Honoo.BouncyCastle.Helpers.Security.Crypto.Symmetric
{
    /// <summary>
    /// TEA.
    /// <para/>Legal block size 64 bits. Legal key size 128 bits.
    /// </summary>
    public sealed class TEA : BlockAlgorithm
    {
        #region Properties

        private static readonly KeySizes[] _blockSizes = new KeySizes[] { new KeySizes(64, 64, 0) };
        private static readonly KeySizes[] _keySizes = new KeySizes[] { new KeySizes(128, 128, 0) };

        #endregion Properties

        #region Constructor

        /// <summary>
        /// TEA.
        /// <para/>Legal block size 64 bits. Legal key size 128 bits.
        /// </summary>
        public TEA() : base("TEA", _blockSizes, 64, _keySizes)
        {
        }

        #endregion Constructor

        internal override IBlockCipher GenerateEngine()
        {
            return new TeaEngine();
        }
    }
}