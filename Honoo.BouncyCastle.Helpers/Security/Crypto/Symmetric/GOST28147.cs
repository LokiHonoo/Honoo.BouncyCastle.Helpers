using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using System.Security.Cryptography;

namespace Honoo.BouncyCastle.Helpers.Security.Crypto.Symmetric
{
    /// <summary>
    /// GOST28147.
    /// <para/>Legal block size 64 bits. Legal key size 256 bits.
    /// </summary>
    public sealed class GOST28147 : BlockAlgorithm
    {
        #region Properties

        private static readonly KeySizes[] _blockSizes = new KeySizes[] { new KeySizes(64, 64, 0) };
        private static readonly KeySizes[] _keySizes = new KeySizes[] { new KeySizes(256, 256, 0) };

        #endregion Properties

        #region Constructor

        /// <summary>
        /// GOST28147.
        /// <para/>Legal block size 64 bits. Legal key size 256 bits.
        /// </summary>
        public GOST28147() : base("GOST28147", _blockSizes, 64, _keySizes)
        {
        }

        #endregion Constructor

        internal override IBlockCipher GenerateEngine()
        {
            return new Gost28147Engine();
        }
    }
}