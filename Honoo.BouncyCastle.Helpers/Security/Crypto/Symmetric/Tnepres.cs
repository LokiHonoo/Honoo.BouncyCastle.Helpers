using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using System.Security.Cryptography;

namespace Honoo.BouncyCastle.Helpers.Security.Crypto.Symmetric
{
    /// <summary>
    /// Tnepres.
    /// <para/>Legal block size 128 bits. Legal key size 32-512 bits (32 bits increments).
    /// </summary>
    public sealed class Tnepres : BlockAlgorithm
    {
        #region Properties

        private static readonly KeySizes[] _blockSizes = new KeySizes[] { new KeySizes(128, 128, 0) };
        private static readonly KeySizes[] _keySizes = new KeySizes[] { new KeySizes(32, 512, 32) };

        #endregion Properties

        #region Constructor

        /// <summary>
        /// Tnepres.
        /// <para/>Legal block size 128 bits. Legal key size 32-512 bits (32 bits increments).
        /// </summary>
        public Tnepres() : base("Tnepres", _blockSizes, 128, _keySizes)
        {
        }

        #endregion Constructor

        internal override IBlockCipher GenerateEngine()
        {
            return new TnepresEngine();
        }
    }
}