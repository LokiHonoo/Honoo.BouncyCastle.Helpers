using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using System.Security.Cryptography;

namespace Honoo.BouncyCastle.Helpers.Security.Crypto.Symmetric
{
    /// <summary>
    /// Twofish.
    /// <para/>Legal block size 128 bits. Legal key size 64-256 bits (64 bits increments).
    /// </summary>
    public sealed class Twofish : SymmetricBlockAlgorithm
    {
        #region Properties

        private static readonly KeySizes[] _blockSizes = new KeySizes[] { new KeySizes(128, 128, 0) };
        private static readonly KeySizes[] _keySizes = new KeySizes[] { new KeySizes(64, 256, 64) };

        #endregion Properties

        #region Constructor

        /// <summary>
        /// Twofish.
        /// <para/>Legal block size 128 bits. Legal key size 64-256 bits (64 bits increments).
        /// </summary>
        public Twofish() : base("Twofish", SymmetricAlgorithmKind.Block, _blockSizes, 128, _keySizes)
        {
        }

        #endregion Constructor

        internal override IBlockCipher GenerateEngine()
        {
            return new TwofishEngine();
        }
    }
}