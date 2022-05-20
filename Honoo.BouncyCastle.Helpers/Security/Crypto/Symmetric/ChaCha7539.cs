using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using System.Security.Cryptography;

namespace Honoo.BouncyCastle.Helpers.Security.Crypto.Symmetric
{
    /// <summary>
    /// ChaCha7539, ChaCha20.
    /// <para/>Legal key size 256 bits. Legal iv size 96 bits.
    /// </summary>
    public sealed class ChaCha7539 : StreamAlgorithm
    {
        #region Properties

        private static readonly KeySizes[] _ivSizes = new KeySizes[] { new KeySizes(96, 96, 0) };
        private static readonly KeySizes[] _keySizes = new KeySizes[] { new KeySizes(256, 256, 0) };

        #endregion Properties

        #region Constructor

        /// <summary>
        /// ChaCha7539, ChaCha20.
        /// <para/>Legal key size 256 bits. Legal iv size 96 bits.
        /// </summary>
        public ChaCha7539() : base("ChaCha7539", _keySizes, _ivSizes)
        {
        }

        #endregion Constructor

        /// <summary>
        /// Generate engine.
        /// </summary>
        /// <returns></returns>
        protected override IStreamCipher GenerateEngine()
        {
            return new ChaCha7539Engine();
        }
    }
}