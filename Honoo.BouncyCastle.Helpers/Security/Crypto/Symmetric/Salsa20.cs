using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using System.Security.Cryptography;

namespace Honoo.BouncyCastle.Helpers.Security.Crypto.Symmetric
{
    /// <summary>
    /// Salsa20.
    /// <para/>Legal key size 128, 256 bits. Legal iv size 64 bits.
    /// <para/>Uses rounds 20 by default.
    /// </summary>
    public sealed class Salsa20 : StreamAlgorithm
    {
        #region Properties

        private static readonly KeySizes[] _ivSizes = new KeySizes[] { new KeySizes(64, 64, 0) };
        private static readonly KeySizes[] _keySizes = new KeySizes[] { new KeySizes(128, 256, 128) };
        private readonly int _rounds;

        #endregion Properties

        #region Constructor

        /// <summary>
        /// Salsa20.
        /// <para/>Legal key size 128, 256 bits. Legal iv size 64 bits.
        /// <para/>Uses rounds 20 by default.
        /// </summary>
        public Salsa20() : this(20)
        {
        }

        /// <summary>
        /// Salsa20.
        /// <para/>Legal key size 128, 256 bits. Legal iv size 64 bits.
        /// <para/>Uses rounds 20 by default.
        /// </summary>
        /// <param name="rounds">Rounds. Must be an even number.</param>
        public Salsa20(int rounds) : base("Salsa20", SymmetricAlgorithmKind.Stream, _keySizes, _ivSizes)
        {
            _rounds = rounds;
        }

        #endregion Constructor

        /// <summary>
        /// Generate engine.
        /// </summary>
        /// <returns></returns>
        protected override IStreamCipher GenerateEngine()
        {
            return new Salsa20Engine(_rounds);
        }
    }
}