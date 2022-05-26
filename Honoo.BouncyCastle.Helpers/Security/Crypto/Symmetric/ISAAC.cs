using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using System.Security.Cryptography;

namespace Honoo.BouncyCastle.Helpers.Security.Crypto.Symmetric
{
    /// <summary>
    /// ISAAC.
    /// <para/>Legal key size 64-8192 bits (16 bits increments). Not need IV.
    /// </summary>
    public sealed class ISAAC : SymmetricStreamAlgorithm
    {
        #region Properties

        private static readonly KeySizes[] _ivSizes = new KeySizes[] { new KeySizes(0, 0, 0) };
        private static readonly KeySizes[] _keySizes = new KeySizes[] { new KeySizes(64, 8192, 16) };

        #endregion Properties

        #region Constructor

        /// <summary>
        /// ISAAC.
        /// <para/>Legal key size 64-8192 bits (16 bits increments). Not need IV.
        /// </summary>
        public ISAAC() : base("ISAAC", SymmetricAlgorithmKind.Stream, _keySizes, _ivSizes)
        {
        }

        #endregion Constructor

        /// <summary>
        /// Generate engine.
        /// </summary>
        /// <returns></returns>
        protected override IStreamCipher GenerateEngine()
        {
            return new IsaacEngine();
        }
    }
}