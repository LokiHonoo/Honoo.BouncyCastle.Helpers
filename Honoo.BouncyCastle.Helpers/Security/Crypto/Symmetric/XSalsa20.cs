using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using System.Security.Cryptography;

namespace Honoo.BouncyCastle.Helpers.Security.Crypto.Symmetric
{
    /// <summary>
    /// XSalsa20.
    /// <para/>Legal key size 256 bits. Legal IV size 192 bits.
    /// </summary>
    public sealed class XSalsa20 : SymmetricStreamAlgorithm
    {
        #region Properties

        private static readonly KeySizes[] _ivSizes = new KeySizes[] { new KeySizes(192, 192, 0) };
        private static readonly KeySizes[] _keySizes = new KeySizes[] { new KeySizes(256, 256, 0) };

        #endregion Properties

        #region Construction

        /// <summary>
        /// XSalsa20.
        /// <para/>Legal key size 256 bits. Legal IV size 192 bits.
        /// </summary>
        public XSalsa20() : base("XSalsa20", SymmetricAlgorithmKind.Stream, _keySizes, _ivSizes)
        {
        }

        #endregion Construction

        /// <summary>
        /// Generate engine.
        /// </summary>
        /// <returns></returns>
        protected override IStreamCipher GenerateEngine()
        {
            return new XSalsa20Engine();
        }
    }
}