using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using System.Security.Cryptography;

namespace Honoo.BouncyCastle.Helpers.Security.Crypto.Hash
{
    /// <summary>
    /// SHA224.
    /// <para/>Legal hash size 224 bits.
    /// </summary>
    public sealed class SHA224 : HashAlgorithm
    {
        #region Properties

        private static readonly KeySizes[] _hashSizes = new KeySizes[] { new KeySizes(224, 224, 0) };

        #endregion Properties

        #region Constructor

        /// <summary>
        /// SHA224.
        /// <para/>Legal hash size 224 bits.
        /// </summary>
        public SHA224() : base("SHA224", _hashSizes, 224)
        {
        }

        #endregion Constructor

        /// <summary>
        /// Generate digest. The digest can be reused.
        /// </summary>
        /// <returns></returns>
        public override IDigest GenerateDigest()
        {
            return new Sha224Digest();
        }
    }
}