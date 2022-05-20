using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using System.Security.Cryptography;

namespace Honoo.BouncyCastle.Helpers.Security.Crypto.Hash
{
    /// <summary>
    /// SHA256.
    /// <para/>Legal hash size 256 bits.
    /// </summary>
    public sealed class SHA256 : HashAlgorithm
    {
        #region Properties

        private static readonly KeySizes[] _hashSizes = new KeySizes[] { new KeySizes(256, 256, 0) };

        #endregion Properties

        #region Constructor

        /// <summary>
        /// SHA256.
        /// <para/>Legal hash size 256 bits.
        /// </summary>
        public SHA256() : base("SHA256", _hashSizes, 256)
        {
        }

        #endregion Constructor

        /// <summary>
        /// Generate digest. The digest can be reused.
        /// </summary>
        /// <returns></returns>
        public override IDigest GenerateDigest()
        {
            return new Sha256Digest();
        }
    }
}