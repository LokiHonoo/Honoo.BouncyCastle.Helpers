using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using System.Security.Cryptography;

namespace Honoo.BouncyCastle.Helpers.Security.Crypto.Hash
{
    /// <summary>
    /// SHA384.
    /// <para/>Legal hash size 384 bits.
    /// </summary>
    public sealed class SHA384 : HashAlgorithm
    {
        #region Properties

        private static readonly KeySizes[] _hashSizes = new KeySizes[] { new KeySizes(384, 384, 0) };

        #endregion Properties

        #region Constructor

        /// <summary>
        /// SHA384.
        /// <para/>Legal hash size 384 bits.
        /// </summary>
        public SHA384() : base("SHA384", _hashSizes, 384)
        {
        }

        #endregion Constructor

        /// <summary>
        /// Generate digest. The digest can be reused.
        /// </summary>
        /// <returns></returns>
        public override IDigest GenerateDigest()
        {
            return new Sha384Digest();
        }
    }
}