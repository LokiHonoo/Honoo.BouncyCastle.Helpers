using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using System.Security.Cryptography;

namespace Honoo.BouncyCastle.Helpers.Security.Crypto.Hash
{
    /// <summary>
    /// Tiger.
    /// <para/>Legal hash size 192 bits.
    /// </summary>
    public sealed class Tiger : HashAlgorithm
    {
        #region Properties

        private static readonly KeySizes[] _hashSizes = new KeySizes[] { new KeySizes(192, 192, 0) };

        #endregion Properties

        #region Construction

        /// <summary>
        /// Tiger.
        /// <para/>Legal hash size 192 bits.
        /// </summary>
        public Tiger() : base("Tiger", _hashSizes, 192)
        {
        }

        #endregion Construction

        /// <summary>
        /// Generate digest. The digest can be reused.
        /// </summary>
        /// <returns></returns>
        public override IDigest GenerateDigest()
        {
            return new TigerDigest();
        }
    }
}