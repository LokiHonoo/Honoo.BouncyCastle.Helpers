using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using System.Security.Cryptography;

namespace Honoo.BouncyCastle.Helpers.Security.Crypto.Hash
{
    /// <summary>
    /// Whirlpool.
    /// <para/>Legal hash size 512 bits.
    /// </summary>
    public sealed class Whirlpool : HashAlgorithm
    {
        #region Properties

        private static readonly KeySizes[] _hashSizes = new KeySizes[] { new KeySizes(512, 512, 0) };

        #endregion Properties

        #region Construction

        /// <summary>
        /// Whirlpool.
        /// <para/>Legal hash size 512 bits.
        /// </summary>
        public Whirlpool() : base("Whirlpool", _hashSizes, 512)
        {
        }

        #endregion Construction

        /// <summary>
        /// Generate digest. The digest can be reused.
        /// </summary>
        /// <returns></returns>
        public override IDigest GenerateDigest()
        {
            return new WhirlpoolDigest();
        }
    }
}