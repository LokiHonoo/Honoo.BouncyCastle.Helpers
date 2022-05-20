using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using System.Security.Cryptography;

namespace Honoo.BouncyCastle.Helpers.Security.Crypto.Hash
{
    /// <summary>
    /// RIPEMD256.
    /// <para/>Legal hash size 256 bits.
    /// </summary>
    public sealed class RIPEMD256 : HashAlgorithm
    {
        #region Properties

        private static readonly KeySizes[] _hashSizes = new KeySizes[] { new KeySizes(256, 256, 0) };

        #endregion Properties

        #region Constructor

        /// <summary>
        /// RIPEMD256.
        /// <para/>Legal hash size 256 bits.
        /// </summary>
        public RIPEMD256() : base("RIPEMD256", _hashSizes, 256)
        {
        }

        #endregion Constructor

        /// <summary>
        /// Generate digest. The digest can be reused.
        /// </summary>
        /// <returns></returns>
        public override IDigest GenerateDigest()
        {
            return new RipeMD256Digest();
        }
    }
}