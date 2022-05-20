using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using System.Security.Cryptography;

namespace Honoo.BouncyCastle.Helpers.Security.Crypto.Hash
{
    /// <summary>
    /// RIPEMD160.
    /// <para/>Legal hash size 160 bits.
    /// </summary>
    public sealed class RIPEMD160 : HashAlgorithm
    {
        #region Properties

        private static readonly KeySizes[] _hashSizes = new KeySizes[] { new KeySizes(160, 160, 0) };

        #endregion Properties

        #region Constructor

        /// <summary>
        /// RIPEMD160.
        /// <para/>Legal hash size 160 bits.
        /// </summary>
        public RIPEMD160() : base("RIPEMD160", _hashSizes, 160)
        {
        }

        #endregion Constructor

        /// <summary>
        /// Generate digest. The digest can be reused.
        /// </summary>
        /// <returns></returns>
        public override IDigest GenerateDigest()
        {
            return new RipeMD160Digest();
        }
    }
}