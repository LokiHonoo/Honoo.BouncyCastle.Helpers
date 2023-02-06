using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using System.Security.Cryptography;

namespace Honoo.BouncyCastle.Helpers.Security.Crypto.Hash
{
    /// <summary>
    /// RIPEMD320.
    /// <para/>Legal hash size 320 bits.
    /// </summary>
    public sealed class RIPEMD320 : HashAlgorithm
    {
        #region Properties

        private static readonly KeySizes[] _hashSizes = new KeySizes[] { new KeySizes(320, 320, 0) };

        #endregion Properties

        #region Construction

        /// <summary>
        /// RIPEMD320.
        /// <para/>Legal hash size 320 bits.
        /// </summary>
        public RIPEMD320() : base("RIPEMD320", _hashSizes, 320)
        {
        }

        #endregion Construction

        /// <summary>
        /// Generate digest. The digest can be reused.
        /// </summary>
        /// <returns></returns>
        public override IDigest GenerateDigest()
        {
            return new RipeMD320Digest();
        }
    }
}