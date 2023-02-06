using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using System.Security.Cryptography;

namespace Honoo.BouncyCastle.Helpers.Security.Crypto.Hash
{
    /// <summary>
    /// SM3.
    /// <para/>Legal hash size 256 bits.
    /// </summary>
    public sealed class SM3 : HashAlgorithm
    {
        #region Properties

        private static readonly KeySizes[] _hashSizes = new KeySizes[] { new KeySizes(256, 256, 0) };

        #endregion Properties

        #region Construction

        /// <summary>
        /// SM3.
        /// <para/>Legal hash size 256 bits.
        /// </summary>
        public SM3() : base("SM3", _hashSizes, 256)
        {
        }

        #endregion Construction

        /// <summary>
        /// Generate digest. The digest can be reused.
        /// </summary>
        /// <returns></returns>
        public override IDigest GenerateDigest()
        {
            return new SM3Digest();
        }
    }
}