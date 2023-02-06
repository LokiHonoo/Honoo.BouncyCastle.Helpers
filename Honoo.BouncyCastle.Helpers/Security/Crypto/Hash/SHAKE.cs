using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using System;
using System.Globalization;
using System.Security.Cryptography;

namespace Honoo.BouncyCastle.Helpers.Security.Crypto.Hash
{
    /// <summary>
    /// SHAKE.
    /// <para/>Legal hash size 128, 256 bits.
    /// </summary>
    public sealed class SHAKE : HashAlgorithm
    {
        #region Properties

        private static readonly KeySizes[] _hashSizes = new KeySizes[] { new KeySizes(128, 256, 128) };

        #endregion Properties

        #region Construction

        /// <summary>
        /// SHAKE.
        /// <para/>Legal hash size 128, 256 bits.
        /// </summary>
        /// <param name="hashSize">Hash size bits.</param>
        /// <exception cref="Exception"/>
        public SHAKE(int hashSize) : base(string.Format(CultureInfo.InvariantCulture, "SHAKE{0}", hashSize), _hashSizes, hashSize)
        {
        }

        #endregion Construction

        /// <summary>
        /// Generate digest. The digest can be reused.
        /// </summary>
        /// <returns></returns>
        public override IDigest GenerateDigest()
        {
            return new ShakeDigest(base.HashSize);
        }
    }
}