using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using System;
using System.Globalization;
using System.Security.Cryptography;

namespace Honoo.BouncyCastle.Helpers.Security.Crypto.Hash
{
    /// <summary>
    /// SHA3.
    /// <para/>Legal hash size 224, 256, 384, 512 bits.
    /// </summary>
    public sealed class SHA3 : HashAlgorithm
    {
        #region Properties

        private static readonly KeySizes[] _hashSizes = new KeySizes[]
        {
            new KeySizes(224, 224, 0),
            new KeySizes(256, 256, 0),
            new KeySizes(384, 384, 0),
            new KeySizes(512, 512, 0)
        };

        #endregion Properties

        #region Construction

        /// <summary>
        /// SHA3.
        /// <para/>Legal hash size 224, 256, 384, 512 bits.
        /// </summary>
        /// <param name="hashSize">Hash size bits.</param>
        /// <exception cref="Exception"/>
        public SHA3(int hashSize) : base(string.Format(CultureInfo.InvariantCulture, "SHA3-{0}", hashSize), _hashSizes, hashSize)
        {
        }

        #endregion Construction

        /// <summary>
        /// Generate digest. The digest can be reused.
        /// </summary>
        /// <returns></returns>
        public override IDigest GenerateDigest()
        {
            return new Sha3Digest(base.HashSize);
        }
    }
}