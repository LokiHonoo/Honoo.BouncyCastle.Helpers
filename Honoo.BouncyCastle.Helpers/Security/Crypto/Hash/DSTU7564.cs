using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using System;
using System.Globalization;
using System.Security.Cryptography;

namespace Honoo.BouncyCastle.Helpers.Security.Crypto.Hash
{
    /// <summary>
    /// DSTU7564.
    /// <para/>Legal hash size 256, 384, 512 bits.
    /// </summary>
    public sealed class DSTU7564 : HashAlgorithm
    {
        #region Properties

        private static readonly KeySizes[] _hashSizes = new KeySizes[] { new KeySizes(256, 512, 128) };

        #endregion Properties

        #region Construction

        /// <summary>
        /// DSTU7564.
        /// <para/>Legal hash size 256, 384, 512 bits.
        /// </summary>
        /// <param name="hashSize">Hash size bits.</param>
        /// <exception cref="Exception"/>
        public DSTU7564(int hashSize) : base(string.Format(CultureInfo.InvariantCulture, "DSTU7564-{0}", hashSize), _hashSizes, hashSize)
        {
        }

        #endregion Construction

        /// <summary>
        /// Generate digest. The digest can be reused.
        /// </summary>
        /// <returns></returns>
        public override IDigest GenerateDigest()
        {
            return new Dstu7564Digest(base.HashSize);
        }
    }
}