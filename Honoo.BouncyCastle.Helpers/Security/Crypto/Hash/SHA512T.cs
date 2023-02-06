using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using System;
using System.Globalization;
using System.Security.Cryptography;

namespace Honoo.BouncyCastle.Helpers.Security.Crypto.Hash
{
    /// <summary>
    /// SHA512T.
    /// <para/>Legal hash size 224-376 bits (8 bits increments), 392-504 bits (8 bitsincrements).
    /// </summary>
    public sealed class SHA512T : HashAlgorithm
    {
        #region Properties

        private static readonly KeySizes[] _hashSizes = new KeySizes[] { new KeySizes(224, 376, 8), new KeySizes(392, 504, 8) };

        internal static KeySizes[] HashSizes => _hashSizes;

        #endregion Properties

        #region Construction

        /// <summary>
        /// SHA512T.
        /// <para/>Legal hash size 224-376 bits (8 bits increments), 392-504 bits (8 bitsincrements).
        /// </summary>
        /// <param name="hashSize">Hash size bits.</param>
        /// <exception cref="Exception"/>
        public SHA512T(int hashSize) : base(string.Format(CultureInfo.InvariantCulture, "SHA512/{0}", hashSize), _hashSizes, hashSize)
        {
        }

        #endregion Construction

        /// <summary>
        /// Generate digest. The digest can be reused.
        /// </summary>
        /// <returns></returns>
        public override IDigest GenerateDigest()
        {
            return new Sha512tDigest(base.HashSize);
        }
    }
}