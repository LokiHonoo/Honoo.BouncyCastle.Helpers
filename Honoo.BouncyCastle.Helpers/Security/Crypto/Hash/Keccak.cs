using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using System;
using System.Globalization;
using System.Security.Cryptography;

namespace Honoo.BouncyCastle.Helpers.Security.Crypto.Hash
{
    /// <summary>
    /// Keccak.
    /// <para/>Legal hash size 128, 224, 256, 288, 384, 512 bits.
    /// </summary>
    public sealed class Keccak : HashAlgorithm
    {
        #region Properties

        private static readonly KeySizes[] _hashSizes = new KeySizes[]
        {
            new KeySizes(128, 128, 0),
            new KeySizes(224, 224, 0),
            new KeySizes(256, 256, 0),
            new KeySizes(288, 288, 0),
            new KeySizes(384, 384, 0),
            new KeySizes(512, 512, 0)
        };

        #endregion Properties

        #region Construction

        /// <summary>
        /// Keccak.
        /// <para/>Legal hash size 128, 224, 256, 288, 384, 512 bits.
        /// </summary>
        /// <param name="hashSize">Hash size bits.</param>
        /// <exception cref="Exception"/>
        public Keccak(int hashSize) : base(string.Format(CultureInfo.InvariantCulture, "Keccak{0}", hashSize), _hashSizes, hashSize)
        {
        }

        #endregion Construction

        /// <summary>
        /// Generate digest. The digest can be reused.
        /// </summary>
        /// <returns></returns>
        public override IDigest GenerateDigest()
        {
            return new KeccakDigest(base.HashSize);
        }
    }
}