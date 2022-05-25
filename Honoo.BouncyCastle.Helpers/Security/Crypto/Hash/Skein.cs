using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using System;
using System.Globalization;
using System.Security.Cryptography;

namespace Honoo.BouncyCastle.Helpers.Security.Crypto.Hash
{
    /// <summary>
    /// Skein.
    /// <para/>Legal hash size is greater than or equal to 8 bits (8 bits increments).
    /// <para/>Legal state size 256, 512, 1024 bits.
    /// <para/>As HMAC, hash size should be less than or equal to state size.
    /// </summary>
    public sealed class Skein : HashAlgorithm
    {
        #region Properties

        private static readonly KeySizes[] _hashSizes = new KeySizes[] { new KeySizes(8, 2147483640, 8) };
        private static readonly KeySizes[] _stateSizes = new KeySizes[] { new KeySizes(256, 256, 0), new KeySizes(512, 512, 0), new KeySizes(1024, 1024, 0) };
        private readonly int _stateSize;

        /// <summary>
        /// Gets state size bits.
        /// </summary>
        public int StateSize => _stateSize;

        internal static KeySizes[] HashSizes => _hashSizes;

        internal static KeySizes[] StateSizes => _stateSizes;

        #endregion Properties

        #region Constructor

        /// <summary>
        /// Skein.
        /// <para/>Legal hash size is greater than or equal to 8 bits (8 bits increments).
        /// <para/>Legal state size 256, 512, 1024 bits.
        /// <para/>As HMAC, hash size should be less than or equal to state size.
        /// </summary>
        /// <param name="hashSize">Hash size bits.</param>
        /// <param name="stateSize">State size bits.</param>
        /// <exception cref="Exception"/>
        public Skein(int hashSize, int stateSize) : base(string.Format(CultureInfo.InvariantCulture, "Skein-{0}-{1}", stateSize, hashSize), _hashSizes, hashSize)
        {
            if (stateSize != 256 && stateSize != 512 && stateSize != 1024)
            {
                throw new CryptographicException("Legal state size 256, 512, 1024 bits.");
            }
            _stateSize = stateSize;
        }

        #endregion Constructor

        /// <summary>
        /// Generate digest. The digest can be reused.
        /// </summary>
        /// <returns></returns>
        public override IDigest GenerateDigest()
        {
            return new SkeinDigest(_stateSize, base.HashSize);
        }
    }
}