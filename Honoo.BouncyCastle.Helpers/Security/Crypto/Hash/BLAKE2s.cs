using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using System;
using System.Globalization;
using System.Security.Cryptography;

namespace Honoo.BouncyCastle.Helpers.Security.Crypto.Hash
{
    /// <summary>
    /// BLAKE2s.
    /// <para/>Legal hash size 8-256 bits (8 bits increments).
    /// <para/>Arguments key need null or less than 32 bytes, salt need null or less than 8 bytes, personalization need null or less than 8 bytes.
    /// </summary>
    public sealed class BLAKE2s : HashAlgorithm
    {
        #region Properties

        private static readonly KeySizes[] _hashSizes = new KeySizes[] { new KeySizes(8, 256, 8) };
        private readonly byte[] _key;
        private readonly byte[] _personalization;
        private readonly byte[] _salt;

        internal static KeySizes[] HashSizes => _hashSizes;

        #endregion Properties

        #region Construction

        /// <summary>
        /// BLAKE2s.
        /// <para/>Legal hash size 8-256 bits (8 bits increments).
        /// <para/>Arguments key need null or less than 32 bytes, salt need null or less than 8 bytes, personalization need null or less than 8 bytes.
        /// </summary>
        /// <param name="hashSize">Hash size bits.</param>
        /// <exception cref="Exception"/>
        public BLAKE2s(int hashSize) : this(hashSize, null, null, null)
        {
        }

        /// <summary>
        /// BLAKE2s.
        /// <para/>Legal hash size 8-256 bits (8 bits increments).
        /// <para/>Arguments key need null or less than 32 bytes, salt need null or less than 8 bytes, personalization need null or less than 8 bytes.
        /// </summary>
        /// <param name="hashSize">Hash size bits.</param>
        /// <param name="key">Key bytes.</param>
        /// <param name="salt">Salt bytes.</param>
        /// <param name="personalization">Personalization bytes.</param>
        /// <exception cref="Exception"/>
        public BLAKE2s(int hashSize, byte[] key, byte[] salt, byte[] personalization)
            : base(string.Format(CultureInfo.InvariantCulture, "BLAKE2s{0}", hashSize), _hashSizes, hashSize)
        {
            if (key != null && key.Length != 32)
            {
                throw new CryptographicException("Argument key length need null or less than 32 bytes.");
            }
            if (salt != null && key.Length != 8)
            {
                throw new CryptographicException("Argument salt length need null or less than 8 bytes.");
            }
            if (personalization != null && key.Length != 8)
            {
                throw new CryptographicException("Argument personalization length need null or less than 8 bytes.");
            }
            _key = key;
            _salt = salt;
            _personalization = personalization;
        }

        #endregion Construction

        /// <summary>
        /// Generate digest. The digest can be reused.
        /// </summary>
        /// <returns></returns>
        public override IDigest GenerateDigest()
        {
            return new Blake2sDigest(_key, base.HashSize / 8, _salt, _personalization);
        }
    }
}