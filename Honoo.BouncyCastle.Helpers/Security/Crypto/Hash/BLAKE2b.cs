using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using System;
using System.Globalization;
using System.Security.Cryptography;

namespace Honoo.BouncyCastle.Helpers.Security.Crypto.Hash
{
    /// <summary>
    /// BLAKE2b.
    /// <para/>Legal hash size 8-512 bits (8 bits increments).
    /// <para/>Arguments key need null or less than 64 bytes, salt need null or less than 16 bytes, personalization need null or less than 16 bytes.
    /// </summary>
    public sealed class BLAKE2b : HashAlgorithm
    {
        #region Properties

        private static readonly KeySizes[] _hashSizes = new KeySizes[] { new KeySizes(8, 512, 8) };
        private readonly byte[] _key;
        private readonly byte[] _personalization;
        private readonly byte[] _salt;
        internal static KeySizes[] HashSizes => _hashSizes;

        #endregion Properties

        #region Constructor

        /// <summary>
        /// BLAKE2b.
        /// <para/>Legal hash size 8-512 bits (8 bits increments).
        /// <para/>Arguments key need null or less than 64 bytes, salt need null or less than 16 bytes, personalization need null or less than 16 bytes.
        /// </summary>
        /// <param name="hashSize">Hash size bits.</param>
        /// <exception cref="Exception"/>
        public BLAKE2b(int hashSize) : this(hashSize, null, null, null)
        {
        }

        /// <summary>
        /// BLAKE2b.
        /// <para/>Legal hash size 8-512 bits (8 bits increments).
        /// <para/>Arguments key need null or less than 64 bytes, salt need null or less than 16 bytes, personalization need null or less than 16 bytes.
        /// </summary>
        /// <param name="hashSize">Hash size bits.</param>
        /// <param name="key">Key bytes.</param>
        /// <param name="salt">Salt bytes.</param>
        /// <param name="personalization">Personalization bytes.</param>
        /// <exception cref="Exception"/>
        public BLAKE2b(int hashSize, byte[] key, byte[] salt, byte[] personalization)
            : base(string.Format(CultureInfo.InvariantCulture, "BLAKE2b-{0}", hashSize), _hashSizes, hashSize)
        {
            if (key != null && key.Length != 64)
            {
                throw new CryptographicException("Argument key length need null or less than 64 bytes.");
            }
            if (salt != null && key.Length != 16)
            {
                throw new CryptographicException("Argument salt length need null or less than 16 bytes.");
            }
            if (personalization != null && key.Length != 16)
            {
                throw new CryptographicException("Argument personalization length need null or less than 16 bytes.");
            }
            _key = key;
            _salt = salt;
            _personalization = personalization;
        }

        #endregion Constructor

        /// <summary>
        /// Generate digest. The digest can be reused.
        /// </summary>
        /// <returns></returns>
        public override IDigest GenerateDigest()
        {
            return new Blake2bDigest(_key, this.HashSize / 8, _salt, _personalization);
        }
    }
}