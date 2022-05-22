using Honoo.BouncyCastle.Helpers.Utilities;
using Org.BouncyCastle.Crypto;
using System.Security.Cryptography;

namespace Honoo.BouncyCastle.Helpers.Security.Crypto.Hash
{
    /// <summary>
    /// Hash algorithm.
    /// </summary>
    public abstract class HashAlgorithm : IHashAlgorithm
    {
        #region Properties

        /// <summary>
        /// Gets hash size bits.
        /// </summary>
        public int HashSize { get; }

        /// <summary>
        /// Gets mechanism.
        /// </summary>
        public string Mechanism { get; }

        #endregion Properties

        #region Constructor

        /// <summary>
        /// Hash algorithm.
        /// </summary>
        /// <param name="mechanism">Hash algorithm mechanism.</param>
        /// <param name="hashSizes">Hash sizes.</param>
        /// <param name="hashSize">Hash size.</param>
        /// <exception cref="CryptographicException"></exception>
        protected HashAlgorithm(string mechanism, KeySizes[] hashSizes, int hashSize)
        {
            if (!DetectionUtilities.ValidSize(hashSizes, hashSize))
            {
                throw new CryptographicException("Unsupported hash size.");
            }
            this.Mechanism = mechanism;
            this.HashSize = hashSize;
        }

        #endregion Constructor

        /// <summary>
        /// Generate a new digest and compute data hash.
        /// </summary>
        /// <param name="data">Data bytes.</param>
        /// <returns></returns>
        public byte[] ComputeHash(byte[] data)
        {
            return ComputeHash(data, 0, data.Length);
        }

        /// <summary>
        /// Generate a new digest and compute data hash.
        /// </summary>
        /// <param name="data">Data buffer bytes.</param>
        /// <param name="offset">The starting offset to read.</param>
        /// <param name="length">The length to read.</param>
        /// <returns></returns>
        public byte[] ComputeHash(byte[] data, int offset, int length)
        {
            IDigest digest = GenerateDigest();
            digest.BlockUpdate(data, offset, length);
            byte[] hash = new byte[this.HashSize];
            digest.DoFinal(hash, 0);
            return hash;
        }

        /// <summary>
        /// Generate digest. The digest can be reused.
        /// </summary>
        /// <returns></returns>
        public abstract IDigest GenerateDigest();

        /// <summary>
        /// Return mechanism.
        /// </summary>
        /// <returns></returns>
        public override string ToString()
        {
            return this.Mechanism;
        }
    }
}