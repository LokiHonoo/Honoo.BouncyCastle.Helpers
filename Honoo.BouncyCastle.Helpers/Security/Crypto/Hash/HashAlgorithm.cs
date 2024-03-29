﻿using Honoo.BouncyCastle.Helpers.Utilities;
using Org.BouncyCastle.Crypto;
using System;
using System.Security.Cryptography;

namespace Honoo.BouncyCastle.Helpers.Security.Crypto.Hash
{
    /// <summary>
    /// Hash algorithm.
    /// </summary>
    public abstract class HashAlgorithm : IHashAlgorithm
    {
        #region Properties

        private readonly int _hashSize;
        private readonly string _name;

        /// <summary>
        /// Gets hash size bits.
        /// </summary>
        public int HashSize => _hashSize;

        /// <summary>
        /// Gets algorithm name.
        /// </summary>
        public string Name => _name;

        #endregion Properties

        #region Construction

        /// <summary>
        /// Hash algorithm.
        /// </summary>
        /// <param name="name">Hash algorithm name.</param>
        /// <param name="hashSizes">Hash sizes.</param>
        /// <param name="hashSize">Hash size bits.</param>
        /// <exception cref="CryptographicException"></exception>
        protected HashAlgorithm(string name, KeySizes[] hashSizes, int hashSize)
        {
            if (!DetectionUtilities.ValidSize(hashSizes, hashSize))
            {
                throw new CryptographicException("Unsupported hash size.");
            }
            _name = name;
            _hashSize = hashSize;
        }

        #endregion Construction

        /// <summary>
        /// Generate a new digest and compute data hash.
        /// </summary>
        /// <param name="data">Data bytes.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        public byte[] ComputeHash(byte[] data)
        {
            return ComputeHash(data, 0, data.Length);
        }

        /// <summary>
        /// Generate a new digest and compute data hash.
        /// </summary>
        /// <param name="dataBuffer">Data buffer bytes.</param>
        /// <param name="offset">The starting offset to read.</param>
        /// <param name="length">The length to read.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        public byte[] ComputeHash(byte[] dataBuffer, int offset, int length)
        {
            if (dataBuffer == null)
            {
                throw new ArgumentNullException(nameof(dataBuffer));
            }
            IDigest digest = GenerateDigest();
            digest.BlockUpdate(dataBuffer, offset, length);
            byte[] hash = new byte[_hashSize / 8];
            digest.DoFinal(hash, 0);
            return hash;
        }

        /// <summary>
        /// Generate digest. The digest can be reused.
        /// </summary>
        /// <returns></returns>
        public abstract IDigest GenerateDigest();
    }
}