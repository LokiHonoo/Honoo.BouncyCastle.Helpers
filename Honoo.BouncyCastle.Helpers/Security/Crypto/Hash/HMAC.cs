﻿using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.Globalization;

namespace Honoo.BouncyCastle.Helpers.Security.Crypto.Hash
{
    /// <summary>
    /// HMAC.
    /// </summary>
    public sealed class HMAC : IHMAC
    {
        #region Properties

        private readonly IHashAlgorithm _hashAlgorithm;
        private readonly string _name;

        /// <summary>
        /// Gets hash size bits.
        /// </summary>
        public int HashSize => _hashAlgorithm.HashSize;

        /// <summary>
        /// Gets algorithm name.
        /// </summary>
        public string Name => _name;

        #endregion Properties

        #region Construction

        /// <summary>
        /// HMAC.
        /// </summary>
        /// <param name="hashAlgorithm">Hash algorithm.</param>
        public HMAC(IHashAlgorithm hashAlgorithm)
        {
            _name = string.Format(CultureInfo.InvariantCulture, "{0}/HMAC", hashAlgorithm.Name);
            _hashAlgorithm = hashAlgorithm;
        }

        #endregion Construction

        /// <summary>
        /// Generate a new digest and compute data hash.
        /// </summary>
        /// <param name="parameters">Parameters.</param>
        /// <param name="data">Data bytes.</param>
        /// <returns></returns>
        public byte[] ComputeHash(ICipherParameters parameters, byte[] data)
        {
            return ComputeHash(parameters, data, 0, data.Length);
        }

        /// <summary>
        /// Generate a new digest and compute data hash.
        /// </summary>
        /// <param name="parameters">Parameters.</param>
        /// <param name="dataBuffer">Data buffer bytes.</param>
        /// <param name="offset">The starting offset to read.</param>
        /// <param name="length">The length to read.</param>
        /// <returns></returns>
        public byte[] ComputeHash(ICipherParameters parameters, byte[] dataBuffer, int offset, int length)
        {
            if (parameters == null)
            {
                throw new ArgumentNullException(nameof(parameters));
            }
            if (dataBuffer == null)
            {
                throw new ArgumentNullException(nameof(dataBuffer));
            }
            IMac digest = GenerateDigest(parameters);
            digest.BlockUpdate(dataBuffer, offset, length);
            byte[] hash = new byte[_hashAlgorithm.HashSize];
            digest.DoFinal(hash, 0);
            return hash;
        }

        /// <summary>
        /// Generate digest. The digest can be reused.
        /// </summary>
        /// <param name="parameters">Parameters.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        public IMac GenerateDigest(ICipherParameters parameters)
        {
            IMac digest = new HMac(_hashAlgorithm.GenerateDigest());
            digest.Init(parameters);
            return digest;
        }

        /// <summary>
        /// Generate parameters.
        /// </summary>
        /// <param name="key">Any length can be used except null.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        public ICipherParameters GenerateParameters(byte[] key)
        {
            return new KeyParameter(key);
        }

        /// <summary>
        /// Generate parameters.
        /// </summary>
        /// <param name="keyBuffer">Key buffer bytes.</param>
        /// <param name="offset">The starting offset to read.</param>
        /// <param name="length">The length to read.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        public ICipherParameters GenerateParameters(byte[] keyBuffer, int offset, int length)
        {
            return new KeyParameter(keyBuffer, offset, length);
        }

        /// <summary>
        /// Verify key size.
        /// </summary>
        /// <param name="keySize">Key size bits.</param>
        /// <returns></returns>
        public bool VerifyKeySize(int keySize)
        {
            return keySize > 0 && keySize % 8 == 0;
        }
    }
}