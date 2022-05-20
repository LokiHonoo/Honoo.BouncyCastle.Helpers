using Org.BouncyCastle.Crypto;
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

        /// <summary>
        /// Gets hash size bits.
        /// </summary>
        public int HashSize => _hashAlgorithm.HashSize;

        /// <summary>
        /// Gets mechanism.
        /// </summary>
        public string Mechanism { get; }

        #endregion Properties

        #region Constructor

        /// <summary>
        /// HMAC.
        /// </summary>
        /// <param name="hashAlgorithm">Hash algorithm.</param>
        public HMAC(IHashAlgorithm hashAlgorithm)
        {
            this.Mechanism = string.Format(CultureInfo.InvariantCulture, "{0}/HMAC", hashAlgorithm.Mechanism);
            _hashAlgorithm = hashAlgorithm;
        }

        #endregion Constructor

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
        /// <param name="data">Data buffer bytes.</param>
        /// <param name="offset">The starting offset to read.</param>
        /// <param name="length">The length to read.</param>
        /// <returns></returns>
        public byte[] ComputeHash(ICipherParameters parameters, byte[] data, int offset, int length)
        {
            IMac digest = GenerateDigest(parameters);
            digest.BlockUpdate(data, offset, length);
            byte[] hash = new byte[this.HashSize];
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
        /// <param name="key">Key buffer.</param>
        /// <param name="offset">The starting offset to read.</param>
        /// <param name="length">The length to read.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        public ICipherParameters GenerateParameters(byte[] key, int offset, int length)
        {
            return new KeyParameter(key, offset, length);
        }

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