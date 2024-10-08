﻿using Honoo.BouncyCastle.Helpers.Utilities;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.Security.Cryptography;

namespace Honoo.BouncyCastle.Helpers
{
    /// <summary>
    /// Computes a HMAC using the specified hash algorithm.
    /// </summary>
    public sealed class HMAC : HashAlgorithm
    {
        #region Properties

        private const int DEFAULT_KEY_SIZE = 128;
        private static readonly KeySizes[] LEGAL_KEY_SIZES = new KeySizes[] { new KeySizes(8, Common.IntgerMulti8Max, 8) };
        private readonly IDigest _core;
        private HMac _digest;
        private bool _initialized;
        private int _keySize = DEFAULT_KEY_SIZE;
        private KeyParameter _parameters;

        /// <summary>
        /// Gets key size bits.
        /// </summary>
        public int KeySize => _keySize;

        #endregion Properties

        #region Construction

        /// <summary>
        /// Initializes a new instance of the HMAC class.
        /// </summary>
        /// <param name="algorithmName">HMAC name.</param>
        public HMAC(HMACName algorithmName) : base(algorithmName == null ? throw new ArgumentNullException(nameof(algorithmName)) : algorithmName.Name, algorithmName.HashSize)
        {
            _core = algorithmName.HashAlgorithmName.GetEngine();
        }

        #endregion Construction

        /// <summary>
        /// Creates an instance of the algorithm by algorithm name.
        /// </summary>
        /// <param name="algorithmName">HMAC name.</param>
        /// <returns></returns>
        public static HMAC Create(HMACName algorithmName)
        {
            return new HMAC(algorithmName);
        }

        /// <inheritdoc/>
        public override int ComputeFinal(byte[] outputBuffer, int offset)
        {
            InspectParameters();
            if (_digest == null)
            {
                _digest = GetDigest();
            }
            _digest.DoFinal(outputBuffer, offset);
            return base.HashSize / 8;
        }

        /// <summary>
        /// Exports a <see cref="ICipherParameters"/> containing the HMAC parameters information associated.
        /// </summary>
        /// <returns></returns>
        public ICipherParameters ExportParameters()
        {
            InspectParameters();
            return _parameters;
        }

        /// <summary>
        /// Exports key.
        /// </summary>
        /// <param name="key">Output key bytes.</param>
        /// <returns></returns>
        public void ExportParameters(out byte[] key)
        {
            InspectParameters();
            key = _parameters.GetKey();
        }

        /// <summary>
        /// Renew parameters of the algorithm by default key size.
        /// </summary>
        public void GenerateParameters()
        {
            byte[] key = new byte[DEFAULT_KEY_SIZE / 8];
            Common.SecureRandom.Value.NextBytes(key);
            _parameters = new KeyParameter(key);
            _keySize = DEFAULT_KEY_SIZE;
            _digest = null;
            _initialized = true;
        }

        /// <summary>
        /// Renew parameters of the algorithm.
        /// </summary>
        /// <param name="keySize">Legal key size is more than or equal to 8 bits (8 bits increments).</param>
        public void GenerateParameters(int keySize)
        {
            if (!ValidKeySize(keySize, out string exception))
            {
                throw new CryptographicException(exception);
            }
            byte[] key = new byte[keySize / 8];
            Common.SecureRandom.Value.NextBytes(key);
            _parameters = new KeyParameter(key);
            _keySize = keySize;
            _digest = null;
            _initialized = true;
        }

        /// <summary>
        /// Imports a <see cref="ICipherParameters"/> that represents HMAC parameters information.
        /// </summary>
        /// <param name="parameters">A BouncyCastle <see cref="ICipherParameters"/> that represents an HMAC parameters.</param>
        public void ImportParameters(ICipherParameters parameters)
        {
            if (parameters == null)
            {
                throw new ArgumentNullException(nameof(parameters));
            }
            byte[] key = ((KeyParameter)parameters).GetKey();
            int keySize = key.Length * 8;
            if (!ValidKeySize(keySize, out string exception))
            {
                throw new CryptographicException(exception);
            }
            _parameters = new KeyParameter(key);
            _keySize = keySize;
            _digest = null;
            _initialized = true;
        }

        /// <summary>
        /// Imports key.
        /// </summary>
        /// <param name="key">Legal key size is more than or equal to 8 bits (8 bits increments).</param>
        public void ImportParameters(byte[] key)
        {
            if (key == null)
            {
                throw new ArgumentNullException(nameof(key));
            }
            int keySize = key.Length * 8;
            if (!ValidKeySize(keySize, out string exception))
            {
                throw new CryptographicException(exception);
            }
            _parameters = new KeyParameter(key);
            _keySize = keySize;
            _digest = null;
            _initialized = true;
        }

        /// <inheritdoc/>
        public override void Reset()
        {
            _digest.Reset();
        }

        /// <summary>
        /// Compute data hash.
        /// </summary>
        /// <param name="inputBuffer">The data buffer to be hash.</param>
        /// <param name="offset">The starting offset to read.</param>
        /// <param name="length">The length to read.</param>
        public override void Update(byte[] inputBuffer, int offset, int length)
        {
            InspectParameters();
            if (_digest == null)
            {
                _digest = GetDigest();
            }
            _digest.BlockUpdate(inputBuffer, offset, length);
        }

        /// <summary>
        /// Determines whether the specified size is valid for the current algorithm.
        /// </summary>
        /// <param name="keySize">Legal key size is more than or equal to 8 bits (8 bits increments).</param>
        /// <param name="exception">Exception message.</param>
        /// <returns></returns>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Performance", "CA1822:将成员标记为 static", Justification = "<挂起>")]
        public bool ValidKeySize(int keySize, out string exception)
        {
            if (DetectionUtilities.ValidSize(LEGAL_KEY_SIZES, keySize))
            {
                exception = string.Empty;
                return true;
            }
            else
            {
                exception = "Legal key size is more than or equal to 8 bits (8 bits increments).";
                return false;
            }
        }

        private HMac GetDigest()
        {
            HMac digest = new HMac(_core);
            digest.Init(_parameters);
            return digest;
        }

        private void InspectParameters()
        {
            if (!_initialized)
            {
                GenerateParameters();
            }
        }
    }
}