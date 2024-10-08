﻿using Honoo.BouncyCastle.Helpers.Utilities;
using Org.BouncyCastle.Crypto.Digests;
using System.Security.Cryptography;

namespace Honoo.BouncyCastle.Helpers
{
    /// <summary>
    /// Using the BouncyCastle implementation of the algorithm.
    /// </summary>
    public sealed class Skein : HashAlgorithm
    {
        #region Properties

        private const int DEFAULT_STATE_SIZE = 512;
        private const string NAME = "Skein";
        private static readonly KeySizes[] LEGAL_HASH_SIZES = new KeySizes[] { new KeySizes(8, Common.IntgerMulti8Max, 8) };

        private static readonly KeySizes[] LEGAL_STATE_SIZES = new KeySizes[]
        {
            new KeySizes(256, 256, 0),
            new KeySizes(512, 512, 0),
            new KeySizes(1024, 1024, 0)
        };

        private readonly int _stateSize;
        private SkeinDigest _digest;

        #endregion Properties

        #region Construction

        /// <summary>
        /// Initializes a new instance of the Skein class.
        /// </summary>
        /// <param name="hashSize">Legal hash size is greater than or equal to 8 bits (8 bits increments).</param>
        /// <param name="stateSize">Legal state size 256, 512, 1024 bits.</param>

        public Skein(int hashSize, int stateSize = DEFAULT_STATE_SIZE) : base($"{NAME}{hashSize}-{stateSize}", hashSize)
        {
            if (!ValidHashSize(hashSize, out string exception))
            {
                throw new CryptographicException(exception);
            }
            if (!ValidStateSize(stateSize, out exception))
            {
                throw new CryptographicException(exception);
            }
            _stateSize = stateSize;
        }

        #endregion Construction

        /// <summary>
        /// Creates an instance of the algorithm.
        /// </summary>
        /// <param name="hashSize">Legal hash size is greater than or equal to 8 bits (8 bits increments).</param>
        /// <param name="stateSize">Legal state size 256, 512, 1024 bits.</param>
        /// <returns></returns>
        public static Skein Create(int hashSize, int stateSize = DEFAULT_STATE_SIZE)
        {
            return new Skein(hashSize, stateSize);
        }

        /// <inheritdoc/>
        public override int ComputeFinal(byte[] outputBuffer, int offset)
        {
            if (_digest == null)
            {
                _digest = GetDigest();
            }
            _digest.DoFinal(outputBuffer, offset);
            return base.HashSize / 8;
        }

        /// <inheritdoc/>
        public override void Reset()
        {
            _digest.Reset();
        }

        /// <inheritdoc/>
        public override void Update(byte[] inputBuffer, int offset, int length)
        {
            if (_digest == null)
            {
                _digest = GetDigest();
            }
            _digest.BlockUpdate(inputBuffer, offset, length);
        }

        internal static HashAlgorithmName GetAlgorithmName(int hashSize, int stateSize)
        {
            return new HashAlgorithmName($"{NAME}{hashSize}-{stateSize}", hashSize, () => { return new SkeinDigest(stateSize, hashSize); }, () => { return new Skein(hashSize, stateSize); });
        }

        internal static bool ValidHashSize(int hashSize, out string exception)
        {
            if (DetectionUtilities.ValidSize(LEGAL_HASH_SIZES, hashSize))
            {
                exception = string.Empty;
                return true;
            }
            else
            {
                exception = "Legal hash size is greater than or equal to 8 bits (8 bits increments).";
                return false;
            }
        }

        internal static bool ValidStateSize(int hashSize, out string exception)
        {
            if (DetectionUtilities.ValidSize(LEGAL_STATE_SIZES, hashSize))
            {
                exception = string.Empty;
                return true;
            }
            else
            {
                exception = "Legal state size 256, 512, 1024 bits.";
                return false;
            }
        }

        private SkeinDigest GetDigest()
        {
            return new SkeinDigest(_stateSize, base.HashSize);
        }
    }
}