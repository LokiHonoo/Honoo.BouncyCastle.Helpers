﻿using Honoo.BouncyCastle.Helpers.Utilities;
using Org.BouncyCastle.Crypto.Digests;
using System.Security.Cryptography;

namespace Honoo.BouncyCastle.Helpers
{
    /// <summary>
    /// Using the BouncyCastle implementation of the algorithm.
    /// </summary>
    public sealed class DSTU7564 : HashAlgorithm
    {
        #region Properties

        private const string NAME = "DSTU7564-";
        private static readonly KeySizes[] LEGAL_HASH_SIZES = new KeySizes[] { new KeySizes(256, 512, 128) };
        private Dstu7564Digest _digest;

        #endregion Properties

        #region Construction

        /// <summary>
        /// Initializes a new instance of the DSTU7564 class.
        /// </summary>
        /// <param name="hashSize">Legal hash size 256, 384, 512 bits.</param>
        public DSTU7564(int hashSize) : base($"{NAME}{hashSize}", hashSize)
        {
            if (!ValidHashSize(hashSize, out string exception))
            {
                throw new CryptographicException(exception);
            }
        }

        #endregion Construction

        /// <summary>
        /// Creates an instance of the algorithm.
        /// </summary>
        /// <param name="hashSize">Legal hash size 256, 384, 512 bits.</param>
        /// <returns></returns>
        public static DSTU7564 Create(int hashSize)
        {
            return new DSTU7564(hashSize);
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

        internal static HashAlgorithmName GetAlgorithmName(int hashSize)
        {
            return new HashAlgorithmName($"{NAME}{hashSize}", hashSize, () => { return new Dstu7564Digest(hashSize); }, () => { return new DSTU7564(hashSize); });
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
                exception = "Legal hash size 256, 384, 512 bits.";
                return false;
            }
        }

        private Dstu7564Digest GetDigest()
        {
            return new Dstu7564Digest(base.HashSize);
        }
    }
}