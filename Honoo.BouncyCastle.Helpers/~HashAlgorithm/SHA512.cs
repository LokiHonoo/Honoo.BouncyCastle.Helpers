﻿using Org.BouncyCastle.Crypto.Digests;

namespace Honoo.BouncyCastle.Helpers
{
    /// <summary>
    /// Using the BouncyCastle implementation of the algorithm.
    /// </summary>
    public sealed class SHA512 : HashAlgorithm
    {
        #region Properties

        private const int HASH_SIZE = 512;
        private const string NAME = "SHA512";
        private Sha512Digest _digest;

        #endregion Properties

        #region Construction

        /// <summary>
        /// Initializes a new instance of the SHA512 class.
        /// </summary>
        public SHA512() : base(NAME, HASH_SIZE)
        {
        }

        #endregion Construction

        /// <summary>
        /// Creates an instance of the algorithm.
        /// </summary>
        /// <returns></returns>
        public static SHA512 Create()
        {
            return new SHA512();
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

        internal static HashAlgorithmName GetAlgorithmName()
        {
            return new HashAlgorithmName(NAME, HASH_SIZE, () => { return new Sha512Digest(); }, () => { return new SHA512(); });
        }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Performance", "CA1822:将成员标记为 static", Justification = "<挂起>")]
        private Sha512Digest GetDigest()
        {
            return new Sha512Digest();
        }
    }
}