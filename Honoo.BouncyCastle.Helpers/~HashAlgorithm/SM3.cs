using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using System;

namespace Honoo.BouncyCastle.Helpers
{
    /// <summary>
    /// Using the BouncyCastle implementation of the algorithm.
    /// </summary>
    public sealed class SM3 : HashAlgorithm
    {
        #region Properties

        private const int HASH_SIZE = 256;
        private const string NAME = "SM3";
        private SM3Digest _digest;

        #endregion Properties

        #region Construction

        /// <summary>
        /// Initializes a new instance of the SM3 class.
        /// </summary>
        public SM3() : base(NAME, HASH_SIZE)
        {
        }

        #endregion Construction

        /// <summary>
        /// Creates an instance of the algorithm.
        /// </summary>
        /// <returns></returns>
        public static SM3 Create()
        {
            return new SM3();
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
            return new HashAlgorithmName(NAME, HASH_SIZE, () => { return new SM3Digest(); }, () => { return new SM3(); });
        }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Performance", "CA1822:将成员标记为 static", Justification = "<挂起>")]
        private SM3Digest GetDigest()
        {
            return new SM3Digest();
        }
    }
}