using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;

namespace Honoo.BouncyCastle.Helpers
{
    /// <summary>
    /// Using the BouncyCastle implementation of the algorithm.
    /// </summary>
    public sealed class MD5 : HashAlgorithm
    {
        #region Properties

        private const int HASH_SIZE = 128;
        private const string NAME = "MD5";
        private MD5Digest _digest;

        #endregion Properties

        #region Construction

        /// <summary>
        /// Initializes a new instance of the MD5 class.
        /// </summary>
        public MD5() : base(NAME, HASH_SIZE)
        {
        }

        #endregion Construction

        /// <summary>
        /// Creates an instance of the algorithm.
        /// </summary>
        /// <returns></returns>
        public static MD5 Create()
        {
            return new MD5();
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
            return new HashAlgorithmName(NAME, HASH_SIZE, () => { return new MD5Digest(); }, () => { return new MD5(); });
        }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Performance", "CA1822:将成员标记为 static", Justification = "<挂起>")]
        private MD5Digest GetDigest()
        {
            return new MD5Digest();
        }
    }
}