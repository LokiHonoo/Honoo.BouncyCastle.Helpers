using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Utilities;

namespace Honoo.BouncyCastle.Helpers.Security.Crypto.Signature
{
    /// <summary>
    /// Ed448ph.
    /// </summary>
    public sealed class Ed448ph : SignatureAlgorithm
    {
        #region Properties

        private readonly byte[] _context;

        #endregion Properties

        #region Construction

        /// <summary>
        /// Ed448ph.
        /// <para/>Uses context byte[0] by default.
        /// </summary>
        public Ed448ph() : this(Arrays.EmptyBytes)
        {
        }

        /// <summary>
        /// Ed448ph.
        /// <para/>Uses context byte[0] by default.
        /// </summary>
        /// <param name="context">Context.</param>
        public Ed448ph(byte[] context) : base("Ed448ph", AsymmetricAlgorithms.Ed448)
        {
            _context = context ?? Arrays.EmptyBytes;
        }

        #endregion Construction

        /// <summary>
        /// Generate signer.
        /// </summary>
        /// <returns></returns>
        protected override ISigner GenerateSignerCore()
        {
            return new Ed448phSigner(_context);
        }
    }
}