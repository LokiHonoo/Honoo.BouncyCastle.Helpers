using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Utilities;

namespace Honoo.BouncyCastle.Helpers.Security.Crypto.Signature
{
    /// <summary>
    /// Ed448.
    /// </summary>
    public sealed class Ed448 : SignatureAlgorithm
    {
        #region Properties

        private readonly byte[] _context;

        #endregion Properties

        #region Construction

        /// <summary>
        /// Ed448.
        /// <para/>Uses context byte[0] by default.
        /// </summary>
        public Ed448() : this(Arrays.EmptyBytes)
        {
        }

        /// <summary>
        /// Ed448.
        /// <para/>Uses context byte[0] by default.
        /// </summary>
        /// <param name="context">Context.</param>
        public Ed448(byte[] context) : base("Ed448", AsymmetricAlgorithms.Ed448)
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
            return new Ed448Signer(_context);
        }
    }
}