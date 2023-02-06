using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Utilities;

namespace Honoo.BouncyCastle.Helpers.Security.Crypto.Signature
{
    /// <summary>
    /// Ed25519ph.
    /// </summary>
    public sealed class Ed25519ph : SignatureAlgorithm
    {
        #region Properties

        private readonly byte[] _context;

        #endregion Properties

        #region Construction

        /// <summary>
        /// Ed25519ph.
        /// <para/>Uses context byte[0] by default.
        /// </summary>
        public Ed25519ph() : this(Arrays.EmptyBytes)
        {
        }

        /// <summary>
        /// Ed25519ph.
        /// <para/>Uses context byte[0] by default.
        /// </summary>
        /// <param name="context">Context.</param>
        public Ed25519ph(byte[] context) : base("Ed25519ph", AsymmetricAlgorithms.Ed25519)
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
            return new Ed25519phSigner(_context);
        }
    }
}