using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Utilities;

namespace Honoo.BouncyCastle.Helpers.Security.Crypto.Signature
{
    /// <summary>
    /// Ed25519ctx.
    /// </summary>
    public sealed class Ed25519ctx : SignatureAlgorithm
    {
        #region Properties

        private readonly byte[] _context;

        #endregion Properties

        #region Construction

        /// <summary>
        /// Ed25519ctx.
        /// <para/>Uses context byte[0] by default.
        /// </summary>
        public Ed25519ctx() : this(Arrays.EmptyBytes)
        {
        }

        /// <summary>
        /// Ed25519ctx.
        /// <para/>Uses context byte[0] by default.
        /// </summary>
        /// <param name="context">Context.</param>
        public Ed25519ctx(byte[] context) : base("Ed25519ctx", AsymmetricAlgorithms.Ed25519)
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
            return new Ed25519ctxSigner(_context);
        }
    }
}