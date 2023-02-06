using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Signers;

namespace Honoo.BouncyCastle.Helpers.Security.Crypto.Signature
{
    /// <summary>
    /// Ed25519.
    /// </summary>
    public sealed class Ed25519 : SignatureAlgorithm
    {
        #region Construction

        /// <summary>
        /// Ed25519.
        /// </summary>
        public Ed25519() : base("Ed25519", AsymmetricAlgorithms.Ed25519)
        {
        }

        #endregion Construction

        /// <summary>
        /// Generate signer.
        /// </summary>
        /// <returns></returns>
        protected override ISigner GenerateSignerCore()
        {
            return new Ed25519Signer();
        }
    }
}