using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Signers;
using System.Security.Cryptography;

namespace Honoo.BouncyCastle.Helpers.Security.Crypto.Signature
{
    /// <summary>
    /// Ed25519.
    /// </summary>
    public sealed class Ed25519 : SignatureAlgorithm
    {
        #region Constructor

        /// <summary>
        /// Ed25519.
        /// </summary>
        public Ed25519() : this(AsymmetricAlgorithmHelper.Ed25519)
        {
        }

        /// <summary>
        /// Ed25519.
        /// </summary>
        /// <param name="asymmetricAlgorithm">Asymmetric algorithm.</param>
        public Ed25519(IAsymmetricAlgorithm asymmetricAlgorithm) : base("Ed25519", EnsureAlgorithm(asymmetricAlgorithm))
        {
        }

        #endregion Constructor

        /// <summary>
        /// Generate signer.
        /// </summary>
        /// <returns></returns>
        protected override ISigner GenerateSignerCore()
        {
            return new Ed25519Signer();
        }

        private static IAsymmetricAlgorithm EnsureAlgorithm(IAsymmetricAlgorithm asymmetricAlgorithm)
        {
            if (asymmetricAlgorithm.Name != "Ed25519")
            {
                throw new CryptographicException("Requires Ed25519 asymmetric algorithm.");
            }
            else
            {
                return asymmetricAlgorithm;
            }
        }
    }
}