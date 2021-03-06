using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Signers;
using System;
using System.Globalization;
using System.Security.Cryptography;

namespace Honoo.BouncyCastle.Helpers.Security.Crypto.Signature
{
    /// <summary>
    /// CVC-ECDSA.
    /// </summary>
    public sealed class CVC_ECDSA : SignatureAlgorithm
    {
        #region Properties

        private readonly IHashAlgorithm _hashAlgorithm;

        #endregion Properties

        #region Constructor

        /// <summary>
        /// CVC-ECDSA.
        /// </summary>
        /// <param name="hashAlgorithm">Hash algorithm.</param>
        public CVC_ECDSA(IHashAlgorithm hashAlgorithm) : this(hashAlgorithm, AsymmetricAlgorithmHelper.ECDSA)
        {
        }

        /// <summary>
        /// CVC-ECDSA.
        /// </summary>
        /// <param name="hashAlgorithm">Hash algorithm.</param>
        /// <param name="asymmetricAlgorithm">Asymmetric algorithm.</param>
        public CVC_ECDSA(IHashAlgorithm hashAlgorithm, IAsymmetricAlgorithm asymmetricAlgorithm)
            : base(string.Format(CultureInfo.InvariantCulture, "{0}withCVC-ECDSA", hashAlgorithm.Name), EnsureAlgorithm(asymmetricAlgorithm))
        {
            _hashAlgorithm = hashAlgorithm ?? throw new ArgumentNullException(nameof(hashAlgorithm));
        }

        #endregion Constructor

        /// <summary>
        /// Generate signer.
        /// </summary>
        /// <returns></returns>
        protected override ISigner GenerateSignerCore()
        {
            IDigest digest = _hashAlgorithm.GenerateDigest();
            return new DsaDigestSigner(new ECDsaSigner(), digest, PlainDsaEncoding.Instance);
        }

        private static IAsymmetricAlgorithm EnsureAlgorithm(IAsymmetricAlgorithm asymmetricAlgorithm)
        {
            if (asymmetricAlgorithm.Name != "ECDSA")
            {
                throw new CryptographicException("Requires ECDSA asymmetric algorithm.");
            }
            else
            {
                return asymmetricAlgorithm;
            }
        }
    }
}