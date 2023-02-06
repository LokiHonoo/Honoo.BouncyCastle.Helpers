using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Signers;
using System;
using System.Globalization;

namespace Honoo.BouncyCastle.Helpers.Security.Crypto.Signature
{
    /// <summary>
    /// ECDSA.
    /// </summary>
    public sealed class ECDSA : SignatureAlgorithm
    {
        #region Properties

        private readonly IHashAlgorithm _hashAlgorithm;

        #endregion Properties

        #region Construction

        /// <summary>
        /// ECDSA.
        /// </summary>
        /// <param name="hashAlgorithm">Hash algorithm.</param>
        public ECDSA(IHashAlgorithm hashAlgorithm)
            : base(string.Format(CultureInfo.InvariantCulture, "{0}withECDSA", hashAlgorithm.Name), AsymmetricAlgorithms.ECDSA)
        {
            _hashAlgorithm = hashAlgorithm ?? throw new ArgumentNullException(nameof(hashAlgorithm));
        }

        #endregion Construction

        /// <summary>
        /// Generate signer.
        /// </summary>
        /// <returns></returns>
        protected override ISigner GenerateSignerCore()
        {
            IDigest digest = _hashAlgorithm.GenerateDigest();
            return new DsaDigestSigner(new ECDsaSigner(), digest);
        }
    }
}