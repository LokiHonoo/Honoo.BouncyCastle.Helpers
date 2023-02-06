using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Signers;
using System;
using System.Globalization;

namespace Honoo.BouncyCastle.Helpers.Security.Crypto.Signature
{
    /// <summary>
    /// ECNR.
    /// </summary>
    public sealed class ECNR : SignatureAlgorithm
    {
        #region Properties

        private readonly IHashAlgorithm _hashAlgorithm;

        #endregion Properties

        #region Construction

        /// <summary>
        /// ECNR.
        /// </summary>
        /// <param name="hashAlgorithm">Hash algorithm.</param>
        public ECNR(IHashAlgorithm hashAlgorithm)
            : base(string.Format(CultureInfo.InvariantCulture, "{0}withECNR", hashAlgorithm.Name), AsymmetricAlgorithms.ECDSA)
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
            return new DsaDigestSigner(new ECNRSigner(), digest);
        }
    }
}