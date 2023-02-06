using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Signers;
using System;
using System.Globalization;

namespace Honoo.BouncyCastle.Helpers.Security.Crypto.Signature
{
    /// <summary>
    /// RSA/ISO9796-2.
    /// </summary>
    public sealed class RSAandISO9796_2 : SignatureAlgorithm
    {
        #region Properties

        private readonly IHashAlgorithm _hashAlgorithm;

        #endregion Properties

        #region Construction

        /// <summary>
        /// RSA/ISO9796-2.
        /// </summary>
        /// <param name="hashAlgorithm">Hash algorithm.</param>
        public RSAandISO9796_2(IHashAlgorithm hashAlgorithm)
            : base(string.Format(CultureInfo.InvariantCulture, "{0}withRSA/ISO9796-2", hashAlgorithm.Name), AsymmetricAlgorithms.RSA)
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
            return new Iso9796d2Signer(new RsaBlindedEngine(), digest, true);
        }
    }
}