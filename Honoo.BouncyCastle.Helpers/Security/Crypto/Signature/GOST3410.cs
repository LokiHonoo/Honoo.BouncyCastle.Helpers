using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Signers;
using System;
using System.Globalization;

namespace Honoo.BouncyCastle.Helpers.Security.Crypto.Signature
{
    /// <summary>
    /// GOST3410.
    /// </summary>
    public sealed class GOST3410 : SignatureAlgorithm
    {
        #region Properties

        private readonly IHashAlgorithm _hashAlgorithm;

        #endregion Properties

        #region Construction

        /// <summary>
        /// GOST3410.
        /// </summary>
        /// <param name="hashAlgorithm">Hash algorithm.</param>
        public GOST3410(IHashAlgorithm hashAlgorithm)
            : base(string.Format(CultureInfo.InvariantCulture, "{0}withGOST3410", hashAlgorithm.Name), AsymmetricAlgorithms.GOST3410)
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
            return new Gost3410DigestSigner(new Gost3410Signer(), digest);
        }
    }
}