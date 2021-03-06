using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Signers;
using System;
using System.Globalization;
using System.Security.Cryptography;

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

        #region Constructor

        /// <summary>
        /// GOST3410.
        /// </summary>
        /// <param name="hashAlgorithm">Hash algorithm.</param>
        public GOST3410(IHashAlgorithm hashAlgorithm) : this(hashAlgorithm, AsymmetricAlgorithmHelper.GOST3410)
        {
        }

        /// <summary>
        /// GOST3410.
        /// </summary>
        /// <param name="hashAlgorithm">Hash algorithm.</param>
        /// <param name="asymmetricAlgorithm">Asymmetric algorithm.</param>
        public GOST3410(IHashAlgorithm hashAlgorithm, IAsymmetricAlgorithm asymmetricAlgorithm)
            : base(string.Format(CultureInfo.InvariantCulture, "{0}withGOST3410", hashAlgorithm.Name), EnsureAlgorithm(asymmetricAlgorithm))
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
            return new Gost3410DigestSigner(new Gost3410Signer(), digest);
        }

        private static IAsymmetricAlgorithm EnsureAlgorithm(IAsymmetricAlgorithm asymmetricAlgorithm)
        {
            if (asymmetricAlgorithm.Name != "GOST3410")
            {
                throw new CryptographicException("Requires GOST3410 asymmetric algorithm.");
            }
            else
            {
                return asymmetricAlgorithm;
            }
        }
    }
}