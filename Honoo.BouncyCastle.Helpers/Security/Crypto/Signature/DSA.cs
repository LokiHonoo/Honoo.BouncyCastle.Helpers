using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Signers;
using System;
using System.Globalization;
using System.Security.Cryptography;

namespace Honoo.BouncyCastle.Helpers.Security.Crypto.Signature
{
    /// <summary>
    /// DSA.
    /// </summary>
    public sealed class DSA : SignatureAlgorithm
    {
        #region Properties

        private readonly IHashAlgorithm _hashAlgorithm;

        #endregion Properties

        #region Constructor

        /// <summary>
        /// DSA.
        /// </summary>
        /// <param name="hashAlgorithm">Hash algorithm.</param>
        public DSA(IHashAlgorithm hashAlgorithm) : this(hashAlgorithm, AsymmetricAlgorithmHelper.DSA)
        {
        }

        /// <summary>
        /// DSA.
        /// </summary>
        /// <param name="hashAlgorithm">Hash algorithm.</param>
        /// <param name="asymmetricAlgorithm">Asymmetric algorithm. To provide function generate key pair, this argument is not required.</param>
        public DSA(IHashAlgorithm hashAlgorithm, IAsymmetricAlgorithm asymmetricAlgorithm)
            : base(string.Format(CultureInfo.InvariantCulture, "{0}withDSA", hashAlgorithm.Mechanism), EnsureAlgorithm(asymmetricAlgorithm))
        {
            _hashAlgorithm = hashAlgorithm ?? throw new ArgumentNullException(nameof(hashAlgorithm));
        }

        #endregion Constructor

        /// <summary>
        /// Generate signer.
        /// </summary>
        /// <returns></returns>
        protected override ISigner GenerateSigner()
        {
            IDigest digest = _hashAlgorithm.GenerateDigest();
            return new DsaDigestSigner(new DsaSigner(), digest);
        }

        private static IAsymmetricAlgorithm EnsureAlgorithm(IAsymmetricAlgorithm asymmetricAlgorithm)
        {
            if (asymmetricAlgorithm is null)
            {
                return AsymmetricAlgorithmHelper.DSA;
            }
            else if (asymmetricAlgorithm.Mechanism != "DSA")
            {
                throw new CryptographicException("Requires DSA asymmetric algorithm.");
            }
            else
            {
                return asymmetricAlgorithm;
            }
        }
    }
}