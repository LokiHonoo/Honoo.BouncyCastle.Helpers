using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Signers;
using System;
using System.Globalization;
using System.Security.Cryptography;

namespace Honoo.BouncyCastle.Helpers.Security.Crypto.Signature
{
    /// <summary>
    /// RSAandMGF1.
    /// </summary>
    public sealed class RSAandMGF1 : SignatureAlgorithm
    {
        #region Properties

        //private readonly IHashAlgorithm _hashAlgorithmContent;
        //private readonly int _saltLength;
        //private readonly byte _trailer = 0xBC;
        //private readonly byte[] _salt;
        private readonly IHashAlgorithm _hashAlgorithm;

        #endregion Properties

        #region Constructor

        /// <summary>
        /// RSAandMGF1.
        /// </summary>
        /// <param name="hashAlgorithm">Hash algorithm.</param>
        public RSAandMGF1(IHashAlgorithm hashAlgorithm) : this(hashAlgorithm, (IAsymmetricAlgorithm)AsymmetricAlgorithms.RSA)
        {
        }

        /// <summary>
        /// RSAandMGF1.
        /// </summary>
        /// <param name="hashAlgorithm">Hash algorithm.</param>
        /// <param name="asymmetricAlgorithm">Asymmetric algorithm.</param>
        public RSAandMGF1(IHashAlgorithm hashAlgorithm, IAsymmetricAlgorithm asymmetricAlgorithm)
            : base(string.Format(CultureInfo.InvariantCulture, "{0}withRSAandMGF1", hashAlgorithm.Name), EnsureAlgorithm(asymmetricAlgorithm))
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
            return new PssSigner(new RsaBlindedEngine(), digest);
        }

        private static IAsymmetricAlgorithm EnsureAlgorithm(IAsymmetricAlgorithm asymmetricAlgorithm)
        {
            if (asymmetricAlgorithm.Name != "RSA")
            {
                throw new CryptographicException("Requires RSA asymmetric algorithm.");
            }
            else
            {
                return asymmetricAlgorithm;
            }
        }
    }
}