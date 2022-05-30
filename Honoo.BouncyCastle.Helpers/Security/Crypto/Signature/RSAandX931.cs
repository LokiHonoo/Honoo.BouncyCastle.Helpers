using Honoo.BouncyCastle.Helpers.Security.Crypto.Hash;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Signers;
using System;
using System.Globalization;
using System.Security.Cryptography;

namespace Honoo.BouncyCastle.Helpers.Security.Crypto.Signature
{
    /// <summary>
    /// RSA/X9.31.
    /// <para/>Legal key size is more than or equal to 512 bits (64 bits increments).
    /// <para/>Uses key size 2048 bits, certainty 25 by default.
    /// <para/>Legal signature hash Algorithm:
    /// <see cref="SHA1"/>,<see cref="SHA224"/>,<see cref="SHA256"/>,<see cref="SHA384"/>,<see cref="SHA512"/>,
    /// <see cref="RIPEMD128"/>,<see cref="RIPEMD160"/>,
    /// <see cref="SHA512T"/>/224,<see cref="SHA512T"/>/256,
    /// <see cref="Whirlpool"/>.
    /// </summary>
    public sealed class RSAandX931 : SignatureAlgorithm
    {
        #region Properties

        private readonly IHashAlgorithm _hashAlgorithm;

        #endregion Properties

        #region Constructor

        /// <summary>
        /// RSA/X9.31.
        /// <para/>Legal key size is more than or equal to 512 bits (64 bits increments).
        /// <para/>Uses key size 2048 bits, certainty 25 by default.
        /// <para/>Legal signature hash Algorithm:
        /// <see cref="SHA1"/>,<see cref="SHA224"/>,<see cref="SHA256"/>,<see cref="SHA384"/>,<see cref="SHA512"/>,
        /// <see cref="RIPEMD128"/>,<see cref="RIPEMD160"/>,
        /// <see cref="SHA512T"/>/224,<see cref="SHA512T"/>/256,
        /// <see cref="Whirlpool"/>.
        /// </summary>
        /// <param name="hashAlgorithm">Hash algorithm.</param>
        public RSAandX931(IHashAlgorithm hashAlgorithm) : this(hashAlgorithm, (IAsymmetricAlgorithm)AsymmetricAlgorithmHelper.RSA)
        {
        }

        /// <summary>
        /// RSA/X9.31.
        /// <para/>Legal key size is more than or equal to 512 bits (64 bits increments).
        /// <para/>Uses key size 2048 bits, certainty 25 by default.
        /// <para/>Legal signature hash Algorithm:
        /// <see cref="SHA1"/>,<see cref="SHA224"/>,<see cref="SHA256"/>,<see cref="SHA384"/>,<see cref="SHA512"/>,
        /// <see cref="RIPEMD128"/>,<see cref="RIPEMD160"/>,
        /// <see cref="SHA512T"/>/224,<see cref="SHA512T"/>/256,
        /// <see cref="Whirlpool"/>.
        /// </summary>
        /// <param name="hashAlgorithm">Hash algorithm.</param>
        /// <param name="asymmetricAlgorithm">Asymmetric algorithm. To provide function generate key pair, this argument is not required.</param>
        public RSAandX931(IHashAlgorithm hashAlgorithm, IAsymmetricAlgorithm asymmetricAlgorithm)
            : base(string.Format(CultureInfo.InvariantCulture, "{0}withRSA/X9.31", hashAlgorithm.Name), asymmetricAlgorithm)
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
            return new X931Signer(new RsaBlindedEngine(), digest);
        }

        private static IAsymmetricAlgorithm EnsureAlgorithm(IAsymmetricAlgorithm asymmetricAlgorithm)
        {
            if (asymmetricAlgorithm is null)
            {
                return (IAsymmetricAlgorithm)AsymmetricAlgorithmHelper.RSA;
            }
            else if (asymmetricAlgorithm.Name != "RSA")
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