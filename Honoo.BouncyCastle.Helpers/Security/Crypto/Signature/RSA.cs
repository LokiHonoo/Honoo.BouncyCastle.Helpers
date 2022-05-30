using Honoo.BouncyCastle.Helpers.Security.Crypto.Hash;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Signers;
using System;
using System.Globalization;
using System.Security.Cryptography;

namespace Honoo.BouncyCastle.Helpers.Security.Crypto.Signature
{
    /// <summary>
    /// RSA.
    /// <para/>Legal signature hash Algorithm:
    /// <see cref="MD2"/>,<see cref="MD4"/>,<see cref="MD5"/>,
    /// <see cref="SHA1"/>,<see cref="SHA224"/>,<see cref="SHA256"/>,<see cref="SHA384"/>,<see cref="SHA512"/>,
    /// <see cref="RIPEMD128"/>,<see cref="RIPEMD160"/>,<see cref="RIPEMD256"/>.
    /// </summary>
    public sealed class RSA : SignatureAlgorithm
    {
        #region Properties

        private readonly IHashAlgorithm _hashAlgorithm;

        #endregion Properties

        #region Constructor

        /// <summary>
        /// RSA.
        /// <para/>Legal signature hash Algorithm:
        /// <see cref="MD2"/>,<see cref="MD4"/>,<see cref="MD5"/>,
        /// <see cref="SHA1"/>,<see cref="SHA224"/>,<see cref="SHA256"/>,<see cref="SHA384"/>,<see cref="SHA512"/>,
        /// <see cref="RIPEMD128"/>,<see cref="RIPEMD160"/>,<see cref="RIPEMD256"/>.
        /// </summary>
        /// <param name="hashAlgorithm">Hash algorithm.</param>
        public RSA(IHashAlgorithm hashAlgorithm) : this(hashAlgorithm, (IAsymmetricAlgorithm)AsymmetricAlgorithmHelper.RSA)
        {
        }

        /// <summary>
        /// RSA.
        /// <para/>Legal signature hash Algorithm:
        /// <see cref="MD2"/>,<see cref="MD4"/>,<see cref="MD5"/>,
        /// <see cref="SHA1"/>,<see cref="SHA224"/>,<see cref="SHA256"/>,<see cref="SHA384"/>,<see cref="SHA512"/>,
        /// <see cref="RIPEMD128"/>,<see cref="RIPEMD160"/>,<see cref="RIPEMD256"/>.
        /// </summary>
        /// <param name="hashAlgorithm">Hash algorithm.</param>
        /// <param name="asymmetricAlgorithm">Asymmetric algorithm. To provide function generate key pair, this argument is not required.</param>
        public RSA(IHashAlgorithm hashAlgorithm, IAsymmetricAlgorithm asymmetricAlgorithm)
            : base(string.Format(CultureInfo.InvariantCulture, "{0}withRSA", hashAlgorithm.Name), EnsureAlgorithm(asymmetricAlgorithm))
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
            return new RsaDigestSigner(digest);
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