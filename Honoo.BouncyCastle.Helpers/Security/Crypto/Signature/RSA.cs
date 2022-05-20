using Honoo.BouncyCastle.Helpers.Security.Crypto.Hash;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Signers;
using System.Globalization;

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

        private static readonly DefaultSignatureAlgorithmIdentifierFinder _finder = new DefaultSignatureAlgorithmIdentifierFinder();
        private readonly IHashAlgorithm _hashAlgorithm;
        private readonly AlgorithmIdentifier _identifier;

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
            : base(string.Format(CultureInfo.InvariantCulture, "{0}withRSA", hashAlgorithm.Mechanism), EnsureAlgorithm(asymmetricAlgorithm))
        {
            _hashAlgorithm = hashAlgorithm;
            _identifier = GetAlgorithmIdentifier(base.Mechanism, _finder);
        }

        #endregion Constructor

        /// <summary>
        /// Generate signer.
        /// </summary>
        /// <returns></returns>
        protected override ISigner GenerateSigner()
        {
            IDigest digest = _hashAlgorithm.GenerateDigest();
            return _identifier is null ? new RsaDigestSigner(digest) : new RsaDigestSigner(digest, _identifier);
        }

        private static IAsymmetricAlgorithm EnsureAlgorithm(IAsymmetricAlgorithm asymmetricAlgorithm)
        {
            if (asymmetricAlgorithm is null)
            {
                return (IAsymmetricAlgorithm)AsymmetricAlgorithmHelper.RSA;
            }
            else if (asymmetricAlgorithm.Mechanism != "RSA")
            {
                throw new System.Security.Cryptography.CryptographicException("Requires RSA asymmetric algorithm.");
            }
            else
            {
                return asymmetricAlgorithm;
            }
        }

        private static AlgorithmIdentifier GetAlgorithmIdentifier(string mechanism, DefaultSignatureAlgorithmIdentifierFinder finder)
        {
            try
            {
                return finder.Find(mechanism);
            }
            catch
            {
                return null;
            }
        }
    }
}