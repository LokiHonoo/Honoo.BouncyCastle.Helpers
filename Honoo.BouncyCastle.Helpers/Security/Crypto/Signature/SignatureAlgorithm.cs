using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Bsi;
using Org.BouncyCastle.Asn1.CryptoPro;
using Org.BouncyCastle.Asn1.Eac;
using Org.BouncyCastle.Asn1.GM;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.TeleTrust;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using System;

namespace Honoo.BouncyCastle.Helpers.Security.Crypto.Signature
{
    /// <summary>
    /// Signature algorithm.
    /// </summary>
    public abstract class SignatureAlgorithm : ISignatureAlgorithm
    {
        #region Properties

        /// <summary>
        /// Gets the corresponding asymmetric algorithm.
        /// </summary>
        public IAsymmetricAlgorithm AsymmetricAlgorithm { get; }

        /// <summary>
        /// Gets mechanism.
        /// </summary>
        public string Mechanism { get; }

        /// <summary>
        /// Gets x509 signature algorithm oid. Return null if not exists.
        /// </summary>
        public DerObjectIdentifier X509 { get; }

        #endregion Properties

        #region Constructor

        /// <summary>
        /// Signature algorithm.
        /// </summary>
        /// <param name="mechanism">Mechanism.</param>
        /// <param name="asymmetricAlgorithm">Asymmetric algorithm.</param>
        protected SignatureAlgorithm(string mechanism, IAsymmetricAlgorithm asymmetricAlgorithm)
        {
            this.Mechanism = mechanism;
            this.AsymmetricAlgorithm = asymmetricAlgorithm;
            this.X509 = GetX509Oid(mechanism);
        }

        #endregion Constructor

        /// <summary>
        /// Generate signer. The signer can be reused.
        /// </summary>
        /// <param name="asymmetricKey">Asymmetric public key or private key.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        public ISigner GenerateSigner(AsymmetricKeyParameter asymmetricKey)
        {
            ISigner signer = GenerateSigner();
            signer.Init(asymmetricKey.IsPrivate, asymmetricKey);
            return signer;
        }

        /// <summary>
        /// Return mechanism.
        /// </summary>
        /// <returns></returns>
        public override string ToString()
        {
            return this.Mechanism;
        }

        /// <summary>
        /// Generate signer.
        /// </summary>
        /// <returns></returns>
        protected abstract ISigner GenerateSigner();

        private static DerObjectIdentifier GetX509Oid(string mechanism)
        {
            mechanism = mechanism.Replace('_', '-').ToUpperInvariant();
            switch (mechanism)
            {
                case "SHA1WITHCVC-ECDSA": case "SHA-1WITHCVC-ECDSA": return EacObjectIdentifiers.id_TA_ECDSA_SHA_1;
                case "SHA224WITHCVC-ECDSA": case "SHA-224WITHCVC-ECDSA": return EacObjectIdentifiers.id_TA_ECDSA_SHA_224;
                case "SHA256WITHCVC-ECDSA": case "SHA-256WITHCVC-ECDSA": return EacObjectIdentifiers.id_TA_ECDSA_SHA_256;
                case "SHA384WITHCVC-ECDSA": case "SHA-384WITHCVC-ECDSA": return EacObjectIdentifiers.id_TA_ECDSA_SHA_384;
                case "SHA512WITHCVC-ECDSA": case "SHA-512WITHCVC-ECDSA": return EacObjectIdentifiers.id_TA_ECDSA_SHA_512;

                case "GOST3411WITHECGOST3410": case "ECGOST3410": case "ECGOST3410-2001": case "ECGOST-3410": case "ECGOST-3410-2001": return CryptoProObjectIdentifiers.GostR3411x94WithGostR3410x2001;
                case "GOST3411WITHGOST3410": case "GOST3410": case "GOST3410-94": case "GOST-3410": case "GOST-3410-94": return CryptoProObjectIdentifiers.GostR3411x94WithGostR3410x94;

                case "RIPEMD160WITHPLAIN-ECDSA": case "RIPEMD-160WITHPLAIN-ECDSA": return BsiObjectIdentifiers.ecdsa_plain_RIPEMD160;
                case "SHA1WITHPLAIN-ECDSA": case "SHA-1WITHPLAIN-ECDSA": return BsiObjectIdentifiers.ecdsa_plain_SHA1;
                case "SHA224WITHPLAIN-ECDSA": case "SHA-224WITHPLAIN-ECDSA": return BsiObjectIdentifiers.ecdsa_plain_SHA224;
                case "SHA256WITHPLAIN-ECDSA": case "SHA-256WITHPLAIN-ECDSA": return BsiObjectIdentifiers.ecdsa_plain_SHA256;
                case "SHA384WITHPLAIN-ECDSA": case "SHA-384WITHPLAIN-ECDSA": return BsiObjectIdentifiers.ecdsa_plain_SHA384;
                case "SHA512WITHPLAIN-ECDSA": case "SHA-512WITHPLAIN-ECDSA": return BsiObjectIdentifiers.ecdsa_plain_SHA512;

                case "PSSWITHRSA": return PkcsObjectIdentifiers.IdRsassaPss;

                case "SHA1WITHDSA": case "SHA-1WITHDSA": return X9ObjectIdentifiers.IdDsaWithSha1;
                case "SHA224WITHDSA": case "SHA-224WITHDSA": return NistObjectIdentifiers.DsaWithSha224;
                case "SHA256WITHDSA": case "SHA-256WITHDSA": return NistObjectIdentifiers.DsaWithSha256;
                case "SHA384WITHDSA": case "SHA-384WITHDSA": return NistObjectIdentifiers.DsaWithSha384;
                case "SHA512WITHDSA": case "SHA-512WITHDSA": return NistObjectIdentifiers.DsaWithSha512;
                case "SHA3-224WITHDSA": case "SHA-3-224WITHDSA": return NistObjectIdentifiers.IdDsaWithSha3_224;
                case "SHA3-256WITHDSA": case "SHA-3-256WITHDSA": return NistObjectIdentifiers.IdDsaWithSha3_256;
                case "SHA3-384WITHDSA": case "SHA-3-384WITHDSA": return NistObjectIdentifiers.IdDsaWithSha3_384;
                case "SHA3-512WITHDSA": case "SHA-3-512WITHDSA": return NistObjectIdentifiers.IdDsaWithSha3_512;

                case "SHA1WITHECDSA": case "SHA-1WITHECDSA": return X9ObjectIdentifiers.ECDsaWithSha1;
                case "SHA224WITHECDSA": case "SHA-224WITHECDSA": return X9ObjectIdentifiers.ECDsaWithSha224;
                case "SHA256WITHECDSA": case "SHA-256WITHECDSA": return X9ObjectIdentifiers.ECDsaWithSha256;
                case "SHA384WITHECDSA": case "SHA-384WITHECDSA": return X9ObjectIdentifiers.ECDsaWithSha384;
                case "SHA512WITHECDSA": case "SHA-512WITHECDSA": return X9ObjectIdentifiers.ECDsaWithSha512;
                case "SHA3-224WITHECDSA": case "SHA-3-224WITHECDSA": return NistObjectIdentifiers.IdEcdsaWithSha3_224;
                case "SHA3-256WITHECDSA": case "SHA-3-256WITHECDSA": return NistObjectIdentifiers.IdEcdsaWithSha3_256;
                case "SHA3-384WITHECDSA": case "SHA-3-384WITHECDSA": return NistObjectIdentifiers.IdEcdsaWithSha3_384;
                case "SHA3-512WITHECDSA": case "SHA-3-512WITHECDSA": return NistObjectIdentifiers.IdEcdsaWithSha3_512;

                case "MD2WITHRSA": return PkcsObjectIdentifiers.MD2WithRsaEncryption;
                case "MD5WITHRSA": return PkcsObjectIdentifiers.MD5WithRsaEncryption;
                case "RIPEMD128WITHRSA": case "RIPEMD-128WITHRSA": return TeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD128;
                case "RIPEMD160WITHRSA": case "RIPEMD-160WITHRSA": return TeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD160;
                case "RIPEMD256WITHRSA": case "RIPEMD-256WITHRSA": return TeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD256;
                case "SHA1WITHRSA": case "SHA-1WITHRSA": return PkcsObjectIdentifiers.Sha1WithRsaEncryption;
                case "SHA224WITHRSA": case "SHA-224WITHRSA": return PkcsObjectIdentifiers.Sha224WithRsaEncryption;
                case "SHA256WITHRSA": case "SHA-256WITHRSA": return PkcsObjectIdentifiers.Sha256WithRsaEncryption;
                case "SHA384WITHRSA": case "SHA-384WITHRSA": return PkcsObjectIdentifiers.Sha384WithRsaEncryption;
                case "SHA512WITHRSA": case "SHA-512WITHRSA": return PkcsObjectIdentifiers.Sha512WithRsaEncryption;
                case "SHA3-224WITHRSA": case "SHA-3-224WITHRSA": return NistObjectIdentifiers.IdRsassaPkcs1V15WithSha3_224;
                case "SHA3-256WITHRSA": case "SHA-3-256WITHRSA": return NistObjectIdentifiers.IdRsassaPkcs1V15WithSha3_256;
                case "SHA3-384WITHRSA": case "SHA-3-384WITHRSA": return NistObjectIdentifiers.IdRsassaPkcs1V15WithSha3_384;
                case "SHA3-512WITHRSA": case "SHA-3-512WITHRSA": return NistObjectIdentifiers.IdRsassaPkcs1V15WithSha3_512;

                case "SHA1WITHRSAANDMGF1": case "SHA-1WITHRSAANDMGF1": return PkcsObjectIdentifiers.IdRsassaPss;

                case "SHA256WITHSM2": case "SHA-256WITHSM2": return GMObjectIdentifiers.sm2sign_with_sha256;
                case "SM3WITHSM2": return GMObjectIdentifiers.sm2sign_with_sm3;

                default: return null;
            }
        }
    }
}