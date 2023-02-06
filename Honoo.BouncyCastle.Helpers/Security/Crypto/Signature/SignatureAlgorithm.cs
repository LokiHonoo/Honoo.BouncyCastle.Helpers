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
    public abstract class SignatureAlgorithm : IEquatable<SignatureAlgorithm>, ISignatureAlgorithm
    {
        #region Properties

        private readonly IAsymmetricAlgorithm _asymmetricAlgorithm;
        private readonly string _name;
        private readonly DerObjectIdentifier _oid;

        /// <summary>
        /// Gets the correlate asymmetric algorithm.
        /// </summary>
        public IAsymmetricAlgorithm AsymmetricAlgorithm => _asymmetricAlgorithm;

        /// <summary>
        /// Gets algorithm name.
        /// </summary>
        public string Name => _name;

        /// <summary>
        /// Gets signature algorithm oid. It's maybe 'null' if not supported.
        /// </summary>
        public DerObjectIdentifier Oid => _oid;

        #endregion Properties

        #region Construction

        /// <summary>
        /// Signature algorithm.
        /// </summary>
        /// <param name="name">Signature algorithm name.</param>
        /// <param name="asymmetricAlgorithm">Asymmetric algorithm.</param>
        protected SignatureAlgorithm(string name, IAsymmetricAlgorithm asymmetricAlgorithm)
        {
            _name = name;
            _asymmetricAlgorithm = asymmetricAlgorithm ?? throw new ArgumentNullException(nameof(asymmetricAlgorithm));
            _oid = GetOid(name);
        }

        #endregion Construction

        /// <summary>
        /// Determines whether the specified object is equal to the current.
        /// </summary>
        /// <param name="other"></param>
        /// <returns></returns>
        public bool Equals(SignatureAlgorithm other)
        {
            return _name.Equals(other._name);
        }

        /// <summary>
        /// Determines whether the specified object is equal to the current.
        /// </summary>
        /// <param name="obj"></param>
        /// <returns></returns>
        public override bool Equals(object obj)
        {
            return Equals((SignatureAlgorithm)obj);
        }

        /// <summary>
        /// Generate signer. The signer can be reused.
        /// </summary>
        /// <param name="privateKey">Asymmetric private key.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        public ISigner GenerateSigner(AsymmetricKeyParameter privateKey)
        {
            if (privateKey == null)
            {
                throw new ArgumentNullException(nameof(privateKey));
            }
            if (!privateKey.IsPrivate)
            {
                throw new CryptoException("Must be a asymmetric private key.");
            }
            ISigner signer = GenerateSignerCore();
            signer.Init(true, privateKey);
            return signer;
        }

        /// <summary>
        /// Generate signer. The signer can be reused.
        /// </summary>
        /// <param name="publicKey">Asymmetric public key.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        public ISigner GenerateVerifier(AsymmetricKeyParameter publicKey)
        {
            if (publicKey == null)
            {
                throw new ArgumentNullException(nameof(publicKey));
            }
            if (publicKey.IsPrivate)
            {
                throw new CryptoException("Must be a asymmetric public key.");
            }
            ISigner signer = GenerateSignerCore();
            signer.Init(false, publicKey);
            return signer;
        }

        /// <summary>
        /// Returns the hash code for this object.
        /// </summary>
        /// <returns></returns>
        public override int GetHashCode()
        {
            return _name.GetHashCode();
        }

        /// <summary>
        /// Generate a new signature algorithm and sign data.
        /// </summary>
        /// <param name="privateKey">Asymmetric private key.</param>
        /// <param name="data">Data bytes.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        public byte[] Sign(AsymmetricKeyParameter privateKey, byte[] data)
        {
            return Sign(privateKey, data, 0, data.Length);
        }

        /// <summary>
        /// Generate a new signature algorithm and sign data.
        /// </summary>
        /// <param name="privateKey">Asymmetric private key.</param>
        /// <param name="dataBuffer">Data buffer bytes.</param>
        /// <param name="offset">The starting offset to read.</param>
        /// <param name="length">The length to read.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        public byte[] Sign(AsymmetricKeyParameter privateKey, byte[] dataBuffer, int offset, int length)
        {
            if (privateKey == null)
            {
                throw new ArgumentNullException(nameof(privateKey));
            }
            if (dataBuffer == null)
            {
                throw new ArgumentNullException(nameof(dataBuffer));
            }
            if (!privateKey.IsPrivate)
            {
                throw new CryptoException("Must be a asymmetric private key.");
            }
            ISigner signer = GenerateSigner(privateKey);
            signer.BlockUpdate(dataBuffer, offset, length);
            return signer.GenerateSignature();
        }

        /// <summary>
        /// Return algorithm name.
        /// </summary>
        /// <returns></returns>
        public override string ToString()
        {
            return _name;
        }

        /// <summary>
        /// Generate a new signature algorithm and verify data.
        /// </summary>
        /// <param name="publicKey">Asymmetric public key.</param>
        /// <param name="data">Data bytes.</param>
        /// <param name="signature">Signature.</param>
        /// <returns></returns>
        public bool Verify(AsymmetricKeyParameter publicKey, byte[] data, byte[] signature)
        {
            return Verify(publicKey, data, 0, data.Length, signature, 0, signature.Length);
        }

        /// <summary>
        /// Generate a new signature algorithm and sign data.
        /// </summary>
        /// <param name="publicKey">Asymmetric public key.</param>
        /// <param name="dataBuffer">Data buffer bytes.</param>
        /// <param name="offset">The starting offset to read.</param>
        /// <param name="length">The length to read.</param>
        /// <param name="signature">Signature buffer bytes.</param>
        /// <param name="signatureOffset">The starting offset to read.</param>
        /// <param name="signatureLength">The length to read.</param>
        /// <returns></returns>
        public bool Verify(AsymmetricKeyParameter publicKey, byte[] dataBuffer, int offset, int length, byte[] signature, int signatureOffset, int signatureLength)
        {
            if (publicKey == null)
            {
                throw new ArgumentNullException(nameof(publicKey));
            }
            if (dataBuffer == null)
            {
                throw new ArgumentNullException(nameof(dataBuffer));
            }
            if (signature == null)
            {
                throw new ArgumentNullException(nameof(signature));
            }
            if (publicKey.IsPrivate)
            {
                throw new CryptoException("Must be a asymmetric public key.");
            }
            ISigner verifier = GenerateVerifier(publicKey);
            verifier.BlockUpdate(dataBuffer, offset, length);
            if (signatureOffset == 0 && signatureLength == signature.Length)
            {
                return verifier.VerifySignature(signature);
            }
            else
            {
                byte[] tmp = new byte[signatureLength];
                Buffer.BlockCopy(signature, signatureOffset, tmp, 0, signatureLength);
                return verifier.VerifySignature(tmp);
            }
        }

        /// <summary>
        /// Generate signer.
        /// </summary>
        /// <returns></returns>
        protected abstract ISigner GenerateSignerCore();

        private static DerObjectIdentifier GetOid(string mechanism)
        {
            if (string.IsNullOrWhiteSpace(mechanism))
            {
                return null;
            }
            mechanism = mechanism.Replace('_', '-').ToUpperInvariant();
            switch (mechanism)
            {
                case "1.2.840.10045.4.1": case "SHA1WITHECDSA": case "SHA-1WITHECDSA": return X9ObjectIdentifiers.ECDsaWithSha1;
                case "1.2.840.10045.4.3.1": case "SHA224WITHECDSA": case "SHA-224WITHECDSA": return X9ObjectIdentifiers.ECDsaWithSha224;
                case "1.2.840.10045.4.3.2": case "SHA256WITHECDSA": case "SHA-256WITHECDSA": return X9ObjectIdentifiers.ECDsaWithSha256;
                case "1.2.840.10045.4.3.3": case "SHA384WITHECDSA": case "SHA-384WITHECDSA": return X9ObjectIdentifiers.ECDsaWithSha384;
                case "1.2.840.10045.4.3.4": case "SHA512WITHECDSA": case "SHA-512WITHECDSA": return X9ObjectIdentifiers.ECDsaWithSha512;
                case "2.16.840.1.101.3.4.3.9": case "SHA3-224WITHECDSA": case "SHA-3-224WITHECDSA": return NistObjectIdentifiers.IdEcdsaWithSha3_224;
                case "2.16.840.1.101.3.4.3.10": case "SHA3-256WITHECDSA": case "SHA-3-256WITHECDSA": return NistObjectIdentifiers.IdEcdsaWithSha3_256;
                case "2.16.840.1.101.3.4.3.11": case "SHA3-384WITHECDSA": case "SHA-3-384WITHECDSA": return NistObjectIdentifiers.IdEcdsaWithSha3_384;
                case "2.16.840.1.101.3.4.3.12": case "SHA3-512WITHECDSA": case "SHA-3-512WITHECDSA": return NistObjectIdentifiers.IdEcdsaWithSha3_512;

                case "0.4.0.127.0.7.2.2.2.2.1": case "SHA1WITHCVC-ECDSA": case "SHA-1WITHCVC-ECDSA": return EacObjectIdentifiers.id_TA_ECDSA_SHA_1;
                case "0.4.0.127.0.7.2.2.2.2.2": case "SHA224WITHCVC-ECDSA": case "SHA-224WITHCVC-ECDSA": return EacObjectIdentifiers.id_TA_ECDSA_SHA_224;
                case "0.4.0.127.0.7.2.2.2.2.3": case "SHA256WITHCVC-ECDSA": case "SHA-256WITHCVC-ECDSA": return EacObjectIdentifiers.id_TA_ECDSA_SHA_256;
                case "0.4.0.127.0.7.2.2.2.2.4": case "SHA384WITHCVC-ECDSA": case "SHA-384WITHCVC-ECDSA": return EacObjectIdentifiers.id_TA_ECDSA_SHA_384;
                case "0.4.0.127.0.7.2.2.2.2.5": case "SHA512WITHCVC-ECDSA": case "SHA-512WITHCVC-ECDSA": return EacObjectIdentifiers.id_TA_ECDSA_SHA_512;

                case "0.4.0.127.0.7.1.1.4.1.1": case "SHA1WITHPLAIN-ECDSA": case "SHA-1WITHPLAIN-ECDSA": return BsiObjectIdentifiers.ecdsa_plain_SHA1;
                case "0.4.0.127.0.7.1.1.4.1.2": case "SHA224WITHPLAIN-ECDSA": case "SHA-224WITHPLAIN-ECDSA": return BsiObjectIdentifiers.ecdsa_plain_SHA224;
                case "0.4.0.127.0.7.1.1.4.1.3": case "SHA256WITHPLAIN-ECDSA": case "SHA-256WITHPLAIN-ECDSA": return BsiObjectIdentifiers.ecdsa_plain_SHA256;
                case "0.4.0.127.0.7.1.1.4.1.4": case "SHA384WITHPLAIN-ECDSA": case "SHA-384WITHPLAIN-ECDSA": return BsiObjectIdentifiers.ecdsa_plain_SHA384;
                case "0.4.0.127.0.7.1.1.4.1.5": case "SHA512WITHPLAIN-ECDSA": case "SHA-512WITHPLAIN-ECDSA": return BsiObjectIdentifiers.ecdsa_plain_SHA512;
                case "0.4.0.127.0.7.1.1.4.1.6": case "RIPEMD160WITHPLAIN-ECDSA": case "RIPEMD-160WITHPLAIN-ECDSA": return BsiObjectIdentifiers.ecdsa_plain_RIPEMD160;

                case "1.2.840.113549.1.1.10": case "PSSWITHRSA": case "SHA1WITHRSAANDMGF1": case "SHA-1WITHRSAANDMGF1": return PkcsObjectIdentifiers.IdRsassaPss;

                case "1.2.840.113549.1.1.2": case "MD2WITHRSA": return PkcsObjectIdentifiers.MD2WithRsaEncryption;
                case "1.2.840.113549.1.1.4": case "MD5WITHRSA": return PkcsObjectIdentifiers.MD5WithRsaEncryption;
                case "1.3.36.3.3.1.3": case "RIPEMD128WITHRSA": case "RIPEMD-128WITHRSA": return TeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD128;
                case "1.3.36.3.3.1.2": case "RIPEMD160WITHRSA": case "RIPEMD-160WITHRSA": return TeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD160;
                case "1.3.36.3.3.1.4": case "RIPEMD256WITHRSA": case "RIPEMD-256WITHRSA": return TeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD256;
                case "1.2.840.113549.1.1.5": case "SHA1WITHRSA": case "SHA-1WITHRSA": return PkcsObjectIdentifiers.Sha1WithRsaEncryption;
                case "1.2.840.113549.1.1.14": case "SHA224WITHRSA": case "SHA-224WITHRSA": return PkcsObjectIdentifiers.Sha224WithRsaEncryption;
                case "1.2.840.113549.1.1.11": case "SHA256WITHRSA": case "SHA-256WITHRSA": return PkcsObjectIdentifiers.Sha256WithRsaEncryption;
                case "1.2.840.113549.1.1.12": case "SHA384WITHRSA": case "SHA-384WITHRSA": return PkcsObjectIdentifiers.Sha384WithRsaEncryption;
                case "1.2.840.113549.1.1.13": case "SHA512WITHRSA": case "SHA-512WITHRSA": return PkcsObjectIdentifiers.Sha512WithRsaEncryption;
                case "2.16.840.1.101.3.4.3.13": case "SHA3-224WITHRSA": case "SHA-3-224WITHRSA": return NistObjectIdentifiers.IdRsassaPkcs1V15WithSha3_224;
                case "2.16.840.1.101.3.4.3.14": case "SHA3-256WITHRSA": case "SHA-3-256WITHRSA": return NistObjectIdentifiers.IdRsassaPkcs1V15WithSha3_256;
                case "2.16.840.1.101.3.4.3.15": case "SHA3-384WITHRSA": case "SHA-3-384WITHRSA": return NistObjectIdentifiers.IdRsassaPkcs1V15WithSha3_384;
                case "2.16.840.1.101.3.4.3.16": case "SHA3-512WITHRSA": case "SHA-3-512WITHRSA": return NistObjectIdentifiers.IdRsassaPkcs1V15WithSha3_512;

                case "1.2.840.10040.4.3": case "SHA1WITHDSA": case "SHA-1WITHDSA": return X9ObjectIdentifiers.IdDsaWithSha1;
                case "2.16.840.1.101.3.4.3.1": case "SHA224WITHDSA": case "SHA-224WITHDSA": return NistObjectIdentifiers.DsaWithSha224;
                case "2.16.840.1.101.3.4.3.2": case "SHA256WITHDSA": case "SHA-256WITHDSA": return NistObjectIdentifiers.DsaWithSha256;
                case "2.16.840.1.101.3.4.3.3": case "SHA384WITHDSA": case "SHA-384WITHDSA": return NistObjectIdentifiers.DsaWithSha384;
                case "2.16.840.1.101.3.4.3.4": case "SHA512WITHDSA": case "SHA-512WITHDSA": return NistObjectIdentifiers.DsaWithSha512;
                case "2.16.840.1.101.3.4.3.5": case "SHA3-224WITHDSA": case "SHA-3-224WITHDSA": return NistObjectIdentifiers.IdDsaWithSha3_224;
                case "2.16.840.1.101.3.4.3.6": case "SHA3-256WITHDSA": case "SHA-3-256WITHDSA": return NistObjectIdentifiers.IdDsaWithSha3_256;
                case "2.16.840.1.101.3.4.3.7": case "SHA3-384WITHDSA": case "SHA-3-384WITHDSA": return NistObjectIdentifiers.IdDsaWithSha3_384;
                case "2.16.840.1.101.3.4.3.8": case "SHA3-512WITHDSA": case "SHA-3-512WITHDSA": return NistObjectIdentifiers.IdDsaWithSha3_512;

                case "1.2.643.2.2.4": case "GOST3411WITHGOST3410": case "GOST3410": case "GOST3410-94": return CryptoProObjectIdentifiers.GostR3411x94WithGostR3410x94;

                case "1.2.643.2.2.3": case "GOST3411WITHECGOST3410": case "ECGOST3410": case "ECGOST3410-2001": return CryptoProObjectIdentifiers.GostR3411x94WithGostR3410x2001;

                case "1.2.156.10197.1.503": case "SHA256WITHSM2": case "SHA-256WITHSM2": return GMObjectIdentifiers.sm2sign_with_sha256;
                case "1.2.156.10197.1.501": case "SM3WITHSM2": return GMObjectIdentifiers.sm2sign_with_sm3;

                default: return null;
            }
        }
    }
}