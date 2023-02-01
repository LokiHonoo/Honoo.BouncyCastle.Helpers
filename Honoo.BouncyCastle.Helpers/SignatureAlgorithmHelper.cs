using Honoo.BouncyCastle.Helpers.Security.Crypto.Signature;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Bsi;
using Org.BouncyCastle.Asn1.CryptoPro;
using Org.BouncyCastle.Asn1.Eac;
using Org.BouncyCastle.Asn1.GM;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.TeleTrust;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Utilities;

namespace Honoo.BouncyCastle.Helpers
{
    /// <summary>
    /// Signature algorithm helper.
    /// </summary>
    public static class SignatureAlgorithmHelper
    {
        /// <summary>
        /// Try get signature algorithm used arguments hash algorithm, asymmetric algorithm.
        /// </summary>
        /// <param name="model">Signature algorithm model.
        /// <para />e.g. CVC-ECDSA, DSA, ECDSA, ECGOST3410, ECNR, GOST3410, PLAIN-ECDSA, RSA, RSA/ISO9796-2, RSAandMGF1, RSA/X9.31, SM2.
        /// </param>
        /// <param name="hashAlgorithm">Hash algorithm.</param>
        /// <param name="asymmetricAlgorithm">Asymmetric algorithm.</param>
        /// <param name="algorithm">Signature algorithm.</param>
        /// <returns></returns>
        public static bool TryGetAlgorithm(string model, IHashAlgorithm hashAlgorithm, IAsymmetricAlgorithm asymmetricAlgorithm, out ISignatureAlgorithm algorithm)
        {
            if (string.IsNullOrWhiteSpace(model))
            {
                algorithm = null;
                return false;
            }
            if (asymmetricAlgorithm is null)
            {
                algorithm = null;
                return false;
            }
            model = model.Replace('_', '-').ToUpperInvariant();
            bool corresponding = false;
            bool ed = false;
            switch (model)
            {
                case "CVC-ECDSA": corresponding = asymmetricAlgorithm.Name == "ECDSA"; break;
                case "DSA": corresponding = asymmetricAlgorithm.Name == "DSA"; break;
                case "ECDSA": corresponding = asymmetricAlgorithm.Name == "ECDSA"; break;
                case "ECGOST3410": case "ECGOST3410-2001": corresponding = asymmetricAlgorithm.Name == "ECGOST3410"; break;
                case "ECNR": corresponding = asymmetricAlgorithm.Name == "ECDSA"; break;
                case "GOST3410": case "GOST3410-94": corresponding = asymmetricAlgorithm.Name == "GOST3410"; break;
                case "PLAIN-ECDSA": corresponding = asymmetricAlgorithm.Name == "ECDSA"; break;
                case "RSA": corresponding = asymmetricAlgorithm.Name == "RSA"; break;
                case "ISO9796-2": case "RSA/ISO9796-2": case "RSAANDISO9796-2": corresponding = asymmetricAlgorithm.Name == "RSA"; break;
                case "RSAANDMGF1": corresponding = asymmetricAlgorithm.Name == "RSA"; break;
                case "RSA/X9.31": case "RSA/X931": case "RSAANDX931": case "RSAANDX9.31": corresponding = asymmetricAlgorithm.Name == "RSA"; break;
                case "SM2": corresponding = asymmetricAlgorithm.Name == "SM2"; break;

                case "ED25519": corresponding = asymmetricAlgorithm.Name == "Ed25519"; ed = true; break;
                case "ED25519CTX": corresponding = asymmetricAlgorithm.Name == "Ed25519"; ed = true; break;
                case "ED25519PH": corresponding = asymmetricAlgorithm.Name == "Ed25519"; ed = true; break;
                case "ED448": corresponding = asymmetricAlgorithm.Name == "Ed448"; ed = true; break;
                case "ED448PH": corresponding = asymmetricAlgorithm.Name == "Ed448"; ed = true; break;
                default: break;
            }
            if (corresponding)
            {
                if (ed)
                {
                    switch (model)
                    {
                        case "ED25519": algorithm = new Ed25519(asymmetricAlgorithm); return true;
                        case "ED25519CTX": algorithm = new Ed25519ctx(Arrays.EmptyBytes, asymmetricAlgorithm); return true;
                        case "ED25519PH": algorithm = new Ed25519ph(Arrays.EmptyBytes, asymmetricAlgorithm); return true;
                        case "ED448": algorithm = new Ed448(Arrays.EmptyBytes, asymmetricAlgorithm); return true;
                        case "ED448PH": algorithm = new Ed448ph(Arrays.EmptyBytes, asymmetricAlgorithm); return true;
                        default: break;
                    }
                }
                else
                {
                    if (hashAlgorithm is null)
                    {
                        algorithm = null;
                        return false;
                    }
                    switch (model)
                    {
                        case "CVC-ECDSA": algorithm = new CVC_ECDSA(hashAlgorithm, asymmetricAlgorithm); return true;
                        case "DSA": algorithm = new DSA(hashAlgorithm, asymmetricAlgorithm); return true;
                        case "ECDSA": algorithm = new ECDSA(hashAlgorithm, asymmetricAlgorithm); return true;
                        case "ECGOST3410": case "ECGOST3410-2001": algorithm = new ECGOST3410(hashAlgorithm, asymmetricAlgorithm); return true;
                        case "ECNR": algorithm = new ECNR(hashAlgorithm, asymmetricAlgorithm); return true;
                        case "GOST3410": case "GOST3410-94": algorithm = new GOST3410(hashAlgorithm, asymmetricAlgorithm); return true;
                        case "PLAIN-ECDSA": algorithm = new PLAIN_ECDSA(hashAlgorithm, asymmetricAlgorithm); return true;
                        case "RSA": algorithm = new RSA(hashAlgorithm, asymmetricAlgorithm); return true;
                        case "RSA/ISO9796-2": case "RSAANDISO9796-2": case "ISO9796-2": algorithm = new RSAandISO9796_2(hashAlgorithm, asymmetricAlgorithm); return true;
                        case "RSAANDMGF1": algorithm = new RSAandMGF1(hashAlgorithm, asymmetricAlgorithm); return true;
                        case "RSA/X9.31": case "RSA/X931": case "RSAANDX931": case "RSAANDX9.31": algorithm = new RSAandX931(hashAlgorithm, asymmetricAlgorithm); return true;
                        case "SM2": algorithm = new SM2(hashAlgorithm, asymmetricAlgorithm); return true;
                        default: break;
                    }
                }
            }
            algorithm = null;
            return false;
        }

        /// <summary>
        /// Try get signature algorithm from mechanism.
        /// </summary>
        /// <param name="mechanism">Signature algorithm mechanism. e.g. SHA256withRSA.</param>
        /// <param name="algorithm">Signature algorithm.</param>
        /// <returns></returns>
        public static bool TryGetAlgorithm(string mechanism, out ISignatureAlgorithm algorithm)
        {
            if (string.IsNullOrWhiteSpace(mechanism))
            {
                algorithm = null;
                return false;
            }
            mechanism = mechanism.Replace('_', '-').ToUpperInvariant();
            switch (mechanism)
            {
                case "1.2.840.10045.4.1": case "SHA1WITHECDSA": case "SHA-1WITHECDSA": algorithm = SignatureAlgorithms.SHA1withECDSA; return true;
                case "1.2.840.10045.4.3.1": case "SHA224WITHECDSA": case "SHA-224WITHECDSA": algorithm = SignatureAlgorithms.SHA224withECDSA; return true;
                case "1.2.840.10045.4.3.2": case "SHA256WITHECDSA": case "SHA-256WITHECDSA": algorithm = SignatureAlgorithms.SHA256withECDSA; return true;
                case "1.2.840.10045.4.3.3": case "SHA384WITHECDSA": case "SHA-384WITHECDSA": algorithm = SignatureAlgorithms.SHA384withECDSA; return true;
                case "1.2.840.10045.4.3.4": case "SHA512WITHECDSA": case "SHA-512WITHECDSA": algorithm = SignatureAlgorithms.SHA512withECDSA; return true;
                case "2.16.840.1.101.3.4.3.9": case "SHA3-224WITHECDSA": case "SHA-3-224WITHECDSA": algorithm = SignatureAlgorithms.SHA3_224withECDSA; return true;
                case "2.16.840.1.101.3.4.3.10": case "SHA3-256WITHECDSA": case "SHA-3-256WITHECDSA": algorithm = SignatureAlgorithms.SHA3_256withECDSA; return true;
                case "2.16.840.1.101.3.4.3.11": case "SHA3-384WITHECDSA": case "SHA-3-384WITHECDSA": algorithm = SignatureAlgorithms.SHA3_384withECDSA; return true;
                case "2.16.840.1.101.3.4.3.12": case "SHA3-512WITHECDSA": case "SHA-3-512WITHECDSA": algorithm = SignatureAlgorithms.SHA3_512withECDSA; return true;

                case "0.4.0.127.0.7.2.2.2.2.1": case "SHA1WITHCVC-ECDSA": case "SHA-1WITHCVC-ECDSA": algorithm = SignatureAlgorithms.SHA1withCVC_ECDSA; return true;
                case "0.4.0.127.0.7.2.2.2.2.2": case "SHA224WITHCVC-ECDSA": case "SHA-224WITHCVC-ECDSA": algorithm = SignatureAlgorithms.SHA224withCVC_ECDSA; return true;
                case "0.4.0.127.0.7.2.2.2.2.3": case "SHA256WITHCVC-ECDSA": case "SHA-256WITHCVC-ECDSA": algorithm = SignatureAlgorithms.SHA256withCVC_ECDSA; return true;
                case "0.4.0.127.0.7.2.2.2.2.4": case "SHA384WITHCVC-ECDSA": case "SHA-384WITHCVC-ECDSA": algorithm = SignatureAlgorithms.SHA384withCVC_ECDSA; return true;
                case "0.4.0.127.0.7.2.2.2.2.5": case "SHA512WITHCVC-ECDSA": case "SHA-512WITHCVC-ECDSA": algorithm = SignatureAlgorithms.SHA512withCVC_ECDSA; return true;

                case "0.4.0.127.0.7.1.1.4.1.1": case "SHA1WITHPLAIN-ECDSA": case "SHA-1WITHPLAIN-ECDSA": algorithm = SignatureAlgorithms.SHA1withPLAIN_ECDSA; return true;
                case "0.4.0.127.0.7.1.1.4.1.2": case "SHA224WITHPLAIN-ECDSA": case "SHA-224WITHPLAIN-ECDSA": algorithm = SignatureAlgorithms.SHA224withPLAIN_ECDSA; return true;
                case "0.4.0.127.0.7.1.1.4.1.3": case "SHA256WITHPLAIN-ECDSA": case "SHA-256WITHPLAIN-ECDSA": algorithm = SignatureAlgorithms.SHA256withPLAIN_ECDSA; return true;
                case "0.4.0.127.0.7.1.1.4.1.4": case "SHA384WITHPLAIN-ECDSA": case "SHA-384WITHPLAIN-ECDSA": algorithm = SignatureAlgorithms.SHA384withPLAIN_ECDSA; return true;
                case "0.4.0.127.0.7.1.1.4.1.5": case "SHA512WITHPLAIN-ECDSA": case "SHA-512WITHPLAIN-ECDSA": algorithm = SignatureAlgorithms.SHA512withPLAIN_ECDSA; return true;
                case "0.4.0.127.0.7.1.1.4.1.6": case "RIPEMD160WITHPLAIN-ECDSA": case "RIPEMD-160WITHPLAIN-ECDSA": algorithm = SignatureAlgorithms.RIPEMD160withPLAIN_ECDSA; return true;

                case "1.2.840.113549.1.1.10": case "PSSWITHRSA": case "SHA1WITHRSAANDMGF1": case "SHA-1WITHRSAANDMGF1": algorithm = SignatureAlgorithms.PSSwithRSA; return true;

                case "1.2.840.113549.1.1.2": case "MD2WITHRSA": algorithm = SignatureAlgorithms.MD2withRSA; return true;
                case "1.2.840.113549.1.1.4": case "MD5WITHRSA": algorithm = SignatureAlgorithms.MD5withRSA; return true;
                case "1.3.36.3.3.1.3": case "RIPEMD128WITHRSA": case "RIPEMD-128WITHRSA": algorithm = SignatureAlgorithms.RIPEMD128withRSA; return true;
                case "1.3.36.3.3.1.2": case "RIPEMD160WITHRSA": case "RIPEMD-160WITHRSA": algorithm = SignatureAlgorithms.RIPEMD160withRSA; return true;
                case "1.3.36.3.3.1.4": case "RIPEMD256WITHRSA": case "RIPEMD-256WITHRSA": algorithm = SignatureAlgorithms.RIPEMD256withRSA; return true;
                case "1.2.840.113549.1.1.5": case "SHA1WITHRSA": case "SHA-1WITHRSA": algorithm = SignatureAlgorithms.SHA1withRSA; return true;
                case "1.2.840.113549.1.1.14": case "SHA224WITHRSA": case "SHA-224WITHRSA": algorithm = SignatureAlgorithms.SHA224withRSA; return true;
                case "1.2.840.113549.1.1.11": case "SHA256WITHRSA": case "SHA-256WITHRSA": algorithm = SignatureAlgorithms.SHA256withRSA; return true;
                case "1.2.840.113549.1.1.12": case "SHA384WITHRSA": case "SHA-384WITHRSA": algorithm = SignatureAlgorithms.SHA384withRSA; return true;
                case "1.2.840.113549.1.1.13": case "SHA512WITHRSA": case "SHA-512WITHRSA": algorithm = SignatureAlgorithms.SHA512withRSA; return true;
                case "2.16.840.1.101.3.4.3.13": case "SHA3-224WITHRSA": case "SHA-3-224WITHRSA": algorithm = SignatureAlgorithms.SHA3_224withRSA; return true;
                case "2.16.840.1.101.3.4.3.14": case "SHA3-256WITHRSA": case "SHA-3-256WITHRSA": algorithm = SignatureAlgorithms.SHA3_256withRSA; return true;
                case "2.16.840.1.101.3.4.3.15": case "SHA3-384WITHRSA": case "SHA-3-384WITHRSA": algorithm = SignatureAlgorithms.SHA3_384withRSA; return true;
                case "2.16.840.1.101.3.4.3.16": case "SHA3-512WITHRSA": case "SHA-3-512WITHRSA": algorithm = SignatureAlgorithms.SHA3_512withRSA; return true;

                case "1.2.840.10040.4.3": case "SHA1WITHDSA": case "SHA-1WITHDSA": algorithm = SignatureAlgorithms.SHA1withDSA; return true;
                case "2.16.840.1.101.3.4.3.1": case "SHA224WITHDSA": case "SHA-224WITHDSA": algorithm = SignatureAlgorithms.SHA224withDSA; return true;
                case "2.16.840.1.101.3.4.3.2": case "SHA256WITHDSA": case "SHA-256WITHDSA": algorithm = SignatureAlgorithms.SHA256withDSA; return true;
                case "2.16.840.1.101.3.4.3.3": case "SHA384WITHDSA": case "SHA-384WITHDSA": algorithm = SignatureAlgorithms.SHA384withDSA; return true;
                case "2.16.840.1.101.3.4.3.4": case "SHA512WITHDSA": case "SHA-512WITHDSA": algorithm = SignatureAlgorithms.SHA512withDSA; return true;
                case "2.16.840.1.101.3.4.3.5": case "SHA3-224WITHDSA": case "SHA-3-224WITHDSA": algorithm = SignatureAlgorithms.SHA3_224withDSA; return true;
                case "2.16.840.1.101.3.4.3.6": case "SHA3-256WITHDSA": case "SHA-3-256WITHDSA": algorithm = SignatureAlgorithms.SHA3_256withDSA; return true;
                case "2.16.840.1.101.3.4.3.7": case "SHA3-384WITHDSA": case "SHA-3-384WITHDSA": algorithm = SignatureAlgorithms.SHA3_384withDSA; return true;
                case "2.16.840.1.101.3.4.3.8": case "SHA3-512WITHDSA": case "SHA-3-512WITHDSA": algorithm = SignatureAlgorithms.SHA3_512withDSA; return true;

                case "1.2.643.2.2.4": case "GOST3411WITHGOST3410": case "GOST3410": case "GOST3410-94": algorithm = SignatureAlgorithms.GOST3411withGOST3410; return true;

                case "1.2.643.2.2.3": case "GOST3411WITHECGOST3410": case "ECGOST3410": case "ECGOST3410-2001": algorithm = SignatureAlgorithms.GOST3411withECGOST3410; return true;

                case "1.2.156.10197.1.503": case "SHA256WITHSM2": case "SHA-256WITHSM2": algorithm = SignatureAlgorithms.SHA256withSM2; return true;
                case "1.2.156.10197.1.501": case "SM3WITHSM2": algorithm = SignatureAlgorithms.SM3withSM2; return true;

                case "ED25519": algorithm = new Ed25519(); return true;
                case "ED25519CTX": algorithm = new Ed25519ctx(); return true;
                case "ED25519PH": algorithm = new Ed25519ph(); return true;
                case "ED448": algorithm = new Ed448(); return true;
                case "ED448PH": algorithm = new Ed448ph(); return true;

                default: break;
            }
            string prefix;
            string suffix;
            int index = mechanism.IndexOf("WITH");
            if (index >= 0)
            {
                prefix = mechanism.Substring(0, index);
                suffix = mechanism.Substring(index + 4, mechanism.Length - index - 4);
                if (suffix != "ELGAMAL")
                {
                    if (HashAlgorithmHelper.TryGetAlgorithm(prefix, out IHashAlgorithm hashAlgorithm))
                    {
                        switch (suffix)
                        {
                            case "CVC-ECDSA": algorithm = new CVC_ECDSA(hashAlgorithm); return true;
                            case "DSA": algorithm = new DSA(hashAlgorithm); return true;
                            case "ECDSA": algorithm = new ECDSA(hashAlgorithm); return true;
                            case "ECGOST3410": case "ECGOST3410-2001": algorithm = new ECGOST3410(hashAlgorithm); return true;
                            case "ECNR": algorithm = new ECNR(hashAlgorithm); return true;
                            case "GOST3410": case "GOST3410-94": algorithm = new GOST3410(hashAlgorithm); return true;
                            case "PLAIN-ECDSA": algorithm = new PLAIN_ECDSA(hashAlgorithm); return true;
                            case "RSA": algorithm = new RSA(hashAlgorithm); return true;
                            case "RSA/ISO9796-2": case "RSAANDISO9796-2": case "ISO9796-2": algorithm = new RSAandISO9796_2(hashAlgorithm); return true;
                            case "RSAANDMGF1": algorithm = new RSAandMGF1(hashAlgorithm); return true;
                            case "RSA/X9.31": case "RSA/X931": case "RSAANDX931": case "RSAANDX9.31": algorithm = new RSAandX931(hashAlgorithm); return true;
                            case "SM2": algorithm = new SM2(hashAlgorithm); return true;
                            default: break;
                        }
                    }
                }
            }
            algorithm = null;
            return false;
        }

        /// <summary>
        /// Try get signature algorithm oid from mechanism.
        /// </summary>
        /// <param name="mechanism">Signature algorithm mechanism. e.g. SHA256withRSA.</param>
        /// <param name="oid">Signature algorithm oid.</param>
        /// <returns></returns>
        public static bool TryGetOid(string mechanism, out DerObjectIdentifier oid)
        {
            if (string.IsNullOrWhiteSpace(mechanism))
            {
                oid = null;
                return false;
            }
            mechanism = mechanism.Replace('_', '-').ToUpperInvariant();
            switch (mechanism)
            {
                case "1.2.840.10045.4.1": case "SHA1WITHECDSA": case "SHA-1WITHECDSA": oid = X9ObjectIdentifiers.ECDsaWithSha1; return true;
                case "1.2.840.10045.4.3.1": case "SHA224WITHECDSA": case "SHA-224WITHECDSA": oid = X9ObjectIdentifiers.ECDsaWithSha224; return true;
                case "1.2.840.10045.4.3.2": case "SHA256WITHECDSA": case "SHA-256WITHECDSA": oid = X9ObjectIdentifiers.ECDsaWithSha256; return true;
                case "1.2.840.10045.4.3.3": case "SHA384WITHECDSA": case "SHA-384WITHECDSA": oid = X9ObjectIdentifiers.ECDsaWithSha384; return true;
                case "1.2.840.10045.4.3.4": case "SHA512WITHECDSA": case "SHA-512WITHECDSA": oid = X9ObjectIdentifiers.ECDsaWithSha512; return true;
                case "2.16.840.1.101.3.4.3.9": case "SHA3-224WITHECDSA": case "SHA-3-224WITHECDSA": oid = NistObjectIdentifiers.IdEcdsaWithSha3_224; return true;
                case "2.16.840.1.101.3.4.3.10": case "SHA3-256WITHECDSA": case "SHA-3-256WITHECDSA": oid = NistObjectIdentifiers.IdEcdsaWithSha3_256; return true;
                case "2.16.840.1.101.3.4.3.11": case "SHA3-384WITHECDSA": case "SHA-3-384WITHECDSA": oid = NistObjectIdentifiers.IdEcdsaWithSha3_384; return true;
                case "2.16.840.1.101.3.4.3.12": case "SHA3-512WITHECDSA": case "SHA-3-512WITHECDSA": oid = NistObjectIdentifiers.IdEcdsaWithSha3_512; return true;

                case "0.4.0.127.0.7.2.2.2.2.1": case "SHA1WITHCVC-ECDSA": case "SHA-1WITHCVC-ECDSA": oid = EacObjectIdentifiers.id_TA_ECDSA_SHA_1; return true;
                case "0.4.0.127.0.7.2.2.2.2.2": case "SHA224WITHCVC-ECDSA": case "SHA-224WITHCVC-ECDSA": oid = EacObjectIdentifiers.id_TA_ECDSA_SHA_224; return true;
                case "0.4.0.127.0.7.2.2.2.2.3": case "SHA256WITHCVC-ECDSA": case "SHA-256WITHCVC-ECDSA": oid = EacObjectIdentifiers.id_TA_ECDSA_SHA_256; return true;
                case "0.4.0.127.0.7.2.2.2.2.4": case "SHA384WITHCVC-ECDSA": case "SHA-384WITHCVC-ECDSA": oid = EacObjectIdentifiers.id_TA_ECDSA_SHA_384; return true;
                case "0.4.0.127.0.7.2.2.2.2.5": case "SHA512WITHCVC-ECDSA": case "SHA-512WITHCVC-ECDSA": oid = EacObjectIdentifiers.id_TA_ECDSA_SHA_512; return true;

                case "0.4.0.127.0.7.1.1.4.1.1": case "SHA1WITHPLAIN-ECDSA": case "SHA-1WITHPLAIN-ECDSA": oid = BsiObjectIdentifiers.ecdsa_plain_SHA1; return true;
                case "0.4.0.127.0.7.1.1.4.1.2": case "SHA224WITHPLAIN-ECDSA": case "SHA-224WITHPLAIN-ECDSA": oid = BsiObjectIdentifiers.ecdsa_plain_SHA224; return true;
                case "0.4.0.127.0.7.1.1.4.1.3": case "SHA256WITHPLAIN-ECDSA": case "SHA-256WITHPLAIN-ECDSA": oid = BsiObjectIdentifiers.ecdsa_plain_SHA256; return true;
                case "0.4.0.127.0.7.1.1.4.1.4": case "SHA384WITHPLAIN-ECDSA": case "SHA-384WITHPLAIN-ECDSA": oid = BsiObjectIdentifiers.ecdsa_plain_SHA384; return true;
                case "0.4.0.127.0.7.1.1.4.1.5": case "SHA512WITHPLAIN-ECDSA": case "SHA-512WITHPLAIN-ECDSA": oid = BsiObjectIdentifiers.ecdsa_plain_SHA512; return true;
                case "0.4.0.127.0.7.1.1.4.1.6": case "RIPEMD160WITHPLAIN-ECDSA": case "RIPEMD-160WITHPLAIN-ECDSA": oid = BsiObjectIdentifiers.ecdsa_plain_RIPEMD160; return true;

                case "1.2.840.113549.1.1.10": case "PSSWITHRSA": case "SHA1WITHRSAANDMGF1": case "SHA-1WITHRSAANDMGF1": oid = PkcsObjectIdentifiers.IdRsassaPss; return true;

                case "1.2.840.113549.1.1.2": case "MD2WITHRSA": oid = PkcsObjectIdentifiers.MD2WithRsaEncryption; return true;
                case "1.2.840.113549.1.1.4": case "MD5WITHRSA": oid = PkcsObjectIdentifiers.MD5WithRsaEncryption; return true;
                case "1.3.36.3.3.1.3": case "RIPEMD128WITHRSA": case "RIPEMD-128WITHRSA": oid = TeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD128; return true;
                case "1.3.36.3.3.1.2": case "RIPEMD160WITHRSA": case "RIPEMD-160WITHRSA": oid = TeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD160; return true;
                case "1.3.36.3.3.1.4": case "RIPEMD256WITHRSA": case "RIPEMD-256WITHRSA": oid = TeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD256; return true;
                case "1.2.840.113549.1.1.5": case "SHA1WITHRSA": case "SHA-1WITHRSA": oid = PkcsObjectIdentifiers.Sha1WithRsaEncryption; return true;
                case "1.2.840.113549.1.1.14": case "SHA224WITHRSA": case "SHA-224WITHRSA": oid = PkcsObjectIdentifiers.Sha224WithRsaEncryption; return true;
                case "1.2.840.113549.1.1.11": case "SHA256WITHRSA": case "SHA-256WITHRSA": oid = PkcsObjectIdentifiers.Sha256WithRsaEncryption; return true;
                case "1.2.840.113549.1.1.12": case "SHA384WITHRSA": case "SHA-384WITHRSA": oid = PkcsObjectIdentifiers.Sha384WithRsaEncryption; return true;
                case "1.2.840.113549.1.1.13": case "SHA512WITHRSA": case "SHA-512WITHRSA": oid = PkcsObjectIdentifiers.Sha512WithRsaEncryption; return true;
                case "2.16.840.1.101.3.4.3.13": case "SHA3-224WITHRSA": case "SHA-3-224WITHRSA": oid = NistObjectIdentifiers.IdRsassaPkcs1V15WithSha3_224; return true;
                case "2.16.840.1.101.3.4.3.14": case "SHA3-256WITHRSA": case "SHA-3-256WITHRSA": oid = NistObjectIdentifiers.IdRsassaPkcs1V15WithSha3_256; return true;
                case "2.16.840.1.101.3.4.3.15": case "SHA3-384WITHRSA": case "SHA-3-384WITHRSA": oid = NistObjectIdentifiers.IdRsassaPkcs1V15WithSha3_384; return true;
                case "2.16.840.1.101.3.4.3.16": case "SHA3-512WITHRSA": case "SHA-3-512WITHRSA": oid = NistObjectIdentifiers.IdRsassaPkcs1V15WithSha3_512; return true;

                case "1.2.840.10040.4.3": case "SHA1WITHDSA": case "SHA-1WITHDSA": oid = X9ObjectIdentifiers.IdDsaWithSha1; return true;
                case "2.16.840.1.101.3.4.3.1": case "SHA224WITHDSA": case "SHA-224WITHDSA": oid = NistObjectIdentifiers.DsaWithSha224; return true;
                case "2.16.840.1.101.3.4.3.2": case "SHA256WITHDSA": case "SHA-256WITHDSA": oid = NistObjectIdentifiers.DsaWithSha256; return true;
                case "2.16.840.1.101.3.4.3.3": case "SHA384WITHDSA": case "SHA-384WITHDSA": oid = NistObjectIdentifiers.DsaWithSha384; return true;
                case "2.16.840.1.101.3.4.3.4": case "SHA512WITHDSA": case "SHA-512WITHDSA": oid = NistObjectIdentifiers.DsaWithSha512; return true;
                case "2.16.840.1.101.3.4.3.5": case "SHA3-224WITHDSA": case "SHA-3-224WITHDSA": oid = NistObjectIdentifiers.IdDsaWithSha3_224; return true;
                case "2.16.840.1.101.3.4.3.6": case "SHA3-256WITHDSA": case "SHA-3-256WITHDSA": oid = NistObjectIdentifiers.IdDsaWithSha3_256; return true;
                case "2.16.840.1.101.3.4.3.7": case "SHA3-384WITHDSA": case "SHA-3-384WITHDSA": oid = NistObjectIdentifiers.IdDsaWithSha3_384; return true;
                case "2.16.840.1.101.3.4.3.8": case "SHA3-512WITHDSA": case "SHA-3-512WITHDSA": oid = NistObjectIdentifiers.IdDsaWithSha3_512; return true;

                case "1.2.643.2.2.4": case "GOST3411WITHGOST3410": case "GOST3410": case "GOST3410-94": oid = CryptoProObjectIdentifiers.GostR3411x94WithGostR3410x94; return true;

                case "1.2.643.2.2.3": case "GOST3411WITHECGOST3410": case "ECGOST3410": case "ECGOST3410-2001": oid = CryptoProObjectIdentifiers.GostR3411x94WithGostR3410x2001; return true;

                case "1.2.156.10197.1.503": case "SHA256WITHSM2": case "SHA-256WITHSM2": oid = GMObjectIdentifiers.sm2sign_with_sha256; return true;
                case "1.2.156.10197.1.501": case "SM3WITHSM2": oid = GMObjectIdentifiers.sm2sign_with_sm3; return true;

                default: oid = null; return false;
            }
        }
    }
}