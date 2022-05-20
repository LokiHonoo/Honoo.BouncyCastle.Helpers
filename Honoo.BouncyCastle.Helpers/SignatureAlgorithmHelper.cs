using Honoo.BouncyCastle.Helpers.Security.Crypto.Signature;

namespace Honoo.BouncyCastle.Helpers
{
    /// <summary>
    /// Signature algorithm helper.
    /// </summary>
    public static class SignatureAlgorithmHelper
    {
        #region CVC-ECDSA

        /// <summary>
        /// Uses EllipticCurve.SecP256r1 by default.
        /// </summary>
        public static ISignatureAlgorithm SHA1withCVC_ECDSA { get; } = new CVC_ECDSA(HashAlgorithmHelper.SHA1);

        /// <summary>
        /// Uses EllipticCurve.SecP256r1 by default.
        /// </summary>
        public static ISignatureAlgorithm SHA224withCVC_ECDSA { get; } = new CVC_ECDSA(HashAlgorithmHelper.SHA224);

        /// <summary>
        /// Uses EllipticCurve.SecP256r1 by default.
        /// </summary>
        public static ISignatureAlgorithm SHA256withCVC_ECDSA { get; } = new CVC_ECDSA(HashAlgorithmHelper.SHA256);

        /// <summary>
        /// Uses EllipticCurve.SecP256r1 by default.
        /// </summary>
        public static ISignatureAlgorithm SHA384withCVC_ECDSA { get; } = new CVC_ECDSA(HashAlgorithmHelper.SHA384);

        /// <summary>
        /// Uses EllipticCurve.SecP256r1 by default.
        /// </summary>
        public static ISignatureAlgorithm SHA512withCVC_ECDSA { get; } = new CVC_ECDSA(HashAlgorithmHelper.SHA512);

        #endregion CVC-ECDSA

        #region PLAIN-ECDSA

        /// <summary>
        /// Uses EllipticCurve.SecP256r1 by default.
        /// </summary>
        public static ISignatureAlgorithm RIPEMD160withPLAIN_ECDSA { get; } = new PLAIN_ECDSA(HashAlgorithmHelper.RIPEMD160);

        /// <summary>
        /// Uses EllipticCurve.SecP256r1 by default.
        /// </summary>
        public static ISignatureAlgorithm SHA1withPLAIN_ECDSA { get; } = new PLAIN_ECDSA(HashAlgorithmHelper.SHA1);

        /// <summary>
        /// Uses EllipticCurve.SecP256r1 by default.
        /// </summary>
        public static ISignatureAlgorithm SHA224withPLAIN_ECDSA { get; } = new PLAIN_ECDSA(HashAlgorithmHelper.SHA224);

        /// <summary>
        /// Uses EllipticCurve.SecP256r1 by default.
        /// </summary>
        public static ISignatureAlgorithm SHA256withPLAIN_ECDSA { get; } = new PLAIN_ECDSA(HashAlgorithmHelper.SHA256);

        /// <summary>
        /// Uses EllipticCurve.SecP256r1 by default.
        /// </summary>
        public static ISignatureAlgorithm SHA384withPLAIN_ECDSA { get; } = new PLAIN_ECDSA(HashAlgorithmHelper.SHA384);

        /// <summary>
        /// Uses EllipticCurve.SecP256r1 by default.
        /// </summary>
        public static ISignatureAlgorithm SHA512withPLAIN_ECDSA { get; } = new PLAIN_ECDSA(HashAlgorithmHelper.SHA512);

        #endregion PLAIN-ECDSA

        #region DSA

        /// <summary>
        /// Legal key size 512-1024 bits (64 bits increments).
        /// <para/>Uses key size 1024 bits, certainty 80 by default.
        /// </summary>
        public static ISignatureAlgorithm SHA1withDSA { get; } = new DSA(HashAlgorithmHelper.SHA1);

        /// <summary>
        /// Legal key size 512-1024 bits (64 bits increments).
        /// <para/>Uses key size 1024 bits, certainty 80 by default.
        /// </summary>
        public static ISignatureAlgorithm SHA224withDSA { get; } = new DSA(HashAlgorithmHelper.SHA224);

        /// <summary>
        /// Legal key size 512-1024 bits (64 bits increments).
        /// <para/>Uses key size 1024 bits, certainty 80 by default.
        /// </summary>
        public static ISignatureAlgorithm SHA256withDSA { get; } = new DSA(HashAlgorithmHelper.SHA256);

        /// <summary>
        /// Legal key size 512-1024 bits (64 bits increments).
        /// <para/>Uses key size 1024 bits, certainty 80 by default.
        /// </summary>
        public static ISignatureAlgorithm SHA3_224withDSA { get; } = new DSA(HashAlgorithmHelper.SHA3_224);

        /// <summary>
        /// Legal key size 512-1024 bits (64 bits increments).
        /// <para/>Uses key size 1024 bits, certainty 80 by default.
        /// </summary>
        public static ISignatureAlgorithm SHA3_256withDSA { get; } = new DSA(HashAlgorithmHelper.SHA3_256);

        /// <summary>
        /// Legal key size 512-1024 bits (64 bits increments).
        /// <para/>Uses key size 1024 bits, certainty 80 by default.
        /// </summary>
        public static ISignatureAlgorithm SHA3_384withDSA { get; } = new DSA(HashAlgorithmHelper.SHA3_384);

        /// <summary>
        /// Legal key size 512-1024 bits (64 bits increments).
        /// <para/>Uses key size 1024 bits, certainty 80 by default.
        /// </summary>
        public static ISignatureAlgorithm SHA3_512withDSA { get; } = new DSA(HashAlgorithmHelper.SHA3_512);

        /// <summary>
        /// Legal key size 512-1024 bits (64 bits increments).
        /// <para/>Uses key size 1024 bits, certainty 80 by default.
        /// </summary>
        public static ISignatureAlgorithm SHA384withDSA { get; } = new DSA(HashAlgorithmHelper.SHA384);

        /// <summary>
        /// Legal key size 512-1024 bits (64 bits increments).
        /// <para/>Uses key size 1024 bits, certainty 80 by default.
        /// </summary>
        public static ISignatureAlgorithm SHA512withDSA { get; } = new DSA(HashAlgorithmHelper.SHA512);

        #endregion DSA

        #region ECDSA

        /// <summary>
        /// Uses EllipticCurve.SecP256r1 by default.
        /// </summary>
        public static ISignatureAlgorithm SHA1withECDSA { get; } = new ECDSA(HashAlgorithmHelper.SHA1);

        /// <summary>
        /// Uses EllipticCurve.SecP256r1 by default.
        /// </summary>
        public static ISignatureAlgorithm SHA224withECDSA { get; } = new ECDSA(HashAlgorithmHelper.SHA224);

        /// <summary>
        /// Uses EllipticCurve.SecP256r1 by default.
        /// </summary>
        public static ISignatureAlgorithm SHA256withECDSA { get; } = new ECDSA(HashAlgorithmHelper.SHA256);

        /// <summary>
        /// Uses EllipticCurve.SecP256r1 by default.
        /// </summary>
        public static ISignatureAlgorithm SHA3_224withECDSA { get; } = new ECDSA(HashAlgorithmHelper.SHA3_224);

        /// <summary>
        /// Uses EllipticCurve.SecP256r1 by default.
        /// </summary>
        public static ISignatureAlgorithm SHA3_256withECDSA { get; } = new ECDSA(HashAlgorithmHelper.SHA3_256);

        /// <summary>
        /// Uses EllipticCurve.SecP256r1 by default.
        /// </summary>
        public static ISignatureAlgorithm SHA3_384withECDSA { get; } = new ECDSA(HashAlgorithmHelper.SHA3_384);

        /// <summary>
        /// Uses EllipticCurve.SecP256r1 by default.
        /// </summary>
        public static ISignatureAlgorithm SHA3_512withECDSA { get; } = new ECDSA(HashAlgorithmHelper.SHA3_512);

        /// <summary>
        /// Uses EllipticCurve.SecP256r1 by default.
        /// </summary>
        public static ISignatureAlgorithm SHA384withECDSA { get; } = new ECDSA(HashAlgorithmHelper.SHA384);

        /// <summary>
        /// Uses EllipticCurve.SecP256r1 by default.
        /// </summary>
        public static ISignatureAlgorithm SHA512withECDSA { get; } = new ECDSA(HashAlgorithmHelper.SHA512);

        #endregion ECDSA

        #region RSA

        /// <summary>
        /// Legal key size is more than or equal to 512 bits (64 bits increments).
        /// <para/>Uses key size 2048 bits, certainty 25 by default.
        /// </summary>
        public static ISignatureAlgorithm MD2withRSA { get; } = new RSA(HashAlgorithmHelper.MD2);

        /// <summary>
        /// Legal key size is more than or equal to 512 bits (64 bits increments).
        /// <para/>Uses key size 2048 bits, certainty 25 by default.
        /// </summary>
        public static ISignatureAlgorithm MD5withRSA { get; } = new RSA(HashAlgorithmHelper.MD5);

        /// <summary>
        /// Legal key size is more than or equal to 512 bits (64 bits increments).
        /// <para/>Uses key size 2048 bits, certainty 25 by default.
        /// </summary>
        public static ISignatureAlgorithm PSSwithRSA { get; } = new RSAandMGF1(HashAlgorithmHelper.SHA1);

        /// <summary>
        /// Legal key size is more than or equal to 512 bits (64 bits increments).
        /// <para/>Uses key size 2048 bits, certainty 25 by default.
        /// </summary>
        public static ISignatureAlgorithm RIPEMD128withRSA { get; } = new RSA(HashAlgorithmHelper.RIPEMD128);

        /// <summary>
        /// Legal key size is more than or equal to 512 bits (64 bits increments).
        /// <para/>Uses key size 2048 bits, certainty 25 by default.
        /// </summary>
        public static ISignatureAlgorithm RIPEMD160withRSA { get; } = new RSA(HashAlgorithmHelper.RIPEMD160);

        /// <summary>
        /// Legal key size is more than or equal to 512 bits (64 bits increments).
        /// <para/>Uses key size 2048 bits, certainty 25 by default.
        /// </summary>
        public static ISignatureAlgorithm RIPEMD256withRSA { get; } = new RSA(HashAlgorithmHelper.RIPEMD256);

        /// <summary>
        /// Legal key size is more than or equal to 512 bits (64 bits increments).
        /// <para/>Uses key size 2048 bits, certainty 25 by default.
        /// </summary>
        public static ISignatureAlgorithm SHA1withRSA { get; } = new RSA(HashAlgorithmHelper.SHA1);

        /// <summary>
        /// Legal key size is more than or equal to 512 bits (64 bits increments).
        /// <para/>Uses key size 2048 bits, certainty 25 by default.
        /// </summary>
        public static ISignatureAlgorithm SHA224withRSA { get; } = new RSA(HashAlgorithmHelper.SHA224);

        /// <summary>
        /// Legal key size is more than or equal to 512 bits (64 bits increments).
        /// <para/>Uses key size 2048 bits, certainty 25 by default.
        /// </summary>
        public static ISignatureAlgorithm SHA256withRSA { get; } = new RSA(HashAlgorithmHelper.SHA256);

        /// <summary>
        /// Legal key size is more than or equal to 512 bits (64 bits increments).
        /// <para/>Uses key size 2048 bits, certainty 25 by default.
        /// </summary>
        public static ISignatureAlgorithm SHA3_224withRSA { get; } = new RSA(HashAlgorithmHelper.SHA3_224);

        /// <summary>
        /// Legal key size is more than or equal to 512 bits (64 bits increments).
        /// <para/>Uses key size 2048 bits, certainty 25 by default.
        /// </summary>
        public static ISignatureAlgorithm SHA3_256withRSA { get; } = new RSA(HashAlgorithmHelper.SHA3_256);

        /// <summary>
        /// Legal key size is more than or equal to 512 bits (64 bits increments).
        /// <para/>Uses key size 2048 bits, certainty 25 by default.
        /// </summary>
        public static ISignatureAlgorithm SHA3_384withRSA { get; } = new RSA(HashAlgorithmHelper.SHA3_384);

        /// <summary>
        /// Legal key size is more than or equal to 512 bits (64 bits increments).
        /// <para/>Uses key size 2048 bits, certainty 25 by default.
        /// </summary>
        public static ISignatureAlgorithm SHA3_512withRSA { get; } = new RSA(HashAlgorithmHelper.SHA3_512);

        /// <summary>
        /// Legal key size is more than or equal to 512 bits (64 bits increments).
        /// <para/>Uses key size 2048 bits, certainty 25 by default.
        /// </summary>
        public static ISignatureAlgorithm SHA384withRSA { get; } = new RSA(HashAlgorithmHelper.SHA384);

        /// <summary>
        /// Legal key size is more than or equal to 512 bits (64 bits increments).
        /// <para/>Uses key size 2048 bits, certainty 25 by default.
        /// </summary>
        public static ISignatureAlgorithm SHA512withRSA { get; } = new RSA(HashAlgorithmHelper.SHA512);

        #endregion RSA

        #region SM2

        /// <summary>
        ///
        /// </summary>
        public static ISignatureAlgorithm SHA256withSM2 { get; } = new SM2(HashAlgorithmHelper.SHA256);

        /// <summary>
        ///
        /// </summary>
        public static ISignatureAlgorithm SM3withSM2 { get; } = new SM2(HashAlgorithmHelper.SM3);

        #endregion SM2

        /// <summary>
        /// Uses substitution box "D-A" by default.
        /// <para/>Uses EllipticCurve.GostR3410x2001CryptoProA by default.
        /// </summary>
        public static ISignatureAlgorithm GOST3411withECGOST3410 { get; } = new ECGOST3410(HashAlgorithmHelper.GOST3411);

        /// <summary>
        /// Uses substitution box "D-A" by default.
        /// <para/>Legal key size 512, 1024 bits.
        /// <para/>Uses key size 1024 bits, procedure 2 by default.
        /// </summary>
        public static ISignatureAlgorithm GOST3411withGOST3410 { get; } = new GOST3410(HashAlgorithmHelper.GOST3411);

        /// <summary>
        /// Try get algorithm from mechanism.
        /// </summary>
        /// <param name="mechanism">Algorithm mechanism.</param>
        /// <param name="algorithm">Algorithm.</param>
        /// <returns></returns>
        public static bool TryGetAlgorithm(string mechanism, out ISignatureAlgorithm algorithm)
        {
            mechanism = mechanism.Replace('_', '-').ToUpperInvariant();
            switch (mechanism)
            {
                case "SHA1WITHCVC-ECDSA": case "SHA-1WITHCVC-ECDSA": algorithm = SHA1withCVC_ECDSA; return true;
                case "SHA224WITHCVC-ECDSA": case "SHA-224WITHCVC-ECDSA": algorithm = SHA224withCVC_ECDSA; return true;
                case "SHA256WITHCVC-ECDSA": case "SHA-256WITHCVC-ECDSA": algorithm = SHA256withCVC_ECDSA; return true;
                case "SHA384WITHCVC-ECDSA": case "SHA-384WITHCVC-ECDSA": algorithm = SHA384withCVC_ECDSA; return true;
                case "SHA512WITHCVC-ECDSA": case "SHA-512WITHCVC-ECDSA": algorithm = SHA512withCVC_ECDSA; return true;

                case "ED25519": algorithm = new Ed25519(); return true;
                case "ED25519CTX": algorithm = new Ed25519ctx(); return true;
                case "ED25519PH": algorithm = new Ed25519ph(); return true;
                case "ED448": algorithm = new Ed448(); return true;
                case "ED448PH": algorithm = new Ed448ph(); return true;

                case "GOST3411WITHECGOST3410": case "ECGOST3410": case "ECGOST3410-2001": case "ECGOST-3410": case "ECGOST-3410-2001": algorithm = GOST3411withECGOST3410; return true;
                case "GOST3411WITHGOST3410": case "GOST3410": case "GOST3410-94": case "GOST-3410": case "GOST-3410-94": algorithm = GOST3411withGOST3410; return true;

                case "RIPEMD160WITHPLAIN-ECDSA": case "RIPEMD-160WITHPLAIN-ECDSA": algorithm = RIPEMD160withPLAIN_ECDSA; return true;
                case "SHA1WITHPLAIN-ECDSA": case "SHA-1WITHPLAIN-ECDSA": algorithm = SHA1withPLAIN_ECDSA; return true;
                case "SHA224WITHPLAIN-ECDSA": case "SHA-224WITHPLAIN-ECDSA": algorithm = SHA224withPLAIN_ECDSA; return true;
                case "SHA256WITHPLAIN-ECDSA": case "SHA-256WITHPLAIN-ECDSA": algorithm = SHA256withPLAIN_ECDSA; return true;
                case "SHA384WITHPLAIN-ECDSA": case "SHA-384WITHPLAIN-ECDSA": algorithm = SHA384withPLAIN_ECDSA; return true;
                case "SHA512WITHPLAIN-ECDSA": case "SHA-512WITHPLAIN-ECDSA": algorithm = SHA512withPLAIN_ECDSA; return true;

                case "PSSWITHRSA": algorithm = PSSwithRSA; return true;

                case "SHA1WITHDSA": case "SHA-1WITHDSA": algorithm = SHA1withDSA; return true;
                case "SHA224WITHDSA": case "SHA-224WITHDSA": algorithm = SHA224withDSA; return true;
                case "SHA256WITHDSA": case "SHA-256WITHDSA": algorithm = SHA256withDSA; return true;
                case "SHA384WITHDSA": case "SHA-384WITHDSA": algorithm = SHA384withDSA; return true;
                case "SHA512WITHDSA": case "SHA-512WITHDSA": algorithm = SHA512withDSA; return true;
                case "SHA3-224WITHDSA": case "SHA-3-224WITHDSA": algorithm = SHA3_224withDSA; return true;
                case "SHA3-256WITHDSA": case "SHA-3-256WITHDSA": algorithm = SHA3_256withDSA; return true;
                case "SHA3-384WITHDSA": case "SHA-3-384WITHDSA": algorithm = SHA3_384withDSA; return true;
                case "SHA3-512WITHDSA": case "SHA-3-512WITHDSA": algorithm = SHA3_512withDSA; return true;

                case "SHA1WITHECDSA": case "SHA-1WITHECDSA": algorithm = SHA1withECDSA; return true;
                case "SHA224WITHECDSA": case "SHA-224WITHECDSA": algorithm = SHA224withECDSA; return true;
                case "SHA256WITHECDSA": case "SHA-256WITHECDSA": algorithm = SHA256withECDSA; return true;
                case "SHA384WITHECDSA": case "SHA-384WITHECDSA": algorithm = SHA384withECDSA; return true;
                case "SHA512WITHECDSA": case "SHA-512WITHECDSA": algorithm = SHA512withECDSA; return true;
                case "SHA3-224WITHECDSA": case "SHA-3-224WITHECDSA": algorithm = SHA3_224withECDSA; return true;
                case "SHA3-256WITHECDSA": case "SHA-3-256WITHECDSA": algorithm = SHA3_256withECDSA; return true;
                case "SHA3-384WITHECDSA": case "SHA-3-384WITHECDSA": algorithm = SHA3_384withECDSA; return true;
                case "SHA3-512WITHECDSA": case "SHA-3-512WITHECDSA": algorithm = SHA3_512withECDSA; return true;

                case "MD2WITHRSA": algorithm = MD2withRSA; return true;
                case "MD5WITHRSA": algorithm = MD5withRSA; return true;
                case "RIPEMD128WITHRSA": case "RIPEMD-128WITHRSA": algorithm = RIPEMD128withRSA; return true;
                case "RIPEMD160WITHRSA": case "RIPEMD-160WITHRSA": algorithm = RIPEMD160withRSA; return true;
                case "RIPEMD256WITHRSA": case "RIPEMD-256WITHRSA": algorithm = RIPEMD256withRSA; return true;
                case "SHA1WITHRSA": case "SHA-1WITHRSA": algorithm = SHA1withRSA; return true;
                case "SHA224WITHRSA": case "SHA-224WITHRSA": algorithm = SHA224withRSA; return true;
                case "SHA256WITHRSA": case "SHA-256WITHRSA": algorithm = SHA256withRSA; return true;
                case "SHA384WITHRSA": case "SHA-384WITHRSA": algorithm = SHA384withRSA; return true;
                case "SHA512WITHRSA": case "SHA-512WITHRSA": algorithm = SHA512withRSA; return true;
                case "SHA3-224WITHRSA": case "SHA-3-224WITHRSA": algorithm = SHA3_224withRSA; return true;
                case "SHA3-256WITHRSA": case "SHA-3-256WITHRSA": algorithm = SHA3_256withRSA; return true;
                case "SHA3-384WITHRSA": case "SHA-3-384WITHRSA": algorithm = SHA3_384withRSA; return true;
                case "SHA3-512WITHRSA": case "SHA-3-512WITHRSA": algorithm = SHA3_512withRSA; return true;

                case "SHA1WITHRSAANDMGF1": case "SHA-1WITHRSAANDMGF1": algorithm = PSSwithRSA; return true;

                case "SHA256WITHSM2": case "SHA-256WITHSM2": algorithm = SHA256withSM2; return true;
                case "SM3WITHSM2": algorithm = SM3withSM2; return true;

                default: break;
            }
            string prefix;
            string suffix;
            int index = mechanism.IndexOf("WITH");
            if (index >= 0)
            {
                prefix = mechanism.Substring(0, index);
                suffix = mechanism.Substring(index + 4, mechanism.Length - index - 4);
            }
            else
            {
                prefix = string.Empty;
                suffix = mechanism;
            }
            if (suffix == "ELGAMAL")
            {
                algorithm = null;
                return false;
            }
            if (HashAlgorithmHelper.TryGetAlgorithm(prefix, out IHashAlgorithm hashAlgorithm))
            {
                switch (suffix)
                {
                    case "CVC-ECDSA": algorithm = new CVC_ECDSA(hashAlgorithm); return true;
                    case "DSA": algorithm = new DSA(hashAlgorithm); return true;
                    case "ECDSA": algorithm = new ECDSA(hashAlgorithm); return true;
                    case "ECGOST3410": case "ECGOST3410-2001": case "ECGOST-3410": case "ECGOST-3410-2001": algorithm = new ECGOST3410(hashAlgorithm); return true;
                    case "ECNR": algorithm = new ECNR(hashAlgorithm); return true;
                    case "GOST3410": case "GOST3410-94": case "GOST-3410": case "GOST-3410-94": algorithm = new GOST3410(hashAlgorithm); return true;
                    case "PLAIN-ECDSA": algorithm = new PLAIN_ECDSA(hashAlgorithm); return true;
                    case "RSA": algorithm = new RSA(hashAlgorithm); return true;
                    case "ISO9796-2": case "RSA/ISO9796-2": case "RSAANDISO9796-2": algorithm = new RSAandISO9796_2(hashAlgorithm); return true;
                    case "RSAANDMGF1": algorithm = new RSAandMGF1(hashAlgorithm); return true;
                    case "RSA/X9.31": case "RSA/X931": case "RSAANDX931": case "RSAANDX9.31": algorithm = new RSAandX931(hashAlgorithm); return true;
                    case "SM2": algorithm = new SM2(hashAlgorithm); return true;
                    default: break;
                }
            }
            algorithm = null;
            return false;
        }
    }
}