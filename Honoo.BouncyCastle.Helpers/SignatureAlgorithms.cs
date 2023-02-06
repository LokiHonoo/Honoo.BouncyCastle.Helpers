using Honoo.BouncyCastle.Helpers.Security.Crypto.Signature;

namespace Honoo.BouncyCastle.Helpers
{
    /// <summary>
    /// Some signature algorithms. These algorithms has a corresponding OID.
    /// </summary>
    public static class SignatureAlgorithms
    {
        #region ECDSA

        /// <summary></summary>
        public static ISignatureAlgorithm SHA1withECDSA { get; } = new ECDSA(HashAlgorithms.SHA1);

        /// <summary></summary>
        public static ISignatureAlgorithm SHA224withECDSA { get; } = new ECDSA(HashAlgorithms.SHA224);

        /// <summary></summary>
        public static ISignatureAlgorithm SHA256withECDSA { get; } = new ECDSA(HashAlgorithms.SHA256);

        /// <summary></summary>
        public static ISignatureAlgorithm SHA3_224withECDSA { get; } = new ECDSA(HashAlgorithms.SHA3_224);

        /// <summary></summary>
        public static ISignatureAlgorithm SHA3_256withECDSA { get; } = new ECDSA(HashAlgorithms.SHA3_256);

        /// <summary></summary>
        public static ISignatureAlgorithm SHA3_384withECDSA { get; } = new ECDSA(HashAlgorithms.SHA3_384);

        /// <summary></summary>
        public static ISignatureAlgorithm SHA3_512withECDSA { get; } = new ECDSA(HashAlgorithms.SHA3_512);

        /// <summary></summary>
        public static ISignatureAlgorithm SHA384withECDSA { get; } = new ECDSA(HashAlgorithms.SHA384);

        /// <summary></summary>
        public static ISignatureAlgorithm SHA512withECDSA { get; } = new ECDSA(HashAlgorithms.SHA512);

        #endregion ECDSA

        #region CVC-ECDSA

        /// <summary></summary>
        public static ISignatureAlgorithm SHA1withCVC_ECDSA { get; } = new CVC_ECDSA(HashAlgorithms.SHA1);

        /// <summary></summary>
        public static ISignatureAlgorithm SHA224withCVC_ECDSA { get; } = new CVC_ECDSA(HashAlgorithms.SHA224);

        /// <summary></summary>
        public static ISignatureAlgorithm SHA256withCVC_ECDSA { get; } = new CVC_ECDSA(HashAlgorithms.SHA256);

        /// <summary></summary>
        public static ISignatureAlgorithm SHA384withCVC_ECDSA { get; } = new CVC_ECDSA(HashAlgorithms.SHA384);

        /// <summary></summary>
        public static ISignatureAlgorithm SHA512withCVC_ECDSA { get; } = new CVC_ECDSA(HashAlgorithms.SHA512);

        #endregion CVC-ECDSA

        #region PLAIN-ECDSA

        /// <summary></summary>
        public static ISignatureAlgorithm RIPEMD160withPLAIN_ECDSA { get; } = new PLAIN_ECDSA(HashAlgorithms.RIPEMD160);

        /// <summary></summary>
        public static ISignatureAlgorithm SHA1withPLAIN_ECDSA { get; } = new PLAIN_ECDSA(HashAlgorithms.SHA1);

        /// <summary></summary>
        public static ISignatureAlgorithm SHA224withPLAIN_ECDSA { get; } = new PLAIN_ECDSA(HashAlgorithms.SHA224);

        /// <summary></summary>
        public static ISignatureAlgorithm SHA256withPLAIN_ECDSA { get; } = new PLAIN_ECDSA(HashAlgorithms.SHA256);

        /// <summary></summary>
        public static ISignatureAlgorithm SHA384withPLAIN_ECDSA { get; } = new PLAIN_ECDSA(HashAlgorithms.SHA384);

        /// <summary></summary>
        public static ISignatureAlgorithm SHA512withPLAIN_ECDSA { get; } = new PLAIN_ECDSA(HashAlgorithms.SHA512);

        #endregion PLAIN-ECDSA

        #region RSA

        /// <summary></summary>
        public static ISignatureAlgorithm MD2withRSA { get; } = new RSA(HashAlgorithms.MD2);

        /// <summary></summary>
        public static ISignatureAlgorithm MD5withRSA { get; } = new RSA(HashAlgorithms.MD5);

        /// <summary></summary>
        public static ISignatureAlgorithm PSSwithRSA { get; } = new RSAandMGF1(HashAlgorithms.SHA1);

        /// <summary></summary>
        public static ISignatureAlgorithm RIPEMD128withRSA { get; } = new RSA(HashAlgorithms.RIPEMD128);

        /// <summary></summary>
        public static ISignatureAlgorithm RIPEMD160withRSA { get; } = new RSA(HashAlgorithms.RIPEMD160);

        /// <summary></summary>
        public static ISignatureAlgorithm RIPEMD256withRSA { get; } = new RSA(HashAlgorithms.RIPEMD256);

        /// <summary></summary>
        public static ISignatureAlgorithm SHA1withRSA { get; } = new RSA(HashAlgorithms.SHA1);

        /// <summary></summary>
        public static ISignatureAlgorithm SHA224withRSA { get; } = new RSA(HashAlgorithms.SHA224);

        /// <summary></summary>
        public static ISignatureAlgorithm SHA256withRSA { get; } = new RSA(HashAlgorithms.SHA256);

        /// <summary></summary>
        public static ISignatureAlgorithm SHA3_224withRSA { get; } = new RSA(HashAlgorithms.SHA3_224);

        /// <summary></summary>
        public static ISignatureAlgorithm SHA3_256withRSA { get; } = new RSA(HashAlgorithms.SHA3_256);

        /// <summary></summary>
        public static ISignatureAlgorithm SHA3_384withRSA { get; } = new RSA(HashAlgorithms.SHA3_384);

        /// <summary></summary>
        public static ISignatureAlgorithm SHA3_512withRSA { get; } = new RSA(HashAlgorithms.SHA3_512);

        /// <summary></summary>
        public static ISignatureAlgorithm SHA384withRSA { get; } = new RSA(HashAlgorithms.SHA384);

        /// <summary></summary>
        public static ISignatureAlgorithm SHA512withRSA { get; } = new RSA(HashAlgorithms.SHA512);

        #endregion RSA

        #region DSA

        /// <summary></summary>
        public static ISignatureAlgorithm SHA1withDSA { get; } = new DSA(HashAlgorithms.SHA1);

        /// <summary></summary>
        public static ISignatureAlgorithm SHA224withDSA { get; } = new DSA(HashAlgorithms.SHA224);

        /// <summary></summary>
        public static ISignatureAlgorithm SHA256withDSA { get; } = new DSA(HashAlgorithms.SHA256);

        /// <summary></summary>
        public static ISignatureAlgorithm SHA3_224withDSA { get; } = new DSA(HashAlgorithms.SHA3_224);

        /// <summary></summary>
        public static ISignatureAlgorithm SHA3_256withDSA { get; } = new DSA(HashAlgorithms.SHA3_256);

        /// <summary></summary>
        public static ISignatureAlgorithm SHA3_384withDSA { get; } = new DSA(HashAlgorithms.SHA3_384);

        /// <summary></summary>
        public static ISignatureAlgorithm SHA3_512withDSA { get; } = new DSA(HashAlgorithms.SHA3_512);

        /// <summary></summary>
        public static ISignatureAlgorithm SHA384withDSA { get; } = new DSA(HashAlgorithms.SHA384);

        /// <summary></summary>
        public static ISignatureAlgorithm SHA512withDSA { get; } = new DSA(HashAlgorithms.SHA512);

        #endregion DSA

        #region GOST3410

        /// <summary>
        /// Uses substitution box "D-A" by default.
        /// </summary>
        public static ISignatureAlgorithm GOST3411withGOST3410 { get; } = new GOST3410(HashAlgorithms.GOST3411);

        #endregion GOST3410

        #region ECGOST3410

        /// <summary>
        /// Uses substitution box "D-A" by default.
        /// </summary>
        public static ISignatureAlgorithm GOST3411withECGOST3410 { get; } = new ECGOST3410(HashAlgorithms.GOST3411);

        #endregion ECGOST3410

        #region SM2

        /// <summary></summary>
        public static ISignatureAlgorithm SHA256withSM2 { get; } = new SM2(HashAlgorithms.SHA256);

        /// <summary></summary>
        public static ISignatureAlgorithm SM3withSM2 { get; } = new SM2(HashAlgorithms.SM3);

        #endregion SM2

        ///// <summary>
        /////
        ///// </summary>
        //public static ISignatureAlgorithm Ed25519 { get; } = new Ed25519();

        ///// <summary>
        ///// Uses context byte[0] by default.
        ///// </summary>
        //public static ISignatureAlgorithm Ed25519ctx { get; } = new Ed25519ctx();

        ///// <summary>
        ///// Uses context byte[0] by default.
        ///// </summary>
        //public static ISignatureAlgorithm Ed25519ph { get; } = new Ed25519ph();

        ///// <summary>
        ///// Uses context byte[0] by default.
        ///// </summary>
        //public static ISignatureAlgorithm Ed448 { get; } = new Ed448();

        ///// <summary>
        ///// Uses context byte[0] by default.
        ///// </summary>
        //public static ISignatureAlgorithm Ed448ph { get; } = new Ed448ph();
    }
}