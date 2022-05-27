using Honoo.BouncyCastle.Helpers.Security.Crypto.Asymmetric;
using System;

namespace Honoo.BouncyCastle.Helpers
{
    /// <summary>
    /// Asymmetric algorithm helper.
    /// </summary>
    public static class AsymmetricAlgorithmHelper
    {
        /// <summary>
        /// DSA.
        /// <para/>Legal key size 512-1024 bits (64 bits increments).
        /// </summary>
        public static IAsymmetricAlgorithm DSA { get; } = new DSA();

        /// <summary>
        /// ECDH.
        /// </summary>
        public static IECDH ECDH { get; } = new ECDH();

        /// <summary>
        /// ECDSA.
        /// <para/>Legal key size 512-1024 bits (64 bits increments).
        /// </summary>
        public static IAsymmetricAlgorithm ECDSA { get; } = new ECDSA();

        /// <summary>
        /// ECGOST3410.
        /// </summary>
        public static IAsymmetricAlgorithm ECGOST3410 { get; } = new ECGOST3410();

        /// <summary>
        /// Ed25519.
        /// </summary>
        public static IAsymmetricAlgorithm Ed25519 { get; } = new Ed25519();

        /// <summary>
        /// Ed448.
        /// </summary>
        public static IAsymmetricAlgorithm Ed448 { get; } = new Ed448();

        /// <summary>
        /// ElGamal.
        /// <para/>Legal key size is more than or equal to 256 bits (64 bits increments).
        /// </summary>
        public static IAsymmetricEncryptionAlgorithm ElGamal { get; } = new ElGamal();

        /// <summary>
        /// GOST3410
        /// <para/>Legal key size 512, 1024 bits.
        /// </summary>
        public static IAsymmetricAlgorithm GOST3410 { get; } = new GOST3410();

        /// <summary>
        /// RSA.
        /// <para/>Legal key size is more than or equal to 512 bits (64 bits increments).
        /// </summary>
        public static IAsymmetricEncryptionAlgorithm RSA { get; } = new RSA();

        /// <summary>
        /// SM2.
        /// </summary>
        public static IAsymmetricAlgorithm SM2 { get; } = new SM2();

        /// <summary>
        /// Try get asymmetric algorithm from mechanism.
        /// </summary>
        /// <param name="mechanism">Asymmetric algorithm mechanism.</param>
        /// <param name="algorithm">Asymmetric algorithm.</param>
        /// <returns></returns>
        public static bool TryGetAlgorithm(string mechanism, out IAsymmetricAlgorithm algorithm)
        {
            if (string.IsNullOrWhiteSpace(mechanism))
            {
                algorithm = null;
                return false;
            }
            mechanism = mechanism.Replace('_', '-').ToUpperInvariant();
            switch (mechanism)
            {
                case "DSA": algorithm = DSA; return true;
                case "ECDH": algorithm = ECDH; return true;
                case "ECDSA": algorithm = ECDSA; return true;
                case "ECGOST3410": case "ECGOST3410-2001": algorithm = ECGOST3410; return true;
                case "ED25519": algorithm = new Ed25519(); return true;
                case "ED448": algorithm = new Ed448(); return true;
                case "ELGAMAL": algorithm = ElGamal; return true;
                case "GOST3410": case "GOST3410-94": algorithm = GOST3410; return true;
                case "RSA": algorithm = RSA; return true;
                case "SM2": algorithm = SM2; return true;
                default: algorithm = null; return false;
            }
        }

        /// <summary>
        /// Try get asymmetric algorithm from mechanism.
        /// </summary>
        /// <param name="mechanism">Asymmetric algorithm mechanism.</param>
        /// <param name="algorithm">Asymmetric algorithm.</param>
        /// <returns></returns>
        public static bool TryGetAlgorithm(string mechanism, out IAsymmetricEncryptionAlgorithm algorithm)
        {
            if (string.IsNullOrWhiteSpace(mechanism))
            {
                algorithm = null;
                return false;
            }
            mechanism = mechanism.ToUpperInvariant();
            switch (mechanism)
            {
                case "ELGAMAL": algorithm = ElGamal; return true;
                case "RSA": algorithm = RSA; return true;
                default: algorithm = null; return false;
            }
        }

        /// <summary>
        /// Try get asymmetric algorithm padding mode from mechanism.
        /// </summary>
        /// <param name="mechanism">Asymmetric padding mode mechanism.</param>
        /// <param name="padding">Asymmetric padding mode.</param>
        /// <returns></returns>
        public static bool TryGetPaddingMode(string mechanism, out AsymmetricPaddingMode? padding)
        {
            if (mechanism is null)
            {
                throw new ArgumentNullException(nameof(mechanism));
            }
            mechanism = mechanism.Replace('_', '-').ToUpperInvariant();
            switch (mechanism)
            {
                case "PKCS1": case "PKCS1PADDING": padding = AsymmetricPaddingMode.PKCS1; return true;
                case "OAEP": case "OAEPPADDING": padding = AsymmetricPaddingMode.OAEP; return true;
                case "NOPADDING": padding = AsymmetricPaddingMode.NoPadding; return true;
                case "ISO9796_1": case "ISO9796_1PADDING": case "ISO9796D1": case "ISO9796D1PADDING": padding = AsymmetricPaddingMode.ISO9796_1; return true;
                case "OAEPWITHMD5ANDMGF1": case "OAEPWITHMD5ANDMGF1PADDING": padding = AsymmetricPaddingMode.OAEPwithMD5andMGF1; return true;
                case "OAEPWITHSHA1ANDMGF1":
                case "OAEPWITHSHA1ANDMGF1PADDING":
                case "OAEPWITHSHA-1ANDMGF1":
                case "OAEPWITHSHA-1ANDMGF1PADDING": padding = AsymmetricPaddingMode.OAEPwithSHA1andMGF1; return true;
                case "OAEPWITHSHA224ANDMGF1":
                case "OAEPWITHSHA224ANDMGF1PADDING":
                case "OAEPWITHSHA-224ANDMGF1":
                case "OAEPWITHSHA-224ANDMGF1PADDING": padding = AsymmetricPaddingMode.OAEPwithSHA224andMGF1; return true;
                case "OAEPWITHSHA256ANDMGF1":
                case "OAEPWITHSHA256ANDMGF1PADDING":
                case "OAEPWITHSHA-256ANDMGF1":
                case "OAEPWITHSHA-256ANDMGF1PADDING": padding = AsymmetricPaddingMode.OAEPwithSHA256andMGF1; return true;
                case "OAEPWITHSHA384ANDMGF1":
                case "OAEPWITHSHA384ANDMGF1PADDING":
                case "OAEPWITHSHA-384ANDMGF1":
                case "OAEPWITHSHA-384ANDMGF1PADDING": padding = AsymmetricPaddingMode.OAEPwithSHA384andMGF1; return true;
                case "OAEPWITHSHA512ANDMGF1":
                case "OAEPWITHSHA512ANDMGF1PADDING":
                case "OAEPWITHSHA-512ANDMGF1":
                case "OAEPWITHSHA-512ANDMGF1PADDING": padding = AsymmetricPaddingMode.OAEPwithSHA512andMGF1; return true;
                case "OAEPWITHSHA1ANDMGF1WITHSHA1":
                case "OAEPWITHSHA1ANDMGF1WITHSHA1PADDING":
                case "OAEPWITHSHA-1ANDMGF1WITHSHA-1":
                case "OAEPWITHSHA-1ANDMGF1WITHSHA-1PADDING": padding = AsymmetricPaddingMode.OAEPwithSHA1andMGF1withSHA1; return true;
                case "OAEPWITHSHA224ANDMGF1WITHSHA1":
                case "OAEPWITHSHA224ANDMGF1WITHSHA1PADDING":
                case "OAEPWITHSHA-224ANDMGF1WITHSHA-1":
                case "OAEPWITHSHA-224ANDMGF1WITHSHA-1PADDING": padding = AsymmetricPaddingMode.OAEPwithSHA224andMGF1withSHA1; return true;
                case "OAEPWITHSHA256ANDMGF1WITHSHA1":
                case "OAEPWITHSHA256ANDMGF1WITHSHA1PADDING":
                case "OAEPWITHSHA-256ANDMGF1WITHSHA-1":
                case "OAEPWITHSHA-256ANDMGF1WITHSHA-1PADDING": padding = AsymmetricPaddingMode.OAEPwithSHA256andMGF1withSHA1; return true;
                case "OAEPWITHSHA384ANDMGF1WITHSHA1":
                case "OAEPWITHSHA384ANDMGF1WITHSHA1PADDING":
                case "OAEPWITHSHA-384ANDMGF1WITHSHA-1":
                case "OAEPWITHSHA-384ANDMGF1WITHSHA-1PADDING": padding = AsymmetricPaddingMode.OAEPwithSHA384andMGF1withSHA1; return true;
                case "OAEPWITHSHA512ANDMGF1WITHSHA1":
                case "OAEPWITHSHA512ANDMGF1WITHSHA1PADDING":
                case "OAEPWITHSHA-512ANDMGF1WITHSHA-1":
                case "OAEPWITHSHA-512ANDMGF1WITHSHA-1PADDING": padding = AsymmetricPaddingMode.OAEPwithSHA512andMGF1withSHA1; return true;
                case "OAEPWITHSHA256ANDMGF1WITHSHA256":
                case "OAEPWITHSHA256ANDMGF1WITHSHA256PADDING":
                case "OAEPWITHSHA-256ANDMGF1WITHSHA-256":
                case "OAEPWITHSHA-256ANDMGF1WITHSHA-256PADDING": padding = AsymmetricPaddingMode.OAEPwithSHA256andMGF1withSHA256; return true;
                case "OAEPWITHSHA384ANDMGF1WITHSHA256":
                case "OAEPWITHSHA384ANDMGF1WITHSHA256PADDING":
                case "OAEPWITHSHA-384ANDMGF1WITHSHA-256":
                case "OAEPWITHSHA-384ANDMGF1WITHSHA-256PADDING": padding = AsymmetricPaddingMode.OAEPwithSHA384andMGF1withSHA256; return true;
                case "OAEPWITHSHA512ANDMGF1WITHSHA256":
                case "OAEPWITHSHA512ANDMGF1WITHSHA256PADDING":
                case "OAEPWITHSHA-512ANDMGF1WITHSHA-256":
                case "OAEPWITHSHA-512ANDMGF1WITHSHA-256PADDING": padding = AsymmetricPaddingMode.OAEPwithSHA512andMGF1withSHA256; return true;

                default: padding = null; return false;
            }
        }
    }
}