using Honoo.BouncyCastle.Helpers.Security.Crypto.Asymmetric;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Math.EC.Multiplier;

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
        /// Try generate asymmetric public key from asymmetric private key.
        /// </summary>
        /// <param name="privateKey">Asymmetric private key.</param>
        /// <param name="publicKey">Asymmetric public key.</param>
        /// <returns></returns>
        public static bool TryGeneratePublicKey(AsymmetricKeyParameter privateKey, out AsymmetricKeyParameter publicKey)
        {
            if (privateKey is null)
            {
                publicKey = null;
                return false;
            }
            switch (privateKey)
            {
                case RsaPrivateCrtKeyParameters pri:
                    {
                        publicKey = new RsaKeyParameters(false, pri.Modulus, pri.PublicExponent);
                        return true;
                    }

                case DsaPrivateKeyParameters pri:
                    {
                        BigInteger y = pri.Parameters.G.ModPow(pri.X, pri.Parameters.P);
                        publicKey = new DsaPublicKeyParameters(y, pri.Parameters);
                        return true;
                    }

                case ECPrivateKeyParameters pri:
                    {
                        ECPoint q = new FixedPointCombMultiplier().Multiply(pri.Parameters.G, pri.D);
                        publicKey = new ECPublicKeyParameters(pri.AlgorithmName, q, pri.Parameters);
                        return true;
                    }

                case ElGamalPrivateKeyParameters pri:
                    {
                        BigInteger y = pri.Parameters.G.ModPow(pri.X, pri.Parameters.P);
                        publicKey = new ElGamalPublicKeyParameters(y, pri.Parameters);
                        return true;
                    }

                case Gost3410PrivateKeyParameters pri:
                    {
                        BigInteger y = pri.Parameters.A.ModPow(pri.X, pri.Parameters.P);
                        publicKey = new Gost3410PublicKeyParameters(y, pri.Parameters);
                        return true;
                    }

                case Ed448PrivateKeyParameters pri:
                    {
                        publicKey = pri.GeneratePublicKey();
                        return true;
                    }

                case Ed25519PrivateKeyParameters pri:
                    {
                        publicKey = pri.GeneratePublicKey();
                        return true;
                    }

                default:
                    publicKey = null;
                    return false;
            }
        }

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
                padding = null;
                return false;
            }
            mechanism = mechanism.Replace('_', '-').ToUpperInvariant();
            switch (mechanism)
            {
                case "PKCS1": case "PKCS1PADDING": padding = AsymmetricPaddingMode.PKCS1; return true;
                case "OAEP": case "OAEPPADDING": padding = AsymmetricPaddingMode.OAEP; return true;
                case "NOPADDING": padding = AsymmetricPaddingMode.NoPadding; return true;
                case "ISO9796_1": case "ISO9796_1PADDING": case "ISO9796D1": case "ISO9796D1PADDING": padding = AsymmetricPaddingMode.ISO9796_1; return true;
                default: padding = null; return false;
            }
        }
    }
}