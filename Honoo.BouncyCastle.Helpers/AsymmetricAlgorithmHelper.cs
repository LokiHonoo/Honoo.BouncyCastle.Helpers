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
        public static DSA DSA { get; } = new DSA();

        /// <summary>
        /// ECDH.
        /// </summary>
        public static ECDH ECDH { get; } = new ECDH();

        /// <summary>
        /// ECDSA.
        /// </summary>
        public static ECDSA ECDSA { get; } = new ECDSA();

        /// <summary>
        /// ECGOST3410.
        /// </summary>
        public static ECGOST3410 ECGOST3410 { get; } = new ECGOST3410();

        /// <summary>
        /// Ed25519.
        /// </summary>
        public static Ed25519 Ed25519 { get; } = new Ed25519();

        /// <summary>
        /// Ed448.
        /// </summary>
        public static Ed448 Ed448 { get; } = new Ed448();

        /// <summary>
        /// ElGamal.
        /// <para/>Legal key size is more than or equal to 8 bits (8 bits increments).
        /// </summary>
        public static ElGamal ElGamal { get; } = new ElGamal();

        /// <summary>
        /// GOST3410
        /// <para/>Legal key size 512, 1024 bits.
        /// </summary>
        public static GOST3410 GOST3410 { get; } = new GOST3410();

        /// <summary>
        /// RSA.
        /// <para/>Legal key size is more than or equal to 24 bits (8 bits increments).
        /// </summary>
        public static RSA RSA { get; } = new RSA();

        /// <summary>
        /// SM2.
        /// </summary>
        public static SM2 SM2 { get; } = new SM2();

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
                case RsaPrivateCrtKeyParameters inputKey:
                    {
                        publicKey = new RsaKeyParameters(false, inputKey.Modulus, inputKey.PublicExponent);
                        return true;
                    }

                case DsaPrivateKeyParameters inputKey:
                    {
                        BigInteger y = inputKey.Parameters.G.ModPow(inputKey.X, inputKey.Parameters.P);
                        publicKey = new DsaPublicKeyParameters(y, inputKey.Parameters);
                        return true;
                    }

                case ECPrivateKeyParameters inputKey:
                    {
                        ECPoint q = new FixedPointCombMultiplier().Multiply(inputKey.Parameters.G, inputKey.D);
                        publicKey = new ECPublicKeyParameters(inputKey.AlgorithmName, q, inputKey.Parameters);
                        return true;
                    }

                case ElGamalPrivateKeyParameters inputKey:
                    {
                        BigInteger y = inputKey.Parameters.G.ModPow(inputKey.X, inputKey.Parameters.P);
                        publicKey = new ElGamalPublicKeyParameters(y, inputKey.Parameters);
                        return true;
                    }

                case Gost3410PrivateKeyParameters inputKey:
                    {
                        BigInteger y = inputKey.Parameters.A.ModPow(inputKey.X, inputKey.Parameters.P);
                        publicKey = new Gost3410PublicKeyParameters(y, inputKey.Parameters);
                        return true;
                    }

                case Ed448PrivateKeyParameters inputKey:
                    {
                        publicKey = inputKey.GeneratePublicKey();
                        return true;
                    }

                case Ed25519PrivateKeyParameters inputKey:
                    {
                        publicKey = inputKey.GeneratePublicKey();
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
                case "NOPADDING": padding = AsymmetricPaddingMode.NoPadding; return true;
                case "PKCS1": case "PKCS1PADDING": padding = AsymmetricPaddingMode.PKCS1; return true;
                case "OAEP": case "OAEPPADDING": padding = AsymmetricPaddingMode.OAEP; return true;
                case "ISO9796_1": case "ISO9796_1PADDING": case "ISO9796D1": case "ISO9796D1PADDING": padding = AsymmetricPaddingMode.ISO9796_1; return true;
                default: padding = null; return false;
            }
        }
    }
}