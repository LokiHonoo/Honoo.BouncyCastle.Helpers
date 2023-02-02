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
        /// Try generate asymmetric public key from asymmetric private key.
        /// </summary>
        /// <param name="privateKey">Asymmetric private key.</param>
        /// <param name="publicKey">Asymmetric public key.</param>
        /// <returns></returns>
        public static bool TryGeneratePublicKey(AsymmetricKeyParameter privateKey, out AsymmetricKeyParameter publicKey)
        {
            if (privateKey == null)
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
                case "DSA": algorithm = AsymmetricAlgorithms.DSA; return true;
                case "ECDH": algorithm = AsymmetricAlgorithms.ECDH; return true;
                case "ECDSA": algorithm = AsymmetricAlgorithms.ECDSA; return true;
                case "ECGOST3410": case "ECGOST3410-2001": algorithm = AsymmetricAlgorithms.ECGOST3410; return true;
                case "ED25519": algorithm = AsymmetricAlgorithms.Ed25519; return true;
                case "ED448": algorithm = AsymmetricAlgorithms.Ed448; return true;
                case "ELGAMAL": algorithm = AsymmetricAlgorithms.ElGamal; return true;
                case "GOST3410": case "GOST3410-94": algorithm = AsymmetricAlgorithms.GOST3410; return true;
                case "RSA": algorithm = AsymmetricAlgorithms.RSA; return true;
                case "SM2": algorithm = AsymmetricAlgorithms.SM2; return true;
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
            if (string.IsNullOrWhiteSpace(mechanism))
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
                case "ISO9796-1":
                case "ISO9796-1PADDING":
                case "ISO9796D1":
                case "ISO9796D1PADDING": padding = AsymmetricPaddingMode.ISO9796_1; return true;
                default: padding = null; return false;
            }
        }
    }
}