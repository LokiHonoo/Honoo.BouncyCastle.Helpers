using Honoo.BouncyCastle.Helpers.Security.Crypto.Asymmetric;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math.EC.Multiplier;
using Org.BouncyCastle.Pkcs;
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
        /// Generate asymmetric public key from asymmetric private key.
        /// </summary>
        /// <param name="privateKey">Asymmetric private key.</param>
        /// <returns></returns>
        public static AsymmetricKeyParameter GeneratePublicKey(AsymmetricKeyParameter privateKey)
        {
            Type type = privateKey.GetType();
            if (type == typeof(RsaPrivateCrtKeyParameters))
            {
                RsaPrivateCrtKeyParameters pri = (RsaPrivateCrtKeyParameters)privateKey;
                return new RsaKeyParameters(false, pri.Modulus, pri.PublicExponent);
            }
           else if (type == typeof(DsaPrivateKeyParameters))
            {
                DsaPrivateKeyParameters pri = (DsaPrivateKeyParameters)privateKey;
                return new DsaPublicKeyParameters(pri.X, pri.Parameters);
            }
            else
            {

            }


            //PrivateKeyInfo info = PrivateKeyInfoFactory.CreatePrivateKeyInfo(privateKey);
            //Asn1Sequence seq = Asn1Sequence.GetInstance(info.GetDerEncoded());
            //switch (info.PrivateKeyAlgorithm.Algorithm.Id)
            //{
            //    case "1"://RSA
            //        var aaa = (RsaPrivateCrtKeyParameters)privateKey;
            //        aaa.Modulus
            //        RsaPrivateKeyStructure rsa = RsaPrivateKeyStructure.GetInstance(seq);
            //        //RsaPrivateCrtKeyParameters pri = new RsaPrivateCrtKeyParameters(rsa.Modulus, rsa.PublicExponent, rsa.PrivateExponent, rsa.Prime1, rsa.Prime2, rsa.Exponent1, rsa.Exponent2, rsa.Coefficient);
            //        return new RsaKeyParameters(false, rsa.Modulus, rsa.PublicExponent);

            //    case "2"://DSA
            //        DerInteger p = (DerInteger)seq[1];
            //        DerInteger q = (DerInteger)seq[2];
            //        DerInteger g = (DerInteger)seq[3];
            //        DerInteger y = (DerInteger)seq[4];
            //        DerInteger x = (DerInteger)seq[5];
            //        DsaParameters parameters = new DsaParameters(p.Value, q.Value, g.Value);
            //        //var pri2 = new DsaPrivateKeyParameters(x.Value, parameters);
            //        return new DsaPublicKeyParameters(y.Value, parameters);

            //    case "3"://EC
            //        ECPrivateKeyStructure pKey = ECPrivateKeyStructure.GetInstance(seq);
            //        AlgorithmIdentifier algId = new AlgorithmIdentifier(X9ObjectIdentifiers.IdECPublicKey, pKey.GetParameters());
            //        DerBitString pubKey = pKey.GetPublicKey();

            //        ECDomainParameters ec = privKey.Parameters;
            //        ECPoint q = new FixedPointCombMultiplier().Multiply(ec.G, privKey.D);

            //        if (privKey.PublicKeyParamSet != null)
            //        {
            //            return new ECPublicKeyParameters(privKey.AlgorithmName, q, privKey.PublicKeyParamSet);
            //        }

            //        return new ECPublicKeyParameters(privKey.AlgorithmName, q, ec);

            //    default: throw new ArgumentException("Unknown private key.");
            //}

            return null;
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
                default: padding = null; return false;
            }
        }
    }
}