using Org.BouncyCastle.Asn1.CryptoPro;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;

namespace Honoo.BouncyCastle.Helpers.Security.Crypto.Asymmetric
{
    /// <summary>
    /// ECGOST3410.
    /// </summary>
    public sealed class ECGOST3410 : AsymmetricAlgorithm
    {
        #region Constructor

        /// <summary>
        /// ECGOST3410.
        /// </summary>
        public ECGOST3410() : base("ECGOST3410")
        {
        }

        #endregion Constructor

        /// <summary>
        /// Generate key pair.
        /// <para/>Uses EllipticCurve.GostR3410x2001CryptoProA by default.
        /// </summary>
        /// <returns></returns>
        public override AsymmetricCipherKeyPair GenerateKeyPair()
        {
            return GenerateKeyPair(ECGOST3410EllipticCurve.GostR3410x2001CryptoProA);
        }

        /// <summary>
        /// Generate key pair.
        /// </summary>
        /// <returns></returns>
        [SuppressMessage("Performance", "CA1822:将成员标记为 static", Justification = "<挂起>")]
        public AsymmetricCipherKeyPair GenerateKeyPair(ECGOST3410EllipticCurve ellipticCurve)
        {
            X9ECParameters parameters2 = GenerateX9(ellipticCurve);
            ECDomainParameters parameters3 = new ECDomainParameters(parameters2);
            KeyGenerationParameters parameters = new ECKeyGenerationParameters(parameters3, Common.ThreadSecureRandom.Value);
            IAsymmetricCipherKeyPairGenerator generator = new ECKeyPairGenerator();
            generator.Init(parameters);
            return generator.GenerateKeyPair();
        }

        private static X9ECParameters GenerateX9(ECGOST3410EllipticCurve ellipticCurve)
        {
            switch (ellipticCurve)
            {
                case ECGOST3410EllipticCurve.GostR3410x2001CryptoProA: return ECGost3410NamedCurves.GetByOidX9(CryptoProObjectIdentifiers.GostR3410x2001CryptoProA);
                case ECGOST3410EllipticCurve.GostR3410x2001CryptoProB: return ECGost3410NamedCurves.GetByOidX9(CryptoProObjectIdentifiers.GostR3410x2001CryptoProB);
                case ECGOST3410EllipticCurve.GostR3410x2001CryptoProC: return ECGost3410NamedCurves.GetByOidX9(CryptoProObjectIdentifiers.GostR3410x2001CryptoProC);
                case ECGOST3410EllipticCurve.GostR3410x2001CryptoProXchA: return ECGost3410NamedCurves.GetByOidX9(CryptoProObjectIdentifiers.GostR3410x2001CryptoProXchA);
                case ECGOST3410EllipticCurve.GostR3410x2001CryptoProXchB: return ECGost3410NamedCurves.GetByOidX9(CryptoProObjectIdentifiers.GostR3410x2001CryptoProXchB);
                default: throw new CryptographicException("Unsupported elliptic curve.");
            }
        }
    }
}