using Org.BouncyCastle.Asn1.CryptoPro;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using System.Security.Cryptography;

namespace Honoo.BouncyCastle.Helpers.Security.Crypto.Asymmetric
{
    /// <summary>
    /// ECGOST3410.
    /// <para/>Uses EllipticCurve.GostR3410x2001CryptoProA by default.
    /// </summary>
    public sealed class ECGOST3410 : AsymmetricAlgorithm
    {
        #region Properties

        private readonly ECGOST3410EllipticCurve _ellipticCurve;

        /// <summary>
        /// Curve.
        /// </summary>
        public ECGOST3410EllipticCurve EllipticCurve => _ellipticCurve;

        #endregion Properties

        #region Constructor

        /// <summary>
        /// ECGOST3410.
        /// <para/>Uses EllipticCurve.GostR3410x2001CryptoProA by default.
        /// </summary>
        public ECGOST3410() : this(ECGOST3410EllipticCurve.GostR3410x2001CryptoProA)
        {
        }

        /// <summary>
        /// ECGOST3410.
        /// <para/>Uses EllipticCurve.GostR3410x2001CryptoProA by default.
        /// </summary>
        /// <param name="ellipticCurve">Elliptic curve.</param>
        public ECGOST3410(ECGOST3410EllipticCurve ellipticCurve) : base("ECGOST3410")
        {
            _ellipticCurve = ellipticCurve;
        }

        #endregion Constructor

        /// <summary>
        /// Generate key pair.
        /// </summary>
        /// <returns></returns>
        public override AsymmetricCipherKeyPair GenerateKeyPair()
        {
            X9ECParameters parameters2 = GenerateEllipticCurve(_ellipticCurve);
            ECDomainParameters parameters3 = new ECDomainParameters(parameters2);
            KeyGenerationParameters parameters = new ECKeyGenerationParameters(parameters3, Common.ThreadSecureRandom.Value);
            IAsymmetricCipherKeyPairGenerator generator = new ECKeyPairGenerator();
            generator.Init(parameters);
            return generator.GenerateKeyPair();
        }

        private static X9ECParameters GenerateEllipticCurve(ECGOST3410EllipticCurve ellipticCurve)
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