using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;

namespace Honoo.BouncyCastle.Helpers.Security.Crypto.Asymmetric
{
    /// <summary>
    /// ECDSA.
    /// <para/>Uses EllipticCurve.SecP256r1 by default.
    /// </summary>
    public sealed class ECDSA : AsymmetricAlgorithm
    {
        #region Properties

        private readonly ECDSAEllipticCurve _ellipticCurve;

        #endregion Properties

        #region Constructor

        /// <summary>
        /// ECDSA.
        /// <para/>Uses EllipticCurve.SecP256r1 by default.
        /// </summary>
        public ECDSA() : this(ECDSAEllipticCurve.SecP256r1)
        {
        }

        /// <summary>
        /// ECDSA.
        /// <para/>Uses EllipticCurve.SecP256r1 by default.
        /// </summary>
        /// <param name="ellipticCurve">Elliptic curve.</param>
        public ECDSA(ECDSAEllipticCurve ellipticCurve) : base("ECDSA")
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

        internal static X9ECParameters GenerateEllipticCurve(ECDSAEllipticCurve ellipticCurve)
        {
            switch (ellipticCurve)
            {
                case ECDSAEllipticCurve.SecT113r1: return SecNamedCurves.GetByOid(SecObjectIdentifiers.SecT113r1);
                case ECDSAEllipticCurve.SecT113r2: return SecNamedCurves.GetByOid(SecObjectIdentifiers.SecT113r2);
                case ECDSAEllipticCurve.SecT131r2: return SecNamedCurves.GetByOid(SecObjectIdentifiers.SecT131r2);
                case ECDSAEllipticCurve.SecT131r1: return SecNamedCurves.GetByOid(SecObjectIdentifiers.SecT131r1);
                case ECDSAEllipticCurve.SecT163k1: return SecNamedCurves.GetByOid(SecObjectIdentifiers.SecT163k1);
                case ECDSAEllipticCurve.SecT163r1: return SecNamedCurves.GetByOid(SecObjectIdentifiers.SecT163r1);
                case ECDSAEllipticCurve.SecT163r2: return SecNamedCurves.GetByOid(SecObjectIdentifiers.SecT163r2);
                case ECDSAEllipticCurve.SecT193r1: return SecNamedCurves.GetByOid(SecObjectIdentifiers.SecT193r1);
                case ECDSAEllipticCurve.SecT193r2: return SecNamedCurves.GetByOid(SecObjectIdentifiers.SecT193r2);
                case ECDSAEllipticCurve.SecT233k1: return SecNamedCurves.GetByOid(SecObjectIdentifiers.SecT233k1);
                case ECDSAEllipticCurve.SecT233r1: return SecNamedCurves.GetByOid(SecObjectIdentifiers.SecT233r1);
                case ECDSAEllipticCurve.SecT239k1: return SecNamedCurves.GetByOid(SecObjectIdentifiers.SecT239k1);
                case ECDSAEllipticCurve.SecT283k1: return SecNamedCurves.GetByOid(SecObjectIdentifiers.SecT283k1);
                case ECDSAEllipticCurve.SecT283r1: return SecNamedCurves.GetByOid(SecObjectIdentifiers.SecT283r1);
                case ECDSAEllipticCurve.SecT409k1: return SecNamedCurves.GetByOid(SecObjectIdentifiers.SecT409k1);
                case ECDSAEllipticCurve.SecT409r1: return SecNamedCurves.GetByOid(SecObjectIdentifiers.SecT409r1);
                case ECDSAEllipticCurve.SecT571k1: return SecNamedCurves.GetByOid(SecObjectIdentifiers.SecT571k1);
                case ECDSAEllipticCurve.SecT571r1: return SecNamedCurves.GetByOid(SecObjectIdentifiers.SecT571r1);
                case ECDSAEllipticCurve.SecP112r1: return SecNamedCurves.GetByOid(SecObjectIdentifiers.SecP112r1);
                case ECDSAEllipticCurve.SecP112r2: return SecNamedCurves.GetByOid(SecObjectIdentifiers.SecP112r2);
                case ECDSAEllipticCurve.SecP128r1: return SecNamedCurves.GetByOid(SecObjectIdentifiers.SecP128r1);
                case ECDSAEllipticCurve.SecP128r2: return SecNamedCurves.GetByOid(SecObjectIdentifiers.SecP128r2);
                case ECDSAEllipticCurve.SecP160k1: return SecNamedCurves.GetByOid(SecObjectIdentifiers.SecP160k1);
                case ECDSAEllipticCurve.SecP160r1: return SecNamedCurves.GetByOid(SecObjectIdentifiers.SecP160r1);
                case ECDSAEllipticCurve.SecP160r2: return SecNamedCurves.GetByOid(SecObjectIdentifiers.SecP160r2);
                case ECDSAEllipticCurve.SecP192k1: return SecNamedCurves.GetByOid(SecObjectIdentifiers.SecP192k1);
                case ECDSAEllipticCurve.SecP192r1: return SecNamedCurves.GetByOid(SecObjectIdentifiers.SecP192r1);
                case ECDSAEllipticCurve.SecP224k1: return SecNamedCurves.GetByOid(SecObjectIdentifiers.SecP224k1);
                case ECDSAEllipticCurve.SecP224r1: return SecNamedCurves.GetByOid(SecObjectIdentifiers.SecP224r1);
                case ECDSAEllipticCurve.SecP256k1: return SecNamedCurves.GetByOid(SecObjectIdentifiers.SecP256k1);
                case ECDSAEllipticCurve.SecP256r1: return SecNamedCurves.GetByOid(SecObjectIdentifiers.SecP256r1);
                case ECDSAEllipticCurve.SecP384r1: return SecNamedCurves.GetByOid(SecObjectIdentifiers.SecP384r1);
                case ECDSAEllipticCurve.SecP521r1: return SecNamedCurves.GetByOid(SecObjectIdentifiers.SecP521r1);
                default: throw new System.Security.Cryptography.CryptographicException("Unsupported elliptic curve.");
            }
        }
    }
}