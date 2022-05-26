using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;

namespace Honoo.BouncyCastle.Helpers.Security.Crypto.Asymmetric
{
    /// <summary>
    /// ECDSA.
    /// </summary>
    public sealed class ECDSA : AsymmetricAlgorithm
    {
        #region Constructor

        /// <summary>
        /// ECDSA.
        /// </summary>
        public ECDSA() : base("ECDSA")
        {
        }

        #endregion Constructor

        /// <summary>
        /// Generate key pair.
        /// <para/>Uses EllipticCurve.SecP256r1 by default.
        /// </summary>
        /// <returns></returns>
        public override AsymmetricCipherKeyPair GenerateKeyPair()
        {
            return GenerateKeyPair(ECDSAEllipticCurve.SecP256r1);
        }

        /// <summary>
        /// Generate key pair.
        /// </summary>
        /// <returns></returns>
        [SuppressMessage("Performance", "CA1822:将成员标记为 static", Justification = "<挂起>")]
        public AsymmetricCipherKeyPair GenerateKeyPair(ECDSAEllipticCurve ellipticCurve)
        {
            X9ECParameters x9Parameters = GenerateX9(ellipticCurve);
            ECDomainParameters domainParameters = new ECDomainParameters(x9Parameters);
            ECKeyGenerationParameters generationParameters = new ECKeyGenerationParameters(domainParameters, Common.SecureRandom);
            ECKeyPairGenerator generator = new ECKeyPairGenerator();
            generator.Init(generationParameters);
            return generator.GenerateKeyPair();
        }

        private static X9ECParameters GenerateX9(ECDSAEllipticCurve ellipticCurve)
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
                default: throw new CryptographicException("Unsupported elliptic curve.");
            }
        }
    }
}