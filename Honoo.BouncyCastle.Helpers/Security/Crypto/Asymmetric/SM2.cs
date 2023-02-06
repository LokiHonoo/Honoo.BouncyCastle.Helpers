using Org.BouncyCastle.Asn1.GM;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using System.Security.Cryptography;

namespace Honoo.BouncyCastle.Helpers.Security.Crypto.Asymmetric
{
    /// <summary>
    /// SM2.
    /// </summary>
    public sealed class SM2 : AsymmetricAlgorithm
    {
        #region Construction

        /// <summary>
        /// SM2.
        /// </summary>
        public SM2() : base("SM2", GMObjectIdentifiers.sm2sign, AsymmetricAlgorithmKind.Signature)
        {
        }

        #endregion Construction

        /// <summary>
        /// Generate Asymmetric key pair.
        /// <para/>Uses EllipticCurve.Sm2P256v1 by default.
        /// </summary>
        /// <returns></returns>
        public override AsymmetricCipherKeyPair GenerateKeyPair()
        {
            return GenerateKeyPair(SM2EllipticCurve.Sm2P256v1);
        }

        /// <summary>
        /// Generate Asymmetric key pair.
        /// </summary>
        /// <param name="ellipticCurve">Elliptic curve.</param>
        /// <returns></returns>
        public AsymmetricCipherKeyPair GenerateKeyPair(SM2EllipticCurve ellipticCurve)
        {
            X9ECParameters x9Parameters = GenerateX9(ellipticCurve);
            ECDomainParameters domainParameters = new ECDomainParameters(x9Parameters);
            ECKeyGenerationParameters generationParameters = new ECKeyGenerationParameters(domainParameters, Common.SecureRandom);
            ECKeyPairGenerator generator = new ECKeyPairGenerator();
            generator.Init(generationParameters);
            return generator.GenerateKeyPair();
        }

        private static X9ECParameters GenerateX9(SM2EllipticCurve ellipticCurve)
        {
            switch (ellipticCurve)
            {
                case SM2EllipticCurve.Sm2P256v1: return GMNamedCurves.GetByOid(GMObjectIdentifiers.sm2p256v1);
                case SM2EllipticCurve.WapiP192v1: return GMNamedCurves.GetByOid(GMObjectIdentifiers.wapip192v1);
                default: throw new CryptographicException("Unsupported elliptic curve.");
            }
        }
    }
}