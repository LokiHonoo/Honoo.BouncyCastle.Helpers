using Org.BouncyCastle.Asn1.GM;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;

namespace Honoo.BouncyCastle.Helpers.Security.Crypto.Asymmetric
{
    /// <summary>
    /// SM2.
    /// </summary>
    public sealed class SM2 : AsymmetricAlgorithm
    {
        #region Constructor

        /// <summary>
        /// SM2.
        /// </summary>
        public SM2() : base("SM2")
        {
        }

        #endregion Constructor

        /// <summary>
        /// Generate key pair.
        /// </summary>
        /// <returns></returns>
        public override AsymmetricCipherKeyPair GenerateKeyPair()
        {
            X9ECParameters x9Parameters = GMNamedCurves.GetByOid(GMObjectIdentifiers.sm2p256v1);
            ECDomainParameters domainParameters = new ECDomainParameters(x9Parameters);
            ECKeyGenerationParameters generationParameters = new ECKeyGenerationParameters(domainParameters, Common.SecureRandom);
            ECKeyPairGenerator generator = new ECKeyPairGenerator();
            generator.Init(generationParameters);
            return generator.GenerateKeyPair();
        }
    }
}