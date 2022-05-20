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
            X9ECParameters parameters2 = GMNamedCurves.GetByOid(GMObjectIdentifiers.sm2p256v1);
            ECDomainParameters parameters3 = new ECDomainParameters(parameters2);
            KeyGenerationParameters parameters = new ECKeyGenerationParameters(parameters3, Common.ThreadSecureRandom.Value);
            IAsymmetricCipherKeyPairGenerator generator = new ECKeyPairGenerator();
            generator.Init(parameters);
            return generator.GenerateKeyPair();
        }
    }
}