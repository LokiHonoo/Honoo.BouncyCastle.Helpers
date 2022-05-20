using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;

namespace Honoo.BouncyCastle.Helpers.Security.Crypto.Asymmetric
{
    /// <summary>
    /// Ed448.
    /// <para/>Uses context byte[0] by default.
    /// </summary>
    public sealed class Ed448 : AsymmetricAlgorithm
    {
        #region Constructor

        /// <summary>
        /// Ed448.
        /// </summary>
        public Ed448() : base("Ed448")
        {
        }

        #endregion Constructor

        /// <summary>
        /// Generate key pair.
        /// </summary>
        /// <returns></returns>
        public override AsymmetricCipherKeyPair GenerateKeyPair()
        {
            IAsymmetricCipherKeyPairGenerator generator = new Ed448KeyPairGenerator();
            KeyGenerationParameters parameters = new Ed448KeyGenerationParameters(Common.ThreadSecureRandom.Value);
            generator.Init(parameters);
            return generator.GenerateKeyPair();
        }
    }
}