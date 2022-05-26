using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;

namespace Honoo.BouncyCastle.Helpers.Security.Crypto.Asymmetric
{
    /// <summary>
    /// Ed25519.
    /// </summary>
    public sealed class Ed25519 : AsymmetricAlgorithm
    {
        #region Constructor

        /// <summary>
        /// Ed25519.
        /// </summary>
        public Ed25519() : base("Ed25519")
        {
        }

        #endregion Constructor

        /// <summary>
        /// Generate key pair.
        /// </summary>
        /// <returns></returns>
        public override AsymmetricCipherKeyPair GenerateKeyPair()
        {
            Ed25519KeyGenerationParameters parameters = new Ed25519KeyGenerationParameters(Common.SecureRandom);
            Ed25519KeyPairGenerator generator = new Ed25519KeyPairGenerator();
            generator.Init(parameters);
            return generator.GenerateKeyPair();
        }
    }
}