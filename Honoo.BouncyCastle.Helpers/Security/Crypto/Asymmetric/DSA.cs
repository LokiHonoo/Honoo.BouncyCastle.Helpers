using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;

namespace Honoo.BouncyCastle.Helpers.Security.Crypto.Asymmetric
{
    /// <summary>
    /// DSA.
    /// <para/>Legal key size 512-1024 bits (64 bits increments).
    /// <para/>Uses key size 1024 bits, certainty 80 by default.
    /// </summary>
    public sealed class DSA : AsymmetricAlgorithm
    {
        #region Properties

        private readonly int _certainty;
        private readonly int _keySize;

        #endregion Properties

        #region Constructor

        /// <summary>
        /// DSA.
        /// <para/>Legal key size 512-1024 bits (64 bits increments).
        /// <para/>Uses key size 1024 bits, certainty 80 by default.
        /// </summary>
        public DSA() : this(1024, 80)
        {
        }

        /// <summary>
        /// DSA.
        /// <para/>Legal key size 512-1024 bits (64 bits increments).
        /// <para/>Uses key size 1024 bits, certainty 80 by default.
        /// </summary>
        /// <param name="keySize">Key size bits.</param>
        public DSA(int keySize) : this(keySize, 80)
        {
        }

        /// <summary>
        /// DSA.
        /// <para/>Legal key size 512-1024 bits (64 bits increments).
        /// <para/>Uses key size 1024 bits, certainty 80 by default.
        /// <param name="keySize">Key size bits.</param>
        /// <param name="certainty">Certainty.</param>
        /// </summary>
        public DSA(int keySize, int certainty) : base("DSA")
        {
            _keySize = keySize;
            _certainty = certainty;
        }

        #endregion Constructor

        /// <summary>
        /// Generate key pair.
        /// </summary>
        /// <returns></returns>
        public override AsymmetricCipherKeyPair GenerateKeyPair()
        {
            DsaParametersGenerator generator2 = new DsaParametersGenerator();
            generator2.Init(_keySize, _certainty, Common.ThreadSecureRandom.Value);
            DsaParameters parameters2 = generator2.GenerateParameters();
            KeyGenerationParameters parameters = new DsaKeyGenerationParameters(Common.ThreadSecureRandom.Value, parameters2);
            IAsymmetricCipherKeyPairGenerator generator = new DsaKeyPairGenerator();
            generator.Init(parameters);
            return generator.GenerateKeyPair();
        }
    }
}