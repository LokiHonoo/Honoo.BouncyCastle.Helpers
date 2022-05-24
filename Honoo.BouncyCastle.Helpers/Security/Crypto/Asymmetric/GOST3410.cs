using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;

namespace Honoo.BouncyCastle.Helpers.Security.Crypto.Asymmetric
{
    /// <summary>
    /// GOST3410.
    /// <para/>Legal key size 512, 1024 bits.
    /// <para/>Uses key size 1024 bits, procedure 2 by default.
    /// </summary>
    public sealed class GOST3410 : AsymmetricAlgorithm
    {
        #region Properties

        private readonly int _keySize;
        private readonly int _procedure;

        /// <summary>
        /// Key size.
        /// </summary>
        public int KeySize => _keySize;

        /// <summary>
        /// Procedure.
        /// </summary>
        public int Procedure => _procedure;

        #endregion Properties

        #region Constructor

        /// <summary>
        /// GOST3410.
        /// <para/>Legal key size 512, 1024 bits.
        /// <para/>Uses key size 1024 bits, procedure 2 by default.
        /// </summary>
        public GOST3410() : this(1024, 2)
        {
        }

        /// <summary>
        /// GOST3410.
        /// <para/>Legal key size 512, 1024 bits.
        /// <para/>Uses key size 1024 bits, procedure 2 by default.
        /// </summary>
        /// <param name="keySize">Key size bits.</param>
        public GOST3410(int keySize) : this(keySize, 2)
        {
        }

        /// <summary>
        /// GOST3410.
        /// <para/>Legal key size 512, 1024 bits.
        /// <para/>Uses key size 1024 bits, procedure 2 by default.
        /// </summary>
        /// <param name="keySize">Key size bits.</param>
        /// <param name="procedure">Procedure.</param>
        public GOST3410(int keySize, int procedure) : base("GOST3410")
        {
            _keySize = keySize;
            _procedure = procedure;
        }

        #endregion Constructor

        /// <summary>
        /// Generate key pair.
        /// </summary>
        /// <returns></returns>
        public override AsymmetricCipherKeyPair GenerateKeyPair()
        {
            Gost3410ParametersGenerator generator2 = new Gost3410ParametersGenerator();
            generator2.Init(_keySize, _procedure, Common.ThreadSecureRandom.Value);
            Gost3410Parameters parameters2 = generator2.GenerateParameters();
            KeyGenerationParameters parameters = new Gost3410KeyGenerationParameters(Common.ThreadSecureRandom.Value, parameters2);
            IAsymmetricCipherKeyPairGenerator generator = new Gost3410KeyPairGenerator();
            generator.Init(parameters);
            return generator.GenerateKeyPair();
        }
    }
}