using Org.BouncyCastle.Crypto;

namespace Honoo.BouncyCastle.Helpers.Security.Crypto.Asymmetric
{
    /// <summary>
    /// Asymmetric algorithm.
    /// </summary>
    public abstract class AsymmetricAlgorithm : IAsymmetricAlgorithm
    {
        #region Properties

        private readonly AsymmetricAlgorithmKind _algorithmKind;
        private readonly string _mechanism;

        /// <summary>
        /// Asymmetric algorithm kind.
        /// </summary>
        public AsymmetricAlgorithmKind AlgorithmKind => _algorithmKind;

        /// <summary>
        /// Gets mechanism.
        /// </summary>
        public string Mechanism => _mechanism;

        #endregion Properties

        #region Constructor

        /// <summary>
        /// Asymmetric algorithm.
        /// </summary>
        /// <param name="mechanism">Asymmetric algorithm mechanism.</param>
        /// <param name="algorithmKind">Asymmetric algorithm kind.</param>
        protected AsymmetricAlgorithm(string mechanism, AsymmetricAlgorithmKind algorithmKind)
        {
            _mechanism = mechanism;
            _algorithmKind = algorithmKind;
        }

        #endregion Constructor

        /// <summary>
        /// Generate key pair by default settings.
        /// </summary>
        /// <returns></returns>
        public abstract AsymmetricCipherKeyPair GenerateKeyPair();

        /// <summary>
        /// Return mechanism.
        /// </summary>
        /// <returns></returns>
        public override string ToString()
        {
            return _mechanism;
        }
    }
}