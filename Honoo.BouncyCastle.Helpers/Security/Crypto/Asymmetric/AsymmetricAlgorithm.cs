using Org.BouncyCastle.Crypto;

namespace Honoo.BouncyCastle.Helpers.Security.Crypto.Asymmetric
{
    /// <summary>
    /// Asymmetric algorithm.
    /// </summary>
    public abstract class AsymmetricAlgorithm : IAsymmetricAlgorithm
    {
        #region Properties

        private readonly AsymmetricAlgorithmKind _kind;
        private readonly string _name;

        /// <summary>
        /// Asymmetric algorithm kind.
        /// </summary>
        public AsymmetricAlgorithmKind Kind => _kind;

        /// <summary>
        /// Gets algorithm name.
        /// </summary>
        public string Name => _name;

        #endregion Properties

        #region Constructor

        /// <summary>
        /// Asymmetric algorithm.
        /// </summary>
        /// <param name="name">Asymmetric algorithm name.</param>
        /// <param name="kind">Asymmetric algorithm kind.</param>
        protected AsymmetricAlgorithm(string name, AsymmetricAlgorithmKind kind)
        {
            _name = name;
            _kind = kind;
        }

        #endregion Constructor

        /// <summary>
        /// Generate key pair by default settings.
        /// </summary>
        /// <returns></returns>
        public abstract AsymmetricCipherKeyPair GenerateKeyPair();

        /// <summary>
        /// Return algorithm name.
        /// </summary>
        /// <returns></returns>
        public override string ToString()
        {
            return _name;
        }
    }
}