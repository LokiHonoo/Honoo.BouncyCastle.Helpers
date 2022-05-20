using Org.BouncyCastle.Crypto;

namespace Honoo.BouncyCastle.Helpers.Security.Crypto.Asymmetric
{
    /// <summary>
    /// Asymmetric algorithm.
    /// </summary>
    public abstract class AsymmetricAlgorithm : IAsymmetricAlgorithm
    {
        #region Properties

        /// <summary>
        /// Gets mechanism.
        /// </summary>
        public string Mechanism { get; }

        #endregion Properties

        #region Constructor

        /// <summary>
        /// Asymmetric algorithm.
        /// </summary>
        /// <param name="mechanism">Mechanism.</param>
        protected AsymmetricAlgorithm(string mechanism)
        {
            this.Mechanism = mechanism;
        }

        #endregion Constructor

        /// <summary>
        /// Generate key pair.
        /// </summary>
        /// <returns></returns>
        public abstract AsymmetricCipherKeyPair GenerateKeyPair();

        /// <summary>
        /// Return mechanism.
        /// </summary>
        /// <returns></returns>
        public override string ToString()
        {
            return this.Mechanism;
        }
    }
}