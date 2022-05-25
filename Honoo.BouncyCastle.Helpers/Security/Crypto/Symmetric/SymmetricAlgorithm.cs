namespace Honoo.BouncyCastle.Helpers.Security.Crypto.Symmetric
{
    /// <summary>
    /// Symmetric algorithm.
    /// </summary>
    public abstract class SymmetricAlgorithm : ISymmetricAlgorithm
    {
        #region Properties

        private readonly string _mechanism;

        /// <summary>
        /// Gets mechanism.
        /// </summary>
        public string Mechanism => _mechanism;

        #endregion Properties

        #region Constructor

        /// <summary>
        /// Symmetric algorithm.
        /// </summary>
        /// <param name="mechanism">Symmetric algorithm mechanism.</param>
        protected SymmetricAlgorithm(string mechanism)
        {
            _mechanism = mechanism;
        }

        #endregion Constructor

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