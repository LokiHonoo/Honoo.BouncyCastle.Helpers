namespace Honoo.BouncyCastle.Helpers.Security.Crypto.Symmetric
{
    /// <summary>
    /// Symmetric algorithm.
    /// </summary>
    public abstract class SymmetricAlgorithm : ISymmetricAlgorithm
    {
        #region Properties

        private readonly SymmetricAlgorithmKind _algorithmKind;
        private readonly string _mechanism;

        /// <summary>
        /// Asymmetric algorithm kind.
        /// </summary>
        public SymmetricAlgorithmKind AlgorithmKind => _algorithmKind;

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
        /// <param name="algorithmKind">Symmetric algorithm kind.</param>
        protected SymmetricAlgorithm(string mechanism, SymmetricAlgorithmKind algorithmKind)
        {
            _mechanism = mechanism;
            _algorithmKind = algorithmKind;
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