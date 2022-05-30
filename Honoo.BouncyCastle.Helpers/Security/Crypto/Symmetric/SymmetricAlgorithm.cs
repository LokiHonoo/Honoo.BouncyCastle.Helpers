namespace Honoo.BouncyCastle.Helpers.Security.Crypto.Symmetric
{
    /// <summary>
    /// Symmetric algorithm.
    /// </summary>
    public abstract class SymmetricAlgorithm : ISymmetricAlgorithm
    {
        #region Properties

        private readonly SymmetricAlgorithmKind _kind;
        private readonly string _name;

        /// <summary>
        /// Symmetric algorithm kind.
        /// </summary>
        public SymmetricAlgorithmKind Kind => _kind;

        /// <summary>
        /// Gets algorithm name.
        /// </summary>
        public string Name => _name;

        #endregion Properties

        #region Constructor

        /// <summary>
        /// Symmetric algorithm.
        /// </summary>
        /// <param name="name">Symmetric algorithm name.</param>
        /// <param name="kind">Symmetric algorithm kind.</param>
        protected SymmetricAlgorithm(string name, SymmetricAlgorithmKind kind)
        {
            _name = name;
            _kind = kind;
        }

        #endregion Constructor

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