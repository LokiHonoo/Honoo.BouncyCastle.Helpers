namespace Honoo.BouncyCastle.Helpers.Security.Crypto.Symmetric
{
    /// <summary>
    /// Symmetric algorithm.
    /// </summary>
    public abstract class SymmetricAlgorithm : ISymmetricAlgorithm
    {
        #region Properties

        /// <summary>
        /// Gets mechanism.
        /// </summary>
        public string Mechanism { get; }

        #endregion Properties

        #region Constructor

        /// <summary>
        ///
        /// </summary>
        /// <param name="mechanism"></param>
        protected SymmetricAlgorithm(string mechanism)
        {
            this.Mechanism = mechanism;
        }

        #endregion Constructor

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