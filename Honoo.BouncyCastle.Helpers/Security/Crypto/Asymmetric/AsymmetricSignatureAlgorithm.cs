namespace Honoo.BouncyCastle.Helpers.Security.Crypto.Asymmetric
{
    /// <summary>
    /// Asymmetric signature algorithm.
    /// </summary>
    public abstract class AsymmetricSignatureAlgorithm : AsymmetricAlgorithm
    {
        #region Constructor

        /// <summary>
        /// Asymmetric signature algorithm.
        /// </summary>
        /// <param name="name">Asymmetric algorithm name.</param>
        /// <param name="kind">Asymmetric algorithm kind.</param>
        public AsymmetricSignatureAlgorithm(string name, AsymmetricAlgorithmKind kind) : base(name, kind)
        {
        }

        #endregion Constructor
    }
}