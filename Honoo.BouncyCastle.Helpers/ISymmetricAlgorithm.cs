namespace Honoo.BouncyCastle.Helpers
{
    /// <summary>
    /// Symmetric algorithm interface.
    /// </summary>
    public interface ISymmetricAlgorithm
    {
        /// <summary>
        /// Symmetric algorithm kind.
        /// </summary>
        SymmetricAlgorithmKind AlgorithmKind { get; }

        /// <summary>
        /// Gets mechanism.
        /// </summary>
        string Mechanism { get; }

        /// <summary>
        /// Return mechanism.
        /// </summary>
        /// <returns></returns>
        string ToString();
    }
}