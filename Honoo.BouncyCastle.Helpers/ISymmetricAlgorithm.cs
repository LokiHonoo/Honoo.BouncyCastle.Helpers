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
        SymmetricAlgorithmKind Kind { get; }

        /// <summary>
        /// Gets algorithm name.
        /// </summary>
        string Name { get; }

        /// <summary>
        /// Return algorithm name.
        /// </summary>
        /// <returns></returns>
        string ToString();
    }
}