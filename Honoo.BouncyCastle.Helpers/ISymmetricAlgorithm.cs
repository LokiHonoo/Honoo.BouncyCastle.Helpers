namespace Honoo.BouncyCastle.Helpers
{
    /// <summary>
    /// Symmetric algorithm interface.
    /// </summary>
    public interface ISymmetricAlgorithm
    {
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