namespace Honoo.BouncyCastle.Helpers
{
    /// <summary>
    /// Symmetric algorithm kind.
    /// </summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1008:枚举应具有零值", Justification = "<挂起>")]
    public enum SymmetricAlgorithmKind
    {
        /// <summary>
        /// Indicates the algorithm is a symmetric block algorithm.
        /// </summary>
        Block = 1,

        /// <summary>
        /// Indicates the algorithm is a symmetric stream algorithm.
        /// </summary>
        Stream
    }
}