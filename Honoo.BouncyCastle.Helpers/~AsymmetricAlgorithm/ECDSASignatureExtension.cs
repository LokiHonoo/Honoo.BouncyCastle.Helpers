namespace Honoo.BouncyCastle.Helpers
{
    /// <summary>
    /// ECDSA signature extension.
    /// </summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1008:枚举应具有零值", Justification = "<挂起>")]
    public enum ECDSASignatureExtension
    {
        /// <summary>
        /// ECDSA signer with standard.
        /// </summary>
        ECDSA = 1,

        /// <summary>
        /// ECNR signer with standard.
        /// </summary>
        ECNR,

        /// <summary>
        /// ECDSA signer with plain.
        /// </summary>
        Plain,

        /// <summary>
        /// ECDSA signer with plain.
        /// </summary>
        CVC,
    }
}