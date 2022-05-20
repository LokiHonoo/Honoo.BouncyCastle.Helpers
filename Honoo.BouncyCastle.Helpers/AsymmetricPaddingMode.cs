namespace Honoo.BouncyCastle.Helpers
{
    /// <summary>
    /// Asymmetric algorithm padding mode.
    /// </summary>
    public enum AsymmetricPaddingMode
    {
        /// <summary>
        ///
        /// </summary>
        NoPadding = 1,

        /// <summary>
        ///
        /// </summary>
        PKCS1,

        /// <summary>
        ///
        /// </summary>
        OAEP,

        /// <summary>
        /// Only for RSA.
        /// </summary>
        ISO9796_1,
    }
}