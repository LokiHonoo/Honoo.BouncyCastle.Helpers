namespace Honoo.BouncyCastle.Helpers
{
    /// <summary>
    /// Asymmetric padding mode.
    /// </summary>
    public enum AsymmetricPaddingMode
    {
        /// <summary>
        /// NoPadding padding mode.
        /// </summary>
        NoPadding = 1,

        /// <summary>
        /// PKCS1 padding mode.
        /// </summary>
        PKCS1,

        /// <summary>
        /// OAEP padding mode.
        /// </summary>
        OAEP,

        /// <summary>
        /// Only for RSA.
        /// </summary>
        ISO9796_1,
    }
}