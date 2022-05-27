namespace Honoo.BouncyCastle.Helpers
{
    /// <summary>
    /// Asymmetric padding mode.
    /// </summary>
    public enum AsymmetricPaddingMode
    {
        /// <summary>
        /// PKCS1 padding mode.
        /// </summary>
        PKCS1 = 0,

        /// <summary>
        /// OAEP padding mode.
        /// </summary>
        OAEP,

        /// <summary>
        /// NoPadding padding mode.
        /// </summary>
        NoPadding = 101,

        /// <summary>
        /// Only for RSA.
        /// </summary>
        ISO9796_1,
    }
}