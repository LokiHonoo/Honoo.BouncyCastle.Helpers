namespace Honoo.BouncyCastle.Helpers
{
    /// <summary>
    /// OAEP MGF1 padding mode.
    /// </summary>
    public enum OAEPMGF1PaddingMode
    {
        /// <summary>
        ///
        /// </summary>
        None = 0,

        /// <summary>
        ///
        /// </summary>
        MD5,

        /// <summary>
        ///
        /// </summary>
        SHA1,

        /// <summary>
        ///
        /// </summary>
        SHA224,

        /// <summary>
        ///
        /// </summary>
        SHA256,

        /// <summary>
        /// Only for RSA.
        /// </summary>
        SHA384,

        /// <summary>
        /// Only for RSA.
        /// </summary>
        SHA512,
    }
}