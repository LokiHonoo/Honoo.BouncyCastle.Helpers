namespace Honoo.BouncyCastle.Helpers
{
    /// <summary>
    /// MAC cipher mode.
    /// </summary>
    public enum MACCipherMode
    {
        /// <summary>
        /// IV size is same as block size.
        /// </summary>
        CBC = 1,

        /// <summary>
        /// IV size is between 8 and block size (8 bits increments).
        /// </summary>
        CFB = 4,
    }
}