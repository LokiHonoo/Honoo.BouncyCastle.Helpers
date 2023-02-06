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
        /// <para/>IV size is between 16 and block size (8 bits increments) when use <see cref="MACPaddingMode.X923"/> or <see cref="MACPaddingMode.ISO7816_4"/>.
        /// </summary>
        CFB = 4,
    }
}