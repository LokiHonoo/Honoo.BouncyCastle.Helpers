namespace Honoo.BouncyCastle.Helpers
{
    /// <summary>
    /// Symmetric algorithm cipher mode.
    /// </summary>
    public enum SymmetricCipherMode
    {
        /// <summary>
        /// IV size is same as block size.
        /// </summary>
        CBC = 1,

        /// <summary>
        /// Not need IV.
        /// </summary>
        ECB,

        /// <summary>
        /// IV size is between 8 and block size (8 bits increments).
        /// </summary>
        OFB,

        /// <summary>
        /// IV size is between 8 and block size (8 bits increments).
        /// </summary>
        CFB,

        /// <summary>
        /// IV size is same as block size.
        /// <para/>CTS cipher mode can only select <see cref="SymmetricPaddingMode.NoPadding" /> padding mode.
        /// </summary>
        CTS,

        /// <summary>
        /// The minimum IV size is the larger of (block size / 2) and (block size - 64) bits. The maximum iv size is is same as block size. 8 bits increments.
        /// </summary>
        CTR = 101,

        /// <summary>
        /// Not need IV.
        /// <para/>CTS cipher mode can only select <see cref="SymmetricPaddingMode.NoPadding" /> padding mode.
        /// </summary>
        CTS_ECB,

        /// <summary>
        /// IV size is same as block size.
        /// <para/>GOFB cipher mode uses with a block size of 64 bits algorithm (e.g. DESede).
        /// </summary>
        GOFB,

        /// <summary>
        /// IV size is between 8 and block size (8 bits increments).
        /// </summary>
        OpenPGPCFB,

        /// <summary>
        /// The minimum IV size is the larger of (block size / 2) and (block size - 64) bits. The maximum iv size is is same as block size. 8 bits increments.
        /// <para/>SIC cipher mode uses with a block size of 128 bits algorithm (e.g. AES).
        /// </summary>
        SIC,
    }
}