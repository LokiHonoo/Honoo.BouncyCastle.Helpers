namespace Honoo.BouncyCastle.Helpers
{
    /// <summary>
    /// Symmetric aead algorithm cipher mode.
    /// </summary>
    public enum SymmetricAeadCipherMode
    {
        /// <summary>
        /// Nonce size 56-104 bits (8 bits increments). MAC size 32-128 bits (16 bits increments).
        /// <para/>CCM cipher mode uses with a block size of 128 bits algorithm (e.g. AES).
        /// <para/>CCM cipher mode can only select <see cref="SymmetricPaddingMode.NoPadding" /> padding mode.
        /// </summary>
        CCM = 201,

        /// <summary>
        /// Nonce size is more than or equal to 8 bits (8 bits increments). MAC size is between 8 and block size (8 bits increments).
        /// <para/>EAX cipher mode uses with a block size of 64 or 128 bits algorithm (e.g. DESede, AES).
        /// <para/>EAX cipher mode can only select <see cref="SymmetricPaddingMode.NoPadding" /> padding mode.
        /// </summary>
        EAX,

        /// <summary>
        /// Nonce size is more than or equal to 8 bits (8 bits increments). MAC size 32-128 bits (8 bits increments).
        /// <para/>GCM cipher mode uses with a block size of 64 or 128 bits algorithm (e.g. DESede, AES).
        /// <para/>GCM cipher mode can only select <see cref="SymmetricPaddingMode.NoPadding" /> padding mode.
        /// <para/>Warning: GCM cipher mode cannot be reused. The cipher instance needs to be recreated every time. (BouncyCastle 1.8.9).
        /// </summary>
        GCM,

        /// <summary>
        /// Nonce size is null or less than 120 bits (8 bits increments). MAC size 64-128 bits (8 bits increments).
        /// <para/>OCB cipher mode uses with a block size of 128 bits algorithm (e.g. AES).
        /// <para/>OCB cipher mode can only select <see cref="SymmetricPaddingMode.NoPadding" /> padding mode.
        /// </summary>
        OCB,
    }
}