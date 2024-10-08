﻿namespace Honoo.BouncyCastle.Helpers
{
    /// <summary>
    /// Symmetric algorithm padding mode.
    /// </summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1008:枚举应具有零值", Justification = "<挂起>")]
    public enum SymmetricPaddingMode
    {
        /// <summary>
        /// NoPadding padding mode.
        /// </summary>
        NoPadding = 1,

        /// <summary>
        /// PKCS7, PKCS5 padding mode.
        /// </summary>
        PKCS7,

        /// <summary>
        /// Zeros padding mode. Warning: End will be removed if the end of the plaintext is 0x00.
        /// </summary>
        Zeros,

        /// <summary>
        /// X9.23, ANSIX9.23 padding mode.
        /// </summary>
        X923,

        /// <summary>
        /// ISO10126, ISO10126_2 padding mode.
        /// </summary>
        ISO10126,

        /// <summary>
        /// ISO7816-4, ISO9797-1 padding mode.
        /// </summary>
        ISO7816_4 = 101,

        /// <summary>
        /// TBC padding mode.
        /// </summary>
        TBC,
    }
}