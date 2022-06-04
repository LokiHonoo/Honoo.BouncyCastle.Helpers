using System;

namespace Honoo.BouncyCastle.Helpers
{
    /// <summary>
    /// Symmetric algorithm cipher mode.
    /// </summary>
    public sealed class SymmetricCipherMode2 : IEquatable<SymmetricCipherMode2>
    {
        #region Properties

        private readonly string _name;

        /// <summary>
        /// IV size is same as block size.
        /// </summary>
        public static SymmetricCipherMode2 CBC { get; } = new SymmetricCipherMode2("CBC");

        /// <summary>
        /// IV size is between 8 and block size (8 bits increments).
        /// </summary>
        public static SymmetricCipherMode2 CFB { get; } = new SymmetricCipherMode2("CFB");

        /// <summary>
        /// The minimum IV size is the larger of (block size / 2) and (block size - 64) bits. The maximum iv size is is same as block size. 8 bits increments.
        /// </summary>
        public static SymmetricCipherMode2 CTR { get; } = new SymmetricCipherMode2("CTR");

        /// <summary>
        /// IV size is same as block size.
        /// <para/>CTS cipher mode can only select <see cref="SymmetricPaddingMode.NoPadding" /> padding mode.
        /// </summary>
        public static SymmetricCipherMode2 CTS { get; } = new SymmetricCipherMode2("CTS");

        /// <summary>
        /// Not need IV.
        /// <para/>CTS cipher mode can only select <see cref="SymmetricPaddingMode.NoPadding" /> padding mode.
        /// </summary>
        public static SymmetricCipherMode2 CTS_ECB { get; } = new SymmetricCipherMode2("CTS-ECB");

        /// <summary>
        /// Not need IV.
        /// </summary>
        public static SymmetricCipherMode2 ECB { get; } = new SymmetricCipherMode2("ECB");

        /// <summary>
        /// IV size is same as block size.
        /// <para/>GOFB cipher mode uses with a block size of 64 bits algorithm (e.g. DESede).
        /// </summary>
        public static SymmetricCipherMode2 GOFB { get; } = new SymmetricCipherMode2("GOFB");

        /// <summary>
        /// IV size is between 8 and block size (8 bits increments).
        /// </summary>
        public static SymmetricCipherMode2 OFB { get; } = new SymmetricCipherMode2("OFB");

        /// <summary>
        /// IV size is between 8 and block size (8 bits increments).
        /// </summary>
        public static SymmetricCipherMode2 OpenPGPCFB { get; } = new SymmetricCipherMode2("OpenPGPCFB");

        /// <summary>
        /// The minimum IV size is the larger of (block size / 2) and (block size - 64) bits. The maximum iv size is is same as block size. 8 bits increments.
        /// <para/>SIC cipher mode uses with a block size of 128 bits algorithm (e.g. AES).
        /// </summary>
        public static SymmetricCipherMode2 SIC { get; } = new SymmetricCipherMode2("SIC");

        /// <summary>
        /// Gets symmetric algorithm cipher mode name.
        /// </summary>
        public string Name => _name;

        #endregion Properties

        #region Constructor

        private SymmetricCipherMode2(string name)
        {
            _name = name;
        }

        #endregion Constructor

        /// <summary>
        /// Determines whether the specified object is equal to the current.
        /// </summary>
        /// <param name="other"></param>
        /// <returns></returns>
        public bool Equals(SymmetricCipherMode2 other)
        {
            return _name.Equals(other._name);
        }

        /// <summary>
        /// Determines whether the specified object is equal to the current.
        /// </summary>
        /// <param name="obj"></param>
        /// <returns></returns>
        public override bool Equals(object obj)
        {
            return Equals((SymmetricCipherMode2)obj);
        }

        /// <summary>
        ///
        /// </summary>
        /// <returns></returns>
        public override int GetHashCode()
        {
            return _name.GetHashCode();
        }

        /// <summary>
        /// Return symmetric algorithm cipher mode name.
        /// </summary>
        /// <returns></returns>
        public override string ToString()
        {
            return _name;
        }
    }
}