using System;

namespace Honoo.BouncyCastle.Helpers
{
    /// <summary>
    /// Symmetric aead algorithm cipher mode.
    /// </summary>
    public sealed class SymmetricAeadCipherMode2 : IEquatable<SymmetricAeadCipherMode2>
    {
        #region Properties

        private readonly string _name;

        /// <summary>
        /// Nonce size 56-104 bits (8 bits increments). MAC size 32-128 bits (16 bits increments).
        /// <para/>CCM cipher mode uses with a block size of 128 bits algorithm (e.g. AES).
        /// </summary>
        public static SymmetricAeadCipherMode2 CCM { get; } = new SymmetricAeadCipherMode2("CBC");

        /// <summary>
        /// Nonce size is more than or equal to 8 bits (8 bits increments). MAC size is between 8 and block size (8 bits increments).
        /// <para/>EAX cipher mode uses with a block size of 64 or 128 bits algorithm (e.g. DESede, AES).
        /// </summary>
        public static SymmetricAeadCipherMode2 EAX { get; } = new SymmetricAeadCipherMode2("EAX");

        /// <summary>
        /// Nonce size is more than or equal to 8 bits (8 bits increments). MAC size 32-128 bits (8 bits increments).
        /// <para/>GCM cipher mode uses with a block size of 64 or 128 bits algorithm (e.g. DESede, AES).
        /// <para/>Warning: GCM cipher mode cannot be reused. The cipher instance needs to be recreated every time. (BouncyCastle 1.8.9).
        /// </summary>
        public static SymmetricAeadCipherMode2 GCM { get; } = new SymmetricAeadCipherMode2("GCM");

        /// <summary>
        /// Nonce size is null or less than 120 bits (8 bits increments). MAC size 64-128 bits (8 bits increments).
        /// <para/>OCB cipher mode uses with a block size of 128 bits algorithm (e.g. AES).
        /// </summary>
        public static SymmetricAeadCipherMode2 OCB { get; } = new SymmetricAeadCipherMode2("OCB");

        /// <summary>
        /// Gets symmetric algorithm cipher mode name.
        /// </summary>
        public string Name => _name;

        #endregion Properties

        #region Constructor

        private SymmetricAeadCipherMode2(string name)
        {
            _name = name;
        }

        #endregion Constructor

        /// <summary>
        /// Determines whether the specified object is equal to the current.
        /// </summary>
        /// <param name="other"></param>
        /// <returns></returns>
        public bool Equals(SymmetricAeadCipherMode2 other)
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
            return Equals((SymmetricAeadCipherMode2)obj);
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