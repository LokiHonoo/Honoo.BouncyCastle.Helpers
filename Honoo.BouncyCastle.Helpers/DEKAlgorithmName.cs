using System;

namespace Honoo.BouncyCastle.Helpers
{
    /// <summary>
    /// DEK algorithm name.
    /// </summary>
    public sealed class DEKAlgorithmName : IEquatable<DEKAlgorithmName>
    {
        #region Static properties

        /// <summary></summary>
        public static DEKAlgorithmName AES_128_CBC { get; } = new DEKAlgorithmName("AES-128-CBC");

        /// <summary></summary>
        public static DEKAlgorithmName AES_128_CFB { get; } = new DEKAlgorithmName("AES-128-CFB");

        /// <summary></summary>
        public static DEKAlgorithmName AES_128_ECB { get; } = new DEKAlgorithmName("AES-128-ECB");

        /// <summary></summary>
        public static DEKAlgorithmName AES_128_OFB { get; } = new DEKAlgorithmName("AES-128-OFB");

        /// <summary></summary>
        public static DEKAlgorithmName AES_192_CBC { get; } = new DEKAlgorithmName("AES-192-CBC");

        /// <summary></summary>
        public static DEKAlgorithmName AES_192_CFB { get; } = new DEKAlgorithmName("AES-192-CFB");

        /// <summary></summary>
        public static DEKAlgorithmName AES_192_ECB { get; } = new DEKAlgorithmName("AES-192-ECB");

        /// <summary></summary>
        public static DEKAlgorithmName AES_192_OFB { get; } = new DEKAlgorithmName("AES-192-OFB");

        /// <summary></summary>
        public static DEKAlgorithmName AES_256_CBC { get; } = new DEKAlgorithmName("AES-256-CBC");

        /// <summary></summary>
        public static DEKAlgorithmName AES_256_CFB { get; } = new DEKAlgorithmName("AES-256-CFB");

        /// <summary></summary>
        public static DEKAlgorithmName AES_256_ECB { get; } = new DEKAlgorithmName("AES-256-ECB");

        /// <summary></summary>
        public static DEKAlgorithmName AES_256_OFB { get; } = new DEKAlgorithmName("AES-256-OFB");

        /// <summary></summary>
        public static DEKAlgorithmName BLOWFISH_CBC { get; } = new DEKAlgorithmName("BLOWFISH-CBC");

        /// <summary></summary>
        public static DEKAlgorithmName BLOWFISH_CFB { get; } = new DEKAlgorithmName("BLOWFISH-CFB");

        /// <summary></summary>
        public static DEKAlgorithmName BLOWFISH_ECB { get; } = new DEKAlgorithmName("BLOWFISH-ECB");

        /// <summary></summary>
        public static DEKAlgorithmName BLOWFISH_OFB { get; } = new DEKAlgorithmName("BLOWFISH-OFB");

        /// <summary></summary>
        public static DEKAlgorithmName DES_CBC { get; } = new DEKAlgorithmName("DES-CBC");

        /// <summary></summary>
        public static DEKAlgorithmName DES_CFB { get; } = new DEKAlgorithmName("DES-CFB");

        /// <summary></summary>
        public static DEKAlgorithmName DES_ECB { get; } = new DEKAlgorithmName("DES-ECB");

        /// <summary></summary>
        public static DEKAlgorithmName DES_EDE_CBC { get; } = new DEKAlgorithmName("DES-EDE-CBC");

        /// <summary></summary>
        public static DEKAlgorithmName DES_EDE_CFB { get; } = new DEKAlgorithmName("DES-EDE-CFB");

        /// <summary></summary>
        public static DEKAlgorithmName DES_EDE_ECB { get; } = new DEKAlgorithmName("DES-EDE-ECB");

        /// <summary></summary>
        public static DEKAlgorithmName DES_EDE_OFB { get; } = new DEKAlgorithmName("DES-EDE-OFB");

        /// <summary></summary>
        public static DEKAlgorithmName DES_EDE3_CBC { get; } = new DEKAlgorithmName("DES-EDE3-CBC");

        /// <summary></summary>
        public static DEKAlgorithmName DES_EDE3_CFB { get; } = new DEKAlgorithmName("DES-EDE3-CFB");

        /// <summary></summary>
        public static DEKAlgorithmName DES_EDE3_ECB { get; } = new DEKAlgorithmName("DES-EDE3-ECB");

        /// <summary></summary>
        public static DEKAlgorithmName DES_EDE3_OFB { get; } = new DEKAlgorithmName("DES-EDE3-OFB");

        /// <summary></summary>
        public static DEKAlgorithmName DES_OFB { get; } = new DEKAlgorithmName("DES-OFB");

        /// <summary></summary>
        public static DEKAlgorithmName RC2_40_CBC { get; } = new DEKAlgorithmName("RC2-40-CBC");

        /// <summary></summary>
        public static DEKAlgorithmName RC2_40_CFB { get; } = new DEKAlgorithmName("RC2-40-CFB");

        /// <summary></summary>
        public static DEKAlgorithmName RC2_40_ECB { get; } = new DEKAlgorithmName("RC2-40-ECB");

        /// <summary></summary>
        public static DEKAlgorithmName RC2_40_OFB { get; } = new DEKAlgorithmName("RC2-40-OFB");

        /// <summary></summary>
        public static DEKAlgorithmName RC2_64_CBC { get; } = new DEKAlgorithmName("RC2-64-CBC");

        /// <summary></summary>
        public static DEKAlgorithmName RC2_64_CFB { get; } = new DEKAlgorithmName("RC2-64-CFB");

        /// <summary></summary>
        public static DEKAlgorithmName RC2_64_ECB { get; } = new DEKAlgorithmName("RC2-64-ECB");

        /// <summary></summary>
        public static DEKAlgorithmName RC2_64_OFB { get; } = new DEKAlgorithmName("RC2-64-OFB");

        /// <summary></summary>
        public static DEKAlgorithmName RC2_CBC { get; } = new DEKAlgorithmName("RC2-CBC");

        /// <summary></summary>
        public static DEKAlgorithmName RC2_CFB { get; } = new DEKAlgorithmName("RC2-CFB");

        /// <summary></summary>
        public static DEKAlgorithmName RC2_ECB { get; } = new DEKAlgorithmName("RC2-ECB");

        /// <summary></summary>
        public static DEKAlgorithmName RC2_OFB { get; } = new DEKAlgorithmName("RC2-OFB");

        #endregion Static properties

        #region Properties

        private readonly string _name;

        /// <summary>
        /// DEK algorithm name.
        /// </summary>
        public string Name => _name;

        #endregion Properties

        #region Constructor

        internal DEKAlgorithmName(string name)
        {
            _name = name;
        }

        #endregion Constructor

        /// <summary>
        /// Determines whether two specified object have different value.
        /// </summary>
        /// <param name="left"></param>
        /// <param name="right"></param>
        /// <returns></returns>
        public static bool operator !=(DEKAlgorithmName left, DEKAlgorithmName right)
        {
            return !(left == right);
        }

        /// <summary>
        /// Determines whether two specified object have the same value.
        /// </summary>
        /// <param name="left"></param>
        /// <param name="right"></param>
        /// <returns></returns>
        public static bool operator ==(DEKAlgorithmName left, DEKAlgorithmName right)
        {
            return left.Equals(right);
        }

        /// <summary>
        /// Determines whether the specified System.Object is equal to the current System.Object.
        /// </summary>
        /// <param name="obj"></param>
        /// <returns></returns>
        public override bool Equals(object obj)
        {
            return obj is DEKAlgorithmName name && Equals(name);
        }

        /// <summary>
        /// Determines whether the specified object is equal to the current object.
        /// </summary>
        /// <param name="other"></param>
        /// <returns></returns>
        public bool Equals(DEKAlgorithmName other)
        {
            return _name == other._name;
        }

        /// <summary>
        /// Returns the hash code for this string.
        /// </summary>
        /// <returns></returns>
        public override int GetHashCode()
        {
            return _name.GetHashCode();
        }

        /// <summary>
        ///
        /// </summary>
        /// <returns></returns>
        public override string ToString()
        {
            return _name;
        }
    }
}