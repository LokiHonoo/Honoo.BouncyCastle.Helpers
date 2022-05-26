namespace Honoo.BouncyCastle.Helpers
{
    /// <summary>
    /// X509Name entity.
    /// </summary>
    public sealed class X509NameEntity
    {
        #region Properties

        private readonly X509NameLabel _label;
        private readonly string _value;

        /// <summary>
        /// X509Name label.
        /// </summary>
        public X509NameLabel Label => _label;

        /// <summary>
        /// X509Name value.
        /// </summary>
        public string Value => _value;

        #endregion Properties

        /// <summary>
        /// X509Name entity.
        /// </summary>
        /// <param name="label">X509Name label.</param>
        /// <param name="value">X509Name value.</param>
        public X509NameEntity(X509NameLabel label, string value)
        {
            _label = label;
            _value = value;
        }
    }
}