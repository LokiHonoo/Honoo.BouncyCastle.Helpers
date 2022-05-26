using Org.BouncyCastle.Asn1;

namespace Honoo.BouncyCastle.Helpers
{
    /// <summary>
    /// X509Extension entity.
    /// </summary>
    public sealed class X509ExtensionEntity
    {
        #region Properties

        private readonly bool _isCritical;
        private readonly X509ExtensionLabel _label;
        private readonly Asn1Encodable _value;

        /// <summary>
        /// X509Extension critical.
        /// </summary>
        public bool IsCritical => _isCritical;

        /// <summary>
        /// X509Extension label.
        /// </summary>
        public X509ExtensionLabel Label => _label;

        /// <summary>
        /// X509Extension value.
        /// </summary>
        public Asn1Encodable Value => _value;

        #endregion Properties

        /// <summary>
        /// X509Extension entity.
        /// </summary>
        /// <param name="label">X509Extension label.</param>
        /// <param name="isCritical">X509Extension critical.</param>
        /// <param name="value">X509Extension value.
        /// <para/>e.g. new BasicConstraints(false)
        /// <para/>e.g. new KeyUsage(KeyUsage.KeyCertSign | KeyUsage.CrlSign)
        /// </param>
        public X509ExtensionEntity(X509ExtensionLabel label, bool isCritical, Asn1Encodable value)
        {
            _label = label;
            _isCritical = isCritical;
            _value = value;
        }
    }
}