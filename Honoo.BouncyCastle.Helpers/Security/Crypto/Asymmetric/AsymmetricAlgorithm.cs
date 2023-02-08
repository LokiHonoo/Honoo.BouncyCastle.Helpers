using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Crypto;

namespace Honoo.BouncyCastle.Helpers.Security.Crypto.Asymmetric
{
    /// <summary>
    /// Asymmetric algorithm.
    /// </summary>
    public abstract class AsymmetricAlgorithm : IAsymmetricAlgorithm
    {
        #region Properties

        private readonly AsymmetricAlgorithmKind _kind;

        private readonly string _name;

        private readonly DerObjectIdentifier _oid;

        /// <summary>
        /// Asymmetric algorithm kind.
        /// </summary>
        public AsymmetricAlgorithmKind Kind => _kind;

        /// <summary>
        /// Gets algorithm name.
        /// </summary>
        public string Name => _name;

        ///// <summary>
        ///// Gets signature algorithm oid. It's maybe 'null' if not supported.
        ///// </summary>
        internal DerObjectIdentifier Oid => _oid;

        #endregion Properties

        #region Construction

        /// <summary>
        /// Asymmetric algorithm.
        /// </summary>
        /// <param name="name">Asymmetric algorithm name.</param>
        /// <param name="oid">Asymmetric algorithm oid.</param>
        /// <param name="kind">Asymmetric algorithm kind.</param>
        protected AsymmetricAlgorithm(string name, DerObjectIdentifier oid, AsymmetricAlgorithmKind kind)
        {
            _name = name;
            _oid = oid;
            _kind = kind;
        }

        #endregion Construction

        /// <summary>
        /// Generate key pair by default settings. Cast to algorithm class to replacement parameters.
        /// </summary>
        /// <returns></returns>
        public abstract AsymmetricCipherKeyPair GenerateKeyPair();
    }
}