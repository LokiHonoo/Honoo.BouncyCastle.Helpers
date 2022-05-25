using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Crypto;
using System;

namespace Honoo.BouncyCastle.Helpers.Security.Crypto.Signature
{
    /// <summary>
    /// Signature algorithm.
    /// </summary>
    public abstract class SignatureAlgorithm : ISignatureAlgorithm
    {
        #region Properties

        private readonly IAsymmetricAlgorithm _asymmetricAlgorithm;
        private readonly string _mechanism;
        private readonly DerObjectIdentifier _oid;



        /// <summary>
        /// Gets signature algorithm mechanism.
        /// </summary>
        public string Mechanism => _mechanism;

        /// <summary>
        /// Gets signature algorithm oid. It's maybe 'null' if not supported.
        /// </summary>
        public DerObjectIdentifier Oid => _oid;

        #endregion Properties

        #region Constructor

        /// <summary>
        /// Signature algorithm.
        /// </summary>
        /// <param name="mechanism">Signature algorithm mechanism.</param>
        /// <param name="asymmetricAlgorithm">Asymmetric algorithm.</param>
        protected SignatureAlgorithm(string mechanism, IAsymmetricAlgorithm asymmetricAlgorithm)
        {
            _mechanism = mechanism;
            _asymmetricAlgorithm = asymmetricAlgorithm;
            _ = SignatureAlgorithmHelper.TryGetOid(mechanism, out DerObjectIdentifier oid);
            _oid = oid;
        }

        #endregion Constructor

        /// <summary>
        /// Generate signer. The signer can be reused.
        /// </summary>
        /// <param name="asymmetricKey">Asymmetric public key or private key.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        public ISigner GenerateSigner(AsymmetricKeyParameter asymmetricKey)
        {
            ISigner signer = GenerateSigner();
            signer.Init(asymmetricKey.IsPrivate, asymmetricKey);
            return signer;
        }
        /// <summary>
        /// Generate key pair by the corresponding asymmetric algorithm.
        /// </summary>
        /// <returns></returns>
        public AsymmetricCipherKeyPair GenerateKeyPair()
        {
          return  _asymmetricAlgorithm.GenerateKeyPair();
        }

        /// <summary>
        /// Return mechanism.
        /// </summary>
        /// <returns></returns>
        public override string ToString()
        {
            return _mechanism;
        }

        /// <summary>
        /// Generate signer.
        /// </summary>
        /// <returns></returns>
        protected abstract ISigner GenerateSigner();
    }
}