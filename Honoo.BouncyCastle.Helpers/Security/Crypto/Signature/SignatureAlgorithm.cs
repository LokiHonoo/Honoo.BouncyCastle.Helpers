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

        /// <summary>
        /// Gets the corresponding asymmetric algorithm.
        /// </summary>
        public IAsymmetricAlgorithm AsymmetricAlgorithm { get; }

        /// <summary>
        /// Gets signature algorithm mechanism.
        /// </summary>
        public string Mechanism { get; }

        /// <summary>
        /// Gets signature algorithm oid. It's maybe 'null' if not supported.
        /// </summary>
        public DerObjectIdentifier Oid { get; }

        #endregion Properties

        #region Constructor

        /// <summary>
        /// Signature algorithm.
        /// </summary>
        /// <param name="mechanism">Signature algorithm mechanism.</param>
        /// <param name="asymmetricAlgorithm">Asymmetric algorithm.</param>
        protected SignatureAlgorithm(string mechanism, IAsymmetricAlgorithm asymmetricAlgorithm)
        {
            this.Mechanism = mechanism;
            this.AsymmetricAlgorithm = asymmetricAlgorithm;
            _ = SignatureAlgorithmHelper.TryGetOid(mechanism, out DerObjectIdentifier oid);
            this.Oid = oid;
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
        /// Return mechanism.
        /// </summary>
        /// <returns></returns>
        public override string ToString()
        {
            return this.Mechanism;
        }

        /// <summary>
        /// Generate signer.
        /// </summary>
        /// <returns></returns>
        protected abstract ISigner GenerateSigner();
    }
}