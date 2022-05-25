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
        /// Generate key pair by the corresponding asymmetric algorithm.
        /// </summary>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        public AsymmetricCipherKeyPair GenerateKeyPair()
        {
            return _asymmetricAlgorithm.GenerateKeyPair();
        }

        /// <summary>
        /// Generate signer. The signer can be reused.
        /// </summary>
        /// <param name="asymmetricKey">Asymmetric public key or private key.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        /// <exception cref="Exception"/>
        public ISigner GenerateSigner(AsymmetricKeyParameter asymmetricKey)
        {
            ISigner signer = GenerateSigner();
            signer.Init(asymmetricKey.IsPrivate, asymmetricKey);
            return signer;
        }

        /// <summary>
        /// Generate a new signature algorithm and sign data.
        /// </summary>
        /// <param name="asymmetricKey">Asymmetric private key.</param>
        /// <param name="data">Data bytes.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        public byte[] Sign(AsymmetricKeyParameter asymmetricKey, byte[] data)
        {
            return Sign(asymmetricKey, data, 0, data.Length);
        }

        /// <summary>
        /// Generate a new signature algorithm and sign data.
        /// </summary>
        /// <param name="asymmetricKey">Asymmetric private key.</param>
        /// <param name="data">Data buffer bytes.</param>
        /// <param name="offset">The starting offset to read.</param>
        /// <param name="length">The length to read.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        public byte[] Sign(AsymmetricKeyParameter asymmetricKey, byte[] data, int offset, int length)
        {
            if (asymmetricKey is null)
            {
                throw new ArgumentNullException(nameof(asymmetricKey));
            }
            if (data is null)
            {
                throw new ArgumentNullException(nameof(data));
            }
            ISigner signer = GenerateSigner(asymmetricKey);
            signer.BlockUpdate(data, offset, length);
            return signer.GenerateSignature();
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
        /// Generate a new signature algorithm and verify data.
        /// </summary>
        /// <param name="asymmetricKey">Asymmetric public key.</param>
        /// <param name="data">Data bytes.</param>
        /// <param name="signature">Signature.</param>
        /// <returns></returns>
        public bool Verify(AsymmetricKeyParameter asymmetricKey, byte[] data, byte[] signature)
        {
            return Verify(asymmetricKey, data, 0, data.Length, signature, 0, signature.Length);
        }

        /// <summary>
        /// Generate a new signature algorithm and sign data.
        /// </summary>
        /// <param name="asymmetricKey">Asymmetric public key.</param>
        /// <param name="data">Data buffer bytes.</param>
        /// <param name="offset">The starting offset to read.</param>
        /// <param name="length">The length to read.</param>
        /// <param name="signature">Signature buffer bytes.</param>
        /// <param name="signatureOffset">The starting offset to read.</param>
        /// <param name="signatureLength">The length to read.</param>
        /// <returns></returns>
        public bool Verify(AsymmetricKeyParameter asymmetricKey, byte[] data, int offset, int length, byte[] signature, int signatureOffset, int signatureLength)
        {
            if (asymmetricKey is null)
            {
                throw new ArgumentNullException(nameof(asymmetricKey));
            }
            if (data is null)
            {
                throw new ArgumentNullException(nameof(data));
            }
            if (signature is null)
            {
                throw new ArgumentNullException(nameof(signature));
            }
            ISigner verifier = GenerateSigner(asymmetricKey);
            verifier.BlockUpdate(data, offset, length);
            if (signatureOffset == 0 && signatureLength == signature.Length)
            {
                return verifier.VerifySignature(signature);
            }
            else
            {
                byte[] tmp = new byte[signatureLength];
                Buffer.BlockCopy(signature, signatureOffset, tmp, 0, signatureLength);
                return verifier.VerifySignature(tmp);
            }
        }

        /// <summary>
        /// Generate signer.
        /// </summary>
        /// <returns></returns>
        protected abstract ISigner GenerateSigner();
    }
}