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
        private readonly string _name;
        private readonly DerObjectIdentifier _oid;

        /// <summary>
        /// Gets algorithm name.
        /// </summary>
        public string Name => _name;

        /// <summary>
        /// Gets signature algorithm oid. It's maybe 'null' if not supported.
        /// </summary>
        public DerObjectIdentifier Oid => _oid;

        #endregion Properties

        #region Constructor

        /// <summary>
        /// Signature algorithm.
        /// </summary>
        /// <param name="name">Signature algorithm name.</param>
        /// <param name="asymmetricAlgorithm">Asymmetric algorithm.</param>
        protected SignatureAlgorithm(string name, IAsymmetricAlgorithm asymmetricAlgorithm)
        {
            _name = name;
            _asymmetricAlgorithm = asymmetricAlgorithm;
            _ = SignatureAlgorithmHelper.TryGetOid(name, out DerObjectIdentifier oid);
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
        /// <param name="privateKey">Asymmetric private key.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        public ISigner GenerateSigner(AsymmetricKeyParameter privateKey)
        {
            if (privateKey is null)
            {
                throw new ArgumentNullException(nameof(privateKey));
            }
            if (!privateKey.IsPrivate)
            {
                throw new CryptoException("Must be a asymmetric private key.");
            }
            ISigner signer = GenerateSignerCore();
            signer.Init(true, privateKey);
            return signer;
        }

        /// <summary>
        /// Generate signer. The signer can be reused.
        /// </summary>
        /// <param name="publicKey">Asymmetric public key.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        public ISigner GenerateVerifier(AsymmetricKeyParameter publicKey)
        {
            if (publicKey is null)
            {
                throw new ArgumentNullException(nameof(publicKey));
            }
            if (publicKey.IsPrivate)
            {
                throw new CryptoException("Must be a asymmetric public key.");
            }
            ISigner signer = GenerateSignerCore();
            signer.Init(false, publicKey);
            return signer;
        }

        /// <summary>
        /// Generate a new signature algorithm and sign data.
        /// </summary>
        /// <param name="privateKey">Asymmetric private key.</param>
        /// <param name="data">Data bytes.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        public byte[] Sign(AsymmetricKeyParameter privateKey, byte[] data)
        {
            return Sign(privateKey, data, 0, data.Length);
        }

        /// <summary>
        /// Generate a new signature algorithm and sign data.
        /// </summary>
        /// <param name="privateKey">Asymmetric private key.</param>
        /// <param name="data">Data buffer bytes.</param>
        /// <param name="offset">The starting offset to read.</param>
        /// <param name="length">The length to read.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        public byte[] Sign(AsymmetricKeyParameter privateKey, byte[] data, int offset, int length)
        {
            if (privateKey is null)
            {
                throw new ArgumentNullException(nameof(privateKey));
            }
            if (data is null)
            {
                throw new ArgumentNullException(nameof(data));
            }
            if (!privateKey.IsPrivate)
            {
                throw new CryptoException("Must be a asymmetric private key.");
            }
            ISigner signer = GenerateSigner(privateKey);
            signer.BlockUpdate(data, offset, length);
            return signer.GenerateSignature();
        }

        /// <summary>
        /// Return algorithm name.
        /// </summary>
        /// <returns></returns>
        public override string ToString()
        {
            return _name;
        }

        /// <summary>
        /// Generate a new signature algorithm and verify data.
        /// </summary>
        /// <param name="publicKey">Asymmetric public key.</param>
        /// <param name="data">Data bytes.</param>
        /// <param name="signature">Signature.</param>
        /// <returns></returns>
        public bool Verify(AsymmetricKeyParameter publicKey, byte[] data, byte[] signature)
        {
            return Verify(publicKey, data, 0, data.Length, signature, 0, signature.Length);
        }

        /// <summary>
        /// Generate a new signature algorithm and sign data.
        /// </summary>
        /// <param name="publicKey">Asymmetric public key.</param>
        /// <param name="data">Data buffer bytes.</param>
        /// <param name="offset">The starting offset to read.</param>
        /// <param name="length">The length to read.</param>
        /// <param name="signature">Signature buffer bytes.</param>
        /// <param name="signatureOffset">The starting offset to read.</param>
        /// <param name="signatureLength">The length to read.</param>
        /// <returns></returns>
        public bool Verify(AsymmetricKeyParameter publicKey, byte[] data, int offset, int length, byte[] signature, int signatureOffset, int signatureLength)
        {
            if (publicKey is null)
            {
                throw new ArgumentNullException(nameof(publicKey));
            }
            if (data is null)
            {
                throw new ArgumentNullException(nameof(data));
            }
            if (signature is null)
            {
                throw new ArgumentNullException(nameof(signature));
            }
            if (publicKey.IsPrivate)
            {
                throw new CryptoException("Must be a asymmetric public key.");
            }
            ISigner verifier = GenerateVerifier(publicKey);
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
        protected abstract ISigner GenerateSignerCore();
    }
}