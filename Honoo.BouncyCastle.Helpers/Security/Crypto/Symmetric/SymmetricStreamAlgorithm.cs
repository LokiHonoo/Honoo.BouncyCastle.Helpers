using Honoo.BouncyCastle.Helpers.Utilities;
using Org.BouncyCastle.Crypto;
using System;
using System.Security.Cryptography;

namespace Honoo.BouncyCastle.Helpers.Security.Crypto.Symmetric
{
    /// <summary>
    /// Symmetric stream algorithm.
    /// </summary>
    public abstract class SymmetricStreamAlgorithm : SymmetricAlgorithm, ISymmetricStreamAlgorithm
    {
        #region Properties

        private readonly KeySizes[] _legalIVSizes;
        private readonly KeySizes[] _legalKeySizes;

        /// <summary>
        /// Gets legal IV size bits.
        /// </summary>
        public KeySizes[] LegalIVSizes
        { get { return (KeySizes[])_legalIVSizes.Clone(); } }

        /// <summary>
        /// Gets legal key size bits.
        /// </summary>
        public override KeySizes[] LegalKeySizes
        { get { return (KeySizes[])_legalKeySizes.Clone(); } }

        #endregion Properties

        #region Construction

        /// <summary>
        /// Symmetric stream algorithm.
        /// </summary>
        /// <param name="name">Symmetric stream algorithm name.</param>
        /// <param name="kind">Symmetric algorithm kind.</param>
        /// <param name="keySizes">Key sizes.</param>
        /// <param name="ivSizes">IV sizes.</param>
        protected SymmetricStreamAlgorithm(string name, SymmetricAlgorithmKind kind, KeySizes[] keySizes, KeySizes[] ivSizes) : base(name, kind)
        {
            _legalKeySizes = keySizes;
            _legalIVSizes = ivSizes;
        }

        #endregion Construction

        /// <summary>
        /// Generate a new symmetric stream algorithm and decrypt data.
        /// </summary>
        /// <param name="parameters">Parameters.</param>
        /// <param name="data">Data bytes.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        public byte[] Decrypt(ICipherParameters parameters, byte[] data)
        {
            return Decrypt(parameters, data, 0, data.Length);
        }

        /// <summary>
        /// Generate a new symmetric stream algorithm and decrypt data.
        /// </summary>
        /// <param name="parameters">Parameters.</param>
        /// <param name="dataBuffer">Data buffer bytes.</param>
        /// <param name="offset">The starting offset to read.</param>
        /// <param name="length">The length to read.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        public byte[] Decrypt(ICipherParameters parameters, byte[] dataBuffer, int offset, int length)
        {
            if (parameters == null)
            {
                throw new ArgumentNullException(nameof(parameters));
            }

            if (dataBuffer == null)
            {
                throw new ArgumentNullException(nameof(dataBuffer));
            }
            IBufferedCipher decryptor = GenerateCipher(false, parameters);
            return decryptor.DoFinal(dataBuffer, offset, length);
        }

        /// <summary>
        /// Generate a new symmetric stream algorithm and encrypt data.
        /// </summary>
        /// <param name="parameters">Parameters.</param>
        /// <param name="data">Data bytes.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        public byte[] Encrypt(ICipherParameters parameters, byte[] data)
        {
            return Encrypt(parameters, data, 0, data.Length);
        }

        /// <summary>
        /// Generate a new symmetric stream algorithm and encrypt data.
        /// </summary>
        /// <param name="parameters">Parameters.</param>
        /// <param name="dataBuffer">Data buffer bytes.</param>
        /// <param name="offset">The starting offset to read.</param>
        /// <param name="length">The length to read.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        public byte[] Encrypt(ICipherParameters parameters, byte[] dataBuffer, int offset, int length)
        {
            if (parameters == null)
            {
                throw new ArgumentNullException(nameof(parameters));
            }
            if (dataBuffer == null)
            {
                throw new ArgumentNullException(nameof(dataBuffer));
            }
            IBufferedCipher encryptor = GenerateCipher(true, parameters);
            return encryptor.DoFinal(dataBuffer, offset, length);
        }

        /// <summary>
        /// Generate cipher.
        /// </summary>
        /// <param name="parameters">Parameters.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        public IBufferedCipher GenerateDecryptor(ICipherParameters parameters)
        {
            return GenerateCipher(false, parameters);
        }

        /// <summary>
        /// Generate cipher.
        /// </summary>
        /// <param name="parameters">Parameters.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        public IBufferedCipher GenerateEncryptor(ICipherParameters parameters)
        {
            return GenerateCipher(true, parameters);
        }

        /// <summary>
        /// Verify IV size.
        /// </summary>
        /// <param name="ivSize">IV size bits.</param>
        /// <returns></returns>
        public bool VerifyIVSize(int ivSize)
        {
            return DetectionUtilities.ValidSize(_legalIVSizes, ivSize);
        }

        /// <summary>
        /// Verify key size.
        /// </summary>
        /// <param name="keySize">Key size bits.</param>
        /// <returns></returns>
        public override bool VerifyKeySize(int keySize)
        {
            return DetectionUtilities.ValidSize(_legalKeySizes, keySize);
        }

        /// <summary>
        /// Generate engine.
        /// </summary>
        /// <returns></returns>
        protected abstract IStreamCipher GenerateEngine();

        private IBufferedCipher GenerateCipher(bool forEncryption, ICipherParameters parameters)
        {
            IStreamCipher engine = GenerateEngine();
            IBufferedCipher cipher = new BufferedStreamCipher(engine);
            cipher.Init(forEncryption, parameters);
            return cipher;
        }
    }
}