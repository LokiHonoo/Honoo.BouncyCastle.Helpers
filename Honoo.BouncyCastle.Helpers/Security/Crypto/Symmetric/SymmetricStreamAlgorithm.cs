using Honoo.BouncyCastle.Helpers.Utilities;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
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

        private readonly KeySizes[] _ivSizes;
        private readonly KeySizes[] _keySizes;

        /// <summary>
        /// Gets legal IV size bits.
        /// </summary>
        public KeySizes[] IVSizes
        { get { return (KeySizes[])_ivSizes.Clone(); } }

        /// <summary>
        /// Gets legal key size bits.
        /// </summary>
        public override KeySizes[] KeySizes
        { get { return (KeySizes[])_keySizes.Clone(); } }

        #endregion Properties

        #region Constructor

        /// <summary>
        /// Symmetric stream algorithm.
        /// </summary>
        /// <param name="name">Symmetric stream algorithm name.</param>
        /// <param name="kind">Symmetric algorithm kind.</param>
        /// <param name="keySizes">Key sizes.</param>
        /// <param name="ivSizes">IV sizes.</param>
        protected SymmetricStreamAlgorithm(string name, SymmetricAlgorithmKind kind, KeySizes[] keySizes, KeySizes[] ivSizes) : base(name, kind)
        {
            _keySizes = keySizes;
            _ivSizes = ivSizes;
        }

        #endregion Constructor

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
            if (parameters is null)
            {
                throw new ArgumentNullException(nameof(parameters));
            }

            if (dataBuffer is null)
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
            if (parameters is null)
            {
                throw new ArgumentNullException(nameof(parameters));
            }
            if (dataBuffer is null)
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
        /// Generate parameters.
        /// </summary>
        /// <param name="key">Key bytes.</param>
        /// <param name="iv">IV bytes.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        public override ICipherParameters GenerateParameters(byte[] key, byte[] iv)
        {
            ICipherParameters parameters = new KeyParameter(key);
            if (iv != null)
            {
                parameters = new ParametersWithIV(parameters, iv);
            }
            return parameters;
        }

        /// <summary>
        /// Generate parameters.
        /// </summary>
        /// <param name="keyBuffer">Key buffer bytes.</param>
        /// <param name="keyOffset">The starting offset to read.</param>
        /// <param name="keyLength">The length to read.</param>
        /// <param name="ivBuffer">IV buffer bytes.</param>
        /// <param name="ivOffset">The starting offset to read.</param>
        /// <param name="ivLength">The length to read.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        public override ICipherParameters GenerateParameters(byte[] keyBuffer, int keyOffset, int keyLength, byte[] ivBuffer, int ivOffset, int ivLength)
        {
            ICipherParameters parameters = new KeyParameter(keyBuffer, keyOffset, keyLength);
            if (ivBuffer != null && ivLength > 0)
            {
                parameters = new ParametersWithIV(parameters, ivBuffer, ivOffset, ivLength);
            }
            return parameters;
        }

        /// <summary>
        /// Verify IV size.
        /// </summary>
        /// <param name="ivSize">IV size bits.</param>
        /// <returns></returns>
        public bool VerifyIVSize(int ivSize)
        {
            return DetectionUtilities.ValidSize(_ivSizes, ivSize);
        }

        /// <summary>
        /// Verify key size.
        /// </summary>
        /// <param name="keySize">Key size bits.</param>
        /// <returns></returns>
        public override bool VerifyKeySize(int keySize)
        {
            return DetectionUtilities.ValidSize(_keySizes, keySize);
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