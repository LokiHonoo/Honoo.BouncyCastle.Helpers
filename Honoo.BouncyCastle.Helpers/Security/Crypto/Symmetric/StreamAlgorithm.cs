using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.Security.Cryptography;

namespace Honoo.BouncyCastle.Helpers.Security.Crypto.Symmetric
{
    /// <summary>
    /// Symmetric stream algorithm.
    /// </summary>
    public abstract class StreamAlgorithm : SymmetricAlgorithm, IStreamAlgorithm
    {
        #region Properties

        private readonly KeySizes[] _ivSizes;
        private readonly KeySizes[] _keySizes;

        /// <summary>
        /// Gets legal iv size bits.
        /// </summary>
        public KeySizes[] IVSizes
        { get { return (KeySizes[])_ivSizes.Clone(); } }

        /// <summary>
        /// Gets legal key size bits.
        /// </summary>
        public KeySizes[] KeySizes
        { get { return (KeySizes[])_keySizes.Clone(); } }

        #endregion Properties

        #region Constructor

        /// <summary>
        /// Symmetric stream algorithm.
        /// </summary>
        /// <param name="mechanism">Symmetric stream algorithm mechanism.</param>
        /// <param name="algorithmKind">Symmetric algorithm kind.</param>
        /// <param name="keySizes">Key sizes.</param>
        /// <param name="ivSizes">IV sizes.</param>
        protected StreamAlgorithm(string mechanism, SymmetricAlgorithmKind algorithmKind, KeySizes[] keySizes, KeySizes[] ivSizes) : base(mechanism, algorithmKind)
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
        /// <param name="data">Data buffer bytes.</param>
        /// <param name="offset">The starting offset to read.</param>
        /// <param name="length">The length to read.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        public byte[] Decrypt(ICipherParameters parameters, byte[] data, int offset, int length)
        {
            if (parameters is null)
            {
                throw new ArgumentNullException(nameof(parameters));
            }

            if (data is null)
            {
                throw new ArgumentNullException(nameof(data));
            }
            IBufferedCipher decryptor = GenerateCipher(false, parameters);
            return decryptor.DoFinal(data, offset, length);
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
        /// <param name="data">Data buffer bytes.</param>
        /// <param name="offset">The starting offset to read.</param>
        /// <param name="length">The length to read.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        public byte[] Encrypt(ICipherParameters parameters, byte[] data, int offset, int length)
        {
            if (parameters is null)
            {
                throw new ArgumentNullException(nameof(parameters));
            }
            if (data is null)
            {
                throw new ArgumentNullException(nameof(data));
            }
            IBufferedCipher encryptor = GenerateCipher(true, parameters);
            return encryptor.DoFinal(data, offset, length);
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
        public ICipherParameters GenerateParameters(byte[] key, byte[] iv)
        {
            return iv is null ? GenerateParameters(key, 0, key.Length, null, 0, 0) : GenerateParameters(key, 0, key.Length, iv, 0, iv.Length);
        }

        /// <summary>
        /// Generate parameters.
        /// </summary>
        /// <param name="key">Key buffer bytes.</param>
        /// <param name="keyOffset">The starting offset to read.</param>
        /// <param name="keyLength">The length to read.</param>
        /// <param name="iv">IV buffer bytes.</param>
        /// <param name="ivOffset">The starting offset to read.</param>
        /// <param name="ivLength">The length to read.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        public ICipherParameters GenerateParameters(byte[] key, int keyOffset, int keyLength, byte[] iv, int ivOffset, int ivLength)
        {
            ICipherParameters parameters = new KeyParameter(key, keyOffset, keyLength);
            if (iv != null && ivLength > 0)
            {
                parameters = new ParametersWithIV(parameters, iv, ivOffset, ivLength);
            }
            return parameters;
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