using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.Security.Cryptography;

namespace Honoo.BouncyCastle.Helpers
{
    /// <summary>
    /// Represents the abstract base class from which all implementations of symmetric stream algorithms must inherit.
    /// </summary>
    public abstract class SymmetricStreamAlgorithm : SymmetricAlgorithm
    {
        #region Properties

        private readonly int _defaultIVSize;
        private readonly int _defaultKeySize;

        #endregion Properties

        #region Construction

        /// <summary>
        /// Initializes a new instance of the SymmetricStreamAlgorithm class.
        /// </summary>
        /// <param name="name"></param>
        /// <param name="defaultKeySize"></param>
        /// <param name="defaultIVSize"></param>
        protected SymmetricStreamAlgorithm(string name, int defaultKeySize, int defaultIVSize)
            : base(name, SymmetricAlgorithmKind.Stream, 0, defaultKeySize, defaultIVSize)
        {
            _defaultKeySize = defaultKeySize;
            _defaultIVSize = defaultIVSize;
        }

        #endregion Construction

        /// <summary>
        /// Renew parameters of the algorithm by default key size and iv size.
        /// </summary>
        public override void GenerateParameters()
        {
            GenerateParameters(_defaultKeySize, _defaultIVSize);
        }

        /// <inheritdoc/>
        public override void ImportParameters(ICipherParameters parameters)
        {
            if (parameters == null)
            {
                throw new ArgumentNullException(nameof(parameters));
            }
            int keySize;
            int ivSize;
            ICipherParameters parameters1;
            if (parameters.GetType() == typeof(AeadParameters))
            {
                throw new CryptographicException("AeadParameters not supported of symmetric stream algorithm.");
            }
            else if (parameters.GetType() == typeof(ParametersWithIV))
            {
                ParametersWithIV parameters2 = (ParametersWithIV)parameters;
                byte[] iv = parameters2.GetIV();
                ivSize = iv == null ? 0 : iv.Length * 8;
                if (!ValidIVSize(ivSize, out string exception))
                {
                    throw new CryptographicException(exception);
                }
                byte[] key = ((KeyParameter)parameters2.Parameters).GetKey();
                keySize = key.Length * 8;
                if (!ValidKeySize(keySize, out exception))
                {
                    throw new CryptographicException(exception);
                }
                parameters1 = GetKeyParameter(key);
                if (ivSize > 0)
                {
                    parameters1 = new ParametersWithIV(parameters1, iv);
                }
            }
            else
            {
                KeyParameter parameter = (KeyParameter)parameters;
                ivSize = 0;
                if (!ValidIVSize(ivSize, out string exception))
                {
                    throw new CryptographicException(exception);
                }
                byte[] key = parameter.GetKey();
                keySize = key.Length * 8;
                if (!ValidKeySize(keySize, out exception))
                {
                    throw new CryptographicException(exception);
                }
                parameters1 = GetKeyParameter(key);
            }
            base.Parameters = parameters1;
            base.KeySizeProtected = keySize;
            base.IVSizeProtected = ivSize;
            base.Encryptor = null;
            base.Decryptor = null;
            base.Initialized = true;
        }

        /// <summary>
        ///
        /// </summary>
        /// <returns></returns>
        internal abstract IStreamCipher GetEngine();

        /// <summary>
        ///
        /// </summary>
        /// <param name="forEncryption"></param>
        /// <returns></returns>
        protected override IBufferedCipher GetCipher(bool forEncryption)
        {
            IStreamCipher engine = GetEngine();
            BufferedStreamCipher cipher = new BufferedStreamCipher(engine);
            cipher.Init(forEncryption, base.Parameters);
            return cipher;
        }
    }
}