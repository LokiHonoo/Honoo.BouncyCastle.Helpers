using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.Security.Cryptography;

namespace Honoo.BouncyCastle.Helpers.Security.Crypto.Symmetric
{
    /// <summary>
    /// Symmetric algorithm.
    /// </summary>
    public abstract class SymmetricAlgorithm : ISymmetricAlgorithm
    {
        #region Properties

        private readonly SymmetricAlgorithmKind _kind;
        private readonly string _name;

        /// <summary>
        /// Symmetric algorithm kind.
        /// </summary>
        public SymmetricAlgorithmKind Kind => _kind;

        /// <summary>
        /// Gets legal key size bits.
        /// </summary>
        public abstract KeySizes[] LegalKeySizes { get; }

        /// <summary>
        /// Gets algorithm name.
        /// </summary>
        public string Name => _name;

        #endregion Properties

        #region Construction

        /// <summary>
        /// Symmetric algorithm.
        /// </summary>
        /// <param name="name">Symmetric algorithm name.</param>
        /// <param name="kind">Symmetric algorithm kind.</param>
        protected SymmetricAlgorithm(string name, SymmetricAlgorithmKind kind)
        {
            _name = name;
            _kind = kind;
        }

        #endregion Construction

        /// <summary>
        /// Generate parameters.
        /// </summary>
        /// <param name="key">Key bytes.</param>
        /// <param name="iv">IV bytes.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        public ICipherParameters GenerateParameters(byte[] key, byte[] iv)
        {
            ICipherParameters parameters = GenerateKeyParameter(key);
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
        public ICipherParameters GenerateParameters(byte[] keyBuffer, int keyOffset, int keyLength, byte[] ivBuffer, int ivOffset, int ivLength)
        {
            ICipherParameters parameters = GenerateKeyParameter(keyBuffer, keyOffset, keyLength);
            if (ivBuffer != null)
            {
                parameters = new ParametersWithIV(parameters, ivBuffer, ivOffset, ivLength);
            }
            return parameters;
        }

        /// <summary>
        /// Verify key size.
        /// </summary>
        /// <param name="keySize">Key size bits.</param>
        /// <returns></returns>
        public abstract bool VerifyKeySize(int keySize);

        /// <summary>
        /// Generate KeyParameter.
        /// </summary>
        /// <param name="key">Key.</param>
        /// <returns></returns>
        protected virtual KeyParameter GenerateKeyParameter(byte[] key)
        {
            return new KeyParameter(key);
        }

        /// <summary>
        /// Generate KeyParameter.
        /// </summary>
        /// <param name="keyBuffer">Key buffer bytes.</param>
        /// <param name="offset">Offset.</param>
        /// <param name="length">Length.</param>
        /// <returns></returns>
        protected virtual KeyParameter GenerateKeyParameter(byte[] keyBuffer, int offset, int length)
        {
            return new KeyParameter(keyBuffer, offset, length);
        }
    }
}