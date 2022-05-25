using Org.BouncyCastle.Crypto;
using System;

namespace Honoo.BouncyCastle.Helpers.Security.Crypto.Asymmetric
{
    /// <summary>
    /// Asymmetric encryption algorithm.
    /// </summary>
    public abstract class AsymmetricEncryptionAlgorithm : AsymmetricAlgorithm, IAsymmetricEncryptionAlgorithm
    {
        #region Constructor

        /// <summary>
        /// Asymmetric encryption algorithm.
        /// </summary>
        /// <param name="mechanism">Asymmetric algorithm mechanism.</param>
        protected AsymmetricEncryptionAlgorithm(string mechanism) : base(mechanism)
        {
        }

        #endregion Constructor

        /// <summary>
        /// Generate a new asymmetric encryption algorithm and decrypt data.
        /// </summary>
        /// <param name="padding">Asymmetric padding mode.</param>
        /// <param name="asymmetricKey">Asymmetric private key.</param>
        /// <param name="data">Data bytes.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        public byte[] Decrypt(AsymmetricPaddingMode padding, AsymmetricKeyParameter asymmetricKey, byte[] data)
        {
            return Decrypt(padding, asymmetricKey, data, 0, data.Length);
        }

        /// <summary>
        /// Generate a new asymmetric encryption algorithm and decrypt data.
        /// </summary>
        /// <param name="padding">Asymmetric padding mode.</param>
        /// <param name="asymmetricKey">Asymmetric private key.</param>
        /// <param name="data">Data buffer bytes.</param>
        /// <param name="offset">The starting offset to read.</param>
        /// <param name="length">The length to read.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        public byte[] Decrypt(AsymmetricPaddingMode padding, AsymmetricKeyParameter asymmetricKey, byte[] data, int offset, int length)
        {
            if (asymmetricKey is null)
            {
                throw new ArgumentNullException(nameof(asymmetricKey));
            }

            if (data is null)
            {
                throw new ArgumentNullException(nameof(data));
            }
            IAsymmetricBlockCipher decryptor = GenerateCipher(padding, asymmetricKey);
            return decryptor.ProcessBlock(data, offset, length);
        }

        /// <summary>
        /// Generate a new asymmetric encryption algorithm and encrypt data.
        /// </summary>
        /// <param name="padding">Asymmetric padding mode.</param>
        /// <param name="asymmetricKey">Asymmetric public key.</param>
        /// <param name="data">Data bytes.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        public byte[] Encrypt(AsymmetricPaddingMode padding, AsymmetricKeyParameter asymmetricKey, byte[] data)
        {
            return Encrypt(padding, asymmetricKey, data, 0, data.Length);
        }

        /// <summary>
        /// Generate a new asymmetric encryption algorithm and encrypt data.
        /// </summary>
        /// <param name="padding">Asymmetric padding mode.</param>
        /// <param name="asymmetricKey">Asymmetric public key.</param>
        /// <param name="data">Data buffer bytes.</param>
        /// <param name="offset">The starting offset to read.</param>
        /// <param name="length">The length to read.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        public byte[] Encrypt(AsymmetricPaddingMode padding, AsymmetricKeyParameter asymmetricKey, byte[] data, int offset, int length)
        {
            IAsymmetricBlockCipher encryptor = GenerateCipher(padding, asymmetricKey);
            return encryptor.ProcessBlock(data, offset, length);
        }

        /// <summary>
        /// Generate cipher. The cipher can be reused.
        /// </summary>
        /// <param name="padding">Asymmetric algorithm padding mode.</param>
        /// <param name="asymmetricKey">Asymmetric public key or private key.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        public abstract IAsymmetricBlockCipher GenerateCipher(AsymmetricPaddingMode padding, AsymmetricKeyParameter asymmetricKey);
    }
}