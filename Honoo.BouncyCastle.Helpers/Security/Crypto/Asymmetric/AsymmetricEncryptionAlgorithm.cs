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
        /// <param name="algorithmKind">Asymmetric algorithm kind.</param>
        protected AsymmetricEncryptionAlgorithm(string mechanism, AsymmetricAlgorithmKind algorithmKind) : base(mechanism, algorithmKind)
        {
        }

        #endregion Constructor

        /// <summary>
        /// Generate a new asymmetric encryption algorithm and decrypt data.
        /// </summary>
        /// <param name="padding">Asymmetric padding mode.</param>
        /// <param name="privateKey">Asymmetric private key.</param>
        /// <param name="data">Data bytes.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        public byte[] Decrypt(AsymmetricPaddingMode padding, AsymmetricKeyParameter privateKey, byte[] data)
        {
            return Decrypt(padding, privateKey, data, 0, data.Length);
        }

        /// <summary>
        /// Generate a new asymmetric encryption algorithm and decrypt data.
        /// </summary>
        /// <param name="padding">Asymmetric padding mode.</param>
        /// <param name="privateKey">Asymmetric private key.</param>
        /// <param name="data">Data buffer bytes.</param>
        /// <param name="offset">The starting offset to read.</param>
        /// <param name="length">The length to read.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        public byte[] Decrypt(AsymmetricPaddingMode padding, AsymmetricKeyParameter privateKey, byte[] data, int offset, int length)
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
            IAsymmetricBlockCipher decryptor = GenerateDecryptor(padding, privateKey);
            return decryptor.ProcessBlock(data, offset, length);
        }

        /// <summary>
        /// Generate a new asymmetric encryption algorithm and encrypt data.
        /// </summary>
        /// <param name="padding">Asymmetric padding mode.</param>
        /// <param name="publicKey">Asymmetric public key.</param>
        /// <param name="data">Data bytes.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        public byte[] Encrypt(AsymmetricPaddingMode padding, AsymmetricKeyParameter publicKey, byte[] data)
        {
            return Encrypt(padding, publicKey, data, 0, data.Length);
        }

        /// <summary>
        /// Generate a new asymmetric encryption algorithm and encrypt data.
        /// </summary>
        /// <param name="padding">Asymmetric padding mode.</param>
        /// <param name="publicKey">Asymmetric public key.</param>
        /// <param name="data">Data buffer bytes.</param>
        /// <param name="offset">The starting offset to read.</param>
        /// <param name="length">The length to read.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        public byte[] Encrypt(AsymmetricPaddingMode padding, AsymmetricKeyParameter publicKey, byte[] data, int offset, int length)
        {
            if (publicKey is null)
            {
                throw new ArgumentNullException(nameof(publicKey));
            }
            if (data is null)
            {
                throw new ArgumentNullException(nameof(data));
            }
            if (publicKey.IsPrivate)
            {
                throw new CryptoException("Must be a asymmetric public key.");
            }
            IAsymmetricBlockCipher encryptor = GenerateEncryptor(padding, publicKey);
            return encryptor.ProcessBlock(data, offset, length);
        }

        /// <summary>
        /// Generate cipher. The cipher can be reused.
        /// </summary>
        /// <param name="padding">Asymmetric algorithm padding mode.</param>
        /// <param name="privateKey">Asymmetric private key.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        public IAsymmetricBlockCipher GenerateDecryptor(AsymmetricPaddingMode padding, AsymmetricKeyParameter privateKey)
        {
            if (privateKey is null)
            {
                throw new ArgumentNullException(nameof(privateKey));
            }
            if (!privateKey.IsPrivate)
            {
                throw new CryptoException("Must be a asymmetric private key.");
            }
            return GenerateCipher(false, padding, privateKey);
        }

        /// <summary>
        /// Generate cipher. The cipher can be reused.
        /// </summary>
        /// <param name="padding">Asymmetric algorithm padding mode.</param>
        /// <param name="publicKey">Asymmetric public key.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        public IAsymmetricBlockCipher GenerateEncryptor(AsymmetricPaddingMode padding, AsymmetricKeyParameter publicKey)
        {
            if (publicKey is null)
            {
                throw new ArgumentNullException(nameof(publicKey));
            }
            if (publicKey.IsPrivate)
            {
                throw new CryptoException("Must be a asymmetric public key.");
            }
            return GenerateCipher(true, padding, publicKey);
        }

        /// <summary>
        ///
        /// </summary>
        /// <param name="padding"></param>
        /// <returns></returns>
        protected abstract IAsymmetricBlockCipher GenerateCipherCore(AsymmetricPaddingMode padding);

        private IAsymmetricBlockCipher GenerateCipher(bool encryption, AsymmetricPaddingMode padding, AsymmetricKeyParameter asymmetricKey)
        {
            IAsymmetricBlockCipher cipher = GenerateCipherCore(padding);
            cipher.Init(encryption, asymmetricKey);
            return cipher;
        }
    }
}