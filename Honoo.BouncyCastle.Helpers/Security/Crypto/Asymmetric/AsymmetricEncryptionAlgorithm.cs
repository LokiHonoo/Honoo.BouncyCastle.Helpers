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
        /// <param name="mgf1HashAlgorithm1">Only for OAEP padding mode.</param>
        /// <param name="mgf1HashAlgorithm2">Only for OAEP padding mode.</param>
        /// <param name="privateKey">Asymmetric private key.</param>
        /// <param name="data">Data.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        public byte[] Decrypt(AsymmetricPaddingMode padding,
                              IHashAlgorithm mgf1HashAlgorithm1,
                              IHashAlgorithm mgf1HashAlgorithm2,
                              AsymmetricKeyParameter privateKey,
                              byte[] data)
        {
            return Decrypt(padding, mgf1HashAlgorithm1, mgf1HashAlgorithm2, privateKey, data, 0, data.Length);
        }

        /// <summary>
        /// Generate a new asymmetric encryption algorithm and decrypt data.
        /// </summary>
        /// <param name="padding">Asymmetric padding mode.</param>
        /// <param name="privateKey">Asymmetric private key.</param>
        /// <param name="data">Data.</param>
        /// <param name="offset">The starting offset to read.</param>
        /// <param name="length">The length to read.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        public byte[] Decrypt(AsymmetricPaddingMode padding, AsymmetricKeyParameter privateKey, byte[] data, int offset, int length)
        {
            return Decrypt(padding, null, null, privateKey, data, 0, data.Length);
        }

        /// <summary>
        /// Generate a new asymmetric encryption algorithm and decrypt data.
        /// </summary>
        /// <param name="padding">Asymmetric padding mode.</param>
        /// <param name="mgf1HashAlgorithm1">Only for OAEP padding mode.</param>
        /// <param name="mgf1HashAlgorithm2">Only for OAEP padding mode.</param>
        /// <param name="privateKey">Asymmetric private key.</param>
        /// <param name="data">Data.</param>
        /// <param name="offset">The starting offset to read.</param>
        /// <param name="length">The length to read.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        public byte[] Decrypt(AsymmetricPaddingMode padding,
                               IHashAlgorithm mgf1HashAlgorithm1,
                               IHashAlgorithm mgf1HashAlgorithm2,
                               AsymmetricKeyParameter privateKey,
                               byte[] data,
                               int offset,
                               int length)
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
            IAsymmetricBlockCipher decryptor = GenerateDecryptor(padding, mgf1HashAlgorithm1, mgf1HashAlgorithm2, privateKey);
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
        /// <param name="mgf1HashAlgorithm1">Only for OAEP padding mode.</param>
        /// <param name="mgf1HashAlgorithm2">Only for OAEP padding mode.</param>
        /// <param name="publicKey">Asymmetric public key.</param>
        /// <param name="data">Data.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        public byte[] Encrypt(AsymmetricPaddingMode padding,
                              IHashAlgorithm mgf1HashAlgorithm1,
                              IHashAlgorithm mgf1HashAlgorithm2,
                              AsymmetricKeyParameter publicKey,
                              byte[] data)
        {
            return Encrypt(padding, mgf1HashAlgorithm1, mgf1HashAlgorithm2, publicKey, data, 0, data.Length);
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
            return Encrypt(padding, null, null, publicKey, data, offset, length);
        }

        /// <summary>
        /// Generate a new asymmetric encryption algorithm and encrypt data.
        /// </summary>
        /// <param name="padding">Asymmetric padding mode.</param>
        /// <param name="mgf1HashAlgorithm1">Only for OAEP padding mode.</param>
        /// <param name="mgf1HashAlgorithm2">Only for OAEP padding mode.</param>
        /// <param name="publicKey">Asymmetric public key.</param>
        /// <param name="data">Data.</param>
        /// <param name="offset">The starting offset to read.</param>
        /// <param name="length">The length to read.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        public byte[] Encrypt(AsymmetricPaddingMode padding,
                              IHashAlgorithm mgf1HashAlgorithm1,
                              IHashAlgorithm mgf1HashAlgorithm2,
                              AsymmetricKeyParameter publicKey,
                              byte[] data,
                              int offset,
                              int length)
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
            IAsymmetricBlockCipher encryptor = GenerateEncryptor(padding, mgf1HashAlgorithm1, mgf1HashAlgorithm2, publicKey);
            return encryptor.ProcessBlock(data, offset, length);
        }

        /// <summary>
        /// Generate cipher. The cipher can be reused.
        /// </summary>
        /// <param name="padding">Asymmetric padding mode.</param>
        /// <param name="privateKey">Asymmetric private key.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        public IAsymmetricBlockCipher GenerateDecryptor(AsymmetricPaddingMode padding, AsymmetricKeyParameter privateKey)
        {
            return GenerateDecryptor(padding, null, null, privateKey);
        }

        /// <summary>
        /// Generate cipher. The cipher can be reused.
        /// </summary>
        /// <param name="padding">Asymmetric padding mode.</param>
        /// <param name="mgf1HashAlgorithm1">Only for OAEP padding mode.</param>
        /// <param name="mgf1HashAlgorithm2">Only for OAEP padding mode.</param>
        /// <param name="privateKey">Asymmetric private key.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        public IAsymmetricBlockCipher GenerateDecryptor(AsymmetricPaddingMode padding,
                                                         IHashAlgorithm mgf1HashAlgorithm1,
                                                         IHashAlgorithm mgf1HashAlgorithm2,
                                                         AsymmetricKeyParameter privateKey)
        {
            if (privateKey is null)
            {
                throw new ArgumentNullException(nameof(privateKey));
            }
            if (!privateKey.IsPrivate)
            {
                throw new CryptoException("Must be a asymmetric private key.");
            }
            return GenerateCipher(false, padding, mgf1HashAlgorithm1, mgf1HashAlgorithm2, privateKey);
        }

        /// <summary>
        /// Generate cipher. The cipher can be reused.
        /// </summary>
        /// <param name="padding">Asymmetric padding mode.</param>
        /// <param name="publicKey">Asymmetric public key.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        public IAsymmetricBlockCipher GenerateEncryptor(AsymmetricPaddingMode padding, AsymmetricKeyParameter publicKey)
        {
            return GenerateEncryptor(padding, null, null, publicKey);
        }

        /// <summary>
        /// Generate cipher. The cipher can be reused.
        /// </summary>
        /// <param name="padding">Asymmetric padding mode.</param>
        /// <param name="mgf1HashAlgorithm1">Only for OAEP padding mode.</param>
        /// <param name="mgf1HashAlgorithm2">Only for OAEP padding mode.</param>
        /// <param name="publicKey">Asymmetric public key.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        public IAsymmetricBlockCipher GenerateEncryptor(AsymmetricPaddingMode padding,
                                                        IHashAlgorithm mgf1HashAlgorithm1,
                                                        IHashAlgorithm mgf1HashAlgorithm2,
                                                        AsymmetricKeyParameter publicKey)
        {
            if (publicKey is null)
            {
                throw new ArgumentNullException(nameof(publicKey));
            }
            if (publicKey.IsPrivate)
            {
                throw new CryptoException("Must be a asymmetric public key.");
            }
            return GenerateCipher(true, padding, mgf1HashAlgorithm1, mgf1HashAlgorithm2, publicKey);
        }

        /// <summary>
        ///
        /// </summary>
        /// <param name="padding"></param>
        /// <param name="mgf1HashAlgorithm1"></param>
        /// <param name="mgf1HashAlgorithm2"></param>
        /// <returns></returns>
        protected abstract IAsymmetricBlockCipher GenerateCipherCore(AsymmetricPaddingMode padding,
                                                                     IHashAlgorithm mgf1HashAlgorithm1,
                                                                     IHashAlgorithm mgf1HashAlgorithm2);

        private IAsymmetricBlockCipher GenerateCipher(bool encryption,
                                                      AsymmetricPaddingMode padding,
                                                      IHashAlgorithm mgf1HashAlgorithm1,
                                                      IHashAlgorithm mgf1HashAlgorithm2,
                                                      AsymmetricKeyParameter asymmetricKey)
        {
            IAsymmetricBlockCipher cipher = GenerateCipherCore(padding, mgf1HashAlgorithm1, mgf1HashAlgorithm2);
            cipher.Init(encryption, asymmetricKey);
            return cipher;
        }
    }
}