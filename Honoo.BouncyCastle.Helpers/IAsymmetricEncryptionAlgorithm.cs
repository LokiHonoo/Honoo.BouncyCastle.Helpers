using Org.BouncyCastle.Crypto;
using System;

namespace Honoo.BouncyCastle.Helpers
{
    /// <summary>
    /// Asymmetric encryption algorithm interface.
    /// </summary>
    public interface IAsymmetricEncryptionAlgorithm : IAsymmetricAlgorithm
    {
        /// <summary>
        /// Generate a new asymmetric encryption algorithm and decrypt data.
        /// </summary>
        /// <param name="padding">Asymmetric padding mode.</param>
        /// <param name="privateKey">Asymmetric private key.</param>
        /// <param name="data">Data.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        byte[] Decrypt(AsymmetricPaddingMode padding, AsymmetricKeyParameter privateKey, byte[] data);

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
        byte[] Decrypt(AsymmetricPaddingMode padding,
                       IHashAlgorithm mgf1HashAlgorithm1,
                       IHashAlgorithm mgf1HashAlgorithm2,
                       AsymmetricKeyParameter privateKey,
                       byte[] data);

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
        byte[] Decrypt(AsymmetricPaddingMode padding, AsymmetricKeyParameter privateKey, byte[] data, int offset, int length);

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
        byte[] Decrypt(AsymmetricPaddingMode padding,
                       IHashAlgorithm mgf1HashAlgorithm1,
                       IHashAlgorithm mgf1HashAlgorithm2,
                       AsymmetricKeyParameter privateKey,
                       byte[] data,
                       int offset,
                       int length);

        /// <summary>
        /// Generate a new asymmetric encryption algorithm and encrypt data.
        /// </summary>
        /// <param name="padding">Asymmetric padding mode.</param>
        /// <param name="publicKey">Asymmetric public key.</param>
        /// <param name="data">Data.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        byte[] Encrypt(AsymmetricPaddingMode padding, AsymmetricKeyParameter publicKey, byte[] data);

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
        byte[] Encrypt(AsymmetricPaddingMode padding,
                       IHashAlgorithm mgf1HashAlgorithm1,
                       IHashAlgorithm mgf1HashAlgorithm2,
                       AsymmetricKeyParameter publicKey,
                       byte[] data);

        /// <summary>
        /// Generate a new asymmetric encryption algorithm and encrypt data.
        /// </summary>
        /// <param name="padding">Asymmetric padding mode.</param>
        /// <param name="publicKey">Asymmetric public key.</param>
        /// <param name="data">Data.</param>
        /// <param name="offset">The starting offset to read.</param>
        /// <param name="length">The length to read.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        byte[] Encrypt(AsymmetricPaddingMode padding, AsymmetricKeyParameter publicKey, byte[] data, int offset, int length);

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
        byte[] Encrypt(AsymmetricPaddingMode padding,
                       IHashAlgorithm mgf1HashAlgorithm1,
                       IHashAlgorithm mgf1HashAlgorithm2,
                       AsymmetricKeyParameter publicKey,
                       byte[] data,
                       int offset,
                       int length);

        /// <summary>
        /// Generate cipher. The cipher can be reused.
        /// </summary>
        /// <param name="padding">Asymmetric padding mode.</param>
        /// <param name="privateKey">Asymmetric private key.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        IAsymmetricBlockCipher GenerateDecryptor(AsymmetricPaddingMode padding, AsymmetricKeyParameter privateKey);

        /// <summary>
        /// Generate cipher. The cipher can be reused.
        /// </summary>
        /// <param name="padding">Asymmetric padding mode.</param>
        /// <param name="mgf1HashAlgorithm1">Only for OAEP padding mode.</param>
        /// <param name="mgf1HashAlgorithm2">Only for OAEP padding mode.</param>
        /// <param name="privateKey">Asymmetric private key.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        IAsymmetricBlockCipher GenerateDecryptor(AsymmetricPaddingMode padding,
                                                 IHashAlgorithm mgf1HashAlgorithm1,
                                                 IHashAlgorithm mgf1HashAlgorithm2,
                                                 AsymmetricKeyParameter privateKey);

        /// <summary>
        /// Generate cipher. The cipher can be reused.
        /// </summary>
        /// <param name="padding">Asymmetric padding mode.</param>
        /// <param name="publicKey">Asymmetric public key.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        IAsymmetricBlockCipher GenerateEncryptor(AsymmetricPaddingMode padding, AsymmetricKeyParameter publicKey);

        /// <summary>
        /// Generate cipher. The cipher can be reused.
        /// </summary>
        /// <param name="padding">Asymmetric padding mode.</param>
        /// <param name="mgf1HashAlgorithm1">Only for OAEP padding mode.</param>
        /// <param name="mgf1HashAlgorithm2">Only for OAEP padding mode.</param>
        /// <param name="publicKey">Asymmetric public key.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        IAsymmetricBlockCipher GenerateEncryptor(AsymmetricPaddingMode padding,
                                                 IHashAlgorithm mgf1HashAlgorithm1,
                                                 IHashAlgorithm mgf1HashAlgorithm2,
                                                 AsymmetricKeyParameter publicKey);
    }
}