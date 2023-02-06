using Org.BouncyCastle.Asn1.Oiw;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.Security.Cryptography;

namespace Honoo.BouncyCastle.Helpers.Security.Crypto.Asymmetric
{
    /// <summary>
    /// ElGamal.
    /// <para/>Legal key size is more than or equal to 8 bits (8 bits increments).
    /// </summary>
    public sealed class ElGamal : AsymmetricAlgorithm
    {
        #region Construction

        /// <summary>
        /// ElGamal.
        /// <para/>Legal key size is more than or equal to 8 bits (8 bits increments).
        /// </summary>
        public ElGamal() : base("ElGamal", OiwObjectIdentifiers.ElGamalAlgorithm, AsymmetricAlgorithmKind.Encryption)
        {
        }

        #endregion Construction

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
        /// <param name="dataBuffer">Data buffer bytes.</param>
        /// <param name="offset">The starting offset to read.</param>
        /// <param name="length">The length to read.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        public byte[] Decrypt(AsymmetricPaddingMode padding, AsymmetricKeyParameter privateKey, byte[] dataBuffer, int offset, int length)
        {
            return Decrypt(padding, null, null, privateKey, dataBuffer, offset, length);
        }

        /// <summary>
        /// Generate a new asymmetric encryption algorithm and decrypt data.
        /// </summary>
        /// <param name="padding">Asymmetric padding mode.</param>
        /// <param name="mgf1HashAlgorithm1">Only for OAEP padding mode.</param>
        /// <param name="mgf1HashAlgorithm2">Only for OAEP padding mode.</param>
        /// <param name="privateKey">Asymmetric private key.</param>
        /// <param name="dataBuffer">Data buffer bytes.</param>
        /// <param name="offset">The starting offset to read.</param>
        /// <param name="length">The length to read.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        public byte[] Decrypt(AsymmetricPaddingMode padding,
                               IHashAlgorithm mgf1HashAlgorithm1,
                               IHashAlgorithm mgf1HashAlgorithm2,
                               AsymmetricKeyParameter privateKey,
                               byte[] dataBuffer,
                               int offset,
                               int length)
        {
            if (privateKey == null)
            {
                throw new ArgumentNullException(nameof(privateKey));
            }
            if (dataBuffer == null)
            {
                throw new ArgumentNullException(nameof(dataBuffer));
            }
            if (!privateKey.IsPrivate)
            {
                throw new CryptoException("Must be a asymmetric private key.");
            }
            IAsymmetricBlockCipher decryptor = GenerateDecryptor(padding, mgf1HashAlgorithm1, mgf1HashAlgorithm2, privateKey);
            return decryptor.ProcessBlock(dataBuffer, offset, length);
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
        /// <param name="dataBuffer">Data buffer bytes.</param>
        /// <param name="offset">The starting offset to read.</param>
        /// <param name="length">The length to read.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        public byte[] Encrypt(AsymmetricPaddingMode padding, AsymmetricKeyParameter publicKey, byte[] dataBuffer, int offset, int length)
        {
            return Encrypt(padding, null, null, publicKey, dataBuffer, offset, length);
        }

        /// <summary>
        /// Generate a new asymmetric encryption algorithm and encrypt data.
        /// </summary>
        /// <param name="padding">Asymmetric padding mode.</param>
        /// <param name="mgf1HashAlgorithm1">Only for OAEP padding mode.</param>
        /// <param name="mgf1HashAlgorithm2">Only for OAEP padding mode.</param>
        /// <param name="publicKey">Asymmetric public key.</param>
        /// <param name="dataBuffer">Data buffer bytes.</param>
        /// <param name="offset">The starting offset to read.</param>
        /// <param name="length">The length to read.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        public byte[] Encrypt(AsymmetricPaddingMode padding,
                              IHashAlgorithm mgf1HashAlgorithm1,
                              IHashAlgorithm mgf1HashAlgorithm2,
                              AsymmetricKeyParameter publicKey,
                              byte[] dataBuffer,
                              int offset,
                              int length)
        {
            if (publicKey == null)
            {
                throw new ArgumentNullException(nameof(publicKey));
            }
            if (dataBuffer == null)
            {
                throw new ArgumentNullException(nameof(dataBuffer));
            }
            if (publicKey.IsPrivate)
            {
                throw new CryptoException("Must be a asymmetric public key.");
            }
            IAsymmetricBlockCipher encryptor = GenerateEncryptor(padding, mgf1HashAlgorithm1, mgf1HashAlgorithm2, publicKey);
            return encryptor.ProcessBlock(dataBuffer, offset, length);
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
            if (privateKey == null)
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
            if (publicKey == null)
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
        /// Generate Asymmetric key pair.
        /// <para/>Uses key size 768 bits, certainty 20 by default.
        /// </summary>
        /// <returns></returns>
        public override AsymmetricCipherKeyPair GenerateKeyPair()
        {
            return GenerateKeyPair(768, 20);
        }

        /// <summary>
        /// Generate Asymmetric key pair.
        /// <para/>Uses certainty 20 by default.
        /// </summary>
        /// <param name="keySize">Key size bits.
        /// <para/>Legal key size is more than or equal to 8 bits (8 bits increments).
        /// </param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        public AsymmetricCipherKeyPair GenerateKeyPair(int keySize)
        {
            return GenerateKeyPair(keySize, 20);
        }

        /// <summary>
        /// Generate Asymmetric key pair.
        /// </summary>
        /// <param name="keySize">Key size bits.
        /// <para/>Legal key size is more than or equal to 8 bits (8 bits increments).
        /// </param>
        /// <param name="certainty">Certainty.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        public AsymmetricCipherKeyPair GenerateKeyPair(int keySize, int certainty)
        {
            if (keySize < 8 || keySize > 2147483640 || keySize % 8 != 0)
            {
                throw new CryptographicException("Legal key size is more than or equal to 8 bits (8 bits increments).");
            }
            ElGamalParametersGenerator parametersGenerator = new ElGamalParametersGenerator();
            parametersGenerator.Init(keySize, certainty, Common.SecureRandom);
            ElGamalParameters parameters = parametersGenerator.GenerateParameters();
            ElGamalKeyGenerationParameters generationParameters = new ElGamalKeyGenerationParameters(Common.SecureRandom, parameters);
            ElGamalKeyPairGenerator keyPairGenerator = new ElGamalKeyPairGenerator();
            keyPairGenerator.Init(generationParameters);
            return keyPairGenerator.GenerateKeyPair();
        }

        private IAsymmetricBlockCipher GenerateCipher(bool encryption,
                                                      AsymmetricPaddingMode padding,
                                                      IHashAlgorithm mgf1HashAlgorithm1,
                                                      IHashAlgorithm mgf1HashAlgorithm2,
                                                      AsymmetricKeyParameter asymmetricKey)
        {
            IAsymmetricBlockCipher cipher = new ElGamalEngine();
            switch (padding)
            {
                case AsymmetricPaddingMode.PKCS1: cipher = new Pkcs1Encoding(cipher); break;
                case AsymmetricPaddingMode.OAEP:
                    if (mgf1HashAlgorithm1 == null)
                    {
                        cipher = new OaepEncoding(cipher);
                    }
                    else if (mgf1HashAlgorithm2 == null)
                    {
                        cipher = new OaepEncoding(cipher, mgf1HashAlgorithm1.GenerateDigest());
                    }
                    else
                    {
                        cipher = new OaepEncoding(cipher, mgf1HashAlgorithm1.GenerateDigest(), mgf1HashAlgorithm2.GenerateDigest(), null);
                    }
                    break;

                case AsymmetricPaddingMode.NoPadding: break;
                case AsymmetricPaddingMode.ISO9796_1: throw new CryptographicException("Unsupported padding mode.");
                default: throw new CryptographicException("Unsupported padding mode.");
            }
            cipher.Init(encryption, asymmetricKey);
            return cipher;
        }
    }
}