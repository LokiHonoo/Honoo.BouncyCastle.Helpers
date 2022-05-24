using Honoo.BouncyCastle.Helpers.Security.Crypto.Hash;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using System;
using System.Security.Cryptography;

namespace Honoo.BouncyCastle.Helpers.Security.Crypto.Asymmetric
{
    /// <summary>
    /// RSA.
    /// <para/>Legal key size is more than or equal to 512 bits (64 bits increments).
    /// <para/>Uses key size 2048 bits, certainty 25 by default.
    /// </summary>
    public sealed class RSA : AsymmetricAlgorithm, IAsymmetricEncryptionAlgorithm
    {
        #region Properties

        private readonly int _certainty;
        private readonly int _keySize;

        /// <summary>
        /// Certainty.
        /// </summary>
        public int Certainty => _certainty;

        /// <summary>
        /// Key size.
        /// </summary>
        public int KeySize => _keySize;

        #endregion Properties

        #region Constructor

        /// <summary>
        /// RSA.
        /// <para/>Legal key size is more than or equal to 512 bits (64 bits increments).
        /// <para/>Uses key size 2048 bits, certainty 25 by default.
        /// <para/>Legal signature hash Algorithm:
        /// <see cref="MD2"/>,<see cref="MD4"/>,<see cref="MD5"/>,
        /// <see cref="SHA1"/>,<see cref="SHA224"/>,<see cref="SHA256"/>,<see cref="SHA384"/>,<see cref="SHA512"/>,
        /// <see cref="RIPEMD128"/>,<see cref="RIPEMD160"/>,<see cref="RIPEMD256"/>.
        /// </summary>
        public RSA() : this(2048, 25)
        {
        }

        /// <summary>
        /// RSA.
        /// <para/>Legal key size is more than or equal to 512 bits (64 bits increments).
        /// <para/>Uses key size 2048 bits, certainty 25 by default.
        /// <para/>Legal signature hash Algorithm:
        /// <see cref="MD2"/>,<see cref="MD4"/>,<see cref="MD5"/>,
        /// <see cref="SHA1"/>,<see cref="SHA224"/>,<see cref="SHA256"/>,<see cref="SHA384"/>,<see cref="SHA512"/>,
        /// <see cref="RIPEMD128"/>,<see cref="RIPEMD160"/>,<see cref="RIPEMD256"/>.
        /// </summary>
        /// <param name="keySize">Key size bits.</param>
        public RSA(int keySize) : this(keySize, 25)
        {
        }

        /// <summary>
        /// RSA.
        /// <para/>Legal key size is more than or equal to 512 bits (64 bits increments).
        /// <para/>Uses key size 2048 bits, certainty 25 by default.
        /// <para/>Legal signature hash Algorithm:
        /// <see cref="MD2"/>,<see cref="MD4"/>,<see cref="MD5"/>,
        /// <see cref="SHA1"/>,<see cref="SHA224"/>,<see cref="SHA256"/>,<see cref="SHA384"/>,<see cref="SHA512"/>,
        /// <see cref="RIPEMD128"/>,<see cref="RIPEMD160"/>,<see cref="RIPEMD256"/>.
        /// </summary>
        /// <param name="keySize">Key size bits.</param>
        /// <param name="certainty">Certainty.</param>
        public RSA(int keySize, int certainty) : base("RSA")
        {
            _keySize = keySize;
            _certainty = certainty;
        }

        #endregion Constructor

        /// <summary>
        /// Generate cipher. The cipher can be reused.
        /// </summary>
        /// <param name="padding">Asymmetric algorithm padding mode.</param>
        /// <param name="asymmetricKey">Asymmetric public key or private key.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        public IAsymmetricBlockCipher GenerateCipher(AsymmetricPaddingMode padding, AsymmetricKeyParameter asymmetricKey)
        {
            IAsymmetricBlockCipher cipher = new RsaBlindedEngine();
            switch (padding)
            {
                case AsymmetricPaddingMode.NoPadding: break;
                case AsymmetricPaddingMode.PKCS1: cipher = new Pkcs1Encoding(cipher); break;
                case AsymmetricPaddingMode.OAEP: cipher = new OaepEncoding(cipher); break;
                case AsymmetricPaddingMode.ISO9796_1: cipher = new ISO9796d1Encoding(cipher); break;
                default: throw new CryptographicException("Unsupported padding mode.");
            }
            cipher.Init(!asymmetricKey.IsPrivate, asymmetricKey);
            return cipher;
        }

        /// <summary>
        /// Generate key pair.
        /// </summary>
        /// <returns></returns>
        public override AsymmetricCipherKeyPair GenerateKeyPair()
        {
            KeyGenerationParameters parameters = new RsaKeyGenerationParameters(BigInteger.ValueOf(0x10001), Common.ThreadSecureRandom.Value, _keySize, _certainty);
            IAsymmetricCipherKeyPairGenerator generator = new RsaKeyPairGenerator();
            generator.Init(parameters);
            return generator.GenerateKeyPair();
        }

        /// <summary>
        /// Generate key pair.
        /// </summary>
        /// <param name="dotNET">Extract from .NET RSA key pool.</param>
        /// <returns></returns>
        public AsymmetricCipherKeyPair GenerateKeyPair(bool dotNET)
        {
            if (dotNET)
            {
                using (System.Security.Cryptography.RSACryptoServiceProvider rsa = new System.Security.Cryptography.RSACryptoServiceProvider(_keySize))
                {
                    return DotNetUtilities.GetRsaKeyPair(rsa);
                }
            }
            else
            {
                return GenerateKeyPair();
            }
        }
    }
}