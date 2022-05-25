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
    /// <para/>Legal key size is more than or equal to 256 bits (64 bits increments).
    /// <para/>Uses key size 768 bits, certainty 20 by default.
    /// </summary>
    public sealed class ElGamal : AsymmetricEncryptionAlgorithm
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
        /// ElGamal.
        /// <para/>Legal key size is more than or equal to 256 bits (64 bits increments).
        /// <para/>Uses key size 768 bits, certainty 20 by default.
        /// </summary>
        public ElGamal() : this(768, 20)
        {
        }

        /// <summary>
        /// ElGamal.
        /// <para/>Legal key size is more than or equal to 256 bits (64 bits increments).
        /// <para/>Uses key size 768 bits, certainty 20 by default.
        /// </summary>
        /// <param name="keySize">Key size bits.</param>
        public ElGamal(int keySize) : this(keySize, 20)
        {
        }

        /// <summary>
        /// ElGamal.
        /// <para/>Legal key size is more than or equal to 256 bits (64 bits increments).
        /// <para/>Uses key size 768 bits, certainty 20 by default.
        /// </summary>
        /// <param name="keySize">Key size bits.</param>
        /// <param name="certainty">Certainty.</param>
        public ElGamal(int keySize, int certainty) : base("ElGamal")
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
        public override IAsymmetricBlockCipher GenerateCipher(AsymmetricPaddingMode padding, AsymmetricKeyParameter asymmetricKey)
        {
            if (padding == AsymmetricPaddingMode.ISO9796_1)
            {
                throw new CryptographicException("ISO9796_1 padding mode does not support ElGamal.");
            }
            IAsymmetricBlockCipher cipher = new ElGamalEngine();
            switch (padding)
            {
                case AsymmetricPaddingMode.NoPadding: break;
                case AsymmetricPaddingMode.PKCS1: cipher = new Pkcs1Encoding(cipher); break;
                case AsymmetricPaddingMode.OAEP: cipher = new OaepEncoding(cipher); break;
                case AsymmetricPaddingMode.ISO9796_1: break;
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
            ElGamalParametersGenerator generator2 = new ElGamalParametersGenerator();
            generator2.Init(_keySize, _certainty, Common.ThreadSecureRandom.Value);
            ElGamalParameters parameters2 = generator2.GenerateParameters();
            KeyGenerationParameters parameters = new ElGamalKeyGenerationParameters(Common.ThreadSecureRandom.Value, parameters2);
            IAsymmetricCipherKeyPairGenerator generator = new ElGamalKeyPairGenerator();
            generator.Init(parameters);
            return generator.GenerateKeyPair();
        }
    }
}