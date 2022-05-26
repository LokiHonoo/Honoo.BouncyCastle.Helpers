using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.Diagnostics.CodeAnalysis;
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
        #region Constructor

        /// <summary>
        /// ElGamal.
        /// <para/>Legal key size is more than or equal to 256 bits (64 bits increments).
        /// </summary>
        public ElGamal() : base("ElGamal")
        {
        }

        #endregion Constructor

        /// <summary>
        /// Generate key pair.
        /// <para/>Uses key size 768 bits, certainty 20 by default.
        /// </summary>
        /// <returns></returns>
        public override AsymmetricCipherKeyPair GenerateKeyPair()
        {
            return GenerateKeyPair(768, 20);
        }

        /// <summary>
        /// Generate key pair.
        /// </summary>
        /// <param name="keySize">Key size.</param>
        /// <param name="certainty">Certainty.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        [SuppressMessage("Performance", "CA1822:将成员标记为 static", Justification = "<挂起>")]
        public AsymmetricCipherKeyPair GenerateKeyPair(int keySize, int certainty)
        {
            ElGamalParametersGenerator parametersGenerator = new ElGamalParametersGenerator();
            parametersGenerator.Init(keySize, certainty, Common.SecureRandom);
            ElGamalParameters parameters = parametersGenerator.GenerateParameters();
            ElGamalKeyGenerationParameters generationParameters = new ElGamalKeyGenerationParameters(Common.SecureRandom, parameters);
            ElGamalKeyPairGenerator keyPairGenerator = new ElGamalKeyPairGenerator();
            keyPairGenerator.Init(generationParameters);
            return keyPairGenerator.GenerateKeyPair();
        }

        protected override IAsymmetricBlockCipher GenerateCipherCore(AsymmetricPaddingMode padding)
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
            return cipher;
        }
    }
}