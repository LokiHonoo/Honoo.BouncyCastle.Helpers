using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using System;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;

namespace Honoo.BouncyCastle.Helpers.Security.Crypto.Asymmetric
{
    /// <summary>
    /// RSA.
    /// <para/>Legal key size is more than or equal to 512 bits (64 bits increments).
    /// </summary>
    public sealed class RSA : AsymmetricEncryptionAlgorithm
    {
        #region Constructor

        /// <summary>
        /// RSA.
        /// <para/>Legal key size is more than or equal to 512 bits (64 bits increments).
        /// </summary>
        public RSA() : base("RSA", AsymmetricAlgorithmKind.Both)
        {
        }

        #endregion Constructor

        /// <summary>
        /// Generate Asymmetric key pair.
        /// <para/>Uses key size 2048 bits, certainty 25 by default.
        /// </summary>
        /// <returns></returns>
        public override AsymmetricCipherKeyPair GenerateKeyPair()
        {
            return GenerateKeyPair(2048, 25);
        }

        /// <summary>
        /// Generate Asymmetric key pair.
        /// </summary>
        /// <param name="keySize">Key size.</param>
        /// <param name="certainty">Certainty.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        [SuppressMessage("Performance", "CA1822:将成员标记为 static", Justification = "<挂起>")]
        public AsymmetricCipherKeyPair GenerateKeyPair(int keySize, int certainty)
        {
            RsaKeyGenerationParameters parameters = new RsaKeyGenerationParameters(BigInteger.ValueOf(0x10001), Common.SecureRandom, keySize, certainty);
            RsaKeyPairGenerator generator = new RsaKeyPairGenerator();
            generator.Init(parameters);
            return generator.GenerateKeyPair();
        }

        /// <summary>
        ///
        /// </summary>
        /// <param name="padding"></param>
        /// <param name="mgf1HashAlgorithm1"></param>
        /// <param name="mgf1HashAlgorithm2"></param>
        /// <returns></returns>
        /// <exception cref="CryptographicException"></exception>
        protected override IAsymmetricBlockCipher GenerateCipherCore(AsymmetricPaddingMode padding,
                                                                     IHashAlgorithm mgf1HashAlgorithm1,
                                                                     IHashAlgorithm mgf1HashAlgorithm2)
        {
            IAsymmetricBlockCipher cipher = new RsaBlindedEngine();
            switch (padding)
            {
                case AsymmetricPaddingMode.PKCS1: cipher = new Pkcs1Encoding(cipher); break;
                case AsymmetricPaddingMode.OAEP:
                    if (mgf1HashAlgorithm1 is null)
                    {
                        cipher = new OaepEncoding(cipher);
                    }
                    else if (mgf1HashAlgorithm2 is null)
                    {
                        cipher = new OaepEncoding(cipher, mgf1HashAlgorithm1.GenerateDigest());
                    }
                    else
                    {
                        cipher = new OaepEncoding(cipher, mgf1HashAlgorithm1.GenerateDigest(), mgf1HashAlgorithm2.GenerateDigest(), null);
                    }
                    break;

                case AsymmetricPaddingMode.NoPadding: break;
                case AsymmetricPaddingMode.ISO9796_1: cipher = new ISO9796d1Encoding(cipher); break;
                default: throw new CryptographicException("Unsupported padding mode.");
            }
            return cipher;
        }
    }
}