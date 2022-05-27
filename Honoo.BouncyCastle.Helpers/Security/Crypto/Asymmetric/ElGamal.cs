using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
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
    /// </summary>
    public sealed class ElGamal : AsymmetricEncryptionAlgorithm
    {
        #region Constructor

        /// <summary>
        /// ElGamal.
        /// <para/>Legal key size is more than or equal to 256 bits (64 bits increments).
        /// </summary>
        public ElGamal() : base("ElGamal", AsymmetricAlgorithmKind.Encryption)
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

        /// <summary>
        ///
        /// </summary>
        /// <param name="padding"></param>
        /// <returns></returns>
        /// <exception cref="CryptographicException"></exception>
        protected override IAsymmetricBlockCipher GenerateCipherCore(AsymmetricPaddingMode padding, OAEPMGF1PaddingMode mgfPadding1, OAEPMGF1PaddingMode mgfPadding2)
        {
            IAsymmetricBlockCipher cipher = new ElGamalEngine();
            switch (padding)
            {
                case AsymmetricPaddingMode.PKCS1: cipher = new Pkcs1Encoding(cipher); break;
                case AsymmetricPaddingMode.OAEP:
                    IDigest digest1;
                    IDigest digest2;
                    switch (mgfPadding1)
                    {
                        case OAEPMGF1PaddingMode.MD5: digest1 = new MD5Digest(); break;
                        case OAEPMGF1PaddingMode.SHA1: digest1 = new Sha1Digest(); break;
                        case OAEPMGF1PaddingMode.SHA224: digest1 = new Sha224Digest(); break;
                        case OAEPMGF1PaddingMode.SHA256: digest1 = new Sha256Digest(); break;
                        case OAEPMGF1PaddingMode.SHA384: digest1 = new Sha384Digest(); break;
                        case OAEPMGF1PaddingMode.SHA512: digest1 = new Sha512Digest(); break;
                        case OAEPMGF1PaddingMode.None:
                        default: digest1 = null; break;
                    }
                    switch (mgfPadding2)
                    {
                        case OAEPMGF1PaddingMode.MD5: digest2 = new MD5Digest(); break;
                        case OAEPMGF1PaddingMode.SHA1: digest2 = new Sha1Digest(); break;
                        case OAEPMGF1PaddingMode.SHA224: digest2 = new Sha224Digest(); break;
                        case OAEPMGF1PaddingMode.SHA256: digest2 = new Sha256Digest(); break;
                        case OAEPMGF1PaddingMode.SHA384: digest2 = new Sha384Digest(); break;
                        case OAEPMGF1PaddingMode.SHA512: digest2 = new Sha512Digest(); break;
                        case OAEPMGF1PaddingMode.None:
                        default: digest2 = null; break;
                    }
                    if (digest1 is null)
                    {
                        cipher = new OaepEncoding(cipher);
                    }
                    else if (digest2 is null)
                    {
                        cipher = new OaepEncoding(cipher, digest1);
                    }
                    else
                    {
                        cipher = new OaepEncoding(cipher, digest1, digest2, null);
                    }
                    break;

                case AsymmetricPaddingMode.NoPadding: break;
                case AsymmetricPaddingMode.ISO9796_1: throw new CryptographicException("ISO9796_1 padding mode does not support ElGamal.");
                default: throw new CryptographicException("Unsupported padding mode.");
            }
            return cipher;
        }
    }
}