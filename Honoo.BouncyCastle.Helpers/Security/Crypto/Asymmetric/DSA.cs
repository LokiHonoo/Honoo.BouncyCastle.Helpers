using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.Security.Cryptography;

namespace Honoo.BouncyCastle.Helpers.Security.Crypto.Asymmetric
{
    /// <summary>
    /// DSA.
    /// <para/>Legal key size 512-1024 bits (64 bits increments).
    /// </summary>
    public sealed class DSA : AsymmetricAlgorithm
    {
        #region Construction

        /// <summary>
        /// DSA.
        /// <para/>Legal key size 512-1024 bits (64 bits increments).
        /// </summary>
        public DSA() : base("DSA", X9ObjectIdentifiers.IdDsa, AsymmetricAlgorithmKind.Signature)
        {
        }

        #endregion Construction

        /// <summary>
        /// Generate Asymmetric key pair.
        /// <para/>Uses key size 1024 bits, certainty 80 by default.
        /// </summary>
        /// <returns></returns>
        public override AsymmetricCipherKeyPair GenerateKeyPair()
        {
            return GenerateKeyPair(1024, 80);
        }

        /// <summary>
        /// Generate Asymmetric key pair.
        /// <para/>Uses certainty 80 by default.
        /// </summary>
        /// <param name="keySize">Key size bits.
        /// <para/>Legal key size 512-1024 bits (64 bits increments).
        /// </param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        public AsymmetricCipherKeyPair GenerateKeyPair(int keySize)
        {
            return GenerateKeyPair(keySize, 80);
        }

        /// <summary>
        /// Generate Asymmetric key pair.
        /// </summary>
        /// <param name="keySize">Key size bits.
        /// <para/>Legal key size 512-1024 bits (64 bits increments).
        /// </param>
        /// <param name="certainty">Certainty.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        public AsymmetricCipherKeyPair GenerateKeyPair(int keySize, int certainty)
        {
            if (keySize < 512 || keySize > 1024 || keySize % 64 != 0)
            {
                throw new CryptographicException("Legal key size 512-1024 bits (64 bits increments).");
            }
            DsaParametersGenerator parametersGenerator = new DsaParametersGenerator();
            parametersGenerator.Init(keySize, certainty, Common.SecureRandom);
            DsaParameters parameters = parametersGenerator.GenerateParameters();
            DsaKeyGenerationParameters generationParameters = new DsaKeyGenerationParameters(Common.SecureRandom, parameters);
            DsaKeyPairGenerator keyPairGenerator = new DsaKeyPairGenerator();
            keyPairGenerator.Init(generationParameters);
            return keyPairGenerator.GenerateKeyPair();
        }
    }
}