using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.Diagnostics.CodeAnalysis;

namespace Honoo.BouncyCastle.Helpers.Security.Crypto.Asymmetric
{
    /// <summary>
    /// DSA.
    /// <para/>Legal key size 512-1024 bits (64 bits increments).
    /// </summary>
    public sealed class DSA : AsymmetricSignatureAlgorithm
    {
        #region Constructor

        /// <summary>
        /// DSA.
        /// <para/>Legal key size 512-1024 bits (64 bits increments).
        /// </summary>
        public DSA() : base("DSA", AsymmetricAlgorithmKind.Signature)
        {
        }

        #endregion Constructor

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
        /// </summary>
        /// <param name="keySize">Key size.</param>
        /// <param name="certainty">Certainty.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        [SuppressMessage("Performance", "CA1822:将成员标记为 static", Justification = "<挂起>")]
        public AsymmetricCipherKeyPair GenerateKeyPair(int keySize, int certainty)
        {
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