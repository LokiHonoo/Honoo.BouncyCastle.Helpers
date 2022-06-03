using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.Diagnostics.CodeAnalysis;

namespace Honoo.BouncyCastle.Helpers.Security.Crypto.Asymmetric
{
    /// <summary>
    /// GOST3410.
    /// <para/>Legal key size 512, 1024 bits.
    /// </summary>
    public sealed class GOST3410 : AsymmetricSignatureAlgorithm
    {
        #region Constructor

        /// <summary>
        /// GOST3410.
        /// <para/>Legal key size 512, 1024 bits.
        /// </summary>
        public GOST3410() : base("GOST3410", AsymmetricAlgorithmKind.Signature)
        {
        }

        #endregion Constructor

        /// <summary>
        /// Generate Asymmetric key pair.
        /// <para/>Uses key size 1024 bits, procedure 2 by default.
        /// </summary>
        /// <returns></returns>
        public override AsymmetricCipherKeyPair GenerateKeyPair()
        {
            return GenerateKeyPair(1024, 2);
        }

        /// <summary>
        /// Generate Asymmetric key pair.
        /// </summary>
        /// <param name="keySize">Key size bits.</param>
        /// <param name="procedure">Procedure.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        [SuppressMessage("Performance", "CA1822:将成员标记为 static", Justification = "<挂起>")]
        public AsymmetricCipherKeyPair GenerateKeyPair(int keySize, int procedure)
        {
            Gost3410ParametersGenerator parametersGenerator = new Gost3410ParametersGenerator();
            parametersGenerator.Init(keySize, procedure, Common.SecureRandom);
            Gost3410Parameters parameters = parametersGenerator.GenerateParameters();
            Gost3410KeyGenerationParameters generationParameters = new Gost3410KeyGenerationParameters(Common.SecureRandom, parameters);
            Gost3410KeyPairGenerator keyPairGenerator = new Gost3410KeyPairGenerator();
            keyPairGenerator.Init(generationParameters);
            return keyPairGenerator.GenerateKeyPair();
        }
    }
}