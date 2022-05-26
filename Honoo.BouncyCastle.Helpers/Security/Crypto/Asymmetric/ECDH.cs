using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using System;
using System.Text;

namespace Honoo.BouncyCastle.Helpers.Security.Crypto.Asymmetric
{
    /// <summary>
    /// ECDiffieHellman.
    /// </summary>
    public sealed class ECDH : AsymmetricAlgorithm, IECDH
    {
        #region Constructor

        /// <summary>
        /// ECDiffieHellman.
        /// </summary>
        public ECDH() : base("ECDH")
        {
        }

        #endregion Constructor

        /// <summary>
        /// Derive key material from the other asymmetric public key.
        /// </summary>
        /// <param name="agreement">Agreement.</param>
        /// <param name="otherPublicKey">The other asymmetric public key.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        public byte[] DeriveKeyMaterial(IBasicAgreement agreement, AsymmetricKeyParameter otherPublicKey)
        {
            return agreement.CalculateAgreement(otherPublicKey).ToByteArrayUnsigned();
        }

        /// <summary>
        /// Generate agreement.
        /// </summary>
        /// <param name="privateKey">Asymmetric private key.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        public IBasicAgreement GenerateAgreement(AsymmetricKeyParameter privateKey)
        {
            ECDHBasicAgreement agreement = new ECDHBasicAgreement();
            agreement.Init(privateKey);
            return agreement;
        }

        /// <summary>
        /// Generate key pair. NOT Implemented.
        /// </summary>
        /// <returns></returns>
        /// <exception cref="NotImplementedException"/>
        public override AsymmetricCipherKeyPair GenerateKeyPair()
        {
            throw new NotImplementedException();
        }

        /// <summary>
        /// Generate key pair.
        /// </summary>
        /// <param name="parameters"></param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        public AsymmetricCipherKeyPair GenerateKeyPair(DHParameters parameters)
        {
            if (parameters is null)
            {
                throw new ArgumentNullException(nameof(parameters));
            }
            ECKeyPairGenerator generator = new ECKeyPairGenerator("ECDH");
            DHKeyGenerationParameters generationParameters = new DHKeyGenerationParameters(Common.SecureRandom, parameters);
            generator.Init(generationParameters);
            return generator.GenerateKeyPair();
        }

        /// <summary>
        /// Generate parameters Alice.
        /// <para/>Uses key size 256 bits, certainty 25 by default.
        /// </summary>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        public DHParameters GenerateParametersA()
        {
            return GenerateParametersA(256, 25);
        }

        /// <summary>
        /// Generate parameters.
        /// </summary>
        /// <param name="keySize">Key size.</param>
        /// <param name="certainty">Certainty.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        public DHParameters GenerateParametersA(int keySize, int certainty)
        {
            DHParametersGenerator generator = new DHParametersGenerator();
            generator.Init(keySize, certainty, Common.SecureRandom);
            return generator.GenerateParameters();
        }

        /// <summary>
        /// Generate parameters Bob.
        /// </summary>
        /// <param name="ParametersAP">ParametersA P.</param>
        /// <param name="ParametersAG">ParametersA G.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        public DHParameters GenerateParametersB(BigInteger ParametersAP, BigInteger ParametersAG)
        {
            return new DHParameters(ParametersAP, ParametersAG);
        }

        /// <summary>
        /// Generate ECDH terminal Alice.
        /// </summary>
        /// <param name="keySize">
        /// <para/>Can be Prime192v1, SecP224r1, Prime239v1, Prime256v1, SecP384r1, SecP521r1.
        /// </param>
        /// <param name="certainty">Certainty.</param>
        /// <returns></returns>
        public ECDHTerminal GenerateTerminalA(int keySize, int certainty)
        {
            DHParametersGenerator parametersGenerator = new DHParametersGenerator();
            parametersGenerator.Init(keySize, certainty, Common.SecureRandom);
            DHParameters parameters = parametersGenerator.GenerateParameters();
            ECKeyPairGenerator keyPairGenerator = new ECKeyPairGenerator("ECDH");
            DHKeyGenerationParameters generationParameters = new DHKeyGenerationParameters(Common.SecureRandom, parameters);
            keyPairGenerator.Init(generationParameters);
            AsymmetricCipherKeyPair keyPair = keyPairGenerator.GenerateKeyPair();
            ECDHBasicAgreement agreement = new ECDHBasicAgreement();
            agreement.Init(keyPair.Private);
            StringBuilder sb = new StringBuilder();
            sb.Append(PemHelper.KeyToPem(keyPair.Public));
            sb.Append("<DIVIDE>");
            sb.Append(parameters.P.ToString());
            sb.Append("<DIVIDE>");
            sb.Append(parameters.G.ToString());
            byte[] exchange = Encoding.UTF8.GetBytes(sb.ToString());
            return new ECDHTerminal(agreement, exchange);
        }
    }
}