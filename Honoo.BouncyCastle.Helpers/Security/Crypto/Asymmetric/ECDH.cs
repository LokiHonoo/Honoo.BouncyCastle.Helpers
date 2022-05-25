using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using System;
using System.Diagnostics.CodeAnalysis;

namespace Honoo.BouncyCastle.Helpers.Security.Crypto.Asymmetric
{
    /// <summary>
    /// ECDH.
    /// </summary>
    public sealed class ECDH : AsymmetricAlgorithm
    {
        #region Constructor

        /// <summary>
        /// ECDH.
        /// </summary>
        public ECDH() : base("ECDH")
        {
        }

        #endregion Constructor

        /// <summary>
        /// Generate agreement.
        /// </summary>
        /// <param name="privateKey">Asymmetric private key.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        [SuppressMessage("Performance", "CA1822:将成员标记为 static", Justification = "<挂起>")]
        public IBasicAgreement GenerateAgreement(AsymmetricKeyParameter privateKey)
        {
            //IBasicAgreement agreement = AgreementUtilities.GetBasicAgreement("ECDH");
            ECDHBasicAgreement agreement = new ECDHBasicAgreement();
            agreement.Init(privateKey);
            return agreement;
        }


        /// <summary>
        /// Derive key material from the other asymmetric public key.
        /// </summary>
        /// <param name="agreement">Agreement.</param>
        /// <param name="otherPublicKey">The other asymmetric public key.</param>
        /// <returns></returns>
        public byte[] DeriveKeyMaterial(IBasicAgreement agreement, AsymmetricKeyParameter otherPublicKey)
        {
            AsymmetricKeyParameter publicKey = PublicKeyFactory.CreateKey(publicKeyBytes);
            return agreement.CalculateAgreement(otherPublicKey).ToByteArrayUnsigned(); 
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
        /// <returns></returns>
        /// <exception cref="Exception"/>
        [SuppressMessage("Performance", "CA1822:将成员标记为 static", Justification = "<挂起>")]
        public AsymmetricCipherKeyPair GenerateKeyPair(DHParameters parameters)
        {
            //IAsymmetricCipherKeyPairGenerator generator = GeneratorUtilities.GetKeyPairGenerator("ECDH");
            DHKeyPairGenerator generator = new DHKeyPairGenerator();
            DHKeyGenerationParameters generationParameters = new DHKeyGenerationParameters(Common.ThreadSecureRandom.Value, parameters);
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
        [SuppressMessage("Performance", "CA1822:将成员标记为 static", Justification = "<挂起>")]
        public DHParameters GenerateParametersA(int keySize, int certainty)
        {
            DHParametersGenerator generator = new DHParametersGenerator();
            generator.Init(keySize, certainty, Common.ThreadSecureRandom.Value);
            return generator.GenerateParameters();
        }

        /// <summary>
        /// Generate parameters Bob.
        /// </summary>
        /// <param name="aP">ParametersA P.</param>
        /// <param name="aG">ParametersA G.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        [SuppressMessage("Performance", "CA1822:将成员标记为 static", Justification = "<挂起>")]
        public DHParameters GenerateParametersB(BigInteger aP, BigInteger aG)
        {
            return new DHParameters(aP, aG);
        }
    }
}