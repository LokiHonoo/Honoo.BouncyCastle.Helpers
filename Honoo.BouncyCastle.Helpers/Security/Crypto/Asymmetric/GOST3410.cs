using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.CryptoPro;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.Security.Cryptography;

namespace Honoo.BouncyCastle.Helpers.Security.Crypto.Asymmetric
{
    /// <summary>
    /// GOST3410.
    /// <para/>Legal key size 512, 1024 bits.
    /// </summary>
    public sealed class GOST3410 : AsymmetricAlgorithm
    {
        #region Construction

        /// <summary>
        /// GOST3410.
        /// <para/>Legal key size 512, 1024 bits.
        /// </summary>
        public GOST3410() : base("GOST3410", CryptoProObjectIdentifiers.GostR3410x94, AsymmetricAlgorithmKind.Signature)
        {
        }

        #endregion Construction

        /// <summary>
        /// Generate Asymmetric key pair.
        /// </summary>
        /// <returns></returns>
        public override AsymmetricCipherKeyPair GenerateKeyPair()
        {
            return GenerateKeyPair(GOST3410CryptoPro.GostR3410x94CryptoProA);
        }

        /// <summary>
        /// Generate Asymmetric key pair.
        /// </summary>
        /// <param name="cryptoPro">Elliptic curve to be uesd.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        public AsymmetricCipherKeyPair GenerateKeyPair(GOST3410CryptoPro cryptoPro)
        {
            //
            // Gost3410ParametersGenerator with key size created key pair con't be save to pkcs8.
            //
            //Gost3410ParametersGenerator parametersGenerator = new Gost3410ParametersGenerator();
            //parametersGenerator.Init(keySize, procedure, Common.SecureRandom);
            //Gost3410Parameters parameters = parametersGenerator.GenerateParameters();
            //Gost3410KeyGenerationParameters generationParameters = new Gost3410KeyGenerationParameters(Common.SecureRandom, parameters);

            var generationParameters = new Gost3410KeyGenerationParameters(Common.SecureRandom, GetCryptoPro(cryptoPro));
            Gost3410KeyPairGenerator keyPairGenerator = new Gost3410KeyPairGenerator();
            keyPairGenerator.Init(generationParameters);
            return keyPairGenerator.GenerateKeyPair();
        }

        private static DerObjectIdentifier GetCryptoPro(GOST3410CryptoPro cryptoPro)
        {
            switch (cryptoPro)
            {
                case GOST3410CryptoPro.GostR3410x94CryptoProA: return CryptoProObjectIdentifiers.GostR3410x94CryptoProA;
                case GOST3410CryptoPro.GostR3410x94CryptoProB: return CryptoProObjectIdentifiers.GostR3410x94CryptoProB;
                case GOST3410CryptoPro.GostR3410x94CryptoProXchA: return CryptoProObjectIdentifiers.GostR3410x94CryptoProXchA;
                default: throw new CryptographicException("Unsupported crypto pro.");
            }
        }
    }
}