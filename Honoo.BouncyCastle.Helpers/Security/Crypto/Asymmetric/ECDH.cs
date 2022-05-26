using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using System;
using System.Collections.Generic;

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
        public ECDH() : base("ECDH", AsymmetricAlgorithmKind.Neither)
        {
        }

        #endregion Constructor

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
        /// Generate ECDH terminal Alice.
        /// <para/>Uses key size 256 bits, certainty 20 by default.
        /// </summary>
        /// <returns></returns>
        public IECDHTerminalA GenerateTerminalA()
        {
            return GenerateTerminalA(256, 20);
        }

        /// <summary>
        /// Generate ECDH terminal Alice.
        /// </summary>
        /// <param name="keySize">Key size.
        /// <para/>Can be Prime192v1, SecP224r1, Prime239v1, Prime256v1, SecP384r1, SecP521r1.
        /// </param>
        /// <param name="certainty">Certainty.</param>
        /// <returns></returns>
        public IECDHTerminalA GenerateTerminalA(int keySize, int certainty)
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
            //
            List<byte> exchange = new List<byte>();
            SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(keyPair.Public);
            byte[] publicKeyBytes = publicKeyInfo.GetEncoded();
            exchange.AddRange(BitConverter.GetBytes(publicKeyBytes.Length));
            exchange.AddRange(publicKeyBytes);
            byte[] pBytes = parameters.P.ToByteArray();
            exchange.AddRange(BitConverter.GetBytes(pBytes.Length));
            exchange.AddRange(pBytes);
            byte[] gBytes = parameters.G.ToByteArray();
            exchange.AddRange(BitConverter.GetBytes(gBytes.Length));
            exchange.AddRange(gBytes);
            //
            return new ECDHTerminalA(agreement, exchange.ToArray());
        }

        /// <summary>
        /// Generate ECDH terminal Bob.
        /// </summary>
        /// <param name="exchangeA">Terminal Alice's exchange.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        public IECDHTerminalB GenerateTerminalB(byte[] exchangeA)
        {
            if (exchangeA is null)
            {
                throw new ArgumentNullException(nameof(exchangeA));
            }
            int index = 0;
            int length = BitConverter.ToInt32(exchangeA, index);
            index += 4;
            byte[] publicKeyBytes = new byte[length];
            Buffer.BlockCopy(exchangeA, index, publicKeyBytes, 0, length);
            index += length;
            length = BitConverter.ToInt32(exchangeA, index);
            index += 4;
            byte[] pBytes = new byte[length];
            Buffer.BlockCopy(exchangeA, index, pBytes, 0, length);
            index += length;
            length = BitConverter.ToInt32(exchangeA, index);
            index += 4;
            byte[] gBytes = new byte[length];
            Buffer.BlockCopy(exchangeA, index, gBytes, 0, length);
            //
            AsymmetricKeyParameter publicKey = PublicKeyFactory.CreateKey(publicKeyBytes);
            DHParameters parameters = new DHParameters(new BigInteger(pBytes), new BigInteger(gBytes));
            ECKeyPairGenerator generator = new ECKeyPairGenerator("ECDH");
            DHKeyGenerationParameters generationParameters = new DHKeyGenerationParameters(Common.SecureRandom, parameters);
            generator.Init(generationParameters);
            AsymmetricCipherKeyPair keyPair = generator.GenerateKeyPair();
            ECDHBasicAgreement agreement = new ECDHBasicAgreement();
            agreement.Init(keyPair.Private);
            //
            SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(keyPair.Public);
            //
            return new ECDHTerminalB(agreement, publicKeyInfo.GetEncoded(), publicKey);
        }
    }
}