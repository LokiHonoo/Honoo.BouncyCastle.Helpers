using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using System;
using System.Collections.Generic;

namespace Honoo.BouncyCastle.Helpers.Security.Crypto.Asymmetric
{
    /// <summary>
    /// ECDiffieHellman terminal Alice.
    /// </summary>
    public sealed class ECDHTerminalA : IECDHTerminalA
    {
        #region Properties

        private readonly ECDHBasicAgreement _agreement;
        private readonly byte[] _exchangeA;

        /// <summary>
        /// Exchange this bytes to terminal Bob.
        /// </summary>
        public byte[] ExchangeA => _exchangeA;

        #endregion Properties

        #region Constructor

        /// <summary>
        /// ECDiffieHellman terminal Alice.
        /// </summary>
        /// <param name="keySize">Key size.
        /// <para/>Can be Prime192v1, SecP224r1, Prime239v1, Prime256v1, SecP384r1, SecP521r1.
        /// </param>
        /// <param name="certainty">Certainty.</param>
        public ECDHTerminalA(int keySize, int certainty)
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
            _agreement = agreement;
            _exchangeA = exchange.ToArray();
        }

        #endregion Constructor

        /// <summary>
        /// Derive key material from the terminal Bob's exchange.
        /// </summary>
        /// <param name="exchangeB">The terminal Bob's exchange.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        public byte[] DeriveKeyMaterial(byte[] exchangeB)
        {
            if (exchangeB is null)
            {
                throw new ArgumentNullException(nameof(exchangeB));
            }
            AsymmetricKeyParameter publicKey = PublicKeyFactory.CreateKey(exchangeB);
            return _agreement.CalculateAgreement(publicKey).ToByteArray();
        }
    }
}