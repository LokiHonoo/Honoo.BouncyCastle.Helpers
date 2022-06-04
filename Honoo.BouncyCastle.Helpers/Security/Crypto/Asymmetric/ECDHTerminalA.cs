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
    /// ECDiffieHellman terminal Alice.
    /// </summary>
    public sealed class ECDHTerminalA : IEquatable<ECDHTerminalA>, IECDHTerminalA
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
        /// <param name="size">Size.
        /// <para/>Can be Prime192v1, SecP224r1, Prime239v1, Prime256v1, SecP384r1, SecP521r1.
        /// </param>
        /// <param name="certainty">Certainty.</param>
        public ECDHTerminalA(int size, int certainty)
        {
            DHParametersGenerator parametersGenerator = new DHParametersGenerator();
            parametersGenerator.Init(size, certainty, Common.SecureRandom);
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
        /// <param name="unsigned">Output unsigned bytes.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        public byte[] DeriveKeyMaterial(byte[] exchangeB, bool unsigned)
        {
            if (exchangeB is null)
            {
                throw new ArgumentNullException(nameof(exchangeB));
            }
            AsymmetricKeyParameter publicKeyB = PublicKeyFactory.CreateKey(exchangeB);
            BigInteger integer = _agreement.CalculateAgreement(publicKeyB);
            return unsigned ? integer.ToByteArrayUnsigned() : integer.ToByteArray();
        }

        /// <summary>
        /// Determines whether the specified object is equal to the current.
        /// </summary>
        /// <param name="other"></param>
        /// <returns></returns>
        public bool Equals(ECDHTerminalA other)
        {
            return _agreement.Equals(other._agreement) & _exchangeA.Equals(other._exchangeA);
        }

        /// <summary>
        /// Determines whether the specified object is equal to the current.
        /// </summary>
        /// <param name="obj"></param>
        /// <returns></returns>
        public override bool Equals(object obj)
        {
            return Equals((ECDHTerminalA)obj);
        }

        /// <summary>
        ///
        /// </summary>
        /// <returns></returns>
        public override int GetHashCode()
        {
            return _agreement.GetHashCode() ^ _exchangeA.GetHashCode();
        }
    }
}