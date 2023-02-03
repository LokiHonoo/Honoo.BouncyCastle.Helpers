using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using System;

namespace Honoo.BouncyCastle.Helpers.Security.Crypto.Asymmetric
{
    /// <summary>
    /// ECDiffieHellman terminal Bob.
    /// </summary>
    public sealed class ECDHTerminalB : IEquatable<ECDHTerminalB>, IECDHTerminalB
    {
        #region Properties

        private readonly ECDHBasicAgreement _agreement;
        private readonly byte[] _exchangeB;
        private readonly AsymmetricKeyParameter _publicKeyA;

        /// <summary>
        /// Exchange this bytes to terminal Alice.
        /// </summary>
        public byte[] ExchangeB => _exchangeB;

        #endregion Properties

        #region Constructor

        /// <summary>
        /// ECDiffieHellman terminal Bob.
        /// </summary>
        /// <param name="exchangeA">Terminal Alice's exchange.</param>
        /// <exception cref="ArgumentNullException"></exception>
        public ECDHTerminalB(byte[] exchangeA)
        {
            if (exchangeA == null)
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
            AsymmetricKeyParameter publicKeyA = PublicKeyFactory.CreateKey(publicKeyBytes);
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
            _agreement = agreement;
            _exchangeB = publicKeyInfo.GetEncoded();
            _publicKeyA = publicKeyA;
        }

        #endregion Constructor

        /// <summary>
        /// Derive key material.
        /// </summary>
        /// <param name="unsigned">Output unsigned bytes.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        public byte[] DeriveKeyMaterial(bool unsigned)
        {
            BigInteger integer = _agreement.CalculateAgreement(_publicKeyA);
            return unsigned ? integer.ToByteArrayUnsigned() : integer.ToByteArray();
        }

        /// <summary>
        /// Determines whether the specified object is equal to the current.
        /// </summary>
        /// <param name="other"></param>
        /// <returns></returns>
        public bool Equals(ECDHTerminalB other)
        {
            return _agreement.Equals(other._agreement) & _exchangeB.Equals(other._exchangeB);
        }

        /// <summary>
        /// Determines whether the specified object is equal to the current.
        /// </summary>
        /// <param name="obj"></param>
        /// <returns></returns>
        public override bool Equals(object obj)
        {
            return Equals((ECDHTerminalB)obj);
        }

        /// <summary>
        /// Returns the hash code for this object.
        /// </summary>
        /// <returns></returns>
        public override int GetHashCode()
        {
            return _agreement.GetHashCode() ^ _exchangeB.GetHashCode();
        }
    }
}