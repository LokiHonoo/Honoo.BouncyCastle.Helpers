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
    public sealed class ECDHTerminalB : IECDHTerminalB
    {
        #region Properties

        private readonly ECDHBasicAgreement _agreement;
        private readonly byte[] _publicKey;
        private readonly AsymmetricKeyParameter _publicKeyA;

        /// <summary>
        /// Exchange this bytes to terminal Alice.
        /// </summary>
        public byte[] PublicKey => _publicKey;

        #endregion Properties

        #region Construction

        /// <summary>
        /// ECDiffieHellman terminal Bob.
        /// </summary>
        /// <param name="pA">Terminal Alice's P value.</param>
        /// <param name="gA">Terminal Alice's G value.</param>
        /// <param name="publicKeyA">Terminal Alice's public key.</param>
        /// <exception cref="ArgumentNullException"></exception>
        public ECDHTerminalB(byte[] pA, byte[] gA, byte[] publicKeyA)
        {
            if (pA == null)
            {
                throw new ArgumentNullException(nameof(pA));
            }
            if (gA == null)
            {
                throw new ArgumentNullException(nameof(gA));
            }
            if (publicKeyA == null)
            {
                throw new ArgumentNullException(nameof(publicKeyA));
            }
            //
            AsymmetricKeyParameter publicKeyAlice = PublicKeyFactory.CreateKey(publicKeyA);
            DHParameters parameters = new DHParameters(new BigInteger(pA), new BigInteger(gA));
            ECKeyPairGenerator generator = new ECKeyPairGenerator("ECDH");
            DHKeyGenerationParameters generationParameters = new DHKeyGenerationParameters(Common.SecureRandom, parameters);
            generator.Init(generationParameters);
            AsymmetricCipherKeyPair keyPair = generator.GenerateKeyPair();
            ECDHBasicAgreement agreement = new ECDHBasicAgreement();
            agreement.Init(keyPair.Private);
            //
            SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(keyPair.Public);
            _publicKey = publicKeyInfo.GetEncoded();
            _publicKeyA = publicKeyAlice;
            _agreement = agreement;
        }

        #endregion Construction

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
    }
}