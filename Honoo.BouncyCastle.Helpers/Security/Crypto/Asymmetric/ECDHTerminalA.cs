using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using System;
using System.Security.Cryptography;

namespace Honoo.BouncyCastle.Helpers.Security.Crypto.Asymmetric
{
    /// <summary>
    /// ECDiffieHellman terminal Alice.
    /// </summary>
    public sealed class ECDHTerminalA : IEquatable<ECDHTerminalA>, IECDHTerminalA
    {
        #region Properties

        private readonly ECDHBasicAgreement _agreement;
        private readonly byte[] _g;
        private readonly byte[] _p;
        private readonly byte[] _publicKey;

        /// <summary>
        /// Exchange this bytes to terminal Bob.
        /// </summary>
        public byte[] G => _g;

        /// <summary>
        /// Exchange this bytes to terminal Bob.
        /// </summary>
        public byte[] P => _p;

        /// <summary>
        /// Exchange this bytes to terminal Bob.
        /// </summary>
        public byte[] PublicKey => _publicKey;

        #endregion Properties

        #region Construction

        /// <summary>
        /// ECDiffieHellman terminal Alice.
        /// <para/>Uses certainty 20 by default.
        /// </summary>
        /// <param name="keySize">Key size.
        /// <para/>Can be Prime192v1, SecP224r1, Prime239v1, Prime256v1, SecP384r1, SecP521r1.
        /// </param>
        /// <exception cref="Exception"/>
        public ECDHTerminalA(int keySize) : this(keySize, 20)
        {
        }

        /// <summary>
        /// ECDiffieHellman terminal Alice.
        /// </summary>
        /// <param name="keySize">Key size.
        /// <para/>Can be Prime192v1, SecP224r1, Prime239v1, Prime256v1, SecP384r1, SecP521r1.
        /// </param>
        /// <param name="certainty">Certainty.</param>
        /// <exception cref="Exception"/>
        public ECDHTerminalA(int keySize, int certainty)
        {
            if (keySize != 192 && keySize != 224 && keySize != 239 && keySize != 256 && keySize != 384 && keySize != 521)
            {
                throw new CryptographicException("Legal key size 192, 224, 239, 256, 384, 521.");
            }
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
            SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(keyPair.Public);
            _publicKey = publicKeyInfo.GetEncoded();
            _p = parameters.P.ToByteArray();
            _g = parameters.G.ToByteArray();
            //
            _agreement = agreement;
        }

        #endregion Construction

        /// <summary>
        /// Derive key material from the terminal Bob's exchange.
        /// </summary>
        /// <param name="publicKeyB">The terminal Bob's public key.</param>
        /// <param name="unsigned">Output unsigned bytes.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        public byte[] DeriveKeyMaterial(byte[] publicKeyB, bool unsigned)
        {
            if (publicKeyB == null)
            {
                throw new ArgumentNullException(nameof(publicKeyB));
            }
            AsymmetricKeyParameter publicKeyBob = PublicKeyFactory.CreateKey(publicKeyB);
            BigInteger integer = _agreement.CalculateAgreement(publicKeyBob);
            return unsigned ? integer.ToByteArrayUnsigned() : integer.ToByteArray();
        }

        /// <summary>
        /// Determines whether the specified object is equal to the current.
        /// </summary>
        /// <param name="other"></param>
        /// <returns></returns>
        public bool Equals(ECDHTerminalA other)
        {
            return _agreement.Equals(
                other._agreement)
                & _publicKey.Equals(other._publicKey)
                & _p.Equals(other._p)
                & _g.Equals(other._g);
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
        /// Returns the hash code for this object.
        /// </summary>
        /// <returns></returns>
        public override int GetHashCode()
        {
            return _agreement.GetHashCode() ^ _publicKey.GetHashCode() ^ _p.GetHashCode() ^ _g.GetHashCode();
        }
    }
}