﻿using Honoo.BouncyCastle.Helpers.Utilities;
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

namespace Honoo.BouncyCastle.Helpers
{
    /// <summary>
    /// Using the BouncyCastle implementation of the algorithm.
    /// </summary>
    public sealed class ECDH : AsymmetricAlgorithm, IKeyExchangeTerminalA, IKeyExchangeTerminalB
    {
        #region Properties

        private const int DEFAULT_CERTAINTY = 20;
        private const int DEFAULT_KEY_SIZE = 521;
        private const string NAME = "ECDH";

        private static readonly KeySizes[] LEGAL_KEY_SIZES = new KeySizes[]
        {
            new KeySizes(192, 224, 32),
            new KeySizes(239, 239, 0),
            new KeySizes(256, 384, 128),
            new KeySizes(521, 521, 0)
        };

        private ECDHBasicAgreement _agreementA;
        private ECDHBasicAgreement _agreementB;
        private DHParameters _dhParameterA;
        private int _keySize = DEFAULT_KEY_SIZE;
        private BigInteger _pmsB;
        private AsymmetricKeyParameter _publicKeyA;
        private AsymmetricKeyParameter _publicKeyB;

        /// <inheritdoc/>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Performance", "CA1819:属性不应返回数组", Justification = "<挂起>")]
        public byte[] G
        {
            get
            {
                InspectParameters();
                return _dhParameterA.G.ToByteArray();
            }
        }

        /// <inheritdoc/>
        public int KeySize => _keySize;

        /// <inheritdoc/>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Performance", "CA1819:属性不应返回数组", Justification = "<挂起>")]
        public KeySizes[] LegalKeySizes => (KeySizes[])LEGAL_KEY_SIZES.Clone();

        /// <inheritdoc/>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Performance", "CA1819:属性不应返回数组", Justification = "<挂起>")]
        public byte[] P
        {
            get
            {
                InspectParameters();
                return _dhParameterA.P.ToByteArray();
            }
        }

        /// <inheritdoc/>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Performance", "CA1819:属性不应返回数组", Justification = "<挂起>")]
        public byte[] PublicKeyA
        {
            get
            {
                InspectParameters();
                SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(_publicKeyA);
                return publicKeyInfo.GetEncoded();
            }
        }

        /// <inheritdoc/>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Performance", "CA1819:属性不应返回数组", Justification = "<挂起>")]
        public byte[] PublicKeyB
        {
            get
            {
                InspectParameters();
                SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(_publicKeyB);
                return publicKeyInfo.GetEncoded();
            }
        }

        #endregion Properties

        #region Construction

        /// <summary>
        /// Initializes a new instance of the ECDH class.
        /// </summary>
        public ECDH() : base(NAME, AsymmetricAlgorithmKind.KeyExchange)
        {
        }

        #endregion Construction

        #region Interfaces

        /// <summary>
        /// Gets key exchange algorithm terminal A's interface.
        /// </summary>
        /// <returns></returns>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1024:在适用处使用属性", Justification = "<挂起>")]
        public IKeyExchangeTerminalA GetTerminalA()
        {
            return this;
        }

        /// <summary>
        /// Gets key exchange algorithm terminal B's interface.
        /// </summary>
        /// <returns></returns>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1024:在适用处使用属性", Justification = "<挂起>")]
        public IKeyExchangeTerminalB GetTerminalB()
        {
            return this;
        }

        #endregion Interfaces

        #region GenerateParameters

        /// <summary>
        /// Generate new parameters of algorithm terminal A.
        /// </summary>
        public override void GenerateParameters()
        {
            GenerateParameters(DEFAULT_KEY_SIZE, DEFAULT_CERTAINTY);
        }

        /// <inheritdoc/>
        public void GenerateParameters(int keySize = 521, int certainty = 20)
        {
            if (!ValidKeySize(keySize, out string exception))
            {
                throw new CryptographicException(exception);
            }
            if (certainty <= 0)
            {
                throw new CryptographicException("Legal certainty is more than 0.");
            }
            DHParametersGenerator parametersGenerator = new DHParametersGenerator();
            parametersGenerator.Init(keySize, certainty, Common.SecureRandom.Value);
            DHParameters parameters = parametersGenerator.GenerateParameters();
            ECKeyPairGenerator keyPairGenerator = new ECKeyPairGenerator("ECDH");
            DHKeyGenerationParameters generationParameters = new DHKeyGenerationParameters(Common.SecureRandom.Value, parameters);
            keyPairGenerator.Init(generationParameters);
            AsymmetricCipherKeyPair keyPair = keyPairGenerator.GenerateKeyPair();
            _agreementA = new ECDHBasicAgreement();
            _agreementA.Init(keyPair.Private);
            _dhParameterA = parameters;
            _publicKeyA = keyPair.Public;
            _keySize = keySize;
            //
            _agreementB = null;
            _publicKeyB = null;
            _pmsB = null;
            //
            base.Initialized = true;
        }

        /// <inheritdoc/>
        public void GenerateParameters(byte[] p, byte[] g, byte[] publicKeyA)
        {
            AsymmetricKeyParameter publicKeyAlice = PublicKeyFactory.CreateKey(publicKeyA);
            DHParameters parameters = new DHParameters(new BigInteger(p), new BigInteger(g));
            ECKeyPairGenerator generator = new ECKeyPairGenerator("ECDH");
            DHKeyGenerationParameters generationParameters = new DHKeyGenerationParameters(Common.SecureRandom.Value, parameters);
            generator.Init(generationParameters);
            AsymmetricCipherKeyPair keyPair = generator.GenerateKeyPair();
            _agreementB = new ECDHBasicAgreement();
            _agreementB.Init(keyPair.Private);
            _publicKeyB = keyPair.Public;
            _pmsB = _agreementB.CalculateAgreement(publicKeyAlice);
            _keySize = ((ECPublicKeyParameters)keyPair.Public).Parameters.Curve.FieldSize;
            //
            _agreementA = null;
            _dhParameterA = null;
            _publicKeyA = null;
            //
            base.Initialized = true;
        }

        #endregion GenerateParameters

        #region Derive

        /// <inheritdoc/>
        public byte[] DeriveKeyMaterial(bool unsignedMaterial)
        {
            return unsignedMaterial ? _pmsB.ToByteArrayUnsigned() : _pmsB.ToByteArray();
        }

        /// <inheritdoc/>
        public byte[] DeriveKeyMaterial(byte[] publicKeyB, bool unsignedMaterial)
        {
            AsymmetricKeyParameter publicKeyBob = PublicKeyFactory.CreateKey(publicKeyB);
            BigInteger pmsA = _agreementA.CalculateAgreement(publicKeyBob);
            return unsignedMaterial ? pmsA.ToByteArrayUnsigned() : pmsA.ToByteArray();
        }

        #endregion Derive

        #region Export/Import Parameters

        /// <summary>
        /// Imports a byte array that represents asymmetric algorithm key information. Always throw <see cref="NotImplementedException"/>.
        /// </summary>
        /// <param name="keyInfo">A byte buffer that represents an asymmetric algorithm key.</param>
        public override void ImportKeyInfo(byte[] keyInfo)
        {
            throw new NotImplementedException();
        }

        /// <summary>
        /// Imports a byte array that represents encrypted asymmetric algorithm key information. Always throw <see cref="NotImplementedException"/>.
        /// </summary>
        /// <param name="privateKeyInfo">A byte buffer that represents an encrypted asymmetric algorithm private key.</param>
        /// <param name="password">Using decrypt private key.</param>
        public override void ImportKeyInfo(byte[] privateKeyInfo, string password)
        {
            throw new NotImplementedException();
        }

        /// <summary>
        /// Imports a <see cref="AsymmetricCipherKeyPair"/> that represents asymmetric algorithm key pair information. Always throw <see cref="NotImplementedException"/>.
        /// </summary>
        /// <param name="keyPair">A <see cref="AsymmetricCipherKeyPair"/> that represents an asymmetric algorithm key pair.</param>
        public override void ImportParameters(AsymmetricCipherKeyPair keyPair)
        {
            throw new NotImplementedException();
        }

        /// <summary>
        /// Imports a <see cref="AsymmetricKeyParameter"/> that represents asymmetric algorithm key information. Always throw <see cref="NotImplementedException"/>.
        /// </summary>
        /// <param name="asymmetricKey">A <see cref="AsymmetricKeyParameter"/> that represents an asymmetric algorithm key.</param>
        public override void ImportParameters(AsymmetricKeyParameter asymmetricKey)
        {
            throw new NotImplementedException();
        }

        /// <summary>
        /// Imports a pem string that represents asymmetric algorithm private key information. Always throw <see cref="NotImplementedException"/>.
        /// </summary>
        /// <param name="keyPem">A pem string that represents an asymmetric algorithm private key.</param>
        public override void ImportPem(string keyPem)
        {
            throw new NotImplementedException();
        }

        /// <summary>
        /// Imports a pem string that represents encrypted asymmetric algorithm private key information. Always throw <see cref="NotImplementedException"/>.
        /// </summary>
        /// <param name="privateKeyPem">A pem string that represents an encrypted asymmetric algorithm private private key.</param>
        /// <param name="password">Using decrypt private key.</param>
        public override void ImportPem(string privateKeyPem, string password)
        {
            throw new NotImplementedException();
        }

        #endregion Export/Import Parameters

        /// <summary>
        /// Creates an instance of the algorithm.
        /// </summary>
        /// <returns></returns>
        public static ECDH Create()
        {
            return new ECDH();
        }

        /// <inheritdoc/>
        public bool ValidKeySize(int keySize, out string exception)
        {
            if (DetectionUtilities.ValidSize(LEGAL_KEY_SIZES, keySize))
            {
                exception = string.Empty;
                return true;
            }
            else
            {
                exception = "Legal key size 192, 224, 239, 256, 384, 521.";
                return false;
            }
        }

        internal static AsymmetricAlgorithmName GetAlgorithmName()
        {
            return new AsymmetricAlgorithmName(NAME, AsymmetricAlgorithmKind.KeyExchange, () => { return new ECDH(); });
        }
    }
}