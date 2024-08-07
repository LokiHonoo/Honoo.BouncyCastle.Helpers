﻿using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using System;
using System.IO;
using System.Security.Cryptography;

namespace Honoo.BouncyCastle.Helpers
{
    /// <summary>
    /// Using the BouncyCastle implementation of the algorithm.
    /// </summary>
    public sealed class Ed448 : AsymmetricAlgorithm, ISignatureAlgorithm
    {
        #region Properties

        private const string NAME = "Ed448";
        private readonly byte[] _context;
        private Ed448SignatureInstance _signatureInstance = Ed448SignatureInstance.Ed448;
        private ISigner _signer;
        private ISigner _verifier;

        /// <summary>
        /// Ed448 not need hash algorithm. It's null always.
        /// </summary>
        public HashAlgorithmName HashAlgorithmName
        { get => null; set { } }

        /// <inheritdoc/>
        public SignatureAlgorithmName SignatureAlgorithmName => GetSignatureAlgorithmName(_signatureInstance);

        /// <summary>
        /// Represents the signature EdDSA instance (RFC-8032) used in the symmetric algorithm.
        /// </summary>
        public Ed448SignatureInstance SignatureInstance
        {
            get => _signatureInstance;
            set
            {
                if (value != _signatureInstance)
                {
                    _signer = null;
                    _verifier = null;
                    _signatureInstance = value;
                }
            }
        }

        #endregion Properties

        #region Construction

        /// <summary>
        /// Initializes a new instance of the Ed448 class.
        /// </summary>
        /// <param name="context">Context using for signature Ed448/Ed448ph instance.</param>
        public Ed448(byte[] context = null) : base(NAME, AsymmetricAlgorithmKind.Signature)
        {
            if (context == null || context.Length == 0)
            {
                _context = Arrays.EmptyBytes;
            }
            else
            {
                _context = (byte[])context.Clone();
            }
        }

        #endregion Construction

        #region GenerateParameters

        /// <inheritdoc/>
        public override void GenerateParameters()
        {
            Ed448KeyGenerationParameters parameters = new Ed448KeyGenerationParameters(Common.SecureRandom.Value);
            Ed448KeyPairGenerator generator = new Ed448KeyPairGenerator();
            generator.Init(parameters);
            AsymmetricCipherKeyPair keyPair = generator.GenerateKeyPair();
            base.PrivateKey = keyPair.Private;
            base.PublicKey = keyPair.Public;
            _signer = null;
            _verifier = null;
            base.Initialized = true;
        }

        #endregion GenerateParameters

        #region Export/Import Parameters

        /// <inheritdoc/>
        public override void ImportKeyInfo(byte[] keyInfo)
        {
            Ed448PrivateKeyParameters privateKey = null;
            Ed448PublicKeyParameters publicKey = null;
            Asn1Object asn1 = Asn1Object.FromByteArray(keyInfo);
            try
            {
                PrivateKeyInfo priInfo = PrivateKeyInfo.GetInstance(asn1);
                privateKey = (Ed448PrivateKeyParameters)PrivateKeyFactory.CreateKey(priInfo);
                publicKey = privateKey.GeneratePublicKey();
            }
            catch
            {
                try
                {
                    SubjectPublicKeyInfo pubInfo = SubjectPublicKeyInfo.GetInstance(asn1);
                    publicKey = (Ed448PublicKeyParameters)PublicKeyFactory.CreateKey(pubInfo);
                }
                catch
                {
                }
            }
            base.PrivateKey = privateKey;
            base.PublicKey = publicKey;
            _signer = null;
            _verifier = null;
            base.Initialized = true;
        }

        /// <inheritdoc/>
        public override void ImportKeyInfo(byte[] privateKeyInfo, string password)
        {
            Asn1Object asn1 = Asn1Object.FromByteArray(privateKeyInfo);
            EncryptedPrivateKeyInfo enc = EncryptedPrivateKeyInfo.GetInstance(asn1);
            PrivateKeyInfo priInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(password.ToCharArray(), enc);
            Ed448PrivateKeyParameters privateKey = (Ed448PrivateKeyParameters)PrivateKeyFactory.CreateKey(priInfo);
            Ed448PublicKeyParameters publicKey = privateKey.GeneratePublicKey();
            base.PrivateKey = privateKey;
            base.PublicKey = publicKey;
            _signer = null;
            _verifier = null;
            base.Initialized = true;
        }

        /// <inheritdoc/>
        public override void ImportParameters(AsymmetricCipherKeyPair keyPair)
        {
            base.PrivateKey = (Ed448PrivateKeyParameters)keyPair.Private;
            base.PublicKey = (Ed448PublicKeyParameters)keyPair.Public;
            _signer = null;
            _verifier = null;
            base.Initialized = true;
        }

        /// <inheritdoc/>
        public override void ImportParameters(AsymmetricKeyParameter asymmetricKey)
        {
            Ed448PrivateKeyParameters privateKey = null;
            Ed448PublicKeyParameters publicKey;
            if (asymmetricKey.IsPrivate)
            {
                privateKey = (Ed448PrivateKeyParameters)asymmetricKey;
                publicKey = privateKey.GeneratePublicKey();
            }
            else
            {
                publicKey = (Ed448PublicKeyParameters)asymmetricKey;
            }
            base.PrivateKey = privateKey;
            base.PublicKey = publicKey;
            _signer = null;
            _verifier = null;
            base.Initialized = true;
        }

        /// <inheritdoc/>
        public override void ImportPem(string keyPem)
        {
            using (StringReader reader = new StringReader(keyPem))
            {
                Ed448PrivateKeyParameters privateKey = null;
                Ed448PublicKeyParameters publicKey;
                object obj = new PemReader(reader).ReadObject();
                if (obj.GetType() == typeof(Ed448PrivateKeyParameters))
                {
                    privateKey = (Ed448PrivateKeyParameters)obj;
                    publicKey = privateKey.GeneratePublicKey();
                }
                else
                {
                    publicKey = (Ed448PublicKeyParameters)obj;
                }
                base.PrivateKey = privateKey;
                base.PublicKey = publicKey;
                _signer = null;
                _verifier = null;
                base.Initialized = true;
            }
        }

        /// <inheritdoc/>
        public override void ImportPem(string privateKeyPem, string password)
        {
            using (StringReader reader = new StringReader(privateKeyPem))
            {
                object obj = new PemReader(reader, new Password(password)).ReadObject();
                Ed448PrivateKeyParameters privateKey = (Ed448PrivateKeyParameters)obj;
                Ed448PublicKeyParameters publicKey = privateKey.GeneratePublicKey();
                base.PrivateKey = privateKey;
                base.PublicKey = publicKey;
                _signer = null;
                _verifier = null;
                base.Initialized = true;
            }
        }

        #endregion Export/Import Parameters

        #region Signature

        /// <inheritdoc/>
        public void Reset()
        {
            _signer?.Reset();
            _verifier?.Reset();
        }

        /// <inheritdoc/>
        public byte[] SignFinal()
        {
            InspectParameters();
            InspectSigner(true);
            return _signer.GenerateSignature();
        }

        /// <inheritdoc/>
        public byte[] SignFinal(byte[] rgb)
        {
            if (rgb == null)
            {
                throw new ArgumentNullException(nameof(rgb));
            }
            SignUpdate(rgb, 0, rgb.Length);
            return SignFinal();
        }

        /// <inheritdoc/>
        public byte[] SignFinal(byte[] inputBuffer, int offset, int length)
        {
            SignUpdate(inputBuffer, offset, length);
            return SignFinal();
        }

        /// <inheritdoc/>
        public void SignUpdate(byte[] rgb)
        {
            if (rgb == null)
            {
                throw new ArgumentNullException(nameof(rgb));
            }
            SignUpdate(rgb, 0, rgb.Length);
        }

        /// <inheritdoc/>
        public void SignUpdate(byte[] inputBuffer, int offset, int length)
        {
            InspectParameters();
            InspectSigner(true);
            _signer.BlockUpdate(inputBuffer, offset, length);
        }

        /// <inheritdoc/>
        public bool VerifyFinal(byte[] signature)
        {
            InspectParameters();
            InspectSigner(false);
            return _verifier.VerifySignature(signature);
        }

        /// <inheritdoc/>
        public bool VerifyFinal(byte[] rgb, byte[] signature)
        {
            if (rgb == null)
            {
                throw new ArgumentNullException(nameof(rgb));
            }
            VerifyUpdate(rgb, 0, rgb.Length);
            return VerifyFinal(signature);
        }

        /// <inheritdoc/>
        public bool VerifyFinal(byte[] inputBuffer, int offset, int length, byte[] signature)
        {
            VerifyUpdate(inputBuffer, offset, length);
            return VerifyFinal(signature);
        }

        /// <inheritdoc/>
        public void VerifyUpdate(byte[] rgb)
        {
            if (rgb == null)
            {
                throw new ArgumentNullException(nameof(rgb));
            }
            VerifyUpdate(rgb, 0, rgb.Length);
        }

        /// <inheritdoc/>
        public void VerifyUpdate(byte[] inputBuffer, int offset, int length)
        {
            InspectParameters();
            InspectSigner(false);
            _verifier.BlockUpdate(inputBuffer, offset, length);
        }

        #endregion Signature

        /// <summary>
        /// Creates an instance of the algorithm.
        /// </summary>
        /// <param name="context">Context using for signature Ed25519ctx/Ed25519ph instance.</param>
        /// <returns></returns>
        public static Ed448 Create(byte[] context = null)
        {
            return new Ed448(context);
        }

        internal static AsymmetricAlgorithmName GetAlgorithmName()
        {
            return new AsymmetricAlgorithmName(NAME, AsymmetricAlgorithmKind.Signature, () => { return new Ed448(); });
        }

        internal static SignatureAlgorithmName GetSignatureAlgorithmName(Ed448SignatureInstance instance)
        {
            return new SignatureAlgorithmName(GetSignatureAlgorithmMechanism(instance), () => { return new Ed448() { _signatureInstance = instance }; });
        }

        private static string GetSignatureAlgorithmMechanism(Ed448SignatureInstance instance)
        {
            switch (instance)
            {
                case Ed448SignatureInstance.Ed448: return "Ed448";
                case Ed448SignatureInstance.Ed448ph: return "Ed448ph";
                default: throw new CryptographicException("Unsupported signature EdDSA instance (RFC-8032).");
            }
        }

        private void InspectSigner(bool forSigning)
        {
            if (forSigning)
            {
                if (_signer == null)
                {
                    switch (_signatureInstance)
                    {
                        case Ed448SignatureInstance.Ed448: _signer = new Ed448Signer(_context); break;
                        case Ed448SignatureInstance.Ed448ph: _signer = new Ed448phSigner(_context); break;
                        default: throw new CryptographicException("Unsupported signature EdDSA instance (RFC-8032).");
                    }
                    _signer.Init(true, base.PrivateKey);
                }
            }
            else
            {
                if (_verifier == null)
                {
                    switch (_signatureInstance)
                    {
                        case Ed448SignatureInstance.Ed448: _verifier = new Ed448Signer(_context); break;
                        case Ed448SignatureInstance.Ed448ph: _verifier = new Ed448phSigner(_context); break;
                        default: throw new CryptographicException("Unsupported signature EdDSA instance (RFC-8032).");
                    }
                    _verifier.Init(false, base.PublicKey);
                }
            }
        }
    }
}