using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using System;
using System.IO;
using System.Security.Cryptography;

namespace Honoo.BouncyCastle.Helpers
{
    /// <summary>
    /// Represents the abstract base class from which all implementations of asymmetric algorithms must inherit.
    /// </summary>
    public abstract class AsymmetricAlgorithm : IAsymmetricAlgorithm
    {
        #region Properties

        private readonly AsymmetricAlgorithmKind _kind;
        private readonly string _name;
        private bool _initialized;
        private AsymmetricKeyParameter _privateKey;
        private AsymmetricKeyParameter _publicKey;

        /// <inheritdoc/>
        public AsymmetricAlgorithmKind Kind => _kind;

        /// <inheritdoc/>
        public string Name => _name;

        /// <summary>
        /// Initialized.
        /// </summary>
        protected bool Initialized { get => _initialized; set => _initialized = value; }

        /// <summary>
        /// PrivateKey.
        /// </summary>
        protected AsymmetricKeyParameter PrivateKey { get => _privateKey; set => _privateKey = value; }

        /// <summary>
        /// PublicKey.
        /// </summary>
        protected AsymmetricKeyParameter PublicKey { get => _publicKey; set => _publicKey = value; }

        #endregion Properties

        #region Construction

        /// <summary>
        /// Initializes a new instance of the AsymmetricAlgorithm class.
        /// </summary>
        /// <param name="name"></param>
        /// <param name="kind"></param>
        protected AsymmetricAlgorithm(string name, AsymmetricAlgorithmKind kind)
        {
            _name = name;
            _kind = kind;
        }

        #endregion Construction

        #region Export/Import Parameters

        /// <inheritdoc/>
        public byte[] ExportKeyInfo(bool includePrivate)
        {
            InspectParameters();
            if (includePrivate)
            {
                PrivateKeyInfo privateKeyInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(_privateKey);
                return privateKeyInfo.GetEncoded();
            }
            else
            {
                SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(_publicKey);
                return publicKeyInfo.GetEncoded();
            }
        }

        /// <inheritdoc/>
        public byte[] ExportKeyInfo(PBEAlgorithmName pbeAlgorithmName, string password)
        {
            if (pbeAlgorithmName == null)
            {
                throw new ArgumentNullException(nameof(pbeAlgorithmName));
            }
            if (string.IsNullOrWhiteSpace(password))
            {
                throw new ArgumentException($"“{nameof(password)}”can't be null or blank.", nameof(password));
            }
            InspectParameters();
            byte[] salt = new byte[16];
            Common.SecureRandom.Value.NextBytes(salt);
            EncryptedPrivateKeyInfo enc = EncryptedPrivateKeyInfoFactory.CreateEncryptedPrivateKeyInfo(
                pbeAlgorithmName.Oid, password.ToCharArray(), salt, 2048, _privateKey);
            return enc.GetEncoded();
        }

        /// <inheritdoc/>
        public AsymmetricCipherKeyPair ExportParameters()
        {
            InspectParameters();
            return new AsymmetricCipherKeyPair(_publicKey, _privateKey);
        }

        /// <inheritdoc/>
        public AsymmetricKeyParameter ExportParameters(bool privateKey)
        {
            InspectParameters();
            return privateKey ? _privateKey : _publicKey;
        }

        /// <inheritdoc/>
        public string ExportPem(bool includePrivate)
        {
            InspectParameters();
            AsymmetricKeyParameter asymmetricKey = includePrivate ? _privateKey : _publicKey;
            using (StringWriter writer = new StringWriter())
            {
                PemWriter pemWriter = new PemWriter(writer);
                pemWriter.WriteObject(asymmetricKey);
                return writer.ToString();
            }
        }

        /// <inheritdoc/>
        public string ExportPem(DEKAlgorithmName dekAlgorithmName, string password)
        {
            if (dekAlgorithmName == null)
            {
                throw new ArgumentNullException(nameof(dekAlgorithmName));
            }
            if (string.IsNullOrWhiteSpace(password))
            {
                throw new ArgumentException($"“{nameof(password)}”can't be null or blank.", nameof(password));
            }
            InspectParameters();
            using (StringWriter writer = new StringWriter())
            {
                PemWriter pemWriter = new PemWriter(writer);
                pemWriter.WriteObject(_privateKey, dekAlgorithmName.Name, password.ToCharArray(), Common.SecureRandom.Value);
                return writer.ToString();
            }
        }

        /// <inheritdoc/>
        public abstract void ImportKeyInfo(byte[] keyInfo);

        /// <inheritdoc/>
        public abstract void ImportKeyInfo(byte[] privateKeyInfo, string password);

        /// <inheritdoc/>
        public abstract void ImportParameters(AsymmetricCipherKeyPair keyPair);

        /// <inheritdoc/>
        public abstract void ImportParameters(AsymmetricKeyParameter asymmetricKey);

        /// <inheritdoc/>
        public abstract void ImportPem(string keyPem);

        /// <inheritdoc/>
        public abstract void ImportPem(string privateKeyPem, string password);

        #endregion Export/Import Parameters

        /// <summary>
        /// Creates an instance of the algorithm by algorithm name.
        /// </summary>
        /// <param name="algorithmName">Asymmetric algorithm name.</param>
        /// <returns></returns>
        public static AsymmetricAlgorithm Create(AsymmetricAlgorithmName algorithmName)
        {
            if (algorithmName == null)
            {
                throw new ArgumentNullException(nameof(algorithmName));
            }
            return algorithmName.GetAlgorithm();
        }

        /// <summary>
        /// Creates an instance of the algorithm by algorithm name.
        /// </summary>
        /// <param name="mechanism">Asymmetric algorithm name.</param>
        /// <returns></returns>
        public static AsymmetricAlgorithm Create(string mechanism)
        {
            if (string.IsNullOrWhiteSpace(mechanism))
            {
                throw new ArgumentNullException(nameof(mechanism));
            }
            if (AsymmetricAlgorithmName.TryGetAlgorithmName(mechanism, out AsymmetricAlgorithmName algorithmName))
            {
                return algorithmName.GetAlgorithm();
            }
            return null;
        }

        /// <summary>
        /// Creates an instance of the algorithm by algorithm name.
        /// </summary>
        /// <param name="algorithmName">Signature algorithm name.</param>
        /// <returns></returns>
        public static ISignatureAlgorithm Create(SignatureAlgorithmName algorithmName)
        {
            if (algorithmName == null)
            {
                throw new ArgumentNullException(nameof(algorithmName));
            }
            return (ISignatureAlgorithm)algorithmName.GetAlgorithm();
        }

        /// <summary>
        /// Creates an instance of the algorithm by asymmetric algorithm key pair.
        /// </summary>
        /// <param name="keyPair">A <see cref="AsymmetricCipherKeyPair"/> that represents an asymmetric algorithm key pair.</param>
        /// <returns></returns>
        public static AsymmetricAlgorithm CreateBy(AsymmetricCipherKeyPair keyPair)
        {
            if (keyPair == null)
            {
                throw new ArgumentNullException(nameof(keyPair));
            }
            AsymmetricAlgorithm algorithm;
            switch (keyPair.Private)
            {
                case DsaPrivateKeyParameters _: algorithm = AsymmetricAlgorithmName.DSA.GetAlgorithm(); break;
                case ECPrivateKeyParameters _: algorithm = AsymmetricAlgorithmName.ECDSA.GetAlgorithm(); break;
                case Ed25519PrivateKeyParameters _: algorithm = AsymmetricAlgorithmName.Ed25519.GetAlgorithm(); break;
                case Ed448PrivateKeyParameters _: algorithm = AsymmetricAlgorithmName.Ed448.GetAlgorithm(); break;
                case ElGamalPrivateKeyParameters _: algorithm = AsymmetricAlgorithmName.ElGamal.GetAlgorithm(); break;
                case Gost3410PrivateKeyParameters _: algorithm = AsymmetricAlgorithmName.GOST3410.GetAlgorithm(); break;
                case RsaPrivateCrtKeyParameters _: algorithm = AsymmetricAlgorithmName.RSA.GetAlgorithm(); break;
                default: throw new CryptographicException("Unsupported asymmetric algorithm key pair.");
            }
            algorithm.ImportParameters(keyPair);
            return algorithm;
        }

        /// <summary>
        /// Creates an instance of the algorithm by asymmetric algorithm key information.
        /// <para/>Create public key automatically if imports key is a private key.
        /// </summary>
        /// <param name="asymmetricKey">A <see cref="AsymmetricKeyParameter"/> that represents an asymmetric algorithm key.</param>
        /// <returns></returns>
        public static AsymmetricAlgorithm CreateBy(AsymmetricKeyParameter asymmetricKey)
        {
            if (asymmetricKey == null)
            {
                throw new ArgumentNullException(nameof(asymmetricKey));
            }
            AsymmetricAlgorithm algorithm;
            if (asymmetricKey.IsPrivate)
            {
                switch (asymmetricKey)
                {
                    case DsaPrivateKeyParameters _: algorithm = AsymmetricAlgorithmName.DSA.GetAlgorithm(); break;
                    case ECPrivateKeyParameters _: algorithm = AsymmetricAlgorithmName.ECDSA.GetAlgorithm(); break;
                    case Ed25519PrivateKeyParameters _: algorithm = AsymmetricAlgorithmName.Ed25519.GetAlgorithm(); break;
                    case Ed448PrivateKeyParameters _: algorithm = AsymmetricAlgorithmName.Ed448.GetAlgorithm(); break;
                    case ElGamalPrivateKeyParameters _: algorithm = AsymmetricAlgorithmName.ElGamal.GetAlgorithm(); break;
                    case Gost3410PrivateKeyParameters _: algorithm = AsymmetricAlgorithmName.GOST3410.GetAlgorithm(); break;
                    case RsaPrivateCrtKeyParameters _: algorithm = AsymmetricAlgorithmName.RSA.GetAlgorithm(); break;
                    default: throw new CryptographicException("Unsupported asymmetric algorithm key information.");
                }
            }
            else
            {
                switch (asymmetricKey)
                {
                    case DsaPublicKeyParameters _: algorithm = AsymmetricAlgorithmName.DSA.GetAlgorithm(); break;
                    case ECPublicKeyParameters _: algorithm = AsymmetricAlgorithmName.ECDSA.GetAlgorithm(); break;
                    case Ed25519PublicKeyParameters _: algorithm = AsymmetricAlgorithmName.Ed25519.GetAlgorithm(); break;
                    case Ed448PublicKeyParameters _: algorithm = AsymmetricAlgorithmName.Ed448.GetAlgorithm(); break;
                    case ElGamalPublicKeyParameters _: algorithm = AsymmetricAlgorithmName.ElGamal.GetAlgorithm(); break;
                    case Gost3410PublicKeyParameters _: algorithm = AsymmetricAlgorithmName.GOST3410.GetAlgorithm(); break;
                    case RsaKeyParameters _: algorithm = AsymmetricAlgorithmName.RSA.GetAlgorithm(); break;
                    default: throw new CryptographicException("Unsupported asymmetric algorithm key information.");
                }
            }
            algorithm.ImportParameters(asymmetricKey);
            return algorithm;
        }

        /// <summary>
        /// Creates an instance of the algorithm by pem string that represents asymmetric algorithm key information.
        /// <para/>Create public key automatically if imports key is a private key.
        /// </summary>
        /// <param name="keyPem">A pem string that represents an asymmetric algorithm key.</param>
        /// <returns></returns>
        public static AsymmetricAlgorithm CreateBy(string keyPem)
        {
            using (StringReader reader = new StringReader(keyPem))
            {
                object obj = new PemReader(reader).ReadObject();
                if (obj.GetType() == typeof(AsymmetricCipherKeyPair))
                {
                    return CreateBy((AsymmetricCipherKeyPair)obj);
                }
                else
                {
                    return CreateBy((AsymmetricKeyParameter)obj);
                }
            }
        }

        /// <summary>
        /// Creates an instance of the algorithm by pem string that represents asymmetric algorithm key information. The public key is created automatically.
        /// </summary>
        /// <param name="privateKeyPem">A pem string that represents an encrypted asymmetric algorithm private key.</param>
        /// <param name="password">Using decrypt private key.</param>
        /// <returns></returns>
        public static AsymmetricAlgorithm CreateBy(string privateKeyPem, string password)
        {
            if (string.IsNullOrWhiteSpace(privateKeyPem))
            {
                throw new ArgumentException($"“{nameof(privateKeyPem)}”can't be null or blank.", nameof(privateKeyPem));
            }
            if (string.IsNullOrWhiteSpace(password))
            {
                throw new ArgumentException($"“{nameof(password)}”can't be null or blank.", nameof(password));
            }
            using (StringReader reader = new StringReader(privateKeyPem))
            {
                object obj = new PemReader(reader, new Password(password)).ReadObject();
                return CreateBy((AsymmetricCipherKeyPair)obj);
            }
        }

        /// <summary>
        /// Creates an instance of the algorithm by byte array that represents encrypted asymmetric algorithm key information.
        /// <para/>Create public key automatically if imports key is a private key.
        /// </summary>
        /// <param name="keyInfo">A byte buffer that represents an asymmetric algorithm key.</param>
        /// <returns></returns>
        public static AsymmetricAlgorithm CreateBy(byte[] keyInfo)
        {
            Asn1Object asn1 = Asn1Object.FromByteArray(keyInfo);
            try
            {
                PrivateKeyInfo priInfo = PrivateKeyInfo.GetInstance(asn1);
                AsymmetricKeyParameter privateKey = PrivateKeyFactory.CreateKey(priInfo);
                return CreateBy(privateKey);
            }
            catch
            {
                try
                {
                    SubjectPublicKeyInfo pubInfo = SubjectPublicKeyInfo.GetInstance(asn1);
                    AsymmetricKeyParameter publicKey = PublicKeyFactory.CreateKey(pubInfo);
                    return CreateBy(publicKey);
                }
                catch
                {
                    throw new CryptographicException("Unsupported asymmetric algorithm key information.");
                }
            }
        }

        /// <summary>
        /// Creates an instance of the algorithm by byte array that represents encrypted asymmetric algorithm key information. The public key is created automatically.
        /// </summary>
        /// <param name="privateKeyInfo">A byte buffer that represents an encrypted asymmetric algorithm private key.</param>
        /// <param name="password">Using decrypt private key.</param>
        /// <returns></returns>
        public static AsymmetricAlgorithm CreateBy(byte[] privateKeyInfo, string password)
        {
            if (privateKeyInfo == null)
            {
                throw new ArgumentNullException(nameof(privateKeyInfo));
            }
            if (string.IsNullOrWhiteSpace(password))
            {
                throw new ArgumentException($"“{nameof(password)}”can't be null or blank.", nameof(password));
            }
            Asn1Object asn1 = Asn1Object.FromByteArray(privateKeyInfo);
            EncryptedPrivateKeyInfo enc = EncryptedPrivateKeyInfo.GetInstance(asn1);
            PrivateKeyInfo priInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(password.ToCharArray(), enc);
            AsymmetricKeyParameter privateKey = PrivateKeyFactory.CreateKey(priInfo);
            return CreateBy(privateKey);
        }

        /// <inheritdoc/>
        public abstract void GenerateParameters();

        /// <summary></summary>
        protected void InspectParameters()
        {
            if (!_initialized)
            {
                GenerateParameters();
            }
        }
    }
}