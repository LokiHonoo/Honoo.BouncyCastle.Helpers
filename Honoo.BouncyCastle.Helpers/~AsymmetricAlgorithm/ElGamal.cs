using Honoo.BouncyCastle.Helpers.Utilities;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using System;
using System.IO;
using System.Security.Cryptography;

namespace Honoo.BouncyCastle.Helpers
{
    /// <summary>
    /// Using the BouncyCastle implementation of the algorithm.
    /// </summary>
    public sealed class ElGamal : AsymmetricAlgorithm, IAsymmetricEncryptionAlgorithm
    {
        #region Properties

        private const int DEFAULT_CERTAINTY = 20;
        private const int DEFAULT_KEY_SIZE = 768;
        private const string NAME = "ElGamal";
        private static readonly KeySizes[] LEGAL_KEY_SIZES = new KeySizes[] { new KeySizes(8, Common.IntgerMulti8Max, 8) };
        private IAsymmetricBlockCipher _decryptor;
        private IAsymmetricBlockCipher _encryptor;
        private int _keySize = DEFAULT_KEY_SIZE;
        private AsymmetricEncryptionPaddingMode _padding = AsymmetricEncryptionPaddingMode.PKCS1;

        /// <summary>
        /// Gets key size bits.
        /// </summary>
        public int KeySize => _keySize;

        /// <summary>
        /// Gets legal key size bits. Legal key size is more than or equal to 8 bits (8 bits increments).
        /// </summary>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Performance", "CA1819:属性不应返回数组", Justification = "<挂起>")]
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Performance", "CA1822:将成员标记为 static", Justification = "<挂起>")]
        public KeySizes[] LegalKeySizes => (KeySizes[])LEGAL_KEY_SIZES.Clone();

        /// <summary>
        /// Represents the encryption padding mode used in the symmetric algorithm.
        /// </summary>
        public AsymmetricEncryptionPaddingMode Padding
        {
            get => _padding;
            set
            {
                if (value != _padding)
                {
                    _encryptor = null;
                    _decryptor = null;
                    _padding = value;
                }
            }
        }

        #endregion Properties

        #region Construction

        /// <summary>
        /// Initializes a new instance of the ElGamal class.
        /// </summary>
        public ElGamal() : base(NAME, AsymmetricAlgorithmKind.Encryption)
        {
        }

        #endregion Construction

        #region GenerateParameters

        /// <inheritdoc/>
        public override void GenerateParameters()
        {
            GenerateParameters(DEFAULT_KEY_SIZE, DEFAULT_CERTAINTY);
        }

        /// <summary>
        /// Renew private key and public key of the algorithm.
        /// </summary>
        /// <param name="keySize">Legal key size is more than or equal to 8 bits (8 bits increments).</param>
        /// <param name="certainty">Legal certainty is more than 0.</param>
        public void GenerateParameters(int keySize = DEFAULT_KEY_SIZE, int certainty = DEFAULT_CERTAINTY)
        {
            if (!ValidKeySize(keySize, out string exception))
            {
                throw new CryptographicException(exception);
            }
            if (certainty <= 0)
            {
                throw new CryptographicException("Legal certainty is more than 0.");
            }
            ElGamalParametersGenerator parametersGenerator = new ElGamalParametersGenerator();
            parametersGenerator.Init(keySize, certainty, Common.SecureRandom.Value);
            ElGamalParameters parameters = parametersGenerator.GenerateParameters();
            ElGamalKeyGenerationParameters generationParameters = new ElGamalKeyGenerationParameters(Common.SecureRandom.Value, parameters);
            ElGamalKeyPairGenerator keyPairGenerator = new ElGamalKeyPairGenerator();
            keyPairGenerator.Init(generationParameters);
            AsymmetricCipherKeyPair keyPair = keyPairGenerator.GenerateKeyPair();
            base.PrivateKey = keyPair.Private;
            base.PublicKey = keyPair.Public;
            _keySize = keySize;
            _encryptor = null;
            _decryptor = null;
            base.Initialized = true;
        }

        #endregion GenerateParameters

        #region Export/Import Parameters

        /// <inheritdoc/>
        public override void ImportKeyInfo(byte[] keyInfo)
        {
            ElGamalPrivateKeyParameters privateKey = null;
            ElGamalPublicKeyParameters publicKey = null;
            Asn1Object asn1 = Asn1Object.FromByteArray(keyInfo);
            try
            {
                PrivateKeyInfo priInfo = PrivateKeyInfo.GetInstance(asn1);
                privateKey = (ElGamalPrivateKeyParameters)PrivateKeyFactory.CreateKey(priInfo);
                BigInteger y = privateKey.Parameters.G.ModPow(privateKey.X, privateKey.Parameters.P);
                publicKey = new ElGamalPublicKeyParameters(y, privateKey.Parameters);
            }
            catch
            {
                try
                {
                    SubjectPublicKeyInfo pubInfo = SubjectPublicKeyInfo.GetInstance(asn1);
                    publicKey = (ElGamalPublicKeyParameters)PublicKeyFactory.CreateKey(pubInfo);
                }
                catch
                {
                }
            }
            base.PrivateKey = privateKey;
            base.PublicKey = publicKey;
            _keySize = publicKey.Parameters.P.BitLength;
            _encryptor = null;
            _decryptor = null;
            base.Initialized = true;
        }

        /// <inheritdoc/>
        public override void ImportKeyInfo(byte[] privateKeyInfo, string password)
        {
            Asn1Object asn1 = Asn1Object.FromByteArray(privateKeyInfo);
            EncryptedPrivateKeyInfo enc = EncryptedPrivateKeyInfo.GetInstance(asn1);
            PrivateKeyInfo priInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(password.ToCharArray(), enc);
            ElGamalPrivateKeyParameters privateKey = (ElGamalPrivateKeyParameters)PrivateKeyFactory.CreateKey(priInfo);
            BigInteger y = privateKey.Parameters.G.ModPow(privateKey.X, privateKey.Parameters.P);
            ElGamalPublicKeyParameters publicKey = new ElGamalPublicKeyParameters(y, privateKey.Parameters);
            base.PrivateKey = privateKey;
            base.PublicKey = publicKey;
            _keySize = publicKey.Parameters.P.BitLength;
            _encryptor = null;
            _decryptor = null;
            base.Initialized = true;
        }

        /// <inheritdoc/>
        public override void ImportParameters(AsymmetricCipherKeyPair keyPair)
        {
            ElGamalPrivateKeyParameters privateKey = (ElGamalPrivateKeyParameters)keyPair.Private;
            ElGamalPublicKeyParameters publicKey = (ElGamalPublicKeyParameters)keyPair.Public;
            base.PrivateKey = privateKey;
            base.PublicKey = publicKey;
            _keySize = publicKey.Parameters.P.BitLength;
            _encryptor = null;
            _decryptor = null;
            base.Initialized = true;
        }

        /// <inheritdoc/>
        public override void ImportParameters(AsymmetricKeyParameter asymmetricKey)
        {
            ElGamalPrivateKeyParameters privateKey = null;
            ElGamalPublicKeyParameters publicKey;
            if (asymmetricKey.IsPrivate)
            {
                privateKey = (ElGamalPrivateKeyParameters)asymmetricKey;
                BigInteger y = privateKey.Parameters.G.ModPow(privateKey.X, privateKey.Parameters.P);
                publicKey = new ElGamalPublicKeyParameters(y, privateKey.Parameters);
            }
            else
            {
                publicKey = (ElGamalPublicKeyParameters)asymmetricKey;
            }
            base.PrivateKey = privateKey;
            base.PublicKey = publicKey;
            _keySize = publicKey.Parameters.P.BitLength;
            _encryptor = null;
            _decryptor = null;
            base.Initialized = true;
        }

        /// <inheritdoc/>
        public override void ImportPem(string keyPem)
        {
            using (StringReader reader = new StringReader(keyPem))
            {
                ElGamalPrivateKeyParameters privateKey = null;
                ElGamalPublicKeyParameters publicKey;
                object obj = new PemReader(reader).ReadObject();
                if (obj.GetType() == typeof(ElGamalPrivateKeyParameters))
                {
                    privateKey = (ElGamalPrivateKeyParameters)obj;
                    BigInteger y = privateKey.Parameters.G.ModPow(privateKey.X, privateKey.Parameters.P);
                    publicKey = new ElGamalPublicKeyParameters(y, privateKey.Parameters);
                }
                else
                {
                    publicKey = (ElGamalPublicKeyParameters)obj;
                }
                base.PrivateKey = privateKey;
                base.PublicKey = publicKey;
                _keySize = publicKey.Parameters.P.BitLength;
                _encryptor = null;
                _decryptor = null;
                base.Initialized = true;
            }
        }

        /// <inheritdoc/>
        public override void ImportPem(string privateKeyPem, string password)
        {
            using (StringReader reader = new StringReader(privateKeyPem))
            {
                object obj = new PemReader(reader, new Password(password)).ReadObject();
                ElGamalPrivateKeyParameters privateKey = (ElGamalPrivateKeyParameters)obj;
                BigInteger y = privateKey.Parameters.G.ModPow(privateKey.X, privateKey.Parameters.P);
                ElGamalPublicKeyParameters publicKey = new ElGamalPublicKeyParameters(y, privateKey.Parameters);
                base.PrivateKey = privateKey;
                base.PublicKey = publicKey;
                _keySize = publicKey.Parameters.P.BitLength;
                _encryptor = null;
                _decryptor = null;
                base.Initialized = true;
            }
        }

        #endregion Export/Import Parameters

        #region Encryption

        /// <inheritdoc/>
        public byte[] Decrypt(byte[] rgb)
        {
            if (rgb == null)
            {
                throw new ArgumentNullException(nameof(rgb));
            }
            return Decrypt(rgb, 0, rgb.Length);
        }

        /// <inheritdoc/>
        public byte[] Decrypt(byte[] inputBuffer, int offset, int length)
        {
            InspectParameters();
            if (_decryptor == null)
            {
                _decryptor = GetCipher(false, null, null);
            }
            return _decryptor.ProcessBlock(inputBuffer, offset, length);
        }

        /// <summary>
        /// Decrypts data with the asymmetric algorithm. Need set <see cref="Padding"/> = <see cref="AsymmetricEncryptionPaddingMode.OAEP"/>.
        /// </summary>
        /// <param name="inputBuffer">The encrypted data buffer.</param>
        /// <param name="offset">The starting offset to read.</param>
        /// <param name="length">The length to read.</param>
        /// <param name="hashForOAEP">The hash algorithm name for OAEP padding.</param>
        /// <param name="mgf1ForOAEP">The mgf1 algorithm name for OAEP padding.</param>
        /// <returns></returns>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1062:验证公共方法的参数", Justification = "<挂起>")]
        public byte[] Decrypt(byte[] inputBuffer, int offset, int length, HashAlgorithmName hashForOAEP, HashAlgorithmName mgf1ForOAEP)
        {
            if (_padding != AsymmetricEncryptionPaddingMode.OAEP)
            {
                throw new CryptographicException("Need OAEP padding mode.");
            }
            InspectParameters();
            _decryptor = GetCipher(false, hashForOAEP, mgf1ForOAEP);
            return _decryptor.ProcessBlock(inputBuffer, offset, length);
        }

        /// <inheritdoc/>
        public byte[] Encrypt(byte[] rgb)
        {
            if (rgb == null)
            {
                throw new ArgumentNullException(nameof(rgb));
            }
            return Encrypt(rgb, 0, rgb.Length);
        }

        /// <inheritdoc/>
        public byte[] Encrypt(byte[] inputBuffer, int offset, int length)
        {
            InspectParameters();
            if (_encryptor == null)
            {
                _encryptor = GetCipher(true, null, null);
            }
            return _encryptor.ProcessBlock(inputBuffer, offset, length);
        }

        /// <summary>
        /// Encrypts data with the asymmetric algorithm. Need set <see cref="Padding"/> = <see cref="AsymmetricEncryptionPaddingMode.OAEP"/>.
        /// </summary>
        /// <param name="inputBuffer">The data buffer to be encrypted.</param>
        /// <param name="offset">The starting offset to read.</param>
        /// <param name="length">The length to read.</param>
        /// <param name="hashForOAEP">The hash algorithm name for OAEP padding.</param>
        /// <param name="mgf1ForOAEP">The mgf1 algorithm name for OAEP padding.</param>
        /// <returns></returns>
        public byte[] Encrypt(byte[] inputBuffer, int offset, int length, HashAlgorithmName hashForOAEP, HashAlgorithmName mgf1ForOAEP)
        {
            if (_padding != AsymmetricEncryptionPaddingMode.OAEP)
            {
                throw new CryptographicException("Need OAEP padding mode.");
            }
            InspectParameters();
#pragma warning disable CA1062 // 验证公共方法的参数
            _encryptor = GetCipher(true, hashForOAEP, mgf1ForOAEP);
#pragma warning restore CA1062 // 验证公共方法的参数
            return _encryptor.ProcessBlock(inputBuffer, offset, length);
        }

        /// <inheritdoc/>
        public int GetLegalInputLength(bool forEncryption)
        {
            if (forEncryption)
            {
                int length = _keySize / 8;
                switch (_padding)
                {
                    case AsymmetricEncryptionPaddingMode.NoPadding: return length - 1;
                    case AsymmetricEncryptionPaddingMode.PKCS1: return length - 11;
                    case AsymmetricEncryptionPaddingMode.OAEP: return length - 42;
                    case AsymmetricEncryptionPaddingMode.ISO9796_1: return 0;
                    default: throw new CryptographicException("Unsupported padding mode.");
                }
            }
            else
            {
                if (base.Initialized)
                {
                    if (base.PrivateKey == null)
                    {
                        return 0;
                    }
                }
                return _keySize / 4;
            }
        }

        #endregion Encryption

        /// <summary>
        /// Creates an instance of the algorithm.
        /// </summary>
        /// <returns></returns>
        public static ElGamal Create()
        {
            return new ElGamal();
        }

        /// <summary>
        /// Determines whether the specified size is valid for the current algorithm.
        /// </summary>
        /// <param name="keySize">Legal key size is more than or equal to 8 bits (8 bits increments).</param>
        /// <param name="exception">Exception message.</param>
        /// <returns></returns>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Performance", "CA1822:将成员标记为 static", Justification = "<挂起>")]
        public bool ValidKeySize(int keySize, out string exception)
        {
            if (DetectionUtilities.ValidSize(LEGAL_KEY_SIZES, keySize))
            {
                exception = string.Empty;
                return true;
            }
            else
            {
                exception = "Legal key size is more than or equal to 8 bits (8 bits increments).";
                return false;
            }
        }

        internal static AsymmetricAlgorithmName GetAlgorithmName()
        {
            return new AsymmetricAlgorithmName(NAME, AsymmetricAlgorithmKind.Encryption, () => { return new ElGamal(); }, false);
        }

        private IAsymmetricBlockCipher GetCipher(bool encryption, HashAlgorithmName hash, HashAlgorithmName mgf1)
        {
            IAsymmetricBlockCipher cipher = new ElGamalEngine();
            switch (_padding)
            {
                case AsymmetricEncryptionPaddingMode.NoPadding: break;
                case AsymmetricEncryptionPaddingMode.PKCS1: cipher = new Pkcs1Encoding(cipher); break;
                case AsymmetricEncryptionPaddingMode.OAEP:
                    if (hash == null && mgf1 == null)
                    {
                        cipher = new OaepEncoding(cipher);
                    }
                    else if (hash == null)
                    {
                        cipher = new OaepEncoding(cipher, null, mgf1.GetEngine(), null);
                    }
                    else if (mgf1 == null)
                    {
                        cipher = new OaepEncoding(cipher, hash.GetEngine(), null, null);
                    }
                    else
                    {
                        cipher = new OaepEncoding(cipher, hash.GetEngine(), mgf1.GetEngine(), null);
                    }
                    break;

                case AsymmetricEncryptionPaddingMode.ISO9796_1: throw new CryptographicException("ElGamal is unsupported ISO9796_1 padding mode.");
                default: throw new CryptographicException("Unsupported padding mode.");
            }
            cipher.Init(encryption, encryption ? base.PublicKey : base.PrivateKey);
            return cipher;
        }
    }
}