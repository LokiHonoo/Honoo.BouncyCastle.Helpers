using Honoo.BouncyCastle.Helpers.Utilities;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.Security.Cryptography;

namespace Honoo.BouncyCastle.Helpers.Security.Crypto.Symmetric
{
    /// <summary>
    /// Symmetric block algorithm.
    /// </summary>
    public abstract class SymmetricBlockAlgorithm : SymmetricAlgorithm, ISymmetricBlockAlgorithm
    {
        #region Properties

        private readonly int _blockSize;
        private readonly KeySizes[] _legalKeySizes;

        /// <summary>
        /// Gets block size bits.
        /// </summary>
        public int BlockSize => _blockSize;

        /// <summary>
        /// Gets legal key size bits.
        /// </summary>
        public override KeySizes[] LegalKeySizes
        { get { return (KeySizes[])_legalKeySizes.Clone(); } }

        #endregion Properties

        #region Construction

        /// <summary>
        /// Symmetric block algorithm.
        /// </summary>
        /// <param name="name">Symmetric block algorithm name.</param>
        /// <param name="kind">Symmetric algorithm kind.</param>
        /// <param name="blockSizes">Block sizes.</param>
        /// <param name="blockSize">Block size bits.</param>
        /// <param name="keySizes">Key sizes.</param>
        /// <exception cref="CryptographicException"></exception>
        protected SymmetricBlockAlgorithm(string name, SymmetricAlgorithmKind kind, KeySizes[] blockSizes, int blockSize, KeySizes[] keySizes)
            : base(name, kind)
        {
            if (!DetectionUtilities.ValidSize(blockSizes, blockSize))
            {
                throw new CryptographicException("Unsupported block size.");
            }
            _blockSize = blockSize;
            _legalKeySizes = keySizes;
        }

        #endregion Construction

        /// <summary>
        /// Generate a new symmetric block algorithm and decrypt data.
        /// </summary>
        /// <param name="mode">Symmetric algorithm cipher mode.</param>
        /// <param name="padding">Symmetric algorithm padding mode.</param>
        /// <param name="parameters">Parameters.</param>
        /// <param name="data">Data bytes.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        public byte[] Decrypt(SymmetricCipherMode mode, SymmetricPaddingMode padding, ICipherParameters parameters, byte[] data)
        {
            return Decrypt(mode, padding, parameters, data, 0, data.Length);
        }

        /// <summary>
        /// Generate a new symmetric block algorithm and decrypt data.
        /// </summary>
        /// <param name="mode">Symmetric algorithm cipher mode.</param>
        /// <param name="padding">Symmetric algorithm padding mode.</param>
        /// <param name="parameters">Parameters.</param>
        /// <param name="dataBuffer">Data buffer bytes.</param>
        /// <param name="offset">The starting offset to read.</param>
        /// <param name="length">The length to read.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        public byte[] Decrypt(SymmetricCipherMode mode, SymmetricPaddingMode padding, ICipherParameters parameters, byte[] dataBuffer, int offset, int length)
        {
            if (parameters == null)
            {
                throw new ArgumentNullException(nameof(parameters));
            }

            if (dataBuffer == null)
            {
                throw new ArgumentNullException(nameof(dataBuffer));
            }
            IBufferedCipher decryptor = GenerateCipher(false, mode, padding, parameters);
            return decryptor.DoFinal(dataBuffer, offset, length);
        }

        /// <summary>
        /// Generate a new symmetric block algorithm and encrypt data.
        /// </summary>
        /// <param name="mode">Symmetric algorithm cipher mode.</param>
        /// <param name="padding">Symmetric algorithm padding mode.</param>
        /// <param name="parameters">Parameters.</param>
        /// <param name="data">Data bytes.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        public byte[] Encrypt(SymmetricCipherMode mode, SymmetricPaddingMode padding, ICipherParameters parameters, byte[] data)
        {
            return Encrypt(mode, padding, parameters, data, 0, data.Length);
        }

        /// <summary>
        /// Generate a new symmetric block algorithm and encrypt data.
        /// </summary>
        /// <param name="mode">Symmetric algorithm cipher mode.</param>
        /// <param name="padding">Symmetric algorithm padding mode.</param>
        /// <param name="parameters">Parameters.</param>
        /// <param name="dataBuffer">Data buffer bytes.</param>
        /// <param name="offset">The starting offset to read.</param>
        /// <param name="length">The length to read.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        public byte[] Encrypt(SymmetricCipherMode mode, SymmetricPaddingMode padding, ICipherParameters parameters, byte[] dataBuffer, int offset, int length)
        {
            if (parameters == null)
            {
                throw new ArgumentNullException(nameof(parameters));
            }
            if (dataBuffer == null)
            {
                throw new ArgumentNullException(nameof(dataBuffer));
            }
            IBufferedCipher encryptor = GenerateCipher(true, mode, padding, parameters);
            return encryptor.DoFinal(dataBuffer, offset, length);
        }

        /// <summary>
        /// Generate cipher. The cipher can be reused except GCM cipher mode.
        /// </summary>
        /// <param name="mode">Symmetric algorithm cipher mode.</param>
        /// <param name="padding">Symmetric algorithm padding mode.</param>
        /// <param name="parameters">Parameters.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        public IBufferedCipher GenerateDecryptor(SymmetricCipherMode mode, SymmetricPaddingMode padding, ICipherParameters parameters)
        {
            return GenerateCipher(false, mode, padding, parameters);
        }

        /// <summary>
        /// Generate cipher. The cipher can be reused except GCM cipher mode.
        /// </summary>
        /// <param name="mode">Symmetric algorithm cipher mode.</param>
        /// <param name="padding">Symmetric algorithm padding mode.</param>
        /// <param name="parameters">Parameters.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        public IBufferedCipher GenerateEncryptor(SymmetricCipherMode mode, SymmetricPaddingMode padding, ICipherParameters parameters)
        {
            return GenerateCipher(true, mode, padding, parameters);
        }

        /// <summary>
        /// Generate parameters.
        /// </summary>
        /// <param name="key">Key bytes.</param>
        /// <param name="nonce">Nonce bytes.</param>
        /// <param name="macSize">MAC size bits.</param>
        /// <param name="associatedText">Associated text bytes.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        public ICipherParameters GenerateParameters(byte[] key, byte[] nonce, int macSize, byte[] associatedText)
        {
            KeyParameter parameter = GenerateKeyParameter(key);
            return new AeadParameters(parameter, macSize, nonce, associatedText);
        }

        /// <summary>
        /// Try get legal sizes.
        /// </summary>
        /// <param name="mode">Symmetric algorithm cipher mode.</param>
        /// <param name="padding">Symmetric algorithm padding mode.</param>
        /// <param name="ivSizes">Legal IV size bits.</param>
        /// <returns></returns>
        public bool TryGetIVSizes(SymmetricCipherMode mode, SymmetricPaddingMode padding, out KeySizes[] ivSizes)
        {
            bool pad;
            switch (padding)
            {
                case SymmetricPaddingMode.NoPadding: pad = false; break;
                case SymmetricPaddingMode.PKCS7:
                case SymmetricPaddingMode.Zeros:
                case SymmetricPaddingMode.X923:
                case SymmetricPaddingMode.ISO10126:
                case SymmetricPaddingMode.ISO7816_4:
                case SymmetricPaddingMode.TBC: pad = true; break;
                default: ivSizes = null; return false;
            }
            switch (mode)
            {
                case SymmetricCipherMode.CBC: ivSizes = new KeySizes[] { new KeySizes(_blockSize, _blockSize, 0) }; return true;
                case SymmetricCipherMode.ECB: ivSizes = new KeySizes[] { new KeySizes(0, 0, 0) }; return true;
                case SymmetricCipherMode.OFB: ivSizes = new KeySizes[] { new KeySizes(8, _blockSize, 8) }; return true;
                case SymmetricCipherMode.CFB: ivSizes = new KeySizes[] { new KeySizes(8, _blockSize, 8) }; return true;
                case SymmetricCipherMode.CTS:
                    if (!pad)
                    {
                        ivSizes = new KeySizes[] { new KeySizes(_blockSize, _blockSize, 0) };
                        return true;
                    }
                    break;

                case SymmetricCipherMode.CTR:
                    {
                        int min = Math.Max(_blockSize / 2, _blockSize - 64);
                        ivSizes = new KeySizes[] { new KeySizes(min, _blockSize, 8) };
                        return true;
                    }
                case SymmetricCipherMode.CTS_ECB:
                    if (!pad)
                    {
                        ivSizes = new KeySizes[] { new KeySizes(0, 0, 0) };
                        return true;
                    }
                    break;

                case SymmetricCipherMode.GOFB:
                    if (_blockSize == 64)
                    {
                        ivSizes = new KeySizes[] { new KeySizes(_blockSize, _blockSize, 0) };
                        return true;
                    }
                    break;

                case SymmetricCipherMode.OpenPGPCFB:
                    ivSizes = new KeySizes[] { new KeySizes(8, _blockSize, 8) };
                    return true;

                case SymmetricCipherMode.SIC:
                    if (_blockSize >= 128)
                    {
                        int min = Math.Max(_blockSize / 2, _blockSize - 64);
                        ivSizes = new KeySizes[] { new KeySizes(min, _blockSize, 8) };
                        return true;
                    }
                    break;

                case SymmetricCipherMode.CCM:
                    if (!pad && _blockSize == 128)
                    {
                        ivSizes = new KeySizes[] { new KeySizes(56, 104, 8) };
                        return true;
                    }
                    break;

                case SymmetricCipherMode.EAX:
                    if (!pad && (_blockSize == 64 || _blockSize == 128))
                    {
                        ivSizes = new KeySizes[] { new KeySizes(8, 2147483640, 8) };
                        return true;
                    }
                    break;

                case SymmetricCipherMode.GCM:
                    if (!pad && _blockSize == 128)
                    {
                        ivSizes = new KeySizes[] { new KeySizes(8, 2147483640, 8) };
                        return true;
                    }
                    break;

                case SymmetricCipherMode.OCB:
                    if (!pad && _blockSize == 128)
                    {
                        /*
                         * BUG: OCB cipher mode supported null(0) Nonce/IV size but BouncyCastle cannot set that. (BouncyCastle 1.9.0 has not been fixed).
                         * So use limit min value 8.
                         */

                        ivSizes = new KeySizes[] { new KeySizes(8, 120, 8) };
                        return true;
                    }
                    break;

                default: break;
            }
            ivSizes = null;
            return false;
        }

        /// <summary>
        /// Try get legal mac sizes.
        /// </summary>
        /// <param name="mode">Symmetric algorithm cipher mode.</param>
        /// <param name="padding">Symmetric algorithm padding mode.</param>
        /// <param name="macSizes">Legal mac size bits.</param>
        /// <returns></returns>
        public bool TryGetMacSizes(SymmetricCipherMode mode, SymmetricPaddingMode padding, out KeySizes[] macSizes)
        {
            switch (mode)
            {
                case SymmetricCipherMode.CCM:
                    if (padding == SymmetricPaddingMode.NoPadding && _blockSize == 128)
                    {
                        macSizes = new KeySizes[] { new KeySizes(32, 128, 16) };
                        return true;
                    }
                    break;

                case SymmetricCipherMode.EAX:
                    if (padding == SymmetricPaddingMode.NoPadding && (_blockSize == 64 || _blockSize == 128))
                    {
                        macSizes = new KeySizes[] { new KeySizes(8, _blockSize, 8) };
                        return true;
                    }
                    break;

                case SymmetricCipherMode.GCM:
                    if (padding == SymmetricPaddingMode.NoPadding && _blockSize == 128)
                    {
                        macSizes = new KeySizes[] { new KeySizes(32, 128, 8) };
                        return true;
                    }
                    break;

                case SymmetricCipherMode.OCB:
                    if (padding == SymmetricPaddingMode.NoPadding && _blockSize == 128)
                    {
                        macSizes = new KeySizes[] { new KeySizes(64, 128, 8) };
                        return true;
                    }
                    break;

                default: break;
            }
            macSizes = null;
            return false;
        }

        /// <summary>
        /// Try get legal nonce sizes.
        /// </summary>
        /// <param name="mode">Symmetric algorithm cipher mode.</param>
        /// <param name="padding">Symmetric algorithm padding mode.</param>
        /// <param name="nonceSizes">Legal nonce size bits.</param>
        /// <returns></returns>
        public bool TryGetNonceSizes(SymmetricCipherMode mode, SymmetricPaddingMode padding, out KeySizes[] nonceSizes)
        {
            return TryGetIVSizes(mode, padding, out nonceSizes);
        }

        /// <summary>
        /// Verify IV size.
        /// </summary>
        /// <param name="mode">Symmetric algorithm cipher mode.</param>
        /// <param name="padding">Symmetric algorithm padding mode.</param>
        /// <param name="ivSize">IV size bits.</param>
        /// <returns></returns>
        public bool VerifyIVSize(SymmetricCipherMode mode, SymmetricPaddingMode padding, int ivSize)
        {
            bool pad;
            switch (padding)
            {
                case SymmetricPaddingMode.NoPadding: pad = false; break;
                case SymmetricPaddingMode.PKCS7:
                case SymmetricPaddingMode.Zeros:
                case SymmetricPaddingMode.X923:
                case SymmetricPaddingMode.ISO10126:
                case SymmetricPaddingMode.ISO7816_4:
                case SymmetricPaddingMode.TBC: pad = true; break;
                default: return false;
            }
            switch (mode)
            {
                case SymmetricCipherMode.CBC: return ivSize == _blockSize;
                case SymmetricCipherMode.ECB: return ivSize == 0;
                case SymmetricCipherMode.OFB: return ivSize >= 8 && ivSize <= _blockSize && ivSize % 8 == 0;
                case SymmetricCipherMode.CFB: return ivSize >= 8 && ivSize <= _blockSize && ivSize % 8 == 0;
                case SymmetricCipherMode.CTS: return !pad && ivSize == _blockSize;
                case SymmetricCipherMode.CTR: return ivSize >= Math.Max(_blockSize / 2, _blockSize - 64) && ivSize <= _blockSize && ivSize % 8 == 0;
                case SymmetricCipherMode.CTS_ECB: return !pad && ivSize == 0;
                case SymmetricCipherMode.GOFB: return _blockSize == 64 && ivSize == _blockSize;
                case SymmetricCipherMode.OpenPGPCFB: return ivSize >= 8 && ivSize <= _blockSize && ivSize % 8 == 0;
                case SymmetricCipherMode.SIC: return _blockSize >= 128 && ivSize >= Math.Max(_blockSize / 2, _blockSize - 64) && ivSize <= _blockSize && ivSize % 8 == 0;

                case SymmetricCipherMode.CCM: return !pad && _blockSize == 128 && ivSize >= 56 && ivSize <= 104 && ivSize % 8 == 0;
                case SymmetricCipherMode.EAX: return !pad && (_blockSize == 64 || _blockSize == 128) && ivSize >= 8 && ivSize <= 2147483640 && ivSize % 8 == 0;
                case SymmetricCipherMode.GCM: return !pad && _blockSize == 128 && ivSize >= 8 && ivSize <= 2147483640 && ivSize % 8 == 0;

                /*
                 * BUG: OCB cipher mode supported null(0) Nonce/IV size but BouncyCastle cannot set that. (BouncyCastle 1.9.0 has not been fixed).
                 * So use limit min value 8.
                 */

                case SymmetricCipherMode.OCB: return !pad && _blockSize == 128 && ivSize >= 8 && ivSize <= 120 && ivSize % 8 == 0;
                default: return false;
            }
        }

        /// <summary>
        /// Verify key size.
        /// </summary>
        /// <param name="keySize">Key size bits.</param>
        /// <returns></returns>
        public override bool VerifyKeySize(int keySize)
        {
            return DetectionUtilities.ValidSize(_legalKeySizes, keySize);
        }

        /// <summary>
        /// Verify mac size.
        /// </summary>
        /// <param name="mode">Symmetric algorithm cipher mode.</param>
        /// <param name="padding">Symmetric algorithm padding mode.</param>
        /// <param name="macSize">Mac size bits.</param>
        /// <returns></returns>
        public bool VerifyMacSize(SymmetricCipherMode mode, SymmetricPaddingMode padding, int macSize)
        {
            switch (mode)
            {
                case SymmetricCipherMode.CCM: return padding == SymmetricPaddingMode.NoPadding && _blockSize == 128 && macSize >= 32 && macSize <= 128 && macSize % 16 == 0;
                case SymmetricCipherMode.EAX: return padding == SymmetricPaddingMode.NoPadding && (_blockSize == 64 || _blockSize == 128) && macSize >= 8 && macSize <= _blockSize && macSize % 8 == 0;
                case SymmetricCipherMode.GCM: return padding == SymmetricPaddingMode.NoPadding && _blockSize == 128 && macSize >= 32 && macSize <= 128 && macSize % 8 == 0;
                case SymmetricCipherMode.OCB: return padding == SymmetricPaddingMode.NoPadding && _blockSize == 128 && macSize >= 64 && macSize <= 128 && macSize % 8 == 0;
                default: return false;
            }
        }

        /// <summary>
        /// Verify nonce size.
        /// </summary>
        /// <param name="mode">Symmetric algorithm cipher mode.</param>
        /// <param name="padding">Symmetric algorithm padding mode.</param>
        /// <param name="nonceSize">Nonce size bits.</param>
        /// <returns></returns>
        public bool VerifyNonceSize(SymmetricCipherMode mode, SymmetricPaddingMode padding, int nonceSize)
        {
            return VerifyIVSize(mode, padding, nonceSize);
        }

        internal abstract IBlockCipher GenerateEngine();

        private IBufferedCipher GenerateCipher(bool forEncryption, SymmetricCipherMode mode, SymmetricPaddingMode padding, ICipherParameters parameters)
        {
            IBlockCipherPadding pad;
            switch (padding)
            {
                case SymmetricPaddingMode.NoPadding: pad = null; break;
                case SymmetricPaddingMode.PKCS7: pad = SymmetricPadding.PKCS7Padding; break;
                case SymmetricPaddingMode.Zeros: pad = SymmetricPadding.ZEROBYTEPadding; break;
                case SymmetricPaddingMode.X923: pad = SymmetricPadding.X923Padding; break;
                case SymmetricPaddingMode.ISO10126: pad = SymmetricPadding.ISO10126d2Padding; break;
                case SymmetricPaddingMode.ISO7816_4: pad = SymmetricPadding.ISO7816d4Padding; break;
                case SymmetricPaddingMode.TBC: pad = SymmetricPadding.TBCPadding; break;
                default: throw new CryptographicException("Unsupported padding mode.");
            }
            IBlockCipher engine = GenerateEngine();
            IBufferedCipher cipher;
            switch (mode)
            {
                case SymmetricCipherMode.CBC:
                    cipher = pad == null ? new BufferedBlockCipher(new CbcBlockCipher(engine))
                        : new PaddedBufferedBlockCipher(new CbcBlockCipher(engine), pad);
                    break;

                case SymmetricCipherMode.ECB:
                    cipher = pad == null ? new BufferedBlockCipher(engine) : new PaddedBufferedBlockCipher(engine, pad);
                    break;

                case SymmetricCipherMode.OFB:
                    int ofbs = ((ParametersWithIV)parameters).GetIV().Length * 8;
                    cipher = pad == null ? new BufferedBlockCipher(new OfbBlockCipher(engine, ofbs))
                        : new PaddedBufferedBlockCipher(new OfbBlockCipher(engine, ofbs), pad);
                    break;

                case SymmetricCipherMode.CFB:
                    int cfbs = ((ParametersWithIV)parameters).GetIV().Length * 8;
                    cipher = pad == null ? new BufferedBlockCipher(new CfbBlockCipher(engine, cfbs))
                        : new PaddedBufferedBlockCipher(new CfbBlockCipher(engine, cfbs), pad);
                    break;

                case SymmetricCipherMode.CTS:
                    if (pad == null)
                    {
                        cipher = new CtsBlockCipher(new CbcBlockCipher(engine));
                        break;
                    }
                    throw new CryptographicException("CTS cipher mode can only select SymmetricPaddingMode.NoPadding padding mode.");

                case SymmetricCipherMode.CTR:
                    cipher = pad == null ? new BufferedBlockCipher(new SicBlockCipher(engine))
                        : new PaddedBufferedBlockCipher(new SicBlockCipher(engine), pad);
                    break;

                case SymmetricCipherMode.CTS_ECB:
                    if (pad == null)
                    {
                        cipher = new CtsBlockCipher(engine);
                        break;
                    }
                    throw new CryptographicException("CTS cipher mode can only select SymmetricPaddingMode.NoPadding padding mode.");

                case SymmetricCipherMode.GOFB:
                    if (_blockSize == 64)
                    {
                        cipher = pad == null ? new BufferedBlockCipher(new GOfbBlockCipher(engine))
                            : new PaddedBufferedBlockCipher(new GOfbBlockCipher(engine), pad);
                        break;
                    }
                    throw new CryptographicException("GOFB cipher mode uses with a block size of 64 bits algorithm (e.g. DESede).");

                case SymmetricCipherMode.OpenPGPCFB:
                    cipher = pad == null ? new BufferedBlockCipher(new OpenPgpCfbBlockCipher(engine))
                        : new PaddedBufferedBlockCipher(new OpenPgpCfbBlockCipher(engine), pad);
                    break;

                case SymmetricCipherMode.SIC:
                    if (_blockSize >= 128)
                    {
                        cipher = pad == null ? new BufferedBlockCipher(new SicBlockCipher(engine))
                            : new PaddedBufferedBlockCipher(new SicBlockCipher(engine), pad);
                        break;
                    }
                    throw new CryptographicException("SIC cipher mode uses with a block size of at least 128 bits algorithm (e.g. AES).");

                case SymmetricCipherMode.CCM:
                    if (pad == null)
                    {
                        if (_blockSize == 128)
                        {
                            cipher = new BufferedAeadBlockCipher(new CcmBlockCipher(engine));
                            break;
                        }
                        throw new CryptographicException("CCM cipher mode uses with a block size of 128 bits algorithm (e.g. AES).");
                    }
                    throw new CryptographicException("CCM cipher mode can only select SymmetricPaddingMode.NoPadding padding mode.");

                case SymmetricCipherMode.EAX:
                    if (pad == null)
                    {
                        if (_blockSize == 64 || _blockSize == 128)
                        {
                            cipher = new BufferedAeadBlockCipher(new EaxBlockCipher(engine));
                            break;
                        }
                        throw new CryptographicException("EAX cipher mode uses with a block size of 64 or 128 bits algorithm (e.g. DESede, AES).");
                    }
                    throw new CryptographicException("EAX cipher mode can only select SymmetricPaddingMode.NoPadding padding mode.");

                case SymmetricCipherMode.GCM:
                    if (pad == null)
                    {
                        if (_blockSize == 128)
                        {
                            cipher = new BufferedAeadBlockCipher(new GcmBlockCipher(engine));
                            break;
                        }
                        throw new CryptographicException("GCM cipher mode uses with a block size of 128 bits algorithm (e.g. AES).");
                    }
                    throw new CryptographicException("GCM cipher mode can only select SymmetricPaddingMode.NoPadding padding mode.");

                case SymmetricCipherMode.OCB:
                    if (pad == null)
                    {
                        if (_blockSize == 128)
                        {
                            cipher = new BufferedAeadBlockCipher(new OcbBlockCipher(engine, GenerateEngine()));
                            break;
                        }
                        throw new CryptographicException("OCB cipher mode uses with a block size of 128 bits algorithm (e.g. AES).");
                    }
                    throw new CryptographicException("OCB cipher mode can only select SymmetricPaddingMode.NoPadding padding mode.");

                default: throw new CryptographicException("Unsupported cipher mode.");
            }
            cipher.Init(forEncryption, parameters);
            return cipher;
        }
    }
}