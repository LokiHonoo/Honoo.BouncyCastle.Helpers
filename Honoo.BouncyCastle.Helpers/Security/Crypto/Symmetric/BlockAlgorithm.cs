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
    public abstract class BlockAlgorithm : SymmetricAlgorithm, IBlockAlgorithm
    {
        #region Properties

        private readonly int _blockSize;
        private readonly KeySizes[] _keySizes;

        /// <summary>
        /// Gets block size bits.
        /// </summary>
        public int BlockSize => _blockSize;

        /// <summary>
        /// Gets legal key size bits.
        /// </summary>
        public KeySizes[] KeySizes
        { get { return (KeySizes[])_keySizes.Clone(); } }

        #endregion Properties

        #region Constructor

        /// <summary>
        /// Symmetric block algorithm.
        /// </summary>
        /// <param name="mechanism">Symmetric block algorithm mechanism.</param>
        /// <param name="blockSizes">Block sizes.</param>
        /// <param name="blockSize">Block size.</param>
        /// <param name="keySizes">Key sizes.</param>
        /// <exception cref="CryptographicException"></exception>
        protected BlockAlgorithm(string mechanism, KeySizes[] blockSizes, int blockSize, KeySizes[] keySizes) : base(mechanism)
        {
            if (!DetectionUtilities.ValidSize(blockSizes, blockSize))
            {
                throw new CryptographicException("Unsupported block size.");
            }
            _blockSize = blockSize;
            _keySizes = keySizes;
        }

        #endregion Constructor

        /// <summary>
        /// Generate cipher. The cipher can be reused. Except GCM cipher mode.
        /// </summary>
        /// <param name="forEncryption"></param>
        /// <param name="mode">Symmetric algorithm cipher mode.</param>
        /// <param name="padding">Symmetric algorithm padding mode.</param>
        /// <param name="parameters">Parameters.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        public IBufferedCipher GenerateCipher(bool forEncryption, SymmetricCipherMode mode, SymmetricPaddingMode padding, ICipherParameters parameters)
        {
            IBlockCipherPadding pad;
            switch (padding)
            {
                case SymmetricPaddingMode.NoPadding: pad = null; break;
                case SymmetricPaddingMode.PKCS7: pad = Common.PKCS7Padding; break;
                case SymmetricPaddingMode.Zeros: pad = Common.ZEROBYTEPadding; break;
                case SymmetricPaddingMode.X923: pad = Common.X923Padding; break;
                case SymmetricPaddingMode.ISO10126: pad = Common.ISO10126d2Padding; break;
                case SymmetricPaddingMode.ISO7816_4: pad = Common.ISO7816d4Padding; break;
                case SymmetricPaddingMode.TBC: pad = Common.TBCPadding; break;
                default: throw new CryptographicException("Unsupported padding mode.");
            }
            IBlockCipher engine = GenerateEngine();
            IBufferedCipher cipher;
            switch (mode)
            {
                case SymmetricCipherMode.CBC:
                    cipher = pad is null ? new BufferedBlockCipher(new CbcBlockCipher(engine))
                        : new PaddedBufferedBlockCipher(new CbcBlockCipher(engine), pad);
                    break;

                case SymmetricCipherMode.ECB:
                    cipher = pad is null ? new BufferedBlockCipher(engine) : new PaddedBufferedBlockCipher(engine, pad);
                    break;

                case SymmetricCipherMode.OFB:
                    int ofbs = ((ParametersWithIV)parameters).GetIV().Length * 8;
                    cipher = pad is null ? new BufferedBlockCipher(new OfbBlockCipher(engine, ofbs))
                        : new PaddedBufferedBlockCipher(new OfbBlockCipher(engine, ofbs), pad);
                    break;

                case SymmetricCipherMode.CFB:
                    int cfbs = ((ParametersWithIV)parameters).GetIV().Length * 8;
                    cipher = pad is null ? new BufferedBlockCipher(new CfbBlockCipher(engine, cfbs))
                        : new PaddedBufferedBlockCipher(new CfbBlockCipher(engine, cfbs), pad);
                    break;

                case SymmetricCipherMode.CTS:
                    if (pad is null)
                    {
                        cipher = new CtsBlockCipher(new CbcBlockCipher(engine));
                        break;
                    }
                    throw new CryptographicException("CTS cipher mode can only select SymmetricPaddingMode.NoPadding padding mode.");

                case SymmetricCipherMode.CTR:
                    cipher = pad is null ? new BufferedBlockCipher(new SicBlockCipher(engine))
                        : new PaddedBufferedBlockCipher(new SicBlockCipher(engine), pad);
                    break;

                case SymmetricCipherMode.CTS_ECB:
                    if (pad is null)
                    {
                        cipher = new CtsBlockCipher(engine);
                        break;
                    }
                    throw new CryptographicException("CTS cipher mode can only select SymmetricPaddingMode.NoPadding padding mode.");

                case SymmetricCipherMode.GOFB:
                    if (_blockSize == 64)
                    {
                        cipher = pad is null ? new BufferedBlockCipher(new GOfbBlockCipher(engine))
                            : new PaddedBufferedBlockCipher(new GOfbBlockCipher(engine), pad);
                        break;
                    }
                    throw new CryptographicException("GOFB cipher mode uses with a block size of 64 bits algorithm (e.g. DESede).");

                case SymmetricCipherMode.OpenPGPCFB:
                    cipher = pad is null ? new BufferedBlockCipher(new OpenPgpCfbBlockCipher(engine))
                        : new PaddedBufferedBlockCipher(new OpenPgpCfbBlockCipher(engine), pad);
                    break;

                case SymmetricCipherMode.SIC:
                    if (_blockSize >= 128)
                    {
                        cipher = pad is null ? new BufferedBlockCipher(new SicBlockCipher(engine))
                            : new PaddedBufferedBlockCipher(new SicBlockCipher(engine), pad);
                        break;
                    }
                    throw new CryptographicException("SIC cipher mode uses with a block size of at least 128 bits algorithm (e.g. AES).");

                case SymmetricCipherMode.CCM:
                    if (pad is null)
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
                    if (pad is null)
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
                    if (pad is null)
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
                    if (pad is null)
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

        /// <summary>
        /// Generate parameters.
        /// </summary>
        /// <param name="key">Key bytes.</param>
        /// <param name="iv">IV bytes.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        public ICipherParameters GenerateParameters(byte[] key, byte[] iv)
        {
            ICipherParameters parameters = GenerateKeyParameter(key);
            if (iv != null)
            {
                parameters = new ParametersWithIV(parameters, iv);
            }
            return parameters;
        }

        /// <summary>
        /// Generate parameters.
        /// </summary>
        /// <param name="key">Key buffer bytes.</param>
        /// <param name="keyOffset">The starting offset to read.</param>
        /// <param name="keyLength">The length to read.</param>
        /// <param name="iv">IV buffer bytes.</param>
        /// <param name="ivOffset">The starting offset to read.</param>
        /// <param name="ivLength">The length to read.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        public ICipherParameters GenerateParameters(byte[] key, int keyOffset, int keyLength, byte[] iv, int ivOffset, int ivLength)
        {
            ICipherParameters parameters = GenerateKeyParameter(key, keyOffset, keyLength);
            if (iv != null && ivLength > 0)
            {
                parameters = new ParametersWithIV(parameters, iv, ivOffset, ivLength);
            }
            return parameters;
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
        /// <param name="ivSizes">Legal iv size bits.</param>
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
                        ivSizes = new KeySizes[] { new KeySizes(0, 120, 8) };
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
            switch (padding)
            {
                case SymmetricPaddingMode.NoPadding: break;
                default: macSizes = null; return false;
            }
            switch (mode)
            {
                case SymmetricCipherMode.CCM:
                    if (_blockSize == 128)
                    {
                        macSizes = new KeySizes[] { new KeySizes(32, 128, 16) };
                        return true;
                    }
                    break;

                case SymmetricCipherMode.EAX:
                    if (_blockSize == 64 || _blockSize == 128)
                    {
                        macSizes = new KeySizes[] { new KeySizes(8, _blockSize, 8) };
                        return true;
                    }
                    break;

                case SymmetricCipherMode.GCM:
                    if (_blockSize == 128)
                    {
                        macSizes = new KeySizes[] { new KeySizes(32, 128, 8) };
                        return true;
                    }
                    break;

                case SymmetricCipherMode.OCB:
                    if (_blockSize == 128)
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
            switch (padding)
            {
                case SymmetricPaddingMode.NoPadding: break;
                default: nonceSizes = null; return false;
            }
            switch (mode)
            {
                case SymmetricCipherMode.CCM:
                    if (_blockSize == 128)
                    {
                        nonceSizes = new KeySizes[] { new KeySizes(56, 104, 8) };
                        return true;
                    }
                    break;

                case SymmetricCipherMode.EAX:
                    if (_blockSize == 64 || _blockSize == 128)
                    {
                        nonceSizes = new KeySizes[] { new KeySizes(8, 2147483640, 8) };
                        return true;
                    }
                    break;

                case SymmetricCipherMode.GCM:
                    if (_blockSize == 128)
                    {
                        nonceSizes = new KeySizes[] { new KeySizes(8, 2147483640, 8) };
                        return true;
                    }
                    break;

                case SymmetricCipherMode.OCB:
                    if (_blockSize == 128)
                    {
                        nonceSizes = new KeySizes[] { new KeySizes(0, 120, 8) };
                        return true;
                    }
                    break;

                default: break;
            }
            nonceSizes = null;
            return false;
        }

        internal abstract IBlockCipher GenerateEngine();

        /// <summary>
        /// Generate KeyParameter.
        /// </summary>
        /// <param name="key">Key.</param>
        /// <returns></returns>
        protected virtual KeyParameter GenerateKeyParameter(byte[] key)
        {
            return new KeyParameter(key);
        }

        /// <summary>
        /// Generate KeyParameter.
        /// </summary>
        /// <param name="key">Key.</param>
        /// <param name="offset">Offset.</param>
        /// <param name="length">Length.</param>
        /// <returns></returns>
        protected virtual KeyParameter GenerateKeyParameter(byte[] key, int offset, int length)
        {
            return new KeyParameter(key, offset, length);
        }
    }
}