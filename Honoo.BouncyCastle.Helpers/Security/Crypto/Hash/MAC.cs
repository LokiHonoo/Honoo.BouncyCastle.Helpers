using Honoo.BouncyCastle.Helpers.Security.Crypto.Symmetric;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.Globalization;
using System.Security.Cryptography;

namespace Honoo.BouncyCastle.Helpers.Security.Crypto.Hash
{
    /// <summary>
    /// MAC.
    /// <para/>Legal mac size is between 8 and block size (8 bits increments).
    /// <para/>Legal mac size must be at least 24 bits (FIPS Publication 81) or 16 bits if being used as a data authenticator (FIPS Publication 113).
    /// <para/>Used (block size / 2) as mac size by default.
    /// </summary>
    public sealed class MAC : IMAC
    {
        #region Properties

        private readonly BlockAlgorithm _blockAlgorithm;
        private readonly int _hashSize;
        private readonly int _macSize;
        private readonly string _mechanism;

        /// <summary>
        /// Gets block size bits.
        /// </summary>
        public int BlockSize => _blockAlgorithm.BlockSize;

        /// <summary>
        /// Gets hash size bits.
        /// </summary>
        public int HashSize => _hashSize;

        /// <summary>
        /// Gets legal key size bits.
        /// </summary>
        public KeySizes[] KeySizes
        { get { return (KeySizes[])_blockAlgorithm.KeySizes.Clone(); } }

        /// <summary>
        /// Gets mac size bits.
        /// </summary>
        public int MacSize => _macSize;

        /// <summary>
        /// Gets mechanism.
        /// </summary>
        public string Mechanism => _mechanism;

        internal IBlockAlgorithm BlockAlgorithm => _blockAlgorithm;

        #endregion Properties

        #region Constructor

        /// <summary>
        /// MAC.
        /// <para/>Legal mac size is between 8 and block size (8 bits increments).
        /// <para/>Legal mac size must be at least 24 bits (FIPS Publication 81) or 16 bits if being used as a data authenticator (FIPS Publication 113).
        /// <para/>Default mac size used as block size / 2.
        /// </summary>
        /// <param name="blockAlgorithm">Symmetric block algorithm.</param>
        public MAC(IBlockAlgorithm blockAlgorithm) : this(blockAlgorithm, blockAlgorithm.BlockSize / 2)
        {
        }

        /// <summary>
        /// MAC.
        /// <para/>Legal mac size is between 8 and block size (8 bits increments).
        /// <para/>Legal mac size must be at least 24 bits (FIPS Publication 81) or 16 bits if being used as a data authenticator (FIPS Publication 113).
        /// <para/>Default mac size used as block size / 2.
        /// </summary>
        /// <param name="blockAlgorithm">Symmetric block algorithm.</param>
        /// <param name="macSize">MAC size bits.</param>
        public MAC(IBlockAlgorithm blockAlgorithm, int macSize)
        {
            if (macSize < 8 || macSize > blockAlgorithm.BlockSize || macSize % 8 != 0)
            {
                throw new CryptographicException("Legal mac size is between 8 and block size (8 bits increments).");
            }
            _mechanism = string.Format(CultureInfo.InvariantCulture, "{0}/MAC", blockAlgorithm.Mechanism);
            _blockAlgorithm = (BlockAlgorithm)blockAlgorithm;
            _macSize = macSize;
            _hashSize = macSize;
        }

        #endregion Constructor

        /// <summary>
        /// Generate a new digest and compute data hash.
        /// </summary>
        /// <param name="mode">MAC cipher mode.</param>
        /// <param name="padding">MAC padding mode.</param>
        /// <param name="parameters">Parameters.</param>
        /// <param name="data">Data bytes.</param>
        /// <returns></returns>
        public byte[] ComputeHash(MACCipherMode mode, MACPaddingMode padding, ICipherParameters parameters, byte[] data)
        {
            return ComputeHash(mode, padding, parameters, data, 0, data.Length);
        }

        /// <summary>
        /// Generate a new digest and compute data hash.
        /// </summary>
        /// <param name="mode">MAC cipher mode.</param>
        /// <param name="padding">MAC padding mode.</param>
        /// <param name="parameters">Parameters.</param>
        /// <param name="data">Data buffer bytes.</param>
        /// <param name="offset">The starting offset to read.</param>
        /// <param name="length">The length to read.</param>
        /// <returns></returns>
        public byte[] ComputeHash(MACCipherMode mode, MACPaddingMode padding, ICipherParameters parameters, byte[] data, int offset, int length)
        {
            if (parameters is null)
            {
                throw new ArgumentNullException(nameof(parameters));
            }
            if (data is null)
            {
                throw new ArgumentNullException(nameof(data));
            }
            IMac digest = GenerateDigest(mode, padding, parameters);
            digest.BlockUpdate(data, offset, length);
            byte[] hash = new byte[_hashSize];
            digest.DoFinal(hash, 0);
            return hash;
        }

        /// <summary>
        /// Generate digest. The digest can be reused.
        /// </summary>
        /// <param name="mode">MAC cipher mode.</param>
        /// <param name="padding">MAC padding mode.</param>
        /// <param name="parameters">Parameters.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        public IMac GenerateDigest(MACCipherMode mode, MACPaddingMode padding, ICipherParameters parameters)
        {
            IBlockCipherPadding pad;
            switch (padding)
            {
                case MACPaddingMode.NoPadding: pad = null; break;
                case MACPaddingMode.PKCS7: pad = Common.PKCS7Padding; break;
                case MACPaddingMode.Zeros: pad = Common.ZEROBYTEPadding; break;
                case MACPaddingMode.X923: pad = Common.X923Padding; break;
                case MACPaddingMode.ISO7816_4: pad = Common.ISO7816d4Padding; break;
                case MACPaddingMode.TBC: pad = Common.TBCPadding; break;
                default: throw new CryptographicException("Unsupported padding mode.");
            }
            IMac digest;
            switch (mode)
            {
                case MACCipherMode.CBC:
                    digest = pad is null ? new CbcBlockCipherMac(_blockAlgorithm.GenerateEngine(), _hashSize)
                        : new CbcBlockCipherMac(_blockAlgorithm.GenerateEngine(), _hashSize, pad);
                    break;

                case MACCipherMode.CFB:
                    int cfbs = ((ParametersWithIV)parameters).GetIV().Length * 8;
                    digest = pad is null ? new CfbBlockCipherMac(_blockAlgorithm.GenerateEngine(), cfbs, _hashSize)
                        : new CfbBlockCipherMac(_blockAlgorithm.GenerateEngine(), cfbs, _hashSize, pad);
                    break;

                default: throw new CryptographicException("Unsupported cipher mode.");
            }
            digest.Init(parameters);
            return digest;
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
            return _blockAlgorithm.GenerateParameters(key, iv);
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
            return _blockAlgorithm.GenerateParameters(key, keyOffset, keyLength, iv, ivOffset, ivLength);
        }

        /// <summary>
        /// Return mechanism.
        /// </summary>
        /// <returns></returns>
        public override string ToString()
        {
            return _mechanism;
        }

        /// <summary>
        /// Try get legal iv sizes.
        /// </summary>
        /// <param name="mode">MAC cipher mode.</param>
        /// <param name="ivSizes">Legal iv size bits.</param>
        /// <returns></returns>
        public bool TryGetIVSizes(MACCipherMode mode, out KeySizes[] ivSizes)
        {
            switch (mode)
            {
                case MACCipherMode.CBC: ivSizes = new KeySizes[] { new KeySizes(_blockAlgorithm.BlockSize, _blockAlgorithm.BlockSize, 0) }; return true;
                case MACCipherMode.CFB: ivSizes = new KeySizes[] { new KeySizes(8, _blockAlgorithm.BlockSize, 8) }; return true;
                default: break;
            }
            ivSizes = null;
            return false;
        }
    }
}