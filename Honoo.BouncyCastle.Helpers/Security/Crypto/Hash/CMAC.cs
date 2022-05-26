using Honoo.BouncyCastle.Helpers.Security.Crypto.Symmetric;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Macs;
using System;
using System.Globalization;
using System.Security.Cryptography;

namespace Honoo.BouncyCastle.Helpers.Security.Crypto.Hash
{
    /// <summary>
    /// CMAC.
    /// <para/>Legal mac size is between 8 and block size (8 bits increments).
    /// <para/>Used block size as mac size by default.
    /// </summary>
    public sealed class CMAC : ICMAC
    {
        #region Properties

        private readonly SymmetricBlockAlgorithm _blockAlgorithm;
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

        internal ISymmetricBlockAlgorithm BlockAlgorithm => _blockAlgorithm;

        #endregion Properties

        #region Constructor

        /// <summary>
        /// CMAC.
        /// <para/>Legal mac size is between 8 and block size (8 bits increments).
        /// <para/>Default mac size used as block size.
        /// </summary>
        /// <param name="blockAlgorithm">Symmetric block algorithm.</param>
        public CMAC(ISymmetricBlockAlgorithm blockAlgorithm) : this(blockAlgorithm, blockAlgorithm.BlockSize)
        {
        }

        /// <summary>
        /// CMAC.
        /// <para/>Legal mac size is between 8 and block size (8 bits increments).
        /// <para/>Default mac size used as block size.
        /// </summary>
        /// <param name="blockAlgorithm">Symmetric block algorithm.</param>
        /// <param name="macSize">MAC size bits.</param>
        public CMAC(ISymmetricBlockAlgorithm blockAlgorithm, int macSize)
        {
            if (blockAlgorithm.BlockSize != 64 && blockAlgorithm.BlockSize != 128)
            {
                throw new CryptographicException("Legal algorithms of block size 64 or 128 bits.");
            }
            if (macSize < 8 || macSize > blockAlgorithm.BlockSize || macSize % 8 != 0)
            {
                throw new CryptographicException("Legal mac size is between 8 and block size (8 bits increments).");
            }
            _mechanism = string.Format(CultureInfo.InvariantCulture, "{0}/CMAC", blockAlgorithm.Mechanism);
            _blockAlgorithm = (SymmetricBlockAlgorithm)blockAlgorithm;
            _macSize = macSize;
            _hashSize = macSize;
        }

        #endregion Constructor

        /// <summary>
        /// Generate a new digest and compute data hash.
        /// </summary>
        /// <param name="parameters">Parameters.</param>
        /// <param name="data">Data bytes.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        public byte[] ComputeHash(ICipherParameters parameters, byte[] data)
        {
            return ComputeHash(parameters, data, 0, data.Length);
        }

        /// <summary>
        /// Generate a new digest and compute data hash.
        /// </summary>
        /// <param name="parameters">Parameters.</param>
        /// <param name="data">Data buffer bytes.</param>
        /// <param name="offset">The starting offset to read.</param>
        /// <param name="length">The length to read.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        public byte[] ComputeHash(ICipherParameters parameters, byte[] data, int offset, int length)
        {
            if (parameters is null)
            {
                throw new ArgumentNullException(nameof(parameters));
            }
            if (data is null)
            {
                throw new ArgumentNullException(nameof(data));
            }
            IMac digest = GenerateDigest(parameters);

            byte[] hash = new byte[_hashSize / 8];
            digest.BlockUpdate(data, offset, length);
            digest.DoFinal(hash, 0);
            return hash;
        }

        /// <summary>
        /// Generate digest. The digest can be reused.
        /// </summary>
        /// <param name="parameters">Parameters.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        public IMac GenerateDigest(ICipherParameters parameters)
        {
            IMac digest = new CMac(_blockAlgorithm.GenerateEngine(), _hashSize);
            digest.Init(parameters);
            return digest;
        }

        /// <summary>
        /// Generate parameters.
        /// </summary>
        /// <param name="key">Key bytes.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        public ICipherParameters GenerateParameters(byte[] key)
        {
            return _blockAlgorithm.GenerateParameters(key, null);
        }

        /// <summary>
        /// Generate parameters.
        /// </summary>
        /// <param name="key">Key buffer bytes.</param>
        /// <param name="offset">The starting offset to read.</param>
        /// <param name="length">The length to read.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        public ICipherParameters GenerateParameters(byte[] key, int offset, int length)
        {
            return _blockAlgorithm.GenerateParameters(key, offset, length, null, 0, 0);
        }

        /// <summary>
        /// Return mechanism.
        /// </summary>
        /// <returns></returns>
        public override string ToString()
        {
            return _mechanism;
        }
    }
}