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

        /// <summary>
        /// Gets block size bits.
        /// </summary>
        public int BlockSize => this.BlockAlgorithm.BlockSize;

        /// <summary>
        /// Gets hash size bits.
        /// </summary>
        public int HashSize { get; }

        /// <summary>
        /// Gets legal key size bits.
        /// </summary>
        public KeySizes[] KeySizes
        { get { return (KeySizes[])this.BlockAlgorithm.KeySizes.Clone(); } }

        /// <summary>
        /// Gets mechanism.
        /// </summary>
        public string Mechanism { get; }

        internal BlockAlgorithm BlockAlgorithm { get; }

        #endregion Properties

        #region Constructor

        /// <summary>
        /// CMAC.
        /// <para/>Legal mac size is between 8 and block size (8 bits increments).
        /// <para/>Used block size as mac size by default.
        /// </summary>
        /// <param name="blockAlgorithm">Symmetric block algorithm.</param>
        public CMAC(IBlockAlgorithm blockAlgorithm) : this(blockAlgorithm, blockAlgorithm.BlockSize)
        {
        }

        /// <summary>
        /// CMAC.
        /// <para/>Legal mac size is between 8 and block size (8 bits increments).
        /// <para/>Used block size as mac size by default.
        /// </summary>
        /// <param name="blockAlgorithm">Symmetric block algorithm.</param>
        /// <param name="macSize">MAC size bits.</param>
        public CMAC(IBlockAlgorithm blockAlgorithm, int macSize)
        {
            if (blockAlgorithm.BlockSize != 64 && blockAlgorithm.BlockSize != 128)
            {
                throw new CryptographicException("Legal algorithms of block size 64 or 128 bits.");
            }
            if (macSize < 8 || macSize > blockAlgorithm.BlockSize || macSize % 8 != 0)
            {
                throw new CryptographicException("Legal mac size is between 8 and block size (8 bits increments).");
            }
            this.Mechanism = string.Format(CultureInfo.InvariantCulture, "{0}/CMAC", blockAlgorithm.Mechanism);
            this.BlockAlgorithm = (BlockAlgorithm)blockAlgorithm;
            this.HashSize = macSize;
        }

        #endregion Constructor

        /// <summary>
        /// Generate digest. The digest can be reused.
        /// </summary>
        /// <param name="parameters">Parameters.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        public IMac GenerateDigest(ICipherParameters parameters)
        {
            IMac digest = new CMac(this.BlockAlgorithm.GenerateEngine(), this.HashSize);
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
            return this.BlockAlgorithm.GenerateParameters(key, null);
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
            return this.BlockAlgorithm.GenerateParameters(key, offset, length, null, 0, 0);
        }

        /// <summary>
        /// Return mechanism.
        /// </summary>
        /// <returns></returns>
        public override string ToString()
        {
            return this.Mechanism;
        }
    }
}