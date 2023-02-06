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
    public sealed class CMAC : IEquatable<CMAC>, ICMAC
    {
        #region Properties

        private readonly SymmetricBlockAlgorithm _blockAlgorithm;
        private readonly int _hashSize;
        private readonly int _macSize;
        private readonly string _name;

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
        public KeySizes[] LegalKeySizes => _blockAlgorithm.LegalKeySizes;

        /// <summary>
        /// Gets mac size bits.
        /// </summary>
        public int MacSize => _macSize;

        /// <summary>
        /// Gets algorithm name.
        /// </summary>
        public string Name => _name;

        internal ISymmetricBlockAlgorithm BlockAlgorithm => _blockAlgorithm;

        #endregion Properties

        #region Construction

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
            _name = string.Format(CultureInfo.InvariantCulture, "{0}/CMAC", blockAlgorithm.Name);
            _blockAlgorithm = (SymmetricBlockAlgorithm)blockAlgorithm;
            _macSize = macSize;
            _hashSize = macSize;
        }

        #endregion Construction

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
        /// <param name="dataBuffer">Data buffer bytes.</param>
        /// <param name="offset">The starting offset to read.</param>
        /// <param name="length">The length to read.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        public byte[] ComputeHash(ICipherParameters parameters, byte[] dataBuffer, int offset, int length)
        {
            if (parameters == null)
            {
                throw new ArgumentNullException(nameof(parameters));
            }
            if (dataBuffer == null)
            {
                throw new ArgumentNullException(nameof(dataBuffer));
            }
            IMac digest = GenerateDigest(parameters);

            byte[] hash = new byte[_hashSize / 8];
            digest.BlockUpdate(dataBuffer, offset, length);
            digest.DoFinal(hash, 0);
            return hash;
        }

        /// <summary>
        /// Determines whether the specified object is equal to the current.
        /// </summary>
        /// <param name="other"></param>
        /// <returns></returns>
        public bool Equals(CMAC other)
        {
            return _name.Equals(other._name);
        }

        /// <summary>
        /// Determines whether the specified object is equal to the current.
        /// </summary>
        /// <param name="obj"></param>
        /// <returns></returns>
        public override bool Equals(object obj)
        {
            return Equals((CMAC)obj);
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
        /// <param name="keyBuffer">Key buffer bytes.</param>
        /// <param name="offset">The starting offset to read.</param>
        /// <param name="length">The length to read.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        public ICipherParameters GenerateParameters(byte[] keyBuffer, int offset, int length)
        {
            return _blockAlgorithm.GenerateParameters(keyBuffer, offset, length, null, 0, 0);
        }

        /// <summary>
        /// Returns the hash code for this object.
        /// </summary>
        /// <returns></returns>
        public override int GetHashCode()
        {
            return _name.GetHashCode();
        }

        /// <summary>
        /// Return algorithm name.
        /// </summary>
        /// <returns></returns>
        public override string ToString()
        {
            return _name;
        }

        /// <summary>
        /// Verify key size.
        /// </summary>
        /// <param name="keySize">Key size bits.</param>
        /// <returns></returns>
        public bool VerifyKeySize(int keySize)
        {
            return _blockAlgorithm.VerifyKeySize(keySize);
        }
    }
}