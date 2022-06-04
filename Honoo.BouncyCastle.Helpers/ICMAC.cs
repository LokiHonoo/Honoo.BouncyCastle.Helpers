using Org.BouncyCastle.Crypto;
using System;
using System.Security.Cryptography;

namespace Honoo.BouncyCastle.Helpers
{
    /// <summary>
    /// CMAC interface.
    /// </summary>
    public interface ICMAC
    {
        /// <summary>
        /// Gets block size bits.
        /// </summary>
        int BlockSize { get; }

        /// <summary>
        /// Gets hash size bits.
        /// </summary>
        int HashSize { get; }

        /// <summary>
        /// Gets legal key size bits.
        /// </summary>
        KeySizes[] KeySizes { get; }

        /// <summary>
        /// Gets mac size bits.
        /// </summary>
        int MacSize { get; }

        /// <summary>
        /// Gets algorithm name.
        /// </summary>
        string Name { get; }

        /// <summary>
        /// Generate a new digest and compute data hash.
        /// </summary>
        /// <param name="parameters">Parameters.</param>
        /// <param name="data">Data bytes.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        byte[] ComputeHash(ICipherParameters parameters, byte[] data);

        /// <summary>
        /// Generate a new digest and compute data hash.
        /// </summary>
        /// <param name="parameters">Parameters.</param>
        /// <param name="dataBuffer">Data buffer bytes.</param>
        /// <param name="offset">The starting offset to read.</param>
        /// <param name="length">The length to read.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        byte[] ComputeHash(ICipherParameters parameters, byte[] dataBuffer, int offset, int length);

        /// <summary>
        /// Generate digest. The digest can be reused.
        /// </summary>
        /// <param name="parameters">Parameters.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        IMac GenerateDigest(ICipherParameters parameters);

        /// <summary>
        /// Generate parameters.
        /// </summary>
        /// <param name="key">Key bytes.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        ICipherParameters GenerateParameters(byte[] key);

        /// <summary>
        /// Generate parameters.
        /// </summary>
        /// <param name="keyBuffer">Key buffer bytes.</param>
        /// <param name="offset">The starting offset to read.</param>
        /// <param name="length">The length to read.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        ICipherParameters GenerateParameters(byte[] keyBuffer, int offset, int length);

        /// <summary>
        /// Return algorithm name.
        /// </summary>
        /// <returns></returns>
        string ToString();

        /// <summary>
        /// Verify key size.
        /// </summary>
        /// <param name="keySize">Key size bits.</param>
        /// <returns></returns>
        bool VerifyKeySize(int keySize);
    }
}