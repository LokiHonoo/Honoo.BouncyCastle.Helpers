using Org.BouncyCastle.Crypto;
using System;

namespace Honoo.BouncyCastle.Helpers
{
    /// <summary>
    /// HMAC interface.
    /// </summary>
    public interface IHMAC
    {
        /// <summary>
        /// Gets hash size bits.
        /// </summary>
        int HashSize { get; }

        /// <summary>
        /// Gets mechanism.
        /// </summary>
        string Mechanism { get; }

        /// <summary>
        /// Generate a new digest and compute data hash.
        /// </summary>
        /// <param name="parameters">Parameters.</param>
        /// <param name="data">Data bytes.</param>
        /// <returns></returns>
        byte[] ComputeHash(ICipherParameters parameters, byte[] data);

        /// <summary>
        /// Generate a new digest and compute data hash.
        /// </summary>
        /// <param name="parameters">Parameters.</param>
        /// <param name="data">Data buffer bytes.</param>
        /// <param name="offset">The starting offset to read.</param>
        /// <param name="length">The length to read.</param>
        /// <returns></returns>
        byte[] ComputeHash(ICipherParameters parameters, byte[] data, int offset, int length);

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
        /// <param name="key">Any length can be used except null.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        ICipherParameters GenerateParameters(byte[] key);

        /// <summary>
        /// Generate parameters.
        /// </summary>
        /// <param name="key">Key buffer.</param>
        /// <param name="offset">The starting offset to read.</param>
        /// <param name="length">The length to read.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        ICipherParameters GenerateParameters(byte[] key, int offset, int length);

        /// <summary>
        /// Return mechanism.
        /// </summary>
        /// <returns></returns>
        string ToString();
    }
}