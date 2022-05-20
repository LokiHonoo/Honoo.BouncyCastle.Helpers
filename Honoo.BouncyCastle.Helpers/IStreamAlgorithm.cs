using Org.BouncyCastle.Crypto;
using System;
using System.Security.Cryptography;

namespace Honoo.BouncyCastle.Helpers
{
    /// <summary>
    /// Symmetric stream algorithm interface.
    /// </summary>
    public interface IStreamAlgorithm
    {
        /// <summary>
        /// Gets legal iv size bits.
        /// </summary>
        KeySizes[] IVSizes { get; }

        /// <summary>
        /// Gets legal key size bits.
        /// </summary>
        KeySizes[] KeySizes { get; }

        /// <summary>
        /// Gets mechanism.
        /// </summary>
        string Mechanism { get; }

        /// <summary>
        /// Generate cipher.
        /// </summary>
        /// <param name="forEncryption"></param>
        /// <param name="parameters">Parameters.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        IBufferedCipher GenerateCipher(bool forEncryption, ICipherParameters parameters);

        /// <summary>
        /// Generate parameters.
        /// </summary>
        /// <param name="key">Key bytes.</param>
        /// <param name="iv">IV bytes.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        ICipherParameters GenerateParameters(byte[] key, byte[] iv);

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
        ICipherParameters GenerateParameters(byte[] key, int keyOffset, int keyLength, byte[] iv, int ivOffset, int ivLength);

        /// <summary>
        /// Return mechanism.
        /// </summary>
        /// <returns></returns>
        string ToString();
    }
}