using Org.BouncyCastle.Crypto;
using System;
using System.Security.Cryptography;

namespace Honoo.BouncyCastle.Helpers
{
    /// <summary>
    /// Symmetric algorithm interface.
    /// </summary>
    public interface ISymmetricAlgorithm
    {
        /// <summary>
        /// Gets legal key size bits.
        /// </summary>
        KeySizes[] KeySizes { get; }

        /// <summary>
        /// Symmetric algorithm kind.
        /// </summary>
        SymmetricAlgorithmKind Kind { get; }

        /// <summary>
        /// Gets algorithm name.
        /// </summary>
        string Name { get; }

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
        /// <param name="keyBuffer">Key buffer bytes.</param>
        /// <param name="keyOffset">The starting offset to read.</param>
        /// <param name="keyLength">The length to read.</param>
        /// <param name="ivBuffer">IV buffer bytes.</param>
        /// <param name="ivOffset">The starting offset to read.</param>
        /// <param name="ivLength">The length to read.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        ICipherParameters GenerateParameters(byte[] keyBuffer, int keyOffset, int keyLength, byte[] ivBuffer, int ivOffset, int ivLength);

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