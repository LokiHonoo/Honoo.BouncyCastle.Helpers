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
        /// Symmetric algorithm kind.
        /// </summary>
        SymmetricAlgorithmKind AlgorithmKind { get; }

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
        /// Generate a new symmetric stream algorithm and decrypt data.
        /// </summary>
        /// <param name="parameters">Parameters.</param>
        /// <param name="data">Data.</param>
        /// <returns></returns>
        byte[] Decrypt(ICipherParameters parameters, byte[] data);

        /// <summary>
        /// Generate a new symmetric stream algorithm and decrypt data.
        /// </summary>
        /// <param name="parameters">Parameters.</param>
        /// <param name="data">Data.</param>
        /// <param name="offset">The starting offset to read.</param>
        /// <param name="length">The length to read.</param>
        /// <returns></returns>
        byte[] Decrypt(ICipherParameters parameters, byte[] data, int offset, int length);

        /// <summary>
        /// Generate a new symmetric stream algorithm and encrypt data.
        /// </summary>
        /// <param name="parameters">Parameters.</param>
        /// <param name="data">Data.</param>
        /// <returns></returns>
        byte[] Encrypt(ICipherParameters parameters, byte[] data);

        /// <param name="parameters">Parameters.</param>
        /// <param name="data">Data.</param>
        /// <param name="offset">The starting offset to read.</param>
        /// <param name="length">The length to read.</param>
        /// <returns></returns>
        byte[] Encrypt(ICipherParameters parameters, byte[] data, int offset, int length);

        /// <summary>
        /// Generate cipher.
        /// </summary>
        /// <param name="parameters">Parameters.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        IBufferedCipher GenerateDecryptor(ICipherParameters parameters);

        /// <summary>
        /// Generate cipher.
        /// </summary>
        /// <param name="parameters">Parameters.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        IBufferedCipher GenerateEncryptor(ICipherParameters parameters);

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