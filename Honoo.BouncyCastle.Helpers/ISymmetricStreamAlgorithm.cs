using Org.BouncyCastle.Crypto;
using System;
using System.Security.Cryptography;

namespace Honoo.BouncyCastle.Helpers
{
    /// <summary>
    /// Symmetric stream algorithm interface.
    /// </summary>
    public interface ISymmetricStreamAlgorithm : ISymmetricAlgorithm
    {
        /// <summary>
        /// Gets legal IV size bits.
        /// </summary>
        KeySizes[] LegalIVSizes { get; }

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
        /// <param name="dataBuffer">Data buffer bytes.</param>
        /// <param name="offset">The starting offset to read.</param>
        /// <param name="length">The length to read.</param>
        /// <returns></returns>
        byte[] Decrypt(ICipherParameters parameters, byte[] dataBuffer, int offset, int length);

        /// <summary>
        /// Generate a new symmetric stream algorithm and encrypt data.
        /// </summary>
        /// <param name="parameters">Parameters.</param>
        /// <param name="data">Data.</param>
        /// <returns></returns>
        byte[] Encrypt(ICipherParameters parameters, byte[] data);

        /// <param name="parameters">Parameters.</param>
        /// <param name="dataBuffer">Data buffer bytes.</param>
        /// <param name="offset">The starting offset to read.</param>
        /// <param name="length">The length to read.</param>
        /// <returns></returns>
        byte[] Encrypt(ICipherParameters parameters, byte[] dataBuffer, int offset, int length);

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
        /// Verify IV size.
        /// </summary>
        /// <param name="ivSize">IV size bits.</param>
        /// <returns></returns>
        bool VerifyIVSize(int ivSize);
    }
}