using Org.BouncyCastle.Crypto;
using System;
using System.Security.Cryptography;

namespace Honoo.BouncyCastle.Helpers
{
    /// <summary>
    /// Symmetric block algorithm interface.
    /// </summary>
    public interface IBlockAlgorithm
    {
        /// <summary>
        /// Gets block size bits.
        /// </summary>
        int BlockSize { get; }

        /// <summary>
        /// Gets legal key size bits.
        /// </summary>
        KeySizes[] KeySizes { get; }

        /// <summary>
        /// Gets mechanism.
        /// </summary>
        string Mechanism { get; }

        /// <summary>
        /// Generate a new Symmetric block algorithm and decrypt data.
        /// </summary>
        /// <param name="mode">Symmetric algorithm cipher mode.</param>
        /// <param name="padding">Symmetric algorithm padding mode.</param>
        /// <param name="parameters">Parameters.</param>
        /// <param name="data">Data.</param>
        /// <returns></returns>
        byte[] Decrypt(SymmetricCipherMode mode, SymmetricPaddingMode padding, ICipherParameters parameters, byte[] data);

        /// <summary>
        /// Generate a new Symmetric block algorithm and decrypt data.
        /// </summary>
        /// <param name="mode">Symmetric algorithm cipher mode.</param>
        /// <param name="padding">Symmetric algorithm padding mode.</param>
        /// <param name="parameters">Parameters.</param>
        /// <param name="data">Data.</param>
        /// <param name="offset">The starting offset to read.</param>
        /// <param name="length">The length to read.</param>
        /// <returns></returns>
        byte[] Decrypt(SymmetricCipherMode mode, SymmetricPaddingMode padding, ICipherParameters parameters, byte[] data, int offset, int length);

        /// <summary>
        /// Generate a new Symmetric block algorithm and encrypt data.
        /// </summary>
        /// <param name="mode">Symmetric algorithm cipher mode.</param>
        /// <param name="padding">Symmetric algorithm padding mode.</param>
        /// <param name="parameters">Parameters.</param>
        /// <param name="data">Data.</param>
        /// <returns></returns>
        byte[] Encrypt(SymmetricCipherMode mode, SymmetricPaddingMode padding, ICipherParameters parameters, byte[] data);

        /// <summary>
        /// Generate a new Symmetric block algorithm and encrypt data.
        /// </summary>
        /// <param name="mode">Symmetric algorithm cipher mode.</param>
        /// <param name="padding">Symmetric algorithm padding mode.</param>
        /// <param name="parameters">Parameters.</param>
        /// <param name="data">Data.</param>
        /// <param name="offset">The starting offset to read.</param>
        /// <param name="length">The length to read.</param>
        /// <returns></returns>
        byte[] Encrypt(SymmetricCipherMode mode, SymmetricPaddingMode padding, ICipherParameters parameters, byte[] data, int offset, int length);

        /// <summary>
        /// Generate cipher. The cipher can be reused except GCM cipher mode.
        /// </summary>
        /// <param name="mode">Symmetric algorithm cipher mode.</param>
        /// <param name="padding">Symmetric algorithm padding mode.</param>
        /// <param name="parameters">Parameters.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        IBufferedCipher GenerateDecryptor(SymmetricCipherMode mode, SymmetricPaddingMode padding, ICipherParameters parameters);

        /// <summary>
        /// Generate cipher. The cipher can be reused except GCM cipher mode.
        /// </summary>
        /// <param name="mode">Symmetric algorithm cipher mode.</param>
        /// <param name="padding">Symmetric algorithm padding mode.</param>
        /// <param name="parameters">Parameters.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        IBufferedCipher GenerateEncryptor(SymmetricCipherMode mode, SymmetricPaddingMode padding, ICipherParameters parameters);

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
        /// Generate parameters.
        /// </summary>
        /// <param name="key">Key bytes.</param>
        /// <param name="nonce">Nonce bytes.</param>
        /// <param name="macSize">MAC size bits.</param>
        /// <param name="associatedText">Associated text bytes.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        ICipherParameters GenerateParameters(byte[] key, byte[] nonce, int macSize, byte[] associatedText);

        /// <summary>
        /// Return mechanism.
        /// </summary>
        /// <returns></returns>
        string ToString();

        /// <summary>
        /// Try get legal iv sizes.
        /// </summary>
        /// <param name="mode">Symmetric algorithm cipher mode.</param>
        /// <param name="padding">Symmetric algorithm padding mode.</param>
        /// <param name="ivSizes">Legal iv size bits.</param>
        /// <returns></returns>
        bool TryGetIVSizes(SymmetricCipherMode mode, SymmetricPaddingMode padding, out KeySizes[] ivSizes);

        /// <summary>
        /// Try get legal mac sizes.
        /// </summary>
        /// <param name="mode">Symmetric algorithm cipher mode.</param>
        /// <param name="padding">Symmetric algorithm padding mode.</param>
        /// <param name="macSizes">Legal mac size bits.</param>
        /// <returns></returns>
        bool TryGetMacSizes(SymmetricCipherMode mode, SymmetricPaddingMode padding, out KeySizes[] macSizes);

        /// <summary>
        /// Try get legal nonce sizes.
        /// </summary>
        /// <param name="mode">Symmetric algorithm cipher mode.</param>
        /// <param name="padding">Symmetric algorithm padding mode.</param>
        /// <param name="nonceSizes">Legal nonce size bits.</param>
        /// <returns></returns>
        bool TryGetNonceSizes(SymmetricCipherMode mode, SymmetricPaddingMode padding, out KeySizes[] nonceSizes);
    }
}