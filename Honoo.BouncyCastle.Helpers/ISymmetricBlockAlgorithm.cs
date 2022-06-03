using Org.BouncyCastle.Crypto;
using System;
using System.Security.Cryptography;

namespace Honoo.BouncyCastle.Helpers
{
    /// <summary>
    /// Symmetric block algorithm interface.
    /// </summary>
    public interface ISymmetricBlockAlgorithm : ISymmetricAlgorithm
    {
        /// <summary>
        /// Gets block size bits.
        /// </summary>
        int BlockSize { get; }

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
        /// <param name="dataBuffer">Data buffer.</param>
        /// <param name="offset">The starting offset to read.</param>
        /// <param name="length">The length to read.</param>
        /// <returns></returns>
        byte[] Decrypt(SymmetricCipherMode mode, SymmetricPaddingMode padding, ICipherParameters parameters, byte[] dataBuffer, int offset, int length);

        /// <summary>
        /// Generate a new Symmetric block algorithm and decrypt data.
        /// </summary>
        /// <param name="mode">Symmetric algorithm aead cipher mode.</param>
        /// <param name="parameters">Parameters.</param>
        /// <param name="data">Data.</param>
        /// <returns></returns>
        byte[] Decrypt(SymmetricAeadCipherMode mode, ICipherParameters parameters, byte[] data);

        /// <summary>
        /// Generate a new Symmetric block algorithm and decrypt data.
        /// </summary>
        /// <param name="mode">Symmetric algorithm aead cipher mode.</param>
        /// <param name="parameters">Parameters.</param>
        /// <param name="dataBuffer">Data buffer.</param>
        /// <param name="offset">The starting offset to read.</param>
        /// <param name="length">The length to read.</param>
        /// <returns></returns>
        byte[] Decrypt(SymmetricAeadCipherMode mode, ICipherParameters parameters, byte[] dataBuffer, int offset, int length);

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
        /// <param name="dataBuffer">Data buffer.</param>
        /// <param name="offset">The starting offset to read.</param>
        /// <param name="length">The length to read.</param>
        /// <returns></returns>
        byte[] Encrypt(SymmetricCipherMode mode, SymmetricPaddingMode padding, ICipherParameters parameters, byte[] dataBuffer, int offset, int length);

        /// <summary>
        /// Generate a new Symmetric block algorithm and encrypt data.
        /// </summary>
        /// <param name="mode">Symmetric algorithm aead cipher mode.</param>
        /// <param name="parameters">Parameters.</param>
        /// <param name="data">Data.</param>
        /// <returns></returns>
        byte[] Encrypt(SymmetricAeadCipherMode mode, ICipherParameters parameters, byte[] data);

        /// <summary>
        /// Generate a new Symmetric block algorithm and encrypt data.
        /// </summary>
        /// <param name="mode">Symmetric algorithm aead cipher mode.</param>
        /// <param name="parameters">Parameters.</param>
        /// <param name="dataBuffer">Data buffer.</param>
        /// <param name="offset">The starting offset to read.</param>
        /// <param name="length">The length to read.</param>
        /// <returns></returns>
        byte[] Encrypt(SymmetricAeadCipherMode mode, ICipherParameters parameters, byte[] dataBuffer, int offset, int length);

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
        /// <param name="mode">Symmetric algorithm aead cipher mode.</param>
        /// <param name="parameters">Parameters.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        IBufferedCipher GenerateDecryptor(SymmetricAeadCipherMode mode, ICipherParameters parameters);

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
        /// Generate cipher. The cipher can be reused except GCM cipher mode.
        /// </summary>
        /// <param name="mode">Symmetric algorithm aead cipher mode.</param>
        /// <param name="parameters">Parameters.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        IBufferedCipher GenerateEncryptor(SymmetricAeadCipherMode mode, ICipherParameters parameters);

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
        /// Try get legal iv sizes.
        /// </summary>
        /// <param name="mode">Symmetric algorithm cipher mode.</param>
        /// <param name="padding">Symmetric algorithm padding mode.</param>
        /// <param name="ivSizes">Legal iv size bits.</param>
        /// <returns></returns>
        bool TryGetIVSizes(SymmetricCipherMode mode, SymmetricPaddingMode padding, out KeySizes[] ivSizes);

        /// <summary>
        /// Try get legal iv sizes.
        /// </summary>
        /// <param name="mode">Symmetric algorithm aead cipher mode.</param>
        /// <param name="ivSizes">Legal iv size bits.</param>
        /// <returns></returns>
        bool TryGetIVSizes(SymmetricAeadCipherMode mode, out KeySizes[] ivSizes);

        /// <summary>
        /// Try get legal mac sizes.
        /// </summary>
        /// <param name="mode">Symmetric algorithm aead cipher mode.</param>
        /// <param name="macSizes">Legal mac size bits.</param>
        /// <returns></returns>
        bool TryGetMacSizes(SymmetricAeadCipherMode mode, out KeySizes[] macSizes);

        /// <summary>
        /// Try get legal nonce sizes.
        /// </summary>
        /// <param name="mode">Symmetric algorithm aead cipher mode.</param>
        /// <param name="nonceSizes">Legal nonce size bits.</param>
        /// <returns></returns>
        bool TryGetNonceSizes(SymmetricAeadCipherMode mode, out KeySizes[] nonceSizes);

        /// <summary>
        /// Verify iv size.
        /// </summary>
        /// <param name="mode">Symmetric algorithm cipher mode.</param>
        /// <param name="padding">Symmetric algorithm padding mode.</param>
        /// <param name="ivSize">IV size bits.</param>
        /// <returns></returns>
        bool VerifyIVSize(SymmetricCipherMode mode, SymmetricPaddingMode padding, int ivSize);

        /// <summary>
        /// Verify iv size.
        /// </summary>
        /// <param name="mode">Symmetric algorithm aead cipher mode.</param>
        /// <param name="ivSize">IV size bits.</param>
        /// <returns></returns>
        bool VerifyIVSize(SymmetricAeadCipherMode mode, int ivSize);

        /// <summary>
        /// Verify mac size.
        /// </summary>
        /// <param name="mode">Symmetric algorithm aead cipher mode.</param>
        /// <param name="macSize">Mac size bits.</param>
        /// <returns></returns>
        bool VerifyMacSize(SymmetricAeadCipherMode mode, int macSize);

        /// <summary>
        /// Verify nonce size.
        /// </summary>
        /// <param name="mode">Symmetric algorithm aead cipher mode.</param>
        /// <param name="nonceSizes">Nonce size bits.</param>
        /// <returns></returns>
        bool VerifyNonceSize(SymmetricAeadCipherMode mode, int nonceSizes);
    }
}