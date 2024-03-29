﻿using Org.BouncyCastle.Crypto;
using System;
using System.Security.Cryptography;

namespace Honoo.BouncyCastle.Helpers
{
    /// <summary>
    /// MAC interface.
    /// </summary>
    public interface IMAC
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
        KeySizes[] LegalKeySizes { get; }

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
        /// <param name="mode">MAC cipher mode.</param>
        /// <param name="padding">MAC padding mode.</param>
        /// <param name="parameters">Parameters.</param>
        /// <param name="data">Data bytes.</param>
        /// <returns></returns>
        byte[] ComputeHash(MACCipherMode mode, MACPaddingMode padding, ICipherParameters parameters, byte[] data);

        /// <summary>
        /// Generate a new digest and compute data hash.
        /// </summary>
        /// <param name="mode">MAC cipher mode.</param>
        /// <param name="padding">MAC padding mode.</param>
        /// <param name="parameters">Parameters.</param>
        /// <param name="dataBuffer">Data buffer bytes.</param>
        /// <param name="offset">The starting offset to read.</param>
        /// <param name="length">The length to read.</param>
        /// <returns></returns>
        byte[] ComputeHash(MACCipherMode mode, MACPaddingMode padding, ICipherParameters parameters, byte[] dataBuffer, int offset, int length);

        /// <summary>
        /// Generate digest. The digest can be reused.
        /// </summary>
        /// <param name="mode">MAC cipher mode.</param>
        /// <param name="padding">MAC padding mode.</param>
        /// <param name="parameters">Parameters.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        IMac GenerateDigest(MACCipherMode mode, MACPaddingMode padding, ICipherParameters parameters);

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
        /// Try get legal IV sizes.
        /// </summary>
        /// <param name="mode">MAC cipher mode.</param>
        /// <param name="padding">MAC padding mode.</param>
        /// <param name="ivSizes">Legal IV size bits.</param>
        /// <returns></returns>
        bool TryGetIVSizes(MACCipherMode mode, MACPaddingMode padding, out KeySizes[] ivSizes);

        /// <summary>
        /// Verify IV size.
        /// </summary>
        /// <param name="mode">MAC cipher mode.</param>
        /// <param name="padding">MAC padding mode.</param>
        /// <param name="ivSize">IV size bits.</param>
        /// <returns></returns>
        bool VerifyIVSize(MACCipherMode mode, MACPaddingMode padding, int ivSize);

        /// <summary>
        /// Verify key size.
        /// </summary>
        /// <param name="keySize">Key size bits.</param>
        /// <returns></returns>
        bool VerifyKeySize(int keySize);
    }
}