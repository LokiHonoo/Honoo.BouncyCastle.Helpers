﻿using System;

namespace Honoo.BouncyCastle.Helpers
{
    /// <summary>
    /// Represents the abstract base class from which all implementations of hash algorithms must inherit.
    /// </summary>
    public abstract class HashAlgorithm
    {
        #region Properties

        private readonly int _hashSize;

        private readonly string _name;

        /// <summary>
        /// Gets hash size bits.
        /// </summary>
        public int HashSize => _hashSize;

        /// <summary>
        /// Gets algorithm name.
        /// </summary>
        public string Name => _name;

        #endregion Properties

        #region Construction

        /// <summary>
        /// Initializes a new instance of the HashAlgorithm class.
        /// </summary>
        /// <param name="name"></param>
        /// <param name="hashSize"></param>
        protected HashAlgorithm(string name, int hashSize)
        {
            _name = name;
            _hashSize = hashSize;
        }

        #endregion Construction

        /// <summary>
        /// Creates an instance of the algorithm by algorithm name.
        /// </summary>
        /// <param name="algorithmName">Hash algorithm name.</param>
        /// <returns></returns>
        public static HashAlgorithm Create(HashAlgorithmName algorithmName)
        {
            if (algorithmName == null)
            {
                throw new ArgumentNullException(nameof(algorithmName));
            }
            return algorithmName.GetAlgorithm.Invoke();
        }

        /// <summary>
        /// Creates an instance of the algorithm by algorithm name.
        /// </summary>
        /// <param name="mechanism">Asymmetric algorithm name.</param>
        /// <returns></returns>
        public static HashAlgorithm Create(string mechanism)
        {
            if (string.IsNullOrWhiteSpace(mechanism))
            {
                throw new ArgumentNullException(nameof(mechanism));
            }
            if (HashAlgorithmName.TryGetAlgorithmName(mechanism, out HashAlgorithmName algorithmName))
            {
                return algorithmName.GetAlgorithm();
            }
            return null;
        }

        /// <summary>
        /// Compute data hash.
        /// </summary>
        /// <returns></returns>
        public byte[] ComputeFinal()
        {
            byte[] result = new byte[_hashSize / 8];
            ComputeFinal(result, 0);
            return result;
        }

        /// <summary>
        /// Compute data hash.
        /// </summary>
        /// <param name="rgb">The data to be hash.</param>
        public byte[] ComputeFinal(byte[] rgb)
        {
            if (rgb == null)
            {
                throw new ArgumentNullException(nameof(rgb));
            }
            Update(rgb, 0, rgb.Length);
            return ComputeFinal();
        }

        /// <summary>
        /// Compute data hash.
        /// </summary>
        /// <param name="inputBuffer">The data buffer to be hash.</param>
        /// <param name="offset">The starting offset to read.</param>
        /// <param name="length">The length to read.</param>
        public byte[] ComputeFinal(byte[] inputBuffer, int offset, int length)
        {
            Update(inputBuffer, offset, length);
            return ComputeFinal();
        }

        /// <summary>
        /// Compute data hash.
        /// <br/>Write to output buffer and return hash byte length.
        /// </summary>
        /// <param name="outputBuffer">Output buffer.</param>
        /// <param name="offset">Write start offset from buffer.</param>
        /// <returns></returns>
        public abstract int ComputeFinal(byte[] outputBuffer, int offset);

        /// <summary>
        /// Compute data hash.
        /// <br/>Write to output buffer and return hash byte length.
        /// </summary>
        /// <param name="inputBuffer">The data buffer to be hash.</param>
        /// <param name="inputOffset">Read start offset from buffer.</param>
        /// <param name="inputLength">Read length from buffer.</param>
        /// <param name="outputBuffer">Output buffer.</param>
        /// <param name="outputOffset">Write start offset from buffer.</param>
        /// <returns></returns>
        /// <exception cref="Exception"></exception>
        public int ComputeFinal(byte[] inputBuffer, int inputOffset, int inputLength, byte[] outputBuffer, int outputOffset)
        {
            Update(inputBuffer, inputOffset, inputLength);
            return ComputeFinal(outputBuffer, outputOffset);
        }

        /// <summary>
        /// Reset calculator of the algorithm.
        /// </summary>
        public abstract void Reset();

        /// <summary>
        /// Compute data hash.
        /// </summary>
        /// <param name="rgb">The data to be hash.</param>
        public void Update(byte[] rgb)
        {
            if (rgb == null)
            {
                throw new ArgumentNullException(nameof(rgb));
            }
            Update(rgb, 0, rgb.Length);
        }

        /// <summary>
        /// Compute data hash.
        /// </summary>
        /// <param name="inputBuffer">The data buffer to be hash.</param>
        /// <param name="offset">The starting offset to read.</param>
        /// <param name="length">The length to read.</param>
        public abstract void Update(byte[] inputBuffer, int offset, int length);
    }
}