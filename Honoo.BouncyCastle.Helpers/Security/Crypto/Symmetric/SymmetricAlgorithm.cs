using Org.BouncyCastle.Crypto;
using System;
using System.Security.Cryptography;

namespace Honoo.BouncyCastle.Helpers.Security.Crypto.Symmetric
{
    /// <summary>
    /// Symmetric algorithm.
    /// </summary>
    public abstract class SymmetricAlgorithm : IEquatable<SymmetricAlgorithm>, ISymmetricAlgorithm
    {
        #region Properties

        private readonly SymmetricAlgorithmKind _kind;
        private readonly string _name;

        /// <summary>
        /// Gets legal key size bits.
        /// </summary>
        public abstract KeySizes[] KeySizes { get; }

        /// <summary>
        /// Symmetric algorithm kind.
        /// </summary>
        public SymmetricAlgorithmKind Kind => _kind;

        /// <summary>
        /// Gets algorithm name.
        /// </summary>
        public string Name => _name;

        #endregion Properties

        #region Constructor

        /// <summary>
        /// Symmetric algorithm.
        /// </summary>
        /// <param name="name">Symmetric algorithm name.</param>
        /// <param name="kind">Symmetric algorithm kind.</param>
        protected SymmetricAlgorithm(string name, SymmetricAlgorithmKind kind)
        {
            _name = name;
            _kind = kind;
        }

        #endregion Constructor

        /// <summary>
        /// Determines whether the specified object is equal to the current.
        /// </summary>
        /// <param name="other"></param>
        /// <returns></returns>
        public bool Equals(SymmetricAlgorithm other)
        {
            return _name.Equals(other._name);
        }

        /// <summary>
        /// Determines whether the specified object is equal to the current.
        /// </summary>
        /// <param name="obj"></param>
        /// <returns></returns>
        public override bool Equals(object obj)
        {
            return Equals((SymmetricAlgorithm)obj);
        }

        /// <summary>
        /// Generate parameters.
        /// </summary>
        /// <param name="key">Key bytes.</param>
        /// <param name="iv">IV bytes.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        public abstract ICipherParameters GenerateParameters(byte[] key, byte[] iv);

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
        public abstract ICipherParameters GenerateParameters(byte[] keyBuffer, int keyOffset, int keyLength, byte[] ivBuffer, int ivOffset, int ivLength);

        /// <summary>
        ///
        /// </summary>
        /// <returns></returns>
        public override int GetHashCode()
        {
            return _name.GetHashCode();
        }

        /// <summary>
        /// Return algorithm name.
        /// </summary>
        /// <returns></returns>
        public override string ToString()
        {
            return _name;
        }

        /// <summary>
        /// Verify key size.
        /// </summary>
        /// <param name="keySize">Key size bits.</param>
        /// <returns></returns>
        public abstract bool VerifyKeySize(int keySize);
    }
}