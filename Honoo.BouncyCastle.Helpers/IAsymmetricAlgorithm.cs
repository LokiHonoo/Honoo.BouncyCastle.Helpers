using Org.BouncyCastle.Crypto;
using System;

namespace Honoo.BouncyCastle.Helpers
{
    /// <summary>
    /// Asymmetric algorithm interface.
    /// </summary>
    public interface IAsymmetricAlgorithm
    {
        /// <summary>
        /// Asymmetric algorithm kind.
        /// </summary>
        AsymmetricAlgorithmKind Kind { get; }

        /// <summary>
        /// Gets algorithm name.
        /// </summary>
        string Name { get; }

        /// <summary>
        /// Generate Asymmetric key pair.
        /// </summary>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        AsymmetricCipherKeyPair GenerateKeyPair();

        /// <summary>
        /// Return algorithm name.
        /// </summary>
        /// <returns></returns>
        string ToString();
    }
}