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
        /// Gets mechanism.
        /// </summary>
        string Mechanism { get; }

        /// <summary>
        /// Generate Key pair.
        /// </summary>
        /// <returns></returns>
        /// <exception cref="Exception"/>

        AsymmetricCipherKeyPair GenerateKeyPair();

        /// <summary>
        /// Return mechanism.
        /// </summary>
        /// <returns></returns>
        string ToString();
    }
}