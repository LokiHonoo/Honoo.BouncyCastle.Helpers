using Org.BouncyCastle.Crypto;
using System;

namespace Honoo.BouncyCastle.Helpers
{
    /// <summary>
    /// Asymmetric encryption algorithm interface.
    /// </summary>
    public interface IAsymmetricEncryptionAlgorithm
    {
        /// <summary>
        /// Gets mechanism.
        /// </summary>
        string Mechanism { get; }

        /// <summary>
        /// Generate cipher. The cipher can be reused.
        /// </summary>
        /// <param name="padding">Asymmetric algorithm padding mode.</param>
        /// <param name="asymmetricKey">Asymmetric public key or private key.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        IAsymmetricBlockCipher GenerateCipher(AsymmetricPaddingMode padding, AsymmetricKeyParameter asymmetricKey);

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