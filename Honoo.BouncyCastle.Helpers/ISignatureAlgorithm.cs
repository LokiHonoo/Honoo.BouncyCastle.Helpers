using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Crypto;
using System;

namespace Honoo.BouncyCastle.Helpers
{
    /// <summary>
    /// Signature algorithm.
    /// </summary>
    public interface ISignatureAlgorithm
    {
        /// <summary>
        /// Gets the corresponding asymmetric algorithm.
        /// </summary>
        IAsymmetricAlgorithm AsymmetricAlgorithm { get; }

        /// <summary>
        /// Gets signature algorithm mechanism.
        /// </summary>
        string Mechanism { get; }

        /// <summary>
        /// Gets signature algorithm oid. It's maybe 'null' if not supported.
        /// </summary>
        DerObjectIdentifier Oid { get; }

        /// <summary>
        /// Generate signer. The signer can be reused.
        /// </summary>
        /// <param name="asymmetricKey">Asymmetric public key or private key.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        ISigner GenerateSigner(AsymmetricKeyParameter asymmetricKey);

        /// <summary>
        /// Return mechanism.
        /// </summary>
        /// <returns></returns>
        string ToString();
    }
}