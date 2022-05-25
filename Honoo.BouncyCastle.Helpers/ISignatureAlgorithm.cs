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
        /// Gets signature algorithm mechanism.
        /// </summary>
        string Mechanism { get; }

        /// <summary>
        /// Gets signature algorithm oid. It's maybe 'null' if not supported.
        /// </summary>
        DerObjectIdentifier Oid { get; }

        /// <summary>
        /// Generate key pair by the corresponding asymmetric algorithm.
        /// </summary>
        /// <returns></returns>
        AsymmetricCipherKeyPair GenerateKeyPair();

        /// <summary>
        /// Generate signer. The signer can be reused.
        /// </summary>
        /// <param name="asymmetricKey">Asymmetric public key or private key.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        ISigner GenerateSigner(AsymmetricKeyParameter asymmetricKey);

        /// <summary>
        /// Generate a new signature algorithm and sign data.
        /// </summary>
        /// <param name="asymmetricKey">Asymmetric private key.</param>
        /// <param name="data">Data.</param>
        /// <returns></returns>
        byte[] Sign(AsymmetricKeyParameter asymmetricKey, byte[] data);

        /// <summary>
        /// Generate a new signature algorithm and sign data.
        /// </summary>
        /// <param name="asymmetricKey">Asymmetric private key.</param>
        /// <param name="data">Data.</param>
        /// <param name="offset">The starting offset to read.</param>
        /// <param name="length">The length to read.</param>
        /// <returns></returns>
        byte[] Sign(AsymmetricKeyParameter asymmetricKey, byte[] data, int offset, int length);

        /// <summary>
        /// Return mechanism.
        /// </summary>
        /// <returns></returns>
        string ToString();

        /// <summary>
        /// Generate a new signature algorithm and verify data.
        /// </summary>
        /// <param name="asymmetricKey">Asymmetric public key.</param>
        /// <param name="data">Data.</param>
        /// <param name="signature">Signature.</param>
        /// <returns></returns>
        bool Verify(AsymmetricKeyParameter asymmetricKey, byte[] data, byte[] signature);

        /// <summary>
        /// Generate a new signature algorithm and sign data.
        /// </summary>
        /// <param name="asymmetricKey">Asymmetric public key.</param>
        /// <param name="data">Data.</param>
        /// <param name="offset">The starting offset to read.</param>
        /// <param name="length">The length to read.</param>
        /// <param name="signature">Signature.</param>
        /// <param name="signatureOffset">The starting offset to read.</param>
        /// <param name="signatureLength">The length to read.</param>
        /// <returns></returns>
        bool Verify(AsymmetricKeyParameter asymmetricKey, byte[] data, int offset, int length, byte[] signature, int signatureOffset, int signatureLength);
    }
}