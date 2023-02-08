using Org.BouncyCastle.Asn1.Eac;
using Org.BouncyCastle.Crypto;
using System;

namespace Honoo.BouncyCastle.Helpers.Security.Crypto.Asymmetric
{
    /// <summary>
    /// ECDiffieHellman.
    /// </summary>
    public sealed class ECDH : AsymmetricAlgorithm
    {
        #region Construction

        /// <summary>
        /// ECDiffieHellman.
        /// </summary>
        public ECDH() : base("ECDH", EacObjectIdentifiers.id_CA_ECDH, AsymmetricAlgorithmKind.KeyExchange)
        {
        }

        #endregion Construction

        /// <summary>
        /// Generate Asymmetric key pair. Allways throw <see cref="NotImplementedException"/>.
        /// </summary>
        /// <returns></returns>
        /// <exception cref="NotImplementedException"></exception>
        public override AsymmetricCipherKeyPair GenerateKeyPair()
        {
            throw new NotImplementedException();
        }

        /// <summary>
        /// Generate ECDH terminal Alice.
        /// <para/>Uses certainty 20 by default.
        /// </summary>
        /// <param name="keySize">Key size.
        /// <para/>Legal key size Prime192v1, SecP224r1, Prime239v1, Prime256v1, SecP384r1, SecP521r1.
        /// </param>
        /// <returns></returns>
        public IECDHTerminalA GenerateTerminalA(int keySize)
        {
            return GenerateTerminalA(keySize, 20);
        }

        /// <summary>
        /// Generate ECDH terminal Alice.
        /// </summary>
        /// <param name="keySize">Key size.
        /// <para/>Legal key size Prime192v1, SecP224r1, Prime239v1, Prime256v1, SecP384r1, SecP521r1.
        /// </param>
        /// <param name="certainty">Certainty.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        public IECDHTerminalA GenerateTerminalA(int keySize, int certainty)
        {
            return new ECDHTerminalA(keySize, certainty);
        }

        /// <summary>
        /// Generate ECDH terminal Bob.
        /// </summary>
        /// <param name="pA">Terminal Alice's P value.</param>
        /// <param name="gA">Terminal Alice's G value.</param>
        /// <param name="publicKeyA">Terminal Alice's public key.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        public IECDHTerminalB GenerateTerminalB(byte[] pA, byte[] gA, byte[] publicKeyA)
        {
            return new ECDHTerminalB(pA, gA, publicKeyA);
        }
    }
}