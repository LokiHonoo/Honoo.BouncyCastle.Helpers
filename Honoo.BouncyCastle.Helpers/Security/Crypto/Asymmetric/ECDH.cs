using Org.BouncyCastle.Crypto;
using System;
using System.Diagnostics.CodeAnalysis;

namespace Honoo.BouncyCastle.Helpers.Security.Crypto.Asymmetric
{
    /// <summary>
    /// ECDiffieHellman.
    /// </summary>
    public sealed class ECDH : AsymmetricAlgorithm
    {
        #region Constructor

        /// <summary>
        /// ECDiffieHellman.
        /// </summary>
        public ECDH() : base("ECDH", AsymmetricAlgorithmKind.Neither)
        {
        }

        #endregion Constructor

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
        /// <para/>Uses key size 256 bits, certainty 20 by default.
        /// </summary>
        /// <returns></returns>
        public IECDHTerminalA GenerateTerminalA()
        {
            return GenerateTerminalA(256, 20);
        }

        /// <summary>
        /// Generate ECDH terminal Alice.
        /// <para/>Uses certainty 20 by default.
        /// </summary>
        /// <param name="keySize">Key size bits.
        /// <para/>Can be Prime192v1, SecP224r1, Prime239v1, Prime256v1, SecP384r1, SecP521r1.
        /// </param>
        /// <returns></returns>
        public IECDHTerminalA GenerateTerminalA(int keySize)
        {
            return GenerateTerminalA(keySize, 20);
        }

        /// <summary>
        /// Generate ECDH terminal Alice.
        /// </summary>
        /// <param name="keySize">Key size bits.
        /// <para/>Can be Prime192v1, SecP224r1, Prime239v1, Prime256v1, SecP384r1, SecP521r1.
        /// </param>
        /// <param name="certainty">Certainty.</param>
        /// <returns></returns>
        [SuppressMessage("Performance", "CA1822:将成员标记为 static", Justification = "<挂起>")]
        public IECDHTerminalA GenerateTerminalA(int keySize, int certainty)
        {
            return new ECDHTerminalA(keySize, certainty);
        }

        /// <summary>
        /// Generate ECDH terminal Bob.
        /// </summary>
        /// <param name="exchangeA">Terminal Alice's exchange.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        [SuppressMessage("Performance", "CA1822:将成员标记为 static", Justification = "<挂起>")]
        public IECDHTerminalB GenerateTerminalB(byte[] exchangeA)
        {
            return new ECDHTerminalB(exchangeA);
        }
    }
}