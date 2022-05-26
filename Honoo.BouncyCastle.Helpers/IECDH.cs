using System;

namespace Honoo.BouncyCastle.Helpers
{
    /// <summary>
    /// ECDiffieHellman.
    /// </summary>
    public interface IECDH : IAsymmetricAlgorithm
    {
        /// <summary>
        /// Generate ECDH terminal Alice.
        /// <para/>Uses key size 256 bits, certainty 25 by default.
        /// </summary>
        /// <returns></returns>
        IECDHTerminalA GenerateTerminalA();

        /// <summary>
        /// Generate ECDH terminal Alice.
        /// </summary>
        /// <param name="keySize">
        /// <para/>Can be Prime192v1, SecP224r1, Prime239v1, Prime256v1, SecP384r1, SecP521r1.
        /// </param>
        /// <param name="certainty">Certainty.</param>
        /// <returns></returns>
        IECDHTerminalA GenerateTerminalA(int keySize, int certainty);

        /// <summary>
        /// Generate ECDH terminal Bob.
        /// </summary>
        /// <param name="exchangeA">Terminal Alice's exchange.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        IECDHTerminalB GenerateTerminalB(byte[] exchangeA);
    }
}