using System;

namespace Honoo.BouncyCastle.Helpers
{
    /// <summary>
    /// ECDiffieHellman terminal Alice.
    /// </summary>
    public interface IECDHTerminalA
    {
        /// <summary>
        /// Exchange this bytes with terminal Bob.
        /// </summary>
        byte[] ExchangeA { get; }

        /// <summary>
        /// Derive key material from the terminal Bob's exchange.
        /// </summary>
        /// <param name="exchangeB">The terminal Bob's exchange.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        byte[] DeriveKeyMaterial(byte[] exchangeB);
    }
}