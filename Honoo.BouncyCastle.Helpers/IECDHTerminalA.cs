using System;

namespace Honoo.BouncyCastle.Helpers
{
    /// <summary>
    /// ECDiffieHellman terminal Alice interface.
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
        /// <param name="unsigned">Output unsigned bytes.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        byte[] DeriveKeyMaterial(byte[] exchangeB, bool unsigned);
    }
}