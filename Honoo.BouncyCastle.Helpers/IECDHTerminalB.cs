using System;

namespace Honoo.BouncyCastle.Helpers
{
    /// <summary>
    /// ECDiffieHellman terminal Bob interface.
    /// </summary>
    public interface IECDHTerminalB
    {
        /// <summary>
        /// Exchange this bytes with terminal Alice.
        /// </summary>
        byte[] ExchangeB { get; }

        /// <summary>
        /// Derive key material.
        /// </summary>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        byte[] DeriveKeyMaterial();
    }
}