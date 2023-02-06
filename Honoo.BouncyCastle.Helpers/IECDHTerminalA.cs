using System;

namespace Honoo.BouncyCastle.Helpers
{
    /// <summary>
    /// ECDiffieHellman terminal Alice interface.
    /// </summary>
    public interface IECDHTerminalA
    {
        /// <summary>
        /// Exchange this bytes to terminal Bob.
        /// </summary>
        byte[] G { get; }

        /// <summary>
        /// Exchange this bytes to terminal Bob.
        /// </summary>
        byte[] P { get; }

        /// <summary>
        /// Exchange this bytes to terminal Bob.
        /// </summary>
        byte[] PublicKey { get; }

        /// <summary>
        /// Derive key material from the terminal Bob's exchange.
        /// </summary>
        /// <param name="publicKeyB">The terminal Bob's public key.</param>
        /// <param name="unsigned">Output unsigned bytes.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        byte[] DeriveKeyMaterial(byte[] publicKeyB, bool unsigned);
    }
}