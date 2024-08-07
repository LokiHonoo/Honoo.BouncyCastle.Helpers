﻿namespace Honoo.BouncyCastle.Helpers
{
    /// <summary>
    /// Key exchange algorithm terminal B's interface.
    /// </summary>
    public interface IKeyExchangeTerminalB
    {
        /// <summary>
        /// Gets key size bits.
        /// </summary>
        int KeySize { get; }

        /// <summary>
        /// Gets the asymmetric algorithm kind of the algorithm.
        /// </summary>
        AsymmetricAlgorithmKind Kind { get; }

        /// <summary>
        /// Gets the asymmetric algorithm name of the algorithm.
        /// </summary>
        string Name { get; }

        /// <summary>
        /// Sand this value to terminal A.
        /// </summary>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Performance", "CA1819:属性不应返回数组", Justification = "<挂起>")]
        byte[] PublicKeyB { get; }

        /// <summary>
        /// Derive key material.
        /// </summary>
        /// <param name="unsignedMaterial">Output unsigned bytes.</param>
        /// <returns></returns>
        byte[] DeriveKeyMaterial(bool unsignedMaterial);

        /// <summary>
        /// Generate new parameters of algorithm terminal B, Using by terminal A's qualified parameters.
        /// </summary>
        /// <param name="p">The terminal A's P value.</param>
        /// <param name="g">The terminal A's G value.</param>
        /// <param name="publicKeyA">The terminal A's public key blob.</param>
        void GenerateParameters(byte[] p, byte[] g, byte[] publicKeyA);
    }
}