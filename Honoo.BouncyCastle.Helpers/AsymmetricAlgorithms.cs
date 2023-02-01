using Honoo.BouncyCastle.Helpers.Security.Crypto.Asymmetric;

namespace Honoo.BouncyCastle.Helpers
{
    /// <summary>
    /// Some asymmetric algorithms.
    /// </summary>
    public static class AsymmetricAlgorithms
    {
        /// <summary>
        /// DSA.
        /// <para/>Legal key size 512-1024 bits (64 bits increments).
        /// </summary>
        public static DSA DSA { get; } = new DSA();

        /// <summary>
        /// ECDH.
        /// </summary>
        public static ECDH ECDH { get; } = new ECDH();

        /// <summary>
        /// ECDSA.
        /// </summary>
        public static ECDSA ECDSA { get; } = new ECDSA();

        /// <summary>
        /// ECGOST3410.
        /// </summary>
        public static ECGOST3410 ECGOST3410 { get; } = new ECGOST3410();

        /// <summary>
        /// Ed25519.
        /// </summary>
        public static Ed25519 Ed25519 { get; } = new Ed25519();

        /// <summary>
        /// Ed448.
        /// </summary>
        public static Ed448 Ed448 { get; } = new Ed448();

        /// <summary>
        /// ElGamal.
        /// <para/>Legal key size is more than or equal to 8 bits (8 bits increments).
        /// </summary>
        public static ElGamal ElGamal { get; } = new ElGamal();

        /// <summary>
        /// GOST3410
        /// <para/>Legal key size 512, 1024 bits.
        /// </summary>
        public static GOST3410 GOST3410 { get; } = new GOST3410();

        /// <summary>
        /// RSA.
        /// <para/>Legal key size is more than or equal to 24 bits (8 bits increments).
        /// </summary>
        public static RSA RSA { get; } = new RSA();

        /// <summary>
        /// SM2.
        /// </summary>
        public static SM2 SM2 { get; } = new SM2();
    }
}