using Honoo.BouncyCastle.Helpers.Security.Crypto.Asymmetric;

namespace Honoo.BouncyCastle.Helpers
{
    /// <summary>
    /// Asymmetric algorithm helper.
    /// </summary>
    public static class AsymmetricAlgorithmHelper
    {
        /// <summary>
        /// DSA.
        /// <para/>Legal key size 512-1024 bits (64 bits increments).
        /// </summary>
        public static IAsymmetricAlgorithm DSA { get; } = new DSA();

        /// <summary>
        /// ECDH.
        /// </summary>
        public static IAsymmetricAlgorithm ECDH { get; } = new ECDH();

        /// <summary>
        /// ECDSA.
        /// <para/>Legal key size 512-1024 bits (64 bits increments).
        /// </summary>
        public static IAsymmetricAlgorithm ECDSA { get; } = new ECDSA();

        /// <summary>
        /// ECGOST3410.
        /// </summary>
        public static IAsymmetricAlgorithm ECGOST3410 { get; } = new ECGOST3410();

        /// <summary>
        /// Ed25519.
        /// </summary>
        public static IAsymmetricAlgorithm Ed25519 { get; } = new Ed25519();

        /// <summary>
        /// Ed448.
        /// </summary>
        public static IAsymmetricAlgorithm Ed448 { get; } = new Ed448();

        /// <summary>
        /// ElGamal.
        /// <para/>Legal key size is more than or equal to 256 bits (64 bits increments).
        /// </summary>
        public static IAsymmetricEncryptionAlgorithm ElGamal { get; } = new ElGamal();

        /// <summary>
        /// GOST3410
        /// <para/>Legal key size 512, 1024 bits.
        /// </summary>
        public static IAsymmetricAlgorithm GOST3410 { get; } = new GOST3410();

        /// <summary>
        /// RSA.
        /// <para/>Legal key size is more than or equal to 512 bits (64 bits increments).
        /// </summary>
        public static IAsymmetricEncryptionAlgorithm RSA { get; } = new RSA();

        /// <summary>
        /// SM2.
        /// </summary>
        public static IAsymmetricAlgorithm SM2 { get; } = new SM2();

        /// <summary>
        /// Try get asymmetric algorithm from mechanism.
        /// </summary>
        /// <param name="mechanism">Asymmetric algorithm mechanism.</param>
        /// <param name="algorithm">Asymmetric algorithm.</param>
        /// <returns></returns>
        public static bool TryGetAlgorithm(string mechanism, out IAsymmetricAlgorithm algorithm)
        {
            if (string.IsNullOrWhiteSpace(mechanism))
            {
                algorithm = null;
                return false;
            }
            mechanism = mechanism.Replace('_', '-').ToUpperInvariant();
            switch (mechanism)
            {
                case "DSA": algorithm = DSA; return true;
                case "ECDH": algorithm = ECDH; return true;
                case "ECDSA": algorithm = ECDSA; return true;
                case "ECGOST3410": case "ECGOST3410-2001": algorithm = ECGOST3410; return true;
                case "ED25519": algorithm = new Ed25519(); return true;
                case "ED448": algorithm = new Ed448(); return true;
                case "ELGAMAL": algorithm = (IAsymmetricAlgorithm)ElGamal; return true;
                case "GOST3410": case "GOST3410-94": algorithm = GOST3410; return true;
                case "RSA": algorithm = (IAsymmetricAlgorithm)RSA; return true;
                case "SM2": algorithm = SM2; return true;
                default: algorithm = null; return false;
            }
        }

        /// <summary>
        /// Try get asymmetric algorithm from mechanism.
        /// </summary>
        /// <param name="mechanism">Asymmetric algorithm mechanism.</param>
        /// <param name="algorithm">Asymmetric algorithm.</param>
        /// <returns></returns>
        public static bool TryGetAlgorithm(string mechanism, out IAsymmetricEncryptionAlgorithm algorithm)
        {
            if (string.IsNullOrWhiteSpace(mechanism))
            {
                algorithm = null;
                return false;
            }
            mechanism = mechanism.ToUpperInvariant();
            switch (mechanism)
            {
                case "ELGAMAL": algorithm = ElGamal; return true;
                case "RSA": algorithm = RSA; return true;
                default: algorithm = null; return false;
            }
        }
    }
}