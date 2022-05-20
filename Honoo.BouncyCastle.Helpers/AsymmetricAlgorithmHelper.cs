using Honoo.BouncyCastle.Helpers.Security.Crypto.Asymmetric;

namespace Honoo.BouncyCastle.Helpers
{
    /// <summary>
    /// Asymmetric algorithm helper.
    /// </summary>
    public static class AsymmetricAlgorithmHelper
    {
        /// <summary>
        /// Legal key size 512-1024 bits (64 bits increments).
        /// <para/>Uses key size 1024 bits, certainty 80 by default.
        /// </summary>
        public static IAsymmetricAlgorithm DSA { get; } = new DSA();

        /// <summary>
        /// Uses EllipticCurve.SecP256r1 by default.
        /// </summary>
        public static IAsymmetricAlgorithm ECDSA { get; } = new ECDSA();

        /// <summary>
        /// Uses EllipticCurve.GostR3410x2001CryptoProA by default.
        /// </summary>
        public static IAsymmetricAlgorithm ECGOST3410 { get; } = new ECGOST3410();

        /// <summary>
        ///
        /// </summary>
        public static IAsymmetricAlgorithm Ed25519 { get; } = new Ed25519();

        /// <summary>
        ///
        /// </summary>
        public static IAsymmetricAlgorithm Ed448 { get; } = new Ed448();

        /// <summary>
        /// Legal key size is more than or equal to 256 bits (64 bits increments).
        /// <para/>Uses key size 768 bits, certainty 20 by default.
        /// </summary>
        public static IAsymmetricEncryptionAlgorithm ElGamal { get; } = new ElGamal();

        /// <summary>
        /// Legal key size 512, 1024 bits.
        /// <para/>Uses key size 1024 bits, procedure 2 by default.
        /// </summary>
        public static IAsymmetricAlgorithm GOST3410 { get; } = new GOST3410();

        /// <summary>
        /// Legal key size is more than or equal to 512 bits (64 bits increments).
        /// <para/>Uses key size 2048 bits, certainty 25 by default.
        /// </summary>
        public static IAsymmetricEncryptionAlgorithm RSA { get; } = new RSA();

        /// <summary>
        /// SM2.
        /// </summary>
        public static IAsymmetricAlgorithm SM2 { get; } = new SM2();

        /// <summary>
        /// Try get algorithm from mechanism.
        /// </summary>
        /// <param name="mechanism">Algorithm mechanism.</param>
        /// <param name="algorithm">Algorithm.</param>
        /// <returns></returns>
        public static bool TryGetAlgorithm(string mechanism, out IAsymmetricAlgorithm algorithm)
        {
            mechanism = mechanism.Replace('_', '-').ToUpperInvariant();
            switch (mechanism)
            {
                case "DSA": algorithm = DSA; return true;
                case "ECDSA": algorithm = ECDSA; return true;
                case "ECGOST3410": case "ECGOST3410-2001": case "ECGOST-3410": case "ECGOST-3410-2001": algorithm = ECGOST3410; return true;
                case "ED25519": algorithm = new Ed25519(); return true;
                case "ED448": algorithm = new Ed448(); return true;
                case "ELGAMAL": algorithm = (IAsymmetricAlgorithm)ElGamal; return true;
                case "GOST3410": case "GOST3410-94": case "GOST-3410": case "GOST-3410-94": algorithm = GOST3410; return true;
                case "RSA": algorithm = (IAsymmetricAlgorithm)RSA; return true;
                case "SM2": algorithm = SM2; return true;
                default: algorithm = null; return false;
            }
        }

        /// <summary>
        /// Try get algorithm from mechanism.
        /// </summary>
        /// <param name="mechanism">Algorithm mechanism.</param>
        /// <param name="algorithm">Algorithm.</param>
        /// <returns></returns>
        public static bool TryGetAlgorithm(string mechanism, out IAsymmetricEncryptionAlgorithm algorithm)
        {
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