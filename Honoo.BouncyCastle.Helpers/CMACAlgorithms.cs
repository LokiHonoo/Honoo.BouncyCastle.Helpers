using Honoo.BouncyCastle.Helpers.Security.Crypto.Hash;

namespace Honoo.BouncyCastle.Helpers
{
    /// <summary>
    /// Some CMAC algorithms.
    /// </summary>
    public static class CMACAlgorithms
    {
        /// <summary>
        /// Hash size 128 bits. Legal key size 128, 192, 256 bits. Default mac size used as block size.
        /// </summary>
        public static ICMAC AES_CMAC { get; } = new CMAC(SymmetricAlgorithms.AES);

        /// <summary>
        /// Hash size 64 bits. Legal key size 128 bits. Default mac size used as block size.
        /// </summary>
        public static ICMAC Blowfish_CMAC { get; } = new CMAC(SymmetricAlgorithms.Blowfish);

        /// <summary>
        /// Hash size 128 bits. Legal key size 128, 192, 256 bits. Default mac size used as block size.
        /// </summary>
        public static ICMAC Camellia_CMAC { get; } = new CMAC(SymmetricAlgorithms.Camellia);

        /// <summary>
        /// Hash size 64 bits. Legal key size 40-128 bits (8 bits increments). Default mac size used as block size.
        /// </summary>
        public static ICMAC CAST5_CMAC { get; } = new CMAC(SymmetricAlgorithms.CAST5);

        /// <summary>
        /// Hash size 128 bits. Legal key size 128-256 bits (8 bits increments). Default mac size used as block size.
        /// </summary>
        public static ICMAC CAST6_CMAC { get; } = new CMAC(SymmetricAlgorithms.CAST6);

        /// <summary>
        /// Hash size 64 bits. Legal key size 64 bits. Default mac size used as block size.
        /// </summary>
        public static ICMAC DES_CMAC { get; } = new CMAC(SymmetricAlgorithms.DES);

        /// <summary>
        /// DESede, DESede3, TDEA, TripleDES, 3DES.
        /// <para/>Block size 64 bits. Legal key size 128, 192 bits. Default mac size used as block size.
        /// </summary>
        public static ICMAC DESede_CMAC { get; } = new CMAC(SymmetricAlgorithms.DESede);

        /// <summary>
        /// Hash size 128 bits. Legal key size 128, 256 bits. Default mac size used as block size.
        /// </summary>
        public static ICMAC DSTU7624_128_CMAC { get; } = new CMAC(SymmetricAlgorithms.DSTU7624_128);

        /// <summary>
        /// Hash size 64 bits. Legal key size 256 bits. Default mac size used as block size.
        /// </summary>
        public static ICMAC GOST28147_CMAC { get; } = new CMAC(SymmetricAlgorithms.GOST28147);

        /// <summary>
        /// Hash size 64 bits. Legal key size 8-128 bits (8 bits increments). Default mac size used as block size.
        /// </summary>
        public static ICMAC IDEA_CMAC { get; } = new CMAC(SymmetricAlgorithms.IDEA);

        /// <summary>
        /// Hash size 128 bits. Legal key size 128 bits. Default mac size used as block size.
        /// </summary>
        public static ICMAC Noekeon_CMAC { get; } = new CMAC(SymmetricAlgorithms.Noekeon);

        /// <summary>
        /// Hash size 64 bits. Legal key size 8-1024 bits (8 bits increments). Default mac size used as block size.
        /// </summary>
        public static ICMAC RC2_CMAC { get; } = new CMAC(SymmetricAlgorithms.RC2);

        /// <summary>
        /// Hash size 128 bits. Legal key size 8-2040 bits (8 bits increments). Default mac size used as block size.
        /// </summary>
        public static ICMAC RC5_64_CMAC { get; } = new CMAC(SymmetricAlgorithms.RC5_64);

        /// <summary>
        /// Hash size 64 bits. Legal key size 8-2040 bits (8 bits increments). Default mac size used as block size.
        /// </summary>
        public static ICMAC RC5_CMAC { get; } = new CMAC(SymmetricAlgorithms.RC5);

        /// <summary>
        /// Hash size 128 bits. Legal key size is more than or equal to 8 bits (8 bits increments). Default mac size used as block size.
        /// </summary>
        public static ICMAC RC6_CMAC { get; } = new CMAC(SymmetricAlgorithms.RC6);

        /// <summary>
        /// Hash size 128 bits. Legal key size 128, 160, 192, 224, 256 bits. Default mac size used as block size.
        /// </summary>
        public static ICMAC Rijndael_128_CMAC { get; } = new CMAC(SymmetricAlgorithms.Rijndael_128);

        /// <summary>
        /// Hash size 128 bits. Legal key size 128 bits. Default mac size used as block size.
        /// </summary>
        public static ICMAC SEED_CMAC { get; } = new CMAC(SymmetricAlgorithms.SEED);

        /// <summary>
        /// Hash size 128 bits. Legal key size 32-512 bits (32 bits increments). Default mac size used as block size.
        /// </summary>
        public static ICMAC Serpent_CMAC { get; } = new CMAC(SymmetricAlgorithms.Serpent);

        /// <summary>
        /// Hash size 64 bits. Legal key size 128 bits. Default mac size used as block size.
        /// </summary>
        public static ICMAC SKIPJACK_CMAC { get; } = new CMAC(SymmetricAlgorithms.SKIPJACK);

        /// <summary>
        /// Hash size 128 bits. Legal key size 128 bits. Default mac size used as block size.
        /// </summary>
        public static ICMAC SM4_CMAC { get; } = new CMAC(SymmetricAlgorithms.SM4);

        /// <summary>
        /// Hash size 64 bits. Legal key size 128 bits. Default mac size used as block size.
        /// </summary>
        public static ICMAC TEA_CMAC { get; } = new CMAC(SymmetricAlgorithms.TEA);

        /// <summary>
        /// Hash size 128 bits. Legal key size 32-512 bits (32 bits increments). Default mac size used as block size.
        /// </summary>
        public static ICMAC Tnepres_CMAC { get; } = new CMAC(SymmetricAlgorithms.Tnepres);

        /// <summary>
        /// Hash size 128 bits. Legal key size 64-256 bits (64 bits increments). Default mac size used as block size.
        /// </summary>
        public static ICMAC Twofish_CMAC { get; } = new CMAC(SymmetricAlgorithms.Twofish);

        /// <summary>
        /// Hash size 64 bits. Legal key size 128 bits. Default mac size used as block size.
        /// </summary>
        public static ICMAC XTEA_CMAC { get; } = new CMAC(SymmetricAlgorithms.XTEA);
    }
}