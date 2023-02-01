using Honoo.BouncyCastle.Helpers.Security.Crypto.Hash;

namespace Honoo.BouncyCastle.Helpers
{
    /// <summary>
    /// Some MAC algorithms.
    /// </summary>
    public static class MACAlgorithms
    {
        /// <summary>
        /// Hash size 64 bits. Legal key size 128, 192, 256 bits. Default mac size used as block size / 2.
        /// </summary>
        public static IMAC AES_MAC { get; } = new MAC(SymmetricAlgorithms.AES);

        /// <summary>
        /// Hash size 32 bits. Legal key size 128 bits. Default mac size used as block size / 2.
        /// </summary>
        public static IMAC Blowfish_MAC { get; } = new MAC(SymmetricAlgorithms.Blowfish);

        /// <summary>
        /// Hash size 64 bits. Legal key size 128, 192, 256 bits. Default mac size used as block size / 2.
        /// </summary>
        public static IMAC Camellia_MAC { get; } = new MAC(SymmetricAlgorithms.Camellia);

        /// <summary>
        /// Hash size 32 bits. Legal key size 40-128 bits (8 bits increments). Default mac size used as block size / 2.
        /// </summary>
        public static IMAC CAST5_MAC { get; } = new MAC(SymmetricAlgorithms.CAST5);

        /// <summary>
        /// Hash size 64 bits. Legal key size 128-256 bits (8 bits increments). Default mac size used as block size / 2.
        /// </summary>
        public static IMAC CAST6_MAC { get; } = new MAC(SymmetricAlgorithms.CAST6);

        /// <summary>
        /// Hash size 32 bits. Legal key size 64 bits. Default mac size used as block size / 2.
        /// </summary>
        public static IMAC DES_MAC { get; } = new MAC(SymmetricAlgorithms.DES);

        /// <summary>
        /// DESede, DESede3, TDEA, TripleDES, 3DES. Hash size 32 bits. Legal key size 128, 192 bits. Default mac size used as block size / 2.
        /// </summary>
        public static IMAC DESede_MAC { get; } = new MAC(SymmetricAlgorithms.DESede);

        /// <summary>
        /// Hash size 64 bits. Legal key size 128, 256 bits. Default mac size used as block size / 2.
        /// </summary>
        public static IMAC DSTU7624_128_MAC { get; } = new MAC(SymmetricAlgorithms.DSTU7624_128);

        /// <summary>
        /// Hash size 128 bits. Legal key size 256, 512 bits. Default mac size used as block size / 2.
        /// </summary>
        public static IMAC DSTU7624_256_MAC { get; } = new MAC(SymmetricAlgorithms.DSTU7624_256);

        /// <summary>
        /// Hash size 256 bits. Legal key size 512 bits. Default mac size used as block size / 2.
        /// </summary>
        public static IMAC DSTU7624_512_MAC { get; } = new MAC(SymmetricAlgorithms.DSTU7624_512);

        /// <summary>
        /// Hash size 32 bits. Legal key size 256 bits. Default mac size used as block size / 2.
        /// </summary>
        public static IMAC GOST28147_MAC { get; } = new MAC(SymmetricAlgorithms.GOST28147);

        /// <summary>
        /// Hash size 32 bits. Legal key size 8-128 bits (8 bits increments). Default mac size used as block size / 2.
        /// </summary>
        public static IMAC IDEA_MAC { get; } = new MAC(SymmetricAlgorithms.IDEA);

        /// <summary>
        /// Hash size 64 bits. Legal key size 128 bits. Default mac size used as block size / 2.
        /// </summary>
        public static IMAC Noekeon_MAC { get; } = new MAC(SymmetricAlgorithms.Noekeon);

        /// <summary>
        /// Hash size 32 bits. Legal key size 8-1024 bits (8 bits increments). Default mac size used as block size / 2.
        /// </summary>
        public static IMAC RC2_MAC { get; } = new MAC(SymmetricAlgorithms.RC2);

        /// <summary>
        /// Hash size 64 bits. Legal key size 8-2040 bits (8 bits increments). Default mac size used as block size / 2.
        /// </summary>
        public static IMAC RC5_64_MAC { get; } = new MAC(SymmetricAlgorithms.RC5_64);

        /// <summary>
        /// Hash size 32 bits. Legal key size 8-2040 bits (8 bits increments). Default mac size used as block size / 2.
        /// </summary>
        public static IMAC RC5_MAC { get; } = new MAC(SymmetricAlgorithms.RC5);

        /// <summary>
        /// Hash size 64 bits. Legal key size is more than or equal to 8 bits (8 bits increments). Default mac size used as block size / 2.
        /// </summary>
        public static IMAC RC6_MAC { get; } = new MAC(SymmetricAlgorithms.RC6);

        /// <summary>
        /// Hash size 64 bits. Legal key size 128, 160, 192, 224, 256 bits. Default mac size used as block size / 2.
        /// </summary>
        public static IMAC Rijndael_128_MAC { get; } = new MAC(SymmetricAlgorithms.Rijndael_128);

        /// <summary>
        /// Hash size 80 bits. Legal key size 128, 160, 192, 224, 256 bits. Default mac size used as block size / 2.
        /// </summary>
        public static IMAC Rijndael_160_MAC { get; } = new MAC(SymmetricAlgorithms.Rijndael_160);

        /// <summary>
        /// Hash size 96 bits. Legal key size 128, 160, 192, 224, 256 bits. Default mac size used as block size / 2.
        /// </summary>
        public static IMAC Rijndael_192_MAC { get; } = new MAC(SymmetricAlgorithms.Rijndael_192);

        /// <summary>
        /// Hash size 112 bits. Legal key size 128, 160, 192, 224, 256 bits. Default mac size used as block size / 2.
        /// </summary>
        public static IMAC Rijndael_224_MAC { get; } = new MAC(SymmetricAlgorithms.Rijndael_224);

        /// <summary>
        /// Hash size 128 bits. Legal key size 128, 160, 192, 224, 256 bits. Default mac size used as block size / 2.
        /// </summary>
        public static IMAC Rijndael_256_MAC { get; } = new MAC(SymmetricAlgorithms.Rijndael_256);

        /// <summary>
        /// Hash size 64 bits. Legal key size 128 bits. Default mac size used as block size / 2.
        /// </summary>
        public static IMAC SEED_MAC { get; } = new MAC(SymmetricAlgorithms.SEED);

        /// <summary>
        /// Hash size 64 bits. Legal key size 32-512 bits (32 bits increments). Default mac size used as block size / 2.
        /// </summary>
        public static IMAC Serpent_MAC { get; } = new MAC(SymmetricAlgorithms.Serpent);

        /// <summary>
        /// Hash size 32 bits. Legal key size 128 bits. Default mac size used as block size / 2.
        /// </summary>
        public static IMAC SKIPJACK_MAC { get; } = new MAC(SymmetricAlgorithms.SKIPJACK);

        /// <summary>
        /// Hash size 64 bits. Legal key size 128 bits. Default mac size used as block size / 2.
        /// </summary>
        public static IMAC SM4_MAC { get; } = new MAC(SymmetricAlgorithms.SM4);

        /// <summary>
        /// Hash size 32 bits. Legal key size 128 bits. Default mac size used as block size / 2.
        /// </summary>
        public static IMAC TEA_MAC { get; } = new MAC(SymmetricAlgorithms.TEA);

        /// <summary>
        /// Hash size 512 bits. Legal key size 1024 bits. Default mac size used as block size / 2.
        /// </summary>
        public static IMAC Threefish_1024_MAC { get; } = new MAC(SymmetricAlgorithms.Threefish_1024);

        /// <summary>
        /// Hash size 128 bits. Legal key size 256 bits. Default mac size used as block size / 2.
        /// </summary>
        public static IMAC Threefish_256_MAC { get; } = new MAC(SymmetricAlgorithms.Threefish_256);

        /// <summary>
        /// Hash size 256 bits. Legal key size 512 bits. Default mac size used as block size / 2.
        /// </summary>
        public static IMAC Threefish_512_MAC { get; } = new MAC(SymmetricAlgorithms.Threefish_512);

        /// <summary>
        /// Hash size 64 bits. Legal key size 32-512 bits (32 bits increments). Default mac size used as block size / 2.
        /// </summary>
        public static IMAC Tnepres_MAC { get; } = new MAC(SymmetricAlgorithms.Tnepres);

        /// <summary>
        /// Hash size 64 bits. Legal key size 64-256 bits (64 bits increments). Default mac size used as block size / 2.
        /// </summary>
        public static IMAC Twofish_MAC { get; } = new MAC(SymmetricAlgorithms.Twofish);

        /// <summary>
        /// Hash size 32 bits. Legal key size 128 bits. Default mac size used as block size / 2.
        /// </summary>
        public static IMAC XTEA_MAC { get; } = new MAC(SymmetricAlgorithms.XTEA);
    }
}