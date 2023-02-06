using Honoo.BouncyCastle.Helpers.Security.Crypto.Hash;

namespace Honoo.BouncyCastle.Helpers
{
    /// <summary>
    /// Some HMAC algorithms.
    /// </summary>
    public static class HMACAlgorithms
    {
        /// <summary>
        /// Hash size 256 bits.
        /// </summary>
        public static IHMAC BLAKE2b_256_HMAC { get; } = new HMAC(HashAlgorithms.BLAKE2b_256);

        /// <summary>
        /// Hash size 384 bits.
        /// </summary>
        public static IHMAC BLAKE2b_384_HMAC { get; } = new HMAC(HashAlgorithms.BLAKE2b_384);

        /// <summary>
        /// Hash size 512 bits.
        /// </summary>
        public static IHMAC BLAKE2b_512_HMAC { get; } = new HMAC(HashAlgorithms.BLAKE2b_512);

        /// <summary>
        /// Hash size 256 bits.
        /// </summary>
        public static IHMAC BLAKE2s_256_HMAC { get; } = new HMAC(HashAlgorithms.BLAKE2s_256);

        /// <summary>
        /// Hash size 128 bits.
        /// </summary>
        public static IHMAC CSHAKE_128_HMAC { get; } = new HMAC(HashAlgorithms.CSHAKE_128);

        /// <summary>
        /// Hash size 256 bits.
        /// </summary>
        public static IHMAC CSHAKE_256_HMAC { get; } = new HMAC(HashAlgorithms.CSHAKE_256);

        /// <summary>
        /// Hash size 256 bits.
        /// </summary>
        public static IHMAC DSTU7564_256_HMAC { get; } = new HMAC(HashAlgorithms.DSTU7564_256);

        /// <summary>
        /// Hash size 384 bits.
        /// </summary>
        public static IHMAC DSTU7564_384_HMAC { get; } = new HMAC(HashAlgorithms.DSTU7564_384);

        /// <summary>
        /// Hash size 512 bits.
        /// </summary>
        public static IHMAC DSTU7564_512_HMAC { get; } = new HMAC(HashAlgorithms.DSTU7564_512);

        /// <summary>
        /// Hash size 256 bits.
        /// </summary>
        public static IHMAC GOST3411_2012_256_HMAC { get; } = new HMAC(HashAlgorithms.GOST3411_2012_256);

        /// <summary>
        /// Hash size 512 bits.
        /// </summary>
        public static IHMAC GOST3411_2012_512_HMAC { get; } = new HMAC(HashAlgorithms.GOST3411_2012_512);

        /// <summary>
        /// Hash size 256 bits.
        /// <para/>Uses substitution box "D-A" by default.
        /// </summary>
        public static IHMAC GOST3411_HMAC { get; } = new HMAC(HashAlgorithms.GOST3411);

        /// <summary>
        /// Hash size 128 bits.
        /// </summary>
        public static IHMAC Keccak_128_HMAC { get; } = new HMAC(HashAlgorithms.Keccak_128);

        /// <summary>
        /// Hash size 224 bits.
        /// </summary>
        public static IHMAC Keccak_224_HMAC { get; } = new HMAC(HashAlgorithms.Keccak_224);

        /// <summary>
        /// Hash size 256 bits.
        /// </summary>
        public static IHMAC Keccak_256_HMAC { get; } = new HMAC(HashAlgorithms.Keccak_256);

        /// <summary>
        /// Hash size 288 bits.
        /// </summary>
        public static IHMAC Keccak_288_HMAC { get; } = new HMAC(HashAlgorithms.Keccak_288);

        /// <summary>
        /// Hash size 384 bits.
        /// </summary>
        public static IHMAC Keccak_384_HMAC { get; } = new HMAC(HashAlgorithms.Keccak_384);

        /// <summary>
        /// Hash size 512 bits.
        /// </summary>
        public static IHMAC Keccak_512_HMAC { get; } = new HMAC(HashAlgorithms.Keccak_512);

        /// <summary>
        /// Hash size 128 bits.
        /// </summary>
        public static IHMAC MD2_HMAC { get; } = new HMAC(HashAlgorithms.MD2);

        /// <summary>
        /// Hash size 128 bits.
        /// </summary>
        public static IHMAC MD4_HMAC { get; } = new HMAC(HashAlgorithms.MD4);

        /// <summary>
        /// Hash size 128 bits.
        /// </summary>
        public static IHMAC MD5_HMAC { get; } = new HMAC(HashAlgorithms.MD5);

        /// <summary>
        /// Hash size 128 bits.
        /// </summary>
        public static IHMAC RIPEMD128_HMAC { get; } = new HMAC(HashAlgorithms.RIPEMD128);

        /// <summary>
        /// Hash size 160 bits.
        /// </summary>
        public static IHMAC RIPEMD160_HMAC { get; } = new HMAC(HashAlgorithms.RIPEMD160);

        /// <summary>
        /// Hash size 256 bits.
        /// </summary>
        public static IHMAC RIPEMD256_HMAC { get; } = new HMAC(HashAlgorithms.RIPEMD256);

        /// <summary>
        /// Hash size 320 bits.
        /// </summary>
        public static IHMAC RIPEMD320_HMAC { get; } = new HMAC(HashAlgorithms.RIPEMD320);

        /// <summary>
        /// Hash size 160 bits.
        /// </summary>
        public static IHMAC SHA1_HMAC { get; } = new HMAC(HashAlgorithms.SHA1);

        /// <summary>
        /// Hash size 224 bits.
        /// </summary>
        public static IHMAC SHA224_HMAC { get; } = new HMAC(HashAlgorithms.SHA224);

        /// <summary>
        /// Hash size 256 bits.
        /// </summary>
        public static IHMAC SHA256_HMAC { get; } = new HMAC(HashAlgorithms.SHA256);

        /// <summary>
        /// Hash size 224 bits.
        /// </summary>
        public static IHMAC SHA3_224_HMAC { get; } = new HMAC(HashAlgorithms.SHA3_224);

        /// <summary>
        /// Hash size 256 bits.
        /// </summary>
        public static IHMAC SHA3_256_HMAC { get; } = new HMAC(HashAlgorithms.SHA3_256);

        /// <summary>
        /// Hash size 384 bits.
        /// </summary>
        public static IHMAC SHA3_384_HMAC { get; } = new HMAC(HashAlgorithms.SHA3_384);

        /// <summary>
        /// Hash size 512 bits.
        /// </summary>
        public static IHMAC SHA3_512_HMAC { get; } = new HMAC(HashAlgorithms.SHA3_512);

        /// <summary>
        /// Hash size 384 bits.
        /// </summary>
        public static IHMAC SHA384_HMAC { get; } = new HMAC(HashAlgorithms.SHA384);

        /// <summary>
        /// Hash size 224 bits.
        /// </summary>
        public static IHMAC SHA512_224_HMAC { get; } = new HMAC(HashAlgorithms.SHA512_224);

        /// <summary>
        /// Hash size 256 bits.
        /// </summary>
        public static IHMAC SHA512_256_HMAC { get; } = new HMAC(HashAlgorithms.SHA512_256);

        /// <summary>
        /// Hash size 512 bits.
        /// </summary>
        public static IHMAC SHA512_HMAC { get; } = new HMAC(HashAlgorithms.SHA512);

        /// <summary>
        /// Hash size 128 bits.
        /// </summary>
        public static IHMAC SHAKE_128_HMAC { get; } = new HMAC(HashAlgorithms.SHAKE_128);

        /// <summary>
        /// Hash size 256 bits.
        /// </summary>
        public static IHMAC SHAKE_256_HMAC { get; } = new HMAC(HashAlgorithms.SHAKE_256);

        /// <summary>
        /// Hash size 1024 bits.
        /// </summary>
        public static IHMAC Skein_1024_1024_HMAC { get; } = new HMAC(HashAlgorithms.Skein_1024_1024);

        /// <summary>
        /// Hash size 256 bits.
        /// </summary>
        public static IHMAC Skein_256_256_HMAC { get; } = new HMAC(HashAlgorithms.Skein_256_256);

        /// <summary>
        /// Hash size 512 bits.
        /// </summary>
        public static IHMAC Skein_512_512_HMAC { get; } = new HMAC(HashAlgorithms.Skein_512_512);

        /// <summary>
        /// Hash size 256 bits.
        /// </summary>
        public static IHMAC SM3_HMAC { get; } = new HMAC(HashAlgorithms.SM3);

        /// <summary>
        /// Hash size 192 bits.
        /// </summary>
        public static IHMAC Tiger_HMAC { get; } = new HMAC(HashAlgorithms.Tiger);

        /// <summary>
        /// Hash size 512 bits.
        /// </summary>
        public static IHMAC Whirlpool_HMAC { get; } = new HMAC(HashAlgorithms.Whirlpool);
    }
}