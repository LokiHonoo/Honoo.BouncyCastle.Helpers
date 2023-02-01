using Honoo.BouncyCastle.Helpers.Security.Crypto.Hash;

namespace Honoo.BouncyCastle.Helpers
{
    /// <summary>
    /// Some hash algorithms.
    /// </summary>
    public static class HashAlgorithms
    {
        /// <summary>
        /// Hash size 256 bits.
        /// </summary>
        public static IHashAlgorithm BLAKE2b_256 { get; } = new BLAKE2b(256);

        /// <summary>
        /// Hash size 384 bits.
        /// </summary>
        public static IHashAlgorithm BLAKE2b_384 { get; } = new BLAKE2b(384);

        /// <summary>
        /// Hash size 512 bits.
        /// </summary>
        public static IHashAlgorithm BLAKE2b_512 { get; } = new BLAKE2b(512);

        /// <summary>
        /// Hash size 256 bits.
        /// </summary>
        public static IHashAlgorithm BLAKE2s_256 { get; } = new BLAKE2s(256);

        /// <summary>
        /// Hash size 128 bits.
        /// <para/>Uses null nist and null customization.
        /// </summary>
        public static IHashAlgorithm CSHAKE_128 { get; } = new CSHAKE(128, null, null);

        /// <summary>
        /// Hash size 256 bits.
        /// <para/>Uses null nist and null customization.
        /// </summary>
        public static IHashAlgorithm CSHAKE_256 { get; } = new CSHAKE(256, null, null);

        /// <summary>
        /// Hash size 256 bits.
        /// </summary>
        public static IHashAlgorithm DSTU7564_256 { get; } = new DSTU7564(256);

        /// <summary>
        /// Hash size 384 bits.
        /// </summary>
        public static IHashAlgorithm DSTU7564_384 { get; } = new DSTU7564(384);

        /// <summary>
        /// Hash size 512 bits.
        /// </summary>
        public static IHashAlgorithm DSTU7564_512 { get; } = new DSTU7564(512);

        /// <summary>
        /// Hash size 256 bits.
        /// <para/>Uses substitution box "D-A" by default.
        /// </summary>
        public static IHashAlgorithm GOST3411 { get; } = new GOST3411();

        /// <summary>
        /// Hash size 256 bits.
        /// </summary>
        public static IHashAlgorithm GOST3411_2012_256 { get; } = new GOST3411_2012(256);

        /// <summary>
        /// Hash size 512 bits.
        /// </summary>
        public static IHashAlgorithm GOST3411_2012_512 { get; } = new GOST3411_2012(512);

        /// <summary>
        /// Hash size 128 bits.
        /// </summary>
        public static IHashAlgorithm Keccak_128 { get; } = new Keccak(128);

        /// <summary>
        /// Hash size 224 bits.
        /// </summary>
        public static IHashAlgorithm Keccak_224 { get; } = new Keccak(224);

        /// <summary>
        /// Hash size 256 bits.
        /// </summary>
        public static IHashAlgorithm Keccak_256 { get; } = new Keccak(256);

        /// <summary>
        /// Hash size 288 bits.
        /// </summary>
        public static IHashAlgorithm Keccak_288 { get; } = new Keccak(288);

        /// <summary>
        /// Hash size 384 bits.
        /// </summary>
        public static IHashAlgorithm Keccak_384 { get; } = new Keccak(384);

        /// <summary>
        /// Hash size 512 bits.
        /// </summary>
        public static IHashAlgorithm Keccak_512 { get; } = new Keccak(512);

        /// <summary>
        /// Hash size 128 bits.
        /// </summary>
        public static IHashAlgorithm MD2 { get; } = new MD2();

        /// <summary>
        /// Hash size 128 bits.
        /// </summary>
        public static IHashAlgorithm MD4 { get; } = new MD4();

        /// <summary>
        /// Hash size 128 bits.
        /// </summary>
        public static IHashAlgorithm MD5 { get; } = new MD5();

        /// <summary>
        /// Hash size 128 bits.
        /// </summary>
        public static IHashAlgorithm RIPEMD128 { get; } = new RIPEMD128();

        /// <summary>
        /// Hash size 160 bits.
        /// </summary>
        public static IHashAlgorithm RIPEMD160 { get; } = new RIPEMD160();

        /// <summary>
        /// Hash size 256 bits.
        /// </summary>
        public static IHashAlgorithm RIPEMD256 { get; } = new RIPEMD256();

        /// <summary>
        /// Hash size 320 bits.
        /// </summary>
        public static IHashAlgorithm RIPEMD320 { get; } = new RIPEMD320();

        /// <summary>
        /// Hash size 160 bits.
        /// </summary>
        public static IHashAlgorithm SHA1 { get; } = new SHA1();

        /// <summary>
        /// Hash size 224 bits.
        /// </summary>
        public static IHashAlgorithm SHA224 { get; } = new SHA224();

        /// <summary>
        /// Hash size 256 bits.
        /// </summary>
        public static IHashAlgorithm SHA256 { get; } = new SHA256();

        /// <summary>
        /// Hash size 224 bits.
        /// </summary>
        public static IHashAlgorithm SHA3_224 { get; } = new SHA3(224);

        /// <summary>
        /// Hash size 256 bits.
        /// </summary>
        public static IHashAlgorithm SHA3_256 { get; } = new SHA3(256);

        /// <summary>
        /// Hash size 384 bits.
        /// </summary>
        public static IHashAlgorithm SHA3_384 { get; } = new SHA3(384);

        /// <summary>
        /// Hash size 512 bits.
        /// </summary>
        public static IHashAlgorithm SHA3_512 { get; } = new SHA3(512);

        /// <summary>
        /// Hash size 384 bits.
        /// </summary>
        public static IHashAlgorithm SHA384 { get; } = new SHA384();

        /// <summary>
        /// Hash size 512 bits.
        /// </summary>
        public static IHashAlgorithm SHA512 { get; } = new SHA512();

        /// <summary>
        /// Hash size 224 bits.
        /// </summary>
        public static IHashAlgorithm SHA512_224 { get; } = new SHA512T(224);

        /// <summary>
        /// Hash size 256 bits.
        /// </summary>
        public static IHashAlgorithm SHA512_256 { get; } = new SHA512T(256);

        /// <summary>
        /// Hash size 128 bits.
        /// </summary>
        public static IHashAlgorithm SHAKE_128 { get; } = new SHAKE(128);

        /// <summary>
        /// Hash size 256 bits.
        /// </summary>
        public static IHashAlgorithm SHAKE_256 { get; } = new SHAKE(256);

        /// <summary>
        /// Hash size 1024 bits.
        /// </summary>
        public static IHashAlgorithm Skein_1024_1024 { get; } = new Skein(1024, 1024);

        /// <summary>
        /// Hash size 256 bits.
        /// </summary>
        public static IHashAlgorithm Skein_256_256 { get; } = new Skein(256, 256);

        /// <summary>
        /// Hash size 512 bits.
        /// </summary>
        public static IHashAlgorithm Skein_512_512 { get; } = new Skein(512, 512);

        /// <summary>
        /// Hash size 256 bits.
        /// </summary>
        public static IHashAlgorithm SM3 { get; } = new SM3();

        /// <summary>
        /// Hash size 192 bits.
        /// </summary>
        public static IHashAlgorithm Tiger { get; } = new Tiger();

        /// <summary>
        /// Hash size 512 bits.
        /// </summary>
        public static IHashAlgorithm Whirlpool { get; } = new Whirlpool();
    }
}