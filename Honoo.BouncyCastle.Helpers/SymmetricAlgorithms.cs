using Honoo.BouncyCastle.Helpers.Security.Crypto.Symmetric;

namespace Honoo.BouncyCastle.Helpers
{
    /// <summary>
    /// Some symmetric algorithms.
    /// </summary>
    public static class SymmetricAlgorithms
    {
        #region Block algorithms

        /// <summary>
        /// Block size 128 bits. Legal key size 128, 192, 256 bits.
        /// </summary>
        public static ISymmetricBlockAlgorithm AES { get; } = new AES();

        /// <summary>
        /// Block size 64 bits. Legal key size 128 bits.
        /// </summary>
        public static ISymmetricBlockAlgorithm Blowfish { get; } = new Blowfish();

        /// <summary>
        /// Block size 128 bits. Legal key size 128, 192, 256 bits.
        /// </summary>
        public static ISymmetricBlockAlgorithm Camellia { get; } = new Camellia();

        /// <summary>
        /// Block size 64 bits. Legal key size 40-128 bits (8 bits increments).
        /// </summary>
        public static ISymmetricBlockAlgorithm CAST5 { get; } = new CAST5();

        /// <summary>
        /// Block size 128 bits. Legal key size 128-256 bits (8 bits increments).
        /// </summary>
        public static ISymmetricBlockAlgorithm CAST6 { get; } = new CAST6();

        /// <summary>
        /// Block size 64 bits. Legal key size 64 bits.
        /// </summary>
        public static ISymmetricBlockAlgorithm DES { get; } = new DES();

        /// <summary>
        /// DESede, DESede3, TDEA, TripleDES, 3DES.
        /// <para/>Block size 64 bits. Legal key size 128, 192 bits.
        /// </summary>
        public static ISymmetricBlockAlgorithm DESede { get; } = new DESede();

        /// <summary>
        /// Block size 128 bits. Legal key size 128, 256 bits.
        /// </summary>
        public static ISymmetricBlockAlgorithm DSTU7624_128 { get; } = new DSTU7624(128);

        /// <summary>
        /// Block size 256 bits. Legal key size 256, 512 bits.
        /// </summary>
        public static ISymmetricBlockAlgorithm DSTU7624_256 { get; } = new DSTU7624(256);

        /// <summary>
        /// Block size 512 bits. Legal key size 512 bits.
        /// </summary>
        public static ISymmetricBlockAlgorithm DSTU7624_512 { get; } = new DSTU7624(512);

        /// <summary>
        /// Block size 64 bits. Legal key size 256 bits.
        /// </summary>
        public static ISymmetricBlockAlgorithm GOST28147 { get; } = new GOST28147();

        /// <summary>
        /// Block size 64 bits. Legal key size 8-128 bits (8 bits increments).
        /// </summary>
        public static ISymmetricBlockAlgorithm IDEA { get; } = new IDEA();

        /// <summary>
        /// Block size 128 bits. Legal key size 128 bits.
        /// </summary>
        public static ISymmetricBlockAlgorithm Noekeon { get; } = new Noekeon();

        /// <summary>
        /// Block size 64 bits. Legal key size 8-1024 bits (8 bits increments).
        /// </summary>
        public static ISymmetricBlockAlgorithm RC2 { get; } = new RC2();

        /// <summary>
        /// Block size 64 bits. Legal key size 8-2040 bits (8 bits increments).
        /// </summary>
        public static ISymmetricBlockAlgorithm RC5 { get; } = new RC5_32();

        /// <summary>
        /// Block size 128 bits. Legal key size 8-2040 bits (8 bits increments).
        /// </summary>
        public static ISymmetricBlockAlgorithm RC5_64 { get; } = new RC5_64();

        /// <summary>
        /// Block size 128 bits. Legal key size is more than or equal to 8 bits (8 bits increments).
        /// </summary>
        public static ISymmetricBlockAlgorithm RC6 { get; } = new RC6();

        /// <summary>
        /// Block size 128 bits. Legal key size 128, 160, 192, 224, 256 bits.
        /// </summary>
        public static ISymmetricBlockAlgorithm Rijndael_128 { get; } = new Rijndael(128);

        /// <summary>
        /// Block size 160 bits. Legal key size 128, 160, 192, 224, 256 bits.
        /// </summary>
        public static ISymmetricBlockAlgorithm Rijndael_160 { get; } = new Rijndael(160);

        /// <summary>
        /// Block size 192 bits. Legal key size 128, 160, 192, 224, 256 bits.
        /// </summary>
        public static ISymmetricBlockAlgorithm Rijndael_192 { get; } = new Rijndael(192);

        /// <summary>
        /// Block size 224 bits. Legal key size 128, 160, 192, 224, 256 bits.
        /// </summary>
        public static ISymmetricBlockAlgorithm Rijndael_224 { get; } = new Rijndael(224);

        /// <summary>
        /// Block size 256 bits. Legal key size 128, 160, 192, 224, 256 bits.
        /// </summary>
        public static ISymmetricBlockAlgorithm Rijndael_256 { get; } = new Rijndael(256);

        /// <summary>
        /// Block size 128 bits. Legal key size 128 bits.
        /// </summary>
        public static ISymmetricBlockAlgorithm SEED { get; } = new SEED();

        /// <summary>
        /// Block size 128 bits. Legal key size 32-512 bits (32 bits increments).
        /// </summary>
        public static ISymmetricBlockAlgorithm Serpent { get; } = new Serpent();

        /// <summary>
        /// Block size 64 bits. Legal key size 128 bits.
        /// </summary>
        public static ISymmetricBlockAlgorithm SKIPJACK { get; } = new SKIPJACK();

        /// <summary>
        /// Block size 128 bits. Legal key size 128 bits.
        /// </summary>
        public static ISymmetricBlockAlgorithm SM4 { get; } = new SM4();

        /// <summary>
        /// Block size 64 bits. Legal key size 128 bits.
        /// </summary>
        public static ISymmetricBlockAlgorithm TEA { get; } = new TEA();

        /// <summary>
        /// Block size 1024 bits. Legal key size 1024 bits.
        /// </summary>
        public static ISymmetricBlockAlgorithm Threefish_1024 { get; } = new Threefish(1024);

        /// <summary>
        /// Block size 256 bits. Legal key size 256 bits.
        /// </summary>
        public static ISymmetricBlockAlgorithm Threefish_256 { get; } = new Threefish(256);

        /// <summary>
        /// Block size 512 bits. Legal key size 512 bits.
        /// </summary>
        public static ISymmetricBlockAlgorithm Threefish_512 { get; } = new Threefish(512);

        /// <summary>
        /// Block size 128 bits. Legal key size 32-512 bits (32 bits increments).
        /// </summary>
        public static ISymmetricBlockAlgorithm Tnepres { get; } = new Tnepres();

        /// <summary>
        /// Block size 128 bits. Legal key size 64-256 bits (64 bits increments).
        /// </summary>
        public static ISymmetricBlockAlgorithm Twofish { get; } = new Twofish();

        /// <summary>
        /// Block size 64 bits. Legal key size 128 bits.
        /// </summary>
        public static ISymmetricBlockAlgorithm XTEA { get; } = new XTEA();

        #endregion Block algorithms

        #region Stream algorithms

        /// <summary>
        /// Legal key size 128, 256 bits. Legal IV size 64 bits.
        /// <para/>Uses rounds 20 by default.
        /// </summary>
        public static ISymmetricStreamAlgorithm ChaCha { get; } = new ChaCha();

        /// <summary>
        /// ChaCha7539, ChaCha20.
        /// <para/>Legal key size 256 bits. Legal IV size 96 bits.
        /// </summary>
        public static ISymmetricStreamAlgorithm ChaCha7539 { get; } = new ChaCha7539();

        /// <summary>
        /// Legal key size 128 bits. Legal IV size 0-128 bits (8 bits increments).
        /// </summary>
        public static ISymmetricStreamAlgorithm HC128 { get; } = new HC128();

        /// <summary>
        /// Legal key size 128, 256 bits. Legal IV size 128-256 bits (8 bits increments).
        /// </summary>
        public static ISymmetricStreamAlgorithm HC256 { get; } = new HC256();

        /// <summary>
        /// Legal key size 64-8192 bits (16 bits increments). Not need IV.
        /// </summary>
        public static ISymmetricStreamAlgorithm ISAAC { get; } = new ISAAC();

        /// <summary>
        /// RC4, ARC4.
        /// <para/>Legal key size 256 bits. Not need IV.
        /// </summary>
        public static ISymmetricStreamAlgorithm RC4 { get; } = new RC4();

        /// <summary>
        /// Salsa20.
        /// <para/>Legal key size 128, 256 bits. Legal IV size 64 bits.
        /// <para/>Uses rounds 20 by default.
        /// </summary>
        public static ISymmetricStreamAlgorithm Salsa20 { get; } = new Salsa20();

        /// <summary>
        /// Legal key size 256 bits. Legal IV size 8-6144 bits (8 bits increments).
        /// </summary>
        public static ISymmetricStreamAlgorithm VMPC { get; } = new VMPC();

        /// <summary>
        /// Legal key size 256 bits. Legal IV size 8-6144 bits (8 bits increments).
        /// </summary>
        public static ISymmetricStreamAlgorithm VMPC_KSA3 { get; } = new VMPC_KSA3();

        /// <summary>
        /// Legal key size 256 bits. Legal IV size 192 bits.
        /// </summary>
        public static ISymmetricStreamAlgorithm XSalsa20 { get; } = new XSalsa20();

        #endregion Stream algorithms
    }
}