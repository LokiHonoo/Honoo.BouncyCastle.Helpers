using Honoo.BouncyCastle.Helpers.Security.Crypto.Symmetric;

namespace Honoo.BouncyCastle.Helpers
{
    /// <summary>
    /// Symmetric algorithm helper.
    /// </summary>
    public static class SymmetricAlgorithmHelper
    {
        #region Block algorithms

        /// <summary>
        /// Block size 128 bits. Legal key size 128, 192, 256 bits.
        /// </summary>
        public static IBlockAlgorithm AES { get; } = new AES();

        /// <summary>
        /// Block size 64 bits. Legal key size 128 bits.
        /// </summary>
        public static IBlockAlgorithm Blowfish { get; } = new Blowfish();

        /// <summary>
        /// Block size 128 bits. Legal key size 128, 192, 256 bits.
        /// </summary>
        public static IBlockAlgorithm Camellia { get; } = new Camellia();

        /// <summary>
        /// Block size 64 bits. Legal key size 40-128 bits (8 bits increments).
        /// </summary>
        public static IBlockAlgorithm CAST5 { get; } = new CAST5();

        /// <summary>
        /// Block size 128 bits. Legal key size 128-256 bits (8 bits increments).
        /// </summary>
        public static IBlockAlgorithm CAST6 { get; } = new CAST6();

        /// <summary>
        /// Block size 64 bits. Legal key size 64 bits.
        /// </summary>
        public static IBlockAlgorithm DES { get; } = new DES();

        /// <summary>
        /// DESede, DESede3, TDEA, TripleDES, 3DES.
        /// <para/>Block size 64 bits. Legal key size 128, 192 bits.
        /// </summary>
        public static IBlockAlgorithm DESede { get; } = new DESede();

        /// <summary>
        /// Block size 128 bits. Legal key size 128, 256 bits.
        /// </summary>
        public static IBlockAlgorithm DSTU7624_128 { get; } = new DSTU7624(128);

        /// <summary>
        /// Block size 256 bits. Legal key size 256, 512 bits.
        /// </summary>
        public static IBlockAlgorithm DSTU7624_256 { get; } = new DSTU7624(256);

        /// <summary>
        /// Block size 512 bits. Legal key size 512 bits.
        /// </summary>
        public static IBlockAlgorithm DSTU7624_512 { get; } = new DSTU7624(512);

        /// <summary>
        /// Block size 64 bits. Legal key size 256 bits.
        /// </summary>
        public static IBlockAlgorithm GOST28147 { get; } = new GOST28147();

        /// <summary>
        /// Block size 64 bits. Legal key size 8-128 bits (8 bits increments).
        /// </summary>
        public static IBlockAlgorithm IDEA { get; } = new IDEA();

        /// <summary>
        /// Block size 128 bits. Legal key size 128 bits.
        /// </summary>
        public static IBlockAlgorithm Noekeon { get; } = new Noekeon();

        /// <summary>
        /// Block size 64 bits. Legal key size 8-1024 bits (8 bits increments).
        /// </summary>
        public static IBlockAlgorithm RC2 { get; } = new RC2();

        /// <summary>
        /// Block size 64 bits. Legal key size 8-2040 bits (8 bits increments).
        /// </summary>
        public static IBlockAlgorithm RC5 { get; } = new RC5_32();

        /// <summary>
        /// Block size 128 bits. Legal key size 8-2040 bits (8 bits increments).
        /// </summary>
        public static IBlockAlgorithm RC5_64 { get; } = new RC5_64();

        /// <summary>
        /// Block size 128 bits. Legal key size is more than or equal to 8 bits (8 bits increments).
        /// </summary>
        public static IBlockAlgorithm RC6 { get; } = new RC6();

        /// <summary>
        /// Block size 128 bits. Legal key size 128, 160, 192, 224, 256 bits.
        /// </summary>
        public static IBlockAlgorithm Rijndael_128 { get; } = new Rijndael(128);

        /// <summary>
        /// Block size 160 bits. Legal key size 128, 160, 192, 224, 256 bits.
        /// </summary>
        public static IBlockAlgorithm Rijndael_160 { get; } = new Rijndael(160);

        /// <summary>
        /// Block size 192 bits. Legal key size 128, 160, 192, 224, 256 bits.
        /// </summary>
        public static IBlockAlgorithm Rijndael_192 { get; } = new Rijndael(192);

        /// <summary>
        /// Block size 224 bits. Legal key size 128, 160, 192, 224, 256 bits.
        /// </summary>
        public static IBlockAlgorithm Rijndael_224 { get; } = new Rijndael(224);

        /// <summary>
        /// Block size 256 bits. Legal key size 128, 160, 192, 224, 256 bits.
        /// </summary>
        public static IBlockAlgorithm Rijndael_256 { get; } = new Rijndael(256);

        /// <summary>
        /// Block size 128 bits. Legal key size 128 bits.
        /// </summary>
        public static IBlockAlgorithm SEED { get; } = new SEED();

        /// <summary>
        /// Block size 128 bits. Legal key size 32-512 bits (32 bits increments).
        /// </summary>
        public static IBlockAlgorithm Serpent { get; } = new Serpent();

        /// <summary>
        /// Block size 64 bits. Legal key size 128 bits.
        /// </summary>
        public static IBlockAlgorithm SKIPJACK { get; } = new SKIPJACK();

        /// <summary>
        /// Block size 128 bits. Legal key size 128 bits.
        /// </summary>
        public static IBlockAlgorithm SM4 { get; } = new SM4();

        /// <summary>
        /// Block size 64 bits. Legal key size 128 bits.
        /// </summary>
        public static IBlockAlgorithm TEA { get; } = new TEA();

        /// <summary>
        /// Block size 1024 bits. Legal key size 1024 bits.
        /// </summary>
        public static IBlockAlgorithm Threefish_1024 { get; } = new Threefish(1024);

        /// <summary>
        /// Block size 256 bits. Legal key size 256 bits.
        /// </summary>
        public static IBlockAlgorithm Threefish_256 { get; } = new Threefish(256);

        /// <summary>
        /// Block size 512 bits. Legal key size 512 bits.
        /// </summary>
        public static IBlockAlgorithm Threefish_512 { get; } = new Threefish(512);

        /// <summary>
        /// Block size 128 bits. Legal key size 32-512 bits (32 bits increments).
        /// </summary>
        public static IBlockAlgorithm Tnepres { get; } = new Tnepres();

        /// <summary>
        /// Block size 128 bits. Legal key size 64-256 bits (64 bits increments).
        /// </summary>
        public static IBlockAlgorithm Twofish { get; } = new Twofish();

        /// <summary>
        /// Block size 64 bits. Legal key size 128 bits.
        /// </summary>
        public static IBlockAlgorithm XTEA { get; } = new XTEA();

        #endregion Block algorithms

        #region Stream algorithms

        /// <summary>
        /// Legal key size 128, 256 bits. Legal iv size 64 bits.
        /// <para/>Uses rounds 20 by default.
        /// </summary>
        public static IStreamAlgorithm ChaCha { get; } = new ChaCha();

        /// <summary>
        /// ChaCha7539, ChaCha20.
        /// <para/>Legal key size 256 bits. Legal iv size 96 bits.
        /// </summary>
        public static IStreamAlgorithm ChaCha7539 { get; } = new ChaCha7539();

        /// <summary>
        /// Legal key size 128 bits. Legal iv size 0-128 bits (8 bits increments).
        /// </summary>
        public static IStreamAlgorithm HC128 { get; } = new HC128();

        /// <summary>
        /// Legal key size 128, 256 bits. Legal iv size 128-256 bits (8 bits increments).
        /// </summary>
        public static IStreamAlgorithm HC256 { get; } = new HC256();

        /// <summary>
        /// Legal key size 64-8192 bits (16 bits increments). Not need IV.
        /// </summary>
        public static IStreamAlgorithm ISAAC { get; } = new ISAAC();

        /// <summary>
        /// RC4, ARC4.
        /// <para/>Legal key size 256 bits. Not need IV.
        /// </summary>
        public static IStreamAlgorithm RC4 { get; } = new RC4();

        /// <summary>
        /// Salsa20.
        /// <para/>Legal key size 128, 256 bits. Legal iv size 64 bits.
        /// <para/>Uses rounds 20 by default.
        /// </summary>
        public static IStreamAlgorithm Salsa20 { get; } = new Salsa20();

        /// <summary>
        /// Legal key size 256 bits. Legal iv size 8-6144 bits (8 bits increments).
        /// </summary>
        public static IStreamAlgorithm VMPC { get; } = new VMPC();

        /// <summary>
        /// Legal key size 256 bits. Legal iv size 8-6144 bits (8 bits increments).
        /// </summary>
        public static IStreamAlgorithm VMPC_KSA3 { get; } = new VMPC_KSA3();

        /// <summary>
        /// Legal key size 256 bits. Legal iv size 192 bits.
        /// </summary>
        public static IStreamAlgorithm XSalsa20 { get; } = new XSalsa20();

        #endregion Stream algorithms

        /// <summary>
        /// Try get symmetric algorithm from mechanism.
        /// </summary>
        /// <param name="mechanism">Symmetric algorithm mechanism.</param>
        /// <param name="algorithm">Symmetric algorithm.</param>
        /// <returns></returns>
        public static bool TryGetAlgorithm(string mechanism, out IBlockAlgorithm algorithm)
        {
            if (string.IsNullOrWhiteSpace(mechanism))
            {
                algorithm = null;
                return false;
            }
            mechanism = mechanism.Replace('_', '-').ToUpperInvariant();
            switch (mechanism)
            {
                case "AES": algorithm = AES; return true;
                case "BLOWFISH": algorithm = Blowfish; return true;
                case "CAMELLIA": algorithm = Camellia; return true;
                case "CAST5": algorithm = CAST5; return true;
                case "CAST6": algorithm = CAST6; return true;
                case "DES": algorithm = DES; return true;
                case "DESEDE": case "DESEDE3": case "TDEA": case "TRIPLEDES": case "3DES": algorithm = DESede; return true;
                case "DSTU7624-128": algorithm = DSTU7624_128; return true;
                case "DSTU7624-256": algorithm = DSTU7624_256; return true;
                case "DSTU7624-512": algorithm = DSTU7624_512; return true;
                case "GOST28147": algorithm = GOST28147; return true;
                case "IDEA": algorithm = IDEA; return true;
                case "NOEKEON": algorithm = Noekeon; return true;
                case "RC2": algorithm = RC2; return true;
                case "RC5": case "RC5-32": algorithm = RC5; return true;
                case "RC5-64": algorithm = RC5_64; return true;
                case "RC6": algorithm = RC6; return true;
                case "RIJNDAEL-128": case "RIJNDAEL128": algorithm = Rijndael_128; return true;
                case "RIJNDAEL-160": case "RIJNDAEL160": algorithm = Rijndael_160; return true;
                case "RIJNDAEL-192": case "RIJNDAEL192": algorithm = Rijndael_192; return true;
                case "RIJNDAEL-224": case "RIJNDAEL224": algorithm = Rijndael_224; return true;
                case "RIJNDAEL-256": case "RIJNDAEL256": algorithm = Rijndael_256; return true;
                case "SEED": algorithm = SEED; return true;
                case "SERPENT": algorithm = Serpent; return true;
                case "SKIPJACK": algorithm = SKIPJACK; return true;
                case "SM4": algorithm = SM4; return true;
                case "TEA": algorithm = TEA; return true;
                case "THREEFISH-256": case "THREEFISH256": algorithm = Threefish_256; return true;
                case "THREEFISH-512": case "THREEFISH512": algorithm = Threefish_512; return true;
                case "THREEFISH-1024": case "THREEFISH1024": algorithm = Threefish_1024; return true;
                case "TNEPRES": algorithm = Tnepres; return true;
                case "TWOFISH": algorithm = Twofish; return true;
                case "XTEA": algorithm = XTEA; return true;
                default: algorithm = null; return false;
            }
        }

        /// <summary>
        /// Try get symmetric algorithm from mechanism.
        /// </summary>
        /// <param name="mechanism">Symmetric algorithm mechanism.</param>
        /// <param name="algorithm">Symmetric algorithm.</param>
        /// <returns></returns>
        public static bool TryGetAlgorithm(string mechanism, out IStreamAlgorithm algorithm)
        {
            if (string.IsNullOrWhiteSpace(mechanism))
            {
                algorithm = null;
                return false;
            }
            mechanism = mechanism.Replace('_', '-').ToUpperInvariant();
            switch (mechanism)
            {
                case "CHACHA": algorithm = ChaCha; return true;
                case "CHACHA7539": case "CHACHA20": algorithm = ChaCha7539; return true;
                case "HC128": case "HC-128": algorithm = HC128; return true;
                case "HC256": case "HC-256": algorithm = HC256; return true;
                case "ISAAC": algorithm = ISAAC; return true;
                case "RC4": case "ARC4": case "ARCFOUR": algorithm = RC4; return true;
                case "SALSA20": algorithm = Salsa20; return true;
                case "VMPC": algorithm = VMPC; return true;
                case "VMPC-KSA3": case "VMPCKSA3": algorithm = VMPC_KSA3; return true;
                case "XSALSA20": algorithm = XSalsa20; return true;
                default: algorithm = null; return false;
            }
        }
    }
}