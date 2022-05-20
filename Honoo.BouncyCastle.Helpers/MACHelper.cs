using Honoo.BouncyCastle.Helpers.Security.Crypto.Hash;

namespace Honoo.BouncyCastle.Helpers
{
    /// <summary>
    /// MAC helper.
    /// </summary>
    public static class MACHelper
    {
        #region MAC

        /// <summary>
        /// Hash size 64 bits. Legal key size 128, 192, 256 bits.
        /// </summary>
        public static IMAC AES_MAC { get; } = new MAC(SymmetricAlgorithmHelper.AES);

        /// <summary>
        /// Hash size 32 bits. Legal key size 128 bits.
        /// </summary>
        public static IMAC Blowfish_MAC { get; } = new MAC(SymmetricAlgorithmHelper.Blowfish);

        /// <summary>
        /// Hash size 64 bits. Legal key size 128, 192, 256 bits.
        /// </summary>
        public static IMAC Camellia_MAC { get; } = new MAC(SymmetricAlgorithmHelper.Camellia);

        /// <summary>
        /// Hash size 32 bits. Legal key size 40-128 bits (8 bits increments).
        /// </summary>
        public static IMAC CAST5_MAC { get; } = new MAC(SymmetricAlgorithmHelper.CAST5);

        /// <summary>
        /// Hash size 64 bits. Legal key size 128-256 bits (8 bits increments).
        /// </summary>
        public static IMAC CAST6_MAC { get; } = new MAC(SymmetricAlgorithmHelper.CAST6);

        /// <summary>
        /// Hash size 32 bits. Legal key size 64 bits.
        /// </summary>
        public static IMAC DES_MAC { get; } = new MAC(SymmetricAlgorithmHelper.DES);

        /// <summary>
        /// DESede, DESede3, TDEA, TripleDES, 3DES.
        /// <para/>Hash size 32 bits. Legal key size 128, 192 bits.
        /// </summary>
        public static IMAC DESede_MAC { get; } = new MAC(SymmetricAlgorithmHelper.DESede);

        /// <summary>
        /// Hash size 64 bits. Legal key size 128, 256 bits.
        /// </summary>
        public static IMAC DSTU7624_128_MAC { get; } = new MAC(SymmetricAlgorithmHelper.DSTU7624_128);

        /// <summary>
        /// Hash size 128 bits. Legal key size 256, 512 bits.
        /// </summary>
        public static IMAC DSTU7624_256_MAC { get; } = new MAC(SymmetricAlgorithmHelper.DSTU7624_256);

        /// <summary>
        /// Hash size 256 bits. Legal key size 512 bits.
        /// </summary>
        public static IMAC DSTU7624_512_MAC { get; } = new MAC(SymmetricAlgorithmHelper.DSTU7624_512);

        /// <summary>
        /// Hash size 32 bits. Legal key size 256 bits.
        /// </summary>
        public static IMAC GOST28147_MAC { get; } = new MAC(SymmetricAlgorithmHelper.GOST28147);

        /// <summary>
        /// Hash size 32 bits. Legal key size 8-128 bits (8 bits increments).
        /// </summary>
        public static IMAC IDEA_MAC { get; } = new MAC(SymmetricAlgorithmHelper.IDEA);

        /// <summary>
        /// Hash size 64 bits. Legal key size 128 bits.
        /// </summary>
        public static IMAC Noekeon_MAC { get; } = new MAC(SymmetricAlgorithmHelper.Noekeon);

        /// <summary>
        /// Hash size 32 bits. Legal key size 8-1024 bits (8 bits increments).
        /// </summary>
        public static IMAC RC2_MAC { get; } = new MAC(SymmetricAlgorithmHelper.RC2);

        /// <summary>
        /// Hash size 64 bits. Legal key size 8-2040 bits (8 bits increments).
        /// </summary>
        public static IMAC RC5_64_MAC { get; } = new MAC(SymmetricAlgorithmHelper.RC5_64);

        /// <summary>
        /// Hash size 32 bits. Legal key size 8-2040 bits (8 bits increments).
        /// </summary>
        public static IMAC RC5_MAC { get; } = new MAC(SymmetricAlgorithmHelper.RC5);

        /// <summary>
        /// Hash size 64 bits. Legal key size is more than or equal to 8 bits (8 bits increments).
        /// </summary>
        public static IMAC RC6_MAC { get; } = new MAC(SymmetricAlgorithmHelper.RC6);

        /// <summary>
        /// Hash size 64 bits. Legal key size 128, 160, 192, 224, 256 bits.
        /// </summary>
        public static IMAC Rijndael_128_MAC { get; } = new MAC(SymmetricAlgorithmHelper.Rijndael_128);

        /// <summary>
        /// Hash size 80 bits. Legal key size 128, 160, 192, 224, 256 bits.
        /// </summary>
        public static IMAC Rijndael_160_MAC { get; } = new MAC(SymmetricAlgorithmHelper.Rijndael_160);

        /// <summary>
        /// Hash size 96 bits. Legal key size 128, 160, 192, 224, 256 bits.
        /// </summary>
        public static IMAC Rijndael_192_MAC { get; } = new MAC(SymmetricAlgorithmHelper.Rijndael_192);

        /// <summary>
        /// Hash size 112 bits. Legal key size 128, 160, 192, 224, 256 bits.
        /// </summary>
        public static IMAC Rijndael_224_MAC { get; } = new MAC(SymmetricAlgorithmHelper.Rijndael_224);

        /// <summary>
        /// Hash size 128 bits. Legal key size 128, 160, 192, 224, 256 bits.
        /// </summary>
        public static IMAC Rijndael_256_MAC { get; } = new MAC(SymmetricAlgorithmHelper.Rijndael_256);

        /// <summary>
        /// Hash size 64 bits. Legal key size 128 bits.
        /// </summary>
        public static IMAC SEED_MAC { get; } = new MAC(SymmetricAlgorithmHelper.SEED);

        /// <summary>
        /// Hash size 64 bits. Legal key size 32-512 bits (32 bits increments).
        /// </summary>
        public static IMAC Serpent_MAC { get; } = new MAC(SymmetricAlgorithmHelper.Serpent);

        /// <summary>
        /// Hash size 32 bits. Legal key size 128 bits.
        /// </summary>
        public static IMAC SKIPJACK_MAC { get; } = new MAC(SymmetricAlgorithmHelper.SKIPJACK);

        /// <summary>
        /// Hash size 64 bits. Legal key size 128 bits.
        /// </summary>
        public static IMAC SM4_MAC { get; } = new MAC(SymmetricAlgorithmHelper.SM4);

        /// <summary>
        /// Hash size 32 bits. Legal key size 128 bits.
        /// </summary>
        public static IMAC TEA_MAC { get; } = new MAC(SymmetricAlgorithmHelper.TEA);

        /// <summary>
        /// Hash size 512 bits. Legal key size 1024 bits.
        /// </summary>
        public static IMAC Threefish_1024_MAC { get; } = new MAC(SymmetricAlgorithmHelper.Threefish_1024);

        /// <summary>
        /// Hash size 128 bits. Legal key size 256 bits.
        /// </summary>
        public static IMAC Threefish_256_MAC { get; } = new MAC(SymmetricAlgorithmHelper.Threefish_256);

        /// <summary>
        /// Hash size 256 bits. Legal key size 512 bits.
        /// </summary>
        public static IMAC Threefish_512_MAC { get; } = new MAC(SymmetricAlgorithmHelper.Threefish_512);

        /// <summary>
        /// Hash size 64 bits. Legal key size 32-512 bits (32 bits increments).
        /// </summary>
        public static IMAC Tnepres_MAC { get; } = new MAC(SymmetricAlgorithmHelper.Tnepres);

        /// <summary>
        /// Hash size 64 bits. Legal key size 64-256 bits (64 bits increments).
        /// </summary>
        public static IMAC Twofish_MAC { get; } = new MAC(SymmetricAlgorithmHelper.Twofish);

        /// <summary>
        /// Hash size 32 bits. Legal key size 128 bits.
        /// </summary>
        public static IMAC XTEA_MAC { get; } = new MAC(SymmetricAlgorithmHelper.XTEA);

        #endregion MAC

        /// <summary>
        /// Try get algorithm from mechanism.
        /// <para/>Used (block size / 2) as mac size by default.
        /// </summary>
        /// <param name="mechanism">Algorithm mechanism.</param>
        /// <param name="algorithm">Algorithm.</param>
        /// <returns></returns>
        public static bool TryGetAlgorithm(string mechanism, out IMAC algorithm)
        {
            return TryGetAlgorithm(mechanism, -1, out algorithm);
        }

        /// <summary>
        /// Try get algorithm from mechanism.
        /// <para/>Legal mac size is between 8 and block size (8 bits increments).
        /// <para/>Legal mac size must be at least 24 bits (FIPS Publication 81) or 16 bits if being used as a data authenticator (FIPS Publication 113).
        /// <para/>Used (block size / 2) as mac size by default.
        /// </summary>
        /// <param name="mechanism">Algorithm mechanism.</param>
        /// <param name="macSize">MAC size bits.</param>
        /// <param name="algorithm">Algorithm.</param>
        /// <returns></returns>
        public static bool TryGetAlgorithm(string mechanism, int macSize, out IMAC algorithm)
        {
            mechanism = mechanism.Replace('_', '-').ToUpperInvariant();
            if (mechanism.EndsWith("MAC"))
            {
                if (mechanism.EndsWith("/MAC") || mechanism.EndsWith("-MAC"))
                {
                    mechanism = mechanism.Substring(0, mechanism.Length - 4);
                }
                else
                {
                    mechanism = mechanism.Substring(0, mechanism.Length - 3);
                }
            }
            mechanism = mechanism.Replace('/', '-');
            switch (mechanism)
            {
                case "AES": return TryGetNanoAlgorithm(AES_MAC, macSize, out algorithm);
                case "BLOWFISH": return TryGetNanoAlgorithm(Blowfish_MAC, macSize, out algorithm);
                case "CAMELLIA": return TryGetNanoAlgorithm(Camellia_MAC, macSize, out algorithm);
                case "CAST5": return TryGetNanoAlgorithm(CAST5_MAC, macSize, out algorithm);
                case "CAST6": return TryGetNanoAlgorithm(CAST6_MAC, macSize, out algorithm);
                case "DES": return TryGetNanoAlgorithm(DES_MAC, macSize, out algorithm);
                case "DESEDE": case "DESEDE3": case "TDEA": case "TRIPLEDES": case "3DES": return TryGetNanoAlgorithm(DESede_MAC, macSize, out algorithm);
                case "DSTU7624-128": return TryGetNanoAlgorithm(DSTU7624_128_MAC, macSize, out algorithm);
                case "DSTU7624-256": return TryGetNanoAlgorithm(DSTU7624_256_MAC, macSize, out algorithm);
                case "DSTU7624-512": return TryGetNanoAlgorithm(DSTU7624_512_MAC, macSize, out algorithm);
                case "GOST28147": return TryGetNanoAlgorithm(GOST28147_MAC, macSize, out algorithm);
                case "IDEA": return TryGetNanoAlgorithm(IDEA_MAC, macSize, out algorithm);
                case "NOEKEON": return TryGetNanoAlgorithm(Noekeon_MAC, macSize, out algorithm);
                case "RC2": return TryGetNanoAlgorithm(RC2_MAC, macSize, out algorithm);
                case "RC5": case "RC5-32": return TryGetNanoAlgorithm(RC5_MAC, macSize, out algorithm);
                case "RC5-64": return TryGetNanoAlgorithm(RC5_64_MAC, macSize, out algorithm);
                case "RC6": return TryGetNanoAlgorithm(RC6_MAC, macSize, out algorithm);
                case "RIJNDAEL-128": case "RIJNDAEL128": return TryGetNanoAlgorithm(Rijndael_128_MAC, macSize, out algorithm);
                case "RIJNDAEL-160": case "RIJNDAEL160": return TryGetNanoAlgorithm(Rijndael_160_MAC, macSize, out algorithm);
                case "RIJNDAEL-192": case "RIJNDAEL192": return TryGetNanoAlgorithm(Rijndael_192_MAC, macSize, out algorithm);
                case "RIJNDAEL-224": case "RIJNDAEL224": return TryGetNanoAlgorithm(Rijndael_224_MAC, macSize, out algorithm);
                case "RIJNDAEL-256": case "RIJNDAEL256": return TryGetNanoAlgorithm(Rijndael_256_MAC, macSize, out algorithm);
                case "SEED": return TryGetNanoAlgorithm(SEED_MAC, macSize, out algorithm);
                case "SERPENT": return TryGetNanoAlgorithm(Serpent_MAC, macSize, out algorithm);
                case "SKIPJACK": return TryGetNanoAlgorithm(SKIPJACK_MAC, macSize, out algorithm);
                case "SM4": return TryGetNanoAlgorithm(SM4_MAC, macSize, out algorithm);
                case "TEA": return TryGetNanoAlgorithm(TEA_MAC, macSize, out algorithm);
                case "THREEFISH-256": case "THREEFISH256": return TryGetNanoAlgorithm(Threefish_256_MAC, macSize, out algorithm);
                case "THREEFISH-512": case "THREEFISH512": return TryGetNanoAlgorithm(Threefish_512_MAC, macSize, out algorithm);
                case "THREEFISH-1024": case "THREEFISH1024": return TryGetNanoAlgorithm(Threefish_1024_MAC, macSize, out algorithm);
                case "TNEPRES": return TryGetNanoAlgorithm(Tnepres_MAC, macSize, out algorithm);
                case "TWOFISH": return TryGetNanoAlgorithm(Twofish_MAC, macSize, out algorithm);
                case "XTEA": return TryGetNanoAlgorithm(XTEA_MAC, macSize, out algorithm);
                default: algorithm = null; return false;
            }
        }

        private static bool TryGetNanoAlgorithm(IMAC referent, int macSize, out IMAC algorithm)
        {
            if (macSize == -1)
            {
                algorithm = referent;
                return true;
            }
            else if (macSize == referent.BlockSize / 2)
            {
                algorithm = referent;
                return true;
            }
            else if (macSize >= 8 && macSize <= referent.BlockSize && macSize % 8 == 0)
            {
                algorithm = new MAC(((MAC)referent).BlockAlgorithm, macSize);
                return true;
            }
            else
            {
                algorithm = null;
                return false;
            }
        }
    }
}