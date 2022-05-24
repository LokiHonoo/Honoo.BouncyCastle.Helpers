using Honoo.BouncyCastle.Helpers.Security.Crypto.Hash;
using Honoo.BouncyCastle.Helpers.Utilities;

namespace Honoo.BouncyCastle.Helpers
{
    /// <summary>
    /// Hash algorithm helper.
    /// </summary>
    public static class HashAlgorithmHelper
    {
        #region Hash algorithms

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

        #endregion Hash algorithms

        /// <summary>
        /// Try get hash algorithm from mechanism.
        /// </summary>
        /// <param name="mechanism">Hash algorithm mechanism.</param>
        /// <param name="algorithm">Hash algorithm.</param>
        /// <returns></returns>
        public static bool TryGetAlgorithm(string mechanism, out IHashAlgorithm algorithm)
        {
            if (string.IsNullOrWhiteSpace(mechanism))
            {
                algorithm = null;
                return false;
            }
            mechanism = mechanism.Replace('_', '-').ToUpperInvariant();
            switch (mechanism)
            {
                case "BLAKE2B-256": algorithm = BLAKE2b_256; return true;
                case "BLAKE2B-384": algorithm = BLAKE2b_384; return true;
                case "BLAKE2B-512": algorithm = BLAKE2b_512; return true;
                case "BLAKE2S-256": algorithm = BLAKE2s_256; return true;
                case "CSHAKE128": case "CSHAKE-128": algorithm = new CSHAKE(128, null, null); return true;
                case "CSHAKE256": case "CSHAKE-256": algorithm = new CSHAKE(256, null, null); return true;
                case "DSTU7564-256": algorithm = DSTU7564_256; return true;
                case "DSTU7564-384": algorithm = DSTU7564_384; return true;
                case "DSTU7564-512": algorithm = DSTU7564_512; return true;
                case "GOST3411": algorithm = GOST3411; return true;
                case "GOST3411-2012-256": algorithm = GOST3411_2012_256; return true;
                case "GOST3411-2012-512": algorithm = GOST3411_2012_512; return true;
                case "KECCAK-128": case "KECCAK128": algorithm = Keccak_128; return true;
                case "KECCAK-224": case "KECCAK224": algorithm = Keccak_224; return true;
                case "KECCAK-256": case "KECCAK256": algorithm = Keccak_256; return true;
                case "KECCAK-288": case "KECCAK288": algorithm = Keccak_288; return true;
                case "KECCAK-384": case "KECCAK384": algorithm = Keccak_384; return true;
                case "KECCAK-512": case "KECCAK512": algorithm = Keccak_512; return true;
                case "MD2": algorithm = MD2; return true;
                case "MD4": algorithm = MD4; return true;
                case "MD5": algorithm = MD5; return true;
                case "RIPEMD128": case "RIPEMD-128": algorithm = RIPEMD128; return true;
                case "RIPEMD160": case "RIPEMD-160": algorithm = RIPEMD160; return true;
                case "RIPEMD256": case "RIPEMD-256": algorithm = RIPEMD256; return true;
                case "RIPEMD320": case "RIPEMD-320": algorithm = RIPEMD320; return true;
                case "SHA1": case "SHA-1": algorithm = SHA1; return true;
                case "SHA224": case "SHA-224": algorithm = SHA224; return true;
                case "SHA256": case "SHA-256": algorithm = SHA256; return true;
                case "SHA384": case "SHA-384": algorithm = SHA384; return true;
                case "SHA512": case "SHA-512": algorithm = SHA512; return true;
                case "SHA512-224": case "SHA-512-224": case "SHA512/224": case "SHA-512/224": algorithm = SHA512_224; return true;
                case "SHA512-256": case "SHA-512-256": case "SHA512/256": case "SHA-512/256": algorithm = SHA512_256; return true;
                case "SHA3-224": case "SHA-3-224": algorithm = SHA3_224; return true;
                case "SHA3-256": case "SHA-3-256": algorithm = SHA3_256; return true;
                case "SHA3-384": case "SHA-3-384": algorithm = SHA3_384; return true;
                case "SHA3-512": case "SHA-3-512": algorithm = SHA3_512; return true;
                case "SHAKE128": case "SHAKE-128": algorithm = SHAKE_128; return true;
                case "SHAKE256": case "SHAKE-256": algorithm = SHAKE_256; return true;
                case "SKEIN-256-256": algorithm = Skein_256_256; return true;
                case "SKEIN-512-512": algorithm = Skein_512_512; return true;
                case "SKEIN-1024-1024": algorithm = Skein_1024_1024; return true;
                case "SM3": algorithm = SM3; return true;
                case "TIGER": algorithm = Tiger; return true;
                case "WHIRLPOOL": algorithm = Whirlpool; return true;

                default: break;
            }
            return TryGetAlgorithmNano(mechanism, out algorithm);
        }

        internal static bool TryGetAlgorithmNano(string mechanism, out IHashAlgorithm algorithm)
        {
            string name = string.Empty;
            int hashSize = 0;
            int stateSize = 0;
            if (mechanism.StartsWith("BLAKE2B") || mechanism.StartsWith("BLAKE2S"))
            {
                string[] splits = mechanism.Split('-');
                if (splits.Length == 2 && int.TryParse(splits[1], out hashSize))
                {
                    name = splits[0];
                }
            }
            else if (mechanism.StartsWith("SHA512"))
            {
                mechanism = mechanism.Replace('/', '-');
                string[] splits = mechanism.Split('-');
                if (splits.Length == 2 && int.TryParse(splits[1], out hashSize))
                {
                    name = "SHA512T";
                }
            }
            else if (mechanism.StartsWith("SHA-512"))
            {
                mechanism = mechanism.Replace('/', '-');
                string[] splits = mechanism.Split('-');
                if (splits.Length == 3 && int.TryParse(splits[2], out hashSize))
                {
                    name = "SHA512T";
                }
            }
            else if (mechanism.StartsWith("SKEIN"))
            {
                string[] splits = mechanism.Split('-');
                if (splits.Length == 3 && int.TryParse(splits[1], out stateSize) && int.TryParse(splits[2], out hashSize))
                {
                    name = splits[0];
                }
            }
            if (name.Length > 0)
            {
                bool legal;
                switch (name)
                {
                    case "BLAKE2B":
                        {
                            legal = DetectionUtilities.ValidSize(BLAKE2b.HashSizes, hashSize);
                            algorithm = legal ? new BLAKE2b(hashSize) : null;
                            return legal;
                        }

                    case "BLAKE2S":
                        {
                            legal = DetectionUtilities.ValidSize(BLAKE2s.HashSizes, hashSize);
                            algorithm = legal ? new BLAKE2s(hashSize) : null;
                            return legal;
                        }

                    case "SHA512T":
                        {
                            legal = DetectionUtilities.ValidSize(SHA512T.HashSizes, hashSize);
                            algorithm = legal ? new SHA512T(hashSize) : null;
                            return legal;
                        }
                    case "SKEIN":
                        {
                            legal = DetectionUtilities.ValidSize(Skein.HashSizes, hashSize);
                            legal &= DetectionUtilities.ValidSize(Skein.StateSizes, stateSize);
                            algorithm = legal ? new Skein(hashSize, stateSize) : null;
                            return legal;
                        }
                    default: algorithm = null; return false;
                }
            }
            algorithm = null;
            return false;
        }
    }
}