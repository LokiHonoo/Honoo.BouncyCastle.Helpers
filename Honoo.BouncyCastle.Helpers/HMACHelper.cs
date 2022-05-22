using Honoo.BouncyCastle.Helpers.Security.Crypto.Hash;

namespace Honoo.BouncyCastle.Helpers
{
    /// <summary>
    /// HMAC algorithm helper.
    /// </summary>
    public static class HMACHelper
    {
        #region HMAC

        /// <summary>
        /// Hash size 256 bits.
        /// </summary>
        public static IHMAC BLAKE2b_256_HMAC { get; } = new HMAC(HashAlgorithmHelper.BLAKE2b_256);

        /// <summary>
        /// Hash size 384 bits.
        /// </summary>
        public static IHMAC BLAKE2b_384_HMAC { get; } = new HMAC(HashAlgorithmHelper.BLAKE2b_384);

        /// <summary>
        /// Hash size 512 bits.
        /// </summary>
        public static IHMAC BLAKE2b_512_HMAC { get; } = new HMAC(HashAlgorithmHelper.BLAKE2b_512);

        /// <summary>
        /// Hash size 256 bits.
        /// </summary>
        public static IHMAC BLAKE2s_256_HMAC { get; } = new HMAC(HashAlgorithmHelper.BLAKE2s_256);

        /// <summary>
        /// Hash size 256 bits.
        /// </summary>
        public static IHMAC DSTU7564_256_HMAC { get; } = new HMAC(HashAlgorithmHelper.DSTU7564_256);

        /// <summary>
        /// Hash size 384 bits.
        /// </summary>
        public static IHMAC DSTU7564_384_HMAC { get; } = new HMAC(HashAlgorithmHelper.DSTU7564_384);

        /// <summary>
        /// Hash size 512 bits.
        /// </summary>
        public static IHMAC DSTU7564_512_HMAC { get; } = new HMAC(HashAlgorithmHelper.DSTU7564_512);

        /// <summary>
        /// Hash size 256 bits.
        /// </summary>
        public static IHMAC GOST3411_2012_256_HMAC { get; } = new HMAC(HashAlgorithmHelper.GOST3411_2012_256);

        /// <summary>
        /// Hash size 512 bits.
        /// </summary>
        public static IHMAC GOST3411_2012_512_HMAC { get; } = new HMAC(HashAlgorithmHelper.GOST3411_2012_512);

        /// <summary>
        /// Hash size 256 bits.
        /// <para/>Uses substitution box "D-A" by default.
        /// </summary>
        public static IHMAC GOST3411_HMAC { get; } = new HMAC(HashAlgorithmHelper.GOST3411);

        /// <summary>
        /// Hash size 128 bits.
        /// </summary>
        public static IHMAC Keccak_128_HMAC { get; } = new HMAC(HashAlgorithmHelper.Keccak_128);

        /// <summary>
        /// Hash size 224 bits.
        /// </summary>
        public static IHMAC Keccak_224_HMAC { get; } = new HMAC(HashAlgorithmHelper.Keccak_224);

        /// <summary>
        /// Hash size 256 bits.
        /// </summary>
        public static IHMAC Keccak_256_HMAC { get; } = new HMAC(HashAlgorithmHelper.Keccak_256);

        /// <summary>
        /// Hash size 288 bits.
        /// </summary>
        public static IHMAC Keccak_288_HMAC { get; } = new HMAC(HashAlgorithmHelper.Keccak_288);

        /// <summary>
        /// Hash size 384 bits.
        /// </summary>
        public static IHMAC Keccak_384_HMAC { get; } = new HMAC(HashAlgorithmHelper.Keccak_384);

        /// <summary>
        /// Hash size 512 bits.
        /// </summary>
        public static IHMAC Keccak_512_HMAC { get; } = new HMAC(HashAlgorithmHelper.Keccak_512);

        /// <summary>
        /// Hash size 128 bits.
        /// </summary>
        public static IHMAC MD2_HMAC { get; } = new HMAC(HashAlgorithmHelper.MD2);

        /// <summary>
        /// Hash size 128 bits.
        /// </summary>
        public static IHMAC MD4_HMAC { get; } = new HMAC(HashAlgorithmHelper.MD4);

        /// <summary>
        /// Hash size 128 bits.
        /// </summary>
        public static IHMAC MD5_HMAC { get; } = new HMAC(HashAlgorithmHelper.MD5);

        /// <summary>
        /// Hash size 128 bits.
        /// </summary>
        public static IHMAC RIPEMD128_HMAC { get; } = new HMAC(HashAlgorithmHelper.RIPEMD128);

        /// <summary>
        /// Hash size 160 bits.
        /// </summary>
        public static IHMAC RIPEMD160_HMAC { get; } = new HMAC(HashAlgorithmHelper.RIPEMD160);

        /// <summary>
        /// Hash size 256 bits.
        /// </summary>
        public static IHMAC RIPEMD256_HMAC { get; } = new HMAC(HashAlgorithmHelper.RIPEMD256);

        /// <summary>
        /// Hash size 320 bits.
        /// </summary>
        public static IHMAC RIPEMD320_HMAC { get; } = new HMAC(HashAlgorithmHelper.RIPEMD320);

        /// <summary>
        /// Hash size 160 bits.
        /// </summary>
        public static IHMAC SHA1_HMAC { get; } = new HMAC(HashAlgorithmHelper.SHA1);

        /// <summary>
        /// Hash size 224 bits.
        /// </summary>
        public static IHMAC SHA224_HMAC { get; } = new HMAC(HashAlgorithmHelper.SHA224);

        /// <summary>
        /// Hash size 256 bits.
        /// </summary>
        public static IHMAC SHA256_HMAC { get; } = new HMAC(HashAlgorithmHelper.SHA256);

        /// <summary>
        /// Hash size 224 bits.
        /// </summary>
        public static IHMAC SHA3_224_HMAC { get; } = new HMAC(HashAlgorithmHelper.SHA3_224);

        /// <summary>
        /// Hash size 256 bits.
        /// </summary>
        public static IHMAC SHA3_256_HMAC { get; } = new HMAC(HashAlgorithmHelper.SHA3_256);

        /// <summary>
        /// Hash size 384 bits.
        /// </summary>
        public static IHMAC SHA3_384_HMAC { get; } = new HMAC(HashAlgorithmHelper.SHA3_384);

        /// <summary>
        /// Hash size 512 bits.
        /// </summary>
        public static IHMAC SHA3_512_HMAC { get; } = new HMAC(HashAlgorithmHelper.SHA3_512);

        /// <summary>
        /// Hash size 384 bits.
        /// </summary>
        public static IHMAC SHA384_HMAC { get; } = new HMAC(HashAlgorithmHelper.SHA384);

        /// <summary>
        /// Hash size 224 bits.
        /// </summary>
        public static IHMAC SHA512_224_HMAC { get; } = new HMAC(HashAlgorithmHelper.SHA512_224);

        /// <summary>
        /// Hash size 256 bits.
        /// </summary>
        public static IHMAC SHA512_256_HMAC { get; } = new HMAC(HashAlgorithmHelper.SHA512_256);

        /// <summary>
        /// Hash size 512 bits.
        /// </summary>
        public static IHMAC SHA512_HMAC { get; } = new HMAC(HashAlgorithmHelper.SHA512);

        /// <summary>
        /// Hash size 128 bits.
        /// </summary>
        public static IHMAC SHAKE_128_HMAC { get; } = new HMAC(HashAlgorithmHelper.SHAKE_128);

        /// <summary>
        /// Hash size 256 bits.
        /// </summary>
        public static IHMAC SHAKE_256_HMAC { get; } = new HMAC(HashAlgorithmHelper.SHAKE_256);

        /// <summary>
        /// Hash size 1024 bits.
        /// </summary>
        public static IHMAC Skein_1024_1024_HMAC { get; } = new HMAC(HashAlgorithmHelper.Skein_1024_1024);

        /// <summary>
        /// Hash size 256 bits.
        /// </summary>
        public static IHMAC Skein_256_256_HMAC { get; } = new HMAC(HashAlgorithmHelper.Skein_256_256);

        /// <summary>
        /// Hash size 512 bits.
        /// </summary>
        public static IHMAC Skein_512_512_HMAC { get; } = new HMAC(HashAlgorithmHelper.Skein_512_512);

        /// <summary>
        /// Hash size 256 bits.
        /// </summary>
        public static IHMAC SM3_HMAC { get; } = new HMAC(HashAlgorithmHelper.SM3);

        /// <summary>
        /// Hash size 192 bits.
        /// </summary>
        public static IHMAC Tiger_HMAC { get; } = new HMAC(HashAlgorithmHelper.Tiger);

        /// <summary>
        /// Hash size 512 bits.
        /// </summary>
        public static IHMAC Whirlpool_HMAC { get; } = new HMAC(HashAlgorithmHelper.Whirlpool);

        #endregion HMAC

        /// <summary>
        /// Try get HMAC algorithm from mechanism.
        /// </summary>
        /// <param name="mechanism">HMAC algorithm mechanism.</param>
        /// <param name="algorithm">HMAC algorithm.</param>
        /// <returns></returns>
        public static bool TryGetAlgorithm(string mechanism, out IHMAC algorithm)
        {
            mechanism = mechanism.Replace('_', '-').ToUpperInvariant();
            if (mechanism.EndsWith("HMAC"))
            {
                if (mechanism.EndsWith("/HMAC") || mechanism.EndsWith("-HMAC"))
                {
                    mechanism = mechanism.Substring(0, mechanism.Length - 5);
                }
                else
                {
                    mechanism = mechanism.Substring(0, mechanism.Length - 4);
                }
            }
            if (mechanism.StartsWith("HMAC"))
            {
                if (mechanism.StartsWith("HMAC/") || mechanism.StartsWith("HMAC-"))
                {
                    mechanism = mechanism.Substring(5);
                }
                else
                {
                    mechanism = mechanism.Substring(4);
                }
            }
            switch (mechanism)
            {
                case "BLAKE2B-256": algorithm = BLAKE2b_256_HMAC; return true;
                case "BLAKE2B-384": algorithm = BLAKE2b_384_HMAC; return true;
                case "BLAKE2B-512": algorithm = BLAKE2b_512_HMAC; return true;
                case "BLAKE2S-256": algorithm = BLAKE2s_256_HMAC; return true;
                case "DSTU7564-256": algorithm = DSTU7564_256_HMAC; return true;
                case "DSTU7564-384": algorithm = DSTU7564_384_HMAC; return true;
                case "DSTU7564-512": algorithm = DSTU7564_512_HMAC; return true;
                case "GOST3411": algorithm = GOST3411_HMAC; return true;
                case "GOST3411-2012-256": algorithm = GOST3411_2012_256_HMAC; return true;
                case "GOST3411-2012-512": algorithm = GOST3411_2012_512_HMAC; return true;
                case "KECCAK-128": case "KECCAK128": algorithm = Keccak_128_HMAC; return true;
                case "KECCAK-224": case "KECCAK224": algorithm = Keccak_224_HMAC; return true;
                case "KECCAK-256": case "KECCAK256": algorithm = Keccak_256_HMAC; return true;
                case "KECCAK-288": case "KECCAK288": algorithm = Keccak_288_HMAC; return true;
                case "KECCAK-384": case "KECCAK384": algorithm = Keccak_384_HMAC; return true;
                case "KECCAK-512": case "KECCAK512": algorithm = Keccak_512_HMAC; return true;
                case "MD2": algorithm = MD2_HMAC; return true;
                case "MD4": algorithm = MD4_HMAC; return true;
                case "MD5": algorithm = MD5_HMAC; return true;
                case "RIPEMD128": case "RIPEMD-128": algorithm = RIPEMD128_HMAC; return true;
                case "RIPEMD160": case "RIPEMD-160": algorithm = RIPEMD160_HMAC; return true;
                case "RIPEMD256": case "RIPEMD-256": algorithm = RIPEMD256_HMAC; return true;
                case "RIPEMD320": case "RIPEMD-320": algorithm = RIPEMD320_HMAC; return true;
                case "SHA1": case "SHA-1": algorithm = SHA1_HMAC; return true;
                case "SHA224": case "SHA-224": algorithm = SHA224_HMAC; return true;
                case "SHA256": case "SHA-256": algorithm = SHA256_HMAC; return true;
                case "SHA384": case "SHA-384": algorithm = SHA384_HMAC; return true;
                case "SHA512": case "SHA-512": algorithm = SHA512_HMAC; return true;
                case "SHA512-224": case "SHA-512-224": case "SHA512/224": case "SHA-512/224": algorithm = SHA512_224_HMAC; return true;
                case "SHA512-256": case "SHA-512-256": case "SHA512/256": case "SHA-512/256": algorithm = SHA512_256_HMAC; return true;
                case "SHA3-224": case "SHA-3-224": algorithm = SHA3_224_HMAC; return true;
                case "SHA3-256": case "SHA-3-256": algorithm = SHA3_256_HMAC; return true;
                case "SHA3-384": case "SHA-3-384": algorithm = SHA3_384_HMAC; return true;
                case "SHA3-512": case "SHA-3-512": algorithm = SHA3_512_HMAC; return true;
                case "SHAKE128": case "SHAKE-128": algorithm = SHAKE_128_HMAC; return true;
                case "SHAKE256": case "SHAKE-256": algorithm = SHAKE_256_HMAC; return true;
                case "SKEIN-256-256": algorithm = Skein_256_256_HMAC; return true;
                case "SKEIN-512-512": algorithm = Skein_512_512_HMAC; return true;
                case "SKEIN-1024-1024": algorithm = Skein_1024_1024_HMAC; return true;
                case "SM3": algorithm = SM3_HMAC; return true;
                case "TIGER": algorithm = Tiger_HMAC; return true;
                case "WHIRLPOOL": algorithm = Whirlpool_HMAC; return true;

                default: break;
            }
            if (HashAlgorithmHelper.TryGetAlgorithmNano(mechanism, out IHashAlgorithm hashAlgorithm))
            {
                algorithm = new HMAC(hashAlgorithm);
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