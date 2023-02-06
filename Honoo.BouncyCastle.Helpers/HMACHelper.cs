using Honoo.BouncyCastle.Helpers.Security.Crypto.Hash;

namespace Honoo.BouncyCastle.Helpers
{
    /// <summary>
    /// HMAC algorithm helper.
    /// </summary>
    public static class HMACHelper
    {
        /// <summary>
        /// Try get HMAC algorithm from mechanism.
        /// </summary>
        /// <param name="mechanism">HMAC algorithm mechanism.</param>
        /// <param name="algorithm">HMAC algorithm.</param>
        /// <returns></returns>
        public static bool TryGetAlgorithm(string mechanism, out IHMAC algorithm)
        {
            if (string.IsNullOrWhiteSpace(mechanism))
            {
                algorithm = null;
                return false;
            }
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
                case "BLAKE2B-256": algorithm = HMACAlgorithms.BLAKE2b_256_HMAC; return true;
                case "BLAKE2B-384": algorithm = HMACAlgorithms.BLAKE2b_384_HMAC; return true;
                case "BLAKE2B-512": algorithm = HMACAlgorithms.BLAKE2b_512_HMAC; return true;
                case "BLAKE2S-256": algorithm = HMACAlgorithms.BLAKE2s_256_HMAC; return true;
                case "CSHAKE128": case "CSHAKE-128": algorithm = HMACAlgorithms.CSHAKE_128_HMAC; return true;
                case "CSHAKE256": case "CSHAKE-256": algorithm = HMACAlgorithms.CSHAKE_256_HMAC; return true;
                case "DSTU7564-256": algorithm = HMACAlgorithms.DSTU7564_256_HMAC; return true;
                case "DSTU7564-384": algorithm = HMACAlgorithms.DSTU7564_384_HMAC; return true;
                case "DSTU7564-512": algorithm = HMACAlgorithms.DSTU7564_512_HMAC; return true;
                case "GOST3411": algorithm = HMACAlgorithms.GOST3411_HMAC; return true;
                case "GOST3411-2012-256": algorithm = HMACAlgorithms.GOST3411_2012_256_HMAC; return true;
                case "GOST3411-2012-512": algorithm = HMACAlgorithms.GOST3411_2012_512_HMAC; return true;
                case "KECCAK-128": case "KECCAK128": algorithm = HMACAlgorithms.Keccak_128_HMAC; return true;
                case "KECCAK-224": case "KECCAK224": algorithm = HMACAlgorithms.Keccak_224_HMAC; return true;
                case "KECCAK-256": case "KECCAK256": algorithm = HMACAlgorithms.Keccak_256_HMAC; return true;
                case "KECCAK-288": case "KECCAK288": algorithm = HMACAlgorithms.Keccak_288_HMAC; return true;
                case "KECCAK-384": case "KECCAK384": algorithm = HMACAlgorithms.Keccak_384_HMAC; return true;
                case "KECCAK-512": case "KECCAK512": algorithm = HMACAlgorithms.Keccak_512_HMAC; return true;
                case "MD2": algorithm = HMACAlgorithms.MD2_HMAC; return true;
                case "MD4": algorithm = HMACAlgorithms.MD4_HMAC; return true;
                case "MD5": algorithm = HMACAlgorithms.MD5_HMAC; return true;
                case "RIPEMD128": case "RIPEMD-128": algorithm = HMACAlgorithms.RIPEMD128_HMAC; return true;
                case "RIPEMD160": case "RIPEMD-160": algorithm = HMACAlgorithms.RIPEMD160_HMAC; return true;
                case "RIPEMD256": case "RIPEMD-256": algorithm = HMACAlgorithms.RIPEMD256_HMAC; return true;
                case "RIPEMD320": case "RIPEMD-320": algorithm = HMACAlgorithms.RIPEMD320_HMAC; return true;
                case "SHA1": case "SHA-1": algorithm = HMACAlgorithms.SHA1_HMAC; return true;
                case "SHA224": case "SHA-224": algorithm = HMACAlgorithms.SHA224_HMAC; return true;
                case "SHA256": case "SHA-256": algorithm = HMACAlgorithms.SHA256_HMAC; return true;
                case "SHA384": case "SHA-384": algorithm = HMACAlgorithms.SHA384_HMAC; return true;
                case "SHA512": case "SHA-512": algorithm = HMACAlgorithms.SHA512_HMAC; return true;
                case "SHA512-224": case "SHA-512-224": case "SHA512/224": case "SHA-512/224": algorithm = HMACAlgorithms.SHA512_224_HMAC; return true;
                case "SHA512-256": case "SHA-512-256": case "SHA512/256": case "SHA-512/256": algorithm = HMACAlgorithms.SHA512_256_HMAC; return true;
                case "SHA3-224": case "SHA-3-224": algorithm = HMACAlgorithms.SHA3_224_HMAC; return true;
                case "SHA3-256": case "SHA-3-256": algorithm = HMACAlgorithms.SHA3_256_HMAC; return true;
                case "SHA3-384": case "SHA-3-384": algorithm = HMACAlgorithms.SHA3_384_HMAC; return true;
                case "SHA3-512": case "SHA-3-512": algorithm = HMACAlgorithms.SHA3_512_HMAC; return true;
                case "SHAKE128": case "SHAKE-128": algorithm = HMACAlgorithms.SHAKE_128_HMAC; return true;
                case "SHAKE256": case "SHAKE-256": algorithm = HMACAlgorithms.SHAKE_256_HMAC; return true;
                case "SKEIN-256-256": algorithm = HMACAlgorithms.Skein_256_256_HMAC; return true;
                case "SKEIN-512-512": algorithm = HMACAlgorithms.Skein_512_512_HMAC; return true;
                case "SKEIN-1024-1024": algorithm = HMACAlgorithms.Skein_1024_1024_HMAC; return true;
                case "SM3": algorithm = HMACAlgorithms.SM3_HMAC; return true;
                case "TIGER": algorithm = HMACAlgorithms.Tiger_HMAC; return true;
                case "WHIRLPOOL": algorithm = HMACAlgorithms.Whirlpool_HMAC; return true;

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