using Honoo.BouncyCastle.Helpers.Security.Crypto.Hash;
using Honoo.BouncyCastle.Helpers.Utilities;

namespace Honoo.BouncyCastle.Helpers
{
    /// <summary>
    /// Hash algorithm helper.
    /// </summary>
    public static class HashAlgorithmHelper
    {
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
                case "BLAKE2B-256": algorithm = HashAlgorithms.BLAKE2b_256; return true;
                case "BLAKE2B-384": algorithm = HashAlgorithms.BLAKE2b_384; return true;
                case "BLAKE2B-512": algorithm = HashAlgorithms.BLAKE2b_512; return true;
                case "BLAKE2S-256": algorithm = HashAlgorithms.BLAKE2s_256; return true;
                case "CSHAKE128": case "CSHAKE-128": algorithm = HashAlgorithms.CSHAKE_128; return true;
                case "CSHAKE256": case "CSHAKE-256": algorithm = HashAlgorithms.CSHAKE_256; return true;
                case "DSTU7564-256": algorithm = HashAlgorithms.DSTU7564_256; return true;
                case "DSTU7564-384": algorithm = HashAlgorithms.DSTU7564_384; return true;
                case "DSTU7564-512": algorithm = HashAlgorithms.DSTU7564_512; return true;
                case "GOST3411": algorithm = HashAlgorithms.GOST3411; return true;
                case "GOST3411-2012-256": algorithm = HashAlgorithms.GOST3411_2012_256; return true;
                case "GOST3411-2012-512": algorithm = HashAlgorithms.GOST3411_2012_512; return true;
                case "KECCAK-128": case "KECCAK128": algorithm = HashAlgorithms.Keccak_128; return true;
                case "KECCAK-224": case "KECCAK224": algorithm = HashAlgorithms.Keccak_224; return true;
                case "KECCAK-256": case "KECCAK256": algorithm = HashAlgorithms.Keccak_256; return true;
                case "KECCAK-288": case "KECCAK288": algorithm = HashAlgorithms.Keccak_288; return true;
                case "KECCAK-384": case "KECCAK384": algorithm = HashAlgorithms.Keccak_384; return true;
                case "KECCAK-512": case "KECCAK512": algorithm = HashAlgorithms.Keccak_512; return true;
                case "MD2": algorithm = HashAlgorithms.MD2; return true;
                case "MD4": algorithm = HashAlgorithms.MD4; return true;
                case "MD5": algorithm = HashAlgorithms.MD5; return true;
                case "RIPEMD128": case "RIPEMD-128": algorithm = HashAlgorithms.RIPEMD128; return true;
                case "RIPEMD160": case "RIPEMD-160": algorithm = HashAlgorithms.RIPEMD160; return true;
                case "RIPEMD256": case "RIPEMD-256": algorithm = HashAlgorithms.RIPEMD256; return true;
                case "RIPEMD320": case "RIPEMD-320": algorithm = HashAlgorithms.RIPEMD320; return true;
                case "SHA1": case "SHA-1": algorithm = HashAlgorithms.SHA1; return true;
                case "SHA224": case "SHA-224": algorithm = HashAlgorithms.SHA224; return true;
                case "SHA256": case "SHA-256": algorithm = HashAlgorithms.SHA256; return true;
                case "SHA384": case "SHA-384": algorithm = HashAlgorithms.SHA384; return true;
                case "SHA512": case "SHA-512": algorithm = HashAlgorithms.SHA512; return true;
                case "SHA512-224": case "SHA-512-224": case "SHA512/224": case "SHA-512/224": algorithm = HashAlgorithms.SHA512_224; return true;
                case "SHA512-256": case "SHA-512-256": case "SHA512/256": case "SHA-512/256": algorithm = HashAlgorithms.SHA512_256; return true;
                case "SHA3-224": case "SHA-3-224": algorithm = HashAlgorithms.SHA3_224; return true;
                case "SHA3-256": case "SHA-3-256": algorithm = HashAlgorithms.SHA3_256; return true;
                case "SHA3-384": case "SHA-3-384": algorithm = HashAlgorithms.SHA3_384; return true;
                case "SHA3-512": case "SHA-3-512": algorithm = HashAlgorithms.SHA3_512; return true;
                case "SHAKE128": case "SHAKE-128": algorithm = HashAlgorithms.SHAKE_128; return true;
                case "SHAKE256": case "SHAKE-256": algorithm = HashAlgorithms.SHAKE_256; return true;
                case "SKEIN-256-256": algorithm = HashAlgorithms.Skein_256_256; return true;
                case "SKEIN-512-512": algorithm = HashAlgorithms.Skein_512_512; return true;
                case "SKEIN-1024-1024": algorithm = HashAlgorithms.Skein_1024_1024; return true;
                case "SM3": algorithm = HashAlgorithms.SM3; return true;
                case "TIGER": algorithm = HashAlgorithms.Tiger; return true;
                case "WHIRLPOOL": algorithm = HashAlgorithms.Whirlpool; return true;

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