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
            mechanism = mechanism.Replace('_', '-').Replace('/', '-').ToUpperInvariant();
            switch (mechanism)
            {
                case "BLAKE2B-256": case "BLAKE2B256": algorithm = HashAlgorithms.BLAKE2b256; return true;
                case "BLAKE2B-384": case "BLAKE2B384": algorithm = HashAlgorithms.BLAKE2b384; return true;
                case "BLAKE2B-512": case "BLAKE2B512": algorithm = HashAlgorithms.BLAKE2b512; return true;
                case "BLAKE2S-256": case "BLAKE2S256": algorithm = HashAlgorithms.BLAKE2s256; return true;
                case "CSHAKE128-256": case "CSHAKE-128-256": case "CSHAKE128": case "CSHAKE-128": algorithm = HashAlgorithms.CSHAKE128_256; return true;
                case "CSHAKE256-512": case "CSHAKE-256-512": case "CSHAKE256": case "CSHAKE-256": algorithm = HashAlgorithms.CSHAKE256_512; return true;
                case "DSTU7564-256": case "DSTU-7564-256": algorithm = HashAlgorithms.DSTU7564_256; return true;
                case "DSTU7564-384": case "DSTU-7564-384": algorithm = HashAlgorithms.DSTU7564_384; return true;
                case "DSTU7564-512": case "DSTU-7564-512": algorithm = HashAlgorithms.DSTU7564_512; return true;
                case "GOST3411": algorithm = HashAlgorithms.GOST3411; return true;
                case "GOST3411-2012-256": algorithm = HashAlgorithms.GOST3411_2012_256; return true;
                case "GOST3411-2012-512": algorithm = HashAlgorithms.GOST3411_2012_512; return true;
                case "KECCAK-128": case "KECCAK128": algorithm = HashAlgorithms.Keccak128; return true;
                case "KECCAK-224": case "KECCAK224": algorithm = HashAlgorithms.Keccak224; return true;
                case "KECCAK-256": case "KECCAK256": algorithm = HashAlgorithms.Keccak256; return true;
                case "KECCAK-288": case "KECCAK288": algorithm = HashAlgorithms.Keccak288; return true;
                case "KECCAK-384": case "KECCAK384": algorithm = HashAlgorithms.Keccak384; return true;
                case "KECCAK-512": case "KECCAK512": algorithm = HashAlgorithms.Keccak512; return true;
                case "MD2": algorithm = HashAlgorithms.MD2; return true;
                case "MD4": algorithm = HashAlgorithms.MD4; return true;
                case "MD5": algorithm = HashAlgorithms.MD5; return true;
                case "RIPEMD128": case "RIPEMD-128": algorithm = HashAlgorithms.RIPEMD128; return true;
                case "RIPEMD160": case "RIPEMD-160": algorithm = HashAlgorithms.RIPEMD160; return true;
                case "RIPEMD256": case "RIPEMD-256": algorithm = HashAlgorithms.RIPEMD256; return true;
                case "RIPEMD320": case "RIPEMD-320": algorithm = HashAlgorithms.RIPEMD320; return true;
                case "SHA1": case "SHA-1": case "SHA": algorithm = HashAlgorithms.SHA1; return true;
                case "SHA224": case "SHA-224": algorithm = HashAlgorithms.SHA224; return true;
                case "SHA256": case "SHA-256": algorithm = HashAlgorithms.SHA256; return true;
                case "SHA384": case "SHA-384": algorithm = HashAlgorithms.SHA384; return true;
                case "SHA512": case "SHA-512": algorithm = HashAlgorithms.SHA512; return true;
                case "SHA512-224": case "SHA-512-224": case "SHA512T224": case "SHA-512T224": algorithm = HashAlgorithms.SHA512_224; return true;
                case "SHA512-256": case "SHA-512-256": case "SHA512T256": case "SHA-512T256": algorithm = HashAlgorithms.SHA512_256; return true;
                case "SHA3-224": case "SHA-3-224": algorithm = HashAlgorithms.SHA3_224; return true;
                case "SHA3-256": case "SHA-3-256": algorithm = HashAlgorithms.SHA3_256; return true;
                case "SHA3-384": case "SHA-3-384": algorithm = HashAlgorithms.SHA3_384; return true;
                case "SHA3-512": case "SHA-3-512": algorithm = HashAlgorithms.SHA3_512; return true;
                case "SHAKE128-256": case "SHAKE-128-256": case "SHAKE128": case "SHAKE-128": algorithm = HashAlgorithms.SHAKE128_256; return true;
                case "SHAKE256-512": case "SHAKE-256-512": case "SHAKE256": case "SHAKE-256": algorithm = HashAlgorithms.SHAKE256_512; return true;
                case "SKEIN256-256": case "SKEIN-256-256": algorithm = HashAlgorithms.Skein256_256; return true;
                case "SKEIN512-512": case "SKEIN-512-512": algorithm = HashAlgorithms.Skein512_512; return true;
                case "SKEIN1024-1024": case "SKEIN-1024-1024": algorithm = HashAlgorithms.Skein1024_1024; return true;
                case "SM3": algorithm = HashAlgorithms.SM3; return true;
                case "TIGER": algorithm = HashAlgorithms.Tiger; return true;
                case "WHIRLPOOL": algorithm = HashAlgorithms.Whirlpool; return true;
                default: break;
            }
            return TryGetAlgorithmNano(mechanism, out algorithm);
        }

        internal static bool TryGetAlgorithmNano(string mechanism, out IHashAlgorithm algorithm)
        {
            if (mechanism.StartsWith("BLAKE2B"))
            {
                string cut = mechanism.Substring(7, mechanism.Length - 7);
                cut = cut.TrimStart('-');
                if (int.TryParse(cut, out int hashSize))
                {
                    if (DetectionUtilities.ValidSize(BLAKE2b.HashSizes, hashSize))
                    {
                        algorithm = new BLAKE2b(hashSize);
                        return true;
                    }
                }
            }
            else if (mechanism.StartsWith("BLAKE2S"))
            {
                string cut = mechanism.Substring(7, mechanism.Length - 7);
                cut = cut.TrimStart('-');
                if (int.TryParse(cut, out int hashSize))
                {
                    if (DetectionUtilities.ValidSize(BLAKE2s.HashSizes, hashSize))
                    {
                        algorithm = new BLAKE2s(hashSize);
                        return true;
                    }
                }
            }
            else if (mechanism.StartsWith("SHA512T"))
            {
                string cut = mechanism.Substring(7, mechanism.Length - 7);
                if (int.TryParse(cut, out int hashSize))
                {
                    if (DetectionUtilities.ValidSize(SHA512T.HashSizes, hashSize))
                    {
                        algorithm = new SHA512T(hashSize);
                        return true;
                    }
                }
            }
            else if (mechanism.StartsWith("SHA-512"))
            {
                string cut = mechanism.Substring(7, mechanism.Length - 7);
                cut = cut.TrimStart('-');
                if (int.TryParse(cut, out int hashSize))
                {
                    if (DetectionUtilities.ValidSize(SHA512T.HashSizes, hashSize))
                    {
                        algorithm = new SHA512T(hashSize);
                        return true;
                    }
                }
            }
            else if (mechanism.StartsWith("SHA512"))
            {
                string cut = mechanism.Substring(6, mechanism.Length - 6);
                cut = cut.TrimStart('-');
                if (int.TryParse(cut, out int hashSize))
                {
                    if (DetectionUtilities.ValidSize(SHA512T.HashSizes, hashSize))
                    {
                        algorithm = new SHA512T(hashSize);
                        return true;
                    }
                }
            }
            else if (mechanism.StartsWith("SKEIN"))
            {
                string cut = mechanism.Substring(5, mechanism.Length - 5);
                cut = cut.TrimStart('-');
                string[] splits = cut.Split('-');
                if (splits.Length == 2)
                {
                    if (int.TryParse(splits[0], out int hashSize) && int.TryParse(splits[1], out int stateSize))
                    {
                        if (DetectionUtilities.ValidSize(Skein.HashSizes, hashSize) && DetectionUtilities.ValidSize(Skein.StateSizes, hashSize))
                        {
                            algorithm = new Skein(hashSize, stateSize);
                            return true;
                        }
                    }
                }
            }
            algorithm = null;
            return false;
        }
    }
}