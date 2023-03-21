using Honoo.BouncyCastle.Helpers.Security.Crypto.Hash;

namespace Honoo.BouncyCastle.Helpers
{
    /// <summary>
    /// MAC algorithm helper.
    /// </summary>
    public static class MACHelper
    {
        /// <summary>
        /// Try get MAC algorithm from mechanism.
        /// <para/>Legal mac size is between 8 and block size (8 bits increments).
        /// <para/>Legal mac size must be at least 24 bits (FIPS Publication 81) or 16 bits if being used as a data authenticator (FIPS Publication 113).
        /// </summary>
        /// <param name="mechanism">MAC algorithm mechanism.</param>
        /// <param name="macSize">MAC size bits.</param>
        /// <param name="algorithm">MAC algorithm.</param>
        /// <returns></returns>
        public static bool TryGetAlgorithm(string mechanism, int macSize, out IMAC algorithm)
        {
            if (string.IsNullOrWhiteSpace(mechanism))
            {
                algorithm = null;
                return false;
            }
            if (macSize <= 0)
            {
                algorithm = null;
                return false;
            }
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
            switch (mechanism)
            {
                case "AES": return TryGetAlgorithmNano(MACAlgorithms.AES_MAC, macSize, out algorithm);
                case "BLOWFISH": return TryGetAlgorithmNano(MACAlgorithms.Blowfish_MAC, macSize, out algorithm);
                case "CAMELLIA": return TryGetAlgorithmNano(MACAlgorithms.Camellia_MAC, macSize, out algorithm);
                case "CAST5": return TryGetAlgorithmNano(MACAlgorithms.CAST5_MAC, macSize, out algorithm);
                case "CAST6": return TryGetAlgorithmNano(MACAlgorithms.CAST6_MAC, macSize, out algorithm);
                case "DES": return TryGetAlgorithmNano(MACAlgorithms.DES_MAC, macSize, out algorithm);
                case "DESEDE": case "DESEDE3": case "TDEA": case "TRIPLEDES": case "3DES": return TryGetAlgorithmNano(MACAlgorithms.DESede_MAC, macSize, out algorithm);
                case "DSTU7624-128": return TryGetAlgorithmNano(MACAlgorithms.DSTU7624_128_MAC, macSize, out algorithm);
                case "DSTU7624-256": return TryGetAlgorithmNano(MACAlgorithms.DSTU7624_256_MAC, macSize, out algorithm);
                case "DSTU7624-512": return TryGetAlgorithmNano(MACAlgorithms.DSTU7624_512_MAC, macSize, out algorithm);
                case "GOST28147": return TryGetAlgorithmNano(MACAlgorithms.GOST28147_MAC, macSize, out algorithm);
                case "IDEA": return TryGetAlgorithmNano(MACAlgorithms.IDEA_MAC, macSize, out algorithm);
                case "NOEKEON": return TryGetAlgorithmNano(MACAlgorithms.Noekeon_MAC, macSize, out algorithm);
                case "RC2": return TryGetAlgorithmNano(MACAlgorithms.RC2_MAC, macSize, out algorithm);
                case "RC5": case "RC5-32": return TryGetAlgorithmNano(MACAlgorithms.RC5_MAC, macSize, out algorithm);
                case "RC5-64": return TryGetAlgorithmNano(MACAlgorithms.RC5_64_MAC, macSize, out algorithm);
                case "RC6": return TryGetAlgorithmNano(MACAlgorithms.RC6_MAC, macSize, out algorithm);
                case "RIJNDAEL-128": case "RIJNDAEL128": return TryGetAlgorithmNano(MACAlgorithms.Rijndael128_MAC, macSize, out algorithm);
                case "RIJNDAEL-160": case "RIJNDAEL160": return TryGetAlgorithmNano(MACAlgorithms.Rijndael160_MAC, macSize, out algorithm);
                case "RIJNDAEL-192": case "RIJNDAEL192": return TryGetAlgorithmNano(MACAlgorithms.Rijndael192_MAC, macSize, out algorithm);
                case "RIJNDAEL-224": case "RIJNDAEL224": return TryGetAlgorithmNano(MACAlgorithms.Rijndael224_MAC, macSize, out algorithm);
                case "RIJNDAEL-256": case "RIJNDAEL256": return TryGetAlgorithmNano(MACAlgorithms.Rijndael256_MAC, macSize, out algorithm);
                case "SEED": return TryGetAlgorithmNano(MACAlgorithms.SEED_MAC, macSize, out algorithm);
                case "SERPENT": return TryGetAlgorithmNano(MACAlgorithms.Serpent_MAC, macSize, out algorithm);
                case "SKIPJACK": return TryGetAlgorithmNano(MACAlgorithms.SKIPJACK_MAC, macSize, out algorithm);
                case "SM4": return TryGetAlgorithmNano(MACAlgorithms.SM4_MAC, macSize, out algorithm);
                case "TEA": return TryGetAlgorithmNano(MACAlgorithms.TEA_MAC, macSize, out algorithm);
                case "THREEFISH-256": case "THREEFISH256": return TryGetAlgorithmNano(MACAlgorithms.Threefish256_MAC, macSize, out algorithm);
                case "THREEFISH-512": case "THREEFISH512": return TryGetAlgorithmNano(MACAlgorithms.Threefish512_MAC, macSize, out algorithm);
                case "THREEFISH-1024": case "THREEFISH1024": return TryGetAlgorithmNano(MACAlgorithms.Threefish1024_MAC, macSize, out algorithm);
                case "TNEPRES": return TryGetAlgorithmNano(MACAlgorithms.Tnepres_MAC, macSize, out algorithm);
                case "TWOFISH": return TryGetAlgorithmNano(MACAlgorithms.Twofish_MAC, macSize, out algorithm);
                case "XTEA": return TryGetAlgorithmNano(MACAlgorithms.XTEA_MAC, macSize, out algorithm);
                default: algorithm = null; return false;
            }
        }

        /// <summary>
        /// Try get MAC algorithm ciper mode from mechanism.
        /// </summary>
        /// <param name="mechanism">MAC algorithm cipher mode mechanism.</param>
        /// <param name="mode">MAC algorithm cipher mode.</param>
        /// <returns></returns>
        public static bool TryGetCipherMode(string mechanism, out MACCipherMode? mode)
        {
            if (string.IsNullOrWhiteSpace(mechanism))
            {
                mode = null;
                return false;
            }
            mechanism = mechanism.Replace('_', '-').ToUpperInvariant();
            switch (mechanism)
            {
                case "CBC": mode = MACCipherMode.CBC; return true;
                case "CFB": mode = MACCipherMode.CFB; return true;
                default: mode = null; return false;
            }
        }

        /// <summary>
        /// Try get MAC algorithm padding mode from mechanism.
        /// </summary>
        /// <param name="mechanism">MAC algorithm padding mode mechanism.</param>
        /// <param name="padding">MAC algorithm padding mode.</param>
        /// <returns></returns>
        public static bool TryGetPaddingMode(string mechanism, out MACPaddingMode? padding)
        {
            if (string.IsNullOrWhiteSpace(mechanism))
            {
                padding = null;
                return false;
            }
            mechanism = mechanism.Replace('_', '-').ToUpperInvariant();
            switch (mechanism)
            {
                case "NOPADDING": padding = MACPaddingMode.NoPadding; return true;
                case "PKCS7": case "PKCS7PADDING": case "PKCS5": case "PKCS5PADDING": padding = MACPaddingMode.PKCS7; return true;
                case "ZEROS": case "ZEROSPADDING": case "ZERO": case "ZEROPADDING": padding = MACPaddingMode.Zeros; return true;
                case "X923":
                case "X923PADDING":
                case "X9.23":
                case "X9.23PADDING":
                case "ANSIX923":
                case "ANSIX923PADDING":
                case "ANSIX9.23":
                case "ANSIX9.23PADDING": padding = MACPaddingMode.X923; return true;
                case "ISO7816-4":
                case "ISO7816-4PADDING":
                case "ISO7816D4":
                case "ISO7816D4PADDING":
                case "ISO9797-1":
                case "ISO9797-1PADDING":
                case "ISO9797D1":
                case "ISO9797D1PADDING": padding = MACPaddingMode.ISO7816_4; return true;
                case "TBC": case "TBCPADDING": padding = MACPaddingMode.TBC; return true;
                default: padding = null; return false;
            }
        }

        private static bool TryGetAlgorithmNano(IMAC referent, int macSize, out IMAC algorithm)
        {
            if (macSize == referent.MacSize)
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