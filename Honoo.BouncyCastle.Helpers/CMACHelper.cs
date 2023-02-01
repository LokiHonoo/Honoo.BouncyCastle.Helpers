using Honoo.BouncyCastle.Helpers.Security.Crypto.Hash;

namespace Honoo.BouncyCastle.Helpers
{
    /// <summary>
    /// CMAC algorithm helper.
    /// </summary>
    public static class CMACHelper
    {
        /// <summary>
        /// Try get CMAC algorithm from mechanism.
        /// <para/>Legal algorithm's block size 64 or 128 bits.
        /// <para/>Legal mac size is between 8 and block size (8 bits increments).
        /// </summary>
        /// <param name="mechanism">CMAC algorithm mechanism.</param>
        /// <param name="macSize">MAC size bits.</param>
        /// <param name="algorithm">CMAC algorithm.</param>
        /// <returns></returns>
        public static bool TryGetAlgorithm(string mechanism, int macSize, out ICMAC algorithm)
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
            if (mechanism.EndsWith("CMAC"))
            {
                if (mechanism.EndsWith("/CMAC") || mechanism.EndsWith("-CMAC"))
                {
                    mechanism = mechanism.Substring(0, mechanism.Length - 5);
                }
                else
                {
                    mechanism = mechanism.Substring(0, mechanism.Length - 4);
                }
            }
            switch (mechanism)
            {
                case "AES": return TryGetAlgorithmNano(CMACAlgorithms.AES_CMAC, macSize, out algorithm);
                case "BLOWFISH": return TryGetAlgorithmNano(CMACAlgorithms.Blowfish_CMAC, macSize, out algorithm);
                case "CAMELLIA": return TryGetAlgorithmNano(CMACAlgorithms.Camellia_CMAC, macSize, out algorithm);
                case "CAST5": return TryGetAlgorithmNano(CMACAlgorithms.CAST5_CMAC, macSize, out algorithm);
                case "CAST6": return TryGetAlgorithmNano(CMACAlgorithms.CAST6_CMAC, macSize, out algorithm);
                case "DES": return TryGetAlgorithmNano(CMACAlgorithms.DES_CMAC, macSize, out algorithm);
                case "DESEDE": case "DESEDE3": case "TDEA": case "TRIPLEDES": case "3DES": return TryGetAlgorithmNano(CMACAlgorithms.DESede_CMAC, macSize, out algorithm);
                case "DSTU7624-128": return TryGetAlgorithmNano(CMACAlgorithms.DSTU7624_128_CMAC, macSize, out algorithm);
                case "GOST28147": return TryGetAlgorithmNano(CMACAlgorithms.GOST28147_CMAC, macSize, out algorithm);
                case "IDEA": return TryGetAlgorithmNano(CMACAlgorithms.IDEA_CMAC, macSize, out algorithm);
                case "NOEKEON": return TryGetAlgorithmNano(CMACAlgorithms.Noekeon_CMAC, macSize, out algorithm);
                case "RC2": return TryGetAlgorithmNano(CMACAlgorithms.RC2_CMAC, macSize, out algorithm);
                case "RC5": case "RC5-32": return TryGetAlgorithmNano(CMACAlgorithms.RC5_CMAC, macSize, out algorithm);
                case "RC5-64": return TryGetAlgorithmNano(CMACAlgorithms.RC5_64_CMAC, macSize, out algorithm);
                case "RC6": return TryGetAlgorithmNano(CMACAlgorithms.RC6_CMAC, macSize, out algorithm);
                case "RIJNDAEL-128": case "RIJNDAEL128": return TryGetAlgorithmNano(CMACAlgorithms.Rijndael_128_CMAC, macSize, out algorithm);
                case "SEED": return TryGetAlgorithmNano(CMACAlgorithms.SEED_CMAC, macSize, out algorithm);
                case "SERPENT": return TryGetAlgorithmNano(CMACAlgorithms.Serpent_CMAC, macSize, out algorithm);
                case "SKIPJACK": return TryGetAlgorithmNano(CMACAlgorithms.SKIPJACK_CMAC, macSize, out algorithm);
                case "SM4": return TryGetAlgorithmNano(CMACAlgorithms.SM4_CMAC, macSize, out algorithm);
                case "TEA": return TryGetAlgorithmNano(CMACAlgorithms.TEA_CMAC, macSize, out algorithm);
                case "TNEPRES": return TryGetAlgorithmNano(CMACAlgorithms.Tnepres_CMAC, macSize, out algorithm);
                case "TWOFISH": return TryGetAlgorithmNano(CMACAlgorithms.Twofish_CMAC, macSize, out algorithm);
                case "XTEA": return TryGetAlgorithmNano(CMACAlgorithms.XTEA_CMAC, macSize, out algorithm);
                default: algorithm = null; return false;
            }
        }

        private static bool TryGetAlgorithmNano(ICMAC referent, int macSize, out ICMAC algorithm)
        {
            if (macSize == referent.MacSize)
            {
                algorithm = referent;
                return true;
            }
            else if (macSize >= 8 && macSize <= referent.BlockSize && macSize % 8 == 0)
            {
                algorithm = new CMAC(((CMAC)referent).BlockAlgorithm, macSize);
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