using Honoo.BouncyCastle.Helpers.Security.Crypto.Hash;

namespace Honoo.BouncyCastle.Helpers
{
    /// <summary>
    /// CMAC algorithm helper.
    /// </summary>
    public static class CMACHelper
    {
        #region CMAC

        /// <summary>
        /// Hash size 128 bits. Legal key size 128, 192, 256 bits. Default mac size used as block size.
        /// </summary>
        public static ICMAC AES_CMAC { get; } = new CMAC(SymmetricAlgorithmHelper.AES);

        /// <summary>
        /// Hash size 64 bits. Legal key size 128 bits. Default mac size used as block size.
        /// </summary>
        public static ICMAC Blowfish_CMAC { get; } = new CMAC(SymmetricAlgorithmHelper.Blowfish);

        /// <summary>
        /// Hash size 128 bits. Legal key size 128, 192, 256 bits. Default mac size used as block size.
        /// </summary>
        public static ICMAC Camellia_CMAC { get; } = new CMAC(SymmetricAlgorithmHelper.Camellia);

        /// <summary>
        /// Hash size 64 bits. Legal key size 40-128 bits (8 bits increments). Default mac size used as block size.
        /// </summary>
        public static ICMAC CAST5_CMAC { get; } = new CMAC(SymmetricAlgorithmHelper.CAST5);

        /// <summary>
        /// Hash size 128 bits. Legal key size 128-256 bits (8 bits increments). Default mac size used as block size.
        /// </summary>
        public static ICMAC CAST6_CMAC { get; } = new CMAC(SymmetricAlgorithmHelper.CAST6);

        /// <summary>
        /// Hash size 64 bits. Legal key size 64 bits. Default mac size used as block size.
        /// </summary>
        public static ICMAC DES_CMAC { get; } = new CMAC(SymmetricAlgorithmHelper.DES);

        /// <summary>
        /// DESede, DESede3, TDEA, TripleDES, 3DES.
        /// <para/>Block size 64 bits. Legal key size 128, 192 bits. Default mac size used as block size.
        /// </summary>
        public static ICMAC DESede_CMAC { get; } = new CMAC(SymmetricAlgorithmHelper.DESede);

        /// <summary>
        /// Hash size 128 bits. Legal key size 128, 256 bits. Default mac size used as block size.
        /// </summary>
        public static ICMAC DSTU7624_128_CMAC { get; } = new CMAC(SymmetricAlgorithmHelper.DSTU7624_128);



        /// <summary>
        /// Hash size 64 bits. Legal key size 256 bits. Default mac size used as block size.
        /// </summary>
        public static ICMAC GOST28147_CMAC { get; } = new CMAC(SymmetricAlgorithmHelper.GOST28147);

        /// <summary>
        /// Hash size 64 bits. Legal key size 8-128 bits (8 bits increments). Default mac size used as block size.
        /// </summary>
        public static ICMAC IDEA_CMAC { get; } = new CMAC(SymmetricAlgorithmHelper.IDEA);

        /// <summary>
        /// Hash size 128 bits. Legal key size 128 bits. Default mac size used as block size.
        /// </summary>
        public static ICMAC Noekeon_CMAC { get; } = new CMAC(SymmetricAlgorithmHelper.Noekeon);

        /// <summary>
        /// Hash size 64 bits. Legal key size 8-1024 bits (8 bits increments). Default mac size used as block size.
        /// </summary>
        public static ICMAC RC2_CMAC { get; } = new CMAC(SymmetricAlgorithmHelper.RC2);

        /// <summary>
        /// Hash size 128 bits. Legal key size 8-2040 bits (8 bits increments). Default mac size used as block size.
        /// </summary>
        public static ICMAC RC5_64_CMAC { get; } = new CMAC(SymmetricAlgorithmHelper.RC5_64);

        /// <summary>
        /// Hash size 64 bits. Legal key size 8-2040 bits (8 bits increments). Default mac size used as block size.
        /// </summary>
        public static ICMAC RC5_CMAC { get; } = new CMAC(SymmetricAlgorithmHelper.RC5);

        /// <summary>
        /// Hash size 128 bits. Legal key size is more than or equal to 8 bits (8 bits increments). Default mac size used as block size.
        /// </summary>
        public static ICMAC RC6_CMAC { get; } = new CMAC(SymmetricAlgorithmHelper.RC6);

        /// <summary>
        /// Hash size 128 bits. Legal key size 128, 160, 192, 224, 256 bits. Default mac size used as block size.
        /// </summary>
        public static ICMAC Rijndael_128_CMAC { get; } = new CMAC(SymmetricAlgorithmHelper.Rijndael_128);

        /// <summary>
        /// Hash size 128 bits. Legal key size 128 bits. Default mac size used as block size.
        /// </summary>
        public static ICMAC SEED_CMAC { get; } = new CMAC(SymmetricAlgorithmHelper.SEED);

        /// <summary>
        /// Hash size 128 bits. Legal key size 32-512 bits (32 bits increments). Default mac size used as block size.
        /// </summary>
        public static ICMAC Serpent_CMAC { get; } = new CMAC(SymmetricAlgorithmHelper.Serpent);

        /// <summary>
        /// Hash size 64 bits. Legal key size 128 bits. Default mac size used as block size.
        /// </summary>
        public static ICMAC SKIPJACK_CMAC { get; } = new CMAC(SymmetricAlgorithmHelper.SKIPJACK);

        /// <summary>
        /// Hash size 128 bits. Legal key size 128 bits. Default mac size used as block size.
        /// </summary>
        public static ICMAC SM4_CMAC { get; } = new CMAC(SymmetricAlgorithmHelper.SM4);

        /// <summary>
        /// Hash size 64 bits. Legal key size 128 bits. Default mac size used as block size.
        /// </summary>
        public static ICMAC TEA_CMAC { get; } = new CMAC(SymmetricAlgorithmHelper.TEA);

        /// <summary>
        /// Hash size 128 bits. Legal key size 32-512 bits (32 bits increments). Default mac size used as block size.
        /// </summary>
        public static ICMAC Tnepres_CMAC { get; } = new CMAC(SymmetricAlgorithmHelper.Tnepres);

        /// <summary>
        /// Hash size 128 bits. Legal key size 64-256 bits (64 bits increments). Default mac size used as block size.
        /// </summary>
        public static ICMAC Twofish_CMAC { get; } = new CMAC(SymmetricAlgorithmHelper.Twofish);

        /// <summary>
        /// Hash size 64 bits. Legal key size 128 bits. Default mac size used as block size.
        /// </summary>
        public static ICMAC XTEA_CMAC { get; } = new CMAC(SymmetricAlgorithmHelper.XTEA);

        #endregion CMAC

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
                case "AES": return TryGetAlgorithmNano(AES_CMAC, macSize, out algorithm);
                case "BLOWFISH": return TryGetAlgorithmNano(Blowfish_CMAC, macSize, out algorithm);
                case "CAMELLIA": return TryGetAlgorithmNano(Camellia_CMAC, macSize, out algorithm);
                case "CAST5": return TryGetAlgorithmNano(CAST5_CMAC, macSize, out algorithm);
                case "CAST6": return TryGetAlgorithmNano(CAST6_CMAC, macSize, out algorithm);
                case "DES": return TryGetAlgorithmNano(DES_CMAC, macSize, out algorithm);
                case "DESEDE": case "DESEDE3": case "TDEA": case "TRIPLEDES": case "3DES": return TryGetAlgorithmNano(DESede_CMAC, macSize, out algorithm);
                case "DSTU7624-128": return TryGetAlgorithmNano(DSTU7624_128_CMAC, macSize, out algorithm);
                case "GOST28147": return TryGetAlgorithmNano(GOST28147_CMAC, macSize, out algorithm);
                case "IDEA": return TryGetAlgorithmNano(IDEA_CMAC, macSize, out algorithm);
                case "NOEKEON": return TryGetAlgorithmNano(Noekeon_CMAC, macSize, out algorithm);
                case "RC2": return TryGetAlgorithmNano(RC2_CMAC, macSize, out algorithm);
                case "RC5": case "RC5-32": return TryGetAlgorithmNano(RC5_CMAC, macSize, out algorithm);
                case "RC5-64": return TryGetAlgorithmNano(RC5_64_CMAC, macSize, out algorithm);
                case "RC6": return TryGetAlgorithmNano(RC6_CMAC, macSize, out algorithm);
                case "RIJNDAEL-128": case "RIJNDAEL128": return TryGetAlgorithmNano(Rijndael_128_CMAC, macSize, out algorithm);
                case "SEED": return TryGetAlgorithmNano(SEED_CMAC, macSize, out algorithm);
                case "SERPENT": return TryGetAlgorithmNano(Serpent_CMAC, macSize, out algorithm);
                case "SKIPJACK": return TryGetAlgorithmNano(SKIPJACK_CMAC, macSize, out algorithm);
                case "SM4": return TryGetAlgorithmNano(SM4_CMAC, macSize, out algorithm);
                case "TEA": return TryGetAlgorithmNano(TEA_CMAC, macSize, out algorithm);
                case "TNEPRES": return TryGetAlgorithmNano(Tnepres_CMAC, macSize, out algorithm);
                case "TWOFISH": return TryGetAlgorithmNano(Twofish_CMAC, macSize, out algorithm);
                case "XTEA": return TryGetAlgorithmNano(XTEA_CMAC, macSize, out algorithm);
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