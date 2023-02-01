namespace Honoo.BouncyCastle.Helpers
{
    /// <summary>
    /// Symmetric algorithm helper.
    /// </summary>
    public static class SymmetricAlgorithmHelper
    {
        /// <summary>
        /// Try get symmetric algorithm from mechanism.
        /// </summary>
        /// <param name="mechanism">Symmetric algorithm mechanism.</param>
        /// <param name="algorithm">Symmetric algorithm.</param>
        /// <returns></returns>
        public static bool TryGetAlgorithm(string mechanism, out ISymmetricAlgorithm algorithm)
        {
            if (TryGetAlgorithm(mechanism, out ISymmetricBlockAlgorithm blockAlgorithm))
            {
                algorithm = blockAlgorithm;
                return true;
            }
            else if (TryGetAlgorithm(mechanism, out ISymmetricStreamAlgorithm streamAlgorithm))
            {
                algorithm = streamAlgorithm;
                return true;
            }
            algorithm = null;
            return false;
        }

        /// <summary>
        /// Try get symmetric block algorithm from mechanism.
        /// </summary>
        /// <param name="mechanism">Symmetric block algorithm mechanism.</param>
        /// <param name="algorithm">Symmetric block algorithm.</param>
        /// <returns></returns>
        public static bool TryGetAlgorithm(string mechanism, out ISymmetricBlockAlgorithm algorithm)
        {
            if (string.IsNullOrWhiteSpace(mechanism))
            {
                algorithm = null;
                return false;
            }
            mechanism = mechanism.Replace('_', '-').ToUpperInvariant();
            switch (mechanism)
            {
                case "AES": algorithm = SymmetricAlgorithms.AES; return true;
                case "BLOWFISH": algorithm = SymmetricAlgorithms.Blowfish; return true;
                case "CAMELLIA": algorithm = SymmetricAlgorithms.Camellia; return true;
                case "CAST5": algorithm = SymmetricAlgorithms.CAST5; return true;
                case "CAST6": algorithm = SymmetricAlgorithms.CAST6; return true;
                case "DES": algorithm = SymmetricAlgorithms.DES; return true;
                case "DESEDE": case "DESEDE3": case "TDEA": case "TRIPLEDES": case "3DES": algorithm = SymmetricAlgorithms.DESede; return true;
                case "DSTU7624-128": algorithm = SymmetricAlgorithms.DSTU7624_128; return true;
                case "DSTU7624-256": algorithm = SymmetricAlgorithms.DSTU7624_256; return true;
                case "DSTU7624-512": algorithm = SymmetricAlgorithms.DSTU7624_512; return true;
                case "GOST28147": algorithm = SymmetricAlgorithms.GOST28147; return true;
                case "IDEA": algorithm = SymmetricAlgorithms.IDEA; return true;
                case "NOEKEON": algorithm = SymmetricAlgorithms.Noekeon; return true;
                case "RC2": algorithm = SymmetricAlgorithms.RC2; return true;
                case "RC5": case "RC5-32": algorithm = SymmetricAlgorithms.RC5; return true;
                case "RC5-64": algorithm = SymmetricAlgorithms.RC5_64; return true;
                case "RC6": algorithm = SymmetricAlgorithms.RC6; return true;
                case "RIJNDAEL-128": case "RIJNDAEL128": algorithm = SymmetricAlgorithms.Rijndael_128; return true;
                case "RIJNDAEL-160": case "RIJNDAEL160": algorithm = SymmetricAlgorithms.Rijndael_160; return true;
                case "RIJNDAEL-192": case "RIJNDAEL192": algorithm = SymmetricAlgorithms.Rijndael_192; return true;
                case "RIJNDAEL-224": case "RIJNDAEL224": algorithm = SymmetricAlgorithms.Rijndael_224; return true;
                case "RIJNDAEL-256": case "RIJNDAEL256": algorithm = SymmetricAlgorithms.Rijndael_256; return true;
                case "SEED": algorithm = SymmetricAlgorithms.SEED; return true;
                case "SERPENT": algorithm = SymmetricAlgorithms.Serpent; return true;
                case "SKIPJACK": algorithm = SymmetricAlgorithms.SKIPJACK; return true;
                case "SM4": algorithm = SymmetricAlgorithms.SM4; return true;
                case "TEA": algorithm = SymmetricAlgorithms.TEA; return true;
                case "THREEFISH-256": case "THREEFISH256": algorithm = SymmetricAlgorithms.Threefish_256; return true;
                case "THREEFISH-512": case "THREEFISH512": algorithm = SymmetricAlgorithms.Threefish_512; return true;
                case "THREEFISH-1024": case "THREEFISH1024": algorithm = SymmetricAlgorithms.Threefish_1024; return true;
                case "TNEPRES": algorithm = SymmetricAlgorithms.Tnepres; return true;
                case "TWOFISH": algorithm = SymmetricAlgorithms.Twofish; return true;
                case "XTEA": algorithm = SymmetricAlgorithms.XTEA; return true;
                default: algorithm = null; return false;
            }
        }

        /// <summary>
        /// Try get symmetric stream algorithm from mechanism.
        /// </summary>
        /// <param name="mechanism">Symmetric stream algorithm mechanism.</param>
        /// <param name="algorithm">Symmetric stream algorithm.</param>
        /// <returns></returns>
        public static bool TryGetAlgorithm(string mechanism, out ISymmetricStreamAlgorithm algorithm)
        {
            if (string.IsNullOrWhiteSpace(mechanism))
            {
                algorithm = null;
                return false;
            }
            mechanism = mechanism.Replace('_', '-').ToUpperInvariant();
            switch (mechanism)
            {
                case "CHACHA": algorithm = SymmetricAlgorithms.ChaCha; return true;
                case "CHACHA7539": case "CHACHA20": algorithm = SymmetricAlgorithms.ChaCha7539; return true;
                case "HC128": case "HC-128": algorithm = SymmetricAlgorithms.HC128; return true;
                case "HC256": case "HC-256": algorithm = SymmetricAlgorithms.HC256; return true;
                case "ISAAC": algorithm = SymmetricAlgorithms.ISAAC; return true;
                case "RC4": case "ARC4": case "ARCFOUR": algorithm = SymmetricAlgorithms.RC4; return true;
                case "SALSA20": algorithm = SymmetricAlgorithms.Salsa20; return true;
                case "VMPC": algorithm = SymmetricAlgorithms.VMPC; return true;
                case "VMPC-KSA3": case "VMPCKSA3": algorithm = SymmetricAlgorithms.VMPC_KSA3; return true;
                case "XSALSA20": algorithm = SymmetricAlgorithms.XSalsa20; return true;
                default: algorithm = null; return false;
            }
        }

        /// <summary>
        /// Try get symmetric algorithm ciper mode from mechanism.
        /// </summary>
        /// <param name="mechanism">Symmetric algorithm cipher mode mechanism.</param>
        /// <param name="mode">Symmetric algorithm cipher mode.</param>
        /// <returns></returns>
        public static bool TryGetCipherMode(string mechanism, out SymmetricCipherMode? mode)
        {
            if (string.IsNullOrWhiteSpace(mechanism))
            {
                mode = null;
                return false;
            }
            mechanism = mechanism.Replace('_', '-').ToUpperInvariant();
            switch (mechanism)
            {
                case "CBC": mode = SymmetricCipherMode.CBC; return true;
                case "ECB": mode = SymmetricCipherMode.ECB; return true;
                case "OFB": mode = SymmetricCipherMode.OFB; return true;
                case "CFB": mode = SymmetricCipherMode.CFB; return true;
                case "CTS": mode = SymmetricCipherMode.CTS; return true;
                case "CTR": mode = SymmetricCipherMode.CTR; return true;
                case "CTS-ECB": mode = SymmetricCipherMode.CTS_ECB; return true;
                case "GOFB": mode = SymmetricCipherMode.GOFB; return true;
                case "OPENPGPCFB": mode = SymmetricCipherMode.OpenPGPCFB; return true;
                case "SIC": mode = SymmetricCipherMode.SIC; return true;

                case "CCM": mode = SymmetricCipherMode.CCM; return true;
                case "EAX": mode = SymmetricCipherMode.EAX; return true;
                case "GCM": mode = SymmetricCipherMode.GCM; return true;
                case "OCB": mode = SymmetricCipherMode.OCB; return true;
                default: mode = null; return false;
            }
        }

        /// <summary>
        /// Try get symmetric algorithm padding mode from mechanism.
        /// </summary>
        /// <param name="mechanism">Symmetric algorithm padding mode mechanism.</param>
        /// <param name="padding">Symmetric algorithm padding mode.</param>
        /// <returns></returns>
        public static bool TryGetPaddingMode(string mechanism, out SymmetricPaddingMode? padding)
        {
            if (string.IsNullOrWhiteSpace(mechanism))
            {
                padding = null;
                return false;
            }
            mechanism = mechanism.Replace('_', '-').ToUpperInvariant();
            switch (mechanism)
            {
                case "NOPADDING": case "NONE": padding = SymmetricPaddingMode.NoPadding; return true;
                case "PKCS7": case "PKCS7PADDING": case "PKCS5": case "PKCS5PADDING": padding = SymmetricPaddingMode.PKCS7; return true;
                case "ZEROS":
                case "ZEROSPADDING":
                case "ZERO":
                case "ZEROPADDING":
                case "ZEROBYTE":
                case "ZEROBYTEPADDING": padding = SymmetricPaddingMode.Zeros; return true;
                case "X923":
                case "X923PADDING":
                case "X9.23":
                case "X9.23PADDING":
                case "ANSIX923":
                case "ANSIX923PADDING":
                case "ANSIX9.23":
                case "ANSIX9.23PADDING": padding = SymmetricPaddingMode.X923; return true;
                case "ISO10126":
                case "ISO10126PADDING":
                case "ISO10126-2":
                case "ISO10126-2PADDING":
                case "ISO10126D2":
                case "ISO10126D2PADDING": padding = SymmetricPaddingMode.ISO10126; return true;
                case "ISO7816-4":
                case "ISO7816-4PADDING":
                case "ISO7816D4":
                case "ISO7816D4PADDING":
                case "ISO9797-1":
                case "ISO9797-1PADDING":
                case "ISO9797D1":
                case "ISO9797D1PADDING": padding = SymmetricPaddingMode.ISO7816_4; return true;
                case "TBC": case "TBCPADDING": padding = SymmetricPaddingMode.TBC; return true;
                default: padding = null; return false;
            }
        }
    }
}