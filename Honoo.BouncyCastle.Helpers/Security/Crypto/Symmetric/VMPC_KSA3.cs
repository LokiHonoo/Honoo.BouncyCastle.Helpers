using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using System.Security.Cryptography;

namespace Honoo.BouncyCastle.Helpers.Security.Crypto.Symmetric
{
    /// <summary>
    /// VMPC-KSA3.
    /// <para/>Legal key size 256 bits. Legal iv size 8-6144 bits (8 bits increments).
    /// </summary>
    public sealed class VMPC_KSA3 : StreamAlgorithm
    {
        #region Properties

        private static readonly KeySizes[] _ivSizes = new KeySizes[] { new KeySizes(8, 6144, 8) };
        private static readonly KeySizes[] _keySizes = new KeySizes[] { new KeySizes(256, 256, 0) };

        #endregion Properties

        #region Constructor

        /// <summary>
        /// VMPC-KSA3.
        /// <para/>Legal key size 256 bits. Legal iv size 8-6144 bits (8 bits increments).
        /// </summary>
        public VMPC_KSA3() : base("VMPC-KSA3", _keySizes, _ivSizes)
        {
        }

        #endregion Constructor

        /// <summary>
        /// Generate engine.
        /// </summary>
        /// <returns></returns>
        protected override IStreamCipher GenerateEngine()
        {
            return new VmpcKsa3Engine();
        }
    }
}