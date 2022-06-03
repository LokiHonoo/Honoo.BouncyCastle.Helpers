using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using System.Security.Cryptography;

namespace Honoo.BouncyCastle.Helpers.Security.Crypto.Symmetric
{
    /// <summary>
    /// DES.
    /// <para/>Legal block size 64 bits. Legal key size 64 bits.
    /// </summary>
    public sealed class DES : SymmetricBlockAlgorithm
    {
        #region Properties

        private static readonly KeySizes[] _blockSizes = new KeySizes[] { new KeySizes(64, 64, 0) };
        private static readonly KeySizes[] _keySizes = new KeySizes[] { new KeySizes(64, 64, 0) };

        #endregion Properties

        #region Constructor

        /// <summary>
        /// DES.
        /// <para/>Legal block size 64 bits. Legal key size 64 bits.
        /// </summary>
        public DES() : base("DES", SymmetricAlgorithmKind.Block, _blockSizes, 64, _keySizes)
        {
        }

        #endregion Constructor

        internal override IBlockCipher GenerateEngine()
        {
            return new DesEngine();
        }

        /// <summary>
        /// Generate KeyParameter.
        /// </summary>
        /// <param name="key">Key.</param>
        /// <returns></returns>
        protected override KeyParameter GenerateKeyParameter(byte[] key)
        {
            return new DesParameters(key);
        }

        /// <summary>
        /// Generate KeyParameter.
        /// </summary>
        /// <param name="keyBuffer">Key buffer bytes.</param>
        /// <param name="offset">Offset.</param>
        /// <param name="length">Length.</param>
        /// <returns></returns>
        protected override KeyParameter GenerateKeyParameter(byte[] keyBuffer, int offset, int length)
        {
            return new DesParameters(keyBuffer, offset, length);
        }
    }
}