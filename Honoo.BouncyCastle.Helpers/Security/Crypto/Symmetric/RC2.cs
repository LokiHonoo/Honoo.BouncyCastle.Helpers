using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using System.Security.Cryptography;

namespace Honoo.BouncyCastle.Helpers.Security.Crypto.Symmetric
{
    /// <summary>
    /// RC2.
    /// <para/>Legal block size 64 bits. Legal key size 8-1024 bits (8 bits increments).
    /// </summary>
    public sealed class RC2 : SymmetricBlockAlgorithm
    {
        #region Properties

        private static readonly KeySizes[] _blockSizes = new KeySizes[] { new KeySizes(64, 64, 0) };
        private static readonly KeySizes[] _keySizes = new KeySizes[] { new KeySizes(8, 1024, 8) };

        #endregion Properties

        #region Construction

        /// <summary>
        /// RC2.
        /// <para/>Legal block size 64 bits. Legal key size 8-1024 bits (8 bits increments).
        /// </summary>
        public RC2() : base("RC2", SymmetricAlgorithmKind.Block, _blockSizes, 64, _keySizes)
        {
        }

        #endregion Construction

        internal override IBlockCipher GenerateEngine()
        {
            return new RC2Engine();
        }

        /// <summary>
        /// Generate KeyParameter.
        /// </summary>
        /// <param name="key">Key.</param>
        /// <returns></returns>
        protected override KeyParameter GenerateKeyParameter(byte[] key)
        {
            return new RC2Parameters(key);
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
            return new RC2Parameters(keyBuffer, offset, length);
        }
    }
}