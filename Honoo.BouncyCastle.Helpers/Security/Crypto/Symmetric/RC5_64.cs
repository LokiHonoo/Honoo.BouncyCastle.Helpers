using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.Security.Cryptography;

namespace Honoo.BouncyCastle.Helpers.Security.Crypto.Symmetric
{
    /// <summary>
    /// RC5-64.
    /// <para/>Legal block size 128 bits. Legal key size 8-2040 bits (8 bits increments).
    /// </summary>
    public sealed class RC5_64 : BlockAlgorithm
    {
        #region Properties

        private static readonly KeySizes[] _blockSizes = new KeySizes[] { new KeySizes(128, 128, 0) };
        private static readonly KeySizes[] _keySizes = new KeySizes[] { new KeySizes(8, 2040, 8) };

        #endregion Properties

        #region Constructor

        /// <summary>
        /// RC5-64.
        /// <para/>Legal block size 128 bits. Legal key size 8-2040 bits (8 bits increments).
        /// </summary>
        public RC5_64() : base("RC5-64", _blockSizes, 128, _keySizes)
        {
        }

        #endregion Constructor

        internal override IBlockCipher GenerateEngine()
        {
            return new RC564Engine();
        }
        /// <summary>
        /// Generate KeyParameter.
        /// </summary>
        /// <param name="key">Key.</param>
        /// <returns></returns>
        protected override KeyParameter GenerateKeyParameter(byte[] key)
        {
            return new RC5Parameters(key, 12);
        }
        /// <summary>
        /// Generate KeyParameter.
        /// </summary>
        /// <param name="key">Key.</param>
        /// <param name="offset">Offset.</param>
        /// <param name="length">Length.</param>
        /// <returns></returns>
        protected override KeyParameter GenerateKeyParameter(byte[] key, int offset, int length)
        {
            byte[] key2 = new byte[length];
            Buffer.BlockCopy(key, offset, key2, 0, length);
            return new RC5Parameters(key2, 12);
        }
    }
}