﻿using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using System.Security.Cryptography;

namespace Honoo.BouncyCastle.Helpers.Security.Crypto.Hash
{
    /// <summary>
    /// MD4.
    /// <para/>Legal hash size 128 bits.
    /// </summary>
    public sealed class MD4 : HashAlgorithm
    {
        #region Properties

        private static readonly KeySizes[] _hashSizes = new KeySizes[] { new KeySizes(128, 128, 0) };

        #endregion Properties

        #region Construction

        /// <summary>
        /// MD4.
        /// <para/>Legal hash size 128 bits.
        /// </summary>
        public MD4() : base("MD4", _hashSizes, 128)
        {
        }

        #endregion Construction

        /// <summary>
        /// Generate digest. The digest can be reused.
        /// </summary>
        /// <returns></returns>
        public override IDigest GenerateDigest()
        {
            return new MD4Digest();
        }
    }
}