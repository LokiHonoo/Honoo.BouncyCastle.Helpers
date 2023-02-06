using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using System;
using System.Globalization;
using System.Security.Cryptography;

namespace Honoo.BouncyCastle.Helpers.Security.Crypto.Hash
{
    /// <summary>
    /// Gost3411-2012.
    /// <para/>Legal hash size 256, 512 bits.
    /// </summary>
    public sealed class GOST3411_2012 : HashAlgorithm
    {
        #region Properties

        private static readonly KeySizes[] _hashSizes = new KeySizes[] { new KeySizes(256, 512, 256) };

        #endregion Properties

        #region Construction

        /// <summary>
        /// Gost3411-2012.
        /// <para/>Legal hash size 256, 512 bits.
        /// </summary>
        /// <param name="hashSize">Hash size bits.</param>
        /// <exception cref="Exception"/>
        public GOST3411_2012(int hashSize) : base(string.Format(CultureInfo.InvariantCulture, "GOST3411-2012-{0}", hashSize), _hashSizes, hashSize)
        {
        }

        #endregion Construction

        /// <summary>
        /// Generate digest. The digest can be reused.
        /// </summary>
        /// <returns></returns>
        public override IDigest GenerateDigest()
        {
            if (base.HashSize == 512)
            {
                return new Gost3411_2012_512Digest();
            }
            else
            {
                return new Gost3411_2012_256Digest();
            }
        }
    }
}