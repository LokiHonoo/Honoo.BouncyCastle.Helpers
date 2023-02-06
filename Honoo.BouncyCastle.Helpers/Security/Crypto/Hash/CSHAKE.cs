using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using System;
using System.Globalization;
using System.Security.Cryptography;

namespace Honoo.BouncyCastle.Helpers.Security.Crypto.Hash
{
    /// <summary>
    /// CSHAKE.
    /// <para/>Legal hash size 128, 256 bits.
    /// <para/>NIST name. Avoid using it if not required.
    /// </summary>
    public sealed class CSHAKE : HashAlgorithm
    {
        #region Properties

        private static readonly KeySizes[] _hashSizes = new KeySizes[] { new KeySizes(128, 256, 128) };
        private readonly byte[] _customization;
        private readonly byte[] _nist;

        #endregion Properties

        #region Construction

        /// <summary>
        /// CSHAKE.
        /// <para/>Legal hash size 128, 256 bits.
        /// <para/>NIST name. Avoid using it if not required.
        /// </summary>
        /// <param name="hashSize">Hash size bits.</param>
        /// <param name="nist">Nist bytes.</param>
        /// <param name="customization">Customization bytes.</param>
        /// <exception cref="Exception"/>
        public CSHAKE(int hashSize, byte[] nist, byte[] customization) : base(string.Format(CultureInfo.InvariantCulture, "CSHAKE{0}", hashSize), _hashSizes, hashSize)
        {
            _nist = nist;
            _customization = customization;
        }

        #endregion Construction

        /// <summary>
        /// Generate digest. The digest can be reused.
        /// </summary>
        /// <returns></returns>
        public override IDigest GenerateDigest()
        {
            return new CShakeDigest(base.HashSize, _nist, _customization);
        }
    }
}