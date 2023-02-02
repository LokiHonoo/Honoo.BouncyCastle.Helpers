using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using System.Security.Cryptography;

namespace Honoo.BouncyCastle.Helpers.Security.Crypto.Hash
{
    /// <summary>
    /// GOST3411.
    /// <para/>Legal hash size 256 bits.
    /// <para/>Uses substitution box "D-A" by default.
    /// </summary>
    public sealed class GOST3411 : HashAlgorithm
    {
        #region Properties

        private static readonly KeySizes[] _hashSizes = new KeySizes[] { new KeySizes(256, 256, 0) };
        private readonly byte[] _sBox;

        #endregion Properties

        #region Constructor

        /// <summary>
        /// GOST3411.
        /// <para/>Legal hash size 256 bits.
        /// <para/>Uses substitution box "D-A" by default.
        /// </summary>
        public GOST3411() : this(null)
        {
        }

        /// <summary>
        /// GOST3411.
        /// <para/>Legal hash size 256 bits.
        /// <para/>Uses substitution box "D-A" by default.
        /// </summary>
        /// <param name="sBox">Substitution box.</param>

        public GOST3411(Gost28147SBox sBox) : this(GetSBox(sBox))
        {
        }

        /// <summary>
        /// GOST3411.
        /// <para/>Legal hash size 256 bits.
        /// <para/>Uses substitution box "D-A" by default.
        /// </summary>
        /// <param name="sBox">Substitution box.</param>
        public GOST3411(byte[] sBox) : base("GOST3411", _hashSizes, 256)
        {
            _sBox = sBox;
        }

        #endregion Constructor

        /// <summary>
        /// Generate digest. The digest can be reused.
        /// </summary>
        /// <returns></returns>
        public override IDigest GenerateDigest()
        {
            return _sBox == null ? new Gost3411Digest() : new Gost3411Digest(_sBox);
        }

        private static byte[] GetSBox(Gost28147SBox sBox)
        {
            switch (sBox)
            {
                case Gost28147SBox.Default: return null;
                case Gost28147SBox.D_Test: return Gost28147Engine.GetSBox("D-Test");
                case Gost28147SBox.D_A: return Gost28147Engine.GetSBox("D-A");
                case Gost28147SBox.E_Test: return Gost28147Engine.GetSBox("E-Test");
                case Gost28147SBox.E_A: return Gost28147Engine.GetSBox("E-A");
                case Gost28147SBox.E_B: return Gost28147Engine.GetSBox("E-B");
                case Gost28147SBox.E_C: return Gost28147Engine.GetSBox("E-C");
                case Gost28147SBox.E_D: return Gost28147Engine.GetSBox("E-D");
                default: throw new CryptographicException("Unsupported substitution box.");
            }
        }
    }
}