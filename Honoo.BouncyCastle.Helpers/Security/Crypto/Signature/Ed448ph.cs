using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Utilities;
using System;
using System.Security.Cryptography;

namespace Honoo.BouncyCastle.Helpers.Security.Crypto.Signature
{
    /// <summary>
    /// Ed448ph.
    /// </summary>
    public sealed class Ed448ph : SignatureAlgorithm
    {
        #region Properties

        private readonly byte[] _context;

        #endregion Properties

        #region Constructor

        /// <summary>
        /// Ed448ph.
        /// <para/>Uses context byte[0] by default.
        /// </summary>
        public Ed448ph() : this(Arrays.EmptyBytes)
        {
        }

        /// <summary>
        /// Ed448ph.
        /// <para/>Uses context byte[0] by default.
        /// </summary>
        /// <param name="context">Context.</param>
        public Ed448ph(byte[] context) : this(context, AsymmetricAlgorithmHelper.Ed448)
        {
        }

        /// <summary>
        /// Ed448ph.
        /// <para/>Uses context byte[0] by default.
        /// </summary>
        /// <param name="context">Context.</param>
        /// <param name="asymmetricAlgorithm">Asymmetric algorithm.</param>
        public Ed448ph(byte[] context, IAsymmetricAlgorithm asymmetricAlgorithm) : base("Ed448ph", EnsureAlgorithm(asymmetricAlgorithm))
        {
            _context = context ?? throw new ArgumentNullException(nameof(context));
        }

        #endregion Constructor

        /// <summary>
        /// Generate signer.
        /// </summary>
        /// <returns></returns>
        protected override ISigner GenerateSignerCore()
        {
            return new Ed448phSigner(_context);
        }

        private static IAsymmetricAlgorithm EnsureAlgorithm(IAsymmetricAlgorithm asymmetricAlgorithm)
        {
            if (asymmetricAlgorithm.Name != "Ed448")
            {
                throw new CryptographicException("Requires Ed448 asymmetric algorithm.");
            }
            else
            {
                return asymmetricAlgorithm;
            }
        }
    }
}