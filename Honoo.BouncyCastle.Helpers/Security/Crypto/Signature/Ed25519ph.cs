using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Utilities;
using System;
using System.Security.Cryptography;

namespace Honoo.BouncyCastle.Helpers.Security.Crypto.Signature
{
    /// <summary>
    /// Ed25519ph.
    /// </summary>
    public sealed class Ed25519ph : SignatureAlgorithm
    {
        #region Properties

        private readonly byte[] _context;

        #endregion Properties

        #region Constructor

        /// <summary>
        /// Ed25519ph.
        /// <para/>Uses context byte[0] by default.
        /// </summary>
        public Ed25519ph() : this(Arrays.EmptyBytes)
        {
        }

        /// <summary>
        /// Ed25519ph.
        /// <para/>Uses context byte[0] by default.
        /// </summary>
        /// <param name="context">Context.</param>
        public Ed25519ph(byte[] context) : this(context, AsymmetricAlgorithmHelper.Ed25519)
        {
        }

        /// <summary>
        /// Ed25519ph.
        /// <para/>Uses context byte[0] by default.
        /// </summary>
        /// <param name="context">Context.</param>
        /// <param name="asymmetricAlgorithm">Asymmetric algorithm. To provide function generate key pair, this argument is not required.</param>
        public Ed25519ph(byte[] context, IAsymmetricAlgorithm asymmetricAlgorithm) : base("Ed25519ph", EnsureAlgorithm(asymmetricAlgorithm))
        {
            _context = context ?? throw new ArgumentNullException(nameof(context));
        }

        #endregion Constructor

        /// <summary>
        /// Generate signer.
        /// </summary>
        /// <returns></returns>
        protected override ISigner GenerateSigner()
        {
            return new Ed25519phSigner(_context);
        }

        private static IAsymmetricAlgorithm EnsureAlgorithm(IAsymmetricAlgorithm asymmetricAlgorithm)
        {
            if (asymmetricAlgorithm is null)
            {
                return AsymmetricAlgorithmHelper.Ed25519;
            }
            else if (asymmetricAlgorithm.Mechanism != "Ed25519")
            {
                throw new CryptographicException("Requires Ed25519 asymmetric algorithm.");
            }
            else
            {
                return asymmetricAlgorithm;
            }
        }
    }
}