using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Utilities;
using System;
using System.Security.Cryptography;

namespace Honoo.BouncyCastle.Helpers.Security.Crypto.Signature
{
    /// <summary>
    /// Ed448.
    /// </summary>
    public sealed class Ed448 : SignatureAlgorithm
    {
        #region Properties

        private readonly byte[] _context;

        #endregion Properties

        #region Constructor

        /// <summary>
        /// Ed448.
        /// <para/>Uses context byte[0] by default.
        /// </summary>
        public Ed448() : this(Arrays.EmptyBytes)
        {
        }

        /// <summary>
        /// Ed448.
        /// <para/>Uses context byte[0] by default.
        /// </summary>
        /// <param name="context">Context.</param>
        public Ed448(byte[] context) : this(context, AsymmetricAlgorithmHelper.Ed448)
        {
        }

        /// <summary>
        /// Ed448.
        /// <para/>Uses context byte[0] by default.
        /// </summary>
        /// <param name="context">Context.</param>
        /// <param name="asymmetricAlgorithm">Asymmetric algorithm. To provide function generate key pair, this argument is not required.</param>
        public Ed448(byte[] context, IAsymmetricAlgorithm asymmetricAlgorithm) : base("Ed448", EnsureAlgorithm(asymmetricAlgorithm))
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
            return new Ed448Signer(_context);
        }

        private static IAsymmetricAlgorithm EnsureAlgorithm(IAsymmetricAlgorithm asymmetricAlgorithm)
        {
            if (asymmetricAlgorithm is null)
            {
                return AsymmetricAlgorithmHelper.Ed448;
            }
            else if (asymmetricAlgorithm.Name != "Ed448")
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