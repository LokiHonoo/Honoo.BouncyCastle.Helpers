﻿using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using System.Security.Cryptography;

namespace Honoo.BouncyCastle.Helpers
{
    /// <summary>
    /// Using the BouncyCastle implementation of the algorithm.
    /// </summary>
    public sealed class GOST3411 : HashAlgorithm
    {
        #region Properties

        private const int HASH_SIZE = 256;
        private const string NAME = "GOST3411";
        private readonly byte[] _substitutionBox;
        private Gost3411Digest _digest;

        #endregion Properties

        #region Construction

        /// <summary>
        /// Initializes a new instance of the GOST3411 class.
        /// </summary>
        public GOST3411() : base(NAME, HASH_SIZE)
        {
            _substitutionBox = null;
        }

        /// <summary>
        /// Initializes a new instance of the GOST3411 class.
        /// </summary>
        /// <param name="substitutionBox">Substitution box.</param>
        public GOST3411(Gost28147SubstitutionBox substitutionBox) : base(NAME, HASH_SIZE)
        {
            _substitutionBox = GetSubstitutionBox(substitutionBox);
        }

        #endregion Construction

        /// <summary>
        /// Creates an instance of the algorithm.
        /// </summary>
        /// <returns></returns>
        public static GOST3411 Create()
        {
            return new GOST3411();
        }

        /// <summary>
        /// Creates an instance of the algorithm.
        /// </summary>
        /// <param name="substitutionBox">Substitution box.</param>
        /// <returns></returns>
        public static GOST3411 Create(Gost28147SubstitutionBox substitutionBox)
        {
            return new GOST3411(substitutionBox);
        }

        /// <inheritdoc/>
        public override int ComputeFinal(byte[] outputBuffer, int offset)
        {
            if (_digest == null)
            {
                _digest = GetDigest();
            }
            _digest.DoFinal(outputBuffer, offset);
            return base.HashSize / 8;
        }

        /// <inheritdoc/>
        public override void Reset()
        {
            _digest.Reset();
        }

        /// <inheritdoc/>
        public override void Update(byte[] inputBuffer, int offset, int length)
        {
            if (_digest == null)
            {
                _digest = GetDigest();
            }
            _digest.BlockUpdate(inputBuffer, offset, length);
        }

        internal static HashAlgorithmName GetAlgorithmName()
        {
            return new HashAlgorithmName(NAME, HASH_SIZE, () => { return new Gost3411Digest(); }, () => { return new GOST3411(); });
        }

        private static byte[] GetSubstitutionBox(Gost28147SubstitutionBox substitutionBox)
        {
            switch (substitutionBox)
            {
                case Gost28147SubstitutionBox.Default: return Gost28147Engine.GetSBox("Default");
                case Gost28147SubstitutionBox.D_Test: return Gost28147Engine.GetSBox("D-Test");
                case Gost28147SubstitutionBox.D_A: return Gost28147Engine.GetSBox("D-A");
                case Gost28147SubstitutionBox.E_Test: return Gost28147Engine.GetSBox("E-Test");
                case Gost28147SubstitutionBox.E_A: return Gost28147Engine.GetSBox("E-A");
                case Gost28147SubstitutionBox.E_B: return Gost28147Engine.GetSBox("E-B");
                case Gost28147SubstitutionBox.E_C: return Gost28147Engine.GetSBox("E-C");
                case Gost28147SubstitutionBox.E_D: return Gost28147Engine.GetSBox("E-D");
                default: throw new CryptographicException("Unsupported substitution box.");
            }
        }

        private Gost3411Digest GetDigest()
        {
            return _substitutionBox == null ? new Gost3411Digest() : new Gost3411Digest(_substitutionBox);
        }
    }
}