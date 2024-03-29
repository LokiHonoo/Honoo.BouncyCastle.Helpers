﻿using Org.BouncyCastle.Asn1.EdEC;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;

namespace Honoo.BouncyCastle.Helpers.Security.Crypto.Asymmetric
{
    /// <summary>
    /// Ed448.
    /// <para/>Uses context byte[0] by default.
    /// </summary>
    public sealed class Ed448 : AsymmetricAlgorithm
    {
        #region Construction

        /// <summary>
        /// Ed448.
        /// </summary>
        public Ed448() : base("Ed448", EdECObjectIdentifiers.id_Ed448, AsymmetricAlgorithmKind.Signature)
        {
        }

        #endregion Construction

        /// <summary>
        /// Generate Asymmetric key pair.
        /// </summary>
        /// <returns></returns>
        public override AsymmetricCipherKeyPair GenerateKeyPair()
        {
            Ed448KeyPairGenerator generator = new Ed448KeyPairGenerator();
            Ed448KeyGenerationParameters parameters = new Ed448KeyGenerationParameters(Common.SecureRandom);
            generator.Init(parameters);
            return generator.GenerateKeyPair();
        }
    }
}