using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Agreement;
using System;

namespace Honoo.BouncyCastle.Helpers.Security.Crypto.Asymmetric
{
    /// <summary>
    /// ECDiffieHellman terminal Bob.
    /// </summary>
    public sealed class ECDHTerminalB : IECDHTerminalB
    {
        #region Properties

        private readonly ECDHBasicAgreement _agreement;
        private readonly byte[] _exchangeB;
        private readonly AsymmetricKeyParameter _publicKeyA;

        /// <summary>
        /// Exchange this bytes with terminal Alice.
        /// </summary>
        public byte[] ExchangeB => _exchangeB;

        #endregion Properties

        #region Constructor

        internal ECDHTerminalB(ECDHBasicAgreement agreement, byte[] exchangeB, AsymmetricKeyParameter publicKeyA)
        {
            _agreement = agreement;
            _exchangeB = exchangeB;
            _publicKeyA = publicKeyA;
        }

        #endregion Constructor

        /// <summary>
        /// Derive key material.
        /// </summary>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        public byte[] DeriveKeyMaterial()
        {
            return _agreement.CalculateAgreement(_publicKeyA).ToByteArrayUnsigned();
        }
    }
}