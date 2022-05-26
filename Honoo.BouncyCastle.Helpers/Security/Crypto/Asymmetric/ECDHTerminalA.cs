using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Security;
using System;

namespace Honoo.BouncyCastle.Helpers.Security.Crypto.Asymmetric
{
    /// <summary>
    /// ECDiffieHellman terminal Alice.
    /// </summary>
    public sealed class ECDHTerminalA : IECDHTerminalA
    {
        #region Properties

        private readonly ECDHBasicAgreement _agreement;
        private readonly byte[] _exchangeA;

        /// <summary>
        /// Exchange this bytes with terminal Bob.
        /// </summary>
        public byte[] ExchangeA => _exchangeA;

        #endregion Properties

        #region Constructor

        internal ECDHTerminalA(ECDHBasicAgreement agreement, byte[] exchangeA)
        {
            _agreement = agreement;
            _exchangeA = exchangeA;
        }

        #endregion Constructor

        /// <summary>
        /// Derive key material from the terminal Bob's exchange.
        /// </summary>
        /// <param name="exchangeB">The terminal Bob's exchange.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        public byte[] DeriveKeyMaterial(byte[] exchangeB)
        {
            if (exchangeB is null)
            {
                throw new ArgumentNullException(nameof(exchangeB));
            }
            AsymmetricKeyParameter publicKey = PublicKeyFactory.CreateKey(exchangeB);
            return _agreement.CalculateAgreement(publicKey).ToByteArrayUnsigned();
        }
    }
}