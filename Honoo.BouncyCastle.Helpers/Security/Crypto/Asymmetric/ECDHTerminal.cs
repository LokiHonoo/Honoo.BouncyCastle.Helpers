using Org.BouncyCastle.Crypto.Agreement;

namespace Honoo.BouncyCastle.Helpers.Security.Crypto.Asymmetric
{
    /// <summary>
    /// ECDiffieHellman terminal.
    /// </summary>
    public sealed class ECDHTerminal
    {
        #region Properties

        private readonly ECDHBasicAgreement _agreement;

        private readonly byte[] _exchange;

        /// <summary>
        /// Exchange this bytes with other terminal.
        /// </summary>
        public byte[] Exchange => _exchange;
        #endregion Properties

        #region Constructor

        internal ECDHTerminal(ECDHBasicAgreement agreement, byte[] exchange)
        {
            _agreement = agreement;
            _exchange = exchange;
        }



        #endregion Constructor
    }
}