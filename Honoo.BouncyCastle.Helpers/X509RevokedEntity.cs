using Org.BouncyCastle.Math;
using System;

namespace Honoo.BouncyCastle.Helpers
{
    /// <summary>
    /// X509 certificate revoked entity.
    /// </summary>
    public sealed class X509RevokedEntity
    {
        #region Properties

        private readonly int _reason;
        private readonly BigInteger _serialNumber;
        private readonly DateTime _time;

        /// <summary>
        /// Revoked reason.
        /// </summary>
        public int Reason => _reason;

        /// <summary>
        /// Certificate serial number.
        /// </summary>
        public BigInteger SerialNumber => _serialNumber;

        /// <summary>
        /// Revoked time.
        /// </summary>
        public DateTime Time => _time;

        #endregion Properties

        /// <summary>
        /// X509 certificate revoked entity.
        /// </summary>
        /// <param name="serialNumber">Certificate serial number.</param>
        /// <param name="time">Revoked time.</param>
        /// <param name="reason">Revoked reason.</param>
        public X509RevokedEntity(BigInteger serialNumber, DateTime time, int reason)
        {
            _serialNumber = serialNumber;
            _time = time;
            _reason = reason;
        }
    }
}