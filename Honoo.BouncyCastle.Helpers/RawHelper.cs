using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.X509;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace Honoo.BouncyCastle.Helpers
{
    /// <summary>
    /// Raw helper.
    /// </summary>
    public static class RawHelper
    {
        /// <summary>
        /// Convert certificate revocation list to raw bytes.
        /// </summary>
        /// <param name="crl">Certificate revocation list.</param>
        /// <returns></returns>
        public static byte[] Crl2Raw(X509Crl crl)
        {
            return crl.GetEncoded();
        }

        /// <summary>
        /// Convert raw bytes to certificate revocation list.
        /// </summary>
        /// <param name="raw">Raw bytes.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        public static X509Crl Raw2Crl(byte[] raw)
        {
            return new X509CrlParser().ReadCrl(raw);
        }
    }
}
