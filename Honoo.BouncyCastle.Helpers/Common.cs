using Org.BouncyCastle.Security;
using System.Threading;

namespace Honoo.BouncyCastle.Helpers
{
    internal static class Common
    {
        /// <summary>
        /// Control global size max value to 65536 or 2147483640. Must be set at program initialization.
        /// </summary>
        internal static int IntgerMulti8Max { get; } = 2147483640;

        internal static ThreadLocal<SecureRandom> SecureRandom { get; } = new ThreadLocal<SecureRandom>(() => { return new SecureRandom(); });
    }
}