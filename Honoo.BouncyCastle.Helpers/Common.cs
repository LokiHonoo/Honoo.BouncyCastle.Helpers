using Org.BouncyCastle.Security;

namespace Honoo.BouncyCastle.Helpers
{
    internal static class Common
    {
        internal static SecureRandom SecureRandom { get; } = SecureRandom.GetInstance("SHA1PRNG");
    }
}