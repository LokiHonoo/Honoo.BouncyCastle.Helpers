using Org.BouncyCastle.Security;

namespace Test
{
    internal static class Common
    {
        internal static SecureRandom Random { get; } = new SecureRandom();
    }
}