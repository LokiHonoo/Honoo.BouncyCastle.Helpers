using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Security;
using System.Threading;

namespace Honoo.BouncyCastle.Helpers
{
    internal static class Common
    {
        #region First

        internal static ThreadLocal<SecureRandom> ThreadSecureRandom { get; } = new ThreadLocal<SecureRandom>(GenerateSecureRandom);

        #endregion First

        internal static IBlockCipherPadding ISO10126d2Padding { get; } = GetISO10126d2Padding();
        internal static IBlockCipherPadding ISO7816d4Padding { get; } = new ISO7816d4Padding();
        internal static IBlockCipherPadding PKCS7Padding { get; } = new Pkcs7Padding();
        internal static IBlockCipherPadding TBCPadding { get; } = new TbcPadding();
        internal static IBlockCipherPadding X923Padding { get; } = new X923Padding();
        internal static IBlockCipherPadding ZEROBYTEPadding { get; } = new ZeroBytePadding();

        private static SecureRandom GenerateSecureRandom()
        {
            return SecureRandom.GetInstance("SHA1PRNG");
        }

        private static IBlockCipherPadding GetISO10126d2Padding()
        {
            IBlockCipherPadding padding = new ISO10126d2Padding();
            padding.Init(ThreadSecureRandom.Value);
            return padding;
        }
    }
}