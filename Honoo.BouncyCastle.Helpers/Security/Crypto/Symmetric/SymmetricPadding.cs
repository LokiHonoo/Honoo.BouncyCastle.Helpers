using Org.BouncyCastle.Crypto.Paddings;

namespace Honoo.BouncyCastle.Helpers.Security.Crypto.Symmetric
{
    internal static class SymmetricPadding
    {
        internal static IBlockCipherPadding ISO10126d2Padding { get; } = GetISO10126d2Padding();
        internal static IBlockCipherPadding ISO7816d4Padding { get; } = new ISO7816d4Padding();
        internal static IBlockCipherPadding PKCS7Padding { get; } = new Pkcs7Padding();
        internal static IBlockCipherPadding TBCPadding { get; } = new TbcPadding();
        internal static IBlockCipherPadding X923Padding { get; } = new X923Padding();
        internal static IBlockCipherPadding ZEROBYTEPadding { get; } = new ZeroBytePadding();

        private static IBlockCipherPadding GetISO10126d2Padding()
        {
            IBlockCipherPadding padding = new ISO10126d2Padding();
            padding.Init(Common.SecureRandom);
            return padding;
        }
    }
}