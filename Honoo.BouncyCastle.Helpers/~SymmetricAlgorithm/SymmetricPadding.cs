﻿using Org.BouncyCastle.Crypto.Paddings;

namespace Honoo.BouncyCastle.Helpers
{
    internal static class SymmetricPadding
    {
        internal static IBlockCipherPadding ISO10126_2_PADDING { get; } = GetISO10126d2Padding();
        internal static IBlockCipherPadding ISO7816_4_PADDING { get; } = new ISO7816d4Padding();
        internal static IBlockCipherPadding PKCS7_PADDING { get; } = new Pkcs7Padding();
        internal static IBlockCipherPadding TBC_PADDING { get; } = new TbcPadding();
        internal static IBlockCipherPadding X923_PADDING { get; } = new X923Padding();
        internal static IBlockCipherPadding ZEROBYTE_PADDING { get; } = new ZeroBytePadding();

        private static ISO10126d2Padding GetISO10126d2Padding()
        {
            ISO10126d2Padding padding = new ISO10126d2Padding();
            padding.Init(Common.SecureRandom.Value);
            return padding;
        }
    }
}