using System;

namespace Test
{
    internal static class Utilities
    {
        private static readonly byte[] _pool = new byte[1048576];

        static Utilities()
        {
            new Random().NextBytes(_pool);
        }

        internal static byte[] ScoopBytes(int length)
        {
            byte[] bytes = new byte[length];
            Buffer.BlockCopy(_pool, 0, bytes, 0, length);
            return bytes;
        }
    }
}